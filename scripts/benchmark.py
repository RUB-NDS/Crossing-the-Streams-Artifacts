"""Benchmark the three attack variants (direct / BEAST / Ansible).

Parallelises independent docker-compose projects.  Each stack is fully
isolated: its own bridge network, its own containers, its own scapy
sniffer.  The benchmark script dials each stack's attacker and client
directly on their docker-bridge IPs -- no host port mapping needed.

Usage:

    python scripts/benchmark.py --stacks 4 --trials 100

On a big machine:

    python scripts/benchmark.py --stacks 32 --trials 100

Reads attack guess counts from the ``total_guesses`` field that
attacker/attack/engine.py now includes in every ``/run_attack`` response.
Writes a detailed JSON dump (``benchmark_results.json``) alongside the
console summary.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import string
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE_FILES = [
    "-f", os.path.join(ROOT, "docker-compose.yml"),
    "-f", os.path.join(ROOT, "docker-compose.bench.yml"),
]

RESP_PREFIX = "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$"
LEN_ALPHABET = "0123456789"
ANSIBLE_PHASE1_PREFIX = "\x5e\x00\x00\x00\x00\x00\x00\x00"
ANSIBLE_PHASE1_ALPHABET = "".join(chr(i) for i in range(1, 33))
ANSIBLE_PHASE1_TERMINATOR = "\x00"
ANSIBLE_PHASE2_TERMINATOR = "\n"


# ---------------------------------------------------------------------------
# Scenario presets
# ---------------------------------------------------------------------------

SCENARIO_PRESETS: dict[str, dict] = {
    "baseline": {
        "alignment_mode": "fixed_single",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
        # alignment_lengths filled in from --fixed-nl N
    },
    "full-sweep": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
    },
    "adaptive-sweep": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": True,
        "stall_detection": True,
        "alignment_hint_carryover": True,
    },
    "candidate-elimination": {
        "alignment_mode": "fixed_single",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
        # alignment_lengths filled in from --fixed-nl N
    },
    "all-opts": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": True,
        "stall_detection": True,
        "alignment_hint_carryover": True,
    },
}


def _build_config_override(scenario: str, fixed_nl: int | None,
                            label_suffix: str) -> dict:
    if scenario not in SCENARIO_PRESETS:
        raise ValueError(f"unknown scenario {scenario!r}")
    cfg = dict(SCENARIO_PRESETS[scenario])
    if cfg.get("alignment_mode") == "fixed_single":
        if fixed_nl is None:
            raise ValueError(
                f"--fixed-nl N is required with --scenario {scenario} "
                "(fixed_single alignment mode needs a pinned length)"
            )
        cfg["alignment_lengths"] = [int(fixed_nl)]
    cfg["label"] = f"{scenario}{label_suffix}"
    return cfg


# ---------------------------------------------------------------------------
# HTTP helper (blocking, stdlib only)
# ---------------------------------------------------------------------------

def _broadcast_cancel(attacker_bases: list[str]) -> None:
    """POST /cancel to every attacker, best-effort. Errors are swallowed —
    a stack that's already wedged or torn down is fine to skip."""
    for base in attacker_bases:
        try:
            http(f"{base}/cancel", method="POST", body={}, timeout=5)
        except Exception:
            pass


def http(
    url: str,
    method: str = "GET",
    body: Any = None,
    timeout: float = 7200.0,
) -> dict:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


# ---------------------------------------------------------------------------
# Docker compose driver
# ---------------------------------------------------------------------------

def _compose(project: str, *args: str, capture: bool = False) -> subprocess.CompletedProcess:
    env = {**os.environ, "COMPOSE_PROJECT_NAME": project}
    cmd = ["docker", "compose", *COMPOSE_FILES, *args]
    return subprocess.run(
        cmd, env=env, check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def build_images(project: str) -> None:
    """Build once, against the first project -- image tags are shared
    across all projects so subsequent ``up`` calls reuse the build.
    """
    print(f"[build] building images via project {project!r} ...", flush=True)
    _compose(project, "build")
    print("[build] done", flush=True)


def up_stack(project: str) -> None:
    _compose(project, "up", "-d")


def down_stack(project: str) -> None:
    try:
        _compose(project, "down", "-v")
    except subprocess.CalledProcessError as exc:
        print(f"[{project}] down failed: {exc}", flush=True)


def inspect_ip(container: str) -> str:
    out = subprocess.check_output(
        ["docker", "inspect", container,
         "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"]
    )
    ip = out.decode().strip()
    if not ip:
        raise RuntimeError(f"no IP for container {container!r}")
    return ip


# ---------------------------------------------------------------------------
# Readiness polling
# ---------------------------------------------------------------------------

def wait_ready(
    attacker_base: str,
    client_base: str,
    need_browser: bool,
    timeout: float = 240.0,
) -> None:
    deadline = time.time() + timeout
    last = "<no response yet>"
    while time.time() < deadline:
        try:
            cs = http(f"{client_base}/status", timeout=5)
            http(f"{attacker_base}/status", timeout=5)
            ssh_ok = bool(cs.get("ssh_connected"))
            redis_ok = bool(
                cs.get("port_forwards", {}).get("redis_tunnel", {}).get("active")
            )
            browser_ok = bool(cs.get("browser_connected"))
            last = f"ssh={ssh_ok} redis_tunnel={redis_ok} browser={browser_ok}"
            if ssh_ok and redis_ok and (not need_browser or browser_ok):
                return
        except Exception as exc:  # noqa: BLE001
            last = f"poll error: {exc}"
        time.sleep(2.0)
    raise RuntimeError(f"stack not ready after {timeout:.0f}s: {last}")


# ---------------------------------------------------------------------------
# Unified runner (replaces legacy per-variant functions and VARIANT_RUNNERS)
# ---------------------------------------------------------------------------

def _http_run_attack(
    attacker_base: str,
    variant: str,
    config_override: dict,
    known_prefix: str,
    alphabet: str,
    max_length: int,
    terminator: str | None = None,
    expected: str | None = None,
) -> dict:
    body_cfg = dict(config_override)
    body_cfg["known_prefix"] = known_prefix
    body_cfg["alphabet"] = alphabet
    body_cfg["max_length"] = max_length
    if terminator is not None:
        body_cfg["terminator"] = terminator
    body: dict[str, Any] = {"variant": variant, "config": body_cfg}
    if expected is not None:
        body["expected"] = expected
    return http(
        f"{attacker_base}/run_attack",
        method="POST",
        body=body,
    )


def _run_two_phase(
    attacker_base: str,
    variant: str,
    base_config: dict,
    set_secret_url: str,
    password: str,
    phase1_prefix: str,
    phase1_alphabet: str,
    phase1_max: int,
    phase1_terminator: str | None,
    phase2_prefix_from_phase1: Callable,
    phase2_alphabet: str,
    phase2_max_fn: Callable,
    phase2_terminator: str | None,
    strip_trailing: str,
    expected_phase1: str | None = None,
    expected_phase2: str | None = None,
) -> dict:
    # Reset secret via client's set-secret endpoint.
    http(set_secret_url, method="POST", body={"value": password})
    # Small settle so the client's "set secret" reaches the server
    # before the attack starts measuring.
    time.sleep(1.0)

    r1 = _http_run_attack(
        attacker_base, variant, base_config,
        phase1_prefix, phase1_alphabet, phase1_max, phase1_terminator,
        expected=expected_phase1,
    )
    phase1_recovered = r1["recovered"]

    r2 = _http_run_attack(
        attacker_base, variant, base_config,
        phase2_prefix_from_phase1(phase1_recovered),
        phase2_alphabet,
        phase2_max_fn(phase1_recovered),
        phase2_terminator,
        expected=expected_phase2,
    )
    recovered = r2["recovered"].rstrip(strip_trailing)

    return {
        "recovered": recovered,
        "phase1_guesses": r1.get("total_guesses", -1),
        "phase2_guesses": r2.get("total_guesses", -1),
        "total_guesses": r1.get("total_guesses", 0) + r2.get("total_guesses", 0),
        "elapsed": r1.get("elapsed_seconds", 0) + r2.get("elapsed_seconds", 0),
        "phase1_per_position": r1.get("per_position", []),
        "phase2_per_position": r2.get("per_position", []),
        "phase1_aborted": bool(r1.get("aborted")),
        "phase2_aborted": bool(r2.get("aborted")),
        "abort_reason": r1.get("abort_reason") or r2.get("abort_reason"),
    }


def run_variant(
    variant: str,
    base_config: dict,
    attacker_base: str,
    client_base: str,
    password: str,
    pw_alphabet: str,
    early_exit: bool = False,
) -> dict:
    if early_exit:
        if variant == "direct" or variant == "beast":
            ep1 = str(len(password)) + "\r"
            ep2 = password + "\r"
        elif variant == "ansible":
            ep1 = chr(len(password)) + "\x00"
            ep2 = password + "\n"
        else:
            ep1 = ep2 = None
    else:
        ep1 = ep2 = None

    if variant == "direct":
        return _run_two_phase(
            attacker_base, "direct", base_config,
            set_secret_url=f"{client_base}/set_secret",
            password=password,
            phase1_prefix=RESP_PREFIX,
            phase1_alphabet=LEN_ALPHABET,
            phase1_max=4,
            phase1_terminator=None,
            phase2_prefix_from_phase1=lambda s: RESP_PREFIX + s + "\r\n",
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda s: len(password) + 1,
            phase2_terminator=None,
            strip_trailing="\r",
            expected_phase1=ep1,
            expected_phase2=ep2,
        )
    if variant == "beast":
        return _run_two_phase(
            attacker_base, "beast", base_config,
            set_secret_url=f"{client_base}/set_secret",
            password=password,
            phase1_prefix=RESP_PREFIX,
            phase1_alphabet=LEN_ALPHABET,
            phase1_max=4,
            phase1_terminator=None,
            phase2_prefix_from_phase1=lambda s: RESP_PREFIX + s + "\r\n",
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda s: len(password) + 1,
            phase2_terminator=None,
            strip_trailing="\r",
            expected_phase1=ep1,
            expected_phase2=ep2,
        )
    if variant == "ansible":
        return _run_two_phase(
            attacker_base, "ansible", base_config,
            set_secret_url=f"{client_base}/set_sudo_secret",
            password=password,
            phase1_prefix=ANSIBLE_PHASE1_PREFIX,
            phase1_alphabet=ANSIBLE_PHASE1_ALPHABET,
            phase1_max=1,
            phase1_terminator=ANSIBLE_PHASE1_TERMINATOR,
            phase2_prefix_from_phase1=lambda length_str: ANSIBLE_PHASE1_PREFIX + length_str,
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda length_str: len(password) + 1,
            phase2_terminator=ANSIBLE_PHASE2_TERMINATOR,
            strip_trailing="\n",
            expected_phase1=ep1,
            expected_phase2=ep2,
        )
    raise ValueError(f"unknown variant {variant!r}")


# ---------------------------------------------------------------------------
# Per-stack worker (one thread per stack, trials sequential within)
# ---------------------------------------------------------------------------

def worker(
    stack_idx: int,
    project: str,
    trial_indices: list[int],
    passwords: list[str],
    variants: list[str],
    pw_alphabet: str,
    config_override: dict,
    early_exit: bool,
    results: list[dict],
    results_lock: threading.Lock,
    failures: list[str],
    stop_event: threading.Event,
    attacker_bases: list[str],
) -> None:
    tag = f"[stack {stack_idx:02d} {project}]"
    try:
        attacker_ip = inspect_ip(f"{project}-attacker")
        client_ip = inspect_ip(f"{project}-client")
        attacker_base = f"http://{attacker_ip}:9000"
        client_base = f"http://{client_ip}:8000"
        with results_lock:
            attacker_bases.append(attacker_base)
        need_browser = "beast" in variants
        print(f"{tag} waiting for readiness at {attacker_base} / {client_base}"
              f" (browser={'yes' if need_browser else 'no'})", flush=True)
        wait_ready(attacker_base, client_base, need_browser=need_browser)
        print(f"{tag} ready; {len(trial_indices)} trial(s) assigned", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"{tag} SETUP FAILED: {exc}", flush=True)
        failures.append(f"{project}: setup: {exc}")
        return

    for trial_idx in trial_indices:
        if early_exit and stop_event.is_set():
            return
        password = passwords[trial_idx]
        for variant in variants:
            if early_exit and stop_event.is_set():
                return
            t0 = time.time()
            try:
                result = run_variant(variant, config_override,
                                     attacker_base, client_base,
                                     password, pw_alphabet,
                                     early_exit=early_exit)
                ok = result["recovered"] == password
                status = "PASS" if ok else f"FAIL(expected={password!r}, got={result['recovered']!r})"
            except Exception as exc:  # noqa: BLE001
                result = {
                    "recovered": f"<error: {exc}>",
                    "phase1_guesses": -1,
                    "phase2_guesses": -1,
                    "total_guesses": -1,
                    "elapsed": 0.0,
                    "phase1_per_position": [],
                    "phase2_per_position": [],
                    "phase1_aborted": False,
                    "phase2_aborted": False,
                    "abort_reason": None,
                }
                ok = False
                status = f"ERROR: {exc}"
            wall = time.time() - t0
            row = {
                "stack": stack_idx,
                "project": project,
                "trial": trial_idx,
                "variant": variant,
                "scenario": config_override.get("label", ""),
                "password": password,
                "recovered": result["recovered"],
                "ok": ok,
                "total_guesses": result["total_guesses"],
                "phase1_guesses": result.get("phase1_guesses"),
                "phase2_guesses": result.get("phase2_guesses"),
                "phase1_per_position": result.get("phase1_per_position", []),
                "phase2_per_position": result.get("phase2_per_position", []),
                "phase1_aborted": result.get("phase1_aborted"),
                "phase2_aborted": result.get("phase2_aborted"),
                "abort_reason": result.get("abort_reason"),
                "wall_seconds": wall,
                "status": status,
            }
            with results_lock:
                results.append(row)
            print(f"{tag} trial={trial_idx:3d} variant={variant:7s} "
                  f"guesses={result['total_guesses']:>7} wall={wall:6.1f}s  {status}",
                  flush=True)

            if early_exit and not ok:
                with results_lock:
                    first_failure = not stop_event.is_set()
                    if first_failure:
                        stop_event.set()
                    bases_snapshot = list(attacker_bases)
                if first_failure:
                    print(f"{tag} early-exit: broadcasting /cancel to "
                          f"{len(bases_snapshot)} stack(s)", flush=True)
                    _broadcast_cancel(bases_snapshot)
                return


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarise(results: list[dict], variants: list[str]) -> dict:
    summary: dict[str, dict] = {}
    for v in variants:
        vr = [r for r in results if r["variant"] == v]
        passed = [r for r in vr if r["ok"]]
        per_attack = [r["total_guesses"] for r in passed]

        # Per-position: flatten both phase lists across all passed trials.
        per_position_guesses: list[int] = []
        for r in passed:
            for entry in (r.get("phase1_per_position") or []):
                per_position_guesses.append(entry["guesses"])
            for entry in (r.get("phase2_per_position") or []):
                per_position_guesses.append(entry["guesses"])

        def stats(xs: list[int]) -> dict:
            return {
                "count": len(xs),
                "min": min(xs) if xs else None,
                "max": max(xs) if xs else None,
                "avg": (sum(xs) / len(xs)) if xs else None,
                "total": sum(xs),
            }

        # Fork metrics: count positions where fork triggered, sum losers' guesses
        fork_triggered_positions = 0
        fork_overhead_guesses = 0
        for r in passed:
            for entry in (r.get("phase1_per_position") or []):
                fi = entry.get("fork_info")
                if fi and fi.get("triggered"):
                    fork_triggered_positions += 1
                    fork_overhead_guesses += fi.get("losers_guesses", 0)
            for entry in (r.get("phase2_per_position") or []):
                fi = entry.get("fork_info")
                if fi and fi.get("triggered"):
                    fork_triggered_positions += 1
                    fork_overhead_guesses += fi.get("losers_guesses", 0)

        summary[v] = {
            "trials_total": len(vr),
            "trials_passed": len(passed),
            "trials_failed": len(vr) - len(passed),
            "per_attack": stats(per_attack),
            "per_position": stats(per_position_guesses),
            "fork_triggered_positions": fork_triggered_positions,
            "fork_overhead_guesses": fork_overhead_guesses,
        }
    return summary


def print_summary(summary: dict) -> None:
    print()
    print("=" * 96)
    print("SUMMARY  (per-attack | per-position)")
    print("=" * 96)
    header = (
        f"{'variant':<10} {'passed':>7} "
        f"{'a.min':>8} {'a.max':>8} {'a.avg':>10} {'a.total':>12} | "
        f"{'p.min':>6} {'p.max':>6} {'p.avg':>8} {'p.count':>7}"
    )
    print(header)
    print("-" * len(header))
    for v, s in summary.items():
        pa = s["per_attack"]
        pp = s["per_position"]

        def fmt(x, fmt_spec=""):
            return "-" if x is None else format(x, fmt_spec)

        print(
            f"{v:<10} {s['trials_passed']:>7} "
            f"{fmt(pa['min']):>8} {fmt(pa['max']):>8} "
            f"{fmt(pa['avg'], '.1f'):>10} {pa['total']:>12} | "
            f"{fmt(pp['min']):>6} {fmt(pp['max']):>6} "
            f"{fmt(pp['avg'], '.1f'):>8} {pp['count']:>7}"
        )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stacks", type=int, default=4,
                    help="number of parallel docker-compose projects")
    ap.add_argument("--trials", type=int, default=100,
                    help="total number of passwords to attack per variant")
    ap.add_argument("--password-length", type=int, default=8,
                    help="password length (excluding terminator)")
    ap.add_argument("--seed", type=int, default=4253,
                    help="RNG seed for password generation (reproducible)")
    ap.add_argument("--alphabet", default=string.ascii_lowercase,
                    help="password alphabet (default: lowercase ASCII)")
    ap.add_argument("--variants", default="direct,beast,ansible",
                    help="comma-separated subset of {direct,beast,ansible}")
    ap.add_argument("--prefix", default="bench",
                    help="compose-project-name prefix (one per stack)")
    ap.add_argument("--no-build", action="store_true",
                    help="skip image build (images already present)")
    ap.add_argument("--no-up", action="store_true",
                    help="skip compose up (stacks already running under --prefix)")
    ap.add_argument("--keep-up", action="store_true",
                    help="do not tear down stacks after benchmark completes")
    ap.add_argument("--output", default="benchmark_results.json",
                    help="path for detailed JSON output")
    ap.add_argument("--scenario", default="all-opts",
                    choices=list(SCENARIO_PRESETS.keys()),
                    help="named optimization preset")
    ap.add_argument("--fixed-nl", type=int, default=None,
                    help="required for fixed_single scenarios "
                         "(baseline, candidate-elimination): "
                         "single pinned alignment length")
    ap.add_argument("--config", default=None,
                    help="path to raw JSON config override; if set, overrides --scenario")
    ap.add_argument("--min-margin", type=int, default=None,
                    help="override min_margin on top of the selected scenario/config "
                         "(e.g. --min-margin 32); appended to config label as -mmN")
    ap.add_argument("--csv-summary", default="benchmark_summary.csv",
                    help="path for the one-row-per-variant CSV summary")
    ap.add_argument("--early-exit", action="store_true",
                    help="abort the run on the first wrong commit; populates "
                         "the engine's `expected` parameter from the known "
                         "password and broadcasts /cancel to all stacks on "
                         "failure")
    args = ap.parse_args()

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    for v in variants:
        if v not in ("direct", "beast", "ansible"):
            print(f"!! unknown variant {v!r}", file=sys.stderr)
            return 2

    if args.config:
        with open(args.config) as f:
            config_override = json.load(f)
        if "label" not in config_override:
            config_override["label"] = os.path.basename(args.config)
    else:
        uses_fixed_single = (
            SCENARIO_PRESETS[args.scenario].get("alignment_mode") == "fixed_single"
        )
        config_override = _build_config_override(
            args.scenario, args.fixed_nl,
            label_suffix=(f"-nl{args.fixed_nl}" if uses_fixed_single else ""),
        )

    if args.min_margin is not None:
        config_override["min_margin"] = args.min_margin
        config_override["label"] = f"{config_override['label']}-mm{args.min_margin}"

    rng = random.Random(args.seed)
    passwords = [
        "".join(rng.choices(args.alphabet, k=args.password_length))
        for _ in range(args.trials)
    ]
    projects = [f"{args.prefix}-{i}" for i in range(args.stacks)]

    # Round-robin distribution so every stack has near-equal load.
    assignments: list[list[int]] = [[] for _ in range(args.stacks)]
    for i in range(args.trials):
        assignments[i % args.stacks].append(i)

    print("=" * 78)
    print("BENCHMARK")
    print("=" * 78)
    print(f"  stacks        : {args.stacks}")
    print(f"  trials        : {args.trials}")
    print(f"  pw length     : {args.password_length}")
    print(f"  alphabet size : {len(args.alphabet)}")
    print(f"  variants      : {variants}")
    print(f"  seed          : {args.seed}")
    print(f"  scenario      : {args.scenario}")
    print(f"  config label  : {config_override['label']}")
    if args.min_margin is not None:
        print(f"  min_margin    : {args.min_margin} (override)")
    print(f"  projects      : {projects[:4]}{' ...' if len(projects) > 4 else ''}")
    print(f"  per-stack load: {[len(a) for a in assignments][:8]}"
          f"{' ...' if args.stacks > 8 else ''}")
    print(f"  first 5 pws   : {passwords[:5]}")

    up_errors: list[str] = []
    try:
        if not args.no_up:
            if not args.no_build:
                print("\n=== Building images (once) ===")
                try:
                    build_images(projects[0])
                except subprocess.CalledProcessError as exc:
                    print(f"!! build failed: {exc}")
                    return 3

            print("\n=== Bringing up stacks ===")
            up_threads = []
            for p in projects:
                def _up(project=p) -> None:
                    try:
                        up_stack(project)
                        print(f"[{project}] up", flush=True)
                    except subprocess.CalledProcessError as exc:
                        up_errors.append(f"{project}: {exc}")
                        print(f"[{project}] UP FAILED: {exc}", flush=True)
                t = threading.Thread(target=_up, daemon=True)
                t.start()
                up_threads.append(t)
            for t in up_threads:
                t.join()

            if up_errors:
                print("!! some stacks failed to come up, aborting")
                for e in up_errors:
                    print(f"  {e}")
                return 3

        print("\n=== Running trials ===")
        results: list[dict] = []
        results_lock = threading.Lock()
        failures: list[str] = []
        stop_event = threading.Event()
        attacker_bases: list[str] = []
        worker_threads = []
        started = time.time()
        for i, p in enumerate(projects):
            t = threading.Thread(
                target=worker,
                args=(i, p, assignments[i], passwords, variants,
                      args.alphabet, config_override, args.early_exit,
                      results, results_lock, failures,
                      stop_event, attacker_bases),
                daemon=True,
            )
            t.start()
            worker_threads.append(t)
        for t in worker_threads:
            t.join()
        wall = time.time() - started

        early_exit_triggered = stop_event.is_set()

        print(f"\n=== All trials done in {wall:.1f}s ===")
        if early_exit_triggered:
            print("=== Early-exit was triggered: at least one trial failed "
                  "and the run was aborted ===")
        if failures:
            print("!! some stacks failed:")
            for f in failures:
                print(f"  {f}")

        summary = summarise(results, variants)
        print_summary(summary)

        all_passed = all(s["trials_failed"] == 0 for s in summary.values())
        success = all_passed and not failures and not early_exit_triggered

        with open(args.output, "w") as f:
            json.dump({
                "config": {
                    "stacks": args.stacks,
                    "trials": args.trials,
                    "password_length": args.password_length,
                    "alphabet": args.alphabet,
                    "variants": variants,
                    "seed": args.seed,
                    "scenario": args.scenario,
                    "config_label": config_override["label"],
                    "early_exit": args.early_exit,
                },
                "passwords": passwords,
                "results": results,
                "summary": summary,
                "wall_seconds": wall,
                "early_exit_triggered": early_exit_triggered,
                "success": success,
            }, f, indent=2)
        print(f"\nDetailed results -> {args.output}")

        with open(args.csv_summary, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "variant", "scenario", "trials_passed",
                "per_attack_min", "per_attack_max", "per_attack_avg", "per_attack_total",
                "per_position_count",
                "per_position_min", "per_position_max", "per_position_avg",
                "fork_triggered_positions", "fork_overhead_guesses",
                "early_exit_triggered",
            ])
            for v, s in summary.items():
                pa = s["per_attack"]
                pp = s["per_position"]
                w.writerow([
                    v, config_override["label"], s["trials_passed"],
                    pa["min"], pa["max"],
                    f"{pa['avg']:.1f}" if pa["avg"] is not None else "",
                    pa["total"],
                    pp["count"],
                    pp["min"], pp["max"],
                    f"{pp['avg']:.1f}" if pp["avg"] is not None else "",
                    s["fork_triggered_positions"], s["fork_overhead_guesses"],
                    "true" if early_exit_triggered else "false",
                ])
        print(f"CSV summary -> {args.csv_summary}")

        return 0 if success else 1
    finally:
        if not args.keep_up and not args.no_up:
            print("\n=== Tearing down stacks ===")
            down_threads = []
            for p in projects:
                t = threading.Thread(target=down_stack, args=(p,), daemon=True)
                t.start()
                down_threads.append(t)
            for t in down_threads:
                t.join()
            print("tear-down complete")


if __name__ == "__main__":
    sys.exit(main())
