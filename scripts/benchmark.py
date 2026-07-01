"""Benchmark the attack scenarios (direct / browser / browser_pna / ansible).

Parallelises N independent docker-compose projects. Each stack is fully
isolated: its own bridge network, its own containers, its own scapy
sniffer. The benchmark script dials each stack's attacker and client
directly on their docker-bridge IPs -- no host port mapping needed.

Usage:

    python scripts/benchmark.py --stacks 4 --trials 100

Reads attack guess counts from the ``total_guesses`` field that
attacker/attack/engine.py includes in every ``/run_attack`` response.
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


# Preset keys match the optimization labels used in the paper's Table 2:
#   NO   = no further optimization (fixed_single alignment)
#   FS   = full alignment sweep
#   AS   = adaptive alignment sweep
#   CE   = candidate elimination (fixed_single alignment)
#   FSCE = full alignment sweep + candidate elimination
#   ASCE = adaptive alignment sweep + candidate elimination
OPTIMIZATION_PRESETS: dict[str, dict] = {
    "NO": {
        "alignment_mode": "fixed_single",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
        # alignment_lengths filled in from --fixed-al N
    },
    "FS": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
    },
    "AS": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": True,
        "stall_detection": True,
        "alignment_hint_carryover": True,
    },
    "CE": {
        "alignment_mode": "fixed_single",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
        # alignment_lengths filled in from --fixed-al N
    },
    "FSCE": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
    },
    "ASCE": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": True,
        "stall_detection": True,
        "alignment_hint_carryover": True,
    },
}


def _build_config_override(optimization: str, fixed_al: int | None,
                            label_suffix: str) -> dict:
    if optimization not in OPTIMIZATION_PRESETS:
        raise ValueError(f"unknown optimization {optimization!r}")
    cfg = dict(OPTIMIZATION_PRESETS[optimization])
    if cfg.get("alignment_mode") == "fixed_single":
        if fixed_al is None:
            raise ValueError(
                f"--fixed-al N is required with --optimization {optimization} "
                "(fixed_single alignment mode needs a pinned length)"
            )
        cfg["alignment_lengths"] = [int(fixed_al)]
    cfg["label"] = f"{optimization}{label_suffix}"
    return cfg


def _broadcast_cancel(attacker_bases: list[str]) -> None:
    """POST /cancel to every attacker, best-effort. Errors are swallowed --
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
    timeout: float = 86400.0,  # 24h -- slow scenarios (browser + high
                               # min_margin + adaptive sweep) can run multi-hour
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


def _compose(project: str, *args: str, capture: bool = False,
             extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "COMPOSE_PROJECT_NAME": project}
    if extra_env:
        env.update(extra_env)
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


def up_stack(project: str, extra_env: dict | None = None) -> None:
    _compose(project, "up", "-d", extra_env=extra_env)


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


def wait_ready(
    attacker_base: str,
    client_base: str,
    need_browser: bool,
    need_browser_pna: bool = False,
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
            browser_pna_ok = bool(cs.get("browser_pna_connected"))
            last = (f"ssh={ssh_ok} redis_tunnel={redis_ok} "
                    f"browser={browser_ok} browser_pna={browser_pna_ok}")
            if (ssh_ok and redis_ok
                    and (not need_browser or browser_ok)
                    and (not need_browser_pna or browser_pna_ok)):
                return
        except Exception as exc:  # noqa: BLE001
            last = f"poll error: {exc}"
        time.sleep(2.0)
    raise RuntimeError(f"stack not ready after {timeout:.0f}s: {last}")


def _http_run_attack(
    attacker_base: str,
    scenario: str,
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
    body: dict[str, Any] = {"scenario": scenario, "config": body_cfg}
    if expected is not None:
        body["expected"] = expected
    return http(
        f"{attacker_base}/run_attack",
        method="POST",
        body=body,
    )


def _run_two_phase(
    attacker_base: str,
    scenario: str,
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
    http(set_secret_url, method="POST", body={"value": password})
    # Small settle so the client's "set secret" reaches the server
    # before the attack starts measuring.
    time.sleep(1.0)

    r1 = _http_run_attack(
        attacker_base, scenario, base_config,
        phase1_prefix, phase1_alphabet, phase1_max, phase1_terminator,
        expected=expected_phase1,
    )
    phase1_recovered = r1["recovered"]

    if r1.get("aborted"):
        # Phase 1 already failed (mismatch or cancelled); phase 2 would attack
        # a wrong prefix and abort almost immediately. Skip it.
        return {
            "recovered": phase1_recovered,
            "phase1_guesses": r1.get("total_guesses", -1),
            "phase2_guesses": 0,
            "total_guesses": r1.get("total_guesses", 0),
            "elapsed": r1.get("elapsed_seconds", 0),
            "phase1_per_position": r1.get("per_position", []),
            "phase2_per_position": [],
            "phase1_aborted": True,
            "phase2_aborted": False,
            "abort_reason": r1.get("abort_reason"),
        }

    r2 = _http_run_attack(
        attacker_base, scenario, base_config,
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


def run_scenario(
    scenario: str,
    base_config: dict,
    attacker_base: str,
    client_base: str,
    password: str,
    pw_alphabet: str,
    early_exit: bool = False,
    seed_len: int = 2,
) -> dict:
    if scenario == "browser_pna":
        # Single-phase, SEEDED + length-bounded (Section 5.2 CORS-PNA remark).
        # The length, pw0 and pw1 sit behind the CR/LF wall and are seeded
        # (their brute-force cost is analytical, reported by
        # scripts/verify_browser_pna.py). Only the tail pw{seed_len}..pw(n-1) is
        # recovered through the live PNA preflight oracle. Reported
        # total_guesses is the MEASURED tail cost, comparable to the recovered
        # portion of the Firefox browser column.
        seed = password[:seed_len]
        tail = password[seed_len:]
        http(f"{client_base}/set_secret", method="POST", body={"value": password})
        time.sleep(1.0)
        r = _http_run_attack(
            attacker_base, "browser_pna", base_config,
            known_prefix=seed, alphabet=pw_alphabet, max_length=len(tail),
            terminator=None,  # length-bounded; default_config terminator is b""
            expected=(tail if early_exit else None),
        )
        recovered_tail = r["recovered"]
        return {
            # Full password for the worker's == check; the seed is known.
            "recovered": seed + recovered_tail,
            "phase1_guesses": 0,  # no length phase: length is seeded
            "phase2_guesses": r.get("total_guesses", -1),
            "total_guesses": r.get("total_guesses", 0),
            "elapsed": r.get("elapsed_seconds", 0),
            "phase1_per_position": [],
            "phase2_per_position": r.get("per_position", []),
            "phase1_aborted": False,
            "phase2_aborted": bool(r.get("aborted")),
            "abort_reason": r.get("abort_reason"),
        }

    if early_exit:
        if scenario == "direct" or scenario == "browser":
            ep1 = str(len(password)) + "\r"
            ep2 = password + "\r"
        elif scenario == "ansible":
            ep1 = chr(len(password + 1)) + "\x00"
            ep2 = password + "\n"
        else:
            ep1 = ep2 = None
    else:
        ep1 = ep2 = None

    if scenario == "direct":
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
    if scenario == "browser":
        return _run_two_phase(
            attacker_base, "browser", base_config,
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
    if scenario == "ansible":
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
    raise ValueError(f"unknown scenario {scenario!r}")


_PRINT_LOCK = threading.Lock()


def _tprint(msg: str) -> None:
    """Thread-safe print: writes the line + newline as a single
    sys.stdout.write so concurrent worker threads don't interleave halfway
    through a line. Plain print() does write(s) then write('\\n') as two
    calls, which can split under load."""
    with _PRINT_LOCK:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()


def worker(
    stack_idx: int,
    project: str,
    project_width: int,
    trial_indices: list[int],
    passwords: list[str],
    scenarios: list[str],
    pw_alphabet: str,
    config_override: dict,
    early_exit: bool,
    seed_len: int,
    max_retries: int,
    results: list[dict],
    results_lock: threading.Lock,
    failures: list[str],
    stop_event: threading.Event,
    attacker_bases: list[str],
    stack_ports: dict | None = None,
) -> None:
    tag = f"[stack {stack_idx:02d} {project:<{project_width}}]"
    try:
        if stack_ports is not None:
            # --host-ports: reach each stack via its published 127.0.0.1 port
            # (bridge IPs are not host-routable under rootless Docker / Desktop).
            att_port, cli_port = stack_ports[project]
            attacker_base = f"http://127.0.0.1:{att_port}"
            client_base = f"http://127.0.0.1:{cli_port}"
        else:
            attacker_ip = inspect_ip(f"{project}-attacker")
            client_ip = inspect_ip(f"{project}-client")
            attacker_base = f"http://{attacker_ip}:9000"
            client_base = f"http://{client_ip}:8000"
        with results_lock:
            attacker_bases.append(attacker_base)
        need_browser = "browser" in scenarios
        need_browser_pna = "browser_pna" in scenarios
        _tprint(f"{tag} waiting for readiness at {attacker_base} / {client_base}"
                f" (browser={'yes' if need_browser else 'no'}"
                f" browser_pna={'yes' if need_browser_pna else 'no'})")
        wait_ready(attacker_base, client_base, need_browser=need_browser,
                   need_browser_pna=need_browser_pna)
        _tprint(f"{tag} ready; {len(trial_indices)} trial(s) assigned")
    except Exception as exc:  # noqa: BLE001
        _tprint(f"{tag} SETUP FAILED: {exc}")
        failures.append(f"{project}: setup: {exc}")
        return

    for trial_idx in trial_indices:
        if early_exit and stop_event.is_set():
            return
        password = passwords[trial_idx]
        for scenario in scenarios:
            if early_exit and stop_event.is_set():
                return
            t0 = time.time()
            max_attempts = 1 + max_retries
            attempts_used = 0
            result: dict = {}
            ok = False
            status = ""
            for attempt in range(1, max_attempts + 1):
                if early_exit and stop_event.is_set():
                    break
                attempts_used = attempt
                try:
                    result = run_scenario(scenario, config_override,
                                          attacker_base, client_base,
                                          password, pw_alphabet,
                                          early_exit=early_exit,
                                          seed_len=seed_len)
                    ok = result["recovered"] == password
                    if ok:
                        status = "PASS"
                        break
                    if result.get("abort_reason") == "cancelled":
                        status = "CANCELLED"
                        break
                    status = f"FAIL(expected={password!r}, got={result['recovered']!r})"
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
                if attempt < max_attempts:
                    _tprint(f"{tag} trial={trial_idx:3d} scenario={scenario:7s} "
                            f"attempt {attempt}/{max_attempts} {status}; retrying")
            wall = time.time() - t0
            row = {
                "stack": stack_idx,
                "project": project,
                "trial": trial_idx,
                "scenario": scenario,
                "optimization": config_override.get("label", ""),
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
                "attempts": attempts_used,
            }
            with results_lock:
                results.append(row)
            attempt_tag = f" (after {attempts_used}/{max_attempts} attempts)" if attempts_used > 1 else ""
            _tprint(f"{tag} trial={trial_idx:3d} scenario={scenario:7s} "
                    f"guesses={result['total_guesses']:>7} wall={wall:6.1f}s  {status}{attempt_tag}")

            if early_exit and not ok:
                with results_lock:
                    first_failure = not stop_event.is_set()
                    if first_failure:
                        stop_event.set()
                    bases_snapshot = list(attacker_bases)
                if first_failure:
                    _tprint(f"{tag} early-exit: broadcasting /cancel to "
                            f"{len(bases_snapshot)} stack(s)")
                    _broadcast_cancel(bases_snapshot)
                return


def summarise(results: list[dict], scenarios: list[str]) -> dict:
    summary: dict[str, dict] = {}
    for s in scenarios:
        sr = [r for r in results if r["scenario"] == s]
        passed = [r for r in sr if r["ok"]]
        per_attack = [r["total_guesses"] for r in passed]

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

        summary[s] = {
            "trials_total": len(sr),
            "trials_passed": len(passed),
            "trials_failed": len(sr) - len(passed),
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
        f"{'scenario':<10} {'passed':>7} "
        f"{'a.min':>8} {'a.max':>8} {'a.avg':>10} {'a.total':>12} | "
        f"{'p.min':>6} {'p.max':>6} {'p.avg':>8} {'p.count':>7}"
    )
    print(header)
    print("-" * len(header))
    for s, summ in summary.items():
        pa = summ["per_attack"]
        pp = summ["per_position"]

        def fmt(x, fmt_spec=""):
            return "-" if x is None else format(x, fmt_spec)

        print(
            f"{s:<10} {summ['trials_passed']:>7} "
            f"{fmt(pa['min']):>8} {fmt(pa['max']):>8} "
            f"{fmt(pa['avg'], '.1f'):>10} {pa['total']:>12} | "
            f"{fmt(pp['min']):>6} {fmt(pp['max']):>6} "
            f"{fmt(pp['avg'], '.1f'):>8} {pp['count']:>7}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stacks", type=int, default=4,
                    help="number of parallel docker-compose projects")
    ap.add_argument("--trials", type=int, default=100,
                    help="total number of passwords to attack per scenario")
    ap.add_argument("--password-length", type=int, default=8,
                    help="password length (excluding terminator)")
    ap.add_argument("--seed", type=int, default=4253,
                    help="RNG seed for password generation (reproducible)")
    ap.add_argument("--alphabet", default=string.ascii_lowercase,
                    help="password alphabet (default: lowercase ASCII)")
    ap.add_argument("--scenarios", default="direct,browser,ansible",
                    help="comma-separated subset of "
                         "{direct,browser,browser_pna,ansible}")
    ap.add_argument("--seed-len", type=int, default=2,
                    help="browser_pna only: number of seeded leading password "
                         "bytes (length + pw0 + pw1 are CR/LF-walled; the "
                         "sanctioned boundary is 2). The tail pw{seed_len}.. is "
                         "recovered for real. Ignored by other scenarios.")
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
    ap.add_argument("--optimization", default="ASCE",
                    choices=list(OPTIMIZATION_PRESETS.keys()),
                    help="named optimization preset (paper Table 2 labels: "
                         "NO, FS, AS, CE, FSCE, ASCE)")
    ap.add_argument("--fixed-al", type=int, default=None,
                    help="required for fixed_single optimizations (NO, CE): "
                         "single pinned alignment length")
    ap.add_argument("--config", default=None,
                    help="path to raw JSON config override; "
                         "if set, overrides --optimization")
    ap.add_argument("--min-margin", type=int, default=None,
                    help="override min_margin on top of the selected "
                         "optimization/config (e.g. --min-margin 32); "
                         "appended to the config label as -mmN")
    ap.add_argument("--csv-summary", default="benchmark_summary.csv",
                    help="path for the one-row-per-scenario CSV summary")
    ap.add_argument("--early-exit", action="store_true",
                    help="abort the run on the first wrong commit; populates "
                         "the engine's `expected` parameter from the known "
                         "password and broadcasts /cancel to all stacks on "
                         "failure")
    ap.add_argument("--max-retries", type=int, default=0,
                    help="if a recovery fails, retry the same password this "
                         "many additional times before recording it as a "
                         "failure (e.g. --max-retries 2 = up to 3 attempts). "
                         "Used by sweep_min_margin.sh to absorb transient "
                         "noise before bumping min_margin.")
    ap.add_argument("--host-ports", action="store_true",
                    help="reach each stack via a published 127.0.0.1 host port "
                         "instead of its docker-bridge IP. REQUIRED under "
                         "rootless Docker and Docker Desktop, where bridge IPs "
                         "are not host-routable (the default bridge-IP mode "
                         "hangs at readiness there). Adds "
                         "docker-compose.bench-ports.yml to the overlay stack.")
    ap.add_argument("--attacker-port-base", type=int, default=19000,
                    help="with --host-ports: stack i's attacker is published on "
                         "127.0.0.1:(base+i) (default base 19000).")
    ap.add_argument("--client-port-base", type=int, default=18000,
                    help="with --host-ports: stack i's client is published on "
                         "127.0.0.1:(base+i) (default base 18000).")
    args = ap.parse_args()

    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for s in scenarios:
        if s not in ("direct", "browser", "browser_pna", "ansible"):
            print(f"!! unknown scenario {s!r}", file=sys.stderr)
            return 2
    if "browser_pna" in scenarios and args.seed_len >= args.password_length:
        print(f"!! --seed-len {args.seed_len} must be < --password-length "
              f"{args.password_length} for browser_pna", file=sys.stderr)
        return 2
    # Anti-shortcut boundary (Section 7): only {length, pw0, pw1} are behind the
    # CR/LF wall; seeding pw2+ hands the oracle bytes it must recover.
    if "browser_pna" in scenarios and args.seed_len > 2:
        print(f"!! --seed-len {args.seed_len} exceeds the sanctioned boundary of "
              f"2 for browser_pna (only {{length, pw0, pw1}} may be seeded)",
              file=sys.stderr)
        return 2

    # Launch only the browser(s) the selected scenarios need (both are heavy;
    # see client.py LAUNCH_FIREFOX / LAUNCH_CHROMIUM). Propagated to
    # `docker compose` via the environment inherited by _compose().
    os.environ["LAUNCH_FIREFOX"] = "1" if "browser" in scenarios else "0"
    os.environ["LAUNCH_CHROMIUM"] = "1" if "browser_pna" in scenarios else "0"

    if args.config:
        with open(args.config) as f:
            config_override = json.load(f)
        if "label" not in config_override:
            config_override["label"] = os.path.basename(args.config)
    else:
        uses_fixed_single = (
            OPTIMIZATION_PRESETS[args.optimization].get("alignment_mode") == "fixed_single"
        )
        config_override = _build_config_override(
            args.optimization, args.fixed_al,
            label_suffix=(f"-al{args.fixed_al}" if uses_fixed_single else ""),
        )

    if args.min_margin is not None:
        config_override["min_margin"] = args.min_margin
        config_override["label"] = f"{config_override['label']}-mm{args.min_margin}"

    # browser_pna's browser-class noise floor mandates the full [0..7] alignment
    # sweep, so the fixed_single presets (NO / CE) are n/a (same as browser).
    # Pinning a single alignment would break recovery -- reject it rather than
    # silently skip the sweep.
    if "browser_pna" in scenarios and config_override.get("alignment_mode") == "fixed_single":
        print(f"!! browser_pna requires the full alignment sweep; optimization "
              f"{args.optimization!r} (fixed_single) is n/a for it -- use FS, AS, "
              f"FSCE, or ASCE", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    passwords = [
        "".join(rng.choices(args.alphabet, k=args.password_length))
        for _ in range(args.trials)
    ]
    projects = [f"{args.prefix}-{i}" for i in range(args.stacks)]

    # --host-ports: publish each stack on a unique 127.0.0.1 port and dial that
    # (rootless Docker / Docker Desktop don't route bridge IPs from the host).
    stack_ports: dict | None = None
    if args.host_ports:
        COMPOSE_FILES.extend(
            ["-f", os.path.join(ROOT, "docker-compose.bench-ports.yml")]
        )
        stack_ports = {
            projects[i]: (args.attacker_port_base + i, args.client_port_base + i)
            for i in range(args.stacks)
        }

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
    print(f"  scenarios     : {scenarios}")
    print(f"  seed          : {args.seed}")
    print(f"  optimization  : {args.optimization}")
    print(f"  config label  : {config_override['label']}")
    if args.min_margin is not None:
        print(f"  min_margin    : {args.min_margin} (override)")
    if args.max_retries > 0:
        print(f"  max_retries   : {args.max_retries} "
              f"(up to {1 + args.max_retries} attempts per password)")
    print(f"  projects      : {projects[:4]}{' ...' if len(projects) > 4 else ''}")
    if stack_ports is not None:
        print(f"  reach stacks  : 127.0.0.1 host ports "
              f"(attacker {args.attacker_port_base}+i, "
              f"client {args.client_port_base}+i) [--host-ports]")
    else:
        print(f"  reach stacks  : docker-bridge IPs (rootful Docker on Linux)")
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
                        env = None
                        if stack_ports is not None:
                            att_port, cli_port = stack_ports[project]
                            env = {
                                "ATTACKER_HOST_PORT": str(att_port),
                                "CLIENT_HOST_PORT": str(cli_port),
                            }
                        up_stack(project, extra_env=env)
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
        project_width = max(len(p) for p in projects)
        for i, p in enumerate(projects):
            t = threading.Thread(
                target=worker,
                args=(i, p, project_width,
                      assignments[i], passwords, scenarios,
                      args.alphabet, config_override, args.early_exit,
                      args.seed_len, args.max_retries,
                      results, results_lock, failures,
                      stop_event, attacker_bases, stack_ports),
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

        summary = summarise(results, scenarios)
        print_summary(summary)

        all_passed = all(s["trials_failed"] == 0 for s in summary.values())
        success = all_passed and not failures and not early_exit_triggered

        # Exit-code triage so the caller (e.g. sweep_min_margin.sh) can tell
        # "algorithm wasn't strong enough at this min_margin" (FAIL/CANCELLED
        # -- bumping mm may help) from "infrastructure broke" (ERROR / setup
        # failure -- bumping mm won't help, abort). CANCELLED is a downstream
        # consequence of *whatever* tripped early-exit first, so we look for
        # ERROR explicitly.
        technical_errors = [
            r for r in results if str(r.get("status", "")).startswith("ERROR:")
        ]
        had_technical_failure = bool(failures) or bool(technical_errors)
        if technical_errors:
            print(f"!! {len(technical_errors)} technical error(s) "
                  f"(non-algorithmic); first: {technical_errors[0]['status']}")

        with open(args.output, "w") as f:
            json.dump({
                "config": {
                    "stacks": args.stacks,
                    "trials": args.trials,
                    "password_length": args.password_length,
                    "alphabet": args.alphabet,
                    "scenarios": scenarios,
                    "seed": args.seed,
                    "optimization": args.optimization,
                    "config_label": config_override["label"],
                    "early_exit": args.early_exit,
                    "max_retries": args.max_retries,
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
                "scenario", "optimization", "trials_passed",
                "per_attack_min", "per_attack_max", "per_attack_avg", "per_attack_total",
                "per_position_count",
                "per_position_min", "per_position_max", "per_position_avg",
                "fork_triggered_positions", "fork_overhead_guesses",
                "early_exit_triggered",
            ])
            for s, summ in summary.items():
                pa = summ["per_attack"]
                pp = summ["per_position"]
                w.writerow([
                    s, config_override["label"], summ["trials_passed"],
                    pa["min"], pa["max"],
                    f"{pa['avg']:.1f}" if pa["avg"] is not None else "",
                    pa["total"],
                    pp["count"],
                    pp["min"], pp["max"],
                    f"{pp['avg']:.1f}" if pp["avg"] is not None else "",
                    summ["fork_triggered_positions"], summ["fork_overhead_guesses"],
                    "true" if early_exit_triggered else "false",
                ])
        print(f"CSV summary -> {args.csv_summary}")

        # Exit codes:
        #   0 = all trials passed
        #   1 = algorithmic miss only (sweep can try a higher min_margin)
        #   2 = technical failure occurred (sweep should abort entirely)
        if success:
            return 0
        if had_technical_failure:
            return 2
        return 1
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
