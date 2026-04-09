"""End-to-end smoke test for the PoC environment.

Run from the host (the docker-compose stack must be up):

    python scripts/verify.py

Checks:
  1. attacker HTTP control API responds
  2. client HTTP control API responds AND reports
        - SSH connection established
        - zlib (or zlib@openssh.com) compression negotiated
        - both port forwards (Redis + web tunnel) active
  3. attacker can trigger client to send a Redis AUTH -> we observe
     non-zero TCP segments on the wire
  4. attacker can inject a payload through the web tunnel -> same
     observation
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"


def http(method: str, url: str, body: bytes | None = None) -> dict:
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


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"FAIL: {msg}")
    sys.exit(1)


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
    web_ok = pf.get("web_tunnel", {}).get("active")
    redis_ok = pf.get("redis_tunnel", {}).get("active")
    if not web_ok:
        fail("web tunnel port forward not active")
    if not redis_ok:
        fail("Redis tunnel port forward not active")
    print(f"  [ok] port forwards active: web={pf['web_tunnel']}  "
          f"redis={pf['redis_tunnel']}")

    step("3. Inspect attacker state")
    asn = http("GET", f"{ATTACKER_BASE}/status")
    print(json.dumps(asn, indent=2))

    step("4. Trigger Redis AUTH (send_secret) and capture packet log")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    print("  [..] cleared packet log")
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

    step("5. Inject payload through web tunnel and capture packet log")
    http("POST", f"{ATTACKER_BASE}/clear_log")
    print("  [..] cleared packet log")
    payload = b"GET / HTTP/1.0\r\nHost: webhost\r\n\r\n"
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
        fail("no TCP segments observed during web tunnel injection")
    print("  [ok] attacker observed packets while injecting through web tunnel")

    step("VERIFICATION PASSED")
    print("All preconditions are met:")
    print("  (1) SSH connection up with zlib compression")
    print("  (2) Two port forwards active (Redis tunnel + web tunnel)")
    print("  (3) Attacker observes encrypted SSH packet sizes on the wire")
    print("  (4) Attacker can trigger Redis AUTH (secret flows c->s)")
    print("  (5) Attacker can inject data through the web tunnel (c->s)")
    print("  Both data flows share a single zlib compression context.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
