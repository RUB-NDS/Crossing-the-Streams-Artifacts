"""Stress-test the CRIME-on-SSH attack against 50 random Redis passwords.

Generates 50 random passwords of varying lengths over the lowercase
alphanumeric alphabet, sets each one via the client's /set_secret
endpoint (which also reconfigures the real Redis server), runs the
attack via the attacker's /run_attack endpoint, and verifies that the
recovered value matches the planted secret.

Run from the host while the docker-compose stack is up:

    python scripts/test_attack_random.py
"""

from __future__ import annotations

import json
import random
import sys
import time
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"

PREFIX = "AUTH "
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Use a fixed seed so the test is reproducible across runs.
SEED = 4253  # RFC 4253, the SSH transport protocol document
N_SECRETS = 50
LEN_MIN = 3
LEN_MAX = 14


def http(method: str, url: str, body: bytes | None = None,
         content_type: str | None = None, timeout: float = 1200.0) -> dict:
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


def run_attack(max_length: int) -> dict:
    body = json.dumps({
        "known_prefix": PREFIX,
        "alphabet": ALPHABET,
        "max_length": max_length,
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack", body=body,
                content_type="application/json")


def main() -> int:
    rng = random.Random(SEED)
    secrets_list = [
        "".join(rng.choice(ALPHABET) for _ in range(rng.randint(LEN_MIN, LEN_MAX)))
        for _ in range(N_SECRETS)
    ]

    print("CRIME-on-SSH PoC: 50-secret stress test (Redis AUTH)")
    print(f"Seed:      {SEED} (reproducible)")
    print(f"Alphabet:  {ALPHABET!r}  ({len(ALPHABET)} chars + terminator)")
    print(f"Lengths:   {LEN_MIN}..{LEN_MAX} characters")
    print()

    results: list[tuple[str, str, bool, float]] = []
    started_total = time.time()

    for idx, secret in enumerate(secrets_list, 1):
        print(f"[{idx:>2}/{N_SECRETS}] target = {secret!r:<18}", end="", flush=True)
        set_secret(secret)
        time.sleep(2.0)
        started = time.time()
        try:
            result = run_attack(max_length=len(secret) + 4)
            recovered = result.get("recovered", "").rstrip("\r\n")
            ok = recovered == secret
        except Exception as exc:  # noqa: BLE001
            recovered = f"<error: {exc!s}>"
            ok = False
        elapsed = time.time() - started
        results.append((secret, recovered, ok, elapsed))
        status = "PASS" if ok else "FAIL"
        print(f"  recovered = {recovered!r:<18}  {elapsed:>6.1f}s  {status}",
              flush=True)

    total_elapsed = time.time() - started_total
    n_pass = sum(1 for _, _, ok, _ in results if ok)

    print()
    print("=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  total elapsed: {total_elapsed:.1f}s "
          f"({total_elapsed/60:.1f} min)")
    print(f"  results:       {n_pass}/{N_SECRETS} passed")
    if n_pass < N_SECRETS:
        print()
        print("  FAILURES:")
        for secret, recovered, ok, _ in results:
            if not ok:
                print(f"    target={secret!r}  recovered={recovered!r}")
    return 0 if n_pass == N_SECRETS else 1


if __name__ == "__main__":
    sys.exit(main())
