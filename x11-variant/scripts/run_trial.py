"""Run one x11-fwd trial against the docker-compose stack.

Exit code 0 = success (recovered cookie matches ground truth AND
e2e auth check passes). Non-zero = failure with diagnostics on stderr.
"""
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

HARNESS_URL = "http://localhost:8000"
ENGINE_URL = "http://localhost:9000"
HARNESS_INTERNAL = "http://client:8000"
ENGINE_INTERNAL = "http://localhost:9000"


def docker_compose(*args, capture=True):
    return subprocess.run(
        ["docker", "compose", *args],
        check=True,
        capture_output=capture,
        text=True,
    )


def docker_exec_in(service, user, *cmd):
    full = ["docker", "compose", "exec", "-T", "-u", user, service, *cmd]
    return subprocess.run(full, check=True, capture_output=True, text=True)


def http_post_in_server(path: str, body: dict | None = None, max_time: int = 60) -> dict:
    """POST to a service URL from inside the server container (so it
    reaches client:8000 / localhost:9000 on the docker network)."""
    payload_bytes = json.dumps(body or {}).encode()
    cmd = [
        "docker", "compose", "exec", "-T", "server",
        "python3", "-c",
        f"""
import urllib.request
req = urllib.request.Request(
    {path!r},
    data={payload_bytes!r},
    headers={{'Content-Type': 'application/json'}},
)
with urllib.request.urlopen(req, timeout={max_time}) as r:
    print(r.read().decode())
""",
    ]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def capture_ground_truth() -> tuple[bytes, int]:
    """Read the fake cookie from victim's xauth and discover the X11 forward
    port. Both via `docker exec` — out-of-band of the SSH compression stream."""
    # xauth nlist output format: "ffff:80:0080hostname/unix:60NN  MIT-MAGIC-COOKIE-1  <hex>"
    proc = docker_exec_in("server", "victim", "xauth", "-f", "/home/victim/.Xauthority", "nlist")
    line = proc.stdout.strip().splitlines()[-1]
    cookie_hex = line.split()[-1]
    cookie = bytes.fromhex(cookie_hex)
    if len(cookie) != 16:
        raise SystemExit(f"unexpected cookie length: {len(cookie)} bytes")

    # Discover the listener port. ss output line:
    # "LISTEN 0 128 127.0.0.1:6010 0.0.0.0:*"
    # (ownership/users column is empty when sshd's per-session forward
    # listener isn't introspectable from a non-root caller; that's fine —
    # the loopback :60NN listener is unambiguously the X11 forward.)
    proc = docker_exec_in("server", "victim", "ss", "-tln")
    port = None
    for line in proc.stdout.splitlines():
        m = re.search(r"127\.0\.0\.1:(\d+)\s+0\.0\.0\.0:\*", line)
        if m:
            p = int(m.group(1))
            if 6010 <= p <= 6100:
                port = p
                break
    if port is None:
        raise SystemExit("no X11 forward listener found in ss -tln output")
    return cookie, port


def main() -> int:
    print("[trial] bringing stack up...")
    docker_compose("up", "-d", "--build", capture=False)

    # Wait for both services to be ready.
    for attempt in range(60):
        try:
            http_post_in_server(f"{HARNESS_INTERNAL}/trial/end")
            break
        except subprocess.CalledProcessError:
            time.sleep(0.5)
    else:
        raise SystemExit("harness did not become ready")

    print("[trial] opening SSH session via harness...")
    http_post_in_server(f"{HARNESS_INTERNAL}/trial/start")

    print("[trial] capturing ground truth out of band...")
    truth_cookie, target_port = capture_ground_truth()
    print(f"[trial] ground-truth cookie: {truth_cookie.hex()}")
    print(f"[trial] X11 forward port: {target_port}")

    print("[trial] running attack (this may take a while)...")
    t0 = time.time()
    resp = http_post_in_server(
        f"{ENGINE_INTERNAL}/run_attack",
        {"target_port": target_port},
        max_time=60 * 60 * 6,  # 6h ceiling
    )
    elapsed = time.time() - t0
    recovered_hex = resp["recovered_cookie"]
    print(f"[trial] recovered cookie:    {recovered_hex} (in {elapsed:.1f}s)")

    match = recovered_hex == truth_cookie.hex()
    print(f"[trial] cookie match:        {match}")

    print("[trial] e2e auth check...")
    e2e = http_post_in_server(
        f"{ENGINE_INTERNAL}/e2e_check",
        {"target_port": target_port, "cookie_hex": recovered_hex},
    )
    print(f"[trial] e2e auth ok:         {e2e['ok']}")

    print("[trial] tearing down session...")
    http_post_in_server(f"{HARNESS_INTERNAL}/trial/end")

    success = match and bool(e2e.get("ok"))
    print(f"[trial] OVERALL:             {'PASS' if success else 'FAIL'}")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
