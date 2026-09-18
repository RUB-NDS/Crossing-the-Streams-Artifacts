# Shared helpers for the artifact-evaluation scenario scripts.
# Sourced, not executed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ATTACKER_BASE="http://127.0.0.1:9000"
CLIENT_BASE="http://127.0.0.1:8000"

# The README says `python`; many systems only ship `python3`.
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "!! no python3/python on PATH" >&2
    exit 2
fi

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n!! %s\n' "$*" >&2; exit 2; }

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
    docker compose version >/dev/null 2>&1 \
        || die "'docker compose' (v2) not available"
}

# Bring the five-service stack up. Idempotent: re-running is cheap once the
# images are built.
ensure_stack() {
    require_docker
    say "Bringing up the docker-compose stack"
    if [ "${AE_SKIP_BUILD:-0}" = "1" ]; then
        docker compose up -d
    else
        docker compose up -d --build
    fi
    wait_healthy
}

# Poll both control APIs until SSH is up with compression and the Redis
# tunnel is active. Fails loudly rather than letting a scenario script run
# against a half-open stack.
wait_healthy() {
    local timeout="${1:-180}" deadline
    deadline=$(( $(date +%s) + timeout ))
    say "Waiting for the stack to become healthy (timeout ${timeout}s)"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if "$PY" - <<'PYEOF' 2>/dev/null
import json, sys, urllib.request
def get(u):
    with urllib.request.urlopen(u, timeout=5) as r:
        return json.loads(r.read())
try:
    get("http://127.0.0.1:9000/status")
    c = get("http://127.0.0.1:8000/status")
except Exception:
    sys.exit(1)
if not c.get("ssh_connected"):
    sys.exit(1)
if c.get("ssh_send_compression") not in ("zlib", "zlib@openssh.com"):
    sys.exit(1)
sys.exit(0)
PYEOF
        then
            info "stack healthy"
            return 0
        fi
        sleep 3
    done
    die "stack did not become healthy within ${timeout}s. Try: docker compose logs"
}

# The attacker runs one attack at a time and only honours /cancel at a byte
# boundary, so a wedged position cannot be cancelled. Restarting the
# attacker drops the SSH forwarder, so the client must be reset afterwards.
reset_stack() {
    say "Resetting attacker + client (clears any wedged attack)"
    docker compose restart attacker >/dev/null
    sleep 5
    curl -fsS -X POST "$CLIENT_BASE/reset" >/dev/null 2>&1 || true
    wait_healthy
}

banner_result() {
    local rc="$1" name="$2"
    if [ "$rc" -eq 0 ]; then
        printf '\n\033[1;32m===> %s: PASS\033[0m\n' "$name"
    else
        printf '\n\033[1;31m===> %s: FAIL (exit %s)\033[0m\n' "$name" "$rc"
    fi
    return "$rc"
}
