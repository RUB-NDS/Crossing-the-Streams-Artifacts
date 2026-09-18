#!/usr/bin/env bash
#
# Scenario 1 -- Direct plaintext injection (paper Section 5.1).
#
# Recovers the Redis AUTH password "hunter2" over a network-exposed SSH
# port forward, by injecting guesses straight into the tunnel over raw TCP
# and watching the compressed packet sizes the attacker sniffs.
#
#   ./artifact-evaluation/scenario1_direct.sh
#   ./artifact-evaluation/scenario1_direct.sh --commit-margin 64
#
# Any extra arguments are passed through to scripts/verify_direct.py.
# Expect roughly 10-25 minutes depending on the commit margin and host.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# The direct adapter's built-in margin is 16, but the adapter defaults also
# select adaptive alignment sweep + candidate elimination, i.e. the AS+CE
# configuration of Table 3 -- and the repo's own sweep data for that cell
# (evaluation/direct/as+ce/) only reaches 100/100 recovery at mu = 80.
# At mu = 16 it recovers 2/100. So we default to the converged value.
DEFAULT_COMMIT_MARGIN="${AE_COMMIT_MARGIN:-80}"

say "Scenario 1: direct plaintext injection (Section 5.1)"
info "target secret : hunter2 (Redis AUTH password)"
info "commit margin : $DEFAULT_COMMIT_MARGIN (converged value for direct AS+CE)"

ensure_stack

set +e
"$PY" scripts/verify_direct.py \
    --commit-margin "$DEFAULT_COMMIT_MARGIN" \
    --fail-fast \
    "$@"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
    cat <<'EOF'

Recovery did not reproduce. The usual cause is measurement noise: the
engine committed a wrong byte and never revisits it. Raise the commit
margin in 8-byte steps and re-run, e.g.

    ./artifact-evaluation/scenario1_direct.sh --commit-margin 88

See ARTIFACT-EVALUATION.md, "Tuning the commit margin".
EOF
fi

banner_result "$rc" "Scenario 1 (direct)"
