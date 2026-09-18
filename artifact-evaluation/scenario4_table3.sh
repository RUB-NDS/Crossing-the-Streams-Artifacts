#!/usr/bin/env bash
#
# Scenario 4 -- Reproduce the performance measurements of Table 3.
#
# Table 3 reports the guess count per recovered password for each
# (scenario, noise-compensation configuration) pair, at the commit margin
# where the sweep first reached 100 % recovery. Three modes, cheapest
# first:
#
#   published  (default)  Recompute the table from the committed sweep
#                         data under evaluation/. Seconds. No stack.
#   quick                 Re-measure one cell live, with a reduced trial
#                         count, and compare against the published cell.
#                         Tens of minutes.
#   full                  The complete commit-margin sweep, all 13 cells.
#                         Days of machine time and 25+ parallel stacks.
#
#   ./artifact-evaluation/scenario4_table3.sh
#   ./artifact-evaluation/scenario4_table3.sh quick
#   ./artifact-evaluation/scenario4_table3.sh quick --scenario ansible
#   ./artifact-evaluation/scenario4_table3.sh full

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

MODE="${1:-published}"
shift || true

# The quick mode defaults to the ansible scenario: it is the only one whose
# converged margin is 8 across every configuration, so it re-measures in
# minutes rather than hours.
QUICK_SCENARIO="ansible"
QUICK_COMPENSATION="AS+CE"
QUICK_COMMIT_MARGIN=8
QUICK_TRIALS="${AE_QUICK_TRIALS:-10}"
QUICK_STACKS="${AE_QUICK_STACKS:-2}"

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario)     QUICK_SCENARIO="$2"; shift 2 ;;
        --compensation) QUICK_COMPENSATION="$2"; shift 2 ;;
        --commit-margin) QUICK_COMMIT_MARGIN="$2"; shift 2 ;;
        --trials)       QUICK_TRIALS="$2"; shift 2 ;;
        --stacks)       QUICK_STACKS="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$MODE" in
published)
    say "Scenario 4 (published): recomputing Table 3 from committed data"
    info "source: evaluation/ -- the sweep output behind the paper's Table 3"
    "$PY" artifact-evaluation/table3.py evaluation
    rc=$?
    cat <<'EOF'

This recomputes every Table 3 cell from the committed per-trial data, so
it checks the paper's numbers against the measurements they came from. To
re-measure instead of recompute:

    ./artifact-evaluation/scenario4_table3.sh quick    # one cell, minutes
    ./artifact-evaluation/scenario4_table3.sh full     # all cells, days
EOF
    banner_result "$rc" "Scenario 4 (published)"
    ;;

quick)
    say "Scenario 4 (quick): re-measuring one Table 3 cell live"
    info "scenario     : $QUICK_SCENARIO"
    info "compensation : $QUICK_COMPENSATION"
    info "commit margin: $QUICK_COMMIT_MARGIN"
    info "trials       : $QUICK_TRIALS across $QUICK_STACKS parallel stacks"
    info ""
    info "This spawns $QUICK_STACKS isolated docker-compose projects. It does"
    info "not use the default stack, and it removes them when done."

    require_docker
    mkdir -p results

    out="results/quick_${QUICK_SCENARIO}_${QUICK_COMPENSATION}_cm${QUICK_COMMIT_MARGIN}.json"
    csv="results/quick_${QUICK_SCENARIO}_${QUICK_COMPENSATION}_cm${QUICK_COMMIT_MARGIN}.csv"

    extra=()
    # NO and CE fix the alignment length rather than sweeping it, so they
    # need the winning length passed in explicitly.
    case "$QUICK_COMPENSATION" in
        NO|CE) extra+=(--alignment-length 1) ;;
    esac

    set +e
    "$PY" scripts/benchmark.py \
        --stacks "$QUICK_STACKS" \
        --trials "$QUICK_TRIALS" \
        --scenarios "$QUICK_SCENARIO" \
        --compensation "$QUICK_COMPENSATION" \
        --commit-margin "$QUICK_COMMIT_MARGIN" \
        --output "$out" \
        --csv-summary "$csv" \
        "${extra[@]}"
    rc=$?
    set -e

    # benchmark.py's exit-code contract: 0 = every trial recovered,
    # 1 = at least one algorithmic miss, 2 = infrastructure failure.
    case "$rc" in
        0) info "all $QUICK_TRIALS trials recovered their password" ;;
        1) info "at least one trial missed -- raise --commit-margin and retry" ;;
        2) die  "infrastructure failure; see the benchmark output above" ;;
    esac

    if [ -f "$out" ]; then
        say "Guess-count statistics for this run"
        "$PY" scripts/stats.py "$out" || true
        say "Published cell for comparison"
        "$PY" artifact-evaluation/table3.py evaluation --csv \
            | awk -F, -v s="$QUICK_SCENARIO" -v c="$QUICK_COMPENSATION" \
                'NR==1 || ($1==s && $2==c)'
    fi
    banner_result "$rc" "Scenario 4 (quick)"
    ;;

full)
    say "Scenario 4 (full): complete commit-margin sweep"
    cat <<'EOF'
This runs scripts/sweep_commit_margin.sh, which sweeps the commit margin
per (scenario, compensation) until every trial recovers. It is what
produced the committed evaluation/ tree.

Cost: days of machine time, 25+ parallel docker-compose stacks, and a
correspondingly large amount of RAM and CPU. Output lands under results/,
NOT evaluation/ -- the committed tree is the dataset the paper cites and
must not be overwritten.
EOF
    require_docker
    printf '\nProceed? [y/N] '
    read -r reply
    case "$reply" in
        [yY]*) ;;
        *) info "aborted"; exit 0 ;;
    esac
    set +e
    ./scripts/sweep_commit_margin.sh
    rc=$?
    set -e
    if [ -d results ]; then
        say "Table 3 recomputed from the fresh sweep"
        "$PY" artifact-evaluation/table3.py results || true
    fi
    banner_result "$rc" "Scenario 4 (full)"
    ;;

*)
    die "unknown mode '$MODE' (expected: published, quick, full)"
    ;;
esac
