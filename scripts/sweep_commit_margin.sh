#!/usr/bin/env bash
# Sweep the commit margin μ across {scenario} x {noise-compensation
# configuration} -- the paper's Table 3:
#   - scenarios:      direct, browser, ansible        (one per benchmark run)
#   - configurations: NO, FS, AS, CE, AS+CE          (Section 4.3, as
#                                                     reported in Table 3)
#   - commit margin:  start at 8, step +8, stop on the first 100%-success
#                     run, give up after 128.
#
# Outputs land at:
#   results/{NO,FS,AS,CE,AS+CE}/benchmark_{results,summary}_{scenario}_cmN.{json,csv}
#
# Knobs (env vars):
#   STACKS               (default 20)   parallel docker-compose projects per run
#   TRIALS               (default 100)  passwords attempted per run
#   ALIGNMENT_LEN_DIRECT (default 2)    known alignment length for direct
#   ALIGNMENT_LEN_ANSIBLE (default 1)   known alignment length for ansible
#   CM_START             (default 8)    starting commit margin
#   CM_STEP              (default 8)    increment
#   CM_MAX               (default 128)  upper bound (inclusive)
#   EARLY_EXIT           (default 1)    if 1, pass --early-exit to benchmark.py
#                                       so a doomed margin step aborts on the
#                                       first wrong commit instead of running
#                                       every trial to completion
#   MAX_RETRIES          (default 2)    on a failed recovery, retry the same
#                                       password this many extra times before
#                                       recording it as a true failure
#                                       (default = 3 attempts per password).
#                                       Absorbs transient measurement noise
#                                       before raising the commit margin.
#
# Notes:
#   - browser is skipped for the known_length configurations (NO and CE):
#     both presuppose a known winning alignment length, which the browser
#     noise floor does not support (the n/a cells of Table 3).
#   - browser still runs for FS, AS, and AS+CE (no --alignment-length
#     needed).

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Strip docker compose progress + buildkit step output from a stream while
# keeping benchmark.py prints and any Python tracebacks. awk always exits 0,
# so pipefail still surfaces python's exit status.
filter_docker_noise() {
    awk '
        /^[[:space:]]*(Network|Container|Volume|Image)[[:space:]].*(Creating|Created|Starting|Started|Stopping|Stopped|Removing|Removed|Recreating|Recreated|Killing|Killed|Waiting|Healthy|Running|Pulling|Pulled|Building|Built)[[:space:]]*$/ { next }
        /^#[0-9]+([[:space:]]|$)/ { next }
        /^\[\+\] /                 { next }
        /^[[:space:]]+=> /         { next }
        /^[[:space:]]*$/           { next }
        { print; fflush() }
    '
}

STACKS="${STACKS:-20}"
TRIALS="${TRIALS:-100}"
ALIGNMENT_LEN_DIRECT="${ALIGNMENT_LEN_DIRECT:-2}"
ALIGNMENT_LEN_ANSIBLE="${ALIGNMENT_LEN_ANSIBLE:-1}"
CM_START="${CM_START:-8}"
CM_STEP="${CM_STEP:-8}"
CM_MAX="${CM_MAX:-128}"
EARLY_EXIT="${EARLY_EXIT:-1}"
MAX_RETRIES="${MAX_RETRIES:-2}"

COMPENSATIONS=(NO FS AS CE AS+CE)
SCENARIOS=(direct browser ansible)

for compensation in "${COMPENSATIONS[@]}"; do
    out_dir="results/$compensation"
    mkdir -p "$out_dir"

    needs_alignment_length=0
    if [[ "$compensation" == "NO" || "$compensation" == "CE" ]]; then
        needs_alignment_length=1
    fi

    for scenario in "${SCENARIOS[@]}"; do
        if [ "$needs_alignment_length" -eq 1 ] && [ "$scenario" == "browser" ]; then
            echo "--- skipping compensation=$compensation scenario=browser" \
                 "(needs a known winning alignment length; n/a in Table 3) ---"
            continue
        fi

        extra_args=()
        if [ "$needs_alignment_length" -eq 1 ]; then
            case "$scenario" in
                direct)  extra_args+=(--alignment-length "$ALIGNMENT_LEN_DIRECT")  ;;
                ansible) extra_args+=(--alignment-length "$ALIGNMENT_LEN_ANSIBLE") ;;
            esac
        fi

        echo "============================================================"
        echo "  compensation=$compensation  scenario=$scenario"
        if [ "${#extra_args[@]}" -gt 0 ]; then
            echo "  extra args: ${extra_args[*]}"
        fi
        echo "============================================================"

        succeeded=0
        cm=$CM_START
        while [ "$cm" -le "$CM_MAX" ]; do
            results_json="$out_dir/benchmark_results_${scenario}_cm${cm}.json"
            summary_csv="$out_dir/benchmark_summary_${scenario}_cm${cm}.csv"
            echo ">>> $compensation/$scenario commit_margin=$cm  -> $results_json"

            ee_args=()
            if [ "$EARLY_EXIT" = "1" ]; then
                ee_args+=(--early-exit)
            fi
            python3 -u scripts/benchmark.py \
                --stacks "$STACKS" \
                --trials "$TRIALS" \
                --scenarios "$scenario" \
                --compensation "$compensation" \
                --commit-margin "$cm" \
                --max-retries "$MAX_RETRIES" \
                --output "$results_json" \
                --csv-summary "$summary_csv" \
                "${ee_args[@]}" \
                "${extra_args[@]}" 2>&1 | filter_docker_noise
            # PIPESTATUS[0] is benchmark.py's exit; filter is awk (always 0).
            rc=${PIPESTATUS[0]}
            case "$rc" in
                0)
                    echo "### $compensation/$scenario cm=$cm: 100% success -- stop"
                    succeeded=1
                    break
                    ;;
                1)
                    echo "### $compensation/$scenario cm=$cm: not yet 100% -- increasing"
                    cm=$((cm + CM_STEP))
                    ;;
                2)
                    echo "### $compensation/$scenario cm=$cm: TECHNICAL FAILURE" \
                         "(infrastructure error, not an algorithmic miss)." \
                         "Aborting entire sweep -- fix the underlying issue and re-run."
                    exit 2
                    ;;
                *)
                    echo "### $compensation/$scenario cm=$cm: benchmark.py" \
                         "exited with unexpected code $rc. Aborting sweep."
                    exit "$rc"
                    ;;
            esac
        done

        if [ "$succeeded" -eq 0 ]; then
            echo "### $compensation/$scenario: did not reach 100% by cm=$CM_MAX"
        fi
    done
done

echo
echo "all sweeps complete. results under results/"
