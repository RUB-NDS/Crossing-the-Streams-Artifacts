#!/usr/bin/env bash
# Sweep min_margin (μ) across {scenario} x {optimization}:
#   - scenarios:    direct, browser, browser_pna, ansible  (one per bench run)
#   - optimizations: NO, FS, AS, CE, FSCE, ASCE       (paper Table 2 labels)
#   - min_margin: start at 8, step +8, stop on first 100%-success run,
#                 give up after 128.
#
# Outputs land at:
#   results/{NO,FS,AS,CE,FSCE,ASCE}/benchmark_{results,summary}_{scenario}_mmN.{json,csv}
#
# Knobs (env vars):
#   STACKS           (default 20)   parallel docker-compose projects per run
#   TRIALS           (default 100)  passwords attempted per run
#   FIXED_AL_DIRECT  (default 2)    pinned alignment length for direct
#   FIXED_AL_ANSIBLE (default 1)    pinned alignment length for ansible
#   MM_START         (default 8)    starting min_margin
#   MM_STEP          (default 8)    increment
#   MM_MAX           (default 128)  upper bound (inclusive)
#   EARLY_EXIT       (default 1)    if 1, pass --early-exit to benchmark.py
#                                   so a doomed mm-step aborts on first
#                                   wrong commit instead of running every
#                                   trial to completion
#   MAX_RETRIES      (default 2)    on a failed recovery, retry the same
#                                   password this many extra times before
#                                   recording it as a true failure
#                                   (default = 3 attempts per password).
#                                   Absorbs transient noise before bumping mm.
#   HOST_PORTS       (default 0)    if 1, pass --host-ports to benchmark.py so
#                                   each stack is reached via a published
#                                   127.0.0.1 port instead of its bridge IP.
#                                   REQUIRED under rootless Docker / Docker
#                                   Desktop (bridge IPs aren't host-routable
#                                   there). Use a smaller STACKS there.
#
# Notes:
#   - browser and browser_pna are skipped for the fixed_single optimizations
#     (NO and CE) -- we have no fixed_al target for either; their noise floor
#     mandates the full alignment sweep.
#   - browser and browser_pna still run for FS, AS, FSCE, and ASCE.
#   - browser_pna uses benchmark.py's defaults (--seed-len 2, so only the
#     CR/LF-walled {length, pw0, pw1} are seeded). It attacks the default
#     8-char password, recovering the 6-byte tail; for a result whose recovered
#     portion is directly comparable to the 8-char browser column, run a
#     targeted `benchmark.py --scenarios browser_pna --password-length 10`
#     separately (2 seeded + 8 recovered). browser_pna's higher noise floor may
#     need MM_MAX raised above the default 128.

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
FIXED_AL_DIRECT="${FIXED_AL_DIRECT:-2}"
FIXED_AL_ANSIBLE="${FIXED_AL_ANSIBLE:-1}"
MM_START="${MM_START:-8}"
MM_STEP="${MM_STEP:-8}"
MM_MAX="${MM_MAX:-128}"
EARLY_EXIT="${EARLY_EXIT:-1}"
MAX_RETRIES="${MAX_RETRIES:-2}"
HOST_PORTS="${HOST_PORTS:-0}"

OPTIMIZATIONS=(NO FS AS CE FSCE ASCE)
SCENARIOS=(direct browser browser_pna ansible)

for optimization in "${OPTIMIZATIONS[@]}"; do
    out_dir="results/$optimization"
    mkdir -p "$out_dir"

    needs_fixed_al=0
    if [[ "$optimization" == "NO" || "$optimization" == "CE" ]]; then
        needs_fixed_al=1
    fi

    for scenario in "${SCENARIOS[@]}"; do
        # The browser-class scenarios (browser, browser_pna) have no fixed_al
        # target -- their noise floor mandates the full alignment sweep, so the
        # fixed_single optimizations (NO, CE) are n/a for both.
        if [ "$needs_fixed_al" -eq 1 ] && [[ "$scenario" == "browser" || "$scenario" == "browser_pna" ]]; then
            echo "--- skipping optimization=$optimization scenario=$scenario (no fixed-al target; full sweep mandatory) ---"
            continue
        fi

        extra_args=()
        if [ "$needs_fixed_al" -eq 1 ]; then
            case "$scenario" in
                direct)  extra_args+=(--fixed-al "$FIXED_AL_DIRECT")  ;;
                ansible) extra_args+=(--fixed-al "$FIXED_AL_ANSIBLE") ;;
            esac
        fi

        echo "============================================================"
        echo "  optimization=$optimization  scenario=$scenario"
        if [ "${#extra_args[@]}" -gt 0 ]; then
            echo "  extra args: ${extra_args[*]}"
        fi
        echo "============================================================"

        succeeded=0
        mm=$MM_START
        while [ "$mm" -le "$MM_MAX" ]; do
            results_json="$out_dir/benchmark_results_${scenario}_mm${mm}.json"
            summary_csv="$out_dir/benchmark_summary_${scenario}_mm${mm}.csv"
            echo ">>> $optimization/$scenario min_margin=$mm  -> $results_json"

            ee_args=()
            if [ "$EARLY_EXIT" = "1" ]; then
                ee_args+=(--early-exit)
            fi
            if [ "$HOST_PORTS" = "1" ]; then
                ee_args+=(--host-ports)
            fi
            python3 -u scripts/benchmark.py \
                --stacks "$STACKS" \
                --trials "$TRIALS" \
                --scenarios "$scenario" \
                --optimization "$optimization" \
                --min-margin "$mm" \
                --max-retries "$MAX_RETRIES" \
                --output "$results_json" \
                --csv-summary "$summary_csv" \
                "${ee_args[@]}" \
                "${extra_args[@]}" 2>&1 | filter_docker_noise
            # PIPESTATUS[0] is benchmark.py's exit; filter is awk (always 0).
            rc=${PIPESTATUS[0]}
            case "$rc" in
                0)
                    echo "### $optimization/$scenario mm=$mm: 100% success -- stop"
                    succeeded=1
                    break
                    ;;
                1)
                    echo "### $optimization/$scenario mm=$mm: not yet 100% -- increasing"
                    mm=$((mm + MM_STEP))
                    ;;
                2)
                    echo "### $optimization/$scenario mm=$mm: TECHNICAL FAILURE" \
                         "(infrastructure error, not an algorithmic miss)." \
                         "Aborting entire sweep -- fix the underlying issue and re-run."
                    exit 2
                    ;;
                *)
                    echo "### $optimization/$scenario mm=$mm: benchmark.py" \
                         "exited with unexpected code $rc. Aborting sweep."
                    exit "$rc"
                    ;;
            esac
        done

        if [ "$succeeded" -eq 0 ]; then
            echo "### $optimization/$scenario: did not reach 100% by mm=$MM_MAX"
        fi
    done
done

echo
echo "all sweeps complete. results under results/"
