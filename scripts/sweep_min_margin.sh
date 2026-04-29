#!/usr/bin/env bash
# Sweep min_margin (μ) across {variant} x {scenario}:
#   - variants:  direct, browser, ansible           (one per benchmark run)
#   - scenarios: baseline, full-sweep, adaptive-sweep,
#                candidate-elimination, all-opts
#   - min_margin: start at 8, step +8, stop on first 100%-success run,
#                 give up after 128.
#
# Outputs land at:
#   results/{baseline,sweep,adaptive,elim,full}/benchmark_{results,summary}_{variant}_mmN.{json,csv}
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
#
# Notes:
#   - browser is skipped for baseline + candidate-elimination (these use
#     fixed_single alignment and we have no fixed_al target for browser).
#   - browser still runs for full-sweep + adaptive-sweep + all-opts (no
#     --fixed-al needed).

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

declare -A PRESET=(
    [baseline]=baseline
    [sweep]=full-sweep
    [adaptive]=adaptive-sweep
    [elim]=candidate-elimination
    [full]=all-opts
)
SCENARIO_ORDER=(baseline sweep adaptive elim full)
VARIANTS=(direct browser ansible)

for scenario_key in "${SCENARIO_ORDER[@]}"; do
    preset="${PRESET[$scenario_key]}"
    out_dir="results/$scenario_key"
    mkdir -p "$out_dir"

    needs_fixed_al=0
    if [[ "$preset" == "baseline" || "$preset" == "candidate-elimination" ]]; then
        needs_fixed_al=1
    fi

    for variant in "${VARIANTS[@]}"; do
        if [ "$needs_fixed_al" -eq 1 ] && [ "$variant" == "browser" ]; then
            echo "--- skipping scenario=$scenario_key variant=browser (no fixed-al target) ---"
            continue
        fi

        extra_args=()
        if [ "$needs_fixed_al" -eq 1 ]; then
            case "$variant" in
                direct)  extra_args+=(--fixed-al "$FIXED_AL_DIRECT")  ;;
                ansible) extra_args+=(--fixed-al "$FIXED_AL_ANSIBLE") ;;
            esac
        fi

        echo "============================================================"
        echo "  scenario=$scenario_key ($preset)  variant=$variant"
        if [ "${#extra_args[@]}" -gt 0 ]; then
            echo "  extra args: ${extra_args[*]}"
        fi
        echo "============================================================"

        succeeded=0
        mm=$MM_START
        while [ "$mm" -le "$MM_MAX" ]; do
            results_json="$out_dir/benchmark_results_${variant}_mm${mm}.json"
            summary_csv="$out_dir/benchmark_summary_${variant}_mm${mm}.csv"
            echo ">>> $scenario_key/$variant min_margin=$mm  -> $results_json"

            ee_args=()
            if [ "$EARLY_EXIT" = "1" ]; then
                ee_args+=(--early-exit)
            fi
            python3 -u scripts/benchmark.py \
                --stacks "$STACKS" \
                --trials "$TRIALS" \
                --variants "$variant" \
                --scenario "$preset" \
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
                    echo "### $scenario_key/$variant mm=$mm: 100% success -- stop"
                    succeeded=1
                    break
                    ;;
                1)
                    echo "### $scenario_key/$variant mm=$mm: not yet 100% -- increasing"
                    mm=$((mm + MM_STEP))
                    ;;
                2)
                    echo "### $scenario_key/$variant mm=$mm: TECHNICAL FAILURE" \
                         "(infrastructure error, not an algorithmic miss)." \
                         "Aborting entire sweep -- fix the underlying issue and re-run."
                    exit 2
                    ;;
                *)
                    echo "### $scenario_key/$variant mm=$mm: benchmark.py" \
                         "exited with unexpected code $rc. Aborting sweep."
                    exit "$rc"
                    ;;
            esac
        done

        if [ "$succeeded" -eq 0 ]; then
            echo "### $scenario_key/$variant: did not reach 100% by mm=$MM_MAX"
        fi
    done
done

echo
echo "all sweeps complete. results under results/"
