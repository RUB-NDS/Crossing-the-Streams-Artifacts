#!/usr/bin/env bash
# Sweep min_margin across {variant} x {scenario}:
#   - variants:  direct, beast, ansible   (one per benchmark run)
#   - scenarios: baseline, full-sweep, candidate-elimination, all-opts
#   - min_margin: start at 8, step +8, stop on first 100%-success run,
#                 give up after 128.
#
# Outputs land at:
#   results/{baseline,sweep,elim,full}/benchmark_{results,summary}_{variant}_mmN.{json,csv}
#
# Knobs (env vars):
#   STACKS           (default 4)    parallel docker-compose projects per run
#   TRIALS           (default 50)   passwords attempted per run
#   FIXED_NL_DIRECT  (default 2)    pinned alignment length for direct
#   FIXED_NL_ANSIBLE (default 1)    pinned alignment length for ansible
#   MM_START         (default 8)    starting min_margin
#   MM_STEP          (default 8)    increment
#   MM_MAX           (default 128)  upper bound (inclusive)
#
# Notes:
#   - beast is skipped for baseline + candidate-elimination (these use
#     fixed_single alignment and we have no fixed_nl target for beast).
#   - beast still runs for full-sweep + all-opts (no --fixed-nl needed).

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STACKS="${STACKS:-16}"
TRIALS="${TRIALS:-100}"
FIXED_NL_DIRECT="${FIXED_NL_DIRECT:-2}"
FIXED_NL_ANSIBLE="${FIXED_NL_ANSIBLE:-1}"
MM_START="${MM_START:-8}"
MM_STEP="${MM_STEP:-8}"
MM_MAX="${MM_MAX:-128}"

# scenario_key -> benchmark.py --scenario preset name
declare -A PRESET=(
    [baseline]=baseline
    [sweep]=full-sweep
    [elim]=candidate-elimination
    [full]=all-opts
)
SCENARIO_ORDER=(baseline sweep elim full)
VARIANTS=(direct beast ansible)

for scenario_key in "${SCENARIO_ORDER[@]}"; do
    preset="${PRESET[$scenario_key]}"
    out_dir="results/$scenario_key"
    mkdir -p "$out_dir"

    needs_fixed_nl=0
    if [[ "$preset" == "baseline" || "$preset" == "candidate-elimination" ]]; then
        needs_fixed_nl=1
    fi

    for variant in "${VARIANTS[@]}"; do
        # beast has no fixed-nl target — skip fixed_single scenarios.
        if [ "$needs_fixed_nl" -eq 1 ] && [ "$variant" == "beast" ]; then
            echo "--- skipping scenario=$scenario_key variant=beast (no fixed-nl target) ---"
            continue
        fi

        extra_args=()
        if [ "$needs_fixed_nl" -eq 1 ]; then
            case "$variant" in
                direct)  extra_args+=(--fixed-nl "$FIXED_NL_DIRECT")  ;;
                ansible) extra_args+=(--fixed-nl "$FIXED_NL_ANSIBLE") ;;
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

            if python3 scripts/benchmark.py \
                --stacks "$STACKS" \
                --trials "$TRIALS" \
                --variants "$variant" \
                --scenario "$preset" \
                --min-margin "$mm" \
                --output "$results_json" \
                --csv-summary "$summary_csv" \
                "${extra_args[@]}"; then
                echo "### $scenario_key/$variant mm=$mm: 100% success — stop"
                succeeded=1
                break
            fi

            echo "### $scenario_key/$variant mm=$mm: not yet 100% — increasing"
            mm=$((mm + MM_STEP))
        done

        if [ "$succeeded" -eq 0 ]; then
            echo "### $scenario_key/$variant: did not reach 100% by mm=$MM_MAX"
        fi
    done
done

echo
echo "all sweeps complete. results under results/"
