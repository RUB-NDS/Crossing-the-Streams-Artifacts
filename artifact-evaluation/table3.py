"""Recompute Table 3 from a tree of benchmark results.

Table 3 reports, per (scenario, noise-compensation configuration), the
guess counts of the commit-margin step at which every trial recovered the
password. `scripts/sweep_commit_margin.sh` walks the margin upward in
8-byte steps and keeps one results file per step, so the converged cell is
the *lowest* margin whose run has `success: true` (100 % recovery).

This script finds that run for every cell and prints the aggregate. It is
the zero-cost reproduction of Table 3: it reads committed data and runs in
under a second, so a reviewer can check the paper's numbers without
spending the days a full re-measurement costs.

Usage:
    python artifact-evaluation/table3.py                 # committed data
    python artifact-evaluation/table3.py results         # a fresh sweep
    python artifact-evaluation/table3.py --csv           # machine-readable

The committed tree is scenario-first with lowercase labels
(evaluation/direct/as+ce/); a fresh sweep writes compensation-first with
uppercase ones (results/AS+CE/). Both layouts are accepted.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
from pathlib import Path

SCENARIOS = ["direct", "browser", "ansible"]
COMPENSATIONS = ["NO", "FS", "AS", "CE", "AS+CE"]
_CM_RE = re.compile(r"benchmark_results_(?P<scenario>[a-z]+)_cm(?P<cm>\d+)\.json$")


def _cells(root: Path) -> dict[tuple[str, str], list[tuple[int, Path]]]:
    """Map (scenario, COMPENSATION) -> [(commit_margin, path), ...].

    Accepts both the scenario-first committed layout and the
    compensation-first layout a fresh sweep writes.
    """
    out: dict[tuple[str, str], list[tuple[int, Path]]] = {}
    for path in sorted(root.rglob("benchmark_results_*_cm*.json")):
        m = _CM_RE.search(path.name)
        if not m:
            continue
        scenario = m.group("scenario")
        parts = [p.lower() for p in path.relative_to(root).parts[:-1]]
        comp = next(
            (p.upper() for p in parts if p.upper() in COMPENSATIONS), None,
        )
        if comp is None or scenario not in SCENARIOS:
            continue
        out.setdefault((scenario, comp), []).append((int(m.group("cm")), path))
    return out


def _converged(runs: list[tuple[int, Path]]) -> tuple[int, dict] | None:
    """Lowest commit margin whose run recovered every password."""
    for cm, path in sorted(runs):
        data = json.loads(path.read_text())
        if data.get("success"):
            return cm, data
    return None


def _stats(data: dict) -> dict[str, float | int]:
    xs = [r["total_guesses"] for r in data["results"] if r.get("ok")]
    return {
        "n": len(xs),
        "min": min(xs),
        "max": max(xs),
        "mean": statistics.mean(xs),
        "median": statistics.median(xs),
        "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0,
    }


def main(argv: list[str]) -> int:
    as_csv = "--csv" in argv
    rest = [a for a in argv if not a.startswith("--")]
    root = Path(rest[0]) if rest else Path("evaluation")
    if not root.is_dir():
        print(f"!! no such directory: {root}", file=sys.stderr)
        return 2

    cells = _cells(root)
    if not cells:
        print(f"!! no benchmark_results_*_cm*.json under {root}", file=sys.stderr)
        return 2

    rows = []
    for scenario in SCENARIOS:
        for comp in COMPENSATIONS:
            runs = cells.get((scenario, comp))
            if not runs:
                rows.append((scenario, comp, None, None))
                continue
            found = _converged(runs)
            if found is None:
                # Sweep never reached 100 %; report the best step so the
                # reviewer sees an honest "not converged" rather than a gap.
                best_cm, best = max(
                    ((cm, json.loads(p.read_text())) for cm, p in runs),
                    key=lambda t: t[1]["summary"][t[1]["config"]["scenarios"][0]]["trials_passed"],
                )
                rows.append((scenario, comp, -best_cm, _stats(best)))
                continue
            cm, data = found
            rows.append((scenario, comp, cm, _stats(data)))

    if as_csv:
        print("scenario,compensation,commit_margin,n,min,max,mean,median,stdev")
        for sc, comp, cm, st in rows:
            if cm is None:
                print(f"{sc},{comp},n/a,,,,,,")
            else:
                print(f"{sc},{comp},{abs(cm)}{'*' if cm < 0 else ''},"
                      f"{st['n']},{st['min']},{st['max']},"
                      f"{st['mean']:.1f},{st['median']:.1f},{st['stdev']:.1f}")
        return 0

    print(f"Table 3 recomputed from {root}/")
    print("Guesses per recovered password, at the commit margin (mu) where")
    print("the sweep first reached 100 % recovery.\n")
    hdr = (f"{'scenario':9s} {'config':6s} {'mu':>4s} {'n':>4s} "
           f"{'mean':>9s} {'median':>9s} {'stdev':>9s} {'min':>8s} {'max':>8s}")
    print(hdr)
    print("-" * len(hdr))
    for sc, comp, cm, st in rows:
        if cm is None:
            print(f"{sc:9s} {comp:6s} {'n/a':>4s} {'':>4s} "
                  f"{'':>9s} {'':>9s} {'':>9s} {'':>8s} {'':>8s}")
            continue
        mark = "*" if cm < 0 else " "
        print(f"{sc:9s} {comp:6s} {abs(cm):4d}{mark[0] if cm<0 else ''} "
              f"{st['n']:4d} {st['mean']:9.1f} {st['median']:9.1f} "
              f"{st['stdev']:9.1f} {st['min']:8d} {st['max']:8d}")
    if any(cm is not None and cm < 0 for _, _, cm, _ in rows):
        print("\n* this cell never reached 100 % recovery; the best step is shown.")
    print("\nn/a cells: browser NO and CE presuppose a known winning alignment")
    print("length, which the browser noise floor does not support.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
