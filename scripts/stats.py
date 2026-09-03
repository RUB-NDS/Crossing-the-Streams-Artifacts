"""Per-attack guess-count stats over a benchmark_results.json.

One attack = one (password, scenario) trial. Aggregates `total_guesses`
across trials where `ok == true`.

Usage:
    python scripts/stats.py benchmark_results.json
"""

import json
import statistics
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
xs = [r["total_guesses"] for r in data["results"] if r.get("ok")]

if not xs:
    sys.exit("no successful trials")

print(f"n      : {len(xs)}")
print(f"min    : {min(xs)}")
print(f"max    : {max(xs)}")
print(f"mean   : {statistics.mean(xs):.1f}")
print(f"median : {statistics.median(xs):.1f}")
print(f"stdev  : {statistics.stdev(xs):.1f}" if len(xs) > 1 else "stdev  : n/a")
