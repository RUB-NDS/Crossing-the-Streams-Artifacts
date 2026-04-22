# Fork-on-stall — design

**Status:** spec, pre-implementation.
**Context:** Follow-up to `2026-04-22-unified-attack-design.md` §"Future work:
candidate fork on stall (BEAST signal edge case)". Addresses BEAST's empirical
failure to commit `hunte` at position 4 of `hunter2` (commits `huntc` instead)
even after the flush-bias fix.

## Problem

The BEAST adapter's per-round signal exhibits a persistent, non-random bias
at some byte positions that averaging across rounds cannot clear. The
existing `stall_detection` optimization expands the alignment sweep on
stall but cannot fix a position whose underlying signal is ambiguous
between the correct candidate and a near-rival. When `crack_byte_position`
exhausts `max_rounds` without reaching `min_margin`, it currently commits
the best-margin candidate, which can be wrong — propagating to all
downstream positions.

## Idea

When a position stalls, speculatively run the *next* position for each of
the top-K candidates at the stalled position. Only the correct branch
produces a clean signal at the next position; wrong branches either stall
again or commit a nonsense byte with a weak margin. The branch whose next
position cleanly commits disambiguates the stalled position.

Successful speculative runs are not thrown away — they commit the next
position too, so a 1-ply fork that wins advances the attack by two
positions at once; a 2-ply fork that wins advances by three.

## Algorithm

### Trigger

Fork fires at position N when `crack_byte_position` exhausts `max_rounds`
without reaching `min_margin`, *and* all of:

- `config.candidate_fork_on_stall == True`
- `depth < config.max_fork_depth`
- `position + depth + 1 < config.max_length`
- After terminator filtering, there are at least 2 forkable candidates in
  the top-K by margin.

If fork is not applicable, fall back to the existing best-margin commit at
N and resume the main loop at N+1.

### Branch selection

From the stalled position's `sums` (accumulated wire-byte totals per
candidate), take the `fork_top_k` candidates ordered ascending by `sums[c]`.
Drop `config.terminator` if it appears in that list. The remainder are the
fork branches.

If fewer than 2 branches remain after terminator filtering, skip fork
(record `fork_info.reason = "insufficient_branches"`).

### Recursion

For each branch `c`:

1. Construct `hypothetical_prefix = committed_prefix + c`.
2. Apply the same `constant_prefix_trim` that the main loop would apply.
3. Select `initial_alignment` from the same N-1 hint the main loop used at
   position N — shared across all branches.
4. Call `crack_byte_position(adapter, config, hypothetical_prefix,
   initial_alignment, log_prefix=f"pos {N+1:2d} fork[{c!r}]")`.

Collect results as `branch_results: list[tuple[bytes, dict]]`.

### Winner rule

Classify by how many branch results are clean commits (margin ≥ min_margin):

| Clean count | Action |
|---|---|
| 1 | **Unique winner.** Return `[fork_N_result, winner_N+1_result]`. Main loop resumes at N+2. |
| 2+ | **Ambiguous.** Recurse to depth+1 using only the cleanly-committing branches as parents. |
| 0 | **All stalled.** Recurse to depth+1 using all branches with their best-margin N+1 commits as tentative parents. |

Recursion terminates by:

- Hitting `max_fork_depth`: fall back to best-margin at N, return
  `[best_margin_fallback_result]`. The N+1 position will be re-attempted by
  the main loop.
- Producing a unique winner at some depth D ≥ 1: each depth's winner
  contributes its clean commit. A winner at depth D commits positions
  N, N+1, ..., N+D.

When recursing to depth+1, each carried-forward parent branch extends its
prefix by one byte for the next round of speculation:

- For a 2+-clean parent: the committed-at-N+1 byte is appended.
  `hypothetical_prefix_depth+1 = committed_prefix + c_N + cleanly_committed_N+1`.
- For a 0-clean parent: the best-margin-at-N+1 byte is appended (tentative).
  `hypothetical_prefix_depth+1 = committed_prefix + c_N + best_margin_N+1`.

The speculated position advances to N+2, then N+3, etc., as recursion
deepens. The alignment hint still comes from the last cleanly-committed
position *before* the original stall N (unchanged across depths).

### Alignment hint carryover

All branches at every depth inherit the same alignment hint — the
`successful_alignment` of the last cleanly-committed position before N
(what the main loop already tracks as `prev_nl`). Post-fork, the main
loop's `prev_nl` updates to the deepest winner's `successful_alignment`,
so subsequent positions use the right hint.

## Code surface

### `attacker/attack/config.py`

Add three fields to `AttackConfig` (with dataclass defaults):

```python
candidate_fork_on_stall: bool = True
fork_top_k: int = 5
max_fork_depth: int = 2
```

No changes to `overlay()` — the fields marshal as plain bool / int.

### `attacker/attack/engine.py`

**Return shape of `crack_byte_position`.** Add `clean_commit: bool` to the
`pos_info` dict so callers can test for stall without re-deriving it from
`final_margin >= min_margin`. Add `sums: dict[str, int]` (stringified keys
for JSON-friendliness) so the fork orchestrator can select the full top-K
beyond the existing `ranked_top5`.

**New pure helpers (unit-tested):**

```python
def _select_fork_branches(
    pos_info: dict, top_k: int, terminator: bytes,
) -> list[bytes]:
    """Top-K candidates by ascending sums, with terminator filtered out."""

def _classify_fork_outcome(
    branch_results: list[tuple[bytes, dict]],
) -> tuple[Literal["unique", "multi", "zero"], list[int]]:
    """Returns (class, indices_of_clean_branches)."""

def _fork_applicable(
    config: AttackConfig,
    position: int,
    pos_info: dict,
    depth: int,
) -> bool:
    """All preconditions for triggering a fork at this position/depth."""
```

**New orchestrator (async):**

```python
async def resolve_stalled_position(
    adapter: Adapter,
    config: AttackConfig,
    committed_prefix: bytes,
    position: int,
    stalled_pos_info: dict,
    alignment_hint: int | None,
    depth: int,
) -> list[dict]:
    """
    Returns 1..(max_fork_depth+1) position-info dicts. The first is the
    stalled position's final result (with fork_info merged in). Each
    subsequent dict is a position committed via a fork winner (with
    via_fork=True and fork_origin set).

    On recursion exhaustion, returns a single best-margin fallback dict.
    """
```

**`run_attack` main loop change.** Replace the `for pos in range(max_length):`
loop with a `while position < max_length:` loop that consumes 1..N position
dicts per iteration:

The inline `constant_prefix_trim` logic in the existing `for pos in
range(...)` body is extracted into a small pure helper `_trimmed_prefix(
known_prefix, recovered, config) -> bytes` so both the main loop and the
fork orchestrator use identical trimming without duplication.

```python
position = 0
done = False
while position < config.max_length and not done:
    full_prefix = _trimmed_prefix(config.known_prefix, recovered, config)
    initial_alignment = _select_initial_alignment(config, prev_nl)

    best, pos_info = await crack_byte_position(
        adapter, config, full_prefix, initial_alignment,
        log_prefix=f"pos {position:2d}",
    )
    pos_info["position"] = position

    if pos_info["clean_commit"] or not _fork_applicable(
        config, position, pos_info, depth=0,
    ):
        committed = [pos_info]
    else:
        committed = await resolve_stalled_position(
            adapter, config, recovered, position,
            pos_info, prev_nl, depth=0,
        )
        # First entry is pos_info with fork_info merged in; subsequent
        # entries are positions committed via fork winners.

    for pr in committed:
        best_byte = pr["best"].encode("latin-1")
        per_position.append(pr)
        prev_nl = pr["successful_alignment"]
        if best_byte == config.terminator:
            done = True
            break
        recovered += best_byte

    position += len(committed)
```

Terminator handling within a multi-commit return: if any committed
position's `best` is the terminator, stop processing further committed
entries and exit the outer loop. The terminator case is unlikely under
fork (terminator is filtered from branches), but defensive handling covers
the rare case where a winner's own deeper commit is the terminator.

### Adapter `default_config()`s

Each of `DirectAdapter`, `BeastAdapter`, `AnsibleAdapter` sets the new fields
explicitly to the same defaults (`True`, `5`, `2`), making the policy
discoverable per-adapter rather than buried in the dataclass default.

### `scripts/benchmark.py`

`SCENARIO_PRESETS` is unchanged — fork-on-stall is not a preset-toggled
dimension. Two new columns in `benchmark_summary.csv`, derived per trial
from `per_position`:

- `fork_triggered_positions` — count of positions where `fork_info` is
  present and `triggered == True`.
- `fork_overhead_guesses` — sum of `fork_info.losers_guesses` across
  positions. This is the "wasted" work the fork protocol added compared
  to a hypothetical oracle that always committed N+1 on the first try; a
  winning branch's N+1 work would have been done by the main loop anyway,
  so it is not overhead. Can be compared to `total_guesses` to report a
  fork-overhead percentage.

Existing columns unchanged. JSON dump auto-carries the new fields through
the existing `json.dump`.

### `attacker/mitm.py`

No code changes. `/run_attack`'s request body passes through arbitrary
config fields via `AttackConfig.overlay()`, so callers can set
`candidate_fork_on_stall`, `fork_top_k`, `max_fork_depth` without endpoint
changes.

## Per-position output shape

### Position that triggered a fork (origin, winner found):

```json
{
  "position": 4,
  "best": "e",
  "guesses": 15200,
  "rounds": 16,
  "final_margin": 12,
  "successful_alignment": 3,
  "ranked_top5": [["e", 73280], ["c", 73292], ["k", 73404], ...],
  "clean_commit": false,
  "via_fork": false,
  "fork_origin": null,
  "fork_info": {
    "triggered": true,
    "depth_used": 1,
    "branches_run": 3,
    "losers_guesses": 11080,
    "total_fork_guesses": 13927,
    "reason": null,
    "outcome": "unique_clean",
    "committed_via_fork": [5]
  }
}
```

The origin's `clean_commit` is `false` — a fork-triggering position is by
definition one that did not commit cleanly. Its `guesses` = stall work
(4120) + losing branches' N+1 work (11080) = 15200. `fork_info.losers_guesses`
(11080) is the subset attributable to losers; `total_fork_guesses` (13927)
is the full fork-protocol cost including the winning branch's work at
position 5 (2847), provided as a summary for analysis. These two fields are
informational — the `total_guesses` sum in the attack response does *not*
use `fork_info`; it sums per-position `guesses` only.

### Position committed via a fork winner:

```json
{
  "position": 5,
  "best": "r",
  "guesses": 2847,
  "rounds": 4,
  "final_margin": 32,
  "successful_alignment": 3,
  "ranked_top5": [...],
  "clean_commit": true,
  "via_fork": true,
  "fork_origin": 4,
  "fork_info": null
}
```

### Position that stalled and exhausted fork:

```json
{
  "position": 4,
  "best": "e",
  "guesses": 50000,
  ...,
  "clean_commit": false,
  "via_fork": false,
  "fork_origin": null,
  "fork_info": {
    "triggered": true,
    "depth_used": 2,
    "branches_run": 9,
    "losers_guesses": 45880,
    "total_fork_guesses": 45880,
    "reason": null,
    "outcome": "best_margin_fallback",
    "committed_via_fork": []
  }
}
```

On fallback, every branch is a "loser" (no unique winner), so
`losers_guesses == total_fork_guesses`. The main loop resumes at position 5
and re-attempts it from scratch — the fork-exhausted origin takes
best-margin at position 4.

### Position that skipped fork (e.g., terminator-only in top-K):

```json
{
  "position": N,
  "best": "...",
  "clean_commit": false,
  "via_fork": false,
  "fork_origin": null,
  "fork_info": {
    "triggered": false,
    "depth_used": 0,
    "branches_run": 0,
    "losers_guesses": 0,
    "total_fork_guesses": 0,
    "reason": "insufficient_branches",
    "outcome": null,
    "committed_via_fork": []
  }
}
```

`fork_info` always has this full shape when present; all fields are
populated (with zeros / nulls where inapplicable). Positions that never
stalled have `fork_info: null` — the shape difference between "null" and
"present with triggered=false" is what distinguishes "never considered
fork" from "considered but skipped".

## Accounting rule (restated)

- Each position's `guesses` is the work attributable to committing *that*
  position.
- Losing-branch work is attributed to the fork origin position.
- Winning-branch work is attributed to the position that was committed by
  that branch's clean signal.
- `total_guesses` in the `/run_attack` response = `sum(p["guesses"] for p
  in per_position)`. No double-counting.

## Testing

### Unit tests (`attacker/attack/tests/test_fork.py`)

Plain-assertion style matching existing tests.

- `_select_fork_branches`:
  - terminator in top-K → filtered out
  - fewer than 2 non-terminator candidates in top-K → empty list
  - top-K respects requested size
- `_classify_fork_outcome`:
  - unique clean → `("unique", [winner_idx])`
  - two clean → `("multi", [idx1, idx2])`
  - zero clean → `("zero", [])`
- `_fork_applicable`:
  - config off → False
  - depth ≥ max_fork_depth → False
  - position + depth + 1 ≥ max_length → False
  - clean_commit True → False (shouldn't be called in that case, but guard)
  - all preconditions met → True
- `resolve_stalled_position` with `crack_byte_position` monkey-patched to a
  scripted fake, covering:
  - 1-ply unique winner: returns 2 position dicts, origin has `fork_info`,
    next has `via_fork=True`
  - 1-ply multi-clean → 2-ply unique: returns 3 position dicts
  - 1-ply zero-clean → 2-ply best-margin: returns 1 position dict with
    `outcome="best_margin_fallback"`
  - terminator in top-K: filtered; fork runs on remaining branches
  - fewer than 2 forkable branches: returns 1 dict with
    `reason="insufficient_branches"`

No adapter I/O in unit tests.

### Host-level acceptance

All three `verify_*.py` scripts must continue to recover `hunter2`.

- `verify_direct.py` — fork should almost never fire (direct's signal is
  clean). Regression signal: if `total_guesses` increases meaningfully vs.
  pre-feature baseline, `_fork_applicable` is firing when it shouldn't.
- `verify_ansible.py` — same expectation (cleanest signal).
- **`verify_beast.py` — acceptance-defining.** Must recover `hunter2`
  end-to-end with `fork_info.triggered = True` and
  `outcome = "unique_clean"` at position 4 (or wherever the stall now
  lands); `committed_via_fork` non-empty.

### Benchmark smoke test

```bash
python scripts/benchmark.py --stacks 2 --trials 4 --scenario all-opts --variants beast
```

Confirms the feature composes with the existing optimizations and does not
blow up trial durations disproportionately.

## Out of scope

- Measuring fork-on-stall's numeric benefit (how many trials would fail
  without it). Researchers can use `--config my.json` with
  `candidate_fork_on_stall=false` to A/B it once the feature ships.
- Fixing any *new* BEAST failure modes exposed by the feature (if pos 4
  passes but some other position now stalls, triage separately).
- Fork depth > 2. The dataclass field `max_fork_depth` accepts larger
  values, but the spec's algorithmic guarantees are designed around depth
  ≤ 2; 3-ply and beyond may produce pathological branching explosions that
  are not addressed here.
- Parallelising branch execution across concurrent adapters. All
  branches run sequentially on the same adapter instance.

## Migration

1. Land the three config fields + pure helpers + `resolve_stalled_position`
   + unit tests. Existing `crack_byte_position` signature gains `sums` and
   `clean_commit` in the returned dict; unchanged callers ignore them.
2. Rewire `run_attack`'s main loop to the while-based form. Verify direct
   and ansible recover `hunter2` — neither should trigger fork under
   normal conditions.
3. Run `verify_beast.py` end-to-end; confirm `hunter2` recovery and
   expected `fork_info` shape.
4. Add the two derived columns to `benchmark.py`'s CSV aggregator.
5. Update `README.md` §"Results" to reflect BEAST now passing, and add a
   short subsection under §"How the attack works" describing the fallback.
