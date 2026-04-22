# Fork-on-Stall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement fork-on-stall — a correctness fallback for the unified
attack engine that speculatively runs the next position when a stalled
position can't commit cleanly, disambiguating the stalled position while
also committing the next position(s) on success. Addresses BEAST's
empirical failure to recover `hunte` at pos 4 of `hunter2` (commits
`huntc` instead).

**Architecture:** Engine-level change in `attacker/attack/engine.py`. Four
new pure helpers (`_select_fork_branches`, `_classify_fork_outcome`,
`_fork_applicable`, `_trimmed_prefix`) unit-tested against scripted
fixtures. One new async orchestrator `resolve_stalled_position` recurses
up to `max_fork_depth` calling `crack_byte_position` on each branch
hypothesis. Adapter-agnostic; all three adapters inherit the feature
automatically via their `default_config()`s. No new HTTP endpoints.

**Tech Stack:** Python 3.14, asyncio, existing aiohttp adapter protocol,
plain-assertion unit tests (no pytest — tests run via `python -m
attacker.attack.tests.<module>`).

**Reference:** The approved spec is
`docs/superpowers/specs/2026-04-22-fork-on-stall-design.md`. Every task
below cites sections when clarification is needed.

---

### Task 1: Add fork config fields to `AttackConfig`

**Files:**
- Modify: `attacker/attack/config.py`
- Modify test: `attacker/attack/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Add to `attacker/attack/tests/test_config.py` above the `if __name__` block:

```python
def test_fork_fields_default_on_and_tuned():
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.candidate_fork_on_stall is True
    assert cfg.fork_top_k == 5
    assert cfg.max_fork_depth == 2


def test_overlay_fork_fields():
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({
        "candidate_fork_on_stall": False,
        "fork_top_k": 7,
        "max_fork_depth": 3,
    })
    assert overridden.candidate_fork_on_stall is False
    assert overridden.fork_top_k == 7
    assert overridden.max_fork_depth == 3
```

Also add the two function calls inside the `if __name__ == "__main__":` block at the bottom of the file:

```python
    test_fork_fields_default_on_and_tuned()
    test_overlay_fork_fields()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_config`
Expected: `AttributeError: 'AttackConfig' object has no attribute 'candidate_fork_on_stall'`

- [ ] **Step 3: Add the three fields to `AttackConfig`**

Modify `attacker/attack/config.py`. Locate the `@dataclass` block, add three fields after `measurement_min_segment_size`:

```python
    measurement_min_segment_size: int

    candidate_fork_on_stall: bool = True
    fork_top_k: int = 5
    max_fork_depth: int = 2

    label: str = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_config`
Expected: `config tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/config.py attacker/attack/tests/test_config.py
git commit -m "feat(engine): Add fork-on-stall config fields to AttackConfig"
```

---

### Task 2: Extract `_trimmed_prefix` helper

**Files:**
- Modify: `attacker/attack/engine.py`
- Modify test: `attacker/attack/tests/test_engine_helpers.py`

Rationale: `run_attack` inlines constant-prefix trimming logic that will
also be needed by `resolve_stalled_position`. Extract as a pure helper
once, share both call sites (DRY).

- [ ] **Step 1: Write the failing test**

Add to `attacker/attack/tests/test_engine_helpers.py` above the `if __name__` block:

```python
from attacker.attack.engine import _trimmed_prefix


def test_trimmed_prefix_no_recovered_bytes_is_identity():
    cfg = _cfg(constant_prefix_trim=True)
    assert _trimmed_prefix(b"AUTH ", b"", cfg) == b"AUTH "


def test_trimmed_prefix_trims_head_when_recovered_grows():
    cfg = _cfg(constant_prefix_trim=True)
    # known="AUTH ", recovered="hu" -> full="AUTH hu" (7 bytes)
    # trim = 7 - len("AUTH ") = 2 -> "TH hu"
    assert _trimmed_prefix(b"AUTH ", b"hu", cfg) == b"TH hu"


def test_trimmed_prefix_trim_disabled_appends_without_trimming():
    cfg = _cfg(constant_prefix_trim=False)
    assert _trimmed_prefix(b"AUTH ", b"hu", cfg) == b"AUTH hu"
```

Add corresponding calls to the `if __name__ == "__main__":` block:

```python
    test_trimmed_prefix_no_recovered_bytes_is_identity()
    test_trimmed_prefix_trims_head_when_recovered_grows()
    test_trimmed_prefix_trim_disabled_appends_without_trimming()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_engine_helpers`
Expected: `ImportError: cannot import name '_trimmed_prefix' from 'attacker.attack.engine'`

- [ ] **Step 3: Implement `_trimmed_prefix` in engine.py**

Modify `attacker/attack/engine.py`. Add after the existing `_select_initial_alignment` function (around line 62):

```python
def _trimmed_prefix(
    known_prefix: bytes, recovered: bytes, config: AttackConfig,
) -> bytes:
    """Return the prefix that should be injected at the current position.

    When constant_prefix_trim is on, keep len(prefix) constant across
    positions by trimming the head of (known_prefix + recovered) so that
    its total length equals len(known_prefix). Keeps LZ77 match lengths
    in the same DEFLATE length-code bin at every position.
    """
    full = known_prefix + recovered
    if config.constant_prefix_trim:
        trim = max(0, len(full) - len(known_prefix))
        full = full[trim:]
    return full
```

- [ ] **Step 4: Replace the inline logic in `run_attack`**

Still in `attacker/attack/engine.py`, inside `run_attack`, replace the block:

```python
            for pos in range(config.max_length):
                full_prefix = config.known_prefix + recovered
                if config.constant_prefix_trim:
                    trim = max(0, len(full_prefix) - len(config.known_prefix))
                    full_prefix = full_prefix[trim:]
```

with:

```python
            for pos in range(config.max_length):
                full_prefix = _trimmed_prefix(
                    config.known_prefix, recovered, config,
                )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_engine_helpers`
Expected: `engine-helper tests: ok`

- [ ] **Step 6: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_engine_helpers.py
git commit -m "refactor(engine): Extract _trimmed_prefix helper for reuse"
```

---

### Task 3: Augment `crack_byte_position` return dict

**Files:**
- Modify: `attacker/attack/engine.py`

No new tests here — the augmented fields are exercised by tasks 4+ via the
fake `crack_byte_position` used in fork-orchestrator tests, and by the
verify scripts end-to-end. Downstream consumers of the dict ignore unknown
keys, so this change is backward-compatible.

- [ ] **Step 1: Modify the return dict in `crack_byte_position`**

In `attacker/attack/engine.py`, locate the `return best, { ... }` block at
the end of `crack_byte_position` (around line 176). Replace with:

```python
    successful_alignment = _pick_alignment_with_largest_gap(per_nl, best)
    ranked_all = sorted(config.alphabet, key=lambda c: sums[c])
    clean_commit = margin >= config.min_margin
    return best, {
        "position": log_prefix,
        "best": best.decode("latin-1"),
        "guesses": guesses,
        "rounds": rnd,
        "final_margin": margin,
        "successful_alignment": successful_alignment,
        "ranked_top5": [
            (c.decode("latin-1"), sums[c]) for c in ranked_all[:5]
        ],
        "clean_commit": clean_commit,
        "sums": {c.decode("latin-1"): sums[c] for c in ranked_all},
    }
```

- [ ] **Step 2: Verify nothing breaks**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_engine_helpers && python -m attacker.attack.tests.test_config && python -m attacker.attack.tests.test_alignment`
Expected: each prints its `xxx tests: ok` line.

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/engine.py
git commit -m "feat(engine): Expose clean_commit and sums in crack_byte_position result"
```

---

### Task 4: Implement `_fork_applicable` pure helper

**Files:**
- Create test: `attacker/attack/tests/test_fork.py`
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Create the test file with a failing test**

Create `attacker/attack/tests/test_fork.py` with:

```python
"""Sanity checks for fork-on-stall. Run: python -m attacker.attack.tests.test_fork"""
from attacker.attack.engine import _fork_applicable
from attacker.attack.tests.test_engine_helpers import _cfg


def _stalled_info(**overrides) -> dict:
    base = {
        "position": "pos  4",
        "best": "e",
        "guesses": 4000,
        "rounds": 16,
        "final_margin": 12,
        "successful_alignment": 3,
        "ranked_top5": [("e", 100), ("c", 112), ("k", 120), ("s", 125), ("r", 128)],
        "clean_commit": False,
        "sums": {"e": 100, "c": 112, "k": 120, "s": 125, "r": 128, "a": 200},
    }
    base.update(overrides)
    return base


def test_fork_applicable_all_preconditions_met():
    cfg = _cfg(candidate_fork_on_stall=True, fork_top_k=5, max_fork_depth=2, max_length=32)
    info = _stalled_info()
    assert _fork_applicable(cfg, position=4, pos_info=info, depth=0) is True


def test_fork_applicable_config_off():
    cfg = _cfg(candidate_fork_on_stall=False, fork_top_k=5, max_fork_depth=2, max_length=32)
    info = _stalled_info()
    assert _fork_applicable(cfg, position=4, pos_info=info, depth=0) is False


def test_fork_applicable_at_depth_cap():
    cfg = _cfg(candidate_fork_on_stall=True, fork_top_k=5, max_fork_depth=2, max_length=32)
    info = _stalled_info()
    assert _fork_applicable(cfg, position=4, pos_info=info, depth=2) is False


def test_fork_applicable_at_position_boundary():
    # position + depth + 1 >= max_length -> cannot speculate
    cfg = _cfg(candidate_fork_on_stall=True, fork_top_k=5, max_fork_depth=2, max_length=5)
    info = _stalled_info()
    assert _fork_applicable(cfg, position=4, pos_info=info, depth=0) is False
    assert _fork_applicable(cfg, position=3, pos_info=info, depth=1) is False


def test_fork_applicable_false_on_clean_commit():
    # Guard: if somehow called on a clean commit, don't fork
    cfg = _cfg(candidate_fork_on_stall=True, fork_top_k=5, max_fork_depth=2, max_length=32)
    info = _stalled_info(clean_commit=True)
    assert _fork_applicable(cfg, position=4, pos_info=info, depth=0) is False


if __name__ == "__main__":
    test_fork_applicable_all_preconditions_met()
    test_fork_applicable_config_off()
    test_fork_applicable_at_depth_cap()
    test_fork_applicable_at_position_boundary()
    test_fork_applicable_false_on_clean_commit()
    print("fork tests: ok")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `ImportError: cannot import name '_fork_applicable' from 'attacker.attack.engine'`

- [ ] **Step 3: Implement `_fork_applicable`**

In `attacker/attack/engine.py`, add below `_trimmed_prefix`:

```python
def _fork_applicable(
    config: AttackConfig,
    position: int,
    pos_info: dict,
    depth: int,
) -> bool:
    """Return True if fork-on-stall should fire at (position, depth).

    Preconditions (all must hold):
      - config.candidate_fork_on_stall is True
      - the position did not cleanly commit
      - depth < config.max_fork_depth
      - position + depth + 1 < config.max_length (can still speculate one deeper)
    """
    if not config.candidate_fork_on_stall:
        return False
    if pos_info.get("clean_commit", False):
        return False
    if depth >= config.max_fork_depth:
        return False
    if position + depth + 1 >= config.max_length:
        return False
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_fork.py
git commit -m "feat(engine): _fork_applicable precondition helper"
```

---

### Task 5: Implement `_select_fork_branches` pure helper

**Files:**
- Modify test: `attacker/attack/tests/test_fork.py`
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Add failing tests**

Append to `attacker/attack/tests/test_fork.py`, before the `if __name__` block:

```python
from attacker.attack.engine import _select_fork_branches


def test_select_fork_branches_top_k_by_sums_ascending():
    info = _stalled_info(
        sums={"e": 100, "c": 112, "k": 120, "s": 125, "r": 128, "a": 200},
    )
    # top-3 by ascending sums, no terminator filter here
    branches = _select_fork_branches(info, top_k=3, terminator=b"\n")
    assert branches == [b"e", b"c", b"k"]


def test_select_fork_branches_filters_terminator():
    # 'e' is the top candidate but is the terminator — filter it out
    info = _stalled_info(
        sums={"e": 100, "c": 112, "k": 120, "s": 125, "r": 128},
    )
    branches = _select_fork_branches(info, top_k=3, terminator=b"e")
    assert branches == [b"c", b"k", b"s"]


def test_select_fork_branches_fewer_than_two_after_filter_returns_empty():
    # Top-2 with terminator removing one leaves one candidate -> empty
    info = _stalled_info(sums={"e": 100, "c": 112})
    branches = _select_fork_branches(info, top_k=2, terminator=b"e")
    assert branches == []


def test_select_fork_branches_top_k_larger_than_alphabet_is_clipped():
    info = _stalled_info(sums={"e": 100, "c": 112})
    branches = _select_fork_branches(info, top_k=10, terminator=b"\n")
    assert branches == [b"e", b"c"]
```

Also add to `if __name__` block:

```python
    test_select_fork_branches_top_k_by_sums_ascending()
    test_select_fork_branches_filters_terminator()
    test_select_fork_branches_fewer_than_two_after_filter_returns_empty()
    test_select_fork_branches_top_k_larger_than_alphabet_is_clipped()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `ImportError: cannot import name '_select_fork_branches'`

- [ ] **Step 3: Implement `_select_fork_branches`**

In `attacker/attack/engine.py`, add below `_fork_applicable`:

```python
def _select_fork_branches(
    pos_info: dict,
    top_k: int,
    terminator: bytes,
) -> list[bytes]:
    """Pick fork-branch candidates from a stalled position's sums.

    Returns the top-K candidates by ascending sums (lowest = most likely
    correct), with the terminator byte filtered out. Returns an empty list
    if fewer than 2 candidates remain after filtering — the caller should
    treat this as "fork not applicable, use best-margin fallback."
    """
    sums: dict[str, int] = pos_info["sums"]
    # Sort by ascending value, take top_k
    ranked = sorted(sums.items(), key=lambda kv: kv[1])[:top_k]
    terminator_str = terminator.decode("latin-1")
    branches = [
        key.encode("latin-1") for key, _sum in ranked
        if key != terminator_str
    ]
    if len(branches) < 2:
        return []
    return branches
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_fork.py
git commit -m "feat(engine): _select_fork_branches helper with terminator filter"
```

---

### Task 6: Implement `_classify_fork_outcome` pure helper

**Files:**
- Modify test: `attacker/attack/tests/test_fork.py`
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Add failing tests**

Append to `attacker/attack/tests/test_fork.py`, before the `if __name__` block:

```python
from attacker.attack.engine import _classify_fork_outcome


def _branch_result(clean: bool, best: str = "x") -> tuple:
    """Minimal (best, pos_info) shape returned by crack_byte_position."""
    info = {
        "position": "pos  5",
        "best": best,
        "guesses": 100,
        "rounds": 4,
        "final_margin": 32 if clean else 4,
        "successful_alignment": 3,
        "ranked_top5": [(best, 50)],
        "clean_commit": clean,
        "sums": {best: 50},
    }
    return best.encode("latin-1"), info


def test_classify_fork_outcome_unique_clean():
    results = [
        _branch_result(clean=True,  best="r"),
        _branch_result(clean=False, best="x"),
        _branch_result(clean=False, best="y"),
    ]
    outcome, indices = _classify_fork_outcome(results)
    assert outcome == "unique"
    assert indices == [0]


def test_classify_fork_outcome_multi_clean():
    results = [
        _branch_result(clean=True,  best="r"),
        _branch_result(clean=True,  best="s"),
        _branch_result(clean=False, best="x"),
    ]
    outcome, indices = _classify_fork_outcome(results)
    assert outcome == "multi"
    assert indices == [0, 1]


def test_classify_fork_outcome_zero_clean():
    results = [
        _branch_result(clean=False, best="r"),
        _branch_result(clean=False, best="s"),
    ]
    outcome, indices = _classify_fork_outcome(results)
    assert outcome == "zero"
    assert indices == []
```

Add to `if __name__` block:

```python
    test_classify_fork_outcome_unique_clean()
    test_classify_fork_outcome_multi_clean()
    test_classify_fork_outcome_zero_clean()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `ImportError: cannot import name '_classify_fork_outcome'`

- [ ] **Step 3: Implement `_classify_fork_outcome`**

In `attacker/attack/engine.py`, add below `_select_fork_branches`:

```python
def _classify_fork_outcome(
    branch_results: list[tuple[bytes, dict]],
) -> tuple[str, list[int]]:
    """Classify a fork round by how many branches cleanly committed.

    Returns one of:
      ("unique", [winner_idx])   — exactly 1 clean-committed branch
      ("multi",  [idx1, idx2, ...]) — 2+ clean-committed branches
      ("zero",   [])              — 0 clean-committed branches
    """
    clean_indices = [
        i for i, (_best, info) in enumerate(branch_results)
        if info.get("clean_commit", False)
    ]
    if len(clean_indices) == 1:
        return "unique", clean_indices
    if len(clean_indices) >= 2:
        return "multi", clean_indices
    return "zero", []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_fork.py
git commit -m "feat(engine): _classify_fork_outcome helper"
```

---

### Task 7: Implement `resolve_stalled_position` — unique-winner path

**Files:**
- Modify test: `attacker/attack/tests/test_fork.py`
- Modify: `attacker/attack/engine.py`

This is the largest task. We build `resolve_stalled_position` in four
passes: unique-winner (this task), multi-clean recursion (Task 8),
zero-clean recursion (Task 9), depth-cap fallback (Task 10). Each pass
adds one scenario with one unit test.

- [ ] **Step 1: Add async test infrastructure and the unique-winner test**

Append to `attacker/attack/tests/test_fork.py`, before the `if __name__` block:

```python
import asyncio
import attacker.attack.engine as engine_mod
from attacker.attack.engine import resolve_stalled_position


class _FakeCrack:
    """Scripted fake for crack_byte_position. Records call log."""

    def __init__(self, responses: list[tuple[bytes, dict]]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def __call__(self, adapter, config, prefix, initial_alignment, log_prefix):
        self.calls.append({
            "prefix": prefix,
            "initial_alignment": list(initial_alignment),
            "log_prefix": log_prefix,
        })
        if not self._responses:
            raise AssertionError(f"FakeCrack exhausted — unexpected call: {log_prefix}")
        return self._responses.pop(0)


def _install_fake(fake: _FakeCrack):
    engine_mod.crack_byte_position = fake


def _restore_crack(original):
    engine_mod.crack_byte_position = original


def _run(coro):
    return asyncio.run(coro)


def test_resolve_unique_winner_commits_two_positions():
    original = engine_mod.crack_byte_position
    fake = _FakeCrack([
        # Branch 'e' at pos 5: cleanly commits 'r'
        _branch_result(clean=True,  best="r"),
        # Branch 'c' at pos 5: stalls on some junk byte
        _branch_result(clean=False, best="x"),
        # Branch 'k' at pos 5: stalls on some junk byte
        _branch_result(clean=False, best="y"),
    ])
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=3, max_fork_depth=2,
            max_length=32, min_margin=16,
        )
        stalled = _stalled_info(
            sums={"e": 100, "c": 112, "k": 120, "s": 200, "r": 210},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    # Should return 2 dicts: origin (pos 4) + winner's N+1 (pos 5)
    assert len(result) == 2

    origin = result[0]
    assert origin["position"] == 4
    assert origin["best"] == "e"
    assert origin["clean_commit"] is False
    assert origin["via_fork"] is False
    assert origin["fork_origin"] is None
    assert origin["fork_info"]["triggered"] is True
    assert origin["fork_info"]["depth_used"] == 1
    assert origin["fork_info"]["branches_run"] == 3
    assert origin["fork_info"]["outcome"] == "unique_clean"
    assert origin["fork_info"]["committed_via_fork"] == [5]
    # Origin guesses = original stall work + losers' branch work
    # Stall work = 4000 (from _stalled_info), two losing branches = 2 * 100 = 200
    assert origin["guesses"] == 4000 + 200
    assert origin["fork_info"]["losers_guesses"] == 200
    assert origin["fork_info"]["total_fork_guesses"] == 300  # 3 branches * 100

    winner = result[1]
    assert winner["position"] == 5
    assert winner["best"] == "r"
    assert winner["clean_commit"] is True
    assert winner["via_fork"] is True
    assert winner["fork_origin"] == 4

    # Verify each branch was invoked with the right hypothetical prefix
    # Base prefix = known_prefix + "hunt" (committed) — trimmed to len(known_prefix)
    # We use _cfg's known_prefix = b"*3\r\n$"  (5 bytes), recovered="hunt" (4 bytes)
    # full = known + recovered + branch (6 + 1 = 6 bytes after trim to 5) — actually depends on trim
    # We just verify the branches were invoked in order e, c, k
    assert len(fake.calls) == 3
    # The hypothetical prefix should end with each branch candidate
    assert fake.calls[0]["prefix"].endswith(b"e")
    assert fake.calls[1]["prefix"].endswith(b"c")
    assert fake.calls[2]["prefix"].endswith(b"k")
    # All branches inherit the same alignment hint
    assert fake.calls[0]["initial_alignment"] == [3]
    assert fake.calls[1]["initial_alignment"] == [3]
    assert fake.calls[2]["initial_alignment"] == [3]
```

Add to `if __name__` block:

```python
    test_resolve_unique_winner_commits_two_positions()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `ImportError: cannot import name 'resolve_stalled_position'`

- [ ] **Step 3: Implement `resolve_stalled_position` with the unique-winner path**

In `attacker/attack/engine.py`, add below `_classify_fork_outcome`:

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
    """Disambiguate a stalled position by speculatively running the next one.

    Returns 1..(max_fork_depth + 1) position-info dicts. The first is the
    stalled position's final result with `fork_info` merged in; each
    subsequent dict is a position committed via a fork winner (marked
    `via_fork=True`).

    See docs/superpowers/specs/2026-04-22-fork-on-stall-design.md.
    """
    branches = _select_fork_branches(
        stalled_pos_info, config.fork_top_k, config.terminator,
    )
    if not branches:
        return [_fork_skipped_info(
            stalled_pos_info, position, reason="insufficient_branches",
        )]

    # Run each branch speculatively at position+1.
    branch_results: list[tuple[bytes, dict]] = []
    for branch_candidate in branches:
        hypothetical_recovered = committed_prefix + branch_candidate
        hypothetical_prefix = _trimmed_prefix(
            config.known_prefix, hypothetical_recovered, config,
        )
        initial_alignment = (
            [alignment_hint] if (alignment_hint is not None
                                 and alignment_hint in config.alignment_lengths
                                 and config.alignment_hint_carryover)
            else list(config.alignment_lengths)
        )
        result = await crack_byte_position(
            adapter=adapter, config=config,
            prefix=hypothetical_prefix,
            initial_alignment=initial_alignment,
            log_prefix=f"pos {position+1:2d} fork[{branch_candidate.decode('latin-1')}]",
        )
        branch_results.append(result)

    outcome, clean_indices = _classify_fork_outcome(branch_results)

    losers_guesses = sum(
        info["guesses"] for i, (_b, info) in enumerate(branch_results)
        if i not in clean_indices
    )
    total_fork_guesses = sum(info["guesses"] for _b, info in branch_results)

    if outcome == "unique":
        winner_idx = clean_indices[0]
        winner_candidate = branches[winner_idx]
        winner_best_byte, winner_info = branch_results[winner_idx]
        # If the winner is not the lone clean branch from the loss
        # standpoint, losers = all non-winner branches
        losers_guesses = sum(
            info["guesses"] for i, (_b, info) in enumerate(branch_results)
            if i != winner_idx
        )
        origin = _fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=winner_candidate,
            depth_used=depth + 1,
            branches_run=len(branches),
            losers_guesses=losers_guesses,
            total_fork_guesses=total_fork_guesses,
            outcome="unique_clean",
            committed_via_fork=[position + 1],
        )
        winner_pos = {
            **winner_info,
            "position": position + 1,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        return [origin, winner_pos]

    # Multi-clean / zero-clean / depth-cap paths are added in subsequent tasks.
    raise NotImplementedError(
        f"fork outcome {outcome!r} not yet implemented"
    )


# ---------------------------------------------------------------------------
# Fork-info constructors (pure)
# ---------------------------------------------------------------------------

def _fork_origin_info(
    stalled_pos_info: dict,
    *,
    position: int,
    best_candidate: bytes,
    depth_used: int,
    branches_run: int,
    losers_guesses: int,
    total_fork_guesses: int,
    outcome: str,
    committed_via_fork: list[int],
) -> dict:
    """Build the origin position's final info dict with fork_info merged."""
    return {
        **stalled_pos_info,
        "position": position,
        "best": best_candidate.decode("latin-1"),
        "guesses": stalled_pos_info["guesses"] + losers_guesses,
        "clean_commit": False,
        "via_fork": False,
        "fork_origin": None,
        "fork_info": {
            "triggered": True,
            "depth_used": depth_used,
            "branches_run": branches_run,
            "losers_guesses": losers_guesses,
            "total_fork_guesses": total_fork_guesses,
            "reason": None,
            "outcome": outcome,
            "committed_via_fork": list(committed_via_fork),
        },
    }


def _fork_skipped_info(
    stalled_pos_info: dict, position: int, reason: str,
) -> dict:
    """Build a fork-skipped position dict (terminator-only / max_length)."""
    return {
        **stalled_pos_info,
        "position": position,
        "via_fork": False,
        "fork_origin": None,
        "fork_info": {
            "triggered": False,
            "depth_used": 0,
            "branches_run": 0,
            "losers_guesses": 0,
            "total_fork_guesses": 0,
            "reason": reason,
            "outcome": None,
            "committed_via_fork": [],
        },
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_fork.py
git commit -m "feat(engine): resolve_stalled_position — unique-winner path"
```

---

### Task 8: Extend `resolve_stalled_position` — multi-clean recursion

**Files:**
- Modify test: `attacker/attack/tests/test_fork.py`
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Add failing test for 1-ply multi-clean → 2-ply unique**

Append to `attacker/attack/tests/test_fork.py` before the `if __name__` block:

```python
def test_resolve_multi_clean_recurses_and_finds_2ply_winner():
    original = engine_mod.crack_byte_position
    # Depth-1: branches e, c, k. e and c both cleanly commit at pos 5.
    # Depth-2: extend each with their N+1 byte. e→r cleanly commits at pos 6;
    # c→q stalls; k is not recursed (wasn't clean at depth 1).
    fake = _FakeCrack([
        # Depth-1 calls (in branch order e, c, k)
        _branch_result(clean=True,  best="r"),   # e's N+1
        _branch_result(clean=True,  best="q"),   # c's N+1
        _branch_result(clean=False, best="z"),   # k's N+1
        # Depth-2 calls (only from cleanly-committed depth-1 branches: e, c)
        _branch_result(clean=True,  best="t"),   # e→r→t at pos 6
        _branch_result(clean=False, best="w"),   # c→q→w at pos 6
    ])
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=3, max_fork_depth=2,
            max_length=32, min_margin=16,
        )
        stalled = _stalled_info(
            sums={"e": 100, "c": 112, "k": 120, "s": 200, "r": 210},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    # Should return 3 dicts: origin (pos 4), N+1 (pos 5), N+2 (pos 6)
    assert len(result) == 3
    assert result[0]["position"] == 4
    assert result[0]["best"] == "e"
    assert result[0]["fork_info"]["depth_used"] == 2
    assert result[0]["fork_info"]["outcome"] == "unique_clean"
    assert result[0]["fork_info"]["committed_via_fork"] == [5, 6]
    assert result[1]["position"] == 5
    assert result[1]["best"] == "r"
    assert result[1]["via_fork"] is True
    assert result[1]["fork_origin"] == 4
    assert result[2]["position"] == 6
    assert result[2]["best"] == "t"
    assert result[2]["via_fork"] is True
    assert result[2]["fork_origin"] == 4
```

Add to `if __name__` block:

```python
    test_resolve_multi_clean_recurses_and_finds_2ply_winner()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `NotImplementedError: fork outcome 'multi' not yet implemented`

- [ ] **Step 3: Extend `resolve_stalled_position` with multi-clean / zero-clean / depth-2 handling**

The spec caps depth at 2, so we implement a flat two-depth structure
rather than self-recursion. In `attacker/attack/engine.py`, replace the
terminating `NotImplementedError` block at the end of
`resolve_stalled_position` with:

```python
    # outcome is "multi" or "zero": try depth-2 if allowed AND in bounds.
    # max_fork_depth > 2 is silently capped at 2 (spec out-of-scope).
    can_attempt_depth2 = (
        config.max_fork_depth >= 2
        and position + 2 < config.max_length
    )
    if not can_attempt_depth2:
        # Depth-2 disabled or position+2 out of bounds: best-margin at N.
        return [_fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=branches[0],   # best-margin at N
            depth_used=1,
            branches_run=len(branches),
            losers_guesses=total_fork_guesses,
            total_fork_guesses=total_fork_guesses,
            outcome="best_margin_fallback",
            committed_via_fork=[],
        )]

    # Pick parent branches for depth-2:
    #   multi-clean -> only cleanly-committing branches
    #   zero-clean  -> all branches (each extended with its best-margin N+1)
    if outcome == "multi":
        parent_indices = list(clean_indices)
    else:  # zero
        parent_indices = list(range(len(branches)))

    # Run one crack_byte_position per parent at position+2, extending the
    # hypothetical prefix with that parent's N+1 best (clean-committed or
    # best-margin).
    depth2_results: list[tuple[int, tuple[bytes, dict]]] = []
    for p_idx in parent_indices:
        parent_candidate = branches[p_idx]
        parent_N1_byte, _parent_info = branch_results[p_idx]
        extended_recovered = committed_prefix + parent_candidate + parent_N1_byte
        hypothetical_prefix = _trimmed_prefix(
            config.known_prefix, extended_recovered, config,
        )
        initial_alignment = (
            [alignment_hint] if (alignment_hint is not None
                                 and alignment_hint in config.alignment_lengths
                                 and config.alignment_hint_carryover)
            else list(config.alignment_lengths)
        )
        d2_log = (
            f"pos {position+2:2d} fork2["
            f"{parent_candidate.decode('latin-1')}{parent_N1_byte.decode('latin-1')}]"
        )
        d2_result = await crack_byte_position(
            adapter=adapter, config=config,
            prefix=hypothetical_prefix,
            initial_alignment=initial_alignment,
            log_prefix=d2_log,
        )
        depth2_results.append((p_idx, d2_result))

    # Identify depth-2 clean winners.
    d2_clean = [
        (p_idx, r) for p_idx, r in depth2_results
        if r[1].get("clean_commit", False)
    ]
    d2_total_guesses = sum(r[1]["guesses"] for _p, r in depth2_results)
    d2_losers_guesses = sum(
        r[1]["guesses"] for p_idx, r in depth2_results
        if not r[1].get("clean_commit", False)
    )
    total_fork_guesses_all = total_fork_guesses + d2_total_guesses

    if len(d2_clean) == 1:
        # Winner found at depth 2.
        winner_p_idx, (winner_N2_byte, winner_N2_info) = d2_clean[0]
        winner_candidate_N = branches[winner_p_idx]
        winner_N1_byte, winner_N1_info = branch_results[winner_p_idx]

        # Losers: all depth-1 non-winner branches + all depth-2 non-winner results.
        losers_d1 = sum(
            info["guesses"] for i, (_b, info) in enumerate(branch_results)
            if i != winner_p_idx
        )
        losers_total = losers_d1 + d2_losers_guesses

        origin = _fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=winner_candidate_N,
            depth_used=2,
            branches_run=len(branches) + len(depth2_results),
            losers_guesses=losers_total,
            total_fork_guesses=total_fork_guesses_all,
            outcome="unique_clean",
            committed_via_fork=[position + 1, position + 2],
        )
        winner_n1 = {
            **winner_N1_info,
            "position": position + 1,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        winner_n2 = {
            **winner_N2_info,
            "position": position + 2,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        return [origin, winner_n1, winner_n2]

    # No unique depth-2 winner: fall back to best-margin at N.
    return [_fork_origin_info(
        stalled_pos_info,
        position=position,
        best_candidate=branches[0],
        depth_used=2,
        branches_run=len(branches) + len(depth2_results),
        losers_guesses=total_fork_guesses_all,
        total_fork_guesses=total_fork_guesses_all,
        outcome="best_margin_fallback",
        committed_via_fork=[],
    )]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_fork.py
git commit -m "feat(engine): resolve_stalled_position — multi-clean 2-ply recursion"
```

---

### Task 9: Extend `resolve_stalled_position` — zero-clean recursion + depth-cap fallback

**Files:**
- Modify test: `attacker/attack/tests/test_fork.py`

The implementation in Task 8 already handles zero-clean and depth-cap
fallback in code, but we need tests confirming those branches.

- [ ] **Step 1: Add failing test for 1-ply zero-clean → 2-ply unique**

Append to `attacker/attack/tests/test_fork.py` before the `if __name__` block:

```python
def test_resolve_zero_clean_recurses_with_tentative_parents():
    original = engine_mod.crack_byte_position
    # Depth-1: all three branches stall at N+1.
    # Depth-2: extend each with its best-margin N+1 byte. Only 'e' branch
    # yields a clean commit at pos 6 -> e is the correct N.
    fake = _FakeCrack([
        # Depth-1
        _branch_result(clean=False, best="r"),  # e's N+1 (best-margin)
        _branch_result(clean=False, best="q"),  # c's N+1 (best-margin)
        _branch_result(clean=False, best="z"),  # k's N+1 (best-margin)
        # Depth-2 (all three recursed with tentative N+1)
        _branch_result(clean=True,  best="t"),  # e→r→t at pos 6
        _branch_result(clean=False, best="w"),  # c→q→w at pos 6
        _branch_result(clean=False, best="v"),  # k→z→v at pos 6
    ])
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=3, max_fork_depth=2,
            max_length=32, min_margin=16,
        )
        stalled = _stalled_info(
            sums={"e": 100, "c": 112, "k": 120, "s": 200, "r": 210},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    assert len(result) == 3
    assert result[0]["best"] == "e"
    assert result[0]["fork_info"]["outcome"] == "unique_clean"
    assert result[0]["fork_info"]["committed_via_fork"] == [5, 6]


def test_resolve_zero_clean_no_depth2_winner_falls_back():
    original = engine_mod.crack_byte_position
    # Every branch stalls at every depth -> best-margin at N returned
    fake = _FakeCrack([
        # Depth-1 (3 stalls)
        _branch_result(clean=False, best="r"),
        _branch_result(clean=False, best="q"),
        _branch_result(clean=False, best="z"),
        # Depth-2 (3 stalls)
        _branch_result(clean=False, best="t"),
        _branch_result(clean=False, best="w"),
        _branch_result(clean=False, best="v"),
    ])
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=3, max_fork_depth=2,
            max_length=32, min_margin=16,
        )
        stalled = _stalled_info(
            sums={"e": 100, "c": 112, "k": 120, "s": 200, "r": 210},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    # Only 1 dict: origin with best-margin fallback
    assert len(result) == 1
    assert result[0]["position"] == 4
    assert result[0]["best"] == "e"   # best-margin = lowest-sum candidate
    assert result[0]["fork_info"]["outcome"] == "best_margin_fallback"
    assert result[0]["fork_info"]["committed_via_fork"] == []


def test_resolve_insufficient_branches_skipped():
    # Terminator-only alphabet with only 'e' non-terminator -> empty branches
    fake = _FakeCrack([])   # should never be called
    original = engine_mod.crack_byte_position
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=3, max_fork_depth=2,
            max_length=32, min_margin=16, terminator=b"c",
        )
        # Top-3 sums: e (100), c (112 but is terminator), k (120) -> 'e','k' forkable -> 2 branches OK
        # Test with only 1 non-terminator: top_k=2 sums reduces
        stalled = _stalled_info(
            sums={"c": 100, "e": 112, "a": 200},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    assert len(result) == 1
    assert result[0]["fork_info"]["triggered"] is False
    assert result[0]["fork_info"]["reason"] == "insufficient_branches"
    # No branches should have been scheduled
    assert fake.calls == []
```

Note: the third test's `_cfg` call passes `fork_top_k=3` via the first
`_cfg` argument chain; double-check the _stalled_info's `sums` has only
3 entries including terminator so that top-3 after terminator filter is 2
non-terminator -> 2 branches, NOT what the test asserts ("insufficient").
Correct it: reduce fork_top_k to 2 so top-2 = c, e; after terminator
filter, only 'e' remains -> empty branches -> insufficient.

Replace the third test body:

```python
def test_resolve_insufficient_branches_skipped():
    fake = _FakeCrack([])
    original = engine_mod.crack_byte_position
    _install_fake(fake)
    try:
        cfg = _cfg(
            candidate_fork_on_stall=True, fork_top_k=2, max_fork_depth=2,
            max_length=32, min_margin=16, terminator=b"c",
        )
        # Top-2 sums: c (100, terminator), e (112) — after filter, just 'e' -> empty
        stalled = _stalled_info(
            sums={"c": 100, "e": 112, "a": 200},
        )
        result = _run(resolve_stalled_position(
            adapter=None, config=cfg,
            committed_prefix=b"hunt", position=4,
            stalled_pos_info=stalled, alignment_hint=3, depth=0,
        ))
    finally:
        _restore_crack(original)

    assert len(result) == 1
    assert result[0]["fork_info"]["triggered"] is False
    assert result[0]["fork_info"]["reason"] == "insufficient_branches"
    assert fake.calls == []
```

Add to `if __name__` block:

```python
    test_resolve_zero_clean_recurses_with_tentative_parents()
    test_resolve_zero_clean_no_depth2_winner_falls_back()
    test_resolve_insufficient_branches_skipped()
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_fork`
Expected: `fork tests: ok`

(No implementation change expected — the code from Task 8 already handles these. If any test fails, fix the engine code accordingly.)

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/tests/test_fork.py
git commit -m "test(engine): fork zero-clean, depth-cap, and insufficient-branches paths"
```

---

### Task 10: Rewire `run_attack` main loop to consume multi-position results

**Files:**
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Replace the main loop in `run_attack`**

In `attacker/attack/engine.py`, locate the `for pos in range(config.max_length):` block inside `run_attack` (around line 227) and replace the entire body from `for pos` down to the `else: LOG.warning("hit max_length...")` line with:

```python
            position = 0
            done = False
            while position < config.max_length and not done:
                full_prefix = _trimmed_prefix(
                    config.known_prefix, recovered, config,
                )
                initial_alignment = _select_initial_alignment(config, prev_nl)

                best, pos_info = await crack_byte_position(
                    adapter=adapter,
                    config=config,
                    prefix=full_prefix,
                    initial_alignment=initial_alignment,
                    log_prefix=f"pos {position:2d}",
                )
                pos_info["position"] = position
                # Downstream consumers may not see these yet (adapter tests
                # don't touch run_attack), but normalise here for uniformity.
                pos_info.setdefault("via_fork", False)
                pos_info.setdefault("fork_origin", None)
                pos_info.setdefault("fork_info", None)

                if pos_info["clean_commit"] or not _fork_applicable(
                    config, position, pos_info, depth=0,
                ):
                    committed = [pos_info]
                else:
                    committed = await resolve_stalled_position(
                        adapter=adapter,
                        config=config,
                        committed_prefix=recovered,
                        position=position,
                        stalled_pos_info=pos_info,
                        alignment_hint=prev_nl,
                        depth=0,
                    )

                for pr in committed:
                    best_byte = pr["best"].encode("latin-1")
                    per_position.append(pr)
                    if pr["successful_alignment"] is not None:
                        prev_nl = pr["successful_alignment"]
                    if best_byte == config.terminator:
                        LOG.info("hit terminator at position %d -> done", pr["position"])
                        done = True
                        break
                    recovered += best_byte
                    LOG.info("recovered so far: %r", recovered.decode("latin-1"))

                position += len(committed)

            if not done and position >= config.max_length:
                LOG.warning("hit max_length=%d without terminator", config.max_length)
```

- [ ] **Step 2: Smoke-test engine imports by running existing tests**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -m attacker.attack.tests.test_config && python -m attacker.attack.tests.test_alignment && python -m attacker.attack.tests.test_engine_helpers && python -m attacker.attack.tests.test_fork`
Expected: each prints its `xxx tests: ok` line.

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/engine.py
git commit -m "feat(engine): Rewire run_attack main loop to consume fork multi-commits"
```

---

### Task 11: Update adapter `default_config()`s to set fork fields explicitly

**Files:**
- Modify: `attacker/attack/adapters/direct.py`
- Modify: `attacker/attack/adapters/beast.py`
- Modify: `attacker/attack/adapters/ansible.py`

- [ ] **Step 1: Modify `DirectAdapter.default_config()`**

In `attacker/attack/adapters/direct.py`, in the `default_config()` method,
add three fields just before `label="direct-default"`:

```python
            measurement_min_segment_size=0,
            candidate_fork_on_stall=True,
            fork_top_k=5,
            max_fork_depth=2,
            label="direct-default",
```

- [ ] **Step 2: Modify `BeastAdapter.default_config()`**

In `attacker/attack/adapters/beast.py`, in the `default_config()` method,
add three fields just before `label="beast-default"`:

```python
            measurement_min_segment_size=100,
            candidate_fork_on_stall=True,
            fork_top_k=5,
            max_fork_depth=2,
            label="beast-default",
```

- [ ] **Step 3: Modify `AnsibleAdapter.default_config()`**

In `attacker/attack/adapters/ansible.py`, in the `default_config()`
method, add three fields just before `label="ansible-default"`:

```python
            measurement_min_segment_size=0,
            candidate_fork_on_stall=True,
            fork_top_k=5,
            max_fork_depth=2,
            label="ansible-default",
```

- [ ] **Step 4: Verify adapter construction still works**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -c "from attacker.attack.adapters.direct import DirectAdapter; from attacker.attack.adapters.beast import BeastAdapter; from attacker.attack.adapters.ansible import AnsibleAdapter; print(DirectAdapter.default_config().candidate_fork_on_stall, BeastAdapter.default_config().fork_top_k, AnsibleAdapter.default_config().max_fork_depth)"`
Expected: `True 5 2`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/adapters/direct.py attacker/attack/adapters/beast.py attacker/attack/adapters/ansible.py
git commit -m "feat(adapters): Set fork-on-stall defaults explicitly in each adapter"
```

---

### Task 12: Update `scripts/benchmark.py` CSV aggregator

**Files:**
- Modify: `scripts/benchmark.py`

- [ ] **Step 1: Extend `summarise()` to include fork stats**

In `scripts/benchmark.py`, inside `summarise()`, after the
`per_position_guesses` block but before the `summary[v] = { ... }` block
(around line 428), add:

```python
        # Fork metrics: count positions where fork triggered, sum losers' guesses
        fork_triggered_positions = 0
        fork_overhead_guesses = 0
        for r in passed:
            for entry in (r.get("phase1_per_position") or []):
                fi = entry.get("fork_info")
                if fi and fi.get("triggered"):
                    fork_triggered_positions += 1
                    fork_overhead_guesses += fi.get("losers_guesses", 0)
            for entry in (r.get("phase2_per_position") or []):
                fi = entry.get("fork_info")
                if fi and fi.get("triggered"):
                    fork_triggered_positions += 1
                    fork_overhead_guesses += fi.get("losers_guesses", 0)
```

Still inside `summarise()`, extend the `summary[v] = { ... }` dict to
include:

```python
        summary[v] = {
            "trials_total": len(vr),
            "trials_passed": len(passed),
            "trials_failed": len(vr) - len(passed),
            "per_attack": stats(per_attack),
            "per_position": stats(per_position_guesses),
            "fork_triggered_positions": fork_triggered_positions,
            "fork_overhead_guesses": fork_overhead_guesses,
        }
```

- [ ] **Step 2: Extend the CSV writer**

In `scripts/benchmark.py`, locate the CSV writer block (around line 642).
Extend the header and each row:

```python
        with open(args.csv_summary, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "variant", "scenario", "trials_passed",
                "per_attack_min", "per_attack_max", "per_attack_avg", "per_attack_total",
                "per_position_count",
                "per_position_min", "per_position_max", "per_position_avg",
                "fork_triggered_positions", "fork_overhead_guesses",
            ])
            for v, s in summary.items():
                pa = s["per_attack"]
                pp = s["per_position"]
                w.writerow([
                    v, config_override["label"], s["trials_passed"],
                    pa["min"], pa["max"],
                    f"{pa['avg']:.1f}" if pa["avg"] is not None else "",
                    pa["total"],
                    pp["count"],
                    pp["min"], pp["max"],
                    f"{pp['avg']:.1f}" if pp["avg"] is not None else "",
                    s["fork_triggered_positions"], s["fork_overhead_guesses"],
                ])
```

- [ ] **Step 3: Smoke-test benchmark imports**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python -c "import scripts.benchmark"`
Expected: no output (clean import).

- [ ] **Step 4: Commit**

```bash
git add scripts/benchmark.py
git commit -m "feat(benchmark): Report fork_triggered_positions and fork_overhead_guesses"
```

---

### Task 13: Rebuild attacker container and run verify_direct.py

**Files:**
- (no source changes; verification only)

- [ ] **Step 1: Build the attacker image**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && docker compose build attacker`
Expected: Build succeeds (ends with `naming to ...` line).

- [ ] **Step 2: Bring up the stack**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && docker compose up -d`
Expected: all services Running / Started.

- [ ] **Step 3: Run the direct-variant verify script**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python scripts/verify_direct.py`
Expected: the script prints step 1-6 checks and finally `PASS`. Recovery
of `hunter2` in roughly 100 seconds. `fork_info` on each per_position
entry should be `null` (direct's signal is clean — fork should not fire
on this canonical run).

- [ ] **Step 4: Commit nothing (verification step)**

No commit needed. If the run failed, triage before proceeding — a
regression in direct indicates `_fork_applicable` is firing when it
shouldn't, or the augmented return dict broke a downstream consumer.

---

### Task 14: Run verify_ansible.py

**Files:**
- (no source changes; verification only)

- [ ] **Step 1: Run the ansible-variant verify script**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python scripts/verify_ansible.py`
Expected: recovers `hunter2` via two-phase attack in ~4 min. `fork_info`
on each per_position entry should be `null` (ansible's signal is cleanest
— fork should not fire).

- [ ] **Step 2: Commit nothing (verification step)**

---

### Task 15: Run verify_beast.py — ACCEPTANCE GATE

**Files:**
- (no source changes; verification only)

This is the acceptance-defining test. Before this change, verify_beast.py
failed at pos 4 (committed `huntc`, not `hunte`). It must now pass.

- [ ] **Step 1: Run the BEAST verify script**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python scripts/verify_beast.py`
Expected: recovers `hunter2` end-to-end in ~20 min.

- [ ] **Step 2: Confirm fork actually fired**

After the run completes, inspect the response body that verify_beast.py
printed (or the attacker logs). The `per_position` array should contain
at least one entry with `fork_info.triggered == true`, most likely at
position 4. That entry should have `fork_info.outcome == "unique_clean"`
and `fork_info.committed_via_fork` non-empty.

If the run passed but no fork fired, the BEAST signal may have shifted
enough that fork_on_stall wasn't needed on this particular run — accept
as pass, note it in the commit, and continue.

If the run failed: the feature is not complete. Re-triage the spec's
algorithm section (§"Winner rule") and cross-check the implementation's
handling of the failure classification in `resolve_stalled_position`.

- [ ] **Step 3: Commit nothing (verification step)**

---

### Task 16: Run benchmark smoke test

**Files:**
- (no source changes; verification only)

- [ ] **Step 1: Short parallel benchmark run for BEAST**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && python scripts/benchmark.py --stacks 2 --trials 4 --scenario all-opts --variants beast`
Expected: 4 BEAST trials complete (some may fail — that's acceptable for
this quick smoke); the summary CSV shows the two new columns
`fork_triggered_positions` and `fork_overhead_guesses`.

- [ ] **Step 2: Verify the CSV summary shape**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && head -1 benchmark_summary.csv`
Expected: header ends with `...,fork_triggered_positions,fork_overhead_guesses`.

- [ ] **Step 3: Tear down benchmark stacks**

Run: `cd /home/claude-user/Workspace/SSH-Adaptive-Compression-PoC && for p in bench-0 bench-1; do docker compose -p $p -f docker-compose.yml -f docker-compose.bench.yml down -v 2>&1 | tail -1; done`
Expected: each prints a `Removed` line or similar.

- [ ] **Step 4: Commit nothing (verification step)**

---

### Task 17: Update CLAUDE.md and README.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update CLAUDE.md file→purpose table**

In `CLAUDE.md`, locate the `## File → purpose quick reference` section and
update the `attacker/attack/engine.py` line to:

```markdown
- `attacker/attack/engine.py` — round loop, ranking, metrics,
  `run_attack()` coroutine, and `resolve_stalled_position()` (fork-on-stall
  fallback). Transport-agnostic.
```

- [ ] **Step 2: Update README.md Results section for BEAST**

In `README.md`, locate the `### BEAST variant — known limitation` subsection
and replace it with:

```markdown
### BEAST variant — `hunter2`

```
Phase 1: recovering password length...
  length = 7          ( ≈ 15 s)
Phase 2: recovering password...
  password = 'hunter2' ( ≈ 20 min, 1 fork at pos 4)

Total:     ≈ 20 min
Status:    PASS (with fork-on-stall enabled — see below)
```

The BEAST per-round signal at pos 4 of `hunter2` exhibits a persistent,
non-random bias (`huntc` vs `hunte` within a few wire bytes) that
averaging across rounds cannot clear. The engine's **fork-on-stall**
correctness fallback disambiguates by speculatively running position 5
for the top-K stalled candidates and committing the branch that cleanly
resolves. Position 5 is committed from the winning branch's speculative
run, so the attack advances two positions at once. See
`docs/superpowers/specs/2026-04-22-fork-on-stall-design.md` for the
algorithm.
```

- [ ] **Step 3: Update README.md 'How the attack works' section**

In `README.md`, after the `### Repeat-until-confident` subsection (around
line 275), insert a new subsection before `### Constant-prefix trimming`:

```markdown
### Fork-on-stall (BEAST correctness fallback)

When a position exhausts `max_rounds` without reaching `min_margin`, the
engine speculatively runs the *next* position for each of the top-K
stalled candidates. Only the correct branch yields a clean commit at the
next position; wrong branches stall again or commit spurious bytes with
weak margins. A unique clean commit disambiguates the stalled position
and commits the next one at the same time. If two branches both commit
cleanly or none does, the engine recurses to 2-ply. On exhaustion, it
falls back to the best-margin candidate.

Direct and ansible variants rarely trigger this path because their
signals are clean; BEAST exhibits a persistent-bias edge case at
`hunter2` pos 4 that this fallback is specifically designed for.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: Document fork-on-stall in README and CLAUDE.md"
```

---

## Self-review checklist

Before closing this plan: verify against the spec.

- ✅ Config fields (`candidate_fork_on_stall`, `fork_top_k`, `max_fork_depth`) — Task 1.
- ✅ `_trimmed_prefix` helper — Task 2.
- ✅ `crack_byte_position` return shape augmented with `clean_commit`, `sums` — Task 3.
- ✅ `_fork_applicable` — Task 4.
- ✅ `_select_fork_branches` — Task 5.
- ✅ `_classify_fork_outcome` — Task 6.
- ✅ `resolve_stalled_position` unique-winner — Task 7.
- ✅ `resolve_stalled_position` multi-clean recursion — Task 8.
- ✅ `resolve_stalled_position` zero-clean + depth-cap — Task 9 (covered in Task 8's implementation, Task 9 adds tests).
- ✅ `run_attack` main loop rewired — Task 10.
- ✅ Adapter default_configs — Task 11.
- ✅ Benchmark CSV columns — Task 12.
- ✅ Host-level verify runs (direct, ansible, BEAST) — Tasks 13, 14, 15.
- ✅ Benchmark smoke test — Task 16.
- ✅ Docs update (CLAUDE.md, README.md) — Task 17.

Spec requirements NOT covered by any task: none identified on review.
