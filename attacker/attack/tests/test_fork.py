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

    # Numeric accounting (depth-2 unique winner):
    # Stall (4000) + depth-1 losers (c: 100, k: 100) + depth-2 loser (c→q: 100) = 4300
    assert result[0]["guesses"] == 4300
    # Losers = all non-winner branches at both depths (c, k at d1 + c→q at d2) = 300
    assert result[0]["fork_info"]["losers_guesses"] == 300
    # All branches at all depths (3 × 100 + 2 × 100) = 500
    assert result[0]["fork_info"]["total_fork_guesses"] == 500
    # 3 depth-1 branches + 2 depth-2 branches = 5
    assert result[0]["fork_info"]["branches_run"] == 5
    # Winner's depth-1 work = 100
    assert result[1]["guesses"] == 100
    # Winner's depth-2 work = 100
    assert result[2]["guesses"] == 100


if __name__ == "__main__":
    test_fork_applicable_all_preconditions_met()
    test_fork_applicable_config_off()
    test_fork_applicable_at_depth_cap()
    test_fork_applicable_at_position_boundary()
    test_fork_applicable_false_on_clean_commit()
    test_select_fork_branches_top_k_by_sums_ascending()
    test_select_fork_branches_filters_terminator()
    test_select_fork_branches_fewer_than_two_after_filter_returns_empty()
    test_select_fork_branches_top_k_larger_than_alphabet_is_clipped()
    test_classify_fork_outcome_unique_clean()
    test_classify_fork_outcome_multi_clean()
    test_classify_fork_outcome_zero_clean()
    test_resolve_unique_winner_commits_two_positions()
    test_resolve_multi_clean_recurses_and_finds_2ply_winner()
    print("fork tests: ok")
