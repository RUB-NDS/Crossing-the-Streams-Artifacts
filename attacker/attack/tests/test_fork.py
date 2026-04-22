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
    print("fork tests: ok")
