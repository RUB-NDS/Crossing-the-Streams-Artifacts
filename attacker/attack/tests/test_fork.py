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
