"""Sanity checks for engine helpers. Run: python -m attacker.attack.tests.test_engine_helpers"""
from attacker.attack.engine import (
    _pick_alignment_with_largest_gap,
    _select_initial_alignment,
)
from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.tests.test_config import _base_kwargs


def _cfg(**overrides) -> AttackConfig:
    k = _base_kwargs()
    k.update(overrides)
    return AttackConfig(**k)


def test_pick_alignment_returns_nl_with_largest_gap():
    # At nl=3 the best candidate is 8 wire bytes cheaper than every other.
    per_nl = {
        0: {b"h": 120, b"a": 120, b"b": 120},
        3: {b"h": 112, b"a": 120, b"b": 120},
        5: {b"h": 120, b"a": 120, b"b": 120},
    }
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") == 3


def test_pick_alignment_returns_none_when_no_gap():
    per_nl = {
        0: {b"h": 120, b"a": 120, b"b": 120},
        3: {b"h": 120, b"a": 120, b"b": 120},
    }
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") is None


def test_pick_alignment_returns_none_when_only_one_candidate():
    # Single-candidate rounds have no "others" to compare against.
    per_nl = {0: {b"h": 120}, 3: {b"h": 112}}
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") is None


def test_select_initial_alignment_fixed_single():
    cfg = _cfg(alignment_mode=AlignmentMode.FIXED_SINGLE, alignment_lengths=[3])
    assert _select_initial_alignment(cfg, prev_nl=None) == [3]
    assert _select_initial_alignment(cfg, prev_nl=5) == [3]  # hint ignored in fixed mode


def test_select_initial_alignment_full_sweep_no_hint():
    cfg = _cfg(alignment_hint_carryover=False)
    assert _select_initial_alignment(cfg, prev_nl=None) == list(range(8))
    assert _select_initial_alignment(cfg, prev_nl=3) == list(range(8))  # carryover off


def test_select_initial_alignment_full_sweep_with_hint():
    cfg = _cfg(alignment_hint_carryover=True)
    assert _select_initial_alignment(cfg, prev_nl=None) == list(range(8))  # no hint yet
    assert _select_initial_alignment(cfg, prev_nl=3) == [3]


def test_select_initial_alignment_hint_out_of_set_falls_back():
    # If prev_nl isn't in the configured alignment set, full sweep is used.
    cfg = _cfg(alignment_hint_carryover=True, alignment_lengths=[0, 2, 4])
    assert _select_initial_alignment(cfg, prev_nl=3) == [0, 2, 4]


def test_trimmed_prefix_no_recovered_bytes_is_identity():
    from attacker.attack.engine import _trimmed_prefix
    cfg = _cfg(constant_prefix_trim=True)
    assert _trimmed_prefix(b"AUTH ", b"", cfg) == b"AUTH "


def test_trimmed_prefix_trims_head_when_recovered_grows():
    from attacker.attack.engine import _trimmed_prefix
    cfg = _cfg(constant_prefix_trim=True)
    # known="AUTH ", recovered="hu" -> full="AUTH hu" (7 bytes)
    # trim = 7 - len("AUTH ") = 2 -> "TH hu"
    assert _trimmed_prefix(b"AUTH ", b"hu", cfg) == b"TH hu"


def test_trimmed_prefix_trim_disabled_appends_without_trimming():
    from attacker.attack.engine import _trimmed_prefix
    cfg = _cfg(constant_prefix_trim=False)
    assert _trimmed_prefix(b"AUTH ", b"hu", cfg) == b"AUTH hu"


if __name__ == "__main__":
    test_pick_alignment_returns_nl_with_largest_gap()
    test_pick_alignment_returns_none_when_no_gap()
    test_pick_alignment_returns_none_when_only_one_candidate()
    test_select_initial_alignment_fixed_single()
    test_select_initial_alignment_full_sweep_no_hint()
    test_select_initial_alignment_full_sweep_with_hint()
    test_select_initial_alignment_hint_out_of_set_falls_back()
    test_trimmed_prefix_no_recovered_bytes_is_identity()
    test_trimmed_prefix_trims_head_when_recovered_grows()
    test_trimmed_prefix_trim_disabled_appends_without_trimming()
    print("engine-helper tests: ok")
