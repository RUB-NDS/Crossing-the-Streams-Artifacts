"""Sanity checks for config.py. Run: python -m attacker.attack.tests.test_config"""
from typing import Any

from attacker.attack.config import AttackConfig, AlignmentMode


def _base_kwargs() -> dict[str, Any]:
    return dict(
        known_prefix=b"*3\r\n$",
        alphabet=[bytes([c]) for c in b"abc"],
        max_length=4,
        terminator=b"\n",
        min_margin=16,
        max_rounds=64,
        settle=0.003,
        alignment_mode=AlignmentMode.FULL_SWEEP,
        alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
        candidate_elimination=True,
        constant_prefix_trim=True,
        adaptive_alignment=True,
        stall_detection=True,
        alignment_hint_carryover=True,
        outlier_threshold=0,
        flush_bytes=32768,
        flush_pool="secrets_random",
        measurement_min_segment_size=0,
    )


def test_construct_defaults() -> None:
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.alignment_mode == AlignmentMode.FULL_SWEEP
    assert cfg.label == ""


def test_from_dict_partial_override() -> None:
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({
        "min_margin": 32,
        "candidate_elimination": False,
        "alignment_mode": "fixed_single",
        "alignment_lengths": [3],
    })
    assert overridden.min_margin == 32
    assert overridden.candidate_elimination is False
    assert overridden.alignment_mode == AlignmentMode.FIXED_SINGLE
    assert overridden.alignment_lengths == [3]
    # Unmentioned fields are preserved.
    assert overridden.max_rounds == base.max_rounds
    assert overridden.flush_bytes == base.flush_bytes


def test_overlay_handles_bytes_fields_as_str() -> None:
    base = AttackConfig(**_base_kwargs())
    # HTTP bodies will carry strings; overlay decodes them to bytes.
    overridden = base.overlay({
        "known_prefix": "AUTH ",
        "terminator": "\r",
        "alphabet": "xyz",
    })
    assert overridden.known_prefix == b"AUTH "
    assert overridden.terminator == b"\r"
    assert overridden.alphabet == [b"x", b"y", b"z"]


def test_fork_fields_default_on_and_tuned() -> None:
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.candidate_fork_on_stall is False
    assert cfg.fork_top_k == 5
    assert cfg.max_fork_depth == 2


def test_overlay_fork_fields() -> None:
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({
        "candidate_fork_on_stall": False,
        "fork_top_k": 7,
        "max_fork_depth": 3,
    })
    assert overridden.candidate_fork_on_stall is False
    assert overridden.fork_top_k == 7
    assert overridden.max_fork_depth == 3


def test_expected_defaults_to_none() -> None:
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.expected is None


def test_overlay_decodes_expected_from_str() -> None:
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({"expected": "hunter2\r"})
    assert overridden.expected == b"hunter2\r"


def test_overlay_decodes_expected_with_control_bytes() -> None:
    # Ansible phase1 expected uses chr(len) + "\x00" -- round-trip must preserve
    # control bytes exactly.
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({"expected": "\x08\x00"})
    assert overridden.expected == b"\x08\x00"


def test_overlay_expected_none_keeps_field_unset() -> None:
    base = AttackConfig(**_base_kwargs())
    # The overlay is meant to skip None values, matching the existing pattern.
    overridden = base.overlay({"expected": None})
    assert overridden.expected is None


if __name__ == "__main__":
    test_construct_defaults()
    test_from_dict_partial_override()
    test_overlay_handles_bytes_fields_as_str()
    test_fork_fields_default_on_and_tuned()
    test_overlay_fork_fields()
    test_expected_defaults_to_none()
    test_overlay_decodes_expected_from_str()
    test_overlay_decodes_expected_with_control_bytes()
    test_overlay_expected_none_keeps_field_unset()
    print("config tests: ok")
