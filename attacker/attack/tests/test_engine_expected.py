"""Tests for the expected-mismatch helper.

Run: python -m attacker.attack.tests.test_engine_expected
"""
from attacker.attack.engine import _check_expected_match


def test_expected_none_returns_none():
    assert _check_expected_match(b"a", 0, None) is None


def test_position_past_expected_returns_none():
    # Once the engine commits past len(expected) we don't second-guess —
    # this is normal terminator handling territory.
    assert _check_expected_match(b"x", 5, b"abc") is None


def test_matching_byte_returns_none():
    assert _check_expected_match(b"b", 1, b"abc") is None


def test_mismatching_byte_returns_dict():
    info = _check_expected_match(b"x", 1, b"abc")
    assert info == {"expected_byte": "b", "committed_byte": "x"}


def test_mismatch_at_terminator_position_is_detected():
    # Position 3 of "abc\r" is the terminator. Committing the wrong byte
    # there must still register as a mismatch — the engine relies on this
    # to catch terminator-position commit errors.
    info = _check_expected_match(b"\n", 3, b"abc\r")
    assert info == {"expected_byte": "\r", "committed_byte": "\n"}


def test_mismatch_with_control_bytes():
    # Ansible phase1 uses chr(len) — make sure non-printable bytes work.
    info = _check_expected_match(b"\x09", 0, b"\x08\x00")
    assert info == {"expected_byte": "\x08", "committed_byte": "\x09"}


if __name__ == "__main__":
    test_expected_none_returns_none()
    test_position_past_expected_returns_none()
    test_matching_byte_returns_none()
    test_mismatching_byte_returns_dict()
    test_mismatch_at_terminator_position_is_detected()
    test_mismatch_with_control_bytes()
    print("engine-expected tests: ok")
