"""Sanity checks for alignment.py. Run: python -m attacker.attack.tests.test_alignment"""
from attacker.attack.alignment import _ALIGNMENT_POOL, make_alignment


def test_pool_size_and_range():
    # 8-bit DEFLATE literals in the 0x80..0x8F range.
    assert list(_ALIGNMENT_POOL) == list(range(0x80, 0x90))


def test_make_alignment_basic():
    assert make_alignment(0) == b""
    assert make_alignment(1) == bytes([0x80])
    assert make_alignment(3) == bytes([0x80, 0x81, 0x82])
    assert make_alignment(8) == bytes(range(0x80, 0x88))


def test_make_alignment_rejects_too_long():
    try:
        make_alignment(17)
    except ValueError:
        return
    raise AssertionError("expected ValueError for length > pool size")


if __name__ == "__main__":
    test_pool_size_and_range()
    test_make_alignment_basic()
    test_make_alignment_rejects_too_long()
    print("alignment tests: ok")
