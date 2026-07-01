"""Sanity checks for the browser_pna URL-safe alignment pool.

Run: python -m attacker.attack.tests.test_url_safe_alignment

These are the machine-checked versions of the invariants documented in
attacker/attack/alignment.py and attacker/attack/adapters/browser_pna.py: the
URL-safe alignment pool must be URL-path-verbatim, mutually distinct, 8-bit
static-Huffman literals, and disjoint from both the recovery alphabet and the
url_safe_disjoint flush pool. (Wire-verbatim-ness is additionally confirmed on
the wire against the pinned Chromium; these tests pin the *analytic*
invariants.)
"""
from attacker.attack.alignment import (
    _ALIGNMENT_POOL,
    _URL_SAFE_ALIGNMENT_POOL,
    make_alignment,
)
from attacker.attack.adapters.browser_pna import (
    _PATH_VERBATIM_BYTES,
    _URL_SAFE_FILLER_POOL,
)

_RECOVERY_ALPHABET = set(b"abcdefghijklmnopqrstuvwxyz0123456789")


def test_pool_is_uppercase_A_to_H():
    assert _URL_SAFE_ALIGNMENT_POOL == list(b"ABCDEFGH")


def test_pool_bytes_are_mutually_distinct():
    assert len(set(_URL_SAFE_ALIGNMENT_POOL)) == len(_URL_SAFE_ALIGNMENT_POOL)


def test_pool_bytes_are_url_path_verbatim():
    # Every alignment byte must survive a URL path verbatim; a percent-encoded
    # byte would change the wire bytes and destroy the tipping-point property.
    for b in _URL_SAFE_ALIGNMENT_POOL:
        assert b in _PATH_VERBATIM_BYTES, hex(b)


def test_pool_bytes_are_8bit_static_huffman_literals():
    # DEFLATE fixed-Huffman literals 0..143 (0x00..0x8F) are 8 bits, so each
    # alignment byte advances the encoded length by exactly one byte.
    for b in _URL_SAFE_ALIGNMENT_POOL:
        assert b <= 0x8F, hex(b)


def test_pool_disjoint_from_recovery_alphabet():
    # An alignment byte must never coincide with a candidate byte, or it could
    # fabricate a spurious match.
    assert not (set(_URL_SAFE_ALIGNMENT_POOL) & _RECOVERY_ALPHABET)


def test_pool_disjoint_from_flush_pool():
    # An alignment byte must never coincide with the random filler, or it could
    # back-reference filler content and stop advancing the length by one.
    assert not (set(_URL_SAFE_ALIGNMENT_POOL) & set(_URL_SAFE_FILLER_POOL))


def test_pool_large_enough_for_chacha_sweep():
    # alignment_lengths [0..7] => make_alignment(7) needs 7 bytes.
    assert len(_URL_SAFE_ALIGNMENT_POOL) >= 8


def test_make_alignment_with_url_safe_pool():
    assert make_alignment(0, _URL_SAFE_ALIGNMENT_POOL) == b""
    assert make_alignment(1, _URL_SAFE_ALIGNMENT_POOL) == b"A"
    assert make_alignment(3, _URL_SAFE_ALIGNMENT_POOL) == b"ABC"
    assert make_alignment(7, _URL_SAFE_ALIGNMENT_POOL) == b"ABCDEFG"


def test_make_alignment_pool_bytes_argument():
    # AttackConfig.alignment_pool is stored as bytes; make_alignment accepts it.
    assert make_alignment(3, bytes(_URL_SAFE_ALIGNMENT_POOL)) == b"ABC"


def test_make_alignment_rejects_too_long_for_url_safe_pool():
    try:
        make_alignment(len(_URL_SAFE_ALIGNMENT_POOL) + 1, _URL_SAFE_ALIGNMENT_POOL)
    except ValueError:
        return
    raise AssertionError("expected ValueError for length > pool size")


def test_default_pool_unchanged_and_disjoint_from_url_safe_pool():
    # The classic pool the other three scenarios rely on must be untouched, and
    # the two pools must not overlap (high-ASCII vs uppercase).
    assert list(_ALIGNMENT_POOL) == list(range(0x80, 0x90))
    assert not (set(_ALIGNMENT_POOL) & set(_URL_SAFE_ALIGNMENT_POOL))


def test_make_alignment_default_pool_is_classic():
    # Backward compat: no pool argument => the classic high-ASCII pool.
    assert make_alignment(3) == bytes([0x80, 0x81, 0x82])
    assert make_alignment(3, None) == bytes([0x80, 0x81, 0x82])


if __name__ == "__main__":
    test_pool_is_uppercase_A_to_H()
    test_pool_bytes_are_mutually_distinct()
    test_pool_bytes_are_url_path_verbatim()
    test_pool_bytes_are_8bit_static_huffman_literals()
    test_pool_disjoint_from_recovery_alphabet()
    test_pool_disjoint_from_flush_pool()
    test_pool_large_enough_for_chacha_sweep()
    test_make_alignment_with_url_safe_pool()
    test_make_alignment_pool_bytes_argument()
    test_make_alignment_rejects_too_long_for_url_safe_pool()
    test_default_pool_unchanged_and_disjoint_from_url_safe_pool()
    test_make_alignment_default_pool_is_classic()
    print("url-safe alignment tests: ok")
