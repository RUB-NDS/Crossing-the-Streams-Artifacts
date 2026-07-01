"""DEFLATE literals used as alignment-data bytes.

Two pools live here, selected per-scenario via ``AttackConfig.alignment_pool``:

``_ALIGNMENT_POOL`` (0x80..0x8F, the default) -- all 8-bit fixed-Huffman
literals (DEFLATE codes 0..143 are 8 bits), mutually distinct so no
intra-alignment LZ77 matches, and absent from plausible dictionary content
(ASCII text, zeros, SSH framing). Used by the direct / browser / ansible
scenarios, whose alignment bytes ride on a raw TCP forward or a POST body and
never have to survive URL encoding.

``_URL_SAFE_ALIGNMENT_POOL`` (uppercase ``A..H``) -- used by ``browser_pna``,
whose alignment bytes ride inside an OPTIONS request-URI *path*. The high-ASCII
0x80..0x8F pool cannot appear in a path without percent-encoding, and
percent-encoding a byte (0x80 -> ``%80``) changes the wire bytes and destroys
the tipping-point property. Every byte here is therefore chosen to be:

  * emitted **verbatim** by the pinned Chromium in an OPTIONS request-URI path
    (uppercase ASCII letters are never percent-encoded; sub-delims such as
    ``! $ ' ( ) * +`` are a validated alternative but browser-encoding of
    sub-delims must be confirmed on the wire before substituting them);
  * an **8-bit static-Huffman literal** (0x41..0x48 are all <= 0x8F), so that
    inside the static-Huffman block the guess prefill isolates it into, each
    alignment byte advances the encoded length by exactly one byte and every
    mod-8 tipping point is reachable;
  * **disjoint** from the browser_pna recovery alphabet (lowercase + digits)
    and from its ``url_safe_disjoint`` flush/prefill pool (uppercase ``I..Z``),
    so an alignment byte can neither fabricate a spurious match with a
    candidate byte nor back-reference the random filler (which would stop it
    advancing the length by one);
  * mutually **distinct**, so an alignment run has no intra-alignment LZ77
    match.

Do not substitute arbitrary bytes into either pool.
"""

_ALIGNMENT_POOL = list(range(0x80, 0x90))

# Uppercase A..H. Only lengths [0..7] (the ChaCha20-Poly1305 sweep) are used,
# so bytes A..G are the ones that ever hit the wire; H is the 8th slot kept for
# make_alignment(8) symmetry. Disjoint from the url_safe_disjoint flush pool
# (I..Z) by construction. See module docstring for the full invariant list and
# attacker/attack/tests/test_alignment.py for the machine-checked version.
_URL_SAFE_ALIGNMENT_POOL = list(b"ABCDEFGH")


def make_alignment(length: int, pool: "bytes | list[int] | None" = None) -> bytes:
    """Return the first ``length`` bytes of ``pool`` (default: the classic
    high-ASCII pool). ``pool`` lets a scenario supply a different alphabet of
    alignment-data bytes (e.g. browser_pna's URL-path-safe pool) without the
    engine having to know which transport it is driving.
    """
    active = _ALIGNMENT_POOL if pool is None else list(pool)
    if length > len(active):
        raise ValueError(
            f"alignment length {length} > pool size {len(active)}"
        )
    return bytes(active[:length])
