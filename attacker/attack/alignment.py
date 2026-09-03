"""8-bit DEFLATE literals used as alignment-data bytes (Section 4.2).

Alignment pads a guess to a tipping point -- the length at which a wrong
candidate's extra literal forces the BPP to emit one more ciphertext
block.

The pool is 0x80..0x8F -- all 8-bit static-Huffman literals (DEFLATE codes
0..143 are 8 bits), so every alignment byte advances the encoded length by
exactly one byte and every tipping point is reachable. The bytes are
mutually distinct so no intra-alignment LZ77 matches arise, and absent
from plausible dictionary content (ASCII text, zeros, SSH framing). Do not
substitute arbitrary bytes here.
"""

_ALIGNMENT_POOL = list(range(0x80, 0x90))


def make_alignment(length: int) -> bytes:
    if length > len(_ALIGNMENT_POOL):
        raise ValueError(
            f"alignment length {length} > pool size {len(_ALIGNMENT_POOL)}"
        )
    return bytes(_ALIGNMENT_POOL[:length])
