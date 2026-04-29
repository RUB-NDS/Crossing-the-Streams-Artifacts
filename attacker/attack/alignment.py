"""8-bit DEFLATE literals used as alignment-data bytes.

The pool is 0x80..0x8F -- all 8-bit fixed-Huffman literals (DEFLATE codes
0..143 are 8 bits), mutually distinct so no intra-alignment LZ77 matches,
and absent from plausible dictionary content (ASCII text, zeros, SSH
framing). Do not substitute arbitrary bytes here.
"""

_ALIGNMENT_POOL = list(range(0x80, 0x90))


def make_alignment(length: int) -> bytes:
    if length > len(_ALIGNMENT_POOL):
        raise ValueError(
            f"alignment length {length} > pool size {len(_ALIGNMENT_POOL)}"
        )
    return bytes(_ALIGNMENT_POOL[:length])
