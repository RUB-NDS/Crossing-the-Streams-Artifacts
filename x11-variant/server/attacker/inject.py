ANCHOR = b"MIT-MAGIC-COOKIE-1\x00\x00"
ALIGNMENT_POOL = bytes(range(0x80, 0x90))


def build_probe(prefix: bytes, candidate: bytes, align_len: int) -> bytes:
    if len(candidate) != 1:
        raise ValueError(f"candidate must be exactly 1 byte, got {len(candidate)}")
    if not 0 <= align_len <= 7:
        raise ValueError(f"align_len must be in [0, 7], got {align_len}")
    return ANCHOR + prefix + candidate + ALIGNMENT_POOL[:align_len]
