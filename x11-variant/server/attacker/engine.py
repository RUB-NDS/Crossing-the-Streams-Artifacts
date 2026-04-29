import statistics
from collections.abc import Iterable

ALIGNMENT_COUNT = 8


def locked(
    ranked: list[bytes],
    samples: dict[bytes, list[int]],
    min_margin: int,
    min_agreement: int,
) -> bool:
    if len(ranked) < 2:
        return False
    top, runner = ranked[0], ranked[1]
    median_top = statistics.median(samples[top])
    median_runner = statistics.median(samples[runner])
    if median_runner - median_top < min_margin:
        return False
    return _alignment_agreement(top, samples) >= min_agreement


def _alignment_agreement(top: bytes, samples: dict[bytes, list[int]]) -> int:
    wins = 0
    for align_idx in range(ALIGNMENT_COUNT):
        top_at = _slice_alignment(samples[top], align_idx)
        if not top_at:
            continue
        top_min = statistics.median(top_at)
        better = True
        for cand, cand_samples in samples.items():
            if cand == top:
                continue
            cand_at = _slice_alignment(cand_samples, align_idx)
            if not cand_at:
                continue
            if statistics.median(cand_at) <= top_min:
                better = False
                break
        if better:
            wins += 1
    return wins


def _slice_alignment(samples: list[int], align_idx: int) -> list[int]:
    return samples[align_idx::ALIGNMENT_COUNT]


class RecoveryFailed(RuntimeError):
    pass


async def find_next_byte(
    oracle,
    prefix: bytes,
    byte_index: int,
    min_margin: int,
    min_agreement: int,
    max_rounds: int,
) -> bytes:
    candidates = [bytes([c]) for c in range(256)]
    samples: dict[bytes, list[int]] = {c: [] for c in candidates}

    for _round in range(max_rounds):
        for cand in candidates:
            for align_len in range(ALIGNMENT_COUNT):
                size = await oracle(prefix, cand, align_len)
                samples[cand].append(size)

        ranked = sorted(candidates, key=lambda c: statistics.median(samples[c]))
        if locked(ranked, samples, min_margin, min_agreement):
            return ranked[0]

    raise RecoveryFailed(
        f"position {byte_index} did not lock after {max_rounds} rounds"
    )
