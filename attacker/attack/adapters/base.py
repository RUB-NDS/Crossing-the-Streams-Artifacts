"""Adapter protocol shared by direct, BEAST, and ansible transports.

The engine asks the adapter for one thing only: given a prefix, candidate,
and alignment bytes, return the measured c->s byte count for one oracle
query. Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read packet log) lives inside the adapter.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import aiohttp

from attacker.attack.config import AttackConfig


@runtime_checkable
class Adapter(Protocol):
    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        """Called once before the first measure_once."""

    async def teardown(self) -> None:
        """Called once after the last measure_once (always, even on error)."""

    async def measure_once(
        self,
        prefix: bytes,
        candidate: bytes,
        alignment: bytes,
    ) -> int:
        """Inject `prefix + candidate + alignment` and return observed c->s bytes."""

    @classmethod
    def default_config(cls) -> AttackConfig:
        """Variant-tuned config; scenario presets override toggle fields on top."""
