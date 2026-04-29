import asyncio
import logging
import os
import shutil

LOG = logging.getLogger("harness")

KEY_PATH = "/home/victim/.ssh/id_ed25519"
KNOWN_HOSTS_PATH = "/tmp/known_hosts"
SSH_TARGET = "victim@server"


class SSHSession:
    """One interactive `ssh -X -T victim@server bash` subprocess.

    Commands are written to stdin one line at a time; each is followed by
    `echo <token>` so we can wait for a deterministic completion signal.
    """

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._counter = 0
        self._io_lock = asyncio.Lock()

    async def open(self) -> None:
        cmd = [
            "ssh", "-X", "-T",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS_PATH}",
            "-o", "ServerAliveInterval=0",
            "-o", "ServerAliveCountMax=0",
            "-o", "Compression=yes",
            "-o", "Ciphers=chacha20-poly1305@openssh.com",
            "-i", KEY_PATH,
            SSH_TARGET,
            "bash",
        ]
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        await self._sync("__READY__")

    async def trigger_xset(self) -> None:
        async with self._io_lock:
            token = self._next_token("TRIG")
            await self._send_line(f"xset q >/dev/null; echo {token}")
            await self._read_until(token)

    async def close(self) -> None:
        if self._proc is None:
            return
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(b"exit\n")
            await self._proc.stdin.drain()
            self._proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            self._proc.kill()
            await self._proc.wait()
        self._proc = None

    async def _sync(self, token: str) -> None:
        await self._send_line(f"echo {token}")
        await self._read_until(token)

    def _next_token(self, kind: str) -> str:
        self._counter += 1
        return f"__{kind}_{self._counter}__"

    async def _send_line(self, line: str) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write((line + "\n").encode())
        await self._proc.stdin.drain()

    async def _read_until(self, token: str, timeout: float = 30.0) -> bytes:
        assert self._proc is not None and self._proc.stdout is not None
        token_b = token.encode()
        buf = bytearray()
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"timeout waiting for {token!r} in stdout")
            chunk = await asyncio.wait_for(
                self._proc.stdout.read(4096), timeout=remaining
            )
            if not chunk:
                raise EOFError(f"ssh stdout closed before {token!r}")
            buf.extend(chunk)
            if token_b in buf:
                return bytes(buf)


async def _selfcheck() -> None:
    """Standalone smoke entry so `python -m harness --selfcheck` exercises
    one open/trigger/close cycle. Used by Task 11 to verify the driver
    works against the live stack before HTTP wiring lands."""
    logging.basicConfig(level=logging.INFO)
    if shutil.which("ssh") is None:
        raise SystemExit("ssh binary not on PATH")
    sess = SSHSession()
    LOG.info("opening session")
    await sess.open()
    LOG.info("triggering xset")
    await sess.trigger_xset()
    LOG.info("closing session")
    await sess.close()
    LOG.info("OK")


from aiohttp import web

HARNESS_PORT = 8000


def _make_app() -> web.Application:
    app = web.Application()
    app["session"] = None

    async def trial_start(request: web.Request) -> web.Response:
        if app["session"] is not None:
            return web.json_response(
                {"error": "trial already in progress"}, status=409
            )
        sess = SSHSession()
        await sess.open()
        app["session"] = sess
        return web.json_response({"ok": True})

    async def trigger(request: web.Request) -> web.Response:
        sess = app["session"]
        if sess is None:
            return web.json_response({"error": "no trial open"}, status=409)
        await sess.trigger_xset()
        return web.json_response({"ok": True})

    async def trial_end(request: web.Request) -> web.Response:
        sess = app["session"]
        if sess is None:
            return web.json_response({"ok": True})  # idempotent
        await sess.close()
        app["session"] = None
        return web.json_response({"ok": True})

    app.router.add_post("/trial/start", trial_start)
    app.router.add_post("/trigger", trigger)
    app.router.add_post("/trial/end", trial_end)
    return app


def _run_http() -> None:
    logging.basicConfig(level=logging.INFO)
    web.run_app(_make_app(), host="0.0.0.0", port=HARNESS_PORT, access_log=None)


if __name__ == "__main__":
    import sys
    if "--selfcheck" in sys.argv:
        asyncio.run(_selfcheck())
    else:
        _run_http()
