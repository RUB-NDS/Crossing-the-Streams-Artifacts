"""SSH client -- OpenSSH subprocess variant of the CRIME-on-SSH PoC.

Scenario
--------
The victim tunnels two internal services through **one** compressed SSH
connection (``ssh -C``):

* **Redis** (127.0.0.1:6379 -> redis:6379) -- the victim's application
  authenticates with ``AUTH <password>`` on every new connection.  The
  tunnel is bound to localhost because only the local app needs it.
* **Internal web tool** (0.0.0.0:8080 -> webhost:80) -- an nginx server
  serving cat pictures.  Bound to 0.0.0.0 because the developer wants
  other devices on the LAN (or a local VM/container) to reach it.

Both tunnels produce ``direct-tcpip`` SSH channels that share a single
c->s zlib compression context (RFC 4253 section 6.2).  An attacker on the
same network can connect to the publicly-bound web tunnel on port 8080
and inject chosen bytes into that shared context, while a passive
on-path observer watches encrypted packet sizes.

HTTP control API (for the test harness only -- the attacker never uses
endpoints that reveal the secret):

    GET  /status               -- SSH state, port-forward info
    POST /send_secret          -- trigger one Redis AUTH cycle
    POST /set_secret           -- change the secret, reconfigure Redis,
                                  and reconnect SSH
    POST /reset                -- reconnect SSH
"""

import asyncio
import logging
import os
import sys
from typing import Optional

import redis.asyncio as aioredis
from aiohttp import web

LOG = logging.getLogger("client")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KEYS_DIR = "/keys"
SERVER_HOST_KEY_PUB = os.path.join(KEYS_DIR, "server_host_key.pub")
CLIENT_KEY = os.path.join(KEYS_DIR, "client_user_key")

SSH_TARGET_HOST = os.environ.get("SSH_TARGET_HOST", "attacker")
SSH_TARGET_PORT = int(os.environ.get("SSH_TARGET_PORT", "2222"))
SSH_REAL_SERVER = os.environ.get("SSH_REAL_SERVER", "server")
SSH_USERNAME = os.environ.get("SSH_USERNAME", "victim")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8000"))

# Port-forward configuration --------------------------------------------------
WEB_TUNNEL_LOCAL_HOST = "0.0.0.0"
WEB_TUNNEL_LOCAL_PORT = int(os.environ.get("WEB_TUNNEL_LOCAL_PORT", "8080"))
WEB_TUNNEL_DEST_HOST = os.environ.get("WEB_TUNNEL_DEST_HOST", "webhost")
WEB_TUNNEL_DEST_PORT = int(os.environ.get("WEB_TUNNEL_DEST_PORT", "80"))

REDIS_TUNNEL_LOCAL_HOST = "127.0.0.1"
REDIS_TUNNEL_LOCAL_PORT = int(os.environ.get("REDIS_TUNNEL_LOCAL_PORT", "6379"))
REDIS_TUNNEL_DEST_HOST = os.environ.get("REDIS_TUNNEL_DEST_HOST", "redis")
REDIS_TUNNEL_DEST_PORT = int(os.environ.get("REDIS_TUNNEL_DEST_PORT", "6379"))

DEFAULT_SECRET_VALUE = os.environ.get("SECRET_VALUE", "hunter2")

KNOWN_HOSTS_PATH = "/tmp/known_hosts"

# Redis username used for ACL-style AUTH (Redis 6+).
# redis-py sends ``AUTH default <password>`` in RESP format.
REDIS_USERNAME = "default"


# ---------------------------------------------------------------------------
# SSH subprocess state
# ---------------------------------------------------------------------------

class SSHState:
    """Manages the OpenSSH client subprocess and its two local port forwards."""

    def __init__(self, secret_value: str) -> None:
        self.ssh_proc: Optional[asyncio.subprocess.Process] = None
        self.secret_value: str = secret_value
        self._lock = asyncio.Lock()
        self._negotiated: dict[str, str] = {}
        self._stderr_task: Optional[asyncio.Task] = None

    # -- SSH lifecycle --------------------------------------------------------

    def _write_known_hosts(self) -> None:
        """Build a known_hosts file from the server's public key."""
        with open(SERVER_HOST_KEY_PUB) as f:
            key_line = f.read().strip()
        # [host]:port format for non-standard ports
        entry = f"[{SSH_TARGET_HOST}]:{SSH_TARGET_PORT} {key_line}\n"
        with open(KNOWN_HOSTS_PATH, "w") as f:
            f.write(entry)
        LOG.info("wrote known_hosts: %s", KNOWN_HOSTS_PATH)

    def _build_ssh_cmd(self) -> list[str]:
        redis_fwd = (
            f"{REDIS_TUNNEL_LOCAL_HOST}:{REDIS_TUNNEL_LOCAL_PORT}:"
            f"{REDIS_TUNNEL_DEST_HOST}:{REDIS_TUNNEL_DEST_PORT}"
        )
        web_fwd = (
            f"{WEB_TUNNEL_LOCAL_HOST}:{WEB_TUNNEL_LOCAL_PORT}:"
            f"{WEB_TUNNEL_DEST_HOST}:{WEB_TUNNEL_DEST_PORT}"
        )
        return [
            "ssh",
            "-N",                                           # no remote command
            "-C",                                           # enable compression
            "-v",                                           # verbose (parse negotiated algs)
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS_PATH}",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=60",
            "-o", "ServerAliveCountMax=3",
            "-i", CLIENT_KEY,
            "-L", redis_fwd,
            "-L", web_fwd,
            "-p", str(SSH_TARGET_PORT),
            f"{SSH_USERNAME}@{SSH_TARGET_HOST}",
        ]

    async def connect(self) -> None:
        """Launch ssh subprocess with port forwards."""
        self._write_known_hosts()
        cmd = self._build_ssh_cmd()
        LOG.info("launching: %s", " ".join(cmd))
        self.ssh_proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        # Parse negotiated algorithms from ssh -v stderr
        self._negotiated = await self._parse_kex(timeout=15)
        LOG.info("negotiated: %s", self._negotiated)
        # Start a background task to drain stderr so the pipe never fills
        # and blocks the ssh process.
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        # Wait for tunnels to accept connections
        await self._wait_for_tunnels(timeout=15)
        LOG.info("SSH tunnels ready")

    async def _drain_stderr(self) -> None:
        """Read and discard ssh -v stderr to prevent pipe buffer deadlock."""
        assert self.ssh_proc is not None and self.ssh_proc.stderr is not None
        try:
            while True:
                line = await self.ssh_proc.stderr.readline()
                if not line:
                    break
        except (asyncio.CancelledError, OSError):
            pass

    async def _parse_kex(self, timeout: float = 15) -> dict[str, str]:
        """Read ssh -v stderr until kex lines appear or authentication completes."""
        info: dict[str, str] = {}
        deadline = asyncio.get_event_loop().time() + timeout
        assert self.ssh_proc is not None
        assert self.ssh_proc.stderr is not None
        while asyncio.get_event_loop().time() < deadline:
            try:
                line_bytes = await asyncio.wait_for(
                    self.ssh_proc.stderr.readline(), timeout=1.0,
                )
            except asyncio.TimeoutError:
                if info:
                    break
                continue
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            LOG.debug("ssh: %s", line)
            # debug1: kex: server->client cipher: ... compression: ...
            if "kex: client->server" in line or "kex: server->client" in line:
                direction = "send" if "client->server" in line else "recv"
                for field in ("cipher:", "compression:", "MAC:"):
                    if field in line:
                        val = line.split(field, 1)[1].strip().split()[0]
                        key = f"{direction}_{field.rstrip(':')}"
                        info[key] = val
            if "Authentication succeeded" in line or "pledge:" in line:
                break
        return info

    async def _wait_for_tunnels(self, timeout: float = 30) -> None:
        """Poll local ports until both tunnels accept connections."""
        tunnels = [
            (REDIS_TUNNEL_LOCAL_HOST, REDIS_TUNNEL_LOCAL_PORT, "redis"),
            (WEB_TUNNEL_LOCAL_HOST, WEB_TUNNEL_LOCAL_PORT, "web"),
        ]
        deadline = asyncio.get_event_loop().time() + timeout
        for host, port, label in tunnels:
            while asyncio.get_event_loop().time() < deadline:
                if self.ssh_proc and self.ssh_proc.returncode is not None:
                    raise RuntimeError(
                        f"ssh exited with code {self.ssh_proc.returncode}"
                    )
                try:
                    _, w = await asyncio.open_connection(host, port)
                    w.close()
                    await w.wait_closed()
                    LOG.info("%s tunnel listening on %s:%d", label, host, port)
                    break
                except OSError:
                    await asyncio.sleep(0.3)
            else:
                raise TimeoutError(f"{label} tunnel not ready after {timeout}s")

    async def reconnect(self) -> None:
        """Kill ssh, re-launch with a fresh compression context."""
        LOG.info("reconnecting (resets SSH compression context)")
        await self._kill_ssh()
        await self.connect()

    async def _kill_ssh(self) -> None:
        if self._stderr_task and not self._stderr_task.done():
            self._stderr_task.cancel()
            self._stderr_task = None
        if self.ssh_proc and self.ssh_proc.returncode is None:
            self.ssh_proc.terminate()
            try:
                await asyncio.wait_for(self.ssh_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.ssh_proc.kill()
                await self.ssh_proc.wait()
        self.ssh_proc = None
        self._negotiated = {}

    # -- Redis interaction ---------------------------------------------------

    async def init_redis_password(self) -> None:
        """Set the initial Redis password (Redis starts with none)."""
        for attempt in range(1, 21):
            try:
                r = aioredis.Redis(
                    host="127.0.0.1", port=REDIS_TUNNEL_LOCAL_PORT,
                    socket_connect_timeout=5,
                )
                await r.config_set("requirepass", self.secret_value)
                await r.aclose()
                LOG.info("initial CONFIG SET requirepass: OK")
                return
            except (OSError, aioredis.RedisError) as exc:
                LOG.warning("Redis init attempt %d: %s", attempt, exc)
                await asyncio.sleep(0.5)
        LOG.error("could not set initial Redis password after retries")

    async def send_secret(self) -> int:
        """Simulate the application connecting to Redis and authenticating.

        Opens a fresh redis-py connection through the tunnel; redis-py
        sends ``AUTH default <password>`` in RESP format.  The connection
        is closed afterwards, just like a short-lived pool checkout.
        """
        async with self._lock:
            r = aioredis.Redis(
                host="127.0.0.1", port=REDIS_TUNNEL_LOCAL_PORT,
                username=REDIS_USERNAME,
                password=self.secret_value,
                socket_connect_timeout=5,
            )
            try:
                await r.ping()
                LOG.info("Redis AUTH+PING: OK")
            finally:
                await r.aclose()
        return 0

    async def reconfigure_redis(self, new_password: str) -> None:
        """Change the Redis requirepass at runtime via CONFIG SET."""
        r = aioredis.Redis(
            host="127.0.0.1", port=REDIS_TUNNEL_LOCAL_PORT,
            username=REDIS_USERNAME,
            password=self.secret_value,
            socket_connect_timeout=5,
        )
        try:
            await r.config_set("requirepass", new_password)
            LOG.info("Redis CONFIG SET requirepass: OK")
        finally:
            await r.aclose()

    def status(self) -> dict:
        if self.ssh_proc is None or self.ssh_proc.returncode is not None:
            return {"ssh_connected": False}
        return {
            "ssh_connected": True,
            "ssh_target": f"{SSH_TARGET_HOST}:{SSH_TARGET_PORT}",
            "ssh_real_server": SSH_REAL_SERVER,
            "ssh_username": SSH_USERNAME,
            "ssh_send_compression": self._negotiated.get(
                "send_compression", "unknown"),
            "ssh_recv_compression": self._negotiated.get(
                "recv_compression", "unknown"),
            "ssh_send_cipher": self._negotiated.get(
                "send_cipher", "unknown"),
            "ssh_recv_cipher": self._negotiated.get(
                "recv_cipher", "unknown"),
            "ssh_send_mac": self._negotiated.get("send_MAC", "unknown"),
            "ssh_recv_mac": self._negotiated.get("recv_MAC", "unknown"),
            "port_forwards": {
                "web_tunnel": {
                    "active": True,
                    "local": f"{WEB_TUNNEL_LOCAL_HOST}:{WEB_TUNNEL_LOCAL_PORT}",
                    "remote": f"{WEB_TUNNEL_DEST_HOST}:{WEB_TUNNEL_DEST_PORT}",
                },
                "redis_tunnel": {
                    "active": True,
                    "local": f"{REDIS_TUNNEL_LOCAL_HOST}:{REDIS_TUNNEL_LOCAL_PORT}",
                    "remote": f"{REDIS_TUNNEL_DEST_HOST}:{REDIS_TUNNEL_DEST_PORT}",
                },
            },
            "secret_value_length": len(self.secret_value),
        }


# ---------------------------------------------------------------------------
# HTTP control plane
# ---------------------------------------------------------------------------

async def handle_status(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    return web.json_response(state.status())


async def handle_send_secret(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    try:
        n = await state.send_secret()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("send_secret failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({"ok": True, "bytes_written": n})


async def handle_set_secret(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    body = await request.json()
    new_value = body.get("value")
    if not isinstance(new_value, str):
        return web.json_response(
            {"ok": False, "error": "missing string 'value'"}, status=400,
        )
    LOG.info("set_secret: new value length %d", len(new_value))
    try:
        await state.reconfigure_redis(new_value)
        state.secret_value = new_value
        await state.reconnect()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("set_secret failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({
        "ok": True,
        "secret_value_length": len(new_value),
    })


async def handle_reset(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    await state.reconnect()
    return web.json_response({"ok": True})


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    state = SSHState(secret_value=DEFAULT_SECRET_VALUE)

    for attempt in range(1, 21):
        try:
            await state.connect()
            break
        except (OSError, RuntimeError, TimeoutError) as exc:
            LOG.warning("connect attempt %d failed: %s", attempt, exc)
            await state._kill_ssh()
            await asyncio.sleep(1.0)
    else:
        LOG.error("could not establish SSH transport after retries")
        return 1

    await state.init_redis_password()

    app = web.Application()
    app["ssh"] = state
    app.router.add_get("/status", handle_status)
    app.router.add_post("/send_secret", handle_send_secret)
    app.router.add_post("/set_secret", handle_set_secret)
    app.router.add_post("/reset", handle_reset)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP control API listening on 0.0.0.0:%d", HTTP_PORT)

    await asyncio.Event().wait()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
