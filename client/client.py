"""SSH client -- port-forwarding variant of the CRIME-on-SSH PoC.

Scenario
--------
The victim tunnels two internal services through **one** compressed SSH
connection:

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
    GET  /compressed_log       -- debug-only compressor output sizes
    POST /clear_compressed_log -- clear the debug log
"""

import asyncio
import logging
import os
import sys
from typing import Optional

import asyncssh
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

COMPRESSION_ALGS = ["zlib@openssh.com", "zlib"]


# Redis username used for ACL-style AUTH (Redis 6+).
# redis-py sends ``AUTH default <password>`` in RESP format.
REDIS_USERNAME = "default"


# ---------------------------------------------------------------------------
# SSH + port-forward state
# ---------------------------------------------------------------------------

class SSHState:
    """Manages the SSH connection and its two local port-forward listeners."""

    def __init__(self, secret_value: str) -> None:
        self.conn: Optional[asyncssh.SSHClientConnection] = None
        self.web_listener: Optional[asyncssh.SSHListener] = None
        self.redis_listener: Optional[asyncssh.SSHListener] = None
        self.secret_value: str = secret_value
        self._lock = asyncio.Lock()
        self.compressed_log: list[tuple] = []

    async def connect(self) -> None:
        host_key = asyncssh.read_public_key(SERVER_HOST_KEY_PUB)
        known_hosts = ([host_key], [], [])

        LOG.info("connecting to %s:%d (real server=%s) as %s",
                 SSH_TARGET_HOST, SSH_TARGET_PORT, SSH_REAL_SERVER, SSH_USERNAME)
        self.conn = await asyncssh.connect(
            host=SSH_TARGET_HOST,
            port=SSH_TARGET_PORT,
            username=SSH_USERNAME,
            client_keys=[CLIENT_KEY],
            known_hosts=known_hosts,
            compression_algs=COMPRESSION_ALGS,
        )
        LOG.info("SSH transport established")
        send_alg = self.conn.get_extra_info("send_compression")
        recv_alg = self.conn.get_extra_info("recv_compression")
        LOG.info("compression: send=%s recv=%s", send_alg, recv_alg)

        self.web_listener = await self.conn.forward_local_port(
            WEB_TUNNEL_LOCAL_HOST, WEB_TUNNEL_LOCAL_PORT,
            WEB_TUNNEL_DEST_HOST, WEB_TUNNEL_DEST_PORT,
        )
        LOG.info("web tunnel: %s:%d -> %s:%d",
                 WEB_TUNNEL_LOCAL_HOST, WEB_TUNNEL_LOCAL_PORT,
                 WEB_TUNNEL_DEST_HOST, WEB_TUNNEL_DEST_PORT)

        self.redis_listener = await self.conn.forward_local_port(
            REDIS_TUNNEL_LOCAL_HOST, REDIS_TUNNEL_LOCAL_PORT,
            REDIS_TUNNEL_DEST_HOST, REDIS_TUNNEL_DEST_PORT,
        )
        LOG.info("Redis tunnel: %s:%d -> %s:%d",
                 REDIS_TUNNEL_LOCAL_HOST, REDIS_TUNNEL_LOCAL_PORT,
                 REDIS_TUNNEL_DEST_HOST, REDIS_TUNNEL_DEST_PORT)

        compressor = self.conn._compressor  # type: ignore[attr-defined]
        if compressor is not None:
            orig_compress = compressor.compress

            def wrapped_compress(data: bytes) -> bytes:
                out = orig_compress(data)
                msg_type = data[0] if data else -1
                self.compressed_log.append(
                    (len(data), len(out), msg_type, data[:32].hex())
                )
                return out

            compressor.compress = wrapped_compress  # type: ignore[method-assign]
            LOG.info("instrumented send compressor for debug logging")
        else:
            LOG.warning("no send compressor (compression disabled?)")

    async def reconnect(self) -> None:
        LOG.info("reconnecting (resets SSH compression context)")
        for attr in ("web_listener", "redis_listener"):
            listener = getattr(self, attr)
            if listener is not None:
                listener.close()
                setattr(self, attr, None)
        if self.conn is not None:
            try:
                self.conn.close()
                await self.conn.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self.conn = None
        self.compressed_log.clear()
        await self.connect()

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

        The connection is closed afterwards, just like a short-lived
        connection-pool checkout.  A PING is sent to force the lazy
        connection open (triggering AUTH on the wire).
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
        if self.conn is None:
            return {"ssh_connected": False}
        return {
            "ssh_connected": True,
            "ssh_target": f"{SSH_TARGET_HOST}:{SSH_TARGET_PORT}",
            "ssh_real_server": SSH_REAL_SERVER,
            "ssh_username": SSH_USERNAME,
            "ssh_send_compression": self.conn.get_extra_info("send_compression"),
            "ssh_recv_compression": self.conn.get_extra_info("recv_compression"),
            "ssh_send_cipher": self.conn.get_extra_info("send_cipher"),
            "ssh_recv_cipher": self.conn.get_extra_info("recv_cipher"),
            "ssh_send_mac": self.conn.get_extra_info("send_mac"),
            "ssh_recv_mac": self.conn.get_extra_info("recv_mac"),
            "port_forwards": {
                "web_tunnel": {
                    "active": self.web_listener is not None,
                    "local": f"{WEB_TUNNEL_LOCAL_HOST}:{WEB_TUNNEL_LOCAL_PORT}",
                    "remote": f"{WEB_TUNNEL_DEST_HOST}:{WEB_TUNNEL_DEST_PORT}",
                },
                "redis_tunnel": {
                    "active": self.redis_listener is not None,
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


async def handle_compressed_log(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    if request.query.get("clear", "0") == "1":
        snapshot = list(state.compressed_log)
        state.compressed_log.clear()
        return web.json_response({"records": snapshot, "cleared": True})
    return web.json_response({"records": list(state.compressed_log)})


async def handle_clear_compressed_log(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    state.compressed_log.clear()
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
        except (OSError, asyncssh.Error) as exc:
            LOG.warning("connect attempt %d failed: %s", attempt, exc)
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
    app.router.add_get("/compressed_log", handle_compressed_log)
    app.router.add_post("/clear_compressed_log", handle_clear_compressed_log)

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
