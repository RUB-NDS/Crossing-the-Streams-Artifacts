"""SSH client side of the CRIME-on-SSH PoC.

The client connects to the *attacker's* TCP port (which forwards on to
the real SSH server) but pins the host key of the real server, so an
active in-the-middle attacker is detected at the SSH layer.  Once the
SSH transport is up the client opens two long-lived session channels:

  * "secret"   - intended to be used by the legitimate workflow that
                  periodically pushes the secret to the server.
  * "attacker" - intended to model an attacker-controlled side channel,
                  e.g. a tailed log file or a port forward whose payload
                  is fully under the attacker's control.

A small HTTP API exposes endpoints for triggering sends on either of
these channels.  In the threat model this stands in for the various
ways the attacker can coerce the victim into sending things (XSRF on a
local web UI, getting the victim to view an attacker-controlled file,
port-forward injection, ...).
"""

import asyncio
import logging
import os
import sys
from typing import Optional

import asyncssh
from aiohttp import web

LOG = logging.getLogger("client")

KEYS_DIR = "/keys"
SERVER_HOST_KEY_PUB = os.path.join(KEYS_DIR, "server_host_key.pub")
CLIENT_KEY = os.path.join(KEYS_DIR, "client_user_key")

SSH_TARGET_HOST = os.environ.get("SSH_TARGET_HOST", "attacker")
SSH_TARGET_PORT = int(os.environ.get("SSH_TARGET_PORT", "2222"))
SSH_REAL_SERVER = os.environ.get("SSH_REAL_SERVER", "server")
SSH_USERNAME = os.environ.get("SSH_USERNAME", "victim")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8000"))

# The legitimate workflow sends `<SECRET_PREFIX><value><SECRET_TERMINATOR>`
# on the secret channel.  The prefix is public knowledge -- it's the
# format the application uses (think `Cookie: sid=` in CRIME).  The value
# is the only thing the attacker is trying to recover.
SECRET_PREFIX = os.environ.get("SECRET_PREFIX", "PASSWORD=")
SECRET_TERMINATOR = os.environ.get("SECRET_TERMINATOR", "\n")
DEFAULT_SECRET_VALUE = os.environ.get("SECRET_VALUE", "hunter2")

COMPRESSION_ALGS = ["zlib@openssh.com", "zlib"]


class SSHState:
    """Holds the live SSH connection and its two long-lived sessions."""

    def __init__(self, secret_value: str) -> None:
        self.conn: Optional[asyncssh.SSHClientConnection] = None
        self.secret_proc: Optional[asyncssh.SSHClientProcess] = None
        self.attacker_proc: Optional[asyncssh.SSHClientProcess] = None
        self.secret_value: str = secret_value
        self._lock = asyncio.Lock()
        # Debug instrumentation: a ring of (uncompressed_len, compressed_len)
        # tuples, populated by a monkey-patched zlib compressor.  This is
        # an out-of-band debug channel for the test harness; the attacker
        # container does NOT use this -- it only sees encrypted wire bytes.
        self.compressed_log: list[tuple[int, int]] = []

    async def connect(self) -> None:
        # Load the real server's host key and pin it.  Even though the
        # client connects to attacker:2222, the SSH layer will verify
        # against the real server's key, so an active MitM (re-encrypt)
        # would be detected.
        host_key = asyncssh.read_public_key(SERVER_HOST_KEY_PUB)
        # known_hosts: trust this key for any hostname (we use the
        # 3-tuple form: (trusted_keys, ca_keys, revoked_keys)).
        known_hosts = ([host_key], [], [])

        LOG.info(
            "connecting to %s:%d (real server=%s) as %s",
            SSH_TARGET_HOST, SSH_TARGET_PORT, SSH_REAL_SERVER, SSH_USERNAME,
        )
        self.conn = await asyncssh.connect(
            host=SSH_TARGET_HOST,
            port=SSH_TARGET_PORT,
            username=SSH_USERNAME,
            client_keys=[CLIENT_KEY],
            known_hosts=known_hosts,
            compression_algs=COMPRESSION_ALGS,
            # Encryption / kex / mac left at defaults; we only care
            # about compression for the attack.
        )
        LOG.info("SSH transport established")
        send_alg = self.conn.get_extra_info("send_compression")
        recv_alg = self.conn.get_extra_info("recv_compression")
        LOG.info("compression: send=%s recv=%s", send_alg, recv_alg)

        # Open both long-lived sessions.  Each one runs an exec on the
        # server (the server doesn't actually care about the command
        # name -- it just consumes stdin -- but we use distinct names
        # to make it visible in the logs).
        #
        # encoding=None opens the streams in binary mode so we can write
        # raw bytes (attacker payloads won't always be valid UTF-8).
        LOG.info("opening 'secret' session channel")
        self.secret_proc = await self.conn.create_process(
            "secret-sink", encoding=None,
        )
        LOG.info("opening 'attacker' session channel")
        self.attacker_proc = await self.conn.create_process(
            "attacker-sink", encoding=None,
        )

        # Debug-only: monkey-patch the c->s compressor so we can read
        # off the actual compressed payload sizes.  This is an
        # out-of-band side channel used by the test harness to
        # validate the attack against ground truth -- the attacker
        # container never queries it.
        compressor = self.conn._compressor  # type: ignore[attr-defined]
        if compressor is not None:
            orig_compress = compressor.compress

            def wrapped_compress(data: bytes) -> bytes:
                out = orig_compress(data)
                # Capture the first byte (msg type) so we can
                # distinguish CHANNEL_DATA (94) from WINDOW_ADJUST (93)
                # etc.
                msg_type = data[0] if data else -1
                self.compressed_log.append(
                    (len(data), len(out), msg_type, data[:32].hex())
                )
                return out

            compressor.compress = wrapped_compress  # type: ignore[method-assign]
            LOG.info("instrumented send compressor for debug logging")
        else:
            LOG.warning("no send compressor present (compression disabled?)")

    async def reconnect(self) -> None:
        """Tear down and re-open the SSH connection.

        This resets the SSH transport's compression context (per
        RFC 4253 the LZ77 dictionary is discarded after a full
        re-key, and re-opening the TCP connection certainly does it).
        We use it between attack runs so a previous secret can't bleed
        into the next experiment via the LZ77 sliding window.
        """
        LOG.info("reconnecting (resets SSH compression context)")
        for proc_attr in ("secret_proc", "attacker_proc"):
            proc = getattr(self, proc_attr)
            if proc is not None:
                try:
                    proc.close()
                except Exception:  # noqa: BLE001
                    pass
                setattr(self, proc_attr, None)
        if self.conn is not None:
            try:
                self.conn.close()
                await self.conn.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self.conn = None
        await self.connect()

    async def send_secret(self) -> int:
        assert self.secret_proc is not None
        data = (SECRET_PREFIX + self.secret_value + SECRET_TERMINATOR).encode("utf-8")
        async with self._lock:
            self.secret_proc.stdin.write(data)
            await self.secret_proc.stdin.drain()
        return len(data)

    async def send_attacker_payload(self, payload: bytes) -> int:
        assert self.attacker_proc is not None
        async with self._lock:
            self.attacker_proc.stdin.write(payload)
            await self.attacker_proc.stdin.drain()
        return len(payload)

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
            "channels": {
                "secret": {
                    "open": self.secret_proc is not None
                            and not self.secret_proc.is_closing(),
                },
                "attacker": {
                    "open": self.attacker_proc is not None
                            and not self.attacker_proc.is_closing(),
                },
            },
            "secret_prefix": SECRET_PREFIX,
            "secret_terminator": SECRET_TERMINATOR,
            "secret_value_length": len(self.secret_value),
        }


# --------------------------------------------------------------------------
# HTTP control plane
# --------------------------------------------------------------------------

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


async def handle_send_attacker_payload(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    body = await request.read()
    if not body:
        return web.json_response(
            {"ok": False, "error": "empty payload"}, status=400,
        )
    try:
        n = await state.send_attacker_payload(body)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("send_attacker_payload failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({"ok": True, "bytes_written": n})


async def handle_set_secret(request: web.Request) -> web.Response:
    """Out-of-band test hook: change the secret and reset the SSH connection.

    Only used by the test harness, *not* by the attacker container.
    """
    state: SSHState = request.app["ssh"]
    body = await request.json()
    new_value = body.get("value")
    if not isinstance(new_value, str):
        return web.json_response(
            {"ok": False, "error": "missing string 'value'"}, status=400,
        )
    LOG.info("set_secret: new value length %d", len(new_value))
    state.secret_value = new_value
    await state.reconnect()
    return web.json_response({
        "ok": True,
        "secret_value_length": len(new_value),
    })


async def handle_reset(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    await state.reconnect()
    return web.json_response({"ok": True})


async def handle_compressed_log(request: web.Request) -> web.Response:
    """Debug-only ground-truth view of the compressor output sizes."""
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

    # Retry a few times in case attacker / server aren't quite up yet.
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

    app = web.Application()
    app["ssh"] = state
    app.router.add_get("/status", handle_status)
    app.router.add_post("/send_secret", handle_send_secret)
    app.router.add_post("/send_attacker_payload", handle_send_attacker_payload)
    app.router.add_post("/set_secret", handle_set_secret)
    app.router.add_post("/reset", handle_reset)
    app.router.add_get("/compressed_log", handle_compressed_log)
    app.router.add_post("/clear_compressed_log", handle_clear_compressed_log)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP control API listening on 0.0.0.0:%d", HTTP_PORT)

    await asyncio.Event().wait()  # block forever
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
