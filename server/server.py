"""SSH server side of the CRIME-on-SSH PoC.

Forces zlib compression in both directions, accepts a single user
authenticating with a public key, and exposes two trivial sinks (one
intended to receive the secret, the other intended to receive the
attacker's chosen payload).  All inputs are simply discarded after the
size is logged so we can confirm what was actually delivered over each
channel.
"""

import asyncio
import logging
import os
import sys

import asyncssh

LOG = logging.getLogger("server")

KEYS_DIR = "/keys"
HOST_KEY = os.path.join(KEYS_DIR, "server_host_key")
AUTHORIZED_USER_KEY = os.path.join(KEYS_DIR, "client_user_key.pub")

USERNAME = "victim"

# Force compression on; do NOT include "none" so the handshake fails
# loudly if the client refuses to compress.
COMPRESSION_ALGS = ["zlib@openssh.com", "zlib"]


async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    """One coroutine per session channel.  Reads stdin until EOF / close."""
    cmd = process.command or "<no-command>"
    peer = process.get_extra_info("peername")
    LOG.info("session opened: command=%r peer=%s", cmd, peer)

    total = 0
    try:
        while True:
            chunk = await process.stdin.read(65536)
            if not chunk:
                break
            total += len(chunk)
            LOG.info("[%s] received chunk: %d bytes (total=%d)", cmd, len(chunk), total)
    except asyncssh.BreakReceived:
        pass
    except asyncssh.misc.ConnectionLost:
        LOG.info("[%s] connection lost", cmd)
    except Exception:  # noqa: BLE001
        LOG.exception("[%s] handler error", cmd)
    finally:
        LOG.info("[%s] session closed (total=%d bytes)", cmd, total)
        try:
            process.exit(0)
        except Exception:  # noqa: BLE001
            pass


class PoCServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        LOG.info("connection from %s", peer)
        self._conn = conn

    def connection_lost(self, exc: BaseException | None) -> None:
        if exc:
            LOG.warning("connection lost: %s", exc)
        else:
            LOG.info("connection closed")

    def begin_auth(self, username: str) -> bool:
        # Force public-key auth (no none-auth shortcut)
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if not os.path.exists(HOST_KEY):
        LOG.error("missing host key at %s", HOST_KEY)
        return 1
    if not os.path.exists(AUTHORIZED_USER_KEY):
        LOG.error("missing authorized client key at %s", AUTHORIZED_USER_KEY)
        return 1

    LOG.info("starting SSH server on 0.0.0.0:22 (user=%s)", USERNAME)
    LOG.info("forced compression algorithms (s2c & c2s): %s", COMPRESSION_ALGS)

    await asyncssh.create_server(
        PoCServer,
        host="0.0.0.0",
        port=22,
        server_host_keys=[HOST_KEY],
        authorized_client_keys=AUTHORIZED_USER_KEY,
        process_factory=handle_session,
        compression_algs=COMPRESSION_ALGS,
        # encoding=None puts session streams in binary mode so arbitrary
        # attacker-chosen byte sequences can pass through cleanly.
        encoding=None,
        # Allow multiple sessions on a single connection - this is the
        # default in AsyncSSH but make it explicit here.
        keepalive_interval=0,
    )

    LOG.info("server listening")
    await asyncio.Event().wait()  # block forever
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
