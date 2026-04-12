"""Minimal victim container for the Ansible SSH compression vulnerability PoC.

Runs ansible-playbook with ``become: yes`` on request.  Each run spawns
a fresh SSH subprocess that inherits the LocalForward declared in
/root/.ssh/config -- the "innocent helper port-forward the user pasted
into their ssh_config and forgot about" that the Ansible variant's
threat model relies on.

HTTP API (consumed by the test driver only; not by the attacker):

    GET  /status                -- liveness + current sudo password length
    POST /set_sudo_secret       -- rotate the victim's sudo password via
                                   a direct root SSH + chpasswd
    POST /send_secret_ansible   -- kill any in-flight ansible run and
                                   start a fresh one; return as soon as
                                   Ansible has written the sudo password
                                   to ssh's stdin
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Optional

from aiohttp import web

LOG = logging.getLogger("client")

# -- Paths --------------------------------------------------------------
KEYS_DIR = "/keys"
SERVER_HOST_KEY_PUB = f"{KEYS_DIR}/server_host_key.pub"
CLIENT_KEY = f"{KEYS_DIR}/client_user_key"
SSH_CONFIG_PATH = "/root/.ssh/config"
KNOWN_HOSTS_PATH = "/tmp/known_hosts"
ANSIBLE_DIR = "/app/ansible"
ANSIBLE_CFG = f"{ANSIBLE_DIR}/ansible.cfg"
ANSIBLE_INVENTORY = f"{ANSIBLE_DIR}/inventory.yml"
ANSIBLE_PLAYBOOK = f"{ANSIBLE_DIR}/playbook.yml"
ANSIBLE_VARS = "/tmp/ansible_vars.json"

# -- Configuration ------------------------------------------------------
ATTACKER_HOST = os.environ.get("ATTACKER_HOST", "attacker")
ATTACKER_PORT = int(os.environ.get("ATTACKER_PORT", "2222"))
SERVER_HOST = os.environ.get("SERVER_HOST", "server")
SSH_USER = os.environ.get("SSH_USER", "victim")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8000"))

# LocalForward declared in /root/.ssh/config and inherited by every
# ansible-playbook invocation.  The attacker connects to
# client:FWD_LOCAL_PORT to inject its guesses into the same zlib
# compression context as the sudo password.
FWD_LOCAL_PORT = int(os.environ.get("FWD_LOCAL_PORT", "15432"))
FWD_DEST_HOST = os.environ.get("FWD_DEST_HOST", "target")
FWD_DEST_PORT = int(os.environ.get("FWD_DEST_PORT", "6379"))

SUDO_SECRET = os.environ.get("SUDO_SECRET", "hunter2")

# Marker Ansible writes to stdout immediately before the sudo password
# hits ssh's stdin.  Only emitted when ANSIBLE_DEBUG=1 is set.
MARKER = b"Sending become_password in response to prompt"




def _write_configs() -> None:
    """Write SSH config and known_hosts.  Ansible config, inventory, and
    playbook are COPY'd into the image by the Dockerfile."""
    os.makedirs("/root/.ssh", exist_ok=True)
    os.chmod("/root/.ssh", 0o700)
    with open(SERVER_HOST_KEY_PUB) as f:
        hostkey = f.read().strip()
    with open(KNOWN_HOSTS_PATH, "w") as f:
        f.write(f"[{ATTACKER_HOST}]:{ATTACKER_PORT} {hostkey}\n")
        f.write(f"{SERVER_HOST} {hostkey}\n")
    os.chmod(KNOWN_HOSTS_PATH, 0o600)

    ssh_config = (
        "Host ansible-target\n"
        f"    HostName {ATTACKER_HOST}\n"
        f"    Port {ATTACKER_PORT}\n"
        f"    User {SSH_USER}\n"
        f"    IdentityFile {CLIENT_KEY}\n"
        f"    UserKnownHostsFile {KNOWN_HOSTS_PATH}\n"
        "    StrictHostKeyChecking yes\n"
        f"    LocalForward 0.0.0.0:{FWD_LOCAL_PORT} "
        f"{FWD_DEST_HOST}:{FWD_DEST_PORT}\n"
        "    Compression yes\n"
        "    ControlMaster no\n"
        "    ControlPath none\n"
        "    ServerAliveInterval 60\n"
        "    ServerAliveCountMax 3\n"
        "\n"
        "Host server-root\n"
        f"    HostName {SERVER_HOST}\n"
        "    Port 22\n"
        "    User root\n"
        f"    IdentityFile {CLIENT_KEY}\n"
        f"    UserKnownHostsFile {KNOWN_HOSTS_PATH}\n"
        "    StrictHostKeyChecking yes\n"
        "    Compression no\n"
        "    BatchMode yes\n"
    )
    with open(SSH_CONFIG_PATH, "w") as f:
        f.write(ssh_config)
    os.chmod(SSH_CONFIG_PATH, 0o600)
    LOG.info("wrote ssh config + known_hosts")


async def _drain_for(stream: Optional[asyncio.StreamReader],
                     marker: bytes, event: asyncio.Event) -> None:
    if stream is None:
        return
    try:
        while True:
            line = await stream.readline()
            if not line:
                return
            if not event.is_set() and marker in line:
                event.set()
    except (asyncio.CancelledError, OSError):
        pass


class State:
    def __init__(self) -> None:
        self.sudo_secret: str = SUDO_SECRET
        self.ansible_proc: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._drain_tasks: list[asyncio.Task] = []

    async def set_sudo_password(self, new_password: str) -> None:
        """SSH to the server as root and run chpasswd to rotate the
        victim's sudo password."""
        if "\n" in new_password or "\r" in new_password:
            raise ValueError("sudo password must not contain newlines")
        async with self._lock:
            await self._kill_ansible()
        proc = await asyncio.create_subprocess_exec(
            "ssh", "-F", SSH_CONFIG_PATH, "server-root", "chpasswd",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(
            f"victim:{new_password}\n".encode("utf-8"),
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"chpasswd failed (rc={proc.returncode}): {stderr!r}"
            )
        self.sudo_secret = new_password
        LOG.info("sudo password rotated (length=%d)", len(new_password))

    async def _kill_ansible(self) -> None:
        """Kill the previous ansible-playbook run and release its
        LocalForward socket.  SIGTERM first for graceful SSH teardown,
        then SIGKILL if it doesn't exit within 3 seconds."""
        proc = self.ansible_proc
        if proc is None:
            return
        if proc.returncode is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
        for task in self._drain_tasks:
            if not task.done():
                task.cancel()
        for task in self._drain_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._drain_tasks = []
        self.ansible_proc = None

    async def send_secret_ansible(self, timeout: float = 20.0) -> dict:
        """Start a fresh ansible-playbook run and block until Ansible
        has written the sudo password to ssh's stdin."""
        async with self._lock:
            await self._kill_ansible()

            # Pass the current sudo password via an extra-vars file
            # (mode 0600) so it never reaches argv / /proc/*/cmdline.
            with open(ANSIBLE_VARS, "w") as f:
                json.dump({"ansible_become_password": self.sudo_secret}, f)
            os.chmod(ANSIBLE_VARS, 0o600)

            env = os.environ.copy()
            env.update({
                "ANSIBLE_CONFIG": ANSIBLE_CFG,
                "PYTHONUNBUFFERED": "1",
                "ANSIBLE_FORCE_COLOR": "0",
                # Needed for display.debug() -- that's the code path
                # that writes the "Sending become_password" marker.
                "ANSIBLE_DEBUG": "1",
            })

            self.ansible_proc = await asyncio.create_subprocess_exec(
                "ansible-playbook", "-vvv",
                "-i", ANSIBLE_INVENTORY,
                "--extra-vars", f"@{ANSIBLE_VARS}",
                ANSIBLE_PLAYBOOK,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                # Own process group so killpg cascades to the ssh slave.
                start_new_session=True,
            )

            sent = asyncio.Event()
            self._drain_tasks = [
                asyncio.create_task(
                    _drain_for(self.ansible_proc.stdout, MARKER, sent)),
                asyncio.create_task(
                    _drain_for(self.ansible_proc.stderr, MARKER, sent)),
            ]

            exit_task = asyncio.create_task(self.ansible_proc.wait())
            marker_task = asyncio.create_task(sent.wait())
            done, _ = await asyncio.wait(
                {exit_task, marker_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if marker_task in done:
                exit_task.cancel()
                # Small settle so the CHANNEL_DATA is actually on the
                # wire before the attacker opens its measure tunnel.
                await asyncio.sleep(0.1)
                return {"ok": True, "marker": "password_sent"}
            marker_task.cancel()
            if exit_task.done():
                rc = self.ansible_proc.returncode
                await self._kill_ansible()
                raise RuntimeError(
                    f"ansible-playbook exited (rc={rc}) before sending password"
                )
            await self._kill_ansible()
            raise asyncio.TimeoutError(
                f"ansible-playbook did not reach the password marker in {timeout}s"
            )


# ---------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------

async def handle_status(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    return web.json_response({
        "ok": True,
        "sudo_secret_length": len(state.sudo_secret),
    })


async def handle_send_secret_ansible(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    try:
        result = await state.send_secret_ansible()
    except asyncio.TimeoutError as exc:
        LOG.exception("send_secret_ansible timed out")
        return web.json_response({"ok": False, "error": str(exc)}, status=504)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("send_secret_ansible failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response(result)


async def handle_set_sudo_secret(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    body = await request.json()
    value = body.get("value")
    if not isinstance(value, str):
        return web.json_response(
            {"ok": False, "error": "missing 'value'"}, status=400,
        )
    try:
        await state.set_sudo_password(value)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("set_sudo_secret failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({"ok": True, "sudo_secret_length": len(value)})


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------

async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    _write_configs()
    state = State()

    # Set the initial sudo password.  Retries because sshd might still
    # be initialising when we start.
    for attempt in range(1, 41):
        try:
            await state.set_sudo_password(SUDO_SECRET)
            break
        except (OSError, RuntimeError) as exc:
            LOG.warning("initial set_sudo_password attempt %d: %s", attempt, exc)
            await asyncio.sleep(1.0)
    else:
        LOG.error("could not set initial sudo password after retries")
        return 1

    app = web.Application()
    app["state"] = state
    app.router.add_get("/status", handle_status)
    app.router.add_post("/send_secret_ansible", handle_send_secret_ansible)
    app.router.add_post("/set_sudo_secret", handle_set_sudo_secret)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP API on :%d", HTTP_PORT)

    await asyncio.Event().wait()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
