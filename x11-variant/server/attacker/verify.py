import asyncio
import socket
import struct

from attacker.inject import ANCHOR


def build_connection_setup(cookie: bytes) -> bytes:
    if len(cookie) != 16:
        raise ValueError(f"cookie must be 16 bytes, got {len(cookie)}")
    # X11 protocol §"Connection Setup":
    #   byte-order(1)='B' major(2)=11 minor(2)=0 nlen(2)=18 dlen(2)=16 pad(2)
    #   "MIT-MAGIC-COOKIE-1"(18) pad(2) cookie(16)
    header = struct.pack(">BBHHHHH", ord("B"), 0, 11, 0, 18, 16, 0)
    assert ANCHOR == b"MIT-MAGIC-COOKIE-1\x00\x00"
    return header + ANCHOR + cookie


async def authenticate(target_port: int, cookie_hex: str) -> bool:
    cookie = bytes.fromhex(cookie_hex)
    setup = build_connection_setup(cookie)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _send_and_check, target_port, setup)


def _send_and_check(target_port: int, setup: bytes) -> bool:
    with socket.create_connection(("127.0.0.1", target_port), timeout=5.0) as s:
        s.sendall(setup)
        s.settimeout(5.0)
        reply = s.recv(8)
    if not reply:
        return False
    return reply[0] == 0x01
