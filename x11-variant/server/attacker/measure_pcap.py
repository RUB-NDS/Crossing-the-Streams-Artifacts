"""Per-packet egress measurement via scapy AsyncSniffer.

Replaces /sys/class/net/eth0/statistics/tx_bytes polling for the PoC. Requires
CAP_NET_RAW on the container (`cap_add: [NET_ADMIN, NET_RAW]` in compose).

The engine's oracle clears the log before each probe and snapshots after the
settle. Sum of tcp_payload_len over the captured packets in that window is
the egress signal — same shape as the existing PoC's _sum_c2s helper, except
filtered for SERVER->CLIENT direction (src port 22 on server container's
eth0).
"""

import logging
import os
import threading
import time
from typing import Any

from scapy.all import IP, TCP, AsyncSniffer

LOG = logging.getLogger("attacker.measure_pcap")

SNIFF_IFACE = os.environ.get("SNIFF_IFACE", "eth0")
SSHD_PORT = int(os.environ.get("SSHD_PORT", "22"))
SNIFF_FILTER = f"tcp and src port {SSHD_PORT}"


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


def _on_packet(pkt) -> None:
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    tcp = pkt[TCP]
    tcp_payload_len = ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)
    PACKET_LOG.add({
        "ts": time.time(),
        "src": ip.src,
        "dst": ip.dst,
        "sport": int(tcp.sport),
        "dport": int(tcp.dport),
        "flags": str(tcp.flags),
        "seq": int(tcp.seq),
        "tcp_payload_len": int(tcp_payload_len),
    })


_sniffer: AsyncSniffer | None = None


def start() -> None:
    global _sniffer
    if _sniffer is not None:
        return
    LOG.info("starting AsyncSniffer iface=%s filter=%r", SNIFF_IFACE, SNIFF_FILTER)
    _sniffer = AsyncSniffer(
        iface=SNIFF_IFACE,
        filter=SNIFF_FILTER,
        prn=_on_packet,
        store=False,
    )
    _sniffer.start()


def stop() -> None:
    global _sniffer
    if _sniffer is None:
        return
    try:
        _sniffer.stop()
    except Exception:  # noqa: BLE001
        pass
    _sniffer = None


def sum_payload(records: list[dict[str, Any]]) -> int:
    return sum(r["tcp_payload_len"] for r in records)
