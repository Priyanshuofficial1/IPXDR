from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterator
from scapy.all import IP, TCP, UDP, DNS, DNSQR, RawPcapReader
from .models import FlowEvent

PROTO = {6: "TCP", 17: "UDP"}

class PCAPIngestor:
    """Read-only PCAP adapter. It parses packets locally and never transmits them."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

    def events(self) -> Iterator[FlowEvent]:
        for index, (raw, meta) in enumerate(RawPcapReader(str(self.path))):
            from scapy.layers.l2 import Ether
            packet = Ether(raw)
            if IP not in packet:
                continue
            ip = packet[IP]
            if TCP in packet:
                transport = packet[TCP]
                src_port, dst_port, flags = transport.sport, transport.dport, [str(transport.flags)]
            elif UDP in packet:
                transport = packet[UDP]
                src_port, dst_port, flags = transport.sport, transport.dport, []
            else:
                src_port = dst_port = 0
                flags = []
            dns = None
            if DNS in packet and DNSQR in packet:
                q = packet[DNSQR]
                qname = q.qname.decode(errors="replace").rstrip(".")
                dns = {"query": qname, "qtype": int(q.qtype)}
            timestamp = datetime.fromtimestamp(float(meta.sec) + float(meta.usec) / 1_000_000, tz=timezone.utc)
            yield FlowEvent(
                event_id=f"pcap-{index}", timestamp=timestamp,
                src_ip=ip.src, dst_ip=ip.dst, src_port=int(src_port), dst_port=int(dst_port),
                protocol=PROTO.get(int(ip.proto), str(ip.proto)), packets=1, bytes=len(raw),
                duration_ms=0, tcp_flags=flags,
                direction="unknown", dns=dns, source="pcap",
            )
