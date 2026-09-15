from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from backend.ingestion.models import FlowEvent

@dataclass(frozen=True, slots=True)
class NormalizedFlow:
    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    duration_ms: float
    tcp_flags: tuple[str, ...]
    direction: str
    dns: dict | None
    tls: dict | None
    quic: dict | None
    source: str

def normalize(event: FlowEvent) -> NormalizedFlow:
    return NormalizedFlow(
        event_id=event.event_id, timestamp=event.timestamp, src_ip=event.src_ip,
        dst_ip=event.dst_ip, src_port=event.src_port, dst_port=event.dst_port,
        protocol=event.protocol.upper(), packets=event.packets, bytes=event.bytes,
        duration_ms=event.duration_ms, tcp_flags=tuple(sorted(set(f.upper() for f in event.tcp_flags))),
        direction=event.direction.lower(), dns=event.dns, tls=event.tls, quic=event.quic,
        source=event.source.lower(),
    )
