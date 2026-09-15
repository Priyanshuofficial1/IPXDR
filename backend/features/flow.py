from __future__ import annotations
from backend.processing.normalizer import NormalizedFlow

def extract_flow_features(event: NormalizedFlow) -> dict[str, float]:
    duration_s = max(event.duration_ms / 1000.0, 0.001)
    return {
        "packets": float(event.packets), "bytes": float(event.bytes),
        "duration_ms": float(event.duration_ms),
        "packets_per_second": event.packets / duration_s,
        "bytes_per_second": event.bytes / duration_s,
        "src_port": float(event.src_port), "dst_port": float(event.dst_port),
        "is_tcp": float(event.protocol == "TCP"), "is_udp": float(event.protocol == "UDP"),
        "syn": float("S" in "".join(event.tcp_flags) and "A" not in "".join(event.tcp_flags)),
        "ack": float("A" in "".join(event.tcp_flags)),
    }
