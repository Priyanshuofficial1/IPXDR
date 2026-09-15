from __future__ import annotations
from collections import defaultdict
from backend.processing.normalizer import NormalizedFlow

def communication_features(events: list[NormalizedFlow]) -> dict[str,float]:
    pairs={(e.src_ip,e.dst_ip) for e in events}; nodes={e.src_ip for e in events}|{e.dst_ip for e in events}
    ports={e.dst_port for e in events}; return {'graph_nodes':float(len(nodes)),'graph_edges':float(len(pairs)),'graph_unique_ports':float(len(ports)),'fanout':float(len({e.dst_ip for e in events}))}
