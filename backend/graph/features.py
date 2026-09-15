from __future__ import annotations
from collections import Counter
from math import log2

def _entropy(values):
    c=Counter(values); n=sum(c.values())
    return -sum((v/n)*log2(v/n) for v in c.values()) if n else 0.0

def communication_features(events):
    pairs={(e.src_ip,e.dst_ip) for e in events}; nodes={e.src_ip for e in events}|{e.dst_ip for e in events}
    dsts=[e.dst_ip for e in events]; ports=[e.dst_port for e in events]
    return {'graph_nodes':float(len(nodes)),'graph_edges':float(len(pairs)),'graph_unique_ports':float(len(set(ports))),
            'fanout':float(len(set(dsts))),'destination_entropy':_entropy(dsts),'host_destination_reuse':len(dsts)/max(1,len(set(dsts)))}
