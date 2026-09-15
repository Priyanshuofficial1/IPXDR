from __future__ import annotations
import csv, json
from pathlib import Path
from collections.abc import Iterator
from .models import FlowEvent

class FlowRecordIngestor:
    """Read-only adapter for JSONL or CSV/NetFlow-like exported flow records."""
    def __init__(self, path: str | Path): self.path=Path(path)
    def events(self) -> Iterator[FlowEvent]:
        if not self.path.is_file(): raise FileNotFoundError(self.path)
        if self.path.suffix.lower() in {'.jsonl','.ndjson'}:
            for line in self.path.read_text().splitlines():
                if line.strip(): yield FlowEvent.model_validate(json.loads(line))
            return
        with self.path.open(newline='') as f:
            for row in csv.DictReader(f):
                # Accept common NetFlow/IPFIX export aliases.
                aliases={'src_ip':['src_ip','srcaddr','source_ip'],'dst_ip':['dst_ip','dstaddr','destination_ip'],
                         'src_port':['src_port','sport','l4_src_port'],'dst_port':['dst_port','dport','l4_dst_port'],
                         'bytes':['bytes','octets','in_bytes'],'packets':['packets','pkts','in_pkts'],
                         'protocol':['protocol','proto'],'timestamp':['timestamp','start','flow_start']}
                def val(k,default=None):
                    for a in aliases.get(k,[k]):
                        if row.get(a) not in (None,''): return row[a]
                    return default
                yield FlowEvent(event_id=row.get('event_id') or f'flow-{id(row)}',timestamp=val('timestamp'),
                    src_ip=val('src_ip','0.0.0.0'),dst_ip=val('dst_ip','0.0.0.0'),src_port=int(val('src_port',0)),
                    dst_port=int(val('dst_port',0)),protocol=str(val('protocol','UNKNOWN')).upper(),
                    packets=int(float(val('packets',1))),bytes=int(float(val('bytes',0))),duration_ms=int(float(row.get('duration_ms',0))),
                    tcp_flags=[x for x in str(row.get('tcp_flags','')).split(',') if x],direction=row.get('direction','unknown'),source='flow_export')
