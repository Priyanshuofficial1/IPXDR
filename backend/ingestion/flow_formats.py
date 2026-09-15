from __future__ import annotations
import csv,json
from pathlib import Path
from collections.abc import Iterator
from datetime import datetime, timezone
from .models import FlowEvent

def _timestamp(v):
    if v in (None,''): return datetime.now(timezone.utc)
    if isinstance(v,datetime): return v
    s=str(v).strip()
    try: return datetime.fromisoformat(s.replace('Z','+00:00'))
    except ValueError: pass
    for fmt in ('%Y-%m-%d %H:%M:%S.%f','%Y-%m-%d %H:%M:%S','%d/%m/%Y %H:%M:%S'):
        try: return datetime.strptime(s,fmt).replace(tzinfo=timezone.utc)
        except ValueError: continue
    try: return datetime.fromtimestamp(float(s),tz=timezone.utc)
    except ValueError: raise ValueError(f'unsupported timestamp: {s}')

class FlowRecordIngestor:
    """Read-only adapter for JSONL or CSV flow exports (NetFlow/IPFIX/sFlow exporter output)."""
    def __init__(self,path): self.path=Path(path)
    def events(self)->Iterator[FlowEvent]:
        if not self.path.is_file(): raise FileNotFoundError(self.path)
        if self.path.suffix.lower() in {'.jsonl','.ndjson'}:
            for line in self.path.read_text().splitlines():
                if line.strip(): yield FlowEvent.model_validate(json.loads(line))
            return
        with self.path.open(newline='',encoding='utf-8-sig') as f:
            for i,row in enumerate(csv.DictReader(f),1):
                aliases={'src_ip':['src_ip','srcaddr','source_ip'],'dst_ip':['dst_ip','dstaddr','destination_ip'],'src_port':['src_port','sport','l4_src_port'],'dst_port':['dst_port','dport','l4_dst_port'],'bytes':['bytes','octets','in_bytes'],'packets':['packets','pkts','in_pkts'],'protocol':['protocol','proto'],'timestamp':['timestamp','start','flow_start']}
                def val(k,d=None):
                    for a in aliases.get(k,[k]):
                        if row.get(a) not in (None,''): return row[a]
                    return d
                yield FlowEvent(event_id=row.get('event_id') or f'flow-{i}',timestamp=_timestamp(val('timestamp')),src_ip=val('src_ip','0.0.0.0'),dst_ip=val('dst_ip','0.0.0.0'),src_port=int(float(val('src_port',0))),dst_port=int(float(val('dst_port',0))),protocol=str(val('protocol','UNKNOWN')).upper(),packets=int(float(val('packets',1))),bytes=int(float(val('bytes',0))),duration_ms=int(float(row.get('duration_ms',0) or 0)),tcp_flags=[x for x in str(row.get('tcp_flags','')).replace('|',',').split(',') if x],direction=row.get('direction','unknown'),source='flow_export')
