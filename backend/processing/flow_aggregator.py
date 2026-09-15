from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict
from backend.ingestion.models import FlowEvent

@dataclass
class _State:
    first: datetime
    last: datetime
    packets: int
    bytes: int
    flags: set[str]
    dns: dict | None
    tls: dict | None
    quic: dict | None

class FlowAggregator:
    """Bounded passive 5-tuple flow aggregation. It never transmits packets."""
    def __init__(self, idle_timeout_s=15, max_flows=50000):
        if idle_timeout_s <= 0 or max_flows <= 0: raise ValueError('invalid aggregator limits')
        self.idle_timeout_s=idle_timeout_s; self.max_flows=max_flows; self._flows={}; self._seq=0

    def add(self,event: FlowEvent) -> list[FlowEvent]:
        key=(event.src_ip,event.dst_ip,event.src_port,event.dst_port,event.protocol.upper())
        emitted=[]; state=self._flows.get(key)
        if state and (event.timestamp-state.last).total_seconds() > self.idle_timeout_s:
            emitted.append(self._emit(key,state)); state=None
        if state is None:
            state=_State(event.timestamp,event.timestamp,0,0,set(),event.dns,event.tls,event.quic); self._flows[key]=state
        state.last=max(state.last,event.timestamp); state.packets+=event.packets; state.bytes+=event.bytes
        state.flags.update(event.tcp_flags); state.dns=state.dns or event.dns; state.tls=state.tls or event.tls; state.quic=state.quic or event.quic
        if len(self._flows)>self.max_flows:
            oldest=min(self._flows,key=lambda k:self._flows[k].last); emitted.append(self._emit(oldest,self._flows.pop(oldest)))
        return emitted

    def flush(self)->list[FlowEvent]:
        out=[self._emit(k,s) for k,s in self._flows.items()]; self._flows.clear(); return out
    def _emit(self,key,state):
        src,dst,sp,dp,proto=key; self._seq+=1
        return FlowEvent(event_id=f'flow-{self._seq}',timestamp=state.first,src_ip=src,dst_ip=dst,src_port=sp,dst_port=dp,protocol=proto,packets=state.packets,bytes=state.bytes,duration_ms=max(0,(state.last-state.first).total_seconds()*1000),tcp_flags=sorted(state.flags),direction='unknown',dns=state.dns,tls=state.tls,quic=state.quic,source='pcap-flow')
