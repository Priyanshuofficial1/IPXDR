from __future__ import annotations
import struct, socket
from datetime import datetime, timezone
from collections.abc import Iterator
from .models import FlowEvent

class SFlowDecoder:
    """Read-only sFlow v5 decoder for flow samples with raw IPv4/IPv6 packet headers."""
    def decode(self, data: bytes, source='sflow') -> Iterator[FlowEvent]:
        if len(data)<28: raise ValueError('truncated sFlow datagram')
        ver,addr_type,addr,sub,seq,uptime,samples=struct.unpack_from('!7I',data,0); _=(addr_type,addr,sub,uptime)
        if ver!=5: raise ValueError('unsupported sFlow version')
        p=28
        for _i in range(samples):
            if p+8>len(data): raise ValueError('truncated sFlow sample')
            fmt,ln=struct.unpack_from('!II',data,p); p+=8
            end=p+ln
            if end>len(data): raise ValueError('truncated sFlow sample body')
            sample=fmt & 0x0fff
            if sample in (1,2) and ln>=36:
                seqno,sourceid,sampling,rate,pool,drops,ifin,ifout,records=struct.unpack_from('!9I',data,p); _=(seqno,sourceid,sampling,rate,pool,drops,ifin,ifout)
                q=p+36
                for _r in range(records):
                    if q+8>end: break
                    rfmt,rln=struct.unpack_from('!II',data,q); q+=8; rend=q+rln
                    if rend>end: break
                    if (rfmt & 0x0fff) == 1 and rln >= 16:
                        hdrproto,frame_len,stripped,cap_len=struct.unpack_from('!4I',data,q); _=(hdrproto,frame_len,stripped)
                        raw=data[q+16:min(q+16+cap_len,rend)]
                        ev=self._packet(raw,seqno)
                        if ev: yield ev
                    q=(rend+3)&~3
            p=(end+3)&~3
    def _packet(self, raw, seqno):
        if len(raw)<14: return None
        eth=struct.unpack_from('!H',raw,12)[0]; off=14
        if eth==0x8100 and len(raw)>=18: eth=struct.unpack_from('!H',raw,16)[0]; off=18
        if eth==0x0800 and len(raw)>=off+20:
            ihl=(raw[off]&15)*4; proto=raw[off+9]; src=socket.inet_ntoa(raw[off+12:off+16]); dst=socket.inet_ntoa(raw[off+16:off+20]); off+=ihl
        elif eth==0x86dd and len(raw)>=off+40:
            proto=raw[off+6]; src=socket.inet_ntop(socket.AF_INET6,raw[off+8:off+24]); dst=socket.inet_ntop(socket.AF_INET6,raw[off+24:off+40]); off+=40
        else: return None
        sport=dport=0
        if proto in (6,17) and len(raw)>=off+4: sport,dport=struct.unpack_from('!HH',raw,off)
        return FlowEvent(event_id=f'sflow-{seqno}-{id(raw)}',timestamp=datetime.now(timezone.utc),src_ip=src,dst_ip=dst,src_port=sport,dst_port=dport,protocol={6:'TCP',17:'UDP'}.get(proto,str(proto)),packets=1,bytes=len(raw),duration_ms=0,direction='unknown',source='sflow')
