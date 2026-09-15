from __future__ import annotations
import struct
from datetime import datetime, timezone
from collections.abc import Iterator
from .models import FlowEvent

# RFC 7011/7012: practical decoder for common IPFIX IEs. Read-only; no network I/O.
_IE = {1:'bytes',2:'packets',4:'protocol',7:'src_port',8:'src_ip',12:'dst_ip',11:'dst_port',152:'start_epoch',153:'end_epoch',27:'src_ip',28:'dst_ip',58:'tcp_flags'}
_FMT = {1:'!Q',2:'!Q',4:'!B',7:'!H',11:'!H',58:'!B'}

class IPFIXDecoder:
    def __init__(self): self.templates: dict[tuple[int,int], list[tuple[int,int]]]={}
    @staticmethod
    def _value(ie, raw):
        if ie in (8,12,27,28) and len(raw)==4: return '.'.join(map(str,raw))
        if ie in (7,11) and len(raw)==2: return struct.unpack('!H',raw)[0]
        if ie in (1,2) and len(raw)<=8: return int.from_bytes(raw,'big')
        if ie==4 and raw: return str(raw[0])
        if ie==58 and raw: return raw[0]
        if ie in (152,153) and len(raw)==4: return datetime.fromtimestamp(int.from_bytes(raw,'big'),tz=timezone.utc)
        return None
    def decode(self, data: bytes, source='ipfix') -> Iterator[FlowEvent]:
        off=0; ordinal=0
        while off+16 <= len(data):
            ver,length,export,seq,domain=struct.unpack_from('!HHIII',data,off)
            if ver != 10 or length < 16 or off+length > len(data): raise ValueError('invalid IPFIX message')
            end=off+length; pos=off+16
            while pos+4<=end:
                set_id,set_len=struct.unpack_from('!HH',data,pos)
                if set_len<4 or pos+set_len>end: raise ValueError('invalid IPFIX set')
                body=data[pos+4:pos+set_len]
                if set_id==2:
                    p=0
                    while p+4<=len(body):
                        tid,count=struct.unpack_from('!HH',body,p); p+=4; fields=[]
                        for _ in range(count):
                            if p+4>len(body): raise ValueError('truncated IPFIX template')
                            ie,l=struct.unpack_from('!HH',body,p); p+=4
                            enterprise=bool(ie&0x8000); ie &= 0x7fff
                            if enterprise:
                                if p+4>len(body): raise ValueError('truncated enterprise IE')
                                p+=4
                            fields.append((ie,l))
                        self.templates[(domain,tid)]=fields
                elif set_id>=256:
                    fields=self.templates.get((domain,set_id))
                    if fields:
                        p=0; size=sum(l for _,l in fields)
                        while p+size<=len(body) and size:
                            row={}
                            for ie,l in fields:
                                raw=body[p:p+l]; p+=l; v=self._value(ie,raw)
                                if v is not None: row[ie]=v
                            if 8 in row and 12 in row:
                                ordinal+=1
                                ts=row.get(152, datetime.fromtimestamp(export,tz=timezone.utc))
                                yield FlowEvent(event_id=f'ipfix-{seq}-{ordinal}',timestamp=ts,src_ip=row[8],dst_ip=row[12],src_port=row.get(7,0),dst_port=row.get(11,0),protocol=row.get(4,'UNKNOWN'),packets=row.get(2,1),bytes=row.get(1,0),tcp_flags=[str(row[58])] if 58 in row else [],duration_ms=0,direction='unknown',source=source)
                pos+=set_len
            off=end
