"""One-command offline SIH demonstration using synthetic passive metadata."""
from __future__ import annotations
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from datetime import datetime, timedelta, timezone
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline
BASE=datetime.now(timezone.utc)

def event(i,src,dst,sp,dp,proto,packets,bytes_,direction='outbound',dns=None,tls=None):
    return FlowEvent(event_id=f'demo-{i}',timestamp=BASE+timedelta(milliseconds=i*100),src_ip=src,dst_ip=dst,src_port=sp,dst_port=dp,protocol=proto,packets=packets,bytes=bytes_,duration_ms=20,tcp_flags=['SYN'] if proto=='TCP' and packets==1 else ['ACK'],direction=direction,source='sih-demo',dns=dns,tls=tls)

def scenario():
    ev=[]
    for i in range(20): ev.append(event(i,'10.10.1.10','198.51.100.10',30000+i,443,'TCP',1,90))
    for i in range(20,45): ev.append(event(i,'10.10.1.20',f'198.51.100.{20+i%3}',40000+i,443,'UDP',30,18000))
    for i in range(45,65): ev.append(event(i,'10.10.1.30','203.0.113.53',50000+i,53,'UDP',2,500,dns={'query':f'{i}xq7v9m2k8z4.example.test','qtype':'A'}))
    for i in range(65,85): ev.append(event(i,'10.10.1.40','203.0.113.80',20000+i,1000+i,'TCP',1,80))
    for i in range(85,105): ev.append(event(i,'10.10.1.50','198.51.100.200',35000+i,443,'TCP',5,50000,direction='outbound'))
    return ev

def main():
    p=Pipeline(); print('IPXDR — SIH26145 passive detection demo'); print('Generating synthetic metadata only; no packets are transmitted.')
    for e in scenario(): p.process(e)
    print(f'Processed: {p.stats.accepted} | Alerts: {len(p.alerts.items)} | Hosts: {len(p.behavior.hosts)}')
    for a in p.alerts.list(20): print(f"[{a.severity}] {a.threat_class:<24} {a.confidence:.1%} :: {'; '.join(a.supporting_evidence[:3])}")
    print('Dashboard: http://127.0.0.1:8000/dashboard')
if __name__=='__main__': main()
