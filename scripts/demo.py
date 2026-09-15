"""One-command offline SIH demonstration using synthetic passive metadata only."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from datetime import datetime,timedelta,timezone
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline
BASE=datetime.now(timezone.utc)

def event(i,src,dst,sp,dp,proto,packets,bytes_,direction='outbound',dns=None,tls=None,quic=None):
    return FlowEvent(event_id=f'demo-{i}',timestamp=BASE+timedelta(milliseconds=i*100),src_ip=src,dst_ip=dst,src_port=sp,dst_port=dp,protocol=proto,packets=packets,bytes=bytes_,duration_ms=20,tcp_flags=['SYN'] if proto=='TCP' and packets==1 else ['ACK'],direction=direction,source='sih-demo',dns=dns,tls=tls,quic=quic)

def scenario():
    ev=[]
    # Normal baseline.
    for i in range(20): ev.append(event(i,'10.10.1.10','198.51.100.10',30000+i,443,'TCP',1,90))
    # SYN flood.
    for i in range(20,45): ev.append(event(i,'10.10.1.20',f'198.51.100.{20+i%3}',40000+i,443,'TCP',1,80))
    # UDP volumetric + reflection-like fan-in.
    for i in range(45,70): ev.append(event(i,f'10.10.2.{i}', '10.10.1.30',50000+i,53,'UDP',30,18000))
    # C2 beaconing: periodic inter-arrivals.
    for i in range(70,90): ev.append(event(i,'10.10.1.40','203.0.113.90',45000+i,443,'TCP',3,240))
    # DGA + DNS tunneling characteristics.
    for i in range(90,115): ev.append(event(i,'10.10.1.50','203.0.113.53',51000+i,53,'UDP',2,900,dns={'query':f'{i}xq7v9m2k8z4p1r6abcdefghijk9876543210payloadsegment.example.test','qtype':'TXT'}))
    # Recon fan-out.
    for i in range(115,140): ev.append(event(i,'10.10.1.60',f'203.0.113.{i}',20000+i,1000+i,'TCP',1,80))
    # Exfilmetry: establish inbound context, then much larger outbound volume.
    for i in range(140,150): ev.append(event(i,'10.10.1.70','198.51.100.5',443,52000+i,'TCP',3,200,direction='inbound'))
    for i in range(150,175): ev.append(event(i,'10.10.1.70','198.51.100.200',52000+i,443,'TCP',20,50000,direction='outbound'))
    # Encrypted metadata-only session.
    for i in range(175,195): ev.append(event(i,'10.10.1.80','198.51.100.220',53000+i,443,'TCP',8,1300,tls={'ja3':'demo-novel-ja3','sni':'cdn.example.test','cipher_count':18,'extension_count':12}))
    return ev

def main():
    p=Pipeline(); print('IPXDR — SIH26145 passive detection demo'); print('Synthetic metadata only; no packets are transmitted or replayed.')
    for e in scenario(): p.process(e)
    print(f'Processed: {p.stats.accepted} | Alerts: {len(p.alerts.items)} | Hosts: {len(p.behavior.hosts)}')
    seen=[]
    for a in p.alerts.list(100):
        if a.threat_class not in seen: seen.append(a.threat_class)
    print('Threat classes observed:', ', '.join(seen) if seen else 'none')
    for a in p.alerts.list(18): print(f"[{a.severity}] {a.threat_class:<28} {a.confidence:.1%} :: {'; '.join(a.supporting_evidence[:3])}")
    print('Dashboard: http://127.0.0.1:8000/dashboard')
if __name__=='__main__': main()
