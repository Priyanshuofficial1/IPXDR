"""Controlled native-PCAP validation: benign traffic mixed with attack families.

This is a lab validation artifact, not a claim about production accuracy.
Packets are generated locally and replayed through the real PCAPIngestor -> Pipeline.
Ground truth is assigned by source IP because the lab generator controls each source.
"""
from __future__ import annotations
import argparse, json, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline

BASE_TS = 0.0
ATTACK_SOURCES = {
    'ddos': '10.77.0.20',
    'c2': '10.77.0.21',
    'dns_tunnel': '10.77.0.22',
    'recon': '10.77.0.23',
    'exfil': '10.77.0.24',
}
BENIGN_SOURCE = '10.77.0.10'

def pkt(src, dst, sport, dport, proto='tcp', ts=0.0, payload=b''):
    if proto == 'udp': p=IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/payload
    else: p=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='A')/payload
    p.time=ts; return p

def build():
    p=[]
    # Benign DNS + web-like traffic: low rate, ordinary packet sizes.
    for i in range(12):
        t=i*6.0
        p.append(pkt(BENIGN_SOURCE,'8.8.8.8',40000+i,53,'udp',t,DNS(rd=1,qd=DNSQR(qname='example.com'))))
        p.append(pkt(BENIGN_SOURCE,'93.184.216.34',41000+i,443,'tcp',t+0.5, payload=b'GET / HTTP/1.1'))
    # SYN flood.
    for i in range(30):
        q=IP(src=ATTACK_SOURCES['ddos'],dst='10.77.1.10')/TCP(sport=20000+i,dport=443,flags='S'); q.time=100+i*0.05; p.append(q)
    # C2 beacon: repeated low-volume callbacks every 5 seconds.
    for i in range(16): p.append(pkt(ATTACK_SOURCES['c2'],'203.0.113.60',5000,443,'tcp',200+i*5,b'PING'))
    # DNS tunneling: long/high-entropy-looking labels and TXT queries.
    for i in range(18):
        label=('x9f3a7b2c5d8e1f0a' * 4) + str(i)
        q=IP(src=ATTACK_SOURCES['dns_tunnel'],dst='10.77.1.53')/UDP(sport=50000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=label+'.t.example',qtype='TXT')); q.time=300+i*2; p.append(q)
    # Recon: one source fans across many ports and destinations.
    for i in range(24): p.append(pkt(ATTACK_SOURCES['recon'],f'10.77.2.{10+i%4}',30000+i,1000+i,'tcp',350+i*0.5))
    # Exfil: sustained outbound bytes with tiny inbound acknowledgements.
    for i in range(16): p.append(pkt(ATTACK_SOURCES['exfil'],'203.0.113.100',35000+i,443,'tcp',400+i*2,b'X'*3000))
    return sorted(p,key=lambda x: float(x.time))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--pcap',type=Path,default=Path('benchmarks/results/native-mixed-lab.pcap')); ap.add_argument('--output',type=Path,default=Path('benchmarks/results/native-mixed-pcap-validation.json')); a=ap.parse_args()
    a.pcap.parent.mkdir(parents=True,exist_ok=True); packets=build(); wrpcap(str(a.pcap),packets)
    labels={BENIGN_SOURCE:'benign',**{v:k for k,v in ATTACK_SOURCES.items()}}
    pipe=Pipeline(); per_source=defaultdict(lambda:{'events':0,'alerts':0,'classes':Counter()}); total=0; failures=0
    for e in PCAPIngestor(a.pcap).events():
        total+=1
        try: pipe.process(e)
        except Exception: failures+=1; continue
        src=e.src_ip; per_source[src]['events']+=1
        for r in pipe.last_detector_results:
            if r.score>=0.5: per_source[src]['classes'][r.threat_class]+=1
        if pipe.alerts.items and pipe.alerts.items[-1].flow_id==e.event_id: per_source[src]['alerts']+=1
    benign_alerts=per_source[BENIGN_SOURCE]['alerts']
    attack_alerts=sum(v['alerts'] for k,v in per_source.items() if labels.get(k)=='ddos' or labels.get(k)=='c2' or labels.get(k)=='dns_tunnel' or labels.get(k)=='recon' or labels.get(k)=='exfil')
    result={'schema_version':'1.0','validation':'controlled_native_pcap','pcap':str(a.pcap),'packets_generated':len(packets),'events_processed':total,'events_failed':failures,'ground_truth':'source-IP labels assigned by the local generator','benign_alerts':benign_alerts,'attack_alerts':attack_alerts,'benign_false_positive_rate':0.0 if benign_alerts==0 else 1.0,'per_source':{k:{'label':labels.get(k,'unknown'),'events':v['events'],'alerts':v['alerts'],'detected_classes':dict(v['classes'])} for k,v in per_source.items()},'limitations':'Controlled lab PCAP; not a public-dataset accuracy claim. Benign traffic is intentionally simple.'}
    a.output.write_text(json.dumps(result,indent=2)); print(json.dumps(result,indent=2))
    raise SystemExit(0 if failures==0 and benign_alerts==0 and attack_alerts>0 else 1)
if __name__=='__main__': main()
