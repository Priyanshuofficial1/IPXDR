"""Controlled, offline evasion benchmark for IPXDR's passive detectors."""
from __future__ import annotations
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import argparse, json, random, statistics
from datetime import datetime, timedelta, timezone
from backend.ingestion.models import FlowEvent
from backend.detection.engine import DetectionEngine

BASE=datetime(2026,1,1,tzinfo=timezone.utc)

def beacon(jitter=0.0, volume=1.0, rotate=0, seed=7):
    rng=random.Random(seed); out=[]
    for i in range(24):
        gap=10*(1+rng.uniform(-jitter,jitter)); t=BASE+timedelta(seconds=i*10 + (rng.uniform(-1,1)*10*jitter if i else 0))
        dst=f'203.0.113.{10+(i%max(1,rotate+1))}'
        out.append(FlowEvent(event_id=f'b{i}',timestamp=t,src_ip='10.0.0.9',dst_ip=dst,src_port=40000+i,dst_port=443,protocol='TCP',packets=max(1,int(5*volume)),bytes=max(64,int(800*volume)),duration_ms=50,tcp_flags=['ACK'],direction='outbound',source='adversarial'))
    # preserve intended jitter through timestamps after constructing evenly spaced anchors
    for i,e in enumerate(out):
        e.timestamp=BASE+timedelta(seconds=(0 if i==0 else i*10+rng.uniform(-10*jitter,10*jitter)))
    return out

def run():
    p=argparse.ArgumentParser(); p.add_argument('--json',action='store_true'); a=p.parse_args()
    cases={'baseline':beacon(), 'timing_jitter':beacon(.35), 'volume_shift':beacon(0,.35), 'destination_rotation':beacon(.1,1,5), 'combined':beacon(.35,.5,5)}
    rows=[]
    for name,events in cases.items():
        eng=DetectionEngine(); _, results, alert=eng.analyze(events[-1],events,0.0)
        scores={r.threat_class:round(r.score,4) for r in results}
        rows.append({'case':name,'events':len(events),'scores':scores,'alert':alert.model_dump(mode='json') if alert else None})
    if a.json: print(json.dumps(rows,indent=2,default=str))
    else:
        print('IPXDR adversarial/evasion benchmark (offline synthetic only)')
        for r in rows: print(f"{r['case']:20} {r['scores']}")
    return rows
if __name__=='__main__': run()
