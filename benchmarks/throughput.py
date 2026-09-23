"""Reproducible end-to-end pipeline benchmark."""
from __future__ import annotations
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import argparse, json, statistics, time
from datetime import datetime, timedelta, timezone
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def make(n):
    base=datetime(2026,1,1,tzinfo=timezone.utc)
    for i in range(n):
        yield FlowEvent(event_id=f'bench-{i}',timestamp=base+timedelta(milliseconds=i),src_ip=f'10.0.{i%20}.{i%240+1}',dst_ip=f'192.0.2.{i%200+1}',src_port=20000+i%40000,dst_port=443 if i%2 else 53,protocol='TCP' if i%2 else 'UDP',packets=3+i%4,bytes=300+i%500,duration_ms=10,tcp_flags=['ACK'] if i%2 else [],direction='outbound',source='benchmark')

def main():
    p=argparse.ArgumentParser(); p.add_argument('-n','--events',type=int,default=10000); p.add_argument('--json',action='store_true'); p.add_argument('--output',type=str); a=p.parse_args()
    pipe=Pipeline(); lat=[]; total_bytes=0; start=time.perf_counter()
    for e in make(a.events):
        t=time.perf_counter(); pipe.process(e); lat.append((time.perf_counter()-t)*1000); total_bytes+=e.bytes
    elapsed=time.perf_counter()-start; rate=a.events/elapsed; mbps=(total_bytes*8/elapsed)/1e6
    result={'events':a.events,'elapsed_s':elapsed,'events_per_s':rate,'mbps':mbps,'latency_ms':{'p50':statistics.median(lat),'p95':sorted(lat)[int(.95*len(lat))-1],'p99':sorted(lat)[int(.99*len(lat))-1]},'alerts':len(pipe.alerts.items)}
    if a.output: _Path(a.output).write_text(json.dumps(result, indent=2) + chr(10), encoding='utf-8')
    print(json.dumps(result,indent=2) if a.json else f"{a.events:,} events | {elapsed:.3f}s | {rate:.2f} events/s | {mbps:.4f} Mbps | p95 {result['latency_ms']['p95']:.3f} ms | alerts {result['alerts']}")

if __name__=='__main__': main()
