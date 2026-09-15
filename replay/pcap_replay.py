from __future__ import annotations
import argparse
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline
from backend.processing.flow_aggregator import FlowAggregator

def main():
    parser=argparse.ArgumentParser(description='Read-only IPXDR PCAP replay')
    parser.add_argument('pcap'); parser.add_argument('--aggregate',action='store_true',help='aggregate packets into passive 5-tuple flows')
    args=parser.parse_args(); pipeline=Pipeline(); agg=FlowAggregator() if args.aggregate else None; count=0
    def process(e):
        nonlocal count; pipeline.process(e); count+=1
    for event in PCAPIngestor(args.pcap).events():
        if agg:
            for flow in agg.add(event): process(flow)
        else: process(event)
    if agg:
        for flow in agg.flush(): process(flow)
    print(f'processed={count} accepted={pipeline.stats.accepted} failed={pipeline.stats.failed} alerts={len(pipeline.alerts.items)}')
if __name__=='__main__': main()
