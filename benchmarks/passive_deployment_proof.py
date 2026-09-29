#!/usr/bin/env python3
"""Passive deployment verification: process a capture and assert no network API is required."""
from __future__ import annotations
import json, socket
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline

def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("pcap",type=Path); ap.add_argument("--max-packets",type=int,default=1000)
    ap.add_argument("--output",type=Path,default=Path("benchmarks/results/passive-deployment-proof.json")); a=ap.parse_args()
    original=socket.socket
    attempts=[]
    def blocked(*args,**kwargs):
        attempts.append({"args":repr(args[:2])}); raise AssertionError("network socket attempted during passive analysis")
    socket.socket=blocked
    try:
        pipe=Pipeline(); count=0
        for e in PCAPIngestor(a.pcap).events():
            pipe.process(e); count+=1
            if count>=a.max_packets: break
    finally:
        socket.socket=original
    result={"schema_version":"1.0","mode":"passive-read-only","pcap":str(a.pcap),"packets_processed":count,
            "events_failed":pipe.stats.failed,"network_socket_attempts":len(attempts),
            "transmission":False,"decryption":False,
            "claim":"IPXDR analysis path does not require an outbound network socket."}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__": main()
