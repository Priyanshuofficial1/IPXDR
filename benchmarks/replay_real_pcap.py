"""Replay a real public PCAP through IPXDR without inventing labels."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("pcap",type=Path)
    ap.add_argument("--max-packets",type=int,default=20000)
    ap.add_argument("--output",type=Path,default=Path("benchmarks/results/real-ctu43-replay.json"))
    a=ap.parse_args()
    pipe=Pipeline()
    packets=0; alerts=0; detectors={}
    for event in PCAPIngestor(a.pcap).events():
        pipe.process(event); packets+=1
        if pipe.last_detector_results: alerts+=1
        for r in pipe.last_detector_results: detectors[r.threat_class]=detectors.get(r.threat_class,0)+1
        if packets>=a.max_packets: break
    result={"schema_version":"1.0","dataset":"CTU-13 Scenario 43 Neris","pcap":str(a.pcap),
            "packets_replayed":packets,"events_accepted":pipe.stats.accepted,
            "events_failed":pipe.stats.failed,"events_with_detector_results":alerts,
            "detector_result_counts":detectors,
            "ground_truth_note":"This public PCAP is botnet-only traffic; it is suitable for integration/coverage replay but cannot establish precision or false-positive rate without benign traffic labels.",
            "source":"https://www.stratosphereips.org/datasets-ctu13"}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))
if __name__=="__main__": main()
