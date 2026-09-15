from __future__ import annotations
import argparse
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline
from backend.features.flow import extract_flow_features

def main():
    parser = argparse.ArgumentParser(description="Read-only IPXDR PCAP replay")
    parser.add_argument("pcap")
    args = parser.parse_args()
    pipeline = Pipeline()
    count = 0
    for event in PCAPIngestor(args.pcap).events():
        normalized = pipeline.process(event)
        extract_flow_features(normalized)
        count += 1
    print(f"processed={count} accepted={pipeline.stats.accepted} failed={pipeline.stats.failed}")

if __name__ == "__main__":
    main()
