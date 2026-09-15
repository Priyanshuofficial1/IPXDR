# Ingestion Adapters

## PCAP
`backend.ingestion.pcap.PCAPIngestor` reads PCAP files with Scapy and emits normalized packet metadata. It never replays packets.

## Flow exports
`backend.ingestion.flow_formats.FlowRecordIngestor` accepts JSONL/CSV exports commonly produced by NetFlow/IPFIX/sFlow collectors. It maps common exporter field aliases into `FlowEvent`.

This adapter is intentionally an **export-record adapter**, not a complete binary IPFIX/sFlow wire-protocol implementation. A production collector should terminate those protocols at the enclave and feed their exported records to IPXDR.

## JSONL
`JSONLIngestor` is the deterministic test/demo format.

All ingestion paths are read-only from the monitored-traffic perspective.
