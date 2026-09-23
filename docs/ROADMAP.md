# Roadmap

## Implemented
- [x] Passive ingest adapters: PCAP, NetFlow/IPFIX/sFlow
- [x] Canonical flow schema
- [x] Flow, temporal, behavioral, DNS, TLS/QUIC and graph features
- [x] Rule/statistical detectors for required threat families
- [x] Supervised Random Forest model lifecycle
- [x] Behavioral baseline engine
- [x] Isolation Forest unknown-behavior detector
- [x] Risk/evidence fusion and standardized alerts
- [x] Incremental streaming pipeline with bounded windows
- [x] SOC cockpit dashboard and WebSocket alert stream
- [x] PCAP replay/demo tooling
- [x] Unseen/adversarial benchmark scaffolding
- [x] Throughput/latency benchmark tooling
- [x] Docker deployment

## SIH completion work
- [ ] Run throughput benchmark on the final demo environment and publish measured flows/sec, Mbps and p50/p95/p99 latency
- [ ] Build a separated labelled train/validation/test dataset from documented captures
- [ ] Run supervised evaluation and publish precision, recall, F1, PR-AUC and confusion matrix
- [ ] Add false-positive-rate and calibration reporting to the evaluation run
- [ ] Validate each required threat class end-to-end from input capture to dashboard evidence
- [ ] Record model/data provenance and benchmark configuration for reproducibility
