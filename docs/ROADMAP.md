# Roadmap

## Implemented
- [x] Passive ingest adapters: PCAP, NetFlow/IPFIX/sFlow
- [x] Canonical flow schema
- [x] Flow, temporal, behavioral, DNS/TLS/QUIC and graph features
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
- [x] Run throughput benchmark on the final demo environment and publish measured flows/sec, Mbps and p50/p95/p99 latency
- [x] Build a separated labelled train/validation/test dataset from documented controlled synthetic/lab captures; keep real public captures as provenance references unless labels are independently established
- [x] Run supervised evaluation and publish precision, recall, F1, PR-AUC, ROC-AUC and confusion matrix
- [x] Add false-positive-rate and calibration reporting to the evaluation run
- [x] Validate each required threat class end-to-end through the production ingestion/feature/detection/alert path
- [x] Record dataset hashes, split configuration, seed, runtime environment and benchmark configuration

## Validation boundary
Controlled synthetic/lab fixtures demonstrate implementation coverage only. They are not real-world accuracy claims. Real public captures require independently verified labels before supervised accuracy claims.
