# IPXDR Final Readiness

## Implemented
- Passive PCAP packet metadata extraction; no packet replay/transmission.
- Read-only JSONL and CSV adapters for exported NetFlow/IPFIX/sFlow-style records.
- Bounded five-tuple aggregation, 60-second host windows and TTL/cap controls.
- Flow, temporal, behavioral, DNS, TLS, QUIC and communication-graph features.
- Protocol/statistical detectors for SYN/UDP floods, UDP reflection-like fan-in, spoof-source entropy, recon, C2 periodicity, DGA/tunneling indicators and encrypted-session metadata.
- Isolation Forest unknown-behavior path and optional labeled Random Forest.
- Evidence-based multi-signal risk fusion and standardized alert schema.
- SQLite alert persistence and JSON export; model save/load lifecycle.
- FastAPI health/metrics/hosts/alerts/status APIs and WebSocket alert stream.
- SOC dashboard with threat distribution, host investigation and model state.
- Synthetic SIH demonstration, throughput benchmark, adversarial stress test and unseen-threat benchmark.
- GitHub Actions CI for tests, compile checks, benchmark smoke tests and diff hygiene.

## Verification
The development environment currently passes the automated suite. Benchmarks are engineering measurements on the local environment, not production guarantees.

## Important evaluation boundary
Synthetic fixtures are for integration and demonstration only. They must not be reported as real-world accuracy. For a final SIH evaluation, use a separated, documented dataset and report precision, recall, F1, PR-AUC, false-positive rate, calibration, latency and throughput.

## Passive security boundary
The monitoring path does not initiate connections to observed sources/destinations, decrypt TLS/QUIC payloads, block traffic or transmit mitigation traffic. Administrative model-training endpoints should remain behind enclave access controls and `IPXDR_ADMIN_TOKEN` in deployed environments.
