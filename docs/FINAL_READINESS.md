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
- Reproducible dataset builder, deterministic train/validation/test evaluation, six-family end-to-end coverage runner and provenance manifests.

## Verification
The development environment passes the automated suite. Benchmarks are engineering measurements on the local environment, not production guarantees.

## Reproducible validation artifacts
- benchmarks/build_dataset.py builds a labelled controlled synthetic/lab feature dataset and SHA-256 provenance manifest.
- benchmarks/evaluate.py performs deterministic stratified train/validation/test evaluation and reports F1, PR-AUC, ROC-AUC, false-positive rate, ECE, Brier score and confusion matrices.
- benchmarks/coverage.py exercises all six SIH threat families through the production Pipeline; output is explicitly marked controlled synthetic/lab validation.
- benchmarks/throughput.py reports events/sec, Mbps, p50/p95/p99 latency and process CPU/RSS measurements.

## Important evaluation boundary
Synthetic fixtures are for integration and demonstration only. They must not be reported as real-world accuracy. Real public-capture labels must be independently verified before those captures are used for supervised accuracy claims.

## Passive security boundary
The monitoring path does not initiate connections to observed sources/destinations, decrypt TLS/QUIC payloads, block traffic or transmit mitigation traffic. Administrative model-training endpoints should remain behind enclave access controls and IPXDR_ADMIN_TOKEN in deployed environments.

## Remaining validation boundary
The software validation harness is complete for controlled lab fixtures. Remaining external evidence is real-world labelled coverage across all six threat families and a physical/isolated one-way TAP/data-diode deployment.
