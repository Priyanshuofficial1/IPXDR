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
The software validation harness is complete for controlled lab fixtures and now includes reproducible evidence from CTU-13, UNSW-NB15, and a CIC-IDS2017 labelled-flow sample. Remaining external evidence is native UGR'16 per-flow validation and a physical/isolated one-way TAP/data-diode deployment.


## Current SIH evidence status

### Verified
- Production six-family controlled coverage remains reproducible through `benchmarks/coverage.py`.
- Synthetic labelled evaluation remains 560 samples / 7 classes with test macro F1 1.0000; explicitly controlled/lab only.
- CTU-13 Scenario 43 replay processed 20,000/20,000 packets with 0 failures.
- UNSW-NB15 5,000-row diagnostic now evaluates the actual production alert decision: TN=5, FP=1592, FN=2, TP=3401, precision=0.6812, recall=0.9994, F1=0.8101.
- CIC-IDS2017 public labelled-flow sample: 56,661 rows acquired locally; 5,000-row stratified production replay: TN=5, FP=2001, FN=2, TP=2992, precision=0.5992, recall=0.9993, F1=0.7492.
- Dashboard smoke test returned HTTP 200 and live API polling endpoints returned HTTP 200. WebSocket `/ws/alerts` was initially blocked because the runtime lacked a WebSocket implementation; `websockets>=13` is now a declared dependency and the live handshake was reverified as accepted.
- Malformed PCAP upload errors no longer expose parser/library exception details; a regression test covers this boundary.
- 50,000-event engineering benchmark completed on WSL2: 228.806 events/s, 1.006 Mbps, p50 3.931 ms, p95 8.407 ms, p99 11.503 ms, max RSS 209.238 MB.

### Partially validated
- UNSW-NB15 and CIC-IDS2017 metrics are reconstructed flow-feature diagnostics because their selected inputs do not retain all native packet/flow semantics required by IPXDR.
- Live dashboard/API/WebSocket availability is verified; browser file-chooser automation was not used to upload a capture. The full upload-to-analysis chain is covered by the TestClient integration test.

### Not validated
- Native UGR'16 per-flow evaluation through IPXDR. The accessible author feature repository is one-minute aggregate data, while automated access to the original download site returned HTTP 403.
- A physical/isolated one-way TAP or data-diode deployment.

### Known limitations
- Synthetic metrics are not real-world accuracy.
- CTU-13 Scenario 43 is not a benign/attack-balanced benchmark and cannot establish FPR by itself.
- Current reconstructed UNSW/CIC diagnostics show very high false-positive rates and should not be used as production accuracy claims.
- WSL2 throughput is an engineering measurement for this environment, not a capacity guarantee.
- Native timestamped, bidirectional/directional flow evidence is still needed for defensible threshold calibration.
