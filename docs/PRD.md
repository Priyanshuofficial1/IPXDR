# IPXDR — Product Requirements Document

**Project:** IPXDR (IP eXtended Detection & Response)
**SIH Problem:** SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Document status:** Active engineering baseline
**Version:** 1.0

## 1. Product vision

IPXDR is a **passive, self-adapting AI cybersecurity platform** for detecting known and previously unseen threats in unidirectional IP traffic. It analyzes network metadata, temporal behavior, host baselines, communication relationships, and multiple detection signals without sending traffic back into the monitored enclave.

The system is designed around a strict **receive-only / monitor-only trust boundary**: observation is allowed; probing, response, mitigation, and payload decryption are not.

## 2. Problem statement

A monitoring system connected through a simulated or physical data-diode/TAP architecture cannot safely depend on active verification. Traditional IDS pipelines can also struggle with encrypted traffic, changing attacker behavior, noisy environments, and threats that were not represented in training data.

IPXDR must therefore answer four questions from one-way metadata alone:

1. **What is happening?** — identify known threat classes.
2. **Is this behavior unusual?** — detect previously unseen behavior.
3. **How strong is the evidence?** — combine model, statistical, temporal, and behavioral signals.
4. **Can an analyst understand the alert?** — expose measurable supporting evidence and confidence.

## 3. Goals

### G1 — Passive detection
- Consume PCAP, NetFlow, IPFIX, sFlow, or normalized flow records.
- Never transmit packets, probes, handshakes, mitigation commands, or application requests toward monitored systems.
- Never require TLS/QUIC payload decryption.

### G2 — Real-time analysis
- Process streaming records with bounded latency.
- Maintain state in bounded sliding windows.
- Measure and report throughput in flows/sec and, where possible, Mbps.
- Report p50/p95/p99 processing latency.

### G3 — Detect required SIH threat classes
- Volumetric/protocol DDoS: SYN floods, UDP reflection/amplification, spoofed-source floods.
- Botnet C2 beaconing: periodic and near-periodic communication.
- DGA and DNS tunneling: high-entropy/algorithmic names, long queries, unusual record patterns.
- Malware in encrypted sessions: TLS/QUIC metadata anomalies and JA3/JA3S/JA4-style fingerprints where available.
- Reconnaissance/port scanning: host/port fan-out and connection patterns.
- Data exfiltration: asymmetric flow volume, outbound/inbound ratios, burst and destination behavior.

### G4 — Detect unknown threats
Run a hybrid detector:

`supervised threat model + anomaly detector + statistical/rule signals + behavioral deviation → risk fusion`

At least one evaluation must hold out an attack family/type from model training and test whether the anomaly layer identifies its abnormal behavior.

### G5 — Explain every important alert
Every alert must contain a threat class, confidence, severity, and concrete evidence such as:
- flow/byte/packet rate;
- source/destination fan-out;
- entropy or n-gram score;
- inter-arrival periodicity;
- TLS fingerprint/metadata;
- host baseline deviation;
- outbound/inbound byte ratio;
- contributing model scores.

## 4. Non-goals and hard safety constraints

IPXDR **must not**:
- actively probe a host, port, domain, or service;
- complete or initiate a handshake for detection purposes;
- send a mitigation/blocking packet;
- modify monitored traffic;
- decrypt TLS/QUIC payloads;
- contact the monitored source/destination to validate an alert;
- become a bridge between the monitored enclave and external networks.

LLMs may be used to turn already-generated evidence into analyst-friendly text, but an LLM must **not** be the authoritative detection or confidence engine.

## 5. Users

### Security analyst
Needs prioritized alerts, evidence, host timelines, and investigation context.

### Network/security engineer
Needs ingestion health, throughput, latency, feature quality, and detector diagnostics.

### ML engineer/researcher
Needs reproducible datasets, feature definitions, training runs, validation metrics, and model versions.

### SIH evaluator
Needs a demonstrable passive architecture, threat coverage, measurable performance, and reproducible experiments.

## 6. Functional requirements

### FR-01 — Ingestion
The system shall accept a normalized internal event format and provide adapters for:
- PCAP;
- NetFlow;
- IPFIX;
- sFlow/derived flow metadata.

The first implementation may prioritize PCAP + normalized JSON/JSONL replay, provided the adapter boundary remains stable.

### FR-02 — Normalization
Each observation should normalize, when available:
- timestamp;
- source/destination IP;
- source/destination port;
- protocol;
- packet count;
- byte count;
- flow duration;
- TCP flags;
- DNS metadata;
- TLS/QUIC metadata;
- interface/direction metadata.

Missing fields must be represented explicitly rather than silently fabricated.

### FR-03 — Stateful windows
Maintain bounded state for configurable windows such as 1s, 5s, 30s, 60s, and longer behavioral baselines. State must have explicit memory limits and expiry behavior.

### FR-04 — Feature extraction
Features shall be grouped into:

**Flow:** packets, bytes, duration, packets/sec, bytes/sec, direction, TCP flags.

**Volume/entropy:** flow rate, unique source count, unique destination count, source-IP entropy, destination/port entropy.

**Temporal:** inter-arrival mean/variance, coefficient of variation, burstiness, periodicity/autocorrelation.

**DNS:** query length, label entropy, character/n-gram statistics, record-type distribution, NXDOMAIN/error ratio, unique-domain behavior.

**Encrypted metadata:** TLS/QUIC version and handshake metadata, JA3/JA3S/JA4-style fingerprints when extractable, packet-size and timing distributions.

**Behavioral:** deviation from host-specific historical baselines.

**Graph:** host→domain/IP→port relationships, fan-out/fan-in, new-neighbor ratio, relationship novelty.

### FR-05 — Behavioral digital twin
For each observed host/entity, maintain a lightweight behavioral profile containing normal ranges and distributions for:
- communication volume;
- destinations and ports;
- temporal activity;
- protocol mix;
- DNS behavior;
- encrypted-session metadata.

Baseline updates must be guarded so an active attack is not immediately learned as normal behavior.

### FR-06 — Known-threat detection
Use supervised models and/or deterministic detectors appropriate to each threat class. Models must be versioned and reproducible.

### FR-07 — Unknown-threat detection
Use anomaly detection to identify deviations without requiring a known attack label. Candidate techniques include Isolation Forest, robust statistical distance, clustering, and sequence/temporal anomaly scoring. The selected implementation must be benchmarked rather than chosen solely by name.

### FR-08 — Temporal intelligence
The detector shall distinguish sustained high-rate traffic from periodic/near-periodic behavior. Beaconing analysis should use inter-arrival statistics and periodicity rather than a single fixed interval threshold.

### FR-09 — Graph intelligence
The system shall derive relationship features from observed communications. Graph analysis is feature intelligence, not an excuse to transmit traffic to validate a relationship.

### FR-10 — Multi-signal fusion
Combine detector outputs into a normalized risk representation. Fusion must preserve individual contributing scores so analysts can see why risk increased.

Conceptually:

`Risk = f(supervised_score, anomaly_score, statistical_score, temporal_score, behavioral_deviation, graph_novelty)`

The exact fusion function must be selected and validated experimentally.

### FR-11 — Confidence and severity
Confidence must represent model/evidence confidence, not simply map to severity. Severity should be based on threat type and measured impact indicators.

Recommended initial bands:
- LOW: informational anomaly;
- MEDIUM: suspicious behavior with moderate evidence;
- HIGH: strong evidence of malicious behavior or significant impact;
- CRITICAL: strong evidence plus severe/large-scale impact.

These bands are configurable and must not replace the underlying evidence.

### FR-12 — Alert schema
Minimum alert fields:

```json
{
  "timestamp": "ISO-8601",
  "flow_id": "string",
  "threat_class": "string",
  "confidence": 0.0,
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "supporting_evidence": [],
  "model_scores": {},
  "behavior_deviation": 0.0
}
```

Optional fields should include host/entity IDs, detector version, feature snapshot, window boundaries, and correlation IDs.

### FR-13 — Dashboard
The dashboard shall expose:
- live/near-real-time alert stream;
- severity and confidence;
- threat-class distribution;
- monitored throughput;
- processing latency;
- host behavioral deviations;
- top anomalous entities;
- temporal activity charts;
- communication relationships;
- alert evidence/details;
- ingestion/model health.

The UI must visualize actual backend state rather than hard-coded demonstration numbers.

### FR-14 — Replay
Provide deterministic replay of recorded/synthetic observations at configurable rates. Replay must support accelerated testing and reproducible demo scenarios.

### FR-15 — Evaluation
Provide scripts/configuration for reproducible evaluation and store:
- dataset/version;
- train/validation/test split;
- model configuration;
- feature version;
- random seed where applicable;
- metrics;
- runtime environment.

## 7. ML/data requirements

### Dataset strategy
Use public datasets where licensing and feature compatibility permit, supplemented by controlled synthetic/lab traffic for gaps in SIH-required classes.

Candidate families may include CICIDS-style intrusion datasets, CTU-13 for botnet behavior, UNSW-NB15, DGA corpora, DNS tunneling data, and generated Scapy/flow fixtures. Exact datasets must be recorded in the repository with provenance and licensing notes.

### Split strategy
Avoid random leakage across near-identical flows where possible. Evaluation should include:
1. standard train/validation/test;
2. temporal holdout;
3. unseen-threat holdout;
4. noisy/imbalanced test set;
5. evasion test with timing jitter, destination rotation, and volume variation.

### Required metrics
- Precision, recall, F1.
- PR-AUC and ROC-AUC where meaningful.
- False-positive rate.
- Per-threat-class confusion matrix.
- Calibration/error of confidence estimates.
- Unknown-threat detection rate.
- Throughput (flows/sec and Mbps when measurable).
- p50/p95/p99 processing latency.
- CPU and memory utilization.

No performance number should be presented as a measured result until the benchmark actually produces it.

## 8. Architecture requirements

Logical pipeline:

`Passive Source → Ingestion Adapter → Normalizer → Window/State Store → Feature Engine →`
`{Known Detector | Anomaly Detector | Temporal Engine | Behavioral Engine | Graph Features}`
`→ Risk Fusion → Alert Engine → API/WebSocket → Dashboard`

Model training/evaluation is separated from the streaming inference path.

The monitoring enclave has no return path through IPXDR.

## 9. Performance requirements

Initial engineering targets (to be measured and revised from evidence):
- near-real-time alerting with a target processing budget of approximately 1 second or less for streaming observations;
- bounded memory through window expiration;
- sustained replay benchmark with documented flows/sec;
- p95 and p99 latency reported separately from average latency.

The prototype is considered successful only when these properties are demonstrated on the actual implementation.

## 10. Reliability requirements

- Malformed input must not crash the entire stream processor.
- Unknown/missing fields must be handled explicitly.
- Backpressure must be visible and measurable.
- State expiration must prevent unbounded memory growth.
- Model loading failures must produce health errors rather than silent fallback.
- Alerts must remain schema-valid even when optional metadata is unavailable.

## 11. Security/privacy requirements

- Treat observed network metadata as sensitive.
- Do not log payloads by default.
- Avoid storing secrets, credentials, or unnecessary identifiers.
- Sanitize data used in dashboard/API responses.
- Authenticate administrative/model-management endpoints.
- Keep ingestion and management interfaces separated where practical.
- Make passive-only behavior enforceable by architecture and configuration, not just documentation.

## 12. Observability

Expose operational metrics for:
- records received/dropped;
- parser errors;
- queue depth/backpressure;
- feature extraction time;
- model inference time;
- alerts generated;
- alerts by threat class;
- p50/p95/p99 latency;
- throughput;
- CPU/memory;
- active state entries.

## 13. Acceptance criteria

IPXDR reaches MVP acceptance when all of the following are demonstrated:

1. A controlled PCAP/flow stream can be ingested without an active return path.
2. The required SIH threat classes have working detection paths or documented limitations.
3. At least one known-threat supervised detector is evaluated with held-out test data.
4. Anomaly detection demonstrates detection of behavior not represented in training labels.
5. Host behavioral baselines produce measurable deviation scores.
6. Temporal features detect periodic behavior without relying only on a fixed interval rule.
7. Encrypted-session analysis works from metadata without payload decryption.
8. Alerts conform to the documented schema and expose evidence.
9. Dashboard values originate from live backend state.
10. Throughput, p95/p99 latency, CPU, and memory are benchmarked and recorded.
11. Reproduction instructions allow another team member to run the demo/evaluation.
12. Automated tests cover normalization, feature extraction, detectors, fusion, and alert serialization.

## 14. MVP phases

### Phase 1 — Foundation
- repository structure;
- normalized flow model;
- PCAP/JSONL replay;
- streaming window engine;
- alert schema;
- tests.

### Phase 2 — Detection core
- DDoS features/detector;
- recon detector;
- beaconing detector;
- DNS/DGA/tunneling features;
- encrypted metadata features;
- exfiltration detector.

### Phase 3 — IPXDR intelligence
- behavioral digital twin;
- anomaly detector;
- temporal engine;
- graph-derived features;
- multi-signal fusion;
- calibrated confidence.

### Phase 4 — Productization
- API/WebSocket;
- live dashboard;
- model/version registry;
- replay scenarios;
- benchmark suite;
- documentation.

### Phase 5 — Validation
- temporal holdout;
- unseen-threat experiment;
- evasion tests;
- throughput/latency/resource benchmark;
- final SIH demo package.

## 15. Definition of done

A feature is done only when its implementation, unit/integration tests, documentation, and reproducible validation are present. For ML features, “done” additionally requires a recorded dataset/split, metrics, model version, and benchmark/evaluation artifact.

**Core principle:** IPXDR should make the strongest possible security decision from the information it can passively observe — and never violate the unidirectional trust boundary to obtain more information.
