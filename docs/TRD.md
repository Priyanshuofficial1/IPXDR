# IPXDR — Technical Requirements Document

**Project:** IPXDR (IP eXtended Detection & Response)  
**SIH Problem:** SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Status:** Active engineering baseline  
**Version:** 1.0

## 1. Purpose

IPXDR is a passive AI/XDR pipeline for one-way network telemetry. It ingests PCAP/flow metadata, normalizes observations, maintains bounded windows and host behavior baselines, extracts temporal/graph/network features, runs known-threat and unknown-threat detectors, fuses evidence, and publishes explainable alerts.

**Hard boundary:** the system observes only. It must not probe, connect to, handshake with, block, modify, or send mitigation traffic to monitored endpoints, and it must not decrypt TLS/QUIC payloads.

## 2. System architecture

```text
MONITORED ENCLAVE
      |
      | one-way telemetry / TAP / data diode
      v
+-------------------+
| INGESTION          | PCAP / JSONL / Flow adapters
+---------+---------+
          v
+-------------------+
| NORMALIZATION      | typed FlowEvent contract
+---------+---------+
          v
+-------------------+
| WINDOW + STATE     | bounded TTL state
+---------+---------+
          v
+-------------------+
| FEATURE ENGINE     | flow/DNS/TLS/time/behavior/graph
+------+--------+---+
       |        |
       v        v
  KNOWN MODEL  ANOMALY
       \        /
        v      v
       +--------+
       | FUSION |
       +---+----+
           v
      ALERT STORE/STREAM
           |
           v
       DASHBOARD
```

No downstream component may create a return path into the monitored enclave.

## 3. Technology baseline

| Layer | Default implementation |
|---|---|
| Runtime | Python 3.12+ |
| API | FastAPI + Pydantic v2 |
| Async | asyncio |
| PCAP | Scapy or equivalent parser |
| ML | scikit-learn |
| Numerical/offline | NumPy, Pandas |
| Model artifacts | joblib or equivalent |
| Database | PostgreSQL |
| Offline features | Parquet |
| Frontend | React + TypeScript + Vite |
| Live updates | WebSocket or SSE |
| Charts | Recharts/ECharts |
| Containers | Docker + Compose |
| Tests | pytest |
| Quality | Ruff + formatter + type checking |
| CI | GitHub Actions |

Redis/Kafka are optional scale-out components, not MVP dependencies.

## 4. Repository structure

```text
ipxdr/
├── backend/{api,ingestion,processing,features,detection,anomaly,temporal,behavioral,graph,fusion,alerts}
├── ml/{datasets,preprocessing,training,evaluation,models,experiments}
├── frontend/{dashboard,alerts,hosts,analytics,components}
├── replay/{scenarios,pcaps}
├── benchmarks/
├── docs/
└── tests/
```

Recommended modules:

```text
backend/ingestion/base.py
backend/ingestion/models.py
backend/ingestion/jsonl.py
backend/ingestion/pcap.py
backend/processing/normalizer.py
backend/processing/windows.py
backend/processing/pipeline.py
backend/features/{flow,volume,temporal,dns,encrypted,behavioral,graph}.py
backend/detection/{base,ddos,beaconing,dga,encrypted_malware,recon,exfiltration}.py
backend/anomaly/{base,isolation_forest}.py
backend/fusion/{risk,calibration}.py
backend/alerts/{schema,builder,publisher}.py
```

## 5. Core data contracts

### 5.1 FlowEvent

```json
{
  "event_id": "uuid",
  "timestamp": "2026-01-01T00:00:00.123Z",
  "src_ip": "10.0.0.10",
  "dst_ip": "10.0.0.20",
  "src_port": 42111,
  "dst_port": 443,
  "protocol": "TCP",
  "packets": 12,
  "bytes": 1840,
  "duration_ms": 120,
  "tcp_flags": ["SYN", "ACK"],
  "direction": "outbound",
  "dns": null,
  "tls": null,
  "quic": null,
  "source": "pcap"
}
```

Rules: validate IP/port values; preserve source timestamp precision; use `null` for unavailable fields; never fabricate telemetry; identify the adapter; maintain a stable internal schema.

### 5.2 DetectorResult

```text
DetectorResult:
  detector_name: str
  threat_class: str
  score: float [0,1]
  evidence: list
  features_used: list[str]
  model_version: str | null
  latency_ms: float
```

### 5.3 Alert

```json
{
  "timestamp": "2026-01-01T00:00:01Z",
  "flow_id": "flow-123",
  "threat_class": "C2_BEACONING",
  "confidence": 0.94,
  "severity": "HIGH",
  "supporting_evidence": [
    {"feature": "inter_arrival_cv", "value": 0.03},
    {"feature": "periodicity_score", "value": 0.91}
  ],
  "model_scores": {"supervised": 0.87, "anomaly": 0.91, "temporal": 0.95},
  "behavior_deviation": 0.82
}
```

Confidence and severity are separate fields. Evidence must remain visible regardless of score.

## 6. Ingestion requirements

### JSONL replay
Primary deterministic test adapter. It reads observations from disk and emits normalized events at configurable replay speed.

### PCAP
Parse packets locally into flow/metadata observations. The adapter is strictly read-only and must never replay packets to a live interface.

### Future adapters
Keep stable interfaces for NetFlow, IPFIX and sFlow-derived metadata.

Adapter contract:

```text
start() -> Iterator[RawObservation]
```

or an equivalent async iterator. Malformed records are isolated into structured errors and counted.

## 7. Processing engine

Pipeline:

```text
raw observation
  -> validation
  -> normalization
  -> bounded window update
  -> feature extraction
  -> detector fan-out
  -> risk fusion
  -> alert build
  -> persistence
  -> live publication
```

Window keys may include source IP, destination IP, source/destination pair, port tuple, DNS name, TLS fingerprint and host neighborhood.

Supported initial windows: 1s, 5s, 30s, 60s plus configurable longer behavioral history. All state requires TTL/eviction and explicit memory limits.

## 8. Feature specification

### Flow
Packets, bytes, duration, packets/sec, bytes/sec, packet-size mean/std/percentiles, TCP flags, protocol mix.

### Volumetric/DDoS
Flows/sec, packets/sec, bytes/sec, unique source/destination counts, source-IP entropy, destination/port entropy, SYN/ACK ratio, passive directional asymmetry where available.

### Temporal/C2
Inter-arrival mean/std, coefficient of variation, MAD, burstiness, autocorrelation/periodicity, timing jitter, active duration and destination consistency.

### DNS/DGA/tunneling
Query length, label count, Shannon entropy, character-class ratios, n-grams, unique-query ratio, NXDOMAIN/error ratio, record-type distribution, subdomain depth, bytes/query, frequency and domain novelty.

### TLS/QUIC metadata
Version, handshake metadata, available cipher metadata, JA3/JA3S/JA4-style fingerprints where available, packet-size distributions, timing, duration, packet/byte counts and destination novelty. **No payload decryption.**

### Recon
Unique destination hosts/ports, fan-out, attempt rate, passive response indicators where available, port entropy and new-neighbor ratio.

### Exfiltration
Outbound/inbound bytes, byte ratio, sustained outbound rate, destination novelty, session duration, burstiness, protocol mix and baseline deviation.

## 9. Behavioral Digital Twin

Maintain a lightweight per-host/entity behavioral profile:
- rolling mean/median;
- variance/MAD and quantiles;
- protocol proportions;
- destination/port frequencies;
- temporal activity profile;
- known fingerprints;
- graph neighborhood summary.

Baseline lifecycle:

```text
WARM-UP -> NORMAL -> ELEVATED RISK -> FROZEN/DEGRADED -> RECOVERY
```

During elevated risk, baseline updates are frozen or strongly down-weighted to resist poisoning. Support minimum sample count, aging/TTL, reset and versioning.

## 10. Detection architecture

### Known-threat path
Use deterministic/statistical rules and supervised models appropriate to each SIH class. Model artifacts and feature schemas are versioned.

### Unknown-threat path
Must not depend on attack labels. MVP uses:
1. robust scaling;
2. Isolation Forest;
3. normalized anomaly score;
4. host deviation;
5. temporal anomaly contribution;
6. fusion.

Later experiments may compare robust covariance, clustering and sequence methods.

### Required unseen-threat experiment
Hold one attack family/type out of supervised training, expose it only in evaluation, and report anomaly detection rate, false-positive rate, time-to-detection, score distribution and contributing signals. Store dataset/model/config versions.

## 11. Threat modules

**DDoS:** detect SYN floods, UDP reflection/amplification and spoofed-source-like floods where passive evidence supports the distinction.

**C2 beaconing:** use periodicity/inter-arrival behavior and destination consistency; avoid fixed-interval-only detection.

**DGA/DNS tunneling:** combine lexical, entropy, length, n-gram and frequency signals; avoid single-threshold detection.

**Encrypted malware:** classify metadata/fingerprint/timing/size behavior without decryption.

**Recon/port scan:** detect fan-out across hosts/ports and connection patterns.

**Exfiltration:** detect directional volume asymmetry, sustained outbound transfer, destination novelty and host deviation.

## 12. Multi-signal risk fusion

Initial transparent combiner:

```text
risk_raw =
  w_supervised * supervised_score +
  w_anomaly    * anomaly_score +
  w_temporal   * temporal_score +
  w_behavior   * behavior_deviation +
  w_graph      * graph_novelty +
  w_rules      * statistical_score
```

Weights live in configuration/model metadata. Preserve every component score. A learned/calibrated combiner may replace this only after baseline evaluation.

Confidence calibration should be measured with calibration curves/expected calibration error when labels support it.

## 13. Graph intelligence

Use a time-aware observational graph:

```text
Host -> IP -> Port
Host -> Domain -> IP
Host -> TLS fingerprint
```

Features: degree, fan-in/fan-out, new-neighbor ratio, neighborhood novelty, relationship strength and destination concentration.

Graph edges never trigger active connection attempts.

## 14. API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | service status/version/uptime |
| GET | `/metrics` | ingestion, latency, throughput, state and alert metrics |
| GET | `/api/v1/alerts` | paginated/filterable alerts |
| GET | `/api/v1/alerts/{alert_id}` | complete evidence/scores |
| GET | `/api/v1/hosts/{ip}` | host baseline/risk/communication summary |
| POST | `/api/v1/replay` | start local file replay only |
| WS | `/api/v1/stream/alerts` | live alert stream |

Use versioned schemas and structured error responses. API authentication is required outside local development.

## 15. Persistence

PostgreSQL tables:

**alerts:** id, timestamp, flow_id, threat_class, confidence, severity, behavior_deviation, evidence JSONB, model_scores JSONB, created_at.

**detector_runs:** id, detector_name, model_version, dataset_version, configuration JSONB, metrics JSONB, created_at.

**hosts:** ip, first_seen, last_seen, baseline_version, baseline JSONB, risk_summary JSONB.

**ingestion_runs:** id, source_type, source_name, start/end time, records seen/processed, errors, throughput, status.

Index alerts by timestamp, severity, threat class, flow ID and host/IP query paths.

## 16. Frontend requirements

Views:
1. Overview — live alert counts, threat distribution, ingestion health, throughput and latency.
2. Live Alerts — stream with severity/confidence/evidence preview.
3. Alert Detail — timeline, evidence, model scores and host context.
4. Hosts — behavioral deviation and communication statistics.
5. Analytics — threat trends, temporal patterns, entropy/fan-out distributions and detector metrics.
6. System — ingestion/state health, model versions and benchmark status.

Clearly distinguish observed telemetry, model output and optional generated explanation.

## 17. Optional LLM boundary

An LLM can summarize **post-detection sanitized evidence** or explain technical terms. It cannot be the authoritative detector, confidence engine, response engine or payload processor. Detection must work if the LLM is offline.

## 18. ML/data engineering

```text
raw source
 -> immutable manifest
 -> parser
 -> normalized events
 -> feature extraction
 -> split
 -> training
 -> validation
 -> test
 -> artifact + metrics
```

Prevent train/test contamination. Consider temporal and host leakage. Version preprocessing with the model. Record source/version/license notes/hashes where possible.

Metrics: precision, recall, F1, PR-AUC, ROC-AUC where meaningful, false-positive rate, confusion matrix, calibration, per-threat metrics and unseen-threat performance.

## 19. Performance/benchmarking

Do not use unmeasured performance claims. Record:
- flows/sec;
- Mbps where derivable;
- end-to-end p50/p95/p99 latency;
- detector latency;
- CPU and memory;
- state size;
- dropped/failed events.

Benchmark profiles: local demo, sustained stream, burst workload, multi-threat workload and anomaly-heavy workload. Store commit, config, model and dataset identifiers with every result.

## 20. Reliability

- Bad input: isolate/count and continue.
- Detector failure: remove only that contribution, mark degraded, never fabricate a score.
- Storage failure: bounded buffering and explicit degraded status.
- Dashboard failure: detection continues independently.
- Restart: preserve run/model/config metadata; rebuild in-memory state from replayable telemetry when needed.

## 21. Security requirements

- No secrets in Git.
- Secrets via environment/secret manager.
- Authentication for non-local deployments.
- RBAC if multi-user mode exists.
- Strict input validation.
- No raw sensitive payload logging.
- Least-privilege PCAP/container access.
- Locked dependencies.
- Validate model artifacts before loading.

## 22. Passive-boundary enforcement

This requirement is architectural and testable.

```text
Captured destination IP/port != permission to connect
```

Replay reads files; it never injects packets into a live interface. Detection code must not contain active-response clients. CI should include practical regression checks for accidental network clients in ingestion/detection modules.

## 23. Testing

### Unit
Schema validation, normalization, feature formulas, window expiry, baseline updates, detector results, fusion and alert serialization.

### Integration
JSONL → pipeline → alert; PCAP → pipeline → alert; API → replay → live alert; persistence/retrieval.

### Security
Malformed records, oversized fields, invalid addresses/ports, baseline-poisoning scenarios, artifact validation and passive-boundary checks.

### ML
Deterministic preprocessing, feature ordering, split integrity, model loading, metrics, calibration and unseen-threat holdout.

## 24. Robustness/evasion evaluation

Use controlled synthetic variations such as beacon timing jitter, destination rotation, source rotation, rate changes, burst fragmentation, DNS-label variation and exfiltration split across sessions. Measure detector score and time-to-detection changes. This is for defensive robustness evaluation.

## 25. Observability

Expose counters/gauges for records received/normalized/rejected/processed, feature errors, detector invocations/latency, alerts generated/persisted, queue depth, state size, CPU/memory and active model versions.

Use structured JSON logs with correlation IDs for ingestion runs and alerts.

## 26. Configuration

Configure API, database, optional Redis/Kafka, windows, baseline parameters, detector thresholds/weights, model paths, log level, replay speed and feature flags. Maintain `.env.example`; never commit real credentials.

## 27. Deployment

MVP:

```text
frontend + backend + postgres
```

Optional scale-out:

```text
redis + kafka + workers
```

The complete MVP must run on one development machine. Scale-out may separate ingestion, processing, detection and API workers later.

## 28. CI/CD

Each PR should run formatting/lint, type checks where configured, unit tests, integration tests, frontend build, Docker build and passive-boundary checks. Main must remain runnable after each milestone.

## 29. Implementation phases

**Phase 1 — Foundation:** schemas, FastAPI health/metrics, JSONL adapter, pipeline skeleton, tests.

**Phase 2 — Real telemetry:** PCAP adapter, normalization, window engine, baseline metrics, replay CLI.

**Phase 3 — Detection:** DDoS, beaconing, DGA/DNS tunneling, encrypted metadata, recon, exfiltration, anomaly detector.

**Phase 4 — Intelligence:** Behavioral Digital Twin, graph features, fusion, calibration, unseen-threat experiment.

**Phase 5 — Productization:** persistent API, React dashboard, live alerts, benchmarks, Docker Compose, CI and demo docs.

## 30. Definition of Done

- [ ] JSONL completes the full pipeline.
- [ ] Real PCAP parses without active traffic generation.
- [ ] All six SIH threat families have a detection path.
- [ ] Unknown/anomalous behavior can alert independently of supervised labels.
- [ ] Host baselines and temporal features contribute to detection.
- [ ] Alerts expose evidence and model scores.
- [ ] Dashboard shows live and historical alerts.
- [ ] Unseen-threat experiment is reproducible.
- [ ] Throughput and p50/p95/p99 latency are measured.
- [ ] Unit/integration/security tests pass.
- [ ] Dockerized local deployment works.
- [ ] No detection component transmits toward monitored endpoints.
- [ ] README contains setup and demo instructions.

## 31. Engineering rules

1. Passive by construction.
2. Metadata-first and payload-independent.
3. Known + unknown detection.
4. Behavior over isolated packets.
5. Evidence over opaque scores.
6. Measure performance; do not market unverified numbers.
7. Reproducible ML over notebook-only workflows.
8. Detector failures are isolated.
9. Security boundaries belong in architecture and CI.
10. Build a working vertical slice before adding distributed infrastructure.
