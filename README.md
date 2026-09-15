# IPXDR

Passive, self-adapting AI threat detection for unidirectional IP traffic.

> SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## Mission

Detect known and previously unseen network threats using only one-way traffic metadata. The monitoring enclave never probes, blocks, completes handshakes, sends mitigation traffic, or decrypts TLS/QUIC payloads.

## Core differentiators

- Per-host behavioral baselines
- Known-threat + unknown-threat detection
- Temporal traffic intelligence
- Communication-graph features
- Multi-model risk fusion
- Evidence-based alerts
- Strict passive/data-diode architecture
- Reproducible attack replay and real throughput/latency benchmarks

## Detection scope

DDoS (SYN/UDP/reflection/spoofing), C2 beaconing, DGA, DNS tunneling, encrypted malware via TLS/QUIC metadata, reconnaissance/port scanning, and data exfiltration.

## Architecture

```text
PCAP / NetFlow / IPFIX / sFlow
        -> Read-only ingest
        -> Flow normalization
        -> Feature engine
        -> Behavioral / Temporal / Graph features
        -> Supervised + Anomaly + Statistical detection
        -> Risk fusion
        -> Explainable alerts
        -> SOC dashboard
```

## Repository status

Core passive detection, advanced heuristic signals, anomaly/supervised model lifecycle, persistent alert storage, SOC dashboard, adversarial stress testing, unseen-threat proof fixture and CI are implemented. Dataset training remains intentionally separate; synthetic benchmarks are not real-world accuracy claims.

## Safety boundary

This project is for authorized defensive monitoring and controlled security research. It is passive by design and must not be used to interfere with monitored systems.

## Quick start

```bash
python -m pip install -e '.[test]'
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/dashboard` for the SOC dashboard and `http://127.0.0.1:8000/docs` for the API documentation.

### Passive ingestion

POST a validated `FlowEvent` to `/ingest`, or process a PCAP with packet events or aggregated passive 5-tuple flows:

```bash
python replay/pcap_replay.py path/to/capture.pcap
python replay/pcap_replay.py path/to/capture.pcap --aggregate
```

No packets are transmitted by the PCAP adapter.

### Detection stack

IPXDR combines interpretable protocol/statistical signals, a per-host behavioral baseline, temporal and communication-graph features, Isolation Forest anomaly scoring, and an optional labeled Random Forest. The fusion layer emits an alert only when combined evidence reaches the configured threshold.

### Validation and operations

```bash
pytest -q
python benchmarks/throughput.py
python benchmarks/adversarial.py
python benchmarks/unknown_threat.py
python scripts/demo.py
```

Alerts persist to SQLite when the API is run (`IPXDR_DB_PATH` controls the path), and fitted models are stored under `IPXDR_MODEL_DIR` (default `models/`). Training endpoints can be protected with `IPXDR_ADMIN_TOKEN`. Export alerts from `/alerts/export`. See `docs/FINAL_READINESS.md` for the implementation/evaluation boundary.

### Benchmark

On the development environment used for this repository, the current end-to-end Python pipeline processed 10,000 synthetic events in 4.20 s (~2,381 events/s; ~10.47 Mbps; p95 ~0.72 ms). This is an engineering benchmark, not a production throughput guarantee; reproduce it with `python benchmarks/throughput.py` on the target deployment hardware.

## Docker

```bash
docker build -t ipxdr .

docker run --rm -p 127.0.0.1:8000:8000 -e IPXDR_ADMIN_TOKEN=change-me ipxdr
```

The container exposes port 8000. The API is intended for a trusted monitoring enclave; put authentication and network policy in front of training endpoints before exposing them beyond localhost. See `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, `docs/ADVERSARIAL_TESTING.md`, and `docs/MODEL_CARD.md` for deployment and evaluation constraints.
