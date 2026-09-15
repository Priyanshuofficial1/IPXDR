# DIODESENTINEL

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

Initial architecture scaffold. Implementation will be developed incrementally with tests, datasets, model cards, and measured benchmarks. No detection-performance claims are made until reproduced by the benchmark suite.

## Safety boundary

This project is for authorized defensive monitoring and controlled security research. It is passive by design and must not be used to interfere with monitored systems.
