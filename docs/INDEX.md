# IPXDR Documentation Index

## Core engineering documents

- `PRD.md` — Product Requirements Document: product scope, goals, users, functional requirements, threat coverage, evaluation and acceptance criteria.
- `TRD.md` — Technical Requirements Document: implementation architecture, technology stack, contracts, processing pipeline, features, ML, APIs, persistence, frontend, testing, deployment and CI/CD.
- `ARCHITECTURE.md` — system architecture.
- `ALERT_SCHEMA.md` — alert schema.
- `ROADMAP.md` — delivery roadmap.

## Build order

1. Read PRD for **what IPXDR must achieve**.
2. Read TRD for **how IPXDR should be engineered**.
3. Implement Phase 1 foundation.
4. Add real PCAP ingestion.
5. Add detectors and anomaly path.
6. Add behavioral, temporal and graph intelligence.
7. Add dashboard, persistence and benchmark automation.

The PRD defines product acceptance. The TRD defines the technical baseline used to implement and test that acceptance.

- `ADVERSARIAL_TESTING.md` — controlled evasion robustness benchmark.
- `DEMO.md` — SIH26145 demonstration and benchmark commands.
- `INGESTION.md` — PCAP and flow-export adapter boundaries.
- `SECURITY.md` — passive invariant and API hardening.
