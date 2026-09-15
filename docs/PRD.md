# IPXDR Product Requirements Document

## Vision
A passive, self-adapting AI platform that detects known and previously unseen cyber threats in unidirectional IP traffic using metadata only.

## Primary requirements
1. Read-only PCAP/NetFlow/IPFIX/sFlow ingestion.
2. Near-real-time bounded-latency processing.
3. Detection of DDoS, C2 beaconing, DGA, DNS tunneling, encrypted malware metadata anomalies, reconnaissance, and exfiltration.
4. Per-host behavioral baselines.
5. Unknown-threat anomaly detection.
6. Temporal and communication-graph features.
7. Multi-model risk fusion with evidence-backed explanations.
8. Standard alert schema: timestamp, flow ID, threat class, confidence, supporting evidence.
9. Measured throughput, latency, and resource utilization.
10. Reproducible validation, including attacks withheld from training.

## Non-goals
No probing, blocking, mitigation packets, handshake completion, payload decryption, or outbound communication into the monitored enclave.

## Success criteria
A working prototype demonstrates the above requirements on controlled data and reports measured performance rather than unverified targets.
