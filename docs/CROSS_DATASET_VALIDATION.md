# Cross-Dataset Validation Evidence

This document summarizes only measurements actually reproduced in the IPXDR repository. Metrics from different datasets are **not combined** into a single accuracy number because the inputs and ground-truth semantics differ.

| Dataset | Type | Samples | Ground truth | Precision | Recall | F1 | FPR | Limitation |
|---|---|---:|---|---:|---:|---:|---:|---|
| Synthetic/lab | Controlled feature fixture | 560 | Controlled 7-class labels | 1.0000 | 1.0000 | 1.0000 | 0.0000 | Not real-world accuracy |
| CTU-13 Scenario 43 / Neris | Real PCAP replay | 20,000 packets | Botnet-oriented scenario | — | — | — | — | No benign control labels for FPR/precision |
| UNSW-NB15 | Labelled flow-feature replay | 5,000 | 0 normal / 1 attack | 0.6812 | 0.9994 | 0.8101 | 0.9969 | Generated timestamps and reconstructed flow semantics |
| CIC-IDS2017 public sample | Labelled flow-feature replay | 5,000 | BENIGN / non-BENIGN | 0.5992 | 0.9993 | 0.7492 | 0.9975 | Sample lacks raw IP/protocol/port fields; adapter reconstructs required fields |
| UGR'16 | One-minute aggregate feature data | — | Labelled attack counts | — | — | — | — | Accessible author feature vectors are not directly compatible with `FlowEvent` |

## Interpretation

The real labelled-flow diagnostics expose a consistent calibration issue: the current production rules are highly sensitive on reconstructed datasets but produce many false positives. This evidence is preserved rather than tuned away. The appropriate next calibration target is native timestamped NetFlow/IPFIX/sFlow or PCAP data where direction, identity and temporal semantics are retained.

### Synthetic validation boundary

The 1.0000 synthetic test metrics demonstrate controlled detector/evaluation integration only. They are not production accuracy.

### CTU-13 boundary

20,000 packets were accepted by the production pipeline with zero replay failures. CTU-13 Scenario 43 is botnet-oriented, so it is useful for parser/integration/coverage validation but cannot independently establish false-positive rate.

### UNSW-NB15 boundary

The selected training CSV has labelled flow features but no packet timestamps. The adapter generates timestamps and uses `direction="unknown"`. A calibration study (`benchmarks/results/unsw-calibration.json`) found that 0.5–0.9 score thresholds produced essentially the same classification on the reconstructed replay, while 0.99 suppressed all detections. Replay spacing of 0.1, 1 and 5 seconds also produced the same result; 10 seconds moved observations outside the 60-second context and suppressed detections. This is evidence of replay/feature-context sensitivity, not a basis for changing production thresholds.

### CIC-IDS2017 boundary

The acquired public sample contains 56,661 labelled flow-feature rows. A stratified 5,000-row replay was evaluated through the production pipeline. Because the sample does not contain source/destination IPs and raw protocol/port fields, the adapter uses fixed documentation IPs and coarse protocol/port derivation. Therefore these metrics are adapter/pipeline evidence, not native PCAP detection accuracy.

### UGR'16 boundary

The official UGR'16 site returned HTTP 403 to automated retrieval during this validation run. An author-maintained feature-data repository was accessible and contains one-minute aggregate vectors and labels, but those observations do not map cleanly to IPXDR's per-flow `FlowEvent` contract. It is therefore recorded as provenance/compatibility evidence rather than a fabricated detector benchmark.

Machine-readable source: `benchmarks/results/cross-dataset-evaluation.json`.
