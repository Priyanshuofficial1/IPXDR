# IPXDR Detection Model Card

## Scope
Passive network-metadata detection for SIH26145. Payload decryption and active response are out of scope.

## Models
- Rule/statistical detectors provide interpretable signals for protocol/volume/temporal behavior.
- Isolation Forest is used for unsupervised unknown-behavior scoring.
- Risk fusion combines detector scores, anomaly score, and host behavioral deviation.
- Random Forest provides optional multiclass classification when labelled training data is available.

## Evaluation
Do not claim production accuracy from synthetic fixtures. Use separated train/validation/test captures and report precision, recall, F1, PR-AUC, false-positive rate, calibration, throughput and p50/p95/p99 latency.

The repository includes benchmarks/evaluate.py for a labelled JSONL feature dataset. Each line contains a string label plus numeric feature fields. The tool performs a stratified train/test split before fitting the Random Forest and emits classification metrics and a confusion matrix. Validation and test captures must remain separated from training data when producing SIH results.

## Limitations
Metadata-only detection can miss attacks whose distinguishing information exists only in payloads. Scores are evidence indicators, not proof of compromise.
