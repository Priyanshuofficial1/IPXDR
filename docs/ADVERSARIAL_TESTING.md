# Adversarial / Evasion Testing

IPXDR includes an offline, defensive evasion benchmark. It transforms synthetic beacon metadata rather than generating or transmitting attack traffic.

```bash
python benchmarks/adversarial.py
python benchmarks/adversarial.py --json
```

Current controlled cases:
- timing jitter
- traffic-volume reduction
- destination rotation
- combined timing/volume/destination variation

The benchmark records detector scores and whether fusion generated an alert. It is an engineering robustness check, **not** a claim of adversarial robustness or real-world detection accuracy. Future validation should use held-out captures and explicit false-positive/false-negative analysis.
