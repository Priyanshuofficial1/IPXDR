# SIH26145 Demo

The prototype can be demonstrated entirely with synthetic metadata.

```bash
python scripts/demo.py
```

The demo exercises passive feature extraction and fusion without transmitting packets. For the live dashboard:

```bash
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
python scripts/demo.py
# open http://127.0.0.1:8000/dashboard
```

For a reproducible throughput/latency measurement:

```bash
python benchmarks/throughput.py -n 10000
```

The benchmark reports events/s, derived Mbps, and p50/p95/p99 per-event processing latency.
