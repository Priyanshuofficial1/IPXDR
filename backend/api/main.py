from __future__ import annotations
from fastapi import FastAPI
from backend.processing.pipeline import Pipeline

app = FastAPI(title="IPXDR API", version="0.1.0")
pipeline = Pipeline()

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ipxdr"}

@app.get("/metrics")
def metrics() -> dict[str, int]:
    stats = pipeline.stats
    return {"received": stats.received, "accepted": stats.accepted, "failed": stats.failed}
