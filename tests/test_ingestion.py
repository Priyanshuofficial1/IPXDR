import json
from datetime import datetime, timezone
from backend.ingestion.jsonl import JSONLIngestor
from backend.ingestion.models import FlowEvent
from backend.processing.normalizer import normalize
from backend.processing.pipeline import Pipeline

def sample():
    return FlowEvent(event_id="e1", timestamp=datetime.now(timezone.utc), src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=443, protocol="tcp", packets=3, bytes=300, duration_ms=10, tcp_flags=["ack", "SYN"], direction="OUTBOUND", source="jsonl")

def test_schema_and_normalization():
    event = sample()
    normalized = normalize(event)
    assert normalized.protocol == "TCP"
    assert normalized.direction == "outbound"
    assert normalized.tcp_flags == ("ACK", "SYN")

def test_jsonl_ingestion(tmp_path):
    event = sample().model_dump(mode="json")
    path = tmp_path / "flows.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    assert [e.event_id for e in JSONLIngestor(path).events()] == ["e1"]

def test_pipeline_window():
    pipeline = Pipeline(window_seconds=60)
    event = sample()
    pipeline.process(event)
    assert pipeline.stats.received == 1
    assert pipeline.stats.accepted == 1
    assert len(pipeline.windows.get("10.0.0.1")) == 1
