from datetime import datetime, timedelta, timezone
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline
from backend.features.temporal import extract_temporal_features
from backend.processing.normalizer import normalize


def event(i, t, dst="10.0.0.2", port=443, size=100):
    return FlowEvent(event_id=str(i), timestamp=t, src_ip="10.0.0.1", dst_ip=dst,
                     src_port=5000+i, dst_port=port, protocol="TCP", packets=1,
                     bytes=size, duration_ms=10, tcp_flags=["A"], direction="inbound")


def test_temporal_features_are_deterministic():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [normalize(event(i, base + timedelta(seconds=i*i))) for i in range(4)]
    f = extract_temporal_features(events)
    assert f["event_count"] == 4
    assert f["interarrival_mean_s"] == 3.0
    assert f["interarrival_median_s"] == 3.0
    assert f["unique_destinations"] == 1
    assert f["unique_ports"] == 1


def test_behavioral_deviation_and_learning():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    p = Pipeline(window_seconds=60)
    for i in range(3):
        p.process(event(i, base + timedelta(seconds=i)))
    assert 0.0 <= p.last_behavior_deviation <= 1.0
    assert p.behavior.hosts["10.0.0.1"].observations >= 1
