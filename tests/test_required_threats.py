from datetime import datetime, timedelta, timezone

from backend.detection.rules import detect
from backend.ingestion.models import FlowEvent
from backend.processing.normalizer import normalize


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make(i, **overrides):
    data = dict(
        event_id=f"accept-{i}",
        timestamp=BASE + timedelta(seconds=i),
        src_ip="10.0.0.1",
        dst_ip="198.51.100.10",
        src_port=40000 + i,
        dst_port=443,
        protocol="TCP",
        packets=5,
        bytes=800,
        duration_ms=20,
        tcp_flags=["A"],
        direction="outbound",
        source="acceptance",
    )
    data.update(overrides)
    return normalize(FlowEvent(**data))


def classes(events):
    return {r.threat_class for r in detect(events)}


def test_required_six_threat_families_have_detector_paths():
    events = [make(i) for i in range(12)]
    assert "volumetric_ddos" in classes(
        [make(i, tcp_flags=["S"], dst_port=443) for i in range(20)]
    )
    assert "botnet_c2_beaconing" in classes(events)
    assert "recon_port_scan" in classes(
        [make(i, dst_port=1000 + i, dst_ip=f"198.51.100.{i + 1}") for i in range(20)]
    )
    assert "data_exfiltration" in classes(
        [make(i, bytes=10000, direction="outbound") for i in range(12)]
        + [make(100 + i, bytes=100, direction="inbound") for i in range(2)]
    )


def test_dns_and_encrypted_metadata_paths():
    dns_events = [
        make(i, protocol="UDP", dst_port=53, dns={
            "query": f"{'x' * 50}{i}.example.test",
            "qtype": "TXT",
            "rcode": "NOERROR",
        })
        for i in range(12)
    ]
    dns_classes = classes(dns_events)
    assert "dga_domain" in dns_classes
    assert "dns_tunneling" in dns_classes

    tls_events = [
        make(i, tls={"ja3": f"fingerprint-{i}", "sni": f"host{i}.example.test"})
        for i in range(12)
    ]
    assert "encrypted_malware" in classes(tls_events)
