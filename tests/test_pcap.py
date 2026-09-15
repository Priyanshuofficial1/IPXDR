from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
from backend.ingestion.pcap import PCAPIngestor
from backend.processing.pipeline import Pipeline
from backend.features.flow import extract_flow_features

def test_pcap_ingestion_and_features(tmp_path: Path):
    pcap = tmp_path / "sample.pcap"
    packets = [
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234,dport=443,flags="S"),
        Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=443,dport=1234,flags="SA"),
        Ether()/IP(src="10.0.0.3", dst="8.8.8.8")/UDP(sport=5000,dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com")),
    ]
    wrpcap(str(pcap), packets)
    events = list(PCAPIngestor(pcap).events())
    assert len(events) == 3
    assert events[0].protocol == "TCP"
    assert events[2].dns["query"] == "example.com"
    pipeline = Pipeline()
    normalized = pipeline.process(events[0])
    features = extract_flow_features(normalized)
    assert features["is_tcp"] == 1
    assert features["syn"] == 1
