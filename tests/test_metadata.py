from scapy.all import Ether, IP, UDP, Raw
from backend.ingestion.metadata import quic_metadata

def test_quic_metadata_passive_heuristic():
    p=Ether()/IP()/UDP(sport=443,dport=443)/Raw(b'\xc0\x00\x00\x00\x01abc')
    m=quic_metadata(p)
    assert m and m['long_header'] is True and m['version']==1
