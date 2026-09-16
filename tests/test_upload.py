from fastapi.testclient import TestClient
from backend.api import main
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

def test_pcap_upload_uses_capture_data(tmp_path):
    path=tmp_path/'sample.pcap'
    pkt=Ether()/IP(src="192.0.2.1",dst="198.51.100.2")/TCP(sport=1234,dport=443,flags="S")
    wrpcap(str(path), [pkt])
    with TestClient(main.app) as c:
        r=c.post('/upload/pcap',files={'file':('sample.pcap',path.read_bytes(),'application/vnd.tcpdump.pcap')})
        assert r.status_code==200
        d=r.json(); assert d['packets']==1 and d['flows']==1 and d['filename']=='sample.pcap'
        a=c.get('/analysis/latest').json(); assert a['loaded'] is True and a['packets']==1
        hosts=c.get('/hosts').json(); assert any(x['src_ip']=='192.0.2.1' for x in hosts)
