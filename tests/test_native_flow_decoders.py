import struct
from backend.ingestion.ipfix import IPFIXDecoder
from backend.ingestion.sflow import SFlowDecoder

def test_ipfix_template_and_data():
    fields=[(8,4),(12,4),(7,2),(11,2),(4,1),(2,8),(1,8)]
    body=struct.pack('!HH',256,len(fields))+b''.join(struct.pack('!HH',*x) for x in fields)
    template=struct.pack('!HH',2,4+len(body))+body
    row=bytes([10,0,0,1])+bytes([10,0,0,2])+struct.pack('!HHBQQ',1234,80,6,3,1200)
    data=struct.pack('!HH',256,4+len(row))+row
    msg=template+data
    hdr=struct.pack('!HHIII',10,16+len(msg),1700000000,7,42)
    ev=list(IPFIXDecoder().decode(hdr+msg))[0]
    assert ev.src_ip=='10.0.0.1' and ev.dst_port==80 and ev.bytes==1200

def test_sflow_raw_ipv4_flow_sample():
    ip=bytes([0x45,0,0,40,0,0,0,0,64,6,0,0,10,0,0,1,10,0,0,2])+struct.pack('!HH',1234,80)+b'\x00'*20
    eth=b'\xaa'*12+struct.pack('!H',0x0800)+ip
    rec_body=struct.pack('!4I',1,len(eth),0,len(eth))+eth
    rec=struct.pack('!II',1,len(rec_body))+rec_body
    sample_body=struct.pack('!9I',1,1,1,1,1,0,1,1,1)+rec
    sample=struct.pack('!II',1,len(sample_body))+sample_body
    dg=struct.pack('!7I',5,1,0x01020304,1,1,100,1)+sample
    ev=list(SFlowDecoder().decode(dg))[0]
    assert ev.src_ip=='10.0.0.1' and ev.dst_port==80
