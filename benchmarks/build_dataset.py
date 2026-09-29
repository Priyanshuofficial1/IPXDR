"""Build a deterministic labelled feature dataset for reproducible IPXDR evaluation.

The generated records are controlled synthetic/lab observations. Real captures are
listed in the provenance manifest but are never mislabeled or treated as synthetic.
"""
from __future__ import annotations
import argparse, hashlib, json, platform
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.normalizer import normalize
from backend.detection.engine import DetectionEngine

BASE=datetime(2026,1,1,tzinfo=timezone.utc)

def ev(i,label,**kw):
    d=dict(event_id=f"dataset-{label}-{i}",timestamp=BASE+timedelta(seconds=i),
           src_ip="10.10.0.10",dst_ip="198.51.100.10",src_port=40000+i,dst_port=443,
           protocol="TCP",packets=5,bytes=800,duration_ms=20,tcp_flags=["A"],
           direction="outbound",source="synthetic-lab")
    d.update(kw); return label, normalize(FlowEvent(**d))

def make_rows(per_class=80):
    specs={
      "normal": lambda i: ev(i,"normal"),
      "ddos": lambda i: ev(i,"ddos",src_ip="10.10.0.50",packets=100,bytes=6000,duration_ms=10,tcp_flags=["S"]),
      "c2_beaconing": lambda i: ev(i,"c2_beaconing",dst_ip="203.0.113.60",src_port=5000,packets=2,bytes=200,duration_ms=100),
      "dga_dns_tunneling": lambda i: ev(i,"dga_dns_tunneling",dst_ip="198.51.100.53",src_port=50000+i,dst_port=53,protocol="UDP",packets=2,bytes=700,dns={"query":"x"*50+str(i)+".example.test","qtype":"TXT","rcode":"NOERROR"}),
      "encrypted_malware": lambda i: ev(i,"encrypted_malware",dst_ip="203.0.113.80",src_port=45000+i,tls={"ja3":f"malware-{i%8}","sni":f"host{i%8}.example.test"}),
      "recon_port_scan": lambda i: ev(i,"recon_port_scan",dst_ip=f"198.51.100.{i%50+1}",src_port=30000+i,dst_port=1000+i%100,packets=1,bytes=60,duration_ms=1,tcp_flags=["S"]),
      "exfiltration": lambda i: ev(i,"exfiltration",dst_ip="203.0.113.100",src_port=35000+i,packets=40,bytes=10000,duration_ms=100),
    }
    engine=DetectionEngine(); windows=[]; rows=[]
    for label,fn in specs.items():
        for i in range(per_class):
            _,n=fn(i); windows.append(n)
            features=engine.features(windows[-min(64,len(windows)):])
            rows.append({"label":label,**{k:float(v) for k,v in features.items() if isinstance(v,(int,float))}})
    return rows

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,default=Path("datasets/evaluation/synthetic_features.jsonl"))
    p.add_argument("--per-class",type=int,default=80); p.add_argument("--seed",type=int,default=42)
    a=p.parse_args(); a.output.parent.mkdir(parents=True,exist_ok=True)
    rows=make_rows(a.per_class)
    with a.output.open("w",encoding="utf-8") as f:
        for row in rows: f.write(json.dumps(row,sort_keys=True)+"\n")
    manifest={"schema_version":"1.0","dataset_id":"ipxdr-synthetic-lab-v1","type":"controlled_synthetic_lab",
              "warning":"Synthetic evaluation only; not real-world accuracy","seed":a.seed,"rows":len(rows),
              "classes":sorted({r["label"] for r in rows}),"python":platform.python_version(),
              "platform":platform.platform(),"created_utc":datetime.now(timezone.utc).isoformat(),
              "source_files":[{"path":"datasets/real/c2/ctu43-neris.pcap","sha256":sha256(Path("datasets/real/c2/ctu43-neris.pcap")),"type":"real_public_capture_reference","used_in_training":False}]}
    manifest["output_sha256"]=sha256(a.output)
    mp=a.output.with_suffix(".manifest.json"); mp.write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    print(json.dumps(manifest,indent=2))

if __name__=="__main__": main()
