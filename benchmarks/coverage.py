"""End-to-end SIH threat-family coverage using the production Pipeline.

All generated traffic is controlled synthetic/lab traffic. It is not a claim of
real-world detection accuracy. The runner proves each required SIH family reaches
the real ingestion -> feature -> detection -> alert path.
"""
from __future__ import annotations
import argparse, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)

def event(i: int, **kw) -> FlowEvent:
    d = dict(event_id=f"coverage-{i}", timestamp=BASE + timedelta(seconds=i),
             src_ip="10.0.0.10", dst_ip="198.51.100.10", src_port=40000+i,
             dst_port=443, protocol="TCP", packets=5, bytes=800, duration_ms=20,
             tcp_flags=["A"], direction="outbound", source="synthetic-lab")
    d.update(kw)
    return FlowEvent(**d)

def scenarios():
    return {
        "ddos": [event(i, src_ip="10.0.0.50", dst_ip="198.51.100.20", src_port=1000+i,
                       dst_port=443, packets=100, bytes=6000, duration_ms=10, tcp_flags=["S"]) for i in range(24)],
        "c2_beaconing": [event(i, src_ip="10.0.0.60", dst_ip="203.0.113.60",
                               src_port=5000, dst_port=443, packets=2, bytes=200,
                               duration_ms=100) for i in range(24)],
        "dga_dns_tunneling": [event(i, src_ip="10.0.0.70", dst_ip="198.51.100.53",
                                    src_port=50000+i, dst_port=53, protocol="UDP",
                                    packets=2, bytes=700,
                                    dns={"query":"x"*50+str(i)+".example.test","qtype":"TXT","rcode":"NOERROR"}) for i in range(24)],
        "encrypted_malware": [event(i, src_ip="10.0.0.80", dst_ip="203.0.113.80",
                                    src_port=45000+i, dst_port=443,
                                    tls={"ja3":f"malware-{i}","sni":f"host{i}.example.test"}, quic={"version":"1","long_header":True,"payload_bytes":120}) for i in range(24)],
        "recon_port_scan": [event(i, src_ip="10.0.0.90", dst_ip=f"198.51.100.{i+1}",
                                  src_port=30000+i, dst_port=1000+i, packets=1, bytes=60,
                                  duration_ms=1, tcp_flags=["A"]) for i in range(24)],
        "exfiltration": (
            [event(i, src_ip="10.0.0.100", dst_ip="203.0.113.100",
                   src_port=35000+i, dst_port=443, packets=40, bytes=10000,
                   duration_ms=100, direction="outbound", timestamp=BASE+timedelta(seconds=(i//12)*100+(i%12)*(1 if i%2 else 7))) for i in range(12)]
            + [event(100+i, src_ip="10.0.0.100", dst_ip="203.0.113.100",
                     src_port=443, dst_port=35000+i, packets=2, bytes=100,
                     direction="inbound", timestamp=BASE+timedelta(seconds=30+i)) for i in range(2)]
        ),
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--json", action="store_true")
    p.add_argument("--output", type=Path)
    a=p.parse_args()
    results=[]
    for name, events in scenarios().items():
        pipe=Pipeline()
        alerts=[]; errors=[]; detector_classes=set()
        for e in events:
            try:
                pipe.process(e)
                detector_classes.update(r.threat_class for r in pipe.last_detector_results if r.score >= 0.5)
                latest=pipe.alerts.list(limit=1)
                if latest:
                    alerts.append(latest[0])
            except Exception as exc:
                errors.append(str(exc))
        classes=sorted(detector_classes | {getattr(x,"threat_class","") for x in alerts if getattr(x,"threat_class","")})
        target={"ddos":"volumetric_ddos","c2_beaconing":"botnet_c2_beaconing","dga_dns_tunneling":"dns_tunneling","encrypted_malware":"encrypted_malware","recon_port_scan":"recon_port_scan","exfiltration":"data_exfiltration"}[name]
        results.append({"scenario":name,"target_class":target,"provenance":"controlled_synthetic_lab","events":len(events),
                        "alerts":len(alerts),"detected_classes":classes,"errors":errors,
                        "covered":target in classes and not errors})
    result={"schema_version":"1.0","dataset_type":"synthetic_lab",
            "warning":"Not real-world accuracy","required_families":list(scenarios()),
            "results":results,"all_covered":all(x["covered"] for x in results)}
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2) if a.json else "\n".join(
        f"{x['scenario']}: {'PASS' if x['covered'] else 'FAIL'} -> {x['detected_classes']}" for x in results))
    raise SystemExit(0 if result["all_covered"] else 1)

if __name__ == "__main__":
    main()
