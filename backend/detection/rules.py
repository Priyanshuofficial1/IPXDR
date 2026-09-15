from __future__ import annotations
from math import log2
from time import perf_counter
from collections import Counter
from backend.ingestion.models import DetectorResult
from backend.processing.normalizer import NormalizedFlow
from backend.features.flow import extract_flow_features
from backend.features.temporal import extract_temporal_features


def _result(name, threat, score, evidence, features, start):
    return DetectorResult(detector_name=name, threat_class=threat, score=max(0,min(1,float(score))), evidence=evidence, features_used=features, latency_ms=(perf_counter()-start)*1000)


def _entropy(values):
    c=Counter(values); n=sum(c.values())
    return -sum((v/n)*log2(v/n) for v in c.values()) if n else 0.0


def detect(events: list[NormalizedFlow]) -> list[DetectorResult]:
    if not events: return []
    f=extract_temporal_features(events); out=[]
    tcp_syn=sum('S' in e.tcp_flags and 'A' not in e.tcp_flags for e in events)
    udp=sum(e.protocol=='UDP' for e in events)
    ports=len({e.dst_port for e in events}); dsts=len({e.dst_ip for e in events})
    bytes_out=sum(e.bytes for e in events)
    for name,threat,score,evidence,features in [
      ('syn_flood','volumetric_ddos', min(1,tcp_syn/max(1,len(events))*1.5), [f'SYN-only ratio={tcp_syn/len(events):.2f}'], ['syn','event_count']),
      ('udp_flood','volumetric_ddos', min(1,(udp/max(1,len(events)))*1.25*(1+min(f['flow_rate']/1000,2))), [f'UDP ratio={udp/len(events):.2f}',f'flow_rate={f["flow_rate"]:.1f}/s'], ['is_udp','flow_rate']),
      ('recon_port_scan','recon_port_scan', min(1,(ports-1)/20 + (dsts-1)/50), [f'unique_ports={ports}',f'unique_destinations={dsts}'], ['unique_ports','unique_destinations']),
      ('spoof_entropy','spoofed_source_flood', min(1,_entropy([e.src_ip for e in events])/8), [f'source_ip_entropy={_entropy([e.src_ip for e in events]):.2f}'], ['source_ip_entropy']),
      ('exfil_asymmetry','data_exfiltration', min(1,bytes_out/10_000_000), [f'window_bytes={bytes_out}'], ['byte_rate','event_count']),
    ]:
        s=perf_counter(); out.append(_result(name,threat,score,evidence,features,s))
    # Beaconing: low IAT variation is a useful passive signal, not a verdict.
    s=perf_counter(); cv=f['interarrival_cv']; periodic=max(0,1-cv) if len(events)>3 else 0
    out.append(_result('c2_beacon','botnet_c2_beaconing',periodic,[f'IAT CV={cv:.3f}',f'events={len(events)}'],['interarrival_cv','interarrival_median_s'],s))
    # DNS/DGA/tunneling metadata signals.
    dns=[e.dns for e in events if e.dns and e.dns.get('query')]
    if dns:
        names=[str(x['query']) for x in dns]; avg_len=sum(len(x) for x in names)/len(names)
        labels=[x.split('.')[0] for x in names]
        ent=sum(_entropy(list(x)) for x in labels)/len(labels)
        dga=min(1,max(0,(ent-3.0)/2.0))
        tunnel=min(1,max(0,(avg_len-45)/80))
        s=perf_counter(); out.append(_result('dga','dga_domain',dga,[f'avg_query_label_entropy={ent:.2f}',f'avg_query_length={avg_len:.1f}'],['dns_query_entropy','dns_query_length'],s))
        s=perf_counter(); out.append(_result('dns_tunnel','dns_tunneling',tunnel,[f'avg_query_length={avg_len:.1f}',f'dns_queries={len(names)}'],['dns_query_length','dns_query_rate'],s))
    tls=[e.tls for e in events if e.tls]
    if tls:
        fps=[str(x.get('ja3') or x.get('ja4') or '') for x in tls]; uniq=len(set(fps))
        s=perf_counter(); out.append(_result('encrypted_metadata','encrypted_malware',min(1,0.15+0.15*uniq),[f'TLS/QUIC metadata records={len(tls)}',f'fingerprints={uniq}'],['tls_fingerprint','packet_timing'],s))
    return out
