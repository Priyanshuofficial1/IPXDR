from __future__ import annotations
from math import log2
from time import perf_counter
from collections import Counter
from backend.ingestion.models import DetectorResult
from backend.processing.normalizer import NormalizedFlow
from backend.features.temporal import extract_temporal_features
from backend.features.dns import extract_dns_features
from backend.features.tls import extract_tls_features

def _result(name, threat, score, evidence, features, start):
    return DetectorResult(detector_name=name, threat_class=threat, score=max(0,min(1,float(score))), evidence=evidence, features_used=features, latency_ms=(perf_counter()-start)*1000)

def _entropy(values):
    c=Counter(values); n=sum(c.values())
    return -sum((v/n)*log2(v/n) for v in c.values()) if n else 0.0

def detect(events: list[NormalizedFlow]) -> list[DetectorResult]:
    if not events: return []
    f=extract_temporal_features(events); out=[]; n=len(events)
    tcp_syn=sum('S' in e.tcp_flags and 'A' not in e.tcp_flags for e in events)
    udp=sum(e.protocol=='UDP' for e in events); ports=len({e.dst_port for e in events}); dsts=len({e.dst_ip for e in events})
    sources=[e.src_ip for e in events]; src_entropy=_entropy(sources)
    total_bytes=sum(e.bytes for e in events)
    # Require enough observations for high-confidence behavioral rules.
    syn_score=min(1,(tcp_syn/max(1,n))*1.5) if n>=8 else 0.0
    udp_score=min(1,(udp/max(1,n))*1.25*(1+min(f['flow_rate']/1000,2))) if n>=8 else 0.0
    scan_score=min(1,max(0,(ports-3)/20)+(max(0,dsts-3)/50)) if n>=10 else 0.0
    spoof_score=min(1,src_entropy/5.0) if n>=20 else 0.0
    s=perf_counter(); out.append(_result('syn_flood','volumetric_ddos',syn_score,[f'SYN-only ratio={tcp_syn/n:.2f}',f'events={n}'],['syn','event_count'],s))
    s=perf_counter(); out.append(_result('udp_flood','volumetric_ddos',udp_score,[f'UDP ratio={udp/n:.2f}',f'flow_rate={f["flow_rate"]:.1f}/s'],['is_udp','flow_rate'],s))
    s=perf_counter(); out.append(_result('recon_port_scan','recon_port_scan',scan_score,[f'unique_ports={ports}',f'unique_destinations={dsts}'],['unique_ports','unique_destinations'],s))
    s=perf_counter(); out.append(_result('spoof_entropy','spoofed_source_flood',spoof_score,[f'source_ip_entropy={src_entropy:.2f}',f'unique_sources={len(set(sources))}'],['source_ip_entropy'],s))
    # Exfiltration requires a directional signal; unknown direction is deliberately not scored.
    outbound=sum(e.bytes for e in events if e.direction.lower() in {'outbound','egress','out','external'}); inbound=sum(e.bytes for e in events if e.direction.lower() in {'inbound','ingress','in','internal'})
    ratio=outbound/max(1,inbound) if outbound else 0.0
    exfil=min(1,max(0,(log2(max(1,ratio))-2)/8)) if outbound and inbound else 0.0
    s=perf_counter(); out.append(_result('exfil_asymmetry','data_exfiltration',exfil,[f'outbound_bytes={outbound}',f'inbound_bytes={inbound}',f'outbound_inbound_ratio={ratio:.2f}'],['directional_bytes','byte_ratio'],s))
    cv=f['interarrival_cv']; periodic=max(0,1-cv) if n>=8 else 0.0
    s=perf_counter(); out.append(_result('c2_beacon','botnet_c2_beaconing',periodic,[f'IAT CV={cv:.3f}',f'events={n}'],['interarrival_cv','interarrival_median_s'],s))
    dns=extract_dns_features(events)
    if dns['dns_query_count']:
        dga=min(1,max(0,(dns['dns_avg_label_entropy']-3.2)/1.8))
        tunnel=min(1,.45*min(1,dns['dns_avg_query_length']/80)+.35*dns['dns_long_label_ratio']+.2*dns['dns_txt_ratio'])
        s=perf_counter(); out.append(_result('dga','dga_domain',dga,[f'avg_label_entropy={dns["dns_avg_label_entropy"]:.2f}',f'unique_domains={dns["dns_unique_domains"]:.0f}'],['dns_avg_label_entropy','dns_unique_domains'],s))
        s=perf_counter(); out.append(_result('dns_tunnel','dns_tunneling',tunnel,[f'avg_query_length={dns["dns_avg_query_length"]:.1f}',f'long_label_ratio={dns["dns_long_label_ratio"]:.2f}',f'txt_ratio={dns["dns_txt_ratio"]:.2f}'],['dns_avg_query_length','dns_long_label_ratio','dns_txt_ratio'],s))
    tls=extract_tls_features(events)
    if tls['tls_records']:
        s=perf_counter(); out.append(_result('encrypted_metadata','encrypted_malware',0.0,[f'TLS metadata records={tls["tls_records"]:.0f}',f'unique_fingerprints={tls["tls_unique_ja3"]:.0f}','metadata alone is non-malware evidence'],['tls_unique_ja3','tls_unique_sni'],s))
    return out
