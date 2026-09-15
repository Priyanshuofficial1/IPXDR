from __future__ import annotations
from math import log2
from time import perf_counter
from collections import Counter
from backend.ingestion.models import DetectorResult
from backend.processing.normalizer import NormalizedFlow
from backend.features.temporal import extract_temporal_features
from backend.features.dns import extract_dns_features
from backend.features.tls import extract_tls_features
from backend.features.quic import extract_quic_features

def _result(name, threat, score, evidence, features, start, version='rules-v2'):
    return DetectorResult(detector_name=name, threat_class=threat, score=max(0,min(1,float(score))), evidence=evidence, features_used=features, model_version=version, latency_ms=(perf_counter()-start)*1000)

def _entropy(values):
    c=Counter(values); n=sum(c.values())
    return -sum((v/n)*log2(v/n) for v in c.values()) if n else 0.0

def detect(events: list[NormalizedFlow]) -> list[DetectorResult]:
    if not events: return []
    f=extract_temporal_features(events); out=[]; n=len(events)
    tcp_syn=sum('S' in e.tcp_flags and 'A' not in e.tcp_flags for e in events)
    udp=sum(e.protocol=='UDP' for e in events); ports=len({e.dst_port for e in events}); dsts=len({e.dst_ip for e in events})
    sources=[e.src_ip for e in events]; src_entropy=_entropy(sources)
    bytes_mean=sum(e.bytes for e in events)/n; packets_mean=sum(e.packets for e in events)/n
    syn_ratio=tcp_syn/n
    syn_score=min(1, max(0,(syn_ratio-.45)/.45)) if n>=8 else 0.0
    udp_ratio=udp/n
    dns_count=sum(1 for e in events if e.dns and e.dns.get('query'))
    non_dns_udp=sum(1 for e in events if e.protocol=='UDP' and not (e.dns and e.dns.get('query')))
    udp_effective_ratio=non_dns_udp/n
    udp_score=min(1, max(0,(udp_effective_ratio-.55)/.4) + .15*min(1,f['flow_rate']/500)) if n>=8 else 0.0
    scan_score=min(1,max(0,(ports-3)/18)+(max(0,dsts-3)/45)) if n>=10 else 0.0
    spoof_score=min(1,src_entropy/5.0) if n>=20 else 0.0
    # Reflection/amplification heuristic: fan-in from many sources to one destination plus large UDP packets.
    dst_counts=Counter(e.dst_ip for e in events); max_fanin=max(dst_counts.values()) if dst_counts else 0
    udp_big=max(0.0,min(1.0,(bytes_mean-300)/1200))
    reflection=min(1.0, max(0,(len(set(sources))-5)/40) + max(0,(max_fanin/n)-.5) + .45*udp_big) if n>=20 and udp else 0.0
    s=perf_counter(); out.append(_result('syn_flood','volumetric_ddos',syn_score,[f'SYN-only ratio={syn_ratio:.2f}',f'events={n}'],['syn','event_count'],s))
    s=perf_counter(); out.append(_result('udp_flood','volumetric_ddos',udp_score,[f'non-DNS UDP ratio={udp_effective_ratio:.2f}',f'flow_rate={f["flow_rate"]:.1f}/s'],['is_udp','flow_rate'],s))
    s=perf_counter(); out.append(_result('udp_reflection','udp_reflection_amplification',reflection,[f'UDP fan-in sources={len(set(sources))}',f'max destination fan-in={max_fanin}',f'mean bytes/event={bytes_mean:.1f}'],['source_fan_in','destination_fan_in','mean_bytes'],s))
    s=perf_counter(); out.append(_result('recon_port_scan','recon_port_scan',scan_score,[f'unique_ports={ports}',f'unique_destinations={dsts}'],['unique_ports','unique_destinations'],s))
    s=perf_counter(); out.append(_result('spoof_entropy','spoofed_source_flood',spoof_score,[f'source_ip_entropy={src_entropy:.2f}',f'unique_sources={len(set(sources))}'],['source_ip_entropy'],s))
    outbound=sum(e.bytes for e in events if e.direction.lower() in {'outbound','egress','out','external'}); inbound=sum(e.bytes for e in events if e.direction.lower() in {'inbound','ingress','in','internal'})
    ratio=outbound/max(1,inbound) if outbound else 0.0
    exfil=min(1,max(0,(log2(max(1,ratio))-2)/8)) if outbound and inbound else 0.0
    s=perf_counter(); out.append(_result('exfil_asymmetry','data_exfiltration',exfil,[f'outbound_bytes={outbound}',f'inbound_bytes={inbound}',f'outbound_inbound_ratio={ratio:.2f}'],['directional_bytes','byte_ratio'],s))
    cv=f['interarrival_cv']; periodic=max(0,1-cv) if n>=8 else 0.0
    # Periodicity alone is weak evidence; require repeated observations and keep score below certainty.
    periodic=min(.92,periodic) if n>=8 else 0.0
    s=perf_counter(); out.append(_result('c2_beacon','botnet_c2_beaconing',periodic,[f'IAT CV={cv:.3f}',f'events={n}'],['interarrival_cv','interarrival_median_s'],s))
    dns=extract_dns_features(events)
    if dns['dns_query_count']:
        dga=min(1,max(0,.45*(dns['dns_avg_label_entropy']-3.0)/2 + .55*dns['dns_avg_ngram_risk']))
        tunnel=min(1,.35*min(1,dns['dns_avg_query_length']/80)+.25*dns['dns_long_label_ratio']+.2*dns['dns_txt_ratio']+.2*dns['dns_unique_label_ratio'])
        s=perf_counter(); out.append(_result('dga','dga_domain',dga,[f'avg_label_entropy={dns["dns_avg_label_entropy"]:.2f}',f'ngram_risk={dns["dns_avg_ngram_risk"]:.2f}',f'digit_ratio={dns["dns_digit_ratio"]:.2f}'],['dns_avg_label_entropy','dns_avg_ngram_risk','dns_digit_ratio'],s))
        s=perf_counter(); out.append(_result('dns_tunnel','dns_tunneling',tunnel,[f'avg_query_length={dns["dns_avg_query_length"]:.1f}',f'long_label_ratio={dns["dns_long_label_ratio"]:.2f}',f'txt_ratio={dns["dns_txt_ratio"]:.2f}'],['dns_avg_query_length','dns_long_label_ratio','dns_txt_ratio'],s))
    tls=extract_tls_features(events); quic=extract_quic_features(events)
    if tls['tls_records'] or quic['quic_records']:
        # Metadata is a feature source, never proof of malware. Score only when novelty/transport behavior is unusual.
        tls_novel=min(1,tls['tls_unique_ja3']/max(1,n)); quic_ratio=quic['quic_long_header_ratio']
        encrypted=min(.78, .35*tls_novel + .25*quic_ratio + .18*min(1,f['interarrival_cv']*.5))
        s=perf_counter(); out.append(_result('encrypted_metadata','encrypted_malware',encrypted,[f'TLS records={tls["tls_records"]:.0f}',f'unique JA3={tls["tls_unique_ja3"]:.0f}',f'QUIC records={quic["quic_records"]:.0f}','metadata-only signal; payload not decrypted'],['tls_unique_ja3','quic_long_header_ratio','interarrival_cv'],s))
    return out
