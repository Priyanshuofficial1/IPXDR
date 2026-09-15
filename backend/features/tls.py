from __future__ import annotations

def extract_tls_features(events) -> dict[str,float]:
    records=[e.tls for e in events if e.tls]
    if not records: return {'tls_records':0.0,'tls_unique_ja3':0.0,'tls_unique_sni':0.0,'tls_cipher_count_mean':0.0,'tls_extension_count_mean':0.0}
    fps={str(x.get('ja3') or x.get('ja4') or '') for x in records}; snis={str(x.get('sni')) for x in records if x.get('sni')}
    return {'tls_records':float(len(records)),'tls_unique_ja3':float(len(fps)),'tls_unique_sni':float(len(snis)),
            'tls_cipher_count_mean':sum(float(x.get('cipher_count',0)) for x in records)/len(records),
            'tls_extension_count_mean':sum(float(x.get('extension_count',0)) for x in records)/len(records)}
