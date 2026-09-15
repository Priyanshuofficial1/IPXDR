from __future__ import annotations

def extract_quic_features(events):
    records=[e.quic for e in events if e.quic]
    versions={str(r.get('version')) for r in records if r.get('version') is not None}
    return {'quic_records':float(len(records)),'quic_unique_versions':float(len(versions)),'quic_long_header_ratio':sum(bool(r.get('long_header')) for r in records)/len(records) if records else 0.0,'quic_payload_mean':sum(float(r.get('payload_bytes',0)) for r in records)/len(records) if records else 0.0}
