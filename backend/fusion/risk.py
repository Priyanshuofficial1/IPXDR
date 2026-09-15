from __future__ import annotations
from backend.ingestion.models import Alert, DetectorResult

def severity(score: float) -> str:
    if score >= .9: return 'CRITICAL'
    if score >= .75: return 'HIGH'
    if score >= .5: return 'MEDIUM'
    return 'LOW'

def fuse(flow_id: str, timestamp, results: list[DetectorResult], behavior_deviation=0.0, anomaly_score=0.0) -> Alert | None:
    if not results and anomaly_score < .5: return None
    groups={}
    for r in results: groups.setdefault(r.threat_class,[]).append(r)
    if not groups:
        threat='unknown_anomaly'; confidence=anomaly_score; chosen=[]
    else:
        # Evidence fusion: strongest detector plus corroboration and host deviation.
        threat,chosen=max(groups.items(), key=lambda x:max(r.score for r in x[1]))
        strongest=max(r.score for r in chosen); corroboration=min(.2,.08*(len(chosen)-1)); confidence=min(1,.65*strongest+.2*behavior_deviation+.15*anomaly_score+corroboration)
        if anomaly_score>.8: confidence=min(1,confidence+.1)
    evidence=[]
    for r in chosen: evidence.extend(r.evidence)
    if behavior_deviation: evidence.append(f'behavior_deviation={behavior_deviation:.3f}')
    if anomaly_score: evidence.append(f'anomaly_score={anomaly_score:.3f}')
    if confidence < 0.5:
        return None
    return Alert(alert_id=f'{flow_id}:{threat}',timestamp=timestamp,flow_id=flow_id,threat_class=threat,confidence=confidence,severity=severity(confidence),supporting_evidence=evidence[:12],model_scores={r.detector_name:r.score for r in chosen},behavior_deviation=behavior_deviation)
