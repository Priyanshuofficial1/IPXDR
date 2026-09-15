from __future__ import annotations
from backend.ingestion.models import Alert, DetectorResult

def severity(score):
    if score>=.9:return 'CRITICAL'
    if score>=.75:return 'HIGH'
    if score>=.5:return 'MEDIUM'
    return 'LOW'

def fuse(flow_id,timestamp,results,behavior_deviation=0.0,anomaly_score=0.0):
    groups={}
    for r in results:
        if r.score>=.5: groups.setdefault(r.threat_class,[]).append(r)
    if not groups:
        if anomaly_score<.5:return None
        threat='unknown_anomaly'; chosen=[]; confidence=anomaly_score*.85+.15*behavior_deviation
    else:
        threat,chosen=max(groups.items(),key=lambda x:(max(r.score for r in x[1]),len(x[1])))
        strongest=max(r.score for r in chosen); corroboration=min(.15,.05*(len(chosen)-1))
        confidence=min(1,.65*strongest+.2*behavior_deviation+.15*anomaly_score+corroboration)
        if anomaly_score>.8: confidence=min(1,confidence+.08)
    if confidence<.5:return None
    evidence=[]
    for r in chosen:evidence.extend(r.evidence)
    if behavior_deviation:evidence.append(f'behavior_deviation={behavior_deviation:.3f}')
    if anomaly_score:evidence.append(f'anomaly_score={anomaly_score:.3f}')
    return Alert(alert_id=f'{flow_id}:{threat}',timestamp=timestamp,flow_id=flow_id,threat_class=threat,confidence=confidence,severity=severity(confidence),supporting_evidence=evidence[:12],model_scores={r.detector_name:r.score for r in chosen},behavior_deviation=behavior_deviation)
