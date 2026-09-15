from __future__ import annotations
from backend.features.flow import extract_flow_features
from backend.features.temporal import extract_temporal_features
from backend.graph.features import communication_features
from backend.detection.rules import detect
from backend.anomaly.isolation_forest import AnomalyDetector
from backend.fusion.risk import fuse
from ml.models.supervised import SupervisedDetector
from backend.ingestion.models import DetectorResult
from time import perf_counter
class DetectionEngine:
    def __init__(self):
        self.anomaly=AnomalyDetector(); self.supervised=SupervisedDetector(); self.trained=False
    def features(self,events):
        if not events:return {}
        return {**extract_flow_features(events[-1]),**extract_temporal_features(events),**communication_features(events)}
    def fit_anomaly(self,rows): self.anomaly.fit(rows); self.trained=True
    def fit_supervised(self,rows,labels): self.supervised.fit(rows,labels); self.trained=True
    def analyze(self,event,window,behavior_deviation=0.0):
        row=self.features(window); anomaly=self.anomaly.score(row) if self.anomaly.fitted else 0.0
        results=detect(window)
        if self.supervised.fitted:
            start=perf_counter(); threat,score=self.supervised.predict(row)
            if threat and threat!='normal':
                results.append(DetectorResult(detector_name='random_forest',threat_class=threat,score=score,evidence=[f'supervised class={threat}',f'supervised probability={score:.3f}'],features_used=self.supervised.feature_names,model_version='rf-v1',latency_ms=(perf_counter()-start)*1000))
        alert=fuse(event.event_id,event.timestamp,results,behavior_deviation,anomaly)
        return row,results,alert
