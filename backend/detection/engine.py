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
from pathlib import Path
class DetectionEngine:
    def __init__(self):
        self.anomaly=AnomalyDetector(); self.supervised=SupervisedDetector(); self.trained=False
    def features(self,events):
        if not events:return {}
        return {**extract_flow_features(events[-1]),**extract_temporal_features(events),**communication_features(events)}
    def fit_anomaly(self,rows): self.anomaly.fit(rows); self.trained=True
    def fit_supervised(self,rows,labels): self.supervised.fit(rows,labels); self.trained=True
    def save_models(self, directory):
        d=Path(directory); d.mkdir(parents=True,exist_ok=True)
        if self.anomaly.fitted: self.anomaly.save(d/'anomaly.joblib')
        if self.supervised.fitted: self.supervised.save(d/'supervised.joblib')
    def load_models(self, directory):
        d=Path(directory)
        if (d/'anomaly.joblib').is_file(): self.anomaly.load(d/'anomaly.joblib')
        if (d/'supervised.joblib').is_file(): self.supervised.load(d/'supervised.joblib')
        self.trained=self.anomaly.fitted or self.supervised.fitted
        return self
    def analyze(self,event,window,behavior_deviation=0.0):
        row=self.features(window); anomaly=self.anomaly.score(row) if self.anomaly.fitted else 0.0
        results=detect(window)
        if self.supervised.fitted:
            start=perf_counter(); threat,score=self.supervised.predict(row)
            if threat and threat!='normal':
                results.append(DetectorResult(detector_name='random_forest',threat_class=threat,score=score,evidence=[f'supervised class={threat}',f'supervised probability={score:.3f}'],features_used=self.supervised.feature_names,model_version='rf-v1',latency_ms=(perf_counter()-start)*1000))
        alert=fuse(event.event_id,event.timestamp,results,behavior_deviation,anomaly)
        return row,results,alert
