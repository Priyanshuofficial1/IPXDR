from __future__ import annotations
from backend.features.flow import extract_flow_features
from backend.features.temporal import extract_temporal_features
from backend.graph.features import communication_features
from backend.detection.rules import detect
from backend.anomaly.isolation_forest import AnomalyDetector
from backend.fusion.risk import fuse
class DetectionEngine:
    def __init__(self): self.anomaly=AnomalyDetector(); self.trained=False
    def features(self,events):
        if not events:return {}
        return {**extract_flow_features(events[-1]),**extract_temporal_features(events),**communication_features(events)}
    def fit_anomaly(self, rows): self.anomaly.fit(rows); self.trained=True
    def analyze(self,event,window,behavior_deviation=0.0):
        row=self.features(window); anomaly=self.anomaly.score(row) if self.trained else 0.0
        results=detect(window)
        alert=fuse(event.event_id,event.timestamp,results,behavior_deviation,anomaly)
        return row,results,alert
