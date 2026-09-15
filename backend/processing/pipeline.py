from __future__ import annotations
from dataclasses import dataclass
from backend.ingestion.models import FlowEvent
from .normalizer import normalize, NormalizedFlow
from .windows import WindowStore
from backend.features.flow import extract_flow_features
from backend.features.temporal import extract_temporal_features
from backend.features.dns import extract_dns_features
from backend.features.tls import extract_tls_features
from backend.features.quic import extract_quic_features
from backend.features.behavioral import BehavioralStore
from backend.detection.engine import DetectionEngine
from backend.alerts.store import AlertStore
@dataclass
class PipelineStats:
    received:int=0; accepted:int=0; failed:int=0
class Pipeline:
    def __init__(self,window_seconds:int=60):
        self.windows=WindowStore(window_seconds); self.stats=PipelineStats(); self.behavior=BehavioralStore(); self.engine=DetectionEngine(); self.alerts=AlertStore(); self.last_features={}; self.last_behavior_deviation=0.0
    def process(self,event:FlowEvent)->NormalizedFlow:
        self.stats.received+=1
        try:
            n=normalize(event); self.windows.add(n); w=self.windows.get(n.src_ip)
            # Bound per-event feature work while retaining the full 60s event window for storage.
            feature_window=w[-256:]
            self.last_features={**extract_flow_features(n),**extract_temporal_features(feature_window),**extract_dns_features(feature_window),**extract_tls_features(feature_window),**extract_quic_features(feature_window)}
            self.last_behavior_deviation=self.behavior.score(n.src_ip,feature_window)
            _,_,alert=self.engine.analyze(n,feature_window,self.last_behavior_deviation)
            if alert: self.alerts.add(alert)
            self.behavior.learn(n.src_ip,[n],self.last_behavior_deviation)
        except Exception:
            self.stats.failed+=1; raise
        self.stats.accepted+=1; return n
