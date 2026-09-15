from __future__ import annotations
from dataclasses import dataclass
from backend.ingestion.models import FlowEvent
from .normalizer import normalize, NormalizedFlow
from .windows import WindowStore
from backend.features.flow import extract_flow_features
from backend.features.temporal import extract_temporal_features
from backend.features.behavioral import BehavioralStore

@dataclass
class PipelineStats:
    received: int = 0
    accepted: int = 0
    failed: int = 0

class Pipeline:
    def __init__(self, window_seconds: int = 60):
        self.windows = WindowStore(window_seconds)
        self.stats = PipelineStats()
        self.behavior = BehavioralStore()

    def process(self, event: FlowEvent) -> NormalizedFlow:
        self.stats.received += 1
        try:
            normalized = normalize(event)
            self.windows.add(normalized)
            window = self.windows.get(normalized.src_ip)
            self.last_features = {**extract_flow_features(normalized), **extract_temporal_features(window)}
            self.last_behavior_deviation = self.behavior.score(normalized.src_ip, window)
            self.behavior.learn(normalized.src_ip, window, self.last_behavior_deviation)
        except Exception:
            self.stats.failed += 1
            raise
        self.stats.accepted += 1
        return normalized
