from __future__ import annotations
from dataclasses import dataclass
from backend.ingestion.models import FlowEvent
from .normalizer import normalize, NormalizedFlow
from .windows import WindowStore

@dataclass
class PipelineStats:
    received: int = 0
    accepted: int = 0
    failed: int = 0

class Pipeline:
    def __init__(self, window_seconds: int = 60):
        self.windows = WindowStore(window_seconds)
        self.stats = PipelineStats()

    def process(self, event: FlowEvent) -> NormalizedFlow:
        self.stats.received += 1
        try:
            normalized = normalize(event)
            self.windows.add(normalized)
        except Exception:
            self.stats.failed += 1
            raise
        self.stats.accepted += 1
        return normalized
