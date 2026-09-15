from __future__ import annotations
from dataclasses import dataclass, field
from math import sqrt
from statistics import mean
from backend.processing.normalizer import NormalizedFlow
from .flow import extract_flow_features
from .temporal import extract_temporal_features


@dataclass
class RunningStat:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def std(self) -> float:
        return sqrt(self.m2 / (self.count - 1)) if self.count > 1 else 0.0


@dataclass
class HostBaseline:
    observations: int = 0
    features: dict[str, RunningStat] = field(default_factory=dict)
    protocols: dict[str, int] = field(default_factory=dict)

    def update(self, events: list[NormalizedFlow]) -> None:
        for event in events:
            values = {**extract_flow_features(event)}
            for key, value in values.items():
                self.features.setdefault(key, RunningStat()).update(value)
            self.protocols[event.protocol] = self.protocols.get(event.protocol, 0) + 1
            self.observations += 1

    def deviation(self, events: list[NormalizedFlow]) -> float:
        if not events or self.observations < 2:
            return 0.0
        values: dict[str, float] = {}
        values.update(extract_temporal_features(events))
        # Compare aggregate rates/counts against flow-level baseline where dimensions overlap.
        values["packets"] = mean(e.packets for e in events)
        values["bytes"] = mean(e.bytes for e in events)
        values["dst_port"] = mean(e.dst_port for e in events)
        zscores = []
        for key, value in values.items():
            stat = self.features.get(key)
            if stat and stat.count > 1 and stat.std > 1e-9:
                zscores.append(abs(value - stat.mean) / stat.std)
        if not zscores:
            return 0.0
        # Smooth z-score into [0,1], preserving sensitivity without unbounded risk scores.
        z = sum(zscores) / len(zscores)
        return z / (1.0 + z)


class BehavioralStore:
    """Per-source behavioral digital twins with bounded baseline state."""
    def __init__(self, warmup_events: int = 20):
        if warmup_events < 1:
            raise ValueError("warmup_events must be positive")
        self.warmup_events = warmup_events
        self.hosts: dict[str, HostBaseline] = {}

    def score(self, src_ip: str, events: list[NormalizedFlow]) -> float:
        baseline = self.hosts.setdefault(src_ip, HostBaseline())
        return baseline.deviation(events)

    def learn(self, src_ip: str, events: list[NormalizedFlow], risk_score: float = 0.0) -> None:
        baseline = self.hosts.setdefault(src_ip, HostBaseline())
        # Do not let strongly suspicious windows immediately poison the baseline.
        if risk_score >= 0.8:
            return
        baseline.update(events)

    def ready(self, src_ip: str) -> bool:
        return self.hosts.get(src_ip, HostBaseline()).observations >= self.warmup_events
