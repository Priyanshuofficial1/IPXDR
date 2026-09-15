from __future__ import annotations
from math import sqrt
from statistics import mean, median
from backend.processing.normalizer import NormalizedFlow


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    if m <= 0:
        return 0.0
    sd = sqrt(mean([(x - m) ** 2 for x in values]))
    return sd / m


def extract_temporal_features(events: list[NormalizedFlow]) -> dict[str, float]:
    """Extract deterministic bounded-window temporal/communication features."""
    if not events:
        return {"event_count": 0.0, "window_span_s": 0.0, "interarrival_mean_s": 0.0,
                "interarrival_std_s": 0.0, "interarrival_median_s": 0.0,
                "interarrival_mad_s": 0.0, "interarrival_cv": 0.0,
                "burstiness": 0.0, "unique_destinations": 0.0, "unique_ports": 0.0,
                "flow_rate": 0.0, "byte_rate": 0.0}
    ordered = sorted(events, key=lambda e: e.timestamp)
    span = max((ordered[-1].timestamp - ordered[0].timestamp).total_seconds(), 0.0)
    iat = [max((b.timestamp - a.timestamp).total_seconds(), 0.0) for a, b in zip(ordered, ordered[1:])]
    m = mean(iat) if iat else 0.0
    sd = sqrt(mean([(x - m) ** 2 for x in iat])) if len(iat) > 1 else 0.0
    med = median(iat) if iat else 0.0
    mad = median([abs(x - med) for x in iat]) if iat else 0.0
    # burstiness: -1..1 approximation based on dispersion relative to mean.
    burstiness = (sd - m) / (sd + m) if (sd + m) > 0 else 0.0
    elapsed = max(span, 1.0)
    return {
        "event_count": float(len(ordered)),
        "window_span_s": span,
        "interarrival_mean_s": m,
        "interarrival_std_s": sd,
        "interarrival_median_s": med,
        "interarrival_mad_s": mad,
        "interarrival_cv": _cv(iat),
        "burstiness": burstiness,
        "unique_destinations": float(len({e.dst_ip for e in ordered})),
        "unique_ports": float(len({e.dst_port for e in ordered})),
        "flow_rate": len(ordered) / elapsed,
        "byte_rate": sum(e.bytes for e in ordered) / elapsed,
    }
