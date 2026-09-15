from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta
from .normalizer import NormalizedFlow

class WindowStore:
    """Bounded in-memory time windows with deterministic TTL eviction."""
    def __init__(self, window_seconds: int = 60, max_events_per_key: int = 10_000):
        if window_seconds <= 0 or max_events_per_key <= 0:
            raise ValueError("window and capacity must be positive")
        self.window = timedelta(seconds=window_seconds)
        self.max_events_per_key = max_events_per_key
        self._events: dict[str, deque[NormalizedFlow]] = defaultdict(deque)

    def add(self, event: NormalizedFlow) -> None:
        bucket = self._events[event.src_ip]
        bucket.append(event)
        self._evict(event.timestamp)
        while len(bucket) > self.max_events_per_key:
            bucket.popleft()

    def get(self, src_ip: str) -> list[NormalizedFlow]:
        return list(self._events.get(src_ip, ()))

    def _evict(self, now: datetime) -> None:
        cutoff = now - self.window
        for bucket in list(self._events.values()):
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()

    @property
    def active_keys(self):
        return tuple(k for k,v in self._events.items() if v)
