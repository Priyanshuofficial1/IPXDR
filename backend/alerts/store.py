from __future__ import annotations
from collections import deque
from backend.ingestion.models import Alert
class AlertStore:
    def __init__(self,max_alerts=5000): self.items=deque(maxlen=max_alerts)
    def add(self,a): self.items.appendleft(a)
    def list(self,limit=100): return list(self.items)[:limit]
    def clear(self): self.items.clear()
