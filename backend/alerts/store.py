from __future__ import annotations
from collections import deque
from backend.ingestion.models import Alert

class AlertStore:
    def __init__(self, max_items: int = 5000):
        self.items = deque(maxlen=max_items)
    def add(self, alert: Alert) -> None:
        # Deduplicate identical flow/threat alerts.
        if self.items and self.items[-1].alert_id == alert.alert_id:
            return
        self.items.append(alert)
    def list(self, limit: int = 100) -> list[Alert]:
        return list(self.items)[-limit:][::-1]
