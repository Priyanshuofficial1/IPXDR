from __future__ import annotations
from collections import deque
from datetime import datetime
import json, sqlite3
from backend.ingestion.models import Alert

class AlertStore:
    def __init__(self, max_items: int = 5000, db_path: str | None = None):
        self.items = deque(maxlen=max_items)
        self.db_path = db_path
        self._db = None
        if db_path:
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.execute('''CREATE TABLE IF NOT EXISTS alerts (alert_id TEXT PRIMARY KEY,timestamp TEXT,flow_id TEXT,threat_class TEXT,confidence REAL,severity TEXT,evidence TEXT,model_scores TEXT,behavior_deviation REAL)''')
            self._db.commit()
            for row in self._db.execute('SELECT alert_id,timestamp,flow_id,threat_class,confidence,severity,evidence,model_scores,behavior_deviation FROM alerts ORDER BY rowid DESC LIMIT ?', (max_items,)).fetchall()[::-1]:
                self.items.append(Alert(alert_id=row[0],timestamp=datetime.fromisoformat(row[1]),flow_id=row[2],threat_class=row[3],confidence=row[4],severity=row[5],supporting_evidence=json.loads(row[6]),model_scores=json.loads(row[7]),behavior_deviation=row[8]))
    def add(self, alert: Alert) -> None:
        if any(x.alert_id == alert.alert_id for x in self.items): return
        self.items.append(alert)
        if self._db:
            self._db.execute('INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?)',(alert.alert_id,alert.timestamp.isoformat(),alert.flow_id,alert.threat_class,alert.confidence,alert.severity,json.dumps(alert.supporting_evidence),json.dumps(alert.model_scores),alert.behavior_deviation))
            self._db.commit()
    def list(self, limit: int = 100) -> list[Alert]:
        return list(self.items)[-limit:][::-1]
    def clear(self) -> None:
        """Clear alerts for a new user analysis session."""
        self.items.clear()
        if self._db:
            self._db.execute("DELETE FROM alerts")
            self._db.commit()
    def close(self):
        if self._db: self._db.close()
