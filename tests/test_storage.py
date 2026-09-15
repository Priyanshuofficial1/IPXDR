from datetime import datetime, timezone
from backend.alerts.store import AlertStore
from backend.ingestion.models import Alert

def alert(i='a1'):
    return Alert(alert_id=i,timestamp=datetime.now(timezone.utc),flow_id='f1',threat_class='recon_port_scan',confidence=.8,severity='HIGH',supporting_evidence=['unique_ports=20'],model_scores={'rules':.8},behavior_deviation=.4)

def test_alert_store_persists_and_deduplicates(tmp_path):
    db=tmp_path/'alerts.db'; s=AlertStore(db_path=str(db)); a=alert(); s.add(a); s.add(a); assert len(s.items)==1; s.close()
    s2=AlertStore(db_path=str(db)); assert len(s2.items)==1 and s2.items[0].alert_id=='a1'; s2.close()
