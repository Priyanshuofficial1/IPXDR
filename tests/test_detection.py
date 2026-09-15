from datetime import datetime,timezone,timedelta
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def ev(i,src='10.0.0.1',syn=False):
 return FlowEvent(event_id=str(i),timestamp=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(milliseconds=i),src_ip=src,dst_ip=f'10.0.0.{i%10+2}',src_port=1000+i,dst_port=100+i,protocol='TCP',packets=1,bytes=60,duration_ms=1,tcp_flags=['S'] if syn else ['A'],direction='outbound')
def test_pipeline_generates_detection_alert():
 p=Pipeline()
 for i in range(30): p.process(ev(i,syn=True))
 assert p.stats.accepted==30
 assert len(p.alerts.items)>0
 assert 0<=p.alerts.items[0].confidence<=1

def test_anomaly_model():
 p=Pipeline(); rows=[{'bytes':float(i+1),'packets':1.0,'dst_port':443.0} for i in range(20)]
 p.engine.fit_anomaly(rows)
 assert p.engine.trained
 assert 0<=p.engine.anomaly.score({'bytes':1000,'packets':20,'dst_port':1})<=1
