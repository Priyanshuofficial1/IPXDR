from datetime import datetime,timezone,timedelta
from backend.ingestion.models import FlowEvent
from backend.processing.flow_aggregator import FlowAggregator

def ev(t, i, b=100):
 return FlowEvent(event_id=str(i),timestamp=t,src_ip='1.1.1.1',dst_ip='2.2.2.2',src_port=1234,dst_port=443,protocol='TCP',packets=1,bytes=b,duration_ms=0,tcp_flags=['S'],direction='unknown')

def test_aggregates_and_flushes():
 t=datetime.now(timezone.utc); a=FlowAggregator(idle_timeout_s=5)
 assert a.add(ev(t,1))==[]
 assert a.add(ev(t+timedelta(seconds=2),2,200))==[]
 out=a.flush(); assert len(out)==1 and out[0].packets==2 and out[0].bytes==300

def test_idle_timeout_emits_old_flow():
 t=datetime.now(timezone.utc); a=FlowAggregator(idle_timeout_s=5)
 a.add(ev(t,1)); out=a.add(ev(t+timedelta(seconds=6),2)); assert len(out)==1
