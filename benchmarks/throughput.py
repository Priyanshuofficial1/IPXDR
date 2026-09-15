from __future__ import annotations
import time
import sys
from pathlib import Path
import sys
from pathlib import Path
import sys
from pathlib import Path
import sys
from pathlib import Path
from datetime import datetime,timezone
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def run(count=10000):
 p=Pipeline(); start=time.perf_counter(); ts=datetime.now(timezone.utc)
 for i in range(count):
  p.process(FlowEvent(event_id=str(i),timestamp=ts,src_ip='10.0.0.1',dst_ip=f'10.0.0.{i%20+2}',src_port=4000+i%1000,dst_port=443,protocol='TCP',packets=1,bytes=500,duration_ms=1,tcp_flags=['A'],direction='outbound'))
 elapsed=time.perf_counter()-start
 return {'events':count,'seconds':elapsed,'events_per_second':count/elapsed}
if __name__=='__main__': print(run())
