from __future__ import annotations
import json,sys
from datetime import datetime,timedelta,timezone

def main(path='replay/scenarios/sample.jsonl'):
    t=datetime.now(timezone.utc); rows=[]
    for i in range(100): rows.append({'event_id':f'normal-{i}','timestamp':(t+timedelta(milliseconds=100*i)).isoformat(),'src_ip':'10.0.0.10','dst_ip':'10.0.0.20','src_port':5000+i,'dst_port':443,'protocol':'TCP','packets':1,'bytes':800,'duration_ms':10,'tcp_flags':['A'],'direction':'outbound','source':'synthetic'})
    for i in range(100): rows.append({'event_id':f'scan-{i}','timestamp':(t+timedelta(milliseconds=10*i)).isoformat(),'src_ip':'10.0.0.50','dst_ip':f'10.0.1.{i%50+1}','src_port':1000+i,'dst_port':1000+i,'protocol':'TCP','packets':1,'bytes':60,'duration_ms':1,'tcp_flags':['S'],'direction':'outbound','source':'synthetic'})
    with open(path,'w') as f:
        for r in rows:f.write(json.dumps(r)+'\n')
if __name__=='__main__': main(sys.argv[1] if len(sys.argv)>1 else None)
