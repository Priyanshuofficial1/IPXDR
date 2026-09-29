"""Evaluate a documented CIC-IDS2017 labelled flow-feature sample via IPXDR.

The public sample omits source/destination IPs and raw protocol/port fields, so
this adapter reconstructs only the fields required by FlowEvent and records
that limitation explicitly. Results are labelled-flow replay, not PCAP replay.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def sha256(p):
 h=hashlib.sha256();
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()

def num(r,k,d=0):
 try:return float(r.get(k,d) or d)
 except:return float(d)

def port_from_prefix(r,prefix):
 candidates=[c for c in r.index if c.startswith(prefix)]
 for c in candidates:
  try:
   if float(r[c] or 0)>0:
    name=c[len(prefix):]
    common={'http':80,'https':443,'dns':53,'ssh':22,'ftpdata':20,'ftpcontrol':21,'smtp':25,'imap4':143,'pop3':110,'ntp':123}
    return common.get(name,0)
  except (TypeError,ValueError): pass
 return 0

def to_event(r,i):
 proto='TCP' if num(r,'SYN Flag Count')+num(r,'ACK Flag Count')+num(r,'FIN Flag Count')>0 else 'UDP'
 packets=max(0,int(num(r,'Total Fwd Packets')+num(r,'Total Backward Packets')))
 bytes_=max(0,int(num(r,'Total Length of Fwd Packets')+num(r,'Total Length of Bwd Packets')))
 flags=[]
 if num(r,'SYN Flag Count')>0: flags.append('S')
 if num(r,'ACK Flag Count')>0: flags.append('A')
 if num(r,'FIN Flag Count')>0: flags.append('F')
 return FlowEvent(event_id=f'cic-replay-{i}',timestamp=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=i),src_ip='192.0.2.1',dst_ip='198.51.100.1',src_port=port_from_prefix(r,'sport'),dst_port=port_from_prefix(r,'dport'),protocol=proto,packets=packets,bytes=bytes_,duration_ms=max(0,num(r,'Flow Duration')/1000),tcp_flags=flags,direction='unknown',source='cic-ids2017-sample')

def main():
 ap=argparse.ArgumentParser();ap.add_argument('csv',type=Path);ap.add_argument('--sample',type=int,default=5000);ap.add_argument('--seed',type=int,default=42);ap.add_argument('--output',type=Path,default=Path('benchmarks/results/real-cic-ids2017-sample.json'));a=ap.parse_args()
 df=pd.read_csv(a.csv); label=df['Label'].astype(str).str.strip(); df['binary_label']=(label.str.upper()!='BENIGN').astype(int)
 if a.sample<len(df):
  parts=[]
  for _,g in df.groupby('binary_label',sort=True):
   n=max(1,round(a.sample*len(g)/len(df)));parts.append(g.sample(n=min(n,len(g)),random_state=a.seed))
  df=pd.concat(parts).sample(frac=1,random_state=a.seed).reset_index(drop=True)
 p=Pipeline();y=[];pred=[];counts={}
 for i,(_,r) in enumerate(df.iterrows()):
  e=to_event(r,i);p.process(e);alert=p.alerts.items[-1] if p.alerts.items and p.alerts.items[-1].flow_id==e.event_id else None
  y.append(int(r.binary_label));pred.append(int(alert is not None))
  for dr in p.last_detector_results:counts[dr.threat_class]=counts.get(dr.threat_class,0)+1
 cm=confusion_matrix(y,pred,labels=[0,1]);tn,fp,fn,tp=[int(x) for x in cm.ravel()]
 out={'schema_version':'1.0','dataset':'CIC-IDS2017','artifact':str(a.csv),'artifact_sha256':sha256(a.csv),'source_sample':'https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/blob/main/data/CICIDS2017_sample.csv','source_official':'https://www.unb.ca/cic/datasets/ids-2017.html','sample_rows':len(df),'label_counts':{str(k):int(v) for k,v in label.value_counts().items()},'binary_mapping':'BENIGN=0; all other published labels=1','replay_note':'The sample is flow-feature CSV, not PCAP. It lacks source/destination IPs and raw protocol/port fields; the adapter uses fixed documentation IPs and derives only coarse protocol/port indicators. Metrics therefore characterize adapter/pipeline behavior, not native packet detection.','confusion_matrix':cm.tolist(),'tn':tn,'fp':fp,'fn':fn,'tp':tp,'precision':float(precision_score(y,pred,zero_division=0)),'recall':float(recall_score(y,pred,zero_division=0)),'f1':float(f1_score(y,pred,zero_division=0)),'classification_report':classification_report(y,pred,output_dict=True,zero_division=0),'detector_result_counts':counts}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(out,indent=2));print(json.dumps({k:out[k] for k in ['sample_rows','tn','fp','fn','tp','precision','recall','f1']},indent=2))
if __name__=='__main__':main()
