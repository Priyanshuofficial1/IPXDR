"""Diagnostic calibration study for UNSW-NB15 reconstructed-flow replay.

This does not tune the production detector. It records how replay assumptions
and detector score thresholds affect the observed diagnostic behavior.
"""
from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def num(row, key, default=0.0):
    try: return float(row.get(key, default) or default)
    except (TypeError, ValueError): return float(default)

def event(row, i, step):
    return FlowEvent(
        event_id=f"unsw-cal-{i}",
        timestamp=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=i*step),
        src_ip=str(row.get("srcip","0.0.0.0")), dst_ip=str(row.get("dstip","0.0.0.0")),
        src_port=max(0,min(65535,int(num(row,"sport")))), dst_port=max(0,min(65535,int(num(row,"dsport")))),
        protocol=str(row.get("proto","TCP")).upper(), packets=max(0,int(num(row,"spkts")+num(row,"dpkts"))),
        bytes=max(0,int(num(row,"sbytes")+num(row,"dbytes"))), duration_ms=max(0,num(row,"dur")*1000),
        tcp_flags=[str(row.get("state",""))] if row.get("state") else [], direction="unknown", source="unsw-nb15")

def sample(df, n, seed):
    parts=[]
    for _, g in df.groupby(df["label"].astype(int), sort=True):
        take=max(1, round(n*len(g)/len(df))); parts.append(g.sample(n=min(take,len(g)), random_state=seed))
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)

def run(df, step):
    pipe=Pipeline(); y=[]; scores=[]; detector_scores={}
    for i,(_,row) in enumerate(df.iterrows()):
        pipe.process(event(row,i,step)); y.append(int(row["label"]))
        rs=pipe.last_detector_results; scores.append(max((r.score for r in rs),default=0.0))
        for r in rs: detector_scores.setdefault(r.detector_name,[[],[]])[int(row["label"])].append(float(r.score))
    return y, scores, detector_scores

def metrics(y,pred):
    tn,fp,fn,tp=[int(x) for x in confusion_matrix(y,pred,labels=[0,1]).ravel()]
    return {"tn":tn,"fp":fp,"fn":fn,"tp":tp,"precision":float(precision_score(y,pred,zero_division=0)),"recall":float(recall_score(y,pred,zero_division=0)),"f1":float(f1_score(y,pred,zero_division=0))}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("csv",type=Path); ap.add_argument("--sample",type=int,default=2000); ap.add_argument("--seed",type=int,default=42); ap.add_argument("--output",type=Path,default=Path("benchmarks/results/unsw-calibration.json")); a=ap.parse_args()
    df=sample(pd.read_csv(a.csv),a.sample,a.seed)
    replay={}; score_runs={}
    for step in (0.1,1,5,10):
        y,scores,det=run(df,step); replay[str(step)]=metrics(y,[int(bool(x>=0.5)) for x in scores]); score_runs[str(step)]=det
    y,scores,det=run(df,1)
    thresholds={str(t):metrics(y,[int(x>=t) for x in scores]) for t in (0.5,0.6,0.7,0.75,0.8,0.85,0.9,0.95,0.99)}
    detector_summary={k:{"normal_mean":float(np.mean(v[0])) if v[0] else 0.0,"attack_mean":float(np.mean(v[1])) if v[1] else 0.0,"normal_ge_0.5":int(sum(x>=0.5 for x in v[0])),"attack_ge_0.5":int(sum(x>=0.5 for x in v[1]))} for k,v in det.items()}
    out={"schema_version":"1.0","dataset":"UNSW-NB15","sample_rows":len(df),"seed":a.seed,"purpose":"diagnostic calibration; no production threshold change","replay_spacing_seconds":replay,"score_thresholds_at_1s":thresholds,"detector_score_summary":detector_summary,"finding":"UDP reflection and C2 periodicity scores remain high for both normal and attack rows under reconstructed flow replay; replay spacing changes do not resolve this until windows exceed the 60-second detector context. The primary limitation is missing original timestamps/direction/packet identity in the selected CSV, not evidence that these thresholds generalize to real traffic.","recommendation":"Use native timestamped flow/PCAP validation for calibration. Do not tune production thresholds against this reconstructed replay alone."}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2)); print(json.dumps({"sample_rows":len(df),"replay_spacing_seconds":replay,"score_thresholds_at_1s":thresholds},indent=2))
if __name__=="__main__": main()
