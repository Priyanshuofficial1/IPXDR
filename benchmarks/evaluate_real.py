"""Evaluate IPXDR's production pipeline on real public flow datasets."""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.ingestion.models import FlowEvent
from backend.processing.pipeline import Pipeline

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()

def to_event(row: pd.Series, i: int) -> FlowEvent:
    def num(k, default=0):
        try: return float(row.get(k, default) or default)
        except (TypeError, ValueError): return float(default)
    proto=str(row.get("proto","TCP")).upper()
    state=str(row.get("state",""))
    return FlowEvent(
        event_id=f"unsw-replay-{i}",
        timestamp=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=i),
        src_ip=str(row.get("srcip","0.0.0.0")),
        dst_ip=str(row.get("dstip","0.0.0.0")),
        src_port=max(0,min(65535,int(num("sport")))),
        dst_port=max(0,min(65535,int(num("dsport")))),
        protocol=proto,
        packets=max(0,int(num("spkts")+num("dpkts"))),
        bytes=max(0,int(num("sbytes")+num("dbytes"))),
        duration_ms=max(0,num("dur")*1000),
        tcp_flags=[state] if state else [],
        direction="unknown",
        source="unsw-nb15",
    )

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("csv",type=Path)
    ap.add_argument("--sample",type=int,default=20000)
    ap.add_argument("--seed",type=int,default=42)
    ap.add_argument("--output",type=Path,default=Path("benchmarks/results/real-unsw-nb15.json"))
    a=ap.parse_args()
    df=pd.read_csv(a.csv)
    if "label" not in df: raise ValueError("UNSW-NB15 CSV must contain label")
    df["binary_label"]=df["label"].astype(int)
    if a.sample < len(df):
        parts=[]
        for _,g in df.groupby("binary_label",sort=True):
            n=max(1,round(a.sample*len(g)/len(df)))
            parts.append(g.sample(n=min(n,len(g)),random_state=a.seed))
        df=pd.concat(parts).sample(frac=1,random_state=a.seed).reset_index(drop=True)
    pipe=Pipeline()
    y_true=[]; y_pred=[]; counts={}
    for i,(_,row) in enumerate(df.iterrows()):
        pipe.process(to_event(row,i))
        results=pipe.last_detector_results
        attack=any(r.threat_class.lower() not in {"normal","benign"} for r in results)
        y_true.append(int(row["binary_label"])); y_pred.append(int(attack))
        for r in results: counts[r.threat_class]=counts.get(r.threat_class,0)+1
    cm=confusion_matrix(y_true,y_pred,labels=[0,1]); tn,fp,fn,tp=[int(x) for x in cm.ravel()]
    result={
      "schema_version":"1.0","dataset":"UNSW-NB15","dataset_path":str(a.csv),
      "dataset_sha256":sha256(a.csv),
      "source_ground_truth":"UNSW-NB15 label column (0 normal, 1 attack)",
      "replay_note":"Replay timestamps are generated because the selected released CSV split has no packet timestamp field.",
      "sample_rows":len(df),"seed":a.seed,"confusion_matrix_labels":["normal","attack"],
      "confusion_matrix":cm.tolist(),"tn":tn,"fp":fp,"fn":fn,"tp":tp,
      "precision":float(precision_score(y_true,y_pred,zero_division=0)),
      "recall":float(recall_score(y_true,y_pred,zero_division=0)),
      "f1":float(f1_score(y_true,y_pred,zero_division=0)),
      "classification_report":classification_report(y_true,y_pred,output_dict=True,zero_division=0),
      "detector_result_counts":counts,
      "provenance":{
        "official_dataset":"https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "mirror_used_for_download":"https://github.com/Nir-J/ML-Projects/blob/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv"
      }
    }
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("sample_rows","tn","fp","fn","tp","precision","recall","f1")},indent=2))
if __name__=="__main__": main()
