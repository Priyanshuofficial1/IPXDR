"""Reproducible labelled-dataset evaluation for IPXDR supervised detection."""
from __future__ import annotations
import argparse,json,sys,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
from sklearn.metrics import (accuracy_score,average_precision_score,classification_report,
    confusion_matrix,f1_score,precision_score,recall_score,roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize
from ml.models.supervised import SupervisedDetector

def sha256(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def load_jsonl(path):
    rows=[]; labels=[]
    for n,line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(),1):
        if not line.strip(): continue
        obj=json.loads(line); label=obj.pop("label",None)
        if not isinstance(label,str) or not label: raise ValueError(f"line {n}: missing label")
        rows.append({k:float(v) for k,v in obj.items()}); labels.append(label)
    if len(rows)<20: raise ValueError("at least 20 labelled rows required")
    return rows,labels

def ece(conf,correct,bins=10):
    edges=np.linspace(0,1,bins+1); value=0.0
    for i in range(bins):
        mask=(conf>=edges[i]) & ((conf<edges[i+1]) if i<bins-1 else (conf<=edges[i+1]))
        if mask.any(): value+=float(mask.mean())*abs(float(correct[mask].mean())-float(conf[mask].mean()))
    return value

def main():
    p=argparse.ArgumentParser()
    p.add_argument("dataset",type=Path); p.add_argument("--test-size",type=float,default=.2)
    p.add_argument("--validation-size",type=float,default=.2); p.add_argument("--seed",type=int,default=42)
    p.add_argument("--json",action="store_true"); p.add_argument("--output",type=Path)
    a=p.parse_args(); rows,labels=load_jsonl(a.dataset)
    trainval_rows,test_rows,trainval_labels,test_labels=train_test_split(rows,labels,test_size=a.test_size,random_state=a.seed,stratify=labels)
    val_rel=a.validation_size/(1-a.test_size)
    train_rows,val_rows,train_labels,val_labels=train_test_split(trainval_rows,trainval_labels,test_size=val_rel,random_state=a.seed,stratify=trainval_labels)
    model=SupervisedDetector(random_state=a.seed).fit(train_rows,train_labels)
    classes=[str(c) for c in model.model.classes_]; names=model.feature_names
    def predict(rs,ys):
        X=np.asarray([[r.get(k,0.0) for k in names] for r in rs]); y=np.asarray(ys)
        pred=model.model.predict(X); probs=model.model.predict_proba(X)
        ybin=label_binarize(y,classes=classes)
        pr=average_precision_score(ybin,probs,average="macro")
        try: roc=roc_auc_score(ybin,probs,average="macro",multi_class="ovr")
        except ValueError: roc=None
        cm=confusion_matrix(y,pred,labels=classes); fprs=[]
        for i in range(len(classes)):
            fp=cm[:,i].sum()-cm[i,i]; tn=cm.sum()-cm[i,:].sum()-cm[:,i].sum()+cm[i,i]
            fprs.append(float(fp)/max(1,float(fp+tn)))
        conf=probs.max(axis=1); correct=(pred==y).astype(float)
        brier=float(np.mean(np.sum((probs-ybin)**2,axis=1)))
        return {"accuracy":float(accuracy_score(y,pred)),"precision_macro":float(precision_score(y,pred,average="macro",zero_division=0)),
                "recall_macro":float(recall_score(y,pred,average="macro",zero_division=0)),
                "f1_macro":float(f1_score(y,pred,average="macro",zero_division=0)),"pr_auc_macro":float(pr),
                "roc_auc_macro":None if roc is None else float(roc),"false_positive_rate_macro":float(np.mean(fprs)),
                "expected_calibration_error":float(ece(conf,correct)),"brier_multiclass":brier,
                "confusion_matrix":cm.tolist(),"classification_report":classification_report(y,pred,output_dict=True,zero_division=0)}
    result={"schema_version":"1.1","dataset":str(a.dataset),"dataset_sha256":sha256(a.dataset),
            "seed":a.seed,"rows":len(rows),"classes":classes,
            "split":{"train":len(train_rows),"validation":len(val_rows),"test":len(test_rows),
                     "strategy":"stratified deterministic holdout"},"metrics":{"validation":predict(val_rows,val_labels),
                     "test":predict(test_rows,test_labels)},"features":names}
    manifest=a.dataset.with_suffix(".evaluation.json") if a.output is None else a.output
    manifest.parent.mkdir(parents=True,exist_ok=True); manifest.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2) if a.json else
          f"train={len(train_rows)} validation={len(val_rows)} test={len(test_rows)} "
          f"test_f1={result['metrics']['test']['f1_macro']:.4f} "
          f"test_pr_auc={result['metrics']['test']['pr_auc_macro']:.4f} "
          f"test_fpr={result['metrics']['test']['false_positive_rate_macro']:.4f} "
          f"ece={result['metrics']['test']['expected_calibration_error']:.4f} brier={result['metrics']['test']['brier_multiclass']:.4f}")
if __name__=="__main__": main()
