from __future__ import annotations
import json
from pathlib import Path

def load_labeled_jsonl(path):
    rows=[]; labels=[]
    for line in Path(path).read_text().splitlines():
        if not line.strip():continue
        obj=json.loads(line); labels.append(obj.pop('label')); rows.append({k:float(v) for k,v in obj.items()})
    return rows,labels
