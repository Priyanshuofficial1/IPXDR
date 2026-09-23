"""Evaluate a labelled JSONL feature dataset with a strict held-out test split."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize
from ml.models.supervised import SupervisedDetector

def load_jsonl(path: Path):
    rows, labels = [], []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip(): continue
        obj = json.loads(line)
        label = obj.pop("label", None)
        if not isinstance(label, str) or not label:
            raise ValueError(f"line {lineno}: missing string 'label'")
        try: row = {k: float(v) for k, v in obj.items()}
        except (TypeError, ValueError) as exc: raise ValueError(f"line {lineno}: features must be numeric") from exc
        rows.append(row); labels.append(label)
    if len(rows) < 10: raise ValueError("at least 10 labelled rows are required")
    return rows, labels

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    rows, labels = load_jsonl(a.dataset)
    train_rows, test_rows, train_labels, test_labels = train_test_split(rows, labels, test_size=a.test_size, random_state=a.seed, stratify=labels)
    model = SupervisedDetector(random_state=a.seed).fit(train_rows, train_labels)
    classes = [str(c) for c in model.model.classes_]
    names = model.feature_names
    X = np.asarray([[r.get(k, 0.0) for k in names] for r in test_rows])
    y = np.asarray(test_labels)
    pred = model.model.predict(X)
    probs = model.model.predict_proba(X)
    ybin = label_binarize(y, classes=classes)
    score = probs[:, 1] if len(classes) == 2 else probs
    cm = confusion_matrix(y, pred, labels=classes)
    fprs = []
    for i in range(len(classes)):
        fp = float(cm[:, i].sum() - cm[i, i])
        tn = float(cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i])
        fprs.append(fp / max(1.0, fp + tn))
    conf = probs.max(axis=1)
    correct = (pred == y).astype(float)
    ece = 0.0
    bins = np.linspace(0.0, 1.0, 11)
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (conf >= lo) & ((conf < hi) if hi < 1.0 else (conf <= hi))
        if mask.any(): ece += float(mask.mean()) * abs(float(correct[mask].mean()) - float(conf[mask].mean()))
    result = {
        "dataset": str(a.dataset), "rows": len(rows), "train_rows": len(train_rows), "test_rows": len(test_rows),
        "classes": classes, "features": names,
        "metrics": {
            "accuracy": float(accuracy_score(y, pred)),
            "precision_macro": float(precision_score(y, pred, average="macro", zero_division=0)),
            "recall_macro": float(recall_score(y, pred, average="macro", zero_division=0)),
            "f1_macro": float(f1_score(y, pred, average="macro", zero_division=0)),
            "pr_auc_macro": float(average_precision_score(ybin, score, average="macro")),
            "false_positive_rate_macro": float(np.mean(fprs)),
            "expected_calibration_error": float(ece),
        },
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(y, pred, output_dict=True, zero_division=0),
    }
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        m = result["metrics"]
        print(f'{len(rows):,} rows | train {len(train_rows):,} | test {len(test_rows):,}')
        print("accuracy={accuracy:.4f} precision={precision_macro:.4f} recall={recall_macro:.4f} f1={f1_macro:.4f} pr_auc={pr_auc_macro:.4f} fpr={false_positive_rate_macro:.4f} ece={expected_calibration_error:.4f}".format(**m))
        print("classes:", ", ".join(classes))

if __name__ == "__main__":
    main()
