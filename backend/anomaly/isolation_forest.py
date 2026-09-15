from __future__ import annotations
import numpy as np
from pathlib import Path
import joblib
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """Unsupervised detector for behavior absent from the learned normal distribution."""
    def __init__(self, contamination=0.05, random_state=42):
        self.model=IsolationForest(n_estimators=100, contamination=contamination, random_state=random_state)
        self.feature_names=[]; self.fitted=False
    def fit(self, rows: list[dict[str,float]]):
        if not rows: raise ValueError('training rows required')
        self.feature_names=sorted(rows[0]); self.model.fit(np.asarray([[r.get(k,0.0) for k in self.feature_names] for r in rows],dtype=float)); self.fitted=True; return self
    def save(self, path):
        if not self.fitted: raise ValueError("model is not fitted")
        Path(path).parent.mkdir(parents=True, exist_ok=True); joblib.dump({"model":self.model,"feature_names":self.feature_names}, path)
    def load(self, path):
        data=joblib.load(path); self.model=data["model"]; self.feature_names=data["feature_names"]; self.fitted=True; return self
    def score(self, row: dict[str,float]) -> float:
        if not self.fitted: return 0.0
        x=np.asarray([[row.get(k,0.0) for k in self.feature_names]],dtype=float)
        raw=float(self.model.decision_function(x)[0])
        return float(1/(1+np.exp(8*raw)))
