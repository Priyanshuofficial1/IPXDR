from __future__ import annotations
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier

class SupervisedDetector:
    """Multiclass Random Forest for labeled, known threat classes."""
    def __init__(self, random_state=42):
        self.model=RandomForestClassifier(n_estimators=150,random_state=random_state,n_jobs=-1,class_weight='balanced_subsample')
        self.feature_names=[]; self.fitted=False
    def fit(self, rows:list[dict[str,float]], labels:list[str]):
        if len(rows)!=len(labels) or len(rows)<10: raise ValueError('at least 10 labeled rows required')
        self.feature_names=sorted({k for r in rows for k in r}); X=[[r.get(k,0.0) for k in self.feature_names] for r in rows]
        self.model.fit(X,labels); self.fitted=True; return self
    def predict(self,row):
        if not self.fitted:return None,0.0
        X=[[row.get(k,0.0) for k in self.feature_names]]; probs=self.model.predict_proba(X)[0]; i=int(probs.argmax()); return str(self.model.classes_[i]),float(probs[i])
    def save(self,path):
        if not self.fitted: raise ValueError('model is not fitted')
        Path(path).parent.mkdir(parents=True,exist_ok=True); joblib.dump({'model':self.model,'feature_names':self.feature_names},path)
    def load(self,path):
        data=joblib.load(path); self.model=data['model']; self.feature_names=data['feature_names']; self.fitted=True; return self
