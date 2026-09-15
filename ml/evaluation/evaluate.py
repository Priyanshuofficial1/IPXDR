from __future__ import annotations
from sklearn.metrics import classification_report, confusion_matrix

def evaluate(model, rows, labels):
    preds=[model.predict(r)[0] for r in rows]
    return {'classification_report':classification_report(labels,preds,zero_division=0,output_dict=True),'confusion_matrix':confusion_matrix(labels,preds).tolist()}
