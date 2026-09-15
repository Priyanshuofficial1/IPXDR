from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from backend.processing.pipeline import Pipeline
from backend.ingestion.models import FlowEvent
app=FastAPI(title='IPXDR API',version='0.3.0')
pipeline=Pipeline()
@app.get('/health')
def health(): return {'status':'ok','service':'ipxdr','passive':True,'detection_engine':'ready'}
@app.get('/metrics')
def metrics():
 s=pipeline.stats; return {'received':s.received,'accepted':s.accepted,'failed':s.failed,'alerts':len(pipeline.alerts.items),'anomaly_model':pipeline.engine.anomaly.fitted,'supervised_model':pipeline.engine.supervised.fitted}
@app.get('/alerts')
def alerts(limit:int=100): return [a.model_dump(mode='json') for a in pipeline.alerts.list(min(max(limit,1),500))]
@app.post('/ingest')
def ingest(event:FlowEvent):
 pipeline.process(event); return {'accepted':True,'flow_id':event.event_id,'behavior_deviation':pipeline.last_behavior_deviation,'features':pipeline.last_features}
@app.post('/anomaly/fit')
def anomaly_fit(rows:list[dict[str,float]]):
 if len(rows)<10: raise HTTPException(400,'at least 10 baseline rows required')
 pipeline.engine.fit_anomaly(rows); return {'trained':True,'rows':len(rows),'features':pipeline.engine.anomaly.feature_names}
@app.post('/supervised/fit')
def supervised_fit(payload:dict):
 rows=payload.get('rows',[]); labels=payload.get('labels',[])
 if len(rows)<10 or len(rows)!=len(labels): raise HTTPException(400,'at least 10 labeled rows and matching labels required')
 pipeline.engine.fit_supervised(rows,labels); return {'trained':True,'rows':len(rows),'classes':list(pipeline.engine.supervised.model.classes_),'features':pipeline.engine.supervised.feature_names}
@app.get('/dashboard')
def dashboard(): return FileResponse(Path(__file__).resolve().parents[2] / 'frontend' / 'dashboard' / 'index.html')
