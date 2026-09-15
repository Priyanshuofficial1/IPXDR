from __future__ import annotations
import asyncio
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from backend.processing.pipeline import Pipeline
from backend.ingestion.models import FlowEvent

app = FastAPI(title='IPXDR API', version='0.4.0', description='Passive AI threat detection for unidirectional IP traffic')
pipeline = Pipeline()
_subscribers: set[WebSocket] = set()

@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'ipxdr', 'passive': True, 'detection_engine': 'ready'}

@app.get('/metrics')
def metrics():
    s = pipeline.stats
    return {'received': s.received, 'accepted': s.accepted, 'failed': s.failed,
            'alerts': len(pipeline.alerts.items), 'anomaly_model': pipeline.engine.anomaly.fitted,
            'supervised_model': pipeline.engine.supervised.fitted,
            'hosts': len(pipeline.behavior.hosts), 'windows': sum(len(v) > 0 for v in pipeline.windows._events.values())}

@app.get('/alerts')
def alerts(limit: int = 100):
    return [a.model_dump(mode='json') for a in pipeline.alerts.list(min(max(limit, 1), 500))]

@app.get('/hosts')
def hosts():
    return [{'src_ip': ip, 'observations': b.observations, 'baseline_ready': pipeline.behavior.ready(ip)}
            for ip, b in pipeline.behavior.hosts.items()]

async def _broadcast(payload: dict):
    dead = []
    for ws in list(_subscribers):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _subscribers.discard(ws)

@app.post('/ingest')
async def ingest(event: FlowEvent):
    pipeline.process(event)
    result = {'accepted': True, 'flow_id': event.event_id,
              'behavior_deviation': pipeline.last_behavior_deviation,
              'features': pipeline.last_features}
    if pipeline.alerts.items:
        latest = pipeline.alerts.items[-1]
        if latest.flow_id == event.event_id:
            result['alert'] = latest.model_dump(mode='json')
            await _broadcast({'type': 'alert', 'alert': result['alert']})
    await _broadcast({'type': 'metrics', 'metrics': metrics()})
    return result

@app.post('/anomaly/fit')
def anomaly_fit(rows: list[dict[str, float]]):
    if len(rows) < 10: raise HTTPException(400, 'at least 10 baseline rows required')
    pipeline.engine.fit_anomaly(rows)
    return {'trained': True, 'rows': len(rows), 'features': pipeline.engine.anomaly.feature_names}

@app.post('/supervised/fit')
def supervised_fit(payload: dict):
    rows, labels = payload.get('rows', []), payload.get('labels', [])
    if len(rows) < 10 or len(rows) != len(labels): raise HTTPException(400, 'at least 10 labeled rows and matching labels required')
    pipeline.engine.fit_supervised(rows, labels)
    return {'trained': True, 'rows': len(rows), 'classes': list(pipeline.engine.supervised.model.classes_),
            'features': pipeline.engine.supervised.feature_names}

@app.websocket('/ws/alerts')
async def alerts_ws(ws: WebSocket):
    await ws.accept(); _subscribers.add(ws)
    try:
        await ws.send_json({'type': 'metrics', 'metrics': metrics()})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _subscribers.discard(ws)
    except Exception:
        _subscribers.discard(ws)

@app.get('/dashboard')
def dashboard():
    return FileResponse(Path(__file__).resolve().parents[2] / 'frontend' / 'dashboard' / 'index.html')
