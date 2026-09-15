from __future__ import annotations
import asyncio
import os
import secrets
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header
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
            'hosts': len(pipeline.behavior.hosts), 'windows': len(pipeline.windows.active_keys)}

@app.get('/alerts')
def alerts(limit: int = 100):
    return [a.model_dump(mode='json') for a in pipeline.alerts.list(min(max(limit, 1), 500))]

@app.get('/hosts')
def hosts():
    return [{'src_ip': ip, 'observations': b.observations, 'baseline_ready': pipeline.behavior.ready(ip)}
            for ip, b in pipeline.behavior.hosts.items()]

@app.get('/hosts/{src_ip}')
def host_detail(src_ip: str):
    b = pipeline.behavior.hosts.get(src_ip)
    if not b: raise HTTPException(404, 'host not found')
    events = pipeline.windows.get(src_ip)
    return {'src_ip': src_ip, 'observations': b.observations, 'baseline_ready': pipeline.behavior.ready(src_ip),
            'window_events': len(events), 'recent_destinations': sorted({e.dst_ip for e in events})[:25],
            'recent_ports': sorted({e.dst_port for e in events})[:50],
            'recent_bytes': sum(e.bytes for e in events), 'recent_packets': sum(e.packets for e in events)}

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

def _admin_guard(x_ipxdr_admin_token: str | None):
    configured = os.getenv('IPXDR_ADMIN_TOKEN')
    if configured and not x_ipxdr_admin_token:
        raise HTTPException(401, 'admin token required')
    if configured and not secrets.compare_digest(x_ipxdr_admin_token or '', configured):
        raise HTTPException(403, 'invalid admin token')

@app.post('/anomaly/fit')
def anomaly_fit(rows: list[dict[str, float]], x_ipxdr_admin_token: str | None = Header(default=None)):
    _admin_guard(x_ipxdr_admin_token)
    if len(rows) < 10: raise HTTPException(400, 'at least 10 baseline rows required')
    pipeline.engine.fit_anomaly(rows)
    return {'trained': True, 'rows': len(rows), 'features': pipeline.engine.anomaly.feature_names}

@app.post('/supervised/fit')
def supervised_fit(payload: dict, x_ipxdr_admin_token: str | None = Header(default=None)):
    _admin_guard(x_ipxdr_admin_token)
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
