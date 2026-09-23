from __future__ import annotations
import asyncio
import os
import secrets
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, UploadFile, File
from fastapi.responses import FileResponse, Response
import json
from backend.processing.pipeline import Pipeline
from backend.ingestion.models import FlowEvent
from backend.ingestion.pcap import PCAPIngestor

app = FastAPI(title='IPXDR API', version='0.4.0', description='Passive AI threat detection for unidirectional IP traffic')
pipeline = Pipeline(db_path=os.getenv('IPXDR_DB_PATH', 'ipxdr.db'))
pipeline.engine.load_models(os.getenv('IPXDR_MODEL_DIR', 'models'))
_subscribers: set[WebSocket] = set()
latest_analysis: dict = {'loaded': False, 'filename': None, 'traffic': [], 'topology': [], 'packets': 0, 'flows': 0}

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


@app.get('/status')
def status():
    return {'service':'ipxdr','version':app.version,'passive':True,'storage':bool(pipeline.alerts.db_path),'detectors':['rules-v2','isolation-forest','random-forest'],'metadata_only_encryption':True}

@app.get('/alerts/export')
def export_alerts():
    payload = json.dumps([a.model_dump(mode='json') for a in pipeline.alerts.list(5000)], indent=2)
    return Response(content=payload, media_type='application/json', headers={'Content-Disposition':'attachment; filename=ipxdr-alerts.json'})

@app.get('/analysis/latest')
def analysis_latest():
    return latest_analysis

@app.get('/alerts')
def alerts(limit: int = 100):
    return [a.model_dump(mode='json') for a in pipeline.alerts.list(min(max(limit, 1), 500))]

@app.get('/hosts')
def hosts():
    return [{'src_ip': ip, 'observations': b.observations, 'baseline_ready': pipeline.behavior.ready(ip),
             'window_events': len(pipeline.windows.get(ip))}
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

@app.post('/upload/pcap')
async def upload_pcap(file: UploadFile = File(...)):
    """Analyze a user-supplied PCAP locally, read-only, and replace the dashboard session with its findings."""
    name = (file.filename or '').lower()
    if not name.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(400, 'upload a PCAP/PCAPNG file')
    max_bytes = int(os.getenv('IPXDR_MAX_UPLOAD_MB', '200')) * 1024 * 1024
    fd, temp_path = tempfile.mkstemp(prefix='ipxdr-', suffix='.pcap')
    os.close(fd)
    size = 0
    try:
        with open(temp_path, 'wb') as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(413, f'PCAP exceeds {max_bytes // (1024*1024)} MB limit')
                out.write(chunk)
        pipeline.reset_session()
        packet_count = 0
        events = []
        for event in PCAPIngestor(temp_path).events():
            pipeline.process(event)
            events.append(event)
            packet_count += 1
        found = pipeline.alerts.list(5000)
        # Build dashboard series strictly from the uploaded capture; no seeded/random telemetry.
        traffic = []
        topology = []
        if events:
            start = min(e.timestamp for e in events)
            buckets = {}
            edges = Counter()
            for e in events:
                idx = int((e.timestamp - start).total_seconds() // 10)
                buckets[idx] = buckets.get(idx, 0) + 1
                edges[(e.src_ip, e.dst_ip)] += 1
            traffic = [{'bucket': k, 'events': buckets[k]} for k in sorted(buckets)]
            topology = [{'src': a, 'dst': b, 'count': c} for (a,b),c in edges.most_common(40)]
        latest_analysis.update({'loaded': True, 'filename': file.filename, 'traffic': traffic, 'topology': topology, 'packets': packet_count, 'flows': pipeline.stats.accepted, 'bytes': sum(e.bytes for e in events)})
        classes = Counter(a.threat_class for a in found)
        severities = Counter(a.severity for a in found)
        top = found[0] if found else None
        return {
            'ok': True, 'filename': file.filename, 'bytes': size, 'packets': packet_count,
            'flows': pipeline.stats.accepted, 'alerts': len(found),
            'threat_classes': dict(classes), 'severity': dict(severities),
            'top_threat': top.model_dump(mode='json') if top else None,
            'passive': True, 'decryption': False, 'transmission': False,
        }
    except HTTPException:
        raise
    except Exception as exc:
        pipeline.reset_session()
        raise HTTPException(400, f'PCAP analysis failed: {exc}') from exc
    finally:
        try: os.unlink(temp_path)
        except OSError: pass

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
    pipeline.engine.save_models(os.getenv('IPXDR_MODEL_DIR', 'models'))
    return {'trained': True, 'rows': len(rows), 'features': pipeline.engine.anomaly.feature_names}

@app.post('/supervised/fit')
def supervised_fit(payload: dict, x_ipxdr_admin_token: str | None = Header(default=None)):
    _admin_guard(x_ipxdr_admin_token)
    rows, labels = payload.get('rows', []), payload.get('labels', [])
    if len(rows) < 10 or len(rows) != len(labels): raise HTTPException(400, 'at least 10 labeled rows and matching labels required')
    pipeline.engine.fit_supervised(rows, labels)
    pipeline.engine.save_models(os.getenv('IPXDR_MODEL_DIR', 'models'))
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

@app.get('/')
def root_dashboard():
    return FileResponse(Path(__file__).resolve().parents[2] / 'frontend' / 'dashboard' / 'index.html')

@app.get('/dashboard')
def dashboard():
    return FileResponse(Path(__file__).resolve().parents[2] / 'frontend' / 'dashboard' / 'index.html')
