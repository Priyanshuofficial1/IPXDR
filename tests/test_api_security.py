from fastapi.testclient import TestClient
from backend.api.main import app

def test_training_endpoint_requires_admin_token_when_configured(monkeypatch):
    monkeypatch.setenv('IPXDR_ADMIN_TOKEN','test-secret')
    c=TestClient(app)
    assert c.post('/anomaly/fit',json=[{'bytes':1.0}]*10).status_code==401
    assert c.post('/anomaly/fit',headers={'X-IPXDR-Admin-Token':'wrong'},json=[{'bytes':1.0}]*10).status_code==403
    assert c.post('/anomaly/fit',headers={'X-IPXDR-Admin-Token':'test-secret'},json=[{'bytes':1.0}]*10).status_code==200
