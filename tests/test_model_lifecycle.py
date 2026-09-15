from backend.anomaly.isolation_forest import AnomalyDetector

def test_anomaly_model_save_load(tmp_path):
    rows=[{'bytes':float(i+1),'packets':1.0,'dst_port':443.0} for i in range(30)]
    a=AnomalyDetector().fit(rows); path=tmp_path/'anomaly.joblib'; a.save(path)
    b=AnomalyDetector().load(path); assert b.fitted and b.feature_names==a.feature_names
    assert 0<=b.score({'bytes':1000,'packets':20,'dst_port':1})<=1
