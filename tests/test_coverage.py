from benchmarks.coverage import scenarios
from backend.processing.pipeline import Pipeline

TARGETS={
    "ddos":"volumetric_ddos","c2_beaconing":"botnet_c2_beaconing",
    "dga_dns_tunneling":"dns_tunneling","encrypted_malware":"encrypted_malware",
    "recon_port_scan":"recon_port_scan","exfiltration":"data_exfiltration",
}

def test_required_threats_reach_production_pipeline():
    for name, events in scenarios().items():
        pipe=Pipeline()
        found=set()
        for event in events:
            pipe.process(event)
            found.update(r.threat_class for r in pipe.last_detector_results if r.score >= 0.5)
        assert TARGETS[name] in found, (name, found)

def test_pipeline_exposes_detector_results_for_evidence():
    pipe=Pipeline()
    pipe.process(scenarios()["ddos"][0])
    assert isinstance(pipe.last_detector_results, list)
