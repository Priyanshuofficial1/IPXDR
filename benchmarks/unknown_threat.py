"""Offline proof-of-concept for unseen-threat detection.
The anomaly model sees only normal behavior during fitting; the test pattern is intentionally different.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.anomaly.isolation_forest import AnomalyDetector

def normal_rows(n=200):
    return [{'event_count':10+(i%3),'flow_rate':8+(i%2),'bytes':800+(i%50),'packets':8+(i%3),'unique_ports':1+(i%2),'unique_destinations':2,'graph_nodes':3,'graph_edges':2} for i in range(n)]
def unseen_rows(n=30):
    return [{'event_count':80+i%7,'flow_rate':150+i*3,'bytes':90000+i*2000,'packets':240+i*5,'unique_ports':35+i%10,'unique_destinations':25+i%8,'graph_nodes':40+i%5,'graph_edges':60+i%9} for i in range(n)]
def main():
    m=AnomalyDetector(contamination=.05).fit(normal_rows())
    scores=[m.score(r) for r in unseen_rows()]
    flagged=sum(s>=.5 for s in scores)
    print(f'normal_fit={200} unseen_test={len(scores)} flagged={flagged}/{len(scores)}')
    print(f'unseen_score_mean={sum(scores)/len(scores):.3f} max={max(scores):.3f} min={min(scores):.3f}')
    print('PASS' if flagged else 'REVIEW: anomaly separation was insufficient on this synthetic fixture')
if __name__=='__main__': main()
