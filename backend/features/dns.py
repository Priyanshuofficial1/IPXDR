from __future__ import annotations
from collections import Counter
from math import log2

def entropy(text: str) -> float:
    if not text: return 0.0
    c=Counter(text); n=len(text)
    return -sum((v/n)*log2(v/n) for v in c.values())

def extract_dns_features(events) -> dict[str,float]:
    records=[e.dns for e in events if e.dns and e.dns.get('query')]
    names=[str(r['query']).rstrip('.').lower() for r in records]
    labels=[n.split('.')[0] for n in names if n]
    if not names: return {'dns_query_count':0.0,'dns_avg_query_length':0.0,'dns_max_query_length':0.0,'dns_avg_label_entropy':0.0,'dns_unique_domains':0.0,'dns_nxdomain_ratio':0.0,'dns_txt_ratio':0.0,'dns_long_label_ratio':0.0}
    rtypes=[str(r.get('qtype','')).upper() for r in records]
    nxd=sum(1 for r in records if str(r.get('rcode','')).upper() in {'3','NXDOMAIN'})
    return {'dns_query_count':float(len(names)),'dns_avg_query_length':sum(map(len,names))/len(names),'dns_max_query_length':float(max(map(len,names))),
            'dns_avg_label_entropy':sum(entropy(x) for x in labels)/max(1,len(labels)),'dns_unique_domains':float(len(set(names))),
            'dns_nxdomain_ratio':nxd/len(records),'dns_txt_ratio':sum(x=='TXT' for x in rtypes)/len(records),
            'dns_long_label_ratio':sum(len(x)>=45 for x in labels)/max(1,len(labels))}
