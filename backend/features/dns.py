from __future__ import annotations
from collections import Counter
from math import log2

# Lightweight character n-gram statistics; intentionally deterministic and model-free.
_COMMON_BIGRAMS = {"co","om","on","io","in","er","re","an","nd","en","at","es","or","te","nt","ar","st","to","ng","al","it","is","et","ti","se","ha","as","ou","be","he","me","de","hi","ri","ro","ic","ne","ea"}

def entropy(text: str) -> float:
    if not text: return 0.0
    c = Counter(text); n = len(text)
    return -sum((v/n)*log2(v/n) for v in c.values())

def ngram_score(text: str) -> float:
    s = ''.join(ch for ch in text.lower() if ch.isalnum())
    if len(s) < 3: return 0.0
    grams = [s[i:i+2] for i in range(len(s)-1)]
    rare = sum(g not in _COMMON_BIGRAMS for g in grams) / len(grams)
    digit = sum(ch.isdigit() for ch in s) / len(s)
    return min(1.0, 0.65*rare + 0.35*min(1.0, digit*3))

def extract_dns_features(events) -> dict[str,float]:
    records = [e.dns for e in events if e.dns and e.dns.get('query')]
    names = [str(r['query']).rstrip('.').lower() for r in records]
    labels = [n.split('.')[0] for n in names if n]
    base = {'dns_query_count':0.0,'dns_avg_query_length':0.0,'dns_max_query_length':0.0,'dns_avg_label_entropy':0.0,
            'dns_unique_domains':0.0,'dns_nxdomain_ratio':0.0,'dns_txt_ratio':0.0,'dns_long_label_ratio':0.0,
            'dns_avg_ngram_risk':0.0,'dns_digit_ratio':0.0,'dns_unique_label_ratio':0.0}
    if not names: return base
    rtypes = [str(r.get('qtype','')).upper() for r in records]
    nxd = sum(1 for r in records if str(r.get('rcode','')).upper() in {'3','NXDOMAIN'})
    base.update({'dns_query_count':float(len(names)), 'dns_avg_query_length':sum(map(len,names))/len(names),
        'dns_max_query_length':float(max(map(len,names))), 'dns_avg_label_entropy':sum(entropy(x) for x in labels)/max(1,len(labels)),
        'dns_unique_domains':float(len(set(names))), 'dns_nxdomain_ratio':nxd/len(records),
        'dns_txt_ratio':sum(x=='TXT' for x in rtypes)/len(records), 'dns_long_label_ratio':sum(len(x)>=45 for x in labels)/max(1,len(labels)),
        'dns_avg_ngram_risk':sum(ngram_score(x) for x in labels)/max(1,len(labels)),
        'dns_digit_ratio':sum(sum(c.isdigit() for c in x)/max(1,len(x)) for x in labels)/max(1,len(labels)),
        'dns_unique_label_ratio':len(set(labels))/max(1,len(labels))})
    return base
