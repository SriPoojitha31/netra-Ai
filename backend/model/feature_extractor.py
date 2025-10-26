# backend/model/feature_extractor.py
"""
Feature extraction utilities used by both training and inference.
Keep inference fast: skip WHOIS & heavy network calls in per-request pipeline.
Only include quick checks (scheme, host, path, token checks, entropy).
"""

import re
import math
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_TOKENS = ['login','verify','account','secure','bank','update','confirm','webscr','signin','password','reset']

def has_ip_in_host(url):
    try:
        host = urlparse(url).netloc.split(':')[0]
        return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host))
    except Exception:
        return False

def url_entropy(s: str):
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    ent = - sum(p * math.log2(p) for p in probs)
    return ent

def count_suspicious_tokens(url):
    url_lower = url.lower()
    return sum(1 for t in SUSPICIOUS_TOKENS if t in url_lower)

def extract_basic_features(url: str):
    """
    Fast per-request feature extraction (no blocking network calls).
    Returns a dict with numeric features used by model.
    """
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://' + url)
        scheme = parsed.scheme
        host = parsed.netloc.lower()
        path = parsed.path or ""
        query = parsed.query or ""
        ext = tldextract.extract(host)

        features = {}
        features['url_len'] = len(url)
        features['host_len'] = len(host)
        features['path_len'] = len(path)
        features['query_len'] = len(query)
        features['num_dots'] = host.count('.')
        features['has_https'] = 1 if scheme == 'https' else 0
        features['has_ip'] = 1 if has_ip_in_host(url) else 0
        features['entropy'] = url_entropy(path + "?" + query)
        features['suspicious_tokens'] = count_suspicious_tokens(url)
        features['tld'] = ext.suffix or ''
        features['domain'] = (ext.domain + ('.' + ext.suffix if ext.suffix else '')) if ext.domain else ''
        # domain_age_days omitted from quick inference
        features['domain_age_days'] = -1
        return features
    except Exception:
        return {
            'url_len': len(url),
            'host_len': 0, 'path_len': 0, 'query_len':0,
            'num_dots':0, 'has_https': 0, 'has_ip': 0,
            'entropy': 0.0, 'suspicious_tokens': 0,
            'tld': '', 'domain':'', 'domain_age_days': -1
        }
