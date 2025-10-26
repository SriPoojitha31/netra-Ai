# backend/utils/explainability.py
"""
Explainability helpers.
For a lightweight approach, use LR/XGBoost coefficients to pick top contributing features.
Optionally use SHAP if installed and available (slow but richer).
"""

import numpy as np
import json

def top_feature_reasons(model_artifact, numeric_cols, input_vector, top_k=3):
    """
    model_artifact: dict with 'classifier' (calibrated estimator) and 'scaler'
    numeric_cols: list of numeric feature names
    input_vector: numeric + embedding vector aligned with model_artifact['feature_columns']
    """
    clf = model_artifact['classifier']
    # base estimator (for CalibratedClassifierCV) may be in clf.base_estimator or clf.base_estimator_
    base = clf
    try:
        # if calibrated
        base = clf.base_estimator
    except Exception:
        base = clf

    # if linear model:
    try:
        coefs = base.coef_.ravel()
    except Exception:
        # fallback: no coefficients (e.g., tree-based). return heuristic reasons.
        return ["Model is tree-based - reasons not available",]

    # match first len(numeric_cols) coefs to numeric columns for interpretability
    num_coefs = coefs[:len(numeric_cols)]
    abs_coefs = np.abs(num_coefs)
    top_idx = np.argsort(abs_coefs)[-top_k:][::-1]
    reasons = []
    for idx in top_idx:
        feat = numeric_cols[idx]
        weight = num_coefs[idx]
        direction = "increases" if weight > 0 else "decreases"
        reasons.append(f"Feature '{feat}' ({'+' if weight>0 else ''}{weight:.3f}) {direction} phishing score")
    return reasons

# human-friendly mapping
HUMAN_MAP = {
    'has_ip': "Links directly to an IP address (instead of a domain) — suspicious.",
    'has_https': "HTTPS missing — site may not be secure.",
    'entropy': "High path entropy — obfuscation likely.",
    'suspicious_tokens': "Contains suspicious words (login, verify, account...).",
    'domain_age_days': "Domain recently created.",
    'url_len': "Excessively long URL with strange paths."
}

def human_reasons_from_features(feat_dict):
    reasons = []
    if feat_dict.get('has_ip',0):
        reasons.append(HUMAN_MAP['has_ip'])
    if feat_dict.get('has_https',1)==0:
        reasons.append(HUMAN_MAP['has_https'])
    if feat_dict.get('entropy',0) > 3.5:
        reasons.append(HUMAN_MAP['entropy'])
    if feat_dict.get('suspicious_tokens',0) > 0:
        reasons.append(HUMAN_MAP['suspicious_tokens'])
    if feat_dict.get('domain_age_days',-1) >=0 and feat_dict.get('domain_age_days') < 30:
        reasons.append(HUMAN_MAP['domain_age_days'])
    return reasons
