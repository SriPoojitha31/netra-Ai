# backend/utils/helpers.py
"""
Utility helpers: load model, vectorize features to model input vector, predict and format response.
"""

import joblib
import numpy as np
from .explainability import human_reasons_from_features, top_feature_reasons

def load_model(path="models/phishing_model.pkl"):
    artifact = joblib.load(path)
    # expected artifact has keys: scaler, classifier, embedder_name, feature_columns
    return artifact

def vectorize_input(features: dict, model_artifact):
    """
    Convert a features dict (basic numeric features) into the numeric+embedding vector expected by the model.
    model_artifact contains scaler and embedding mapping info (we assume embeddings are created externally)
    """
    scaler = model_artifact['scaler']
    cols = model_artifact['feature_columns']
    # numeric cols first
    numeric_cols = [c for c in cols if not c.startswith('emb_')]
    emb_cols = [c for c in cols if c.startswith('emb_')]

    # Build numeric vector
    numeric_vector = np.array([features.get(c, 0.0) for c in numeric_cols], dtype=float).reshape(1, -1)
    # scale numeric
    numeric_scaled = scaler.transform(numeric_vector)

    # Embeddings: if embedder used, create embedding from url text externally
    # Here we'll expect caller to provide 'embedding' key in features if embeddings used
    emb_vector = np.zeros((1, len(emb_cols)))
    if 'embedding' in features and features['embedding'] is not None:
        e = np.array(features['embedding']).reshape(1, -1)
        emb_vector = e
    # combine
    full_vec = np.hstack([numeric_scaled, emb_vector])
    return full_vec, numeric_cols

def predict_and_explain(model_artifact, feature_dict):
    """
    Returns: prediction label, score, human reasons list, top coef reasons
    """
    vec, numeric_cols = vectorize_input(feature_dict, model_artifact)
    clf = model_artifact['classifier']
    prob = float(clf.predict_proba(vec)[0,1])
    pred_label = "Phishing" if prob >= 0.5 else "Safe"
    # human reasons from raw features (quick)
    human_reasons = human_reasons_from_features(feature_dict)
    # coef-based reasons
    try:
        top_reasons = top_feature_reasons(model_artifact, numeric_cols, vec[0], top_k=3)
    except Exception:
        top_reasons = []
    return pred_label, prob, human_reasons, top_reasons
