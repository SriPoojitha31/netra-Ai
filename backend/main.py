# backend/main.py
"""
FastAPI server for phishing analyzer.
Endpoints:
- POST /analyze  -> analyze an input URL (and optional message)
- GET  /health   -> health check
- GET  /logs     -> recent scan logs
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import uvicorn
import time
import os

# local modules
from model.feature_extractor import extract_basic_features
from utils.helpers import load_model, predict_and_explain
from database.db import insert_scan, get_recent

# sentence-transformer embedder (loaded on startup)
from sentence_transformers import SentenceTransformer

app = FastAPI(title="AI Phishing & Malicious Link Analyzer", version="0.1")

MODEL_PATH = os.getenv("MODEL_PATH", "models/phishing_model.pkl")
EMBEDDER_NAME = os.getenv("EMBEDDER_NAME", "all-MiniLM-L6-v2")

# Request/Response schemas
class AnalyzeRequest(BaseModel):
    url: str
    message: Optional[str] = None  # optional message/context
    return_reasons: Optional[bool] = True

class AnalyzeResponse(BaseModel):
    url: str
    prediction: str
    score: float
    human_reasons: List[str]
    feature_reasons: List[str]

@app.on_event("startup")
def startup_event():
    # load model artifact
    global model_artifact, embedder
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(f"Model artifact not found: {MODEL_PATH}. Please train and save a model.")
    model_artifact = load_model(MODEL_PATH)
    # If embedder needed, load it
    try:
        embedder = SentenceTransformer(model_artifact.get('embedder_name', EMBEDDER_NAME))
    except Exception:
        # fallback
        embedder = SentenceTransformer(EMBEDDER_NAME)

@app.get("/health")
def health():
    return {"status":"ok", "model_loaded": bool(model_artifact)}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    start = time.time()
    url = req.url.strip()
    # quick feature extraction
    feats = extract_basic_features(url)
    # get embedding if model expects embeddings
    emb_cols = [c for c in model_artifact['feature_columns'] if c.startswith('emb_')]
    if len(emb_cols) > 0:
        try:
            text_for_embedding = req.message if (req.message and len(req.message.strip())>0) else url
            emb = embedder.encode([text_for_embedding], show_progress_bar=False)[0]
            feats['embedding'] = emb
        except Exception as e:
            feats['embedding'] = None

    # predict
    try:
        pred_label, score, human_reasons, top_reasons = predict_and_explain(model_artifact, feats)
    except Exception as e:
        # fallback safe
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

    # insert log (non-blocking option for production)
    try:
        insert_scan(url, pred_label, float(score), {"human": human_reasons, "coef": top_reasons})
    except Exception:
        pass

    duration = time.time() - start
    # return
    resp = AnalyzeResponse(
        url=url,
        prediction=pred_label,
        score=float(score),
        human_reasons=human_reasons,
        feature_reasons=top_reasons
    )
    return resp

@app.get("/logs")
def logs(limit: int = 50):
    return get_recent(limit)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
