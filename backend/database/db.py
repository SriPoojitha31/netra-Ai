# backend/database/db.py
"""
Simple SQLite-based logging for scans.
Use SQLAlchemy for production or switch by changing DB_URL.
"""

import sqlite3
from datetime import datetime
import json
import os

DB_PATH = os.getenv("PHISH_DB_PATH", "backend/data/phish_logs.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            prediction TEXT,
            score REAL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def insert_scan(url, prediction, score, reasons):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (url, prediction, score, reasons, created_at) VALUES (?, ?, ?, ?, ?)",
                (url, prediction, score, json.dumps(reasons), datetime.utcnow()))
    conn.commit()
    conn.close()

def get_recent(n=100):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, url, prediction, score, reasons, created_at FROM scans ORDER BY created_at DESC LIMIT ?", (n,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r[0],
            "url": r[1],
            "prediction": r[2],
            "score": r[3],
            "reasons": json.loads(r[4]) if r[4] else [],
            "created_at": r[5]
        })
    return out

# init on import if desired
init_db()
