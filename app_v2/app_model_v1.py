"""
DEPRECATED: Legacy model v1 prototype entry point.
This file is preserved for historical reference and backward compatibility testing.
Active production-oriented entry point is app_v2/app_model_v2.py.
"""
import warnings
warnings.warn(
    "app_v2/app_model_v1.py is deprecated and preserved for historical reference. "
    "Use app_v2/app_model_v2.py for the active REST API, multi-model support, and live capture.",
    DeprecationWarning,
    stacklevel=2,
)

from pathlib import Path
import json
import sqlite3
import uuid
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
MODEL_DIR = PROJECT / "models" / "replacement_v1"
MODEL_PATH = MODEL_DIR / "xgboost_nids_replacement_v1.json"
LABEL_PATH = MODEL_DIR / "label_mapping.json"
FEATURE_PATH = MODEL_DIR / "selected_features.txt"
DB_PATH = ROOT / "data" / "nids.sqlite"
METRICS_PATH = PROJECT / "reports" / "evaluation" / "xgboost_baseline_v1" / "metrics.json"

MAX_BYTES = 100 * 1024 * 1024
MAX_ROWS = 50_000
MODEL_VERSION = "replacement_v1"

def read_features():
    return [
        line.strip()
        for line in FEATURE_PATH.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]

def load_model():
    if not MODEL_PATH.is_file():
        raise RuntimeError(f"Model file missing: {MODEL_PATH}")
    if not LABEL_PATH.is_file() or not FEATURE_PATH.is_file():
        raise RuntimeError("Model label mapping or feature list is missing.")

    feature_names = read_features()
    if len(feature_names) != 63 or len(set(feature_names)) != 63:
        raise RuntimeError(f"Expected 63 unique model features; got {len(feature_names)}.")

    labels = json.loads(LABEL_PATH.read_text(encoding="utf-8-sig"))
    labels = {int(k): str(v) for k, v in labels.items()}
    if not labels:
        raise RuntimeError("Label mapping is empty.")

    classifier = xgb.XGBClassifier()
    classifier.load_model(str(MODEL_PATH))
    return classifier, feature_names, labels

# Load the existing trained model; this does not train or evaluate it.
model, MODEL_FEATURES, LABELS = load_model()

app = FastAPI(
    title="NIDS - Network Traffic Classification",
    description="Dataset replay / batch analysis; not live detection.",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                scored_count INTEGER NOT NULL DEFAULT 0,
                not_scored_count INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                row_id INTEGER NOT NULL,
                predicted_class TEXT,
                confidence REAL,
                not_scored INTEGER NOT NULL,
                model_version TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            )
        """)

def load_historical_metrics():
    if not METRICS_PATH.is_file():
        return {"available": False, "message": "Historical metrics file not found."}
    try:
        return {
            "available": True,
            "source": str(METRICS_PATH),
            "data": json.loads(METRICS_PATH.read_text(encoding="utf-8-sig")),
            "note": "Historical baseline metrics; not results for replacement_v1.",
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "message": str(exc)}

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "application": "NIDS",
        "model_loaded": True,
        "model_version": MODEL_VERSION,
        "class_count": len(LABELS),
        "feature_count": len(MODEL_FEATURES),
        "mode": "dataset replay / batch analysis",
        "live_detection": False,
    }

@app.get("/features")
def get_features():
    return {"count": len(MODEL_FEATURES), "features": MODEL_FEATURES}

@app.get("/metrics")
def metrics():
    return load_historical_metrics()

@app.post("/score")
async def score(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")

    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "CSV exceeds the 100 MB upload limit.")
    if not content:
        raise HTTPException(400, "The uploaded CSV is empty.")

    import io
    try:
        frame = pd.read_csv(io.BytesIO(content), nrows=MAX_ROWS + 1)
    except Exception as exc:
        raise HTTPException(400, f"Could not read CSV: {exc}") from exc

    if len(frame) > MAX_ROWS:
        raise HTTPException(413, f"Maximum {MAX_ROWS:,} rows per upload.")
    if frame.empty:
        raise HTTPException(400, "The uploaded CSV contains no rows.")

    missing = [name for name in MODEL_FEATURES if name not in frame.columns]
    if missing:
        preview = ", ".join(missing[:12])
        suffix = " ..." if len(missing) > 12 else ""
        raise HTTPException(
            422,
            f"CSV is missing {len(missing)} required feature columns: {preview}{suffix}",
        )

    try:
        numeric = frame.loc[:, MODEL_FEATURES].apply(pd.to_numeric, errors="raise")
        matrix = numeric.to_numpy(dtype=np.float32, copy=True)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, f"Feature columns must contain numeric values: {exc}") from exc

    # CIC-IDS flow exports can contain non-finite numeric values.
    np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)

    try:
        probabilities = model.predict_proba(matrix)
        indices = np.argmax(probabilities, axis=1)
        confidence = np.max(probabilities, axis=1)
        predicted = [LABELS.get(int(i), f"UNKNOWN_CLASS_{int(i)}") for i in indices]
    except Exception as exc:
        raise HTTPException(500, f"Model inference failed: {exc}") from exc

    run_id = str(uuid.uuid4())
    created = datetime.now(timezone.utc).isoformat()
    count = len(frame)

    with connect() as con:
        con.execute(
            """INSERT INTO runs
               (run_id, created_at, filename, row_count, scored_count, not_scored_count)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (run_id, created, Path(file.filename).name, count, count),
        )
        con.executemany(
            """INSERT INTO flows
               (run_id, row_id, predicted_class, confidence, not_scored, model_version)
               VALUES (?, ?, ?, ?, 0, ?)""",
            [
                (run_id, i, predicted[i], float(confidence[i]), MODEL_VERSION)
                for i in range(count)
            ],
        )

    counts = pd.Series(predicted).value_counts().to_dict()
    return {
        "run_id": run_id,
        "filename": Path(file.filename).name,
        "row_count": count,
        "scored_count": count,
        "not_scored_count": 0,
        "model_version": MODEL_VERSION,
        "predictions": [
            {
                "row_id": i,
                "predicted_class": predicted[i],
                "confidence": float(confidence[i]),
            }
            for i in range(count)
        ],
        "class_counts": {str(k): int(v) for k, v in counts.items()},
        "message": "Predictions generated by the replacement XGBoost model.",
    }

@app.get("/summary")
def summary():
    with connect() as con:
        run_count = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        row = con.execute("""
            SELECT COALESCE(SUM(row_count), 0) AS total,
                   COALESCE(SUM(scored_count), 0) AS scored,
                   COALESCE(SUM(not_scored_count), 0) AS not_scored
            FROM runs
        """).fetchone()
        class_rows = con.execute("""
            SELECT predicted_class, COUNT(*) AS count
            FROM flows
            WHERE not_scored = 0
            GROUP BY predicted_class
            ORDER BY count DESC
        """).fetchall()

    return {
        "runs": run_count,
        "rows_received": row["total"],
        "rows_scored": row["scored"],
        "rows_not_scored": row["not_scored"],
        "predictions_available": True,
        "class_counts": {r["predicted_class"]: r["count"] for r in class_rows},
    }

@app.get("/flows")
def flows(run_id: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    with connect() as con:
        if run_id:
            rows = con.execute(
                """SELECT run_id, row_id, predicted_class, confidence, not_scored, model_version
                   FROM flows WHERE run_id = ? ORDER BY row_id LIMIT ?""",
                (run_id, limit),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT run_id, row_id, predicted_class, confidence, not_scored, model_version
                   FROM flows ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    return {"items": [dict(row) for row in rows], "count": len(rows)}

@app.get("/runs")
def runs(limit: int = 20):
    limit = max(1, min(limit, 100))
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"items": [dict(row) for row in rows]}

init_db()
