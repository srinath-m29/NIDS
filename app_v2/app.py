"""
DEPRECATED: Legacy prototype entry point (v0.1.0).
This file is preserved for historical reference only.
Active production-oriented entry point is app_v2/app_model_v2.py.
"""
import warnings
warnings.warn(
    "app_v2/app.py is deprecated and preserved for historical reference only. "
    "Use app_v2/app_model_v2.py for the active REST API and live monitoring dashboard.",
    DeprecationWarning,
    stacklevel=2,
)

from pathlib import Path
import json
import sqlite3
import uuid
from datetime import datetime, timezone

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
DB_PATH = ROOT / "data" / "nids.sqlite"
FEATURE_FILE = PROJECT / "dataset" / "processed" / "selected_features.txt"
METRICS_FILE = PROJECT / "reports" / "evaluation" / "xgboost_baseline_v1" / "metrics.json"
MAX_BYTES = 100 * 1024 * 1024
MAX_ROWS = 50_000

app = FastAPI(
    title="NIDS - Network Traffic Classification",
    description="Dataset replay and batch analysis prototype; not live detection.",
    version="0.1.0",
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


def features():
    if not FEATURE_FILE.exists():
        raise HTTPException(500, "Selected feature list is missing.")
    return [
        line.strip()
        for line in FEATURE_FILE.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def load_metrics():
    if not METRICS_FILE.exists():
        return {"available": False, "message": "Existing metrics file not found."}
    try:
        data = json.loads(METRICS_FILE.read_text(encoding="utf-8-sig"))
        return {"available": True, "source": str(METRICS_FILE), "data": data}
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "message": f"Could not read metrics: {exc}"}


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
        "model_loaded": False,
        "mode": "dataset replay / batch analysis",
        "live_detection": False,
    }


@app.get("/features")
def get_features():
    return {"count": len(features()), "features": features()}


@app.get("/metrics")
def metrics():
    return load_metrics()


@app.post("/score")
async def score(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "CSV exceeds the 100 MB upload limit.")
    if not content:
        raise HTTPException(400, "The uploaded CSV is empty.")

    try:
        import io
        frame = pd.read_csv(io.BytesIO(content), nrows=MAX_ROWS + 1)
    except Exception as exc:
        raise HTTPException(400, f"Could not read CSV: {exc}")

    if len(frame) > MAX_ROWS:
        raise HTTPException(413, f"Maximum {MAX_ROWS:,} rows per upload.")
    if frame.empty:
        raise HTTPException(400, "The uploaded CSV contains no rows.")

    required = features()
    missing = [name for name in required if name not in frame.columns]
    if missing:
        preview = ", ".join(missing[:12])
        suffix = " ..." if len(missing) > 12 else ""
        raise HTTPException(
            422,
            f"CSV is missing {len(missing)} required feature columns: {preview}{suffix}",
        )

    # No compatible saved model was found. Do not invent predictions.
    run_id = str(uuid.uuid4())
    created = datetime.now(timezone.utc).isoformat()
    count = len(frame)

    with connect() as con:
        con.execute(
            """INSERT INTO runs
               (run_id, created_at, filename, row_count, scored_count, not_scored_count)
               VALUES (?, ?, ?, ?, 0, ?)""",
            (run_id, created, Path(file.filename).name, count, count),
        )
        con.executemany(
            """INSERT INTO flows
               (run_id, row_id, predicted_class, confidence, not_scored, model_version)
               VALUES (?, ?, NULL, NULL, 1, NULL)""",
            [(run_id, i) for i in range(count)],
        )

    return {
        "run_id": run_id,
        "filename": Path(file.filename).name,
        "row_count": count,
        "scored_count": 0,
        "not_scored_count": count,
        "status": "stored_not_scored",
        "message": "CSV validated and stored. Predictions require a compatible saved model.",
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
    return {
        "runs": run_count,
        "rows_received": row["total"],
        "rows_scored": row["scored"],
        "rows_not_scored": row["not_scored"],
        "predictions_available": False,
    }


@app.get("/flows")
def flows(run_id: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    with connect() as con:
        if run_id:
            rows = con.execute(
                """SELECT run_id, row_id, predicted_class, confidence, not_scored
                   FROM flows WHERE run_id = ? ORDER BY row_id LIMIT ?""",
                (run_id, limit),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT run_id, row_id, predicted_class, confidence, not_scored
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
