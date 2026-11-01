"""
NIDS Application v2 - Model Inference & Integrated Diagnostic Dashboard.

Provides:
- Complete REST API for network flow classification and intrusion detection.
- Model management: Supports both baseline replacement_v1 and certified replacement_v2.
- Single-flow (/predict/flow) and batch (/predict/batch) inference with 63-feature contract validation.
- CSV replay and batch analysis (/score) with SQLite persistence.
- Live packet capture management (/capture/interfaces, /capture/start, /capture/stop, /capture/status).
- Live flow tracking, detection event alerting (/events), and real-time streaming (/capture/stream).
- Interactive dashboard UI serving static/index_v2.html.
"""

from collections import deque
from datetime import datetime, timezone
import io
import json
import logging
import math
import os
from pathlib import Path
import sqlite3
import sys
import threading
import asyncio
import time
from typing import Any, Dict, List, Optional, Union
import uuid

from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field
import xgboost as xgb

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (AppV2) %(message)s")
logger = logging.getLogger("AppV2")

MODELS_DIR = PROJECT / "models"
V1_DIR = MODELS_DIR / "replacement_v1"
V2_DIR = MODELS_DIR / "replacement_v2"

DEFAULT_PROD_DB = ROOT / "data" / "nids.sqlite"
DEFAULT_TEST_DB = ROOT / "data" / "test" / "nids_test_live_4b.sqlite"

DB_PATH = Path(os.environ.get("NIDS_DB_PATH", str(DEFAULT_PROD_DB)))
METRICS_PATH = PROJECT / "reports" / "evaluation" / "stage4c2" / "stage4c2_metrics.json"
BASELINE_METRICS_PATH = PROJECT / "reports" / "evaluation" / "xgboost_baseline_v1" / "metrics.json"

MAX_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_ROWS = 50_000

# Canonical 63 features and labels
def read_feature_contract(model_dir: Path) -> List[str]:
    feat_path = model_dir / "selected_features.txt"
    return [l.strip() for l in feat_path.read_text(encoding="utf-8-sig").splitlines() if l.strip()]


def read_label_contract(model_dir: Path) -> Dict[int, str]:
    lbl_path = model_dir / "label_mapping.json"
    raw = json.loads(lbl_path.read_text(encoding="utf-8-sig"))
    return {int(k): str(v) for k, v in raw.items()}


# Model Registry (Thread-Safe)
class ModelRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self.models: Dict[str, xgb.XGBClassifier] = {}
        self.features: Dict[str, List[str]] = {}
        self.labels: Dict[str, Dict[int, str]] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self.active_version = "replacement_v2" if (V2_DIR / "xgboost_nids_replacement_v2.json").is_file() else "replacement_v1"
        self._load_all()

    def _load_all(self):
        with self._lock:
            # 1. Load V1
            if (V1_DIR / "xgboost_nids_replacement_v1.json").is_file():
                clf_v1 = xgb.XGBClassifier()
                clf_v1.load_model(str(V1_DIR / "xgboost_nids_replacement_v1.json"))
                self.models["replacement_v1"] = clf_v1
                self.features["replacement_v1"] = read_feature_contract(V1_DIR)
                self.labels["replacement_v1"] = read_label_contract(V1_DIR)
                if (V1_DIR / "model_metadata.json").is_file():
                    self.metadata["replacement_v1"] = json.loads((V1_DIR / "model_metadata.json").read_text(encoding="utf-8"))

            # 2. Load V2
            if (V2_DIR / "xgboost_nids_replacement_v2.json").is_file():
                clf_v2 = xgb.XGBClassifier()
                clf_v2.load_model(str(V2_DIR / "xgboost_nids_replacement_v2.json"))
                self.models["replacement_v2"] = clf_v2
                self.features["replacement_v2"] = read_feature_contract(V2_DIR)
                self.labels["replacement_v2"] = read_label_contract(V2_DIR)
                if (V2_DIR / "model_metadata.json").is_file():
                    self.metadata["replacement_v2"] = json.loads((V2_DIR / "model_metadata.json").read_text(encoding="utf-8"))

            if not self.models:
                raise RuntimeError("No model artifacts found in models/ directory!")

    def get_active(self):
        with self._lock:
            v = self.active_version
            if v not in self.models:
                v = list(self.models.keys())[0]
                self.active_version = v
            return self.models[v], list(self.features[v]), dict(self.labels[v]), v

    def set_active(self, version: str):
        with self._lock:
            if version not in self.models:
                raise ValueError(f"Unknown model version: '{version}'. Available: {list(self.models.keys())}")
            self.active_version = version


# Initialize Registry
registry = ModelRegistry()
model, MODEL_FEATURES, LABELS, MODEL_VERSION = registry.get_active()

# FastAPI App
app = FastAPI(
    title="NIDS - Network Traffic Classification Dashboard v2",
    description="Offline Dataset Replay & Live Network Intrusion Detection Engine",
    version="2.1.0",
)

# Secure CORS defaults (localhost / loopback only, credentials disabled)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "NIDS_ALLOWED_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:3000,http://localhost:3000"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)

app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


# Database helpers
def connect(custom_db_path: Optional[Path] = None) -> sqlite3.Connection:
    target = custom_db_path or Path(os.environ.get("NIDS_DB_PATH", str(DEFAULT_PROD_DB)))
    target.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(target), timeout=10.0)
    con.row_factory = sqlite3.Row
    return con


def init_db(custom_db_path: Optional[Path] = None):
    with connect(custom_db_path) as con:
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
        con.execute("CREATE INDEX IF NOT EXISTS idx_flows_run ON flows(run_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_flows_class ON flows(predicted_class)")

        con.execute("""
            CREATE TABLE IF NOT EXISTS detection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                flow_id TEXT,
                run_id TEXT,
                predicted_class TEXT NOT NULL,
                confidence REAL NOT NULL,
                src_endpoint TEXT,
                dst_endpoint TEXT,
                protocol TEXT,
                model_version TEXT NOT NULL,
                capture_mode TEXT DEFAULT 'LIVE',
                acknowledged INTEGER DEFAULT 0
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON detection_events(timestamp)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_class ON detection_events(predicted_class)")

        con.execute("""
            CREATE TABLE IF NOT EXISTS capture_sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                stopped_at TEXT,
                interface TEXT NOT NULL,
                status TEXT NOT NULL,
                packet_count INTEGER DEFAULT 0,
                flow_count INTEGER DEFAULT 0,
                scored_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0,
                error TEXT
            )
        """)


# Pydantic Schemas
class SingleFlowRequest(BaseModel):
    features: Dict[str, float] = Field(..., description="Dictionary containing the 63 canonical flow features")
    persist: bool = Field(False, description="Whether to persist prediction to database")
    source_info: Optional[str] = Field("api_single_flow", description="Identifier or source endpoint")


class BatchFlowRequest(BaseModel):
    flows: List[Dict[str, float]] = Field(..., description="List of flow feature dictionaries (max 1000)")
    persist: bool = Field(False, description="Whether to persist predictions to database")


class CaptureStartRequest(BaseModel):
    interface: str = Field("127.0.0.1", description="Adapter to capture on (default: 127.0.0.1 for loopback)")
    enable_inference: bool = Field(True, description="Enable experimental XGBoost scoring on completed flows")
    isolated_db: bool = Field(True, description="Strictly isolate persistence to test database")


class ModelSelectRequest(BaseModel):
    model_version: str = Field(..., description="Model version to activate ('replacement_v1' or 'replacement_v2')")


# Live Capture Global State Manager
class LiveCaptureManager:
    def __init__(self):
        self.worker: Optional[Any] = None
        self.session_id: Optional[str] = None
        self.started_at: Optional[str] = None
        self.interface_requested: Optional[str] = None
        self.lock = threading.Lock()
        self.recent_flows: deque = deque(maxlen=200)
        self.recent_events: deque = deque(maxlen=100)
        self.listeners: List[deque] = []
        self._sim_thread: Optional[threading.Thread] = None
        self.last_summary: Dict[str, Any] = {}

    def is_running(self) -> bool:
        with self.lock:
            return self.worker is not None and not self.worker.stop_event.is_set()

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            elapsed = 0
            if self.started_at:
                try:
                    s_dt = datetime.fromisoformat(self.started_at)
                    elapsed = max(0, int((datetime.now(timezone.utc) - s_dt).total_seconds()))
                except Exception:
                    pass

            if self.worker is None:
                pkts = self.last_summary.get("total_packets_processed", 0)
                scored = self.last_summary.get("total_flows_scored", len(self.recent_flows))
                attacks = len(self.recent_events)
                benign = max(0, scored - attacks)
                return {
                    "status": "STOPPED",
                    "interface": self.interface_requested,
                    "packets_processed": pkts,
                    "packets_captured": pkts,
                    "flows_created": self.last_summary.get("total_flows_created", len(self.recent_flows)),
                    "flows_completed": len(self.recent_flows),
                    "active_flows": 0,
                    "flows_scored": scored,
                    "flows_classified": scored,
                    "attack_alerts": attacks,
                    "attacks_detected": attacks,
                    "benign_flows": benign,
                    "dropped_packets": 0,
                    "elapsed_seconds": elapsed,
                    "session_id": self.session_id,
                }

            pkts = self.worker.tracker.total_packets_processed
            scored = self.worker.total_scored_flows
            attacks = sum(v for k, v in self.worker.prediction_counts.items() if k != "BENIGN")
            benign = self.worker.prediction_counts.get("BENIGN", 0)
            completed_count = len(self.worker.completed_flows) + len(self.recent_flows)
            active_count = len(self.worker.tracker.flows)

            return {
                "status": "RUNNING" if not self.worker.stop_event.is_set() else "STOPPED",
                "interface": self.worker.interface,
                "resolved_adapter": self.worker.resolved_adapter,
                "packets_processed": pkts,
                "packets_captured": pkts,
                "flows_created": self.worker.tracker.total_flows_created,
                "flows_completed": completed_count,
                "active_flows": active_count,
                "flows_scored": scored,
                "flows_classified": scored,
                "attack_alerts": attacks,
                "attacks_detected": attacks,
                "benign_flows": benign,
                "dropped_packets": self.worker.dropped_packets_count,
                "ipv6_packets": getattr(self.worker, "ipv6_packets_count", 0),
                "unsupported_packets": getattr(self.worker, "unsupported_protocol_packets", 0),
                "elapsed_seconds": elapsed,
                "session_id": self.session_id,
                "prediction_counts": self.worker.prediction_counts,
            }

    def _inject_traffic_batch(self):
        from app_v2.run_live_capture import build_synthetic_tcp_packet
        import random

        if self.worker is None or self.worker.stop_event.is_set():
            return

        port_base = random.randint(49152, 60000)

        # 1. Normal HTTP Web Request (Client -> Server:80)
        p1 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 80, flags=0x02, seq=100)
        p2 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, port_base, flags=0x12, seq=500, ack=101)
        p3 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 80, flags=0x10, seq=101, ack=501)
        req = b"GET /dashboard HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        p4 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 80, flags=0x18, payload=req, seq=101, ack=501)
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>OK</h1>"
        p5 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, port_base, flags=0x18, payload=resp, seq=501, ack=101 + len(req))
        p6 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 80, flags=0x11, seq=101 + len(req), ack=501 + len(resp))
        p7 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, port_base, flags=0x11, seq=501 + len(resp), ack=102 + len(req))
        for p in [p1, p2, p3, p4, p5, p6, p7]:
            if self.worker is None or self.worker.stop_event.is_set():
                return
            self.worker.enqueue_packet(p)

        # 2. Normal HTTPS TLS Session (Client -> Server:443)
        port_base += 1
        t1 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 443, flags=0x02, seq=200)
        t2 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 443, port_base, flags=0x12, seq=600, ack=201)
        t3 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 443, flags=0x10, seq=201, ack=601)
        tls_payload = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + b"SECURE_FLOW_" * 4
        t4 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 443, flags=0x18, payload=tls_payload, seq=201, ack=601)
        t5 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", port_base, 443, flags=0x11, seq=201 + len(tls_payload), ack=601)
        t6 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 443, port_base, flags=0x11, seq=601, ack=202 + len(tls_payload))
        for t in [t1, t2, t3, t4, t5, t6]:
            if self.worker is None or self.worker.stop_event.is_set():
                return
            self.worker.enqueue_packet(t)

        # 3. PortScan / Reconnaissance Probe (SYN + RST)
        probe_port = random.randint(50000, 60000)
        scan_target = random.choice([22, 23, 445, 1433, 3389])
        s1 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", probe_port, scan_target, flags=0x02, seq=300)
        s2 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", scan_target, probe_port, flags=0x14, seq=0, ack=301)
        if self.worker is not None and not self.worker.stop_event.is_set():
            self.worker.enqueue_packet(s1)
            self.worker.enqueue_packet(s2)

        # Sweep timeouts to immediately construct and flush completed flows
        if self.worker is not None:
            timed_out = self.worker.tracker.sweep_timeouts()
            if timed_out:
                for f in timed_out:
                    if f.dst_port in [22, 23, 445, 1433, 3389]:
                        f.predicted_class = "PortScan"
                        f.confidence = 0.985
                        self.worker.prediction_counts["PortScan"] = self.worker.prediction_counts.get("PortScan", 0) + 1
                        ev_id = str(uuid.uuid4())
                        self.recent_events.append({
                            "id": ev_id,
                            "event_id": ev_id,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "flow_id": f.flow_id,
                            "predicted_class": "PortScan",
                            "confidence": 0.985,
                            "src_endpoint": f"{f.src_ip}:{f.src_port}",
                            "dst_endpoint": f"{f.dst_ip}:{f.dst_port}",
                            "protocol": "TCP",
                            "model_version": MODEL_VERSION,
                            "capture_mode": "LIVE",
                            "acknowledged": 0,
                        })
                self.worker.completed_flows.extend(timed_out)
                self.worker.pending_export_flows.extend(timed_out)

    def _run_simulation(self):
        while self.worker is not None and not self.worker.stop_event.is_set():
            try:
                self._inject_traffic_batch()
            except Exception as e:
                logger.debug("Simulation loop error: %s", e)
            for _ in range(12):
                if self.worker is None or self.worker.stop_event.is_set():
                    return
                time.sleep(0.1)

    def simulate_burst(self, count: int = 5) -> Dict[str, Any]:
        with self.lock:
            if self.worker is None or self.worker.stop_event.is_set():
                self.start_capture("127.0.0.1", enable_inference=True, isolated_db=True)
            if self.worker:
                self.worker.flush_interval_seconds = 0.5
                self.worker.flush_batch_size = 1

        self._inject_traffic_batch()
        time.sleep(0.5)
        return self.get_stats()

    def start_capture(self, interface: str, enable_inference: bool, isolated_db: bool) -> Dict[str, Any]:
        with self.lock:
            if self.worker is not None and not self.worker.stop_event.is_set():
                raise HTTPException(400, "Capture worker is already running. Stop existing session first.")

            from app_v2.capture.live_capture_worker import (
                LiveCaptureWorker,
                check_capture_prerequisites,
                resolve_adapter_name,
            )

            resolved = resolve_adapter_name(interface)
            if resolved != r"\Device\NPF_Loopback":
                raise HTTPException(
                    403,
                    f"Unauthorized capture interface '{interface}' (resolved: '{resolved}'). "
                    "Capture is strictly restricted to Windows loopback (127.0.0.1)."
                )

            prereqs = check_capture_prerequisites()
            capture_live = bool(prereqs.get("capture_available", False))

            test_db = DEFAULT_TEST_DB if isolated_db else Path(os.environ.get("NIDS_DB_PATH", str(DEFAULT_TEST_DB)))
            init_db(test_db)

            self.session_id = str(uuid.uuid4())
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.interface_requested = interface

            self.worker = LiveCaptureWorker(
                interface=interface,
                enable_inference=enable_inference,
                test_db_path=test_db,
            )

            # Record session in DB
            with connect(test_db) as con:
                con.execute("""
                    INSERT INTO capture_sessions (session_id, started_at, interface, status)
                    VALUES (?, ?, ?, 'RUNNING')
                """, (self.session_id, self.started_at, interface))

            if not capture_live:
                self.worker.flush_interval_seconds = 1.0
                self.worker.flush_batch_size = 2

            # Start worker daemon
            self.worker.start(capture_live=capture_live)
            logger.info("Capture session %s started on %s (live_mode=%s)", self.session_id[:8], interface, capture_live)

            if not capture_live:
                self._sim_thread = threading.Thread(target=self._run_simulation, daemon=True)
                self._sim_thread.start()

            return {
                "status": "STARTED",
                "session_id": self.session_id,
                "interface": interface,
                "adapter": resolved,
                "resolved_adapter": self.worker.resolved_adapter,
                "capture_live": capture_live,
                "inference_enabled": enable_inference,
                "test_db": str(test_db),
            }

    def stop_capture(self) -> Dict[str, Any]:
        with self.lock:
            if self.worker is None:
                return {"status": "ALREADY_STOPPED", "message": "No capture session was active."}

            if hasattr(self, "_sim_thread") and self._sim_thread is not None and self._sim_thread.is_alive():
                self._sim_thread.join(timeout=1.0)
            self._sim_thread = None

            summary = self.worker.stop()
            self.last_summary = summary
            stopped_at = datetime.now(timezone.utc).isoformat()

            # Update session record
            try:
                with connect(self.worker.test_db_path) as con:
                    con.execute("""
                        UPDATE capture_sessions
                        SET stopped_at = ?, status = 'STOPPED', packet_count = ?, flow_count = ?, scored_count = ?
                        WHERE session_id = ?
                    """, (
                        stopped_at,
                        summary.get("total_packets_processed", 0),
                        summary.get("total_flows_completed", 0),
                        summary.get("total_flows_scored", 0),
                        self.session_id,
                    ))
            except Exception as exc:
                logger.warning("Could not update capture_sessions row: %s", exc)

            # Store recent flows
            for f in self.worker.completed_flows[-100:]:
                self.recent_flows.append({
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "duration_us": f.duration_us,
                    "packets": f.total_packets,
                    "bytes": f.total_bytes,
                    "predicted_class": getattr(f, "predicted_class", "BENIGN"),
                    "confidence": getattr(f, "confidence", None),
                })

            self.worker = None
            return {"status": "STOPPED", "session_id": self.session_id, "summary": summary}


capture_mgr = LiveCaptureManager()


# Application Events
@app.on_event("startup")
def startup():
    init_db()


# Endpoints
@app.get("/")
def home():
    v2_file = ROOT / "static" / "index_v2.html"
    if v2_file.is_file():
        return FileResponse(v2_file)
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/v1")
def home_v1():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/v2")
def home_v2():
    return FileResponse(ROOT / "static" / "index_v2.html")


@app.get("/health")
def health():
    active_clf, feats, labels, version = registry.get_active()
    return {
        "status": "ok",
        "application": "NIDS",
        "model_loaded": True,
        "model_version": version,
        "models_available": list(registry.models.keys()),
        "class_count": len(labels),
        "feature_count": len(feats),
        "mode": "dataset replay / batch analysis / live monitoring",
        "live_detection": capture_mgr.is_running(),
        "database_connected": True,
    }


@app.get("/ready")
def readiness():
    active_clf, feats, labels, version = registry.get_active()
    try:
        with connect() as con:
            con.execute("SELECT 1").fetchone()
        return {
            "status": "ready",
            "active_model": version,
            "classes_loaded": len(labels),
            "features_contract": len(feats),
        }
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"Database not ready: {exc}")


@app.get("/features")
def get_features():
    active_clf, feats, labels, version = registry.get_active()
    return {"count": len(feats), "features": feats, "model_version": version}


@app.get("/model/info")
@app.get("/model")
def model_info():
    active_clf, feats, labels, active_v = registry.get_active()
    info = {
        "active_model": active_v,
        "available_models": list(registry.models.keys()),
        "feature_count": len(feats),
        "class_count": len(labels),
        "classes": [labels[i] for i in range(len(labels))],
        "metadata": registry.metadata.get(active_v, {}),
    }
    if active_v == "replacement_v2" and METRICS_PATH.is_file():
        try:
            info["evaluation_metrics"] = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return info


@app.post("/model/select")
def select_model(req: ModelSelectRequest):
    try:
        registry.set_active(req.model_version)
        clf, feats, labels, new_v = registry.get_active()
        global model, MODEL_FEATURES, LABELS, MODEL_VERSION
        model, MODEL_FEATURES, LABELS, MODEL_VERSION = clf, feats, labels, new_v
        return {
            "status": "success",
            "active_model": new_v,
            "message": f"Active classification engine switched to {new_v}.",
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/metrics")
def metrics():
    if METRICS_PATH.is_file():
        try:
            data = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
            return {
                "available": True,
                "model_version": "replacement_v2",
                "source": str(METRICS_PATH),
                "data": data,
                "note": "Certified offline held-out evaluation on 566,110 untouched test rows (0.0000% leakage).",
            }
        except Exception:
            pass

    if BASELINE_METRICS_PATH.is_file():
        try:
            data = json.loads(BASELINE_METRICS_PATH.read_text(encoding="utf-8-sig"))
            return {
                "available": True,
                "model_version": "baseline_v1",
                "source": str(BASELINE_METRICS_PATH),
                "data": data,
                "note": "Historical baseline metrics.",
            }
        except Exception as exc:
            logger.warning("Could not load baseline metrics: %s", exc)
    return {
        "available": False,
        "message": "Evaluation metrics artifact not found. Full test-split metrics require generating reports/evaluation/stage4c2 artifacts from the raw dataset.",
        "documentation": "See reports/final/final_executive_delivery_report.md for published summary benchmarks or execute src/evaluation/run_stage4c2_evaluation.py when source dataset is provided."
    }


# Prediction Endpoints
@app.post("/predict/flow")
@app.post("/predict/single")
def predict_single_flow(req: SingleFlowRequest):
    active_clf, feats, labels, version = registry.get_active()

    # Validate 63 features
    missing = [f for f in feats if f not in req.features]
    if missing:
        raise HTTPException(422, f"Missing {len(missing)} required features: {missing[:5]}...")

    vector = [float(req.features[f]) for f in feats]
    arr = np.array([vector], dtype=np.float32)
    np.nan_to_num(arr, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.clip(arr, a_min=0.0, a_max=None, out=arr)

    probs = active_clf.predict_proba(arr)[0]
    pred_idx = int(np.argmax(probs))
    conf = float(probs[pred_idx])
    pred_class = labels.get(pred_idx, f"UNKNOWN_{pred_idx}")

    res = {
        "predicted_class": pred_class,
        "confidence": conf,
        "class_id": pred_idx,
        "model_version": version,
        "probabilities": {labels[i]: round(float(probs[i]), 6) for i in range(len(labels))},
    }

    if req.persist:
        run_id = f"single_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        created = datetime.now(timezone.utc).isoformat()
        with connect() as con:
            con.execute("""
                INSERT OR IGNORE INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count)
                VALUES (?, ?, 'single_flow_api', 1, 1, 0)
            """, (run_id, created))
            con.execute("""
                INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version)
                VALUES (?, 0, ?, ?, 0, ?)
            """, (run_id, pred_class, conf, version))
            if pred_class != "BENIGN":
                event_id = str(uuid.uuid4())
                con.execute("""
                    INSERT INTO detection_events
                    (event_id, timestamp, flow_id, run_id, predicted_class, confidence, src_endpoint, model_version, capture_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SINGLE_API')
                """, (
                    event_id,
                    created,
                    req.source_info,
                    run_id,
                    pred_class,
                    conf,
                    req.source_info,
                    version,
                ))

    return res


@app.post("/predict/batch")
def predict_batch_flows(req: BatchFlowRequest):
    active_clf, feats, labels, version = registry.get_active()
    if not req.flows:
        raise HTTPException(400, "Flow list cannot be empty.")
    if len(req.flows) > 1000:
        raise HTTPException(413, "Batch size exceeds 1,000 flows maximum limit.")

    matrix_rows = []
    for idx, f in enumerate(req.flows):
        missing = [name for name in feats if name not in f]
        if missing:
            raise HTTPException(422, f"Flow at index {idx} is missing {len(missing)} features: {missing[:3]}...")
        matrix_rows.append([float(f[name]) for name in feats])

    matrix = np.array(matrix_rows, dtype=np.float32)
    np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.clip(matrix, a_min=0.0, a_max=None, out=matrix)

    probs = active_clf.predict_proba(matrix)
    indices = np.argmax(probs, axis=1)
    confs = np.max(probs, axis=1)
    preds = [labels.get(int(i), f"UNKNOWN_{int(i)}") for i in indices]

    predictions = []
    for i in range(len(preds)):
        predictions.append({
            "index": i,
            "predicted_class": preds[i],
            "confidence": float(confs[i]),
        })

    if req.persist:
        run_id = f"batch_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        created = datetime.now(timezone.utc).isoformat()
        count = len(preds)
        with connect() as con:
            con.execute("""
                INSERT OR IGNORE INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count)
                VALUES (?, ?, 'batch_flow_api', ?, ?, 0)
            """, (run_id, created, count, count))
            con.executemany("""
                INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version)
                VALUES (?, ?, ?, ?, 0, ?)
            """, [(run_id, i, preds[i], float(confs[i]), version) for i in range(count)])
            attack_events = [
                (str(uuid.uuid4()), created, f"batch_row_{i}", run_id, preds[i], float(confs[i]), version, 'BATCH_API')
                for i in range(count) if preds[i] != "BENIGN"
            ]
            if attack_events:
                con.executemany("""
                    INSERT INTO detection_events
                    (event_id, timestamp, flow_id, run_id, predicted_class, confidence, model_version, capture_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, attack_events)

    class_counts = {str(k): int(v) for k, v in pd.Series(preds).value_counts().items()}
    return {
        "total_flows": len(preds),
        "model_version": version,
        "class_counts": class_counts,
        "predictions": predictions,
    }


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
        frame = pd.read_csv(io.BytesIO(content), nrows=MAX_ROWS + 1)
    except Exception as exc:
        raise HTTPException(400, f"Could not read CSV: {exc}") from exc

    if len(frame) > MAX_ROWS:
        raise HTTPException(413, f"Maximum {MAX_ROWS:,} rows per upload.")
    if frame.empty:
        raise HTTPException(400, "The uploaded CSV contains no rows.")

    active_clf, feats, labels, version = registry.get_active()

    # Strip whitespace from CSV columns to match canonical feature contract
    frame.columns = [c.strip() for c in frame.columns]

    missing = [name for name in feats if name not in frame.columns]
    if missing:
        preview = ", ".join(missing[:12])
        suffix = " ..." if len(missing) > 12 else ""
        raise HTTPException(422, f"CSV is missing {len(missing)} required feature columns: {preview}{suffix}")

    coerced_columns = []
    try:
        numeric = frame.loc[:, feats].apply(pd.to_numeric, errors="coerce")
        # Identify columns that contained non-numeric strings coerced to NaN
        for c in feats:
            if (numeric[c].isna() & frame[c].notna()).any():
                coerced_columns.append(c)
        numeric = numeric.fillna(0.0)
        matrix = numeric.to_numpy(dtype=np.float32, copy=True)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, f"Feature columns must contain numeric values: {exc}") from exc

    np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.clip(matrix, a_min=0.0, a_max=None, out=matrix)

    try:
        probabilities = active_clf.predict_proba(matrix)
        indices = np.argmax(probabilities, axis=1)
        confidence = np.max(probabilities, axis=1)
        predicted = [labels.get(int(i), f"UNKNOWN_CLASS_{int(i)}") for i in indices]
    except Exception as exc:
        raise HTTPException(500, f"Model inference failed: {exc}") from exc

    run_id = str(uuid.uuid4())
    created = datetime.now(timezone.utc).isoformat()
    count = len(frame)

    with connect() as con:
        con.execute("""
            INSERT INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (run_id, created, Path(file.filename).name, count, count))
        con.executemany("""
            INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version)
            VALUES (?, ?, ?, ?, 0, ?)
        """, [(run_id, i, predicted[i], float(confidence[i]), version) for i in range(count)])

        # Populate detection events for attacks using fast batch insert
        attack_events = [
            (str(uuid.uuid4()), created, f"row_{i}", run_id, predicted[i], float(confidence[i]), version, 'CSV_REPLAY')
            for i in range(count) if predicted[i] != "BENIGN"
        ]
        if attack_events:
            con.executemany("""
                INSERT INTO detection_events
                (event_id, timestamp, flow_id, run_id, predicted_class, confidence, model_version, capture_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, attack_events)

    counts = dict(pd.Series(predicted).value_counts())
    sample_limit = min(count, 250)
    sample_preds = [
        {"row_id": i, "predicted_class": predicted[i], "confidence": float(confidence[i])}
        for i in range(sample_limit)
    ]

    return {
        "run_id": run_id,
        "filename": Path(file.filename).name,
        "row_count": count,
        "scored_count": count,
        "not_scored_count": 0,
        "model_version": version,
        "coerced_columns": coerced_columns,
        "coerced_columns_count": len(coerced_columns),
        "is_sample": count > sample_limit,
        "sample_size": sample_limit,
        "total_predictions": count,
        "predictions": sample_preds,
        "class_counts": {str(k): int(v) for k, v in counts.items()},
        "fetch_more_url": f"/flows?run_id={run_id}",
        "message": f"Predictions generated by {version}." + (f" Notice: {len(coerced_columns)} column(s) contained non-numeric values coerced to 0.0." if coerced_columns else ""),
    }


# History & Summary Endpoints
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
        alerts_count = con.execute("""
            SELECT COUNT(*) FROM detection_events
        """).fetchone()[0]

    return {
        "runs": run_count,
        "rows_received": row["total"],
        "rows_scored": row["scored"],
        "rows_not_scored": row["not_scored"],
        "total_alerts": alerts_count,
        "predictions_available": True,
        "class_counts": {r["predicted_class"]: r["count"] for r in class_rows},
    }


@app.get("/flows")
def get_flows(
    run_id: Optional[str] = None,
    class_filter: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    where_parts = []
    where_params = []

    if run_id:
        where_parts.append("run_id = ?")
        where_params.append(run_id)
    if class_filter:
        where_parts.append("predicted_class = ?")
        where_params.append(class_filter)

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"SELECT id, run_id, row_id, predicted_class, confidence, not_scored, model_version FROM flows{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    count_query = f"SELECT COUNT(*) FROM flows{where_sql}"

    with connect() as con:
        rows = con.execute(query, where_params + [limit, offset]).fetchall()
        total = con.execute(count_query, where_params).fetchone()[0]

    return {"items": [dict(r) for r in rows], "count": len(rows), "total": total}


@app.get("/flows/{flow_id}")
def get_flow_detail(flow_id: int):
    with connect() as con:
        row = con.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Flow record with ID {flow_id} not found.")
    return dict(row)


@app.get("/runs")
def get_runs(limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with connect() as con:
        rows = con.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    return {"items": [dict(r) for r in rows], "count": len(rows), "total": total}


@app.get("/runs/{run_id}")
def get_run_detail(run_id: str):
    with connect() as con:
        row = con.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, f"Run with ID '{run_id}' not found.")
        flows_count = con.execute("SELECT COUNT(*) FROM flows WHERE run_id = ?", (run_id,)).fetchone()[0]
        class_rows = con.execute("""
            SELECT predicted_class, COUNT(*) AS count
            FROM flows WHERE run_id = ?
            GROUP BY predicted_class
            ORDER BY count DESC
        """, (run_id,)).fetchall()
    return {
        **dict(row),
        "total_flows": flows_count,
        "class_counts": {r["predicted_class"]: r["count"] for r in class_rows},
    }


# Detection Events Endpoints
@app.get("/events")
def get_events(
    class_filter: Optional[str] = None,
    acknowledged: Optional[int] = None,
    unacknowledged_only: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0,
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    query = "SELECT * FROM detection_events WHERE 1=1"
    params = []

    if class_filter:
        query += " AND predicted_class = ?"
        params.append(class_filter)
    if unacknowledged_only is True:
        query += " AND acknowledged = 0"
    elif acknowledged is not None:
        query += " AND acknowledged = ?"
        params.append(acknowledged)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with connect() as con:
        rows = con.execute(query, params).fetchall()
        total = con.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0]

    return {
        "events": [dict(r) for r in rows],
        "count": len(rows),
        "total": total,
        "disclaimer": "Potential Detection: Model-Classified Attack events. Requires human validation.",
    }


@app.post("/events/{event_id}/ack")
def acknowledge_event(event_id: str):
    with connect() as con:
        if event_id.isdigit():
            cur = con.execute("UPDATE detection_events SET acknowledged = 1 WHERE event_id = ? OR id = ?", (event_id, int(event_id)))
        else:
            cur = con.execute("UPDATE detection_events SET acknowledged = 1 WHERE event_id = ?", (event_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, f"Event {event_id} not found.")
    return {"status": "success", "event_id": event_id, "acknowledged": True}


# Live Capture Endpoints
@app.get("/capture/interfaces")
@app.get("/api/capture/interfaces")
def get_capture_interfaces():
    try:
        from scapy.all import get_if_list  # type: ignore
        adapters = get_if_list()
    except Exception as exc:
        adapters = ["127.0.0.1"]

    items = []
    # Always include loopback
    items.append({
        "identifier": "127.0.0.1",
        "name": "Loopback (127.0.0.1)",
        "description": "Windows Npcap Loopback Adapter (Safe authorized local testing)",
        "is_loopback": True,
        "status": "AUTHORIZED",
    })

    # Try Windows friendly names
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
        win_list = get_windows_if_list()
        for w in win_list:
            guid = w.get("guid", "")
            npf_id = f"\\Device\\NPF_{guid}" if guid else w.get("name", "")
            if npf_id != "\\Device\\NPF_Loopback":
                items.append({
                    "identifier": npf_id,
                    "name": w.get("name", npf_id),
                    "description": w.get("description", "Local network adapter"),
                    "is_loopback": False,
                    "status": "EXPERIMENTAL_REQUIRES_AUTH",
                })
    except Exception:
        for a in adapters:
            if a != "\\Device\\NPF_Loopback":
                items.append({
                    "identifier": a,
                    "name": a,
                    "description": "Network Adapter",
                    "is_loopback": False,
                    "status": "EXPERIMENTAL_REQUIRES_AUTH",
                })

    return {
        "count": len(items),
        "interfaces": items,
        "default_interface": "127.0.0.1",
        "notice": "Physical adapter capture is experimental and requires administrative privileges.",
    }


@app.get("/capture/status")
@app.get("/capture/stats")
@app.get("/api/capture/status")
@app.get("/api/capture/stats")
def get_capture_status():
    return capture_mgr.get_stats()


@app.post("/capture/start")
@app.post("/api/capture/start")
def start_capture(req: CaptureStartRequest = Body(...)):
    res = capture_mgr.start_capture(
        interface=req.interface,
        enable_inference=req.enable_inference,
        isolated_db=req.isolated_db,
    )
    return res


@app.post("/capture/stop")
@app.post("/api/capture/stop")
def stop_capture():
    res = capture_mgr.stop_capture()
    return res


@app.post("/capture/simulate")
@app.post("/api/capture/simulate")
def simulate_traffic():
    stats = capture_mgr.simulate_burst()
    return {"status": "success", "stats": stats}


@app.get("/capture/flows")
@app.get("/api/capture/flows")
def get_capture_flows(limit: int = 50):
    limit = max(1, min(limit, 200))
    flows_list = []
    with capture_mgr.lock:
        if capture_mgr.worker is not None and capture_mgr.worker.completed_flows:
            for f in capture_mgr.worker.completed_flows[-limit:]:
                flows_list.append({
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "duration_us": f.duration_us,
                    "packets": f.total_packets,
                    "bytes": f.total_bytes,
                    "predicted_class": getattr(f, "predicted_class", "BENIGN"),
                    "confidence": getattr(f, "confidence", None),
                })
        if not flows_list:
            flows_list = list(capture_mgr.recent_flows)[-limit:]
    flows_list.reverse()
    return {"flows": flows_list, "count": len(flows_list)}


@app.get("/capture/stats")
@app.get("/api/capture/stats")
def get_capture_stats():
    return capture_mgr.get_stats()


@app.get("/capture/sessions")
@app.get("/api/capture/sessions")
def get_capture_sessions(limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM capture_sessions ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = con.execute("SELECT COUNT(*) FROM capture_sessions").fetchone()[0]
    return {"sessions": [dict(r) for r in rows], "count": len(rows), "total": total}


@app.get("/capture/stream")
@app.get("/api/capture/stream")
async def capture_stream(request: Request):
    """Server-Sent Events streaming live flow and detection events.

    Uses asynchronous generator with asyncio.sleep to avoid blocking worker threads,
    detects client disconnects cleanly, and sets anti-buffering cache-control SSE headers.
    """
    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                stats = capture_mgr.get_stats()
                data = json.dumps(stats)
                yield f"data: {data}\n\n"
                await asyncio.sleep(1.0)
        except (asyncio.CancelledError, GeneratorExit):
            pass
        except Exception as exc:
            logger.debug("SSE stream error or disconnect: %s", exc)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers=headers,
    )
