"""
test_api_v2.py
Comprehensive automated test suite for the FastAPI backend (app_v2/app_model_v2.py):
- Health & Readiness endpoints
- Model info & model switching (replacement_v1 vs replacement_v2)
- Single flow and batch prediction with 63-feature validation
- Error handling for malformed / incomplete inputs
- Flow and event retrieval endpoints
- Capture interface discovery & start/stop lifecycle
- Strict isolation guarding the production database
"""

import hashlib
import json
import os
from pathlib import Path
import unittest

from fastapi import HTTPException

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
TEST_DB = REPO_ROOT / "app_v2" / "data" / "test" / "nids_test_api_unit.sqlite"
PROD_DB = REPO_ROOT / "app_v2" / "data" / "nids.sqlite"

EXPECTED_PROD_DB_HASH = "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D"

# Set environment variable to test database before importing app
os.environ["NIDS_DB_PATH"] = str(TEST_DB)

import app_v2.app_model_v2 as app_module
from app_v2.app_model_v2 import (
    SingleFlowRequest,
    BatchFlowRequest,
    CaptureStartRequest,
    ModelSelectRequest,
)


def sha256_file(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest().upper()


class TestApiV2(unittest.TestCase):
    _orig_env = None

    @classmethod
    def setUpClass(cls):
        cls._orig_env = os.environ.get("NIDS_DB_PATH")
        os.environ["NIDS_DB_PATH"] = str(TEST_DB)
        TEST_DB.parent.mkdir(parents=True, exist_ok=True)
        app_module.init_db(TEST_DB)

    @classmethod
    def tearDownClass(cls):
        if cls._orig_env is not None:
            os.environ["NIDS_DB_PATH"] = cls._orig_env
        else:
            os.environ.pop("NIDS_DB_PATH", None)
        if TEST_DB.is_file():
            try:
                TEST_DB.unlink()
            except Exception:
                pass

    def setUp(self):
        os.environ["NIDS_DB_PATH"] = str(TEST_DB)

    def test_01_health_and_ready_endpoints(self):
        """Verifies health() and readiness() return expected service metadata."""
        data_h = app_module.health()
        self.assertEqual(data_h["status"], "ok")
        self.assertEqual(data_h["application"], "NIDS")
        self.assertIn("replacement_v2", data_h["models_available"])
        self.assertEqual(data_h["feature_count"], 63)
        self.assertEqual(data_h["class_count"], 15)

        data_r = app_module.readiness()
        self.assertEqual(data_r["status"], "ready")
        self.assertEqual(data_r["classes_loaded"], 15)
        self.assertEqual(data_r["features_contract"], 63)

    def test_02_model_info_and_switch(self):
        """Verifies model_info() and select_model() allow switching between V1 and V2."""
        data_info = app_module.model_info()
        self.assertIn("replacement_v1", data_info["available_models"])
        self.assertIn("replacement_v2", data_info["available_models"])
        self.assertEqual(len(data_info["classes"]), 15)

        # Switch to replacement_v1
        res_v1 = app_module.select_model(ModelSelectRequest(model_version="replacement_v1"))
        self.assertEqual(res_v1["active_model"], "replacement_v1")

        # Switch back to replacement_v2
        res_v2 = app_module.select_model(ModelSelectRequest(model_version="replacement_v2"))
        self.assertEqual(res_v2["active_model"], "replacement_v2")

        # Invalid version raises HTTPException 400
        with self.assertRaises(HTTPException) as ctx:
            app_module.select_model(ModelSelectRequest(model_version="non_existent_model"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_03_features_endpoint(self):
        """Verifies get_features() returns the 63 canonical feature names."""
        data = app_module.get_features()
        self.assertEqual(data["count"], 63)
        self.assertEqual(len(data["features"]), 63)
        self.assertIn("Flow Duration", data["features"])
        self.assertIn("Destination Port", data["features"])

    def test_04_predict_single_flow_valid(self):
        """Verifies predict_single_flow() classifies a valid 63-feature dictionary."""
        feats = app_module.MODEL_FEATURES
        valid_vector = {f: 0.0 for f in feats}
        valid_vector["Destination Port"] = 80.0
        valid_vector["Flow Duration"] = 1000.0

        req = SingleFlowRequest(features=valid_vector, persist=True)
        data = app_module.predict_single_flow(req)
        self.assertIn("predicted_class", data)
        self.assertIn("confidence", data)
        self.assertIn("probabilities", data)
        self.assertEqual(len(data["probabilities"]), 15)
        self.assertGreaterEqual(data["confidence"], 0.0)
        self.assertLessEqual(data["confidence"], 1.0)

    def test_05_predict_single_flow_missing_features(self):
        """Verifies predict_single_flow() rejects payloads missing required features with 422."""
        incomplete_vector = {"Destination Port": 80.0}
        req = SingleFlowRequest(features=incomplete_vector)
        with self.assertRaises(HTTPException) as ctx:
            app_module.predict_single_flow(req)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_06_predict_batch_flows(self):
        """Verifies predict_batch_flows() scores bounded batches of flows."""
        feats = app_module.MODEL_FEATURES
        flow1 = {f: 0.0 for f in feats}
        flow2 = {f: 10.0 for f in feats}

        req = BatchFlowRequest(flows=[flow1, flow2])
        data = app_module.predict_batch_flows(req)
        self.assertEqual(data["total_flows"], 2)
        self.assertEqual(len(data["predictions"]), 2)
        self.assertIn("class_counts", data)

        # Empty batch raises 400
        with self.assertRaises(HTTPException) as ctx:
            app_module.predict_batch_flows(BatchFlowRequest(flows=[]))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_07_summary_and_flows_endpoints(self):
        """Verifies summary() and get_flows() return valid data structures."""
        data_sum = app_module.summary()
        self.assertIn("runs", data_sum)
        self.assertIn("rows_received", data_sum)
        self.assertIn("class_counts", data_sum)

        data_flows = app_module.get_flows(limit=10)
        self.assertIn("items", data_flows)
        self.assertIn("total", data_flows)

    def test_08_capture_interfaces_discovery(self):
        """Verifies get_capture_interfaces() discovers available network adapters."""
        data = app_module.get_capture_interfaces()
        self.assertGreaterEqual(data["count"], 1)
        self.assertEqual(data["default_interface"], "127.0.0.1")

        # Confirm loopback adapter is present and marked AUTHORIZED
        loopback = [i for i in data["interfaces"] if i["is_loopback"]]
        self.assertTrue(len(loopback) > 0)
        self.assertEqual(loopback[0]["status"], "AUTHORIZED")

    def test_09_capture_lifecycle_endpoints(self):
        """Verifies capture status and clean start/stop lifecycle."""
        # Initial status
        data_status = app_module.get_capture_status()
        self.assertEqual(data_status["status"], "STOPPED")

        # Start capture on loopback with isolated test database
        req_start = CaptureStartRequest(
            interface="127.0.0.1",
            enable_inference=False,
            isolated_db=True,
        )
        data_start = app_module.start_capture(req_start)
        self.assertEqual(data_start["status"], "STARTED")

        # Check running status
        data_running = app_module.get_capture_status()
        self.assertEqual(data_running["status"], "RUNNING")

        # Stop capture
        data_stop = app_module.stop_capture()
        self.assertEqual(data_stop["status"], "STOPPED")

        # Check final status
        data_final = app_module.get_capture_status()
        self.assertEqual(data_final["status"], "STOPPED")

    def test_10_production_database_isolation(self):
        """Critical Invariant: Production database must remain 100% untouched."""
        self.assertTrue(PROD_DB.is_file())
        self.assertEqual(sha256_file(PROD_DB), EXPECTED_PROD_DB_HASH)

    def test_11_single_flow_persist_foreign_key_integrity(self):
        """Verifies predict_single_flow with persist=True creates parent runs row."""
        feats = app_module.MODEL_FEATURES
        valid_vector = {f: 0.0 for f in feats}
        valid_vector["Destination Port"] = 443.0
        req = SingleFlowRequest(features=valid_vector, persist=True, source_info="127.0.0.1:443")
        res = app_module.predict_single_flow(req)
        self.assertIn("predicted_class", res)

        with app_module.connect(TEST_DB) as con:
            flow_row = con.execute("SELECT * FROM flows ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(flow_row)
            run_row = con.execute("SELECT * FROM runs WHERE run_id = ?", (flow_row["run_id"],)).fetchone()
            self.assertIsNotNone(run_row, "Orphan flow: runs row missing for single flow prediction")
            self.assertEqual(run_row["filename"], "single_flow_api")

    def test_12_batch_flow_persist(self):
        """Verifies predict_batch_flows with persist=True records batch to runs and flows."""
        feats = app_module.MODEL_FEATURES
        flow1 = {f: 0.0 for f in feats}
        flow2 = {f: 5.0 for f in feats}
        req = BatchFlowRequest(flows=[flow1, flow2], persist=True)
        res = app_module.predict_batch_flows(req)
        self.assertEqual(res["total_flows"], 2)

        with app_module.connect(TEST_DB) as con:
            batch_run = con.execute("SELECT * FROM runs WHERE filename = 'batch_flow_api' ORDER BY created_at DESC LIMIT 1").fetchone()
            self.assertIsNotNone(batch_run, "batch_flow_api run record missing")
            flows_count = con.execute("SELECT COUNT(*) FROM flows WHERE run_id = ?", (batch_run["run_id"],)).fetchone()[0]
            self.assertEqual(flows_count, 2)

    def test_13_csv_score_whitespace_headers(self):
        """Verifies score() handles CSV files with leading/trailing whitespace in header names."""
        import asyncio
        import io
        from fastapi import UploadFile
        import pandas as pd

        feats = app_module.MODEL_FEATURES
        df_sample = pd.DataFrame([{f: float(i % 5) for f in feats} for i in range(5)])
        df_sample.columns = [" " + c + " " for c in df_sample.columns]
        csv_bytes = df_sample.to_csv(index=False).encode("utf-8")

        upload = UploadFile(filename="whitespace_test.csv", file=io.BytesIO(csv_bytes))
        res = asyncio.run(app_module.score(upload))
        self.assertEqual(res["row_count"], 5)
        self.assertEqual(res["scored_count"], 5)

    def test_14_flows_filter_total_count(self):
        """Verifies get_flows accurately computes total count matching active filter."""
        # Insert a run with 3 flows and another with 2 flows
        run_a = "test_run_filter_a"
        run_b = "test_run_filter_b"
        with app_module.connect(TEST_DB) as con:
            con.execute("DELETE FROM flows WHERE run_id IN (?, ?)", (run_a, run_b))
            con.execute("DELETE FROM runs WHERE run_id IN (?, ?)", (run_a, run_b))
            con.execute("INSERT INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count) VALUES (?, '2026-10-12', 'a.csv', 3, 3, 0)", (run_a,))
            con.execute("INSERT INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count) VALUES (?, '2026-10-12', 'b.csv', 2, 2, 0)", (run_b,))
            for i in range(3):
                con.execute("INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version) VALUES (?, ?, 'BENIGN', 0.99, 0, 'v2')", (run_a, i))
            for i in range(2):
                con.execute("INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version) VALUES (?, ?, 'BENIGN', 0.99, 0, 'v2')", (run_b, i))

        data = app_module.get_flows(run_id=run_a, limit=2)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["total"], 3)  # Filtered total must be 3, not total count of all flows in DB

    def test_15_events_ack_numeric_and_uuid(self):
        """Verifies acknowledge_event supports both UUID event_id and integer primary key id."""
        import uuid
        ev_uuid = str(uuid.uuid4())
        with app_module.connect(TEST_DB) as con:
            con.execute("""
                INSERT INTO detection_events
                (event_id, timestamp, flow_id, run_id, predicted_class, confidence, src_endpoint, dst_endpoint, protocol, model_version, capture_mode, acknowledged)
                VALUES (?, '2026-10-12T00:00:00Z', 'flow_x', 'run_x', 'DDoS', 0.98, '127.0.0.1:80', '127.0.0.1:8080', 'TCP', 'v2', 'TEST', 0)
            """, (ev_uuid,))
            int_id = con.execute("SELECT id FROM detection_events WHERE event_id = ?", (ev_uuid,)).fetchone()[0]

        # Acknowledge via integer ID (as triggered by frontend UI)
        res_int = app_module.acknowledge_event(str(int_id))
        self.assertTrue(res_int["acknowledged"])

        # Reset and acknowledge via UUID string
        with app_module.connect(TEST_DB) as con:
            con.execute("UPDATE detection_events SET acknowledged = 0 WHERE id = ?", (int_id,))

        res_uuid = app_module.acknowledge_event(ev_uuid)
        self.assertTrue(res_uuid["acknowledged"])

    def test_16_flow_properties_and_telemetry_keys(self):
        """Verifies Flow dataclass properties and capture status telemetry keys."""
        from app_v2.capture.flow_tracker import Flow

        f = Flow(
            key=("127.0.0.1", "127.0.0.1", 4000, 80, 6),
            start_time_us=1000.0,
            last_time_us=5000.0,
            fwd_src_ip="127.0.0.1",
            fwd_dst_ip="127.0.0.1",
            fwd_src_port=4000,
            fwd_dst_port=80,
            protocol=6,
            total_fwd_packets=2,
            total_bwd_packets=3,
            total_fwd_bytes=100,
            total_bwd_bytes=200,
        )
        self.assertEqual(f.flow_id, "127.0.0.1:4000-127.0.0.1:80-6")
        self.assertEqual(f.src_ip, "127.0.0.1")
        self.assertEqual(f.dst_ip, "127.0.0.1")
        self.assertEqual(f.src_port, 4000)
        self.assertEqual(f.dst_port, 80)
        self.assertEqual(f.duration_us, 4000.0)
        self.assertEqual(f.total_packets, 5)
        self.assertEqual(f.total_bytes, 300)

        # Telemetry keys check
        status = app_module.get_capture_status()
        required_keys = ["packets_captured", "flows_classified", "attacks_detected", "active_flows", "elapsed_seconds"]
        for k in required_keys:
            self.assertIn(k, status, f"Missing telemetry key: {k}")

    def test_17_get_run_detail_endpoint(self):
        """Verifies get_run_detail returns metadata and class breakdown, or 404."""
        run_id = "test_detail_run_123"
        with app_module.connect(TEST_DB) as con:
            con.execute("DELETE FROM flows WHERE run_id = ?", (run_id,))
            con.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            con.execute("INSERT INTO runs (run_id, created_at, filename, row_count, scored_count, not_scored_count) VALUES (?, '2026-10-12T00:00:00Z', 'detail.csv', 1, 1, 0)", (run_id,))
            con.execute("INSERT INTO flows (run_id, row_id, predicted_class, confidence, not_scored, model_version) VALUES (?, 0, 'PortScan', 0.95, 0, 'v2')", (run_id,))

        detail = app_module.get_run_detail(run_id)
        self.assertEqual(detail["run_id"], run_id)
        self.assertEqual(detail["filename"], "detail.csv")
        self.assertEqual(detail["total_flows"], 1)
        self.assertIn("PortScan", detail["class_counts"])

        # Non-existent run raises 404
        with self.assertRaises(HTTPException) as ctx:
            app_module.get_run_detail("non_existent_run_xyz")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_18_batch_flow_json_serializability(self):
        """Verifies predict_batch_flows returns JSON-serializable types (no raw np.int64 in class_counts)."""
        feats = app_module.MODEL_FEATURES
        flow1 = {f: 0.0 for f in feats}
        flow2 = {f: 1.0 for f in feats}
        req = BatchFlowRequest(flows=[flow1, flow2], persist=False)
        res = app_module.predict_batch_flows(req)
        serialized = json.dumps(res)
        self.assertIn("class_counts", serialized)
        for k, v in res["class_counts"].items():
            self.assertIsInstance(v, int, f"class_counts[{k}] should be standard python int, got {type(v)}")

    def test_19_model_and_predict_aliases(self):
        """Verifies route handlers for /model and /predict/single aliases work correctly."""
        info = app_module.model_info()
        self.assertIn("active_model", info)

        feats = app_module.MODEL_FEATURES
        req = SingleFlowRequest(features={f: 0.0 for f in feats}, persist=False)
        res = app_module.predict_single_flow(req)
        self.assertIn("predicted_class", res)

    def test_20_capture_route_aliases_and_prefixes(self):
        """Verifies capture routes and /api/ prefixes are all registered to prevent 404s."""
        route_paths = [getattr(r, "path", "") for r in app_module.app.routes]
        expected_capture_routes = [
            "/capture/start",
            "/api/capture/start",
            "/capture/stop",
            "/api/capture/stop",
            "/capture/status",
            "/capture/stats",
            "/api/capture/status",
            "/api/capture/stats",
            "/capture/interfaces",
            "/api/capture/interfaces",
            "/capture/sessions",
            "/api/capture/sessions",
            "/capture/flows",
            "/api/capture/flows",
        ]
        for route in expected_capture_routes:
            self.assertIn(route, route_paths, f"Missing route registration: {route}")

    def test_21_capture_start_unauthorized_interface_rejection(self):
        """Verifies start_capture rejects non-loopback interface with HTTP 403."""
        req = CaptureStartRequest(interface="192.168.1.100", enable_inference=False, isolated_db=True)
        with self.assertRaises(HTTPException) as ctx:
            app_module.start_capture(req)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("strictly restricted to Windows loopback", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()

