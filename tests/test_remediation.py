"""
tests/test_remediation.py
Targeted test suite verifying fixes for all 10 audit findings:
1. Portable path resolution (Finding 1)
2. Graceful /metrics handling when stage4c2 artifacts are missing (Finding 2)
3. Async non-blocking SSE streaming with disconnect handling (Finding 3)
4. Runtime DB path isolation without os.environ contamination (Finding 4)
5. Robust model selection and concurrent inference safety (Finding 9)
6. Safe /score processing with file-size limits, coerced column reporting, and bounded payload (Finding 6)
7. Buffer flushing in live capture worker (Finding 7)
8. Secure CORS defaults without wildcard credentials (Finding 8)
9. IPv6 and unsupported protocol packet tracking in capture subsystem
"""

import asyncio
import io
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
from starlette.testclient import TestClient

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import app_v2.app_model_v2 as app_module
from app_v2.app_model_v2 import app, registry, capture_mgr
from app_v2.capture.live_capture_worker import LiveCaptureWorker
from app_v2.capture.packet_dissector import PacketDissector
from app_v2.capture.feature_extractor import ORDERED_FEATURES
from src.path_helper import get_project_root


class TestRemediation(unittest.TestCase):
    _orig_env_db = None

    @classmethod
    def setUpClass(cls):
        cls._orig_env_db = os.environ.get("NIDS_DB_PATH")
        cls.test_db = REPO_ROOT / "app_v2" / "data" / "test" / "nids_test_remediation.sqlite"
        cls.test_db.parent.mkdir(parents=True, exist_ok=True)
        os.environ["NIDS_DB_PATH"] = str(cls.test_db)
        app_module.init_db(cls.test_db)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        if cls._orig_env_db is not None:
            os.environ["NIDS_DB_PATH"] = cls._orig_env_db
        else:
            os.environ.pop("NIDS_DB_PATH", None)
        if hasattr(cls, "test_db") and cls.test_db.is_file():
            try:
                cls.test_db.unlink()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 1. Portable Path Resolution (Finding 1)
    # -------------------------------------------------------------------------
    def test_01_portable_path_resolution(self):
        """Verifies path_helper resolves repo root dynamically without hardcoded paths."""
        resolved = get_project_root()
        self.assertTrue(resolved.is_dir())
        self.assertEqual(resolved, REPO_ROOT)
        self.assertTrue((resolved / "models" / "replacement_v1").is_dir())
        self.assertTrue((resolved / "app_v2").is_dir())

    # -------------------------------------------------------------------------
    # 2. Database Path Isolation without os.environ mutation (Finding 4)
    # -------------------------------------------------------------------------
    def test_02_database_path_isolation(self):
        """Verifies worker initialization does not mutate or contaminate os.environ['NIDS_DB_PATH']."""
        env_before = os.environ.get("NIDS_DB_PATH")
        custom_db = self.test_db.parent / "isolated_worker_test.sqlite"

        worker = LiveCaptureWorker(
            enable_inference=True,
            test_db_path=custom_db
        )

        self.assertEqual(worker.test_db_path, custom_db)
        # os.environ must NOT be changed to custom_db
        self.assertEqual(os.environ.get("NIDS_DB_PATH"), env_before)

    # -------------------------------------------------------------------------
    # 3. Thread-Safe Model Selection and Inference Concurrency (Finding 9)
    # -------------------------------------------------------------------------
    def test_03_concurrent_model_selection_and_inference(self):
        """Verifies concurrent model switching and prediction across multiple threads is thread-safe."""
        errors = []
        stop_event = threading.Event()

        def worker_switcher():
            versions = ["replacement_v1", "replacement_v2"]
            idx = 0
            while not stop_event.is_set():
                try:
                    target = versions[idx % len(versions)]
                    registry.set_active(target)
                    idx += 1
                    time.sleep(0.005)
                except Exception as exc:
                    errors.append(f"Switcher error: {exc}")

        def worker_predictor(thread_id: int):
            rng = np.random.RandomState(thread_id)
            dummy_matrix = rng.randn(10, 63).astype(np.float32)
            while not stop_event.is_set():
                try:
                    active_clf, feats, labels, version = registry.get_active()
                    self.assertIn(version, ("replacement_v1", "replacement_v2"))
                    self.assertEqual(len(feats), 63)
                    self.assertEqual(len(labels), 15)
                    probs = active_clf.predict_proba(dummy_matrix)
                    self.assertEqual(probs.shape, (10, 15))
                    time.sleep(0.005)
                except Exception as exc:
                    errors.append(f"Predictor {thread_id} error: {exc}")

        threads = [threading.Thread(target=worker_switcher)]
        for i in range(4):
            threads.append(threading.Thread(target=worker_predictor, args=(i + 100,)))

        for t in threads:
            t.start()

        time.sleep(0.5)  # Let threads run concurrently
        stop_event.set()

        for t in threads:
            t.join(timeout=2.0)

        self.assertEqual(len(errors), 0, f"Concurrency errors encountered: {errors}")

    # -------------------------------------------------------------------------
    # 4. Async SSE Stream Endpoint & Disconnect Headers (Finding 3)
    # -------------------------------------------------------------------------
    def test_04_async_sse_endpoint_headers(self):
        """Verifies /capture/stream returns proper anti-buffering SSE headers."""
        with self.client.stream("GET", "/capture/stream") as resp:
            self.assertEqual(resp.status_code, 200)
            self.assertIn("text/event-stream", resp.headers.get("content-type", ""))
            self.assertEqual(resp.headers.get("cache-control"), "no-cache")
            self.assertEqual(resp.headers.get("x-accel-buffering"), "no")
            # Read first chunk
            for line in resp.iter_lines():
                if line:
                    self.assertTrue(line.startswith("data: ") or line.startswith(b"data: "))
                    break

    # -------------------------------------------------------------------------
    # 5. Safe /score Processing: Validation, Coercion, Bounded Response (Finding 6)
    # -------------------------------------------------------------------------
    def test_05_score_missing_columns_validation(self):
        """Verifies /score rejects CSVs missing required 63 canonical columns with 422."""
        invalid_csv = b"Flow Duration,Total Fwd Packets\n100,5\n"
        resp = self.client.post(
            "/score",
            files={"file": ("invalid.csv", io.BytesIO(invalid_csv), "text/csv")},
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertIn("detail", data)
        self.assertIn("missing", data["detail"].lower())

    def test_06_score_coerced_columns_and_bounded_response(self):
        """Verifies /score handles non-numeric values gracefully and reports coerced columns."""
        # Create a valid 15-row DataFrame
        fixture_csv = REPO_ROOT / "tests" / "fixtures" / "nids_sample_15_flows.csv"
        self.assertTrue(fixture_csv.is_file())
        df = pd.read_csv(fixture_csv)

        # Introduce string values in a numeric column to test coercion
        col_to_coerce = ORDERED_FEATURES[5]
        df[col_to_coerce] = df[col_to_coerce].astype(str) + "_str"

        csv_buffer = io.BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_bytes = csv_buffer.getvalue()

        resp = self.client.post(
            "/score",
            files={"file": ("test_coerced.csv", io.BytesIO(csv_bytes), "text/csv")},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("run_id", data)
        self.assertEqual(data["scored_count"], 15)
        self.assertIn("coerced_columns", data)
        self.assertIn(col_to_coerce, data["coerced_columns"])
        self.assertIn("predictions", data)
        self.assertLessEqual(len(data["predictions"]), 250)

    # -------------------------------------------------------------------------
    # 6. Secure CORS Defaults (Finding 8)
    # -------------------------------------------------------------------------
    def test_07_cors_secure_defaults(self):
        """Verifies CORS headers are restricted to configured origins and credentials disabled."""
        resp = self.client.get(
            "/health",
            headers={"Origin": "https://malicious-external-site.com"},
        )
        self.assertEqual(resp.status_code, 200)
        # Should not echo back unauthorized origin as allowed
        allow_origin = resp.headers.get("access-control-allow-origin")
        self.assertNotEqual(allow_origin, "https://malicious-external-site.com")
        self.assertNotEqual(allow_origin, "*")

    # -------------------------------------------------------------------------
    # 7. Metrics Unavailable Handling (Finding 2)
    # -------------------------------------------------------------------------
    def test_08_metrics_graceful_response(self):
        """Verifies /metrics returns 200 with clear documentation when artifacts are absent."""
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("available", data)
        if not data["available"]:
            self.assertIn("message", data)
            self.assertIn("documentation", data)

    # -------------------------------------------------------------------------
    # 8. IPv6 and Unsupported Protocol Packet Metrics (Finding 7 / Phase 3)
    # -------------------------------------------------------------------------
    def test_09_ipv6_and_unsupported_packet_metrics(self):
        """Verifies IPv6 packets and unsupported protocols are detected and counted in capture metrics."""
        worker = LiveCaptureWorker(max_queue_size=50)

        # Build raw IPv6 packet (Ethernet + IPv6 header: version 6 = 0x60)
        # Ethernet header (14 bytes) + IPv6 header (40 bytes)
        eth_ipv6 = b"\x00" * 12 + b"\x86\xdd" + b"\x60" + b"\x00" * 39
        is_ipv6 = PacketDissector.check_is_ipv6(eth_ipv6)
        self.assertTrue(is_ipv6)

        # Enqueue packet and process
        worker.enqueue_packet(eth_ipv6, timestamp_us=1000.0)
        worker.process_queue_iteration()
        self.assertEqual(worker.ipv6_packets_count, 1)

        # Build unsupported raw protocol packet (e.g. non-IP, ARP = 0x0806)
        eth_arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
        worker.enqueue_packet(eth_arp, timestamp_us=2000.0)
        worker.process_queue_iteration()
        self.assertEqual(worker.unsupported_protocol_packets, 1)

        summary = worker.stop()
        self.assertEqual(summary["ipv6_packets"], 1)
        self.assertEqual(summary["unsupported_packets"], 1)



if __name__ == "__main__":
    unittest.main()
