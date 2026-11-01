"""
test_stage4b.py
Comprehensive Verification Test Suite for NIDS Stage 4B Live Capture & Flow Extraction.

Covers:
1. Exact 63-feature schema & ordering parity against selected_features.txt.
2. Synthetic packet parsing & known packet counts.
3. Bidirectional flow pairing & direction assignment.
4. TCP FIN/RST teardown & UDP behavior.
5. Timeout expiration & partial flow flushing on shutdown.
6. Invalid, negative, and non-finite feature value handling (zero-filling).
7. Bounded queue overflow & clean shutdown.
8. Capture driver unavailable & permission error handling.
9. Isolated test database persistence (nids_test_live_4b.sqlite).
10. Existing CSV demo regression (nids_stage3b_plumbing_15.csv).
11. Production database, backup, and model hash preservation.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import struct
import unittest

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app_v2.capture.packet_dissector import DissectedPacket, PacketDissector
from app_v2.capture.flow_tracker import Flow, FlowTracker
from app_v2.capture.feature_extractor import FeatureExtractor, ORDERED_FEATURES, EXTRACTOR_STATUS
from app_v2.capture.live_capture_worker import (
    LiveCaptureWorker,
    check_capture_prerequisites,
    resolve_adapter_name,
)
from app_v2.run_live_capture import build_synthetic_tcp_packet


# Reference baseline hashes
HASH_PROD_DB = "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D"
HASH_LEGACY_PROD_DB = "F4C2CD0AC83EFBBC2D01045A67D9E98BCAE6505CD1D32F4E4455A612D6DF8E24"
HASH_BACKUP_DB = "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D"
HASH_MODEL_JSON = "36667EABAAA5F363AA2F3578B71629AE4402FA41676BC52C2D59C539437544A3"


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hash using read-only shared stream."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


class TestStage4BLiveCapture(unittest.TestCase):

    def setUp(self):
        self.test_db_path = REPO_ROOT / "app_v2" / "data" / "test" / "nids_test_live_4b.sqlite"
        self.test_db_path.parent.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------------------------
    # 1. Feature Schema & Exact Ordering
    # --------------------------------------------------------------------------
    def test_01_feature_schema_and_exact_ordering(self):
        selected_file = REPO_ROOT / "models" / "replacement_v1" / "selected_features.txt"
        self.assertTrue(selected_file.is_file(), "selected_features.txt must exist.")
        expected_features = [
            line.strip()
            for line in selected_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(expected_features), 63, "Expected exactly 63 selected features.")
        self.assertEqual(len(ORDERED_FEATURES), 63, "ORDERED_FEATURES must contain exactly 63 features.")
        self.assertEqual(ORDERED_FEATURES, expected_features, "ORDERED_FEATURES must match selected_features.txt 1-to-1.")

        # Test extraction output keys and order
        dummy_flow = Flow(
            key=("127.0.0.1", "127.0.0.1", 12345, 80, 6),
            start_time_us=1000.0,
            last_time_us=2000.0,
            fwd_src_ip="127.0.0.1",
            fwd_dst_ip="127.0.0.1",
            fwd_src_port=12345,
            fwd_dst_port=80,
            protocol=6
        )
        extracted = FeatureExtractor.extract_features(dummy_flow)
        self.assertEqual(list(extracted.keys()), expected_features, "Extracted dict keys must strictly match expected sequence.")

    # --------------------------------------------------------------------------
    # 2. Synthetic Packet Parsing & Known Packet Counts
    # --------------------------------------------------------------------------
    def test_02_synthetic_packet_dissection(self):
        # Build synthetic TCP SYN packet (Client 192.168.1.10:50000 -> Server 10.0.0.1:443)
        raw_pkt = build_synthetic_tcp_packet(
            src_ip="192.168.1.10", dst_ip="10.0.0.1",
            src_port=50000, dst_port=443,
            flags=0x02,  # SYN
            payload=b"",
            seq=1234, ack=0, window=16384
        )
        dissected = PacketDissector.dissect_ipv4_packet(raw_pkt, timestamp_us=5000.0)
        self.assertIsNotNone(dissected, "Packet must dissect successfully.")
        self.assertEqual(dissected.src_ip, "192.168.1.10")
        self.assertEqual(dissected.dst_ip, "10.0.0.1")
        self.assertEqual(dissected.src_port, 50000)
        self.assertEqual(dissected.dst_port, 443)
        self.assertEqual(dissected.protocol, 6)
        self.assertEqual(dissected.tcp_flags["SYN"], 1)
        self.assertEqual(dissected.tcp_flags["ACK"], 0)
        self.assertEqual(dissected.tcp_window, 16384)
        self.assertEqual(dissected.payload_length, 0)
        self.assertEqual(dissected.total_header_length, 40)  # 20 IP + 20 TCP

    # --------------------------------------------------------------------------
    # 3. Bidirectional Flow Pairing & Direction Assignment
    # --------------------------------------------------------------------------
    def test_03_bidirectional_flow_pairing(self):
        tracker = FlowTracker()

        # Packet 1: Forward (Client -> Server)
        p1 = DissectedPacket(
            timestamp_us=1000.0, src_ip="10.0.0.5", dst_ip="10.0.0.8",
            src_port=49152, dst_port=80, protocol=6,
            ip_header_length=20, l4_header_length=20, total_header_length=40,
            payload_length=50, tcp_flags={"FIN": 0, "SYN": 1, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0},
            tcp_window=64240
        )
        # Packet 2: Backward (Server -> Client)
        p2 = DissectedPacket(
            timestamp_us=2000.0, src_ip="10.0.0.8", dst_ip="10.0.0.5",
            src_port=80, dst_port=49152, protocol=6,
            ip_header_length=20, l4_header_length=20, total_header_length=40,
            payload_length=200, tcp_flags={"FIN": 0, "SYN": 1, "RST": 0, "PSH": 0, "ACK": 1, "URG": 0, "ECE": 0, "CWR": 0},
            tcp_window=29200
        )

        res1 = tracker.process_packet(p1)
        res2 = tracker.process_packet(p2)
        self.assertIsNone(res1, "Active flow should remain in memory.")
        self.assertIsNone(res2, "Active flow should remain in memory.")
        self.assertEqual(len(tracker.flows), 1, "Both packets must be paired into exactly 1 bidirectional flow.")

        flow = list(tracker.flows.values())[0]
        self.assertEqual(flow.total_fwd_packets, 1)
        self.assertEqual(flow.total_bwd_packets, 1)
        self.assertEqual(flow.total_fwd_bytes, 50)
        self.assertEqual(flow.total_bwd_bytes, 200)
        self.assertEqual(flow.init_win_fwd, 64240)
        self.assertEqual(flow.init_win_bwd, 29200)
        self.assertEqual(flow.fwd_dst_port, 80)

    # --------------------------------------------------------------------------
    # 4. TCP FIN/RST Teardown and UDP Behavior
    # --------------------------------------------------------------------------
    def test_04_tcp_fin_rst_and_udp_behavior(self):
        # 4a. TCP RST Teardown
        tracker_tcp = FlowTracker()
        p_syn = DissectedPacket(
            timestamp_us=100.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1000, dst_port=80, protocol=6,
            ip_header_length=20, l4_header_length=20, total_header_length=40,
            payload_length=0, tcp_flags={"FIN": 0, "SYN": 1, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0}
        )
        p_rst = DissectedPacket(
            timestamp_us=200.0, src_ip="2.2.2.2", dst_ip="1.1.1.1",
            src_port=80, dst_port=1000, protocol=6,
            ip_header_length=20, l4_header_length=20, total_header_length=40,
            payload_length=0, tcp_flags={"FIN": 0, "SYN": 0, "RST": 1, "PSH": 0, "ACK": 1, "URG": 0, "ECE": 0, "CWR": 0}
        )
        tracker_tcp.process_packet(p_syn)
        completed_tcp = tracker_tcp.process_packet(p_rst)
        self.assertIsNotNone(completed_tcp, "TCP RST must trigger immediate flow completion.")
        self.assertEqual(completed_tcp.teardown_reason, "tcp_rst")
        self.assertEqual(len(tracker_tcp.flows), 0, "Completed flow must be removed from active table.")

        # 4b. UDP Behavior
        tracker_udp = FlowTracker()
        p_udp = DissectedPacket(
            timestamp_us=500.0, src_ip="8.8.8.8", dst_ip="192.168.1.1",
            src_port=53, dst_port=53535, protocol=17,  # UDP
            ip_header_length=20, l4_header_length=8, total_header_length=28,
            payload_length=64, tcp_flags={"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0}
        )
        tracker_udp.process_packet(p_udp)
        flow_udp = list(tracker_udp.flows.values())[0]
        feats = FeatureExtractor.extract_features(flow_udp)
        self.assertEqual(feats["Init_Win_bytes_forward"], 0.0, "UDP initial window must be 0.0.")
        self.assertEqual(feats["Init_Win_bytes_backward"], 0.0, "UDP initial window must be 0.0.")
        self.assertEqual(feats["SYN Flag Count"], 0.0, "UDP SYN flag count must be 0.0.")

    # --------------------------------------------------------------------------
    # 5. Timeout & Partial Flow Handling
    # --------------------------------------------------------------------------
    def test_05_timeout_and_partial_flow_handling(self):
        tracker = FlowTracker(inactivity_timeout_us=120_000_000.0)
        p = DissectedPacket(
            timestamp_us=1_000_000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=8080, dst_port=80, protocol=6,
            ip_header_length=20, l4_header_length=20, total_header_length=40,
            payload_length=100
        )
        tracker.process_packet(p)
        self.assertEqual(len(tracker.flows), 1)

        # Inactivity sweep before timeout: nothing expires
        expired = tracker.sweep_timeouts(now_us=1_000_000.0 + 50_000_000.0)  # +50s
        self.assertEqual(len(expired), 0)

        # Inactivity sweep after timeout: expires at +121s
        expired = tracker.sweep_timeouts(now_us=1_000_000.0 + 121_000_000.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].teardown_reason, "inactivity_timeout")
        self.assertEqual(len(tracker.flows), 0)

        # Flush all on shutdown
        tracker.process_packet(p)
        flushed = tracker.flush_all(reason="test_shutdown")
        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0].teardown_reason, "test_shutdown")
        self.assertEqual(len(tracker.flows), 0)

    # --------------------------------------------------------------------------
    # 6. Invalid / Non-Finite Feature Value Handling
    # --------------------------------------------------------------------------
    def test_06_invalid_and_nonfinite_feature_handling(self):
        # Create zero-duration flow (2 packets in identical microsecond)
        flow_zero = Flow(
            key=("127.0.0.1", "127.0.0.1", 1000, 2000, 6),
            start_time_us=1000.0,
            last_time_us=1000.0,
            fwd_src_ip="127.0.0.1",
            fwd_dst_ip="127.0.0.1",
            fwd_src_port=1000,
            fwd_dst_port=2000,
            protocol=6
        )
        feats = FeatureExtractor.extract_features(flow_zero)
        for k, v in feats.items():
            self.assertFalse(math.isnan(v), f"Feature {k} must not be NaN.")
            self.assertFalse(math.isinf(v), f"Feature {k} must not be Inf.")
            self.assertGreaterEqual(v, 0.0, f"Feature {k} must not be negative.")
        self.assertEqual(feats["Flow Bytes/s"], 0.0, "Zero duration must produce 0.0 rate.")
        self.assertEqual(feats["Flow Packets/s"], 0.0, "Zero duration must produce 0.0 rate.")

    # --------------------------------------------------------------------------
    # 7. Bounded Queue & Clean Shutdown
    # --------------------------------------------------------------------------
    def test_07_bounded_queue_and_clean_shutdown(self):
        worker = LiveCaptureWorker(max_queue_size=10)
        dummy_raw = b"\x00" * 40

        # Enqueue 25 packets into queue of size 10
        for _ in range(25):
            worker.enqueue_packet(dummy_raw)

        self.assertLessEqual(len(worker.packet_queue), 10, "Queue must be strictly bounded.")
        self.assertGreater(worker.dropped_packets_count, 0, "Packets exceeding bound must be dropped.")

        # Clean stop
        summary = worker.stop()
        self.assertEqual(summary["status"], "STOPPED")

    # --------------------------------------------------------------------------
    # 8. Capture Prerequisites & Permission Inspection
    # --------------------------------------------------------------------------
    def test_08_capture_prerequisites_inspection(self):
        prereqs = check_capture_prerequisites()
        self.assertIn("npcap_driver_present", prereqs)
        self.assertIn("scapy_installed", prereqs)
        self.assertIn("status", prereqs)
        self.assertIn("message", prereqs)
        self.assertIn(prereqs["status"], ("READY", "CAPTURE_UNAVAILABLE"))
        self.assertTrue(prereqs["scapy_installed"], "Scapy must be installed.")
        if prereqs.get("loopback_adapter_available"):
            self.assertEqual(prereqs["status"], "READY", "Subsystem must report READY when Scapy and Npcap loopback are present.")
        else:
            self.assertEqual(prereqs["status"], "CAPTURE_UNAVAILABLE", "Subsystem must report CAPTURE_UNAVAILABLE when loopback is absent.")

    # --------------------------------------------------------------------------
    # 9. Isolated Database Behavior
    # --------------------------------------------------------------------------
    def test_09_isolated_database_behavior(self):
        worker = LiveCaptureWorker(
            enable_inference=True,
            test_db_path=self.test_db_path
        )
        # Verify worker received explicit test_db_path and does not require global os.environ mutation
        self.assertEqual(worker.test_db_path, self.test_db_path)

        # Create synthetic completed flow and export
        flow = Flow(
            key=("127.0.0.1", "127.0.0.1", 50000, 80, 6),
            start_time_us=1000.0,
            last_time_us=5000.0,
            fwd_src_ip="127.0.0.1",
            fwd_dst_ip="127.0.0.1",
            fwd_src_port=50000,
            fwd_dst_port=80,
            protocol=6,
            total_fwd_packets=2,
            total_bwd_packets=2,
            total_fwd_bytes=100,
            total_bwd_bytes=300
        )
        batch_path = worker.export_flow_batch([flow])
        self.assertIsNotNone(batch_path)
        self.assertTrue(batch_path.is_file(), "Exported CSV batch file must exist.")

        # Inspect isolated test database
        self.assertTrue(self.test_db_path.is_file(), "Test database must be initialized.")
        conn = sqlite3.connect(f"file:{self.test_db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.assertIn("runs", tables)
        self.assertIn("flows", tables)
        runs_count = cur.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        flows_count = cur.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        self.assertGreater(runs_count, 0, "Test database must contain persisted runs.")
        self.assertGreater(flows_count, 0, "Test database must contain persisted flows.")
        conn.close()

    # --------------------------------------------------------------------------
    # 10. Existing CSV Demo Regression
    # --------------------------------------------------------------------------
    def test_10_existing_csv_demo_regression(self):
        plumbing_csv = REPO_ROOT / "reports" / "evaluation" / "stage3b_closure" / "nids_stage3b_plumbing_15.csv"
        if not plumbing_csv.is_file():
            plumbing_csv = REPO_ROOT / "tests" / "fixtures" / "nids_sample_15_flows.csv"
        self.assertTrue(plumbing_csv.is_file(), "Plumbing sample CSV must exist.")

        # Import app_model_v2 and verify model prediction
        import app_v2.app_model_v2 as app_module
        import pandas as pd
        import numpy as np

        df = pd.read_csv(plumbing_csv)
        self.assertEqual(len(df), 15, "Plumbing sample must contain 15 rows.")
        numeric = df.loc[:, ORDERED_FEATURES].apply(pd.to_numeric, errors="raise")
        matrix = numeric.to_numpy(dtype=np.float32, copy=True)
        np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)

        probs = app_module.model.predict_proba(matrix)
        self.assertEqual(probs.shape, (15, 15), "Model must output shape (15, 15).")

    # --------------------------------------------------------------------------
    # 11. Production Database, Backup, and Model Hash Preservation
    # --------------------------------------------------------------------------
    def test_11_production_database_backup_and_model_preservation(self):
        prod_db = REPO_ROOT / "app_v2" / "data" / "nids.sqlite"
        backup_db = REPO_ROOT / "app_v2" / "data" / "nids.sqlite.bak_baseline"
        model_json = REPO_ROOT / "models" / "replacement_v1" / "xgboost_nids_replacement_v1.json"

        h_prod = compute_file_sha256(prod_db)
        h_bak = compute_file_sha256(backup_db)
        h_model = compute_file_sha256(model_json)

        self.assertIn(h_prod, (HASH_PROD_DB, HASH_LEGACY_PROD_DB), "PRODUCTION DATABASE HAS BEEN MODIFIED! HASH MISMATCH!")
        self.assertEqual(h_bak, HASH_BACKUP_DB, "BASELINE BACKUP HAS BEEN MODIFIED! HASH MISMATCH!")
        self.assertEqual(h_model, HASH_MODEL_JSON, "MODEL ARTIFACT HAS BEEN MODIFIED! HASH MISMATCH!")

    # --------------------------------------------------------------------------
    # 12. Adapter-Name Resolution
    # --------------------------------------------------------------------------
    def test_12_adapter_resolution(self):
        # Loopback aliases must resolve to \Device\NPF_Loopback
        self.assertEqual(resolve_adapter_name("127.0.0.1"), r"\Device\NPF_Loopback")
        self.assertEqual(resolve_adapter_name("localhost"), r"\Device\NPF_Loopback")
        self.assertEqual(resolve_adapter_name("loopback"), r"\Device\NPF_Loopback")
        self.assertEqual(resolve_adapter_name("lo"), r"\Device\NPF_Loopback")
        self.assertEqual(resolve_adapter_name(r"\Device\NPF_Loopback"), r"\Device\NPF_Loopback")

        # Explicit Npcap device path must be preserved
        custom_dev = r"\Device\NPF_{12345678-ABCD-EF01-2345-6789ABCDEF01}"
        self.assertEqual(resolve_adapter_name(custom_dev), custom_dev)

    # --------------------------------------------------------------------------
    # 13. Mocked Scapy Capture Callback Integration
    # --------------------------------------------------------------------------
    def test_13_mocked_scapy_capture_callback(self):
        worker = LiveCaptureWorker(interface="127.0.0.1", enable_inference=False)

        # Create mock Scapy packet with IP layer
        from unittest.mock import MagicMock
        from scapy.layers.inet import IP, TCP  # type: ignore

        scapy_pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=54321, dport=80, flags="S")
        scapy_pkt.time = 1700000000.123456

        worker._packet_callback(scapy_pkt)
        self.assertEqual(len(worker.packet_queue), 1, "Packet must be enqueued.")

        raw_bytes, ts = worker.packet_queue.popleft()
        self.assertAlmostEqual(ts, 1700000000123456.0, places=1, msg="Timestamp must be preserved in microseconds.")
        self.assertEqual(raw_bytes[:1], b"\x45", "Raw bytes must begin with IPv4 header 0x45.")

    # --------------------------------------------------------------------------
    # 14. Real Loopback Capture Traffic Test
    # --------------------------------------------------------------------------
    def test_14_real_loopback_capture_traffic(self):
        prereqs = check_capture_prerequisites()
        if not prereqs["capture_available"]:
            self.skipTest("Npcap capture subsystem not available; skipping live capture test.")

        worker = LiveCaptureWorker(
            interface="127.0.0.1",
            enable_inference=False,
            output_dir=REPO_ROOT / "app_v2" / "data" / "test" / "live_batches"
        )
        # Start real packet capture on \Device\NPF_Loopback
        worker.start(capture_live=True)
        import time
        import urllib.request
        time.sleep(0.5)

        # Generate real local loopback HTTP traffic to running NIDS health endpoint
        request_success = False
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2) as resp:
                if resp.status == 200:
                    request_success = True
        except Exception as exc:
            pass

        time.sleep(0.5)
        summary = worker.stop()

        # Verify real packet reception and flow tracking
        self.assertEqual(summary["status"], "STOPPED")
        self.assertEqual(summary["adapter_resolved"], r"\Device\NPF_Loopback")
        self.assertGreater(summary["total_packets_processed"], 0, "Real capture must receive loopback packets.")
        self.assertGreater(summary["total_flows_created"], 0, "Real capture must create at least one flow.")

        # Re-verify production database preservation immediately after real capture
        h_prod = compute_file_sha256(REPO_ROOT / "app_v2" / "data" / "nids.sqlite")
        h_bak = compute_file_sha256(REPO_ROOT / "app_v2" / "data" / "nids.sqlite.bak_baseline")
        self.assertIn(h_prod, (HASH_PROD_DB, HASH_LEGACY_PROD_DB), "Production database was modified during real capture!")
        self.assertEqual(h_bak, HASH_BACKUP_DB, "Production backup was modified during real capture!")

    # --------------------------------------------------------------------------
    # 15. Reference PCAP Parity and Idle Gap Lifecycle
    # --------------------------------------------------------------------------
    def test_15_reference_pcap_parity_and_idle_gap_lifecycle(self):
        fixture_pcap = REPO_ROOT / "tests" / "fixtures" / "reference_validation_traffic.pcap"
        self.assertTrue(fixture_pcap.is_file(), "Reference validation PCAP fixture must exist.")

        from scapy.all import rdpcap  # type: ignore
        read_pkts = rdpcap(str(fixture_pcap))
        self.assertEqual(len(read_pkts), 18, "Fixture must contain exactly 18 reference packets.")

        tracker = FlowTracker()
        completed_flows = []
        for p in read_pkts:
            raw_bytes = bytes(p)
            ts_us = float(p.time) * 1_000_000.0
            dissected = PacketDissector.dissect_any(raw_bytes, timestamp_us=ts_us)
            if dissected:
                c = tracker.process_packet(dissected)
                if c:
                    completed_flows.append(c)

        flushed = tracker.flush_all()
        completed_flows.extend(flushed)

        self.assertEqual(len(completed_flows), 3, "Exactly 3 distinct flows must be tracked and completed.")

        flow_map = {
            (f.fwd_src_ip, f.fwd_dst_ip, f.fwd_dst_port, f.protocol): f
            for f in completed_flows
        }

        # Flow A: Normal TCP HTTP
        flow_a = flow_map.get(("192.168.1.100", "192.168.1.1", 80, 6))
        self.assertIsNotNone(flow_a)
        self.assertEqual(flow_a.teardown_reason, "tcp_fin_mutual")
        feats_a = FeatureExtractor.extract_features(flow_a)
        self.assertEqual(feats_a["Flow Duration"], 180000.0)
        self.assertEqual(feats_a["Total Fwd Packets"], 4.0)
        self.assertEqual(feats_a["Total Backward Packets"], 4.0)
        self.assertEqual(feats_a["Init_Win_bytes_forward"], 8192.0)
        self.assertEqual(feats_a["Init_Win_bytes_backward"], 16384.0)

        # Flow B: Long Duration (>5s) and Idle Gaps (>=5s)
        flow_b = flow_map.get(("10.0.0.5", "10.0.0.1", 443, 6))
        self.assertIsNotNone(flow_b)
        self.assertEqual(flow_b.teardown_reason, "tcp_rst")
        feats_b = FeatureExtractor.extract_features(flow_b)
        self.assertEqual(feats_b["Flow Duration"], 13200000.0)
        self.assertEqual(len(flow_b.idle_periods), 2, "Flow B must have registered exactly 2 idle periods.")
        self.assertGreaterEqual(min(flow_b.idle_periods), 5000000.0, "Idle periods must be >= 5.0 seconds.")
        self.assertEqual(feats_b["Idle Mean"], 5750000.0)
        self.assertEqual(feats_b["Idle Max"], 6000000.0)
        self.assertEqual(feats_b["Idle Min"], 5500000.0)

        # Flow C: UDP Non-TCP
        flow_c = flow_map.get(("172.16.0.2", "172.16.0.1", 53, 17))
        self.assertIsNotNone(flow_c)
        feats_c = FeatureExtractor.extract_features(flow_c)
        self.assertEqual(feats_c["Init_Win_bytes_forward"], 0.0, "UDP initial window must be 0.0.")
        self.assertEqual(feats_c["Init_Win_bytes_backward"], 0.0, "UDP initial window must be 0.0.")
        self.assertEqual(feats_c["min_seg_size_forward"], 8.0, "UDP min seg size must be 8.0.")


if __name__ == "__main__":
    unittest.main()
