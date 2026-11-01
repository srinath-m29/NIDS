"""
live_capture_worker.py
Windows 11 Live Capture & Flow Extraction Worker Daemon.

Guarantees:
- Default loopback-only capture (resolves 127.0.0.1 / localhost to \\Device\\NPF_Loopback).
- Real packet capture via Scapy AsyncSniffer on Windows Npcap.
- Direct link-layer handling (Loopback DLT_NULL, Ethernet, Raw IP).
- Bounded circular queue buffering and coordinated clean shutdown.
- Flow extraction completely separated from model inference.
- Inference disabled by default; strictly isolated to test database when enabled.
"""

from collections import deque
import json
import logging
import os
from pathlib import Path
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from .packet_dissector import DissectedPacket, PacketDissector
from .flow_tracker import Flow, FlowTracker
from .feature_extractor import FeatureExtractor, EXTRACTOR_STATUS, EXTRACTOR_DISCLAIMER

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (LiveWorker) %(message)s"
)
logger = logging.getLogger("LiveWorker")

DEFAULT_TEST_DB = Path(__file__).resolve().parent.parent / "data" / "test" / "nids_test_live_4b.sqlite"


def resolve_adapter_name(interface: str) -> str:
    """
    Resolves human-readable interface names, IP addresses, or aliases
    to the actual Scapy/Npcap adapter string on Windows 11.
    """
    clean = (interface or "").strip()
    if clean.lower() in ("127.0.0.1", "localhost", "loopback", "lo", r"\device\npf_loopback".lower()):
        return r"\Device\NPF_Loopback"

    if clean.startswith(r"\Device\NPF_"):
        return clean

    # Check if interface matches a Windows friendly name or description
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
        for win_iface in get_windows_if_list():
            name = win_iface.get("name", "").lower()
            desc = win_iface.get("description", "").lower()
            if clean.lower() in (name, desc):
                guid = win_iface.get("guid", "")
                if guid:
                    return r"\Device\NPF_" + guid
    except Exception:
        pass

    return clean


def check_capture_prerequisites() -> Dict[str, Any]:
    """
    Non-privileged inspection of Windows 11 capture prerequisites.
    Inspects Scapy availability and Npcap network adapters.
    """
    has_scapy = False
    has_npcap = False
    has_loopback = False
    available_adapters: List[str] = []
    error_msg = ""

    try:
        from scapy.all import get_if_list  # type: ignore
        from scapy.config import conf  # type: ignore
        has_scapy = True
        available_adapters = get_if_list()
        has_loopback = r"\Device\NPF_Loopback" in available_adapters
        has_npcap = getattr(conf, "use_pcap", False) and (len(available_adapters) > 0 and any("NPF" in a for a in available_adapters))
    except Exception as exc:
        error_msg = str(exc)

    available = has_scapy and has_npcap and has_loopback

    return {
        "npcap_driver_present": has_npcap,
        "scapy_installed": has_scapy,
        "loopback_adapter_available": has_loopback,
        "resolved_loopback_adapter": r"\Device\NPF_Loopback" if has_loopback else None,
        "available_adapters_count": len(available_adapters),
        "capture_available": available,
        "status": "READY" if available else "CAPTURE_UNAVAILABLE",
        "error": error_msg,
        "message": (
            "Npcap driver and Scapy loopback capture subsystem verified."
            if available
            else f"Npcap capture subsystem not available: {error_msg or 'Npcap loopback driver not detected'}. "
                 "Run with --synthetic for offline/simulated unit testing."
        )
    }


class LiveCaptureWorker:
    """
    Standalone Live Capture & Flow Processing Daemon.
    Maintains complete separation between packet ingestion, flow aggregation,
    and optional model scoring.
    """

    def __init__(
        self,
        interface: str = "127.0.0.1",
        enable_inference: bool = False,
        test_db_path: Path = DEFAULT_TEST_DB,
        max_queue_size: int = 50_000,
        max_flows: int = 20_000,
        inactivity_timeout_s: float = 120.0,
        output_dir: Optional[Path] = None,
        bpf_filter: Optional[str] = "ip",
    ):
        # 1. Interface resolution and security checks
        self.interface = interface
        self.resolved_adapter = resolve_adapter_name(interface)
        self.bpf_filter = bpf_filter

        if self.resolved_adapter == r"\Device\NPF_Loopback":
            logger.info("Worker bound strictly to loopback adapter: %s (input: %s).", self.resolved_adapter, interface)
        else:
            logger.warning(
                "NON-LOOPBACK ADAPTER CONFIGURED: %s (resolved from '%s'). "
                "Ensure explicit network authorization before starting capture.",
                self.resolved_adapter, interface
            )

        # 2. Inference & Database safety
        self.enable_inference = enable_inference
        self.test_db_path = Path(test_db_path).resolve()
        self.output_dir = output_dir or self.test_db_path.parent / "live_batches"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if self.enable_inference:
            logger.warning(
                "EXPERIMENTAL INFERENCE ENABLED. Output isolated strictly to test DB: %s",
                self.test_db_path
            )
        else:
            logger.info("Model inference is DISABLED by default (Extraction-only mode).")

        # 3. Queue & Flow tracking
        self.packet_queue: deque = deque(maxlen=max_queue_size)
        self.tracker = FlowTracker(
            max_flows=max_flows,
            inactivity_timeout_us=inactivity_timeout_s * 1_000_000.0
        )

        # 4. State, Sniffer, Buffering & Threading
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.sniffer: Optional[Any] = None
        self.sniffer_error: Optional[str] = None
        self.completed_flows: List[Flow] = []
        self.pending_export_flows: List[Flow] = []
        self.last_flush_time: float = time.time()
        self.flush_interval_seconds: float = 5.0
        self.flush_batch_size: int = 50
        self.exported_batches_count = 0
        self.dropped_packets_count = 0
        self.ipv6_packets_count = 0
        self.unsupported_protocol_packets = 0
        self.total_scored_flows = 0
        self.total_inference_errors = 0
        self.prediction_counts: Dict[str, int] = {}
        self.prerequisites = check_capture_prerequisites()

    def _packet_callback(self, pkt: Any) -> None:
        """
        Callback invoked by Scapy AsyncSniffer on packet reception.
        Preserves packet timestamp, extracts raw bytes, and pushes to bounded queue.
        """
        try:
            ts = getattr(pkt, "time", None)
            timestamp_us = float(ts) * 1_000_000.0 if ts is not None else (time.time() * 1_000_000.0)

            # Check if Scapy has IP layer
            from scapy.layers.inet import IP  # type: ignore
            if pkt.haslayer(IP):
                raw_bytes = bytes(pkt[IP])
            else:
                raw_bytes = bytes(pkt)

            self.enqueue_packet(raw_bytes, timestamp_us=timestamp_us)
        except Exception as exc:
            logger.debug("Packet callback processing error: %s", exc)

    def enqueue_packet(self, raw_bytes: bytes, timestamp_us: Optional[float] = None) -> bool:
        """
        Thread-safe packet ingress into bounded circular queue.
        Drops oldest packet if capacity reached.
        """
        if len(self.packet_queue) >= self.packet_queue.maxlen:
            self.dropped_packets_count += 1
            try:
                self.packet_queue.popleft()
            except IndexError:
                pass

        self.packet_queue.append((raw_bytes, timestamp_us))
        return True

    def process_queue_iteration(self) -> List[Flow]:
        """Processes queued packets through universal dissector and returns completed flows."""
        newly_completed: List[Flow] = []

        # Drain up to 500 items per cycle
        for _ in range(500):
            if not self.packet_queue:
                break
            try:
                raw_bytes, ts = self.packet_queue.popleft()
            except IndexError:
                break

            # Dissect packet using universal framing (Raw IPv4, Loopback DLT_NULL, or Ethernet)
            pkt = PacketDissector.dissect_any(raw_bytes, timestamp_us=ts)

            if pkt is not None:
                completed = self.tracker.process_packet(pkt)
                if completed:
                    newly_completed.append(completed)
            else:
                if PacketDissector.check_is_ipv6(raw_bytes):
                    self.ipv6_packets_count += 1
                else:
                    self.unsupported_protocol_packets += 1

        # Sweep inactivity timeouts
        timed_out = self.tracker.sweep_timeouts()
        if timed_out:
            newly_completed.extend(timed_out)

        return newly_completed

    def export_flow_batch(self, flows: List[Flow]) -> Optional[Path]:
        """Converts completed flows to 63-feature CSV and optionally triggers scoring."""
        if not flows:
            return None

        df = FeatureExtractor.flows_to_dataframe(flows)
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        batch_filename = f"live_flows_{timestamp_str}_{self.exported_batches_count + 1}.csv"
        batch_path = self.output_dir / batch_filename
        df.to_csv(batch_path, index=False)
        self.exported_batches_count += 1
        logger.info("Exported %d flow(s) to batch file: %s", len(flows), batch_path)

        if self.enable_inference:
            self._score_batch_safely(batch_path, df, flows)

        return batch_path

    def _score_batch_safely(self, batch_path: Path, df: pd.DataFrame, flows: Optional[List[Flow]] = None) -> None:
        """Scores batch against active model into isolated test database."""
        try:
            import app_v2.app_model_v2 as app_module  # type: ignore
            import numpy as np

            matrix = df.to_numpy(dtype=np.float32, copy=True)
            np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
            np.clip(matrix, a_min=0.0, a_max=None, out=matrix)

            probabilities = app_module.model.predict_proba(matrix)
            indices = np.argmax(probabilities, axis=1)
            confidence = np.max(probabilities, axis=1)
            predicted = [app_module.LABELS.get(int(i), f"UNKNOWN_{int(i)}") for i in indices]

            import uuid
            from datetime import datetime, timezone
            run_id = str(uuid.uuid4())
            created = datetime.now(timezone.utc).isoformat()
            count = len(df)

            # Assign predictions to Flow instances
            if flows and len(flows) == count:
                for i in range(count):
                    flows[i].predicted_class = predicted[i]
                    flows[i].confidence = float(confidence[i])

            attack_events = []
            for i in range(count):
                if predicted[i] != "BENIGN":
                    ev_id = str(uuid.uuid4())
                    flow_obj = flows[i] if (flows and i < len(flows)) else None
                    flow_id_str = flow_obj.flow_id if flow_obj else f"row_{i}"
                    src_ep = f"{flow_obj.src_ip}:{flow_obj.src_port}" if flow_obj else ""
                    dst_ep = f"{flow_obj.dst_ip}:{flow_obj.dst_port}" if flow_obj else ""
                    proto_str = "TCP" if (flow_obj and flow_obj.protocol == 6) else ("UDP" if (flow_obj and flow_obj.protocol == 17) else str(flow_obj.protocol if flow_obj else "IP"))
                    conf_val = float(confidence[i])

                    attack_events.append((
                        ev_id, created, flow_id_str, run_id, predicted[i], conf_val,
                        src_ep, dst_ep, proto_str, app_module.MODEL_VERSION, 'LIVE', 0
                    ))

                    # Also append to in-memory recent events queue for real-time UI
                    if hasattr(app_module, "capture_mgr"):
                        app_module.capture_mgr.recent_events.append({
                            "id": ev_id,
                            "event_id": ev_id,
                            "timestamp": created,
                            "flow_id": flow_id_str,
                            "run_id": run_id,
                            "predicted_class": predicted[i],
                            "confidence": conf_val,
                            "src_endpoint": src_ep,
                            "dst_endpoint": dst_ep,
                            "protocol": proto_str,
                            "model_version": app_module.MODEL_VERSION,
                            "capture_mode": "LIVE",
                            "acknowledged": 0,
                        })

            with app_module.connect(self.test_db_path) as con:
                con.execute(
                    """INSERT INTO runs
                       (run_id, created_at, filename, row_count, scored_count, not_scored_count)
                       VALUES (?, ?, ?, ?, ?, 0)""",
                    (run_id, created, batch_path.name, count, count),
                )
                con.executemany(
                    """INSERT INTO flows
                       (run_id, row_id, predicted_class, confidence, not_scored, model_version)
                       VALUES (?, ?, ?, ?, 0, ?)""",
                    [
                        (run_id, i, predicted[i], float(confidence[i]), app_module.MODEL_VERSION)
                        for i in range(count)
                    ],
                )
                if attack_events:
                    con.executemany(
                        """INSERT INTO detection_events
                           (event_id, timestamp, flow_id, run_id, predicted_class, confidence,
                            src_endpoint, dst_endpoint, protocol, model_version, capture_mode, acknowledged)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        attack_events,
                    )

            for p in predicted:
                self.prediction_counts[p] = self.prediction_counts.get(p, 0) + 1
            self.total_scored_flows += count

            logger.info(
                "Persisted run %s (%d flow(s)) to isolated DB: %s. Predictions: %s",
                run_id[:8], len(df), self.test_db_path.name, dict(pd.Series(predicted).value_counts())
            )
        except Exception as exc:
            self.total_inference_errors += 1
            logger.error("Safe inference failed on batch %s: %s", batch_path.name, exc)

    def start(self, capture_live: bool = True) -> None:
        """
        Starts live packet capture and background queue processing.
        If capture_live is False, runs queue processor only (for synthetic testing).
        """
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.worker_thread.start()

        if capture_live:
            if not self.prerequisites["capture_available"]:
                raise RuntimeError(
                    f"Live capture unavailable: {self.prerequisites['message']}"
                )

            try:
                from scapy.all import AsyncSniffer  # type: ignore
                logger.info(
                    "Starting Scapy AsyncSniffer on adapter: %s (filter='%s')...",
                    self.resolved_adapter, self.bpf_filter or ""
                )
                self.sniffer = AsyncSniffer(
                    iface=self.resolved_adapter,
                    prn=self._packet_callback,
                    store=False,
                    filter=self.bpf_filter,
                )
                self.sniffer.start()
                logger.info("Scapy AsyncSniffer successfully started on %s.", self.resolved_adapter)
            except Exception as exc:
                self.sniffer_error = str(exc)
                logger.error("Failed to start Scapy AsyncSniffer on %s: %s", self.resolved_adapter, exc)
                self.stop()
                raise RuntimeError(
                    f"Failed to start packet capture on {self.resolved_adapter}: {exc}"
                ) from exc

        logger.info("Live capture worker running.")

    def _run_loop(self) -> None:
        while not self.stop_event.is_set():
            completed = self.process_queue_iteration()
            if completed:
                self.completed_flows.extend(completed)
                self.pending_export_flows.extend(completed)

            now = time.time()
            if self.pending_export_flows and (
                len(self.pending_export_flows) >= self.flush_batch_size
                or (now - self.last_flush_time) >= self.flush_interval_seconds
            ):
                to_export = self.pending_export_flows
                self.pending_export_flows = []
                self.last_flush_time = now
                self.export_flow_batch(to_export)

            time.sleep(0.01)

    def stop(self) -> Dict[str, Any]:
        """
        Coordinates clean shutdown: stops sniffer, terminates worker thread,
        drains remaining queue, and flushes all surviving active flows.
        """
        logger.info("Stopping capture worker; coordinating clean shutdown...")

        # 1. Stop sniffer first to halt new packet ingress
        if self.sniffer is not None:
            try:
                logger.info("Stopping Scapy AsyncSniffer...")
                self.sniffer.stop()
            except Exception as exc:
                logger.warning("Error stopping AsyncSniffer: %s", exc)
            finally:
                self.sniffer = None

        # 2. Stop queue processing thread
        self.stop_event.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)

        # 3. Drain remaining packets in queue
        remaining_completed = self.process_queue_iteration()
        if remaining_completed:
            self.completed_flows.extend(remaining_completed)
            self.pending_export_flows.extend(remaining_completed)

        # 4. Flush surviving active flows
        surviving = self.tracker.flush_all(reason="shutdown_flush")
        if surviving:
            self.completed_flows.extend(surviving)
            self.pending_export_flows.extend(surviving)

        # 5. Flush all pending unexported flows to disk
        if self.pending_export_flows:
            self.export_flow_batch(self.pending_export_flows)
            self.pending_export_flows = []

        summary = {
            "status": "STOPPED",
            "interface_requested": self.interface,
            "adapter_resolved": self.resolved_adapter,
            "total_packets_processed": self.tracker.total_packets_processed,
            "total_flows_created": self.tracker.total_flows_created,
            "total_flows_completed": len(self.completed_flows),
            "batches_exported": self.exported_batches_count,
            "packets_dropped": self.dropped_packets_count,
            "ipv6_packets": self.ipv6_packets_count,
            "unsupported_packets": self.unsupported_protocol_packets,
            "inference_enabled": self.enable_inference,
            "total_flows_scored": self.total_scored_flows,
            "total_inference_errors": self.total_inference_errors,
            "prediction_counts": self.prediction_counts,
            "test_db_path": str(self.test_db_path),
            "extractor_status": EXTRACTOR_STATUS,
            "sniffer_error": self.sniffer_error,
        }
        logger.info("Capture worker cleanly stopped. Summary: %s", summary)
        return summary
