"""
run_live_capture.py
Command-line runner for NIDS Stage 4B Live Capture and Flow Processing Prototype.

Usage:
    # 1. Non-privileged prerequisite diagnostic:
    python run_live_capture.py --check-prerequisites

    # 2. Synthetic loopback flow simulation (Safe, requires zero drivers):
    python run_live_capture.py --synthetic --duration 5

    # 3. Synthetic simulation with safe, isolated test database inference:
    python run_live_capture.py --synthetic --enable-inference --duration 5
"""

import argparse
import json
import os
from pathlib import Path
import struct
import sys
import time

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app_v2.capture.live_capture_worker import (
    LiveCaptureWorker,
    check_capture_prerequisites,
    DEFAULT_TEST_DB,
)
from app_v2.capture.packet_dissector import PacketDissector


def build_synthetic_tcp_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    flags: int, payload: bytes = b"", seq: int = 1000, ack: int = 0,
    window: int = 8192
) -> bytes:
    """Builds a raw IPv4 + TCP packet buffer for synthetic testing."""
    import socket
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    # TCP header
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        (5 << 4),  # data offset 20 bytes
        flags,
        window,
        0, 0  # checksum, urgent pointer
    )
    total_l4 = tcp_hdr + payload

    # IPv4 header
    ip_total_len = 20 + len(total_l4)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 54321, 0x4000, 64, 6, 0,  # proto 6 = TCP
        src_bytes, dst_bytes
    )
    return ip_hdr + total_l4


def run_synthetic_session(worker: LiveCaptureWorker, duration_s: float = 3.0) -> None:
    """Simulates realistic bidirectional TCP traffic streams over loopback."""
    print(f"\n[+] Injecting synthetic loopback traffic streams into worker...")

    # Stream 1: Web request (Client 127.0.0.1:49152 -> Server 127.0.0.1:80)
    # SYN
    p1 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 49152, 80, flags=0x02, seq=100)
    worker.enqueue_packet(p1)
    time.sleep(0.01)

    # SYN-ACK
    p2 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, 49152, flags=0x12, seq=500, ack=101)
    worker.enqueue_packet(p2)
    time.sleep(0.01)

    # ACK
    p3 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 49152, 80, flags=0x10, seq=101, ack=501)
    worker.enqueue_packet(p3)
    time.sleep(0.01)

    # HTTP GET Request (Payload 120 bytes)
    req_payload = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: NIDS-Test\r\nAccept: */*\r\n\r\n"
    p4 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 49152, 80, flags=0x18, payload=req_payload, seq=101, ack=501)
    worker.enqueue_packet(p4)
    time.sleep(0.01)

    # HTTP Response (Payload 250 bytes)
    resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n<html><body>NIDS Test OK</body></html>"
    p5 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, 49152, flags=0x18, payload=resp_payload, seq=501, ack=101 + len(req_payload))
    worker.enqueue_packet(p5)
    time.sleep(0.01)

    # Teardown FIN from client
    p6 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 49152, 80, flags=0x11, seq=101 + len(req_payload), ack=501 + len(resp_payload))
    worker.enqueue_packet(p6)
    time.sleep(0.01)

    # Teardown FIN-ACK from server
    p7 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 80, 49152, flags=0x11, seq=501 + len(resp_payload), ack=102 + len(req_payload))
    worker.enqueue_packet(p7)

    # Stream 2: PortScan probe (Single SYN packet without response)
    p8 = build_synthetic_tcp_packet("127.0.0.1", "127.0.0.1", 55555, 445, flags=0x02, seq=999)
    worker.enqueue_packet(p8)

    print(f"[+] Injected 8 synthetic packets across 2 distinct flows.")
    time.sleep(max(1.0, duration_s))


def main() -> None:
    parser = argparse.ArgumentParser(description="NIDS Stage 4B Live Capture Prototype")
    parser.add_argument("--interface", default="127.0.0.1", help="Network interface (default: 127.0.0.1 loopback)")
    parser.add_argument("--check-prerequisites", action="store_true", help="Inspect capture driver and privileges")
    parser.add_argument("--synthetic", action="store_true", help="Run with simulated synthetic loopback packets")
    parser.add_argument("--enable-inference", action="store_true", help="Enable experimental inference into isolated test DB")
    parser.add_argument("--duration", type=float, default=3.0, help="Run duration in seconds (default: 3.0)")
    parser.add_argument("--test-db", default=str(DEFAULT_TEST_DB), help="Isolated test SQLite database path")

    args = parser.parse_args()

    print("=" * 70)
    print(" NIDS STAGE 4B — WINDOWS 11 LIVE CAPTURE & FLOW PROTOTYPE")
    print("=" * 70)

    # 1. Prerequisite check
    prereqs = check_capture_prerequisites()
    if args.check_prerequisites:
        print("\n[*] Host Capture Prerequisites Inspection:")
        print(json.dumps(prereqs, indent=2))
        return

    # 2. Worker setup
    worker = LiveCaptureWorker(
        interface=args.interface,
        enable_inference=args.enable_inference,
        test_db_path=Path(args.test_db),
    )

    # 3. Execution
    if args.synthetic:
        worker.start(capture_live=False)
        run_synthetic_session(worker, duration_s=args.duration)
        summary = worker.stop()
        print("\n[*] Synthetic Session Summary:")
        print(json.dumps(summary, indent=2))
    else:
        if not prereqs["capture_available"]:
            print(f"\n[-] LIVE CAPTURE BLOCKED:")
            print(f"    {prereqs['message']}")
            print(f"    To run offline verification without drivers, use: python run_live_capture.py --synthetic")
            sys.exit(1)

        print(f"\n[+] Starting live capture on interface: {args.interface} (resolved: {worker.resolved_adapter})...")
        try:
            worker.start(capture_live=True)
        except Exception as exc:
            print(f"\n[-] FAILED TO START CAPTURE: {exc}")
            sys.exit(1)

        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            print("\n[*] Stop requested by user.")
        summary = worker.stop()
        print("\n[*] Live Capture Session Summary:")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
