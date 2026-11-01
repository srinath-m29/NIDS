"""
flow_tracker.py
Bidirectional 5-tuple flow lifecycle engine.
Handles forward/backward assignment, packet aggregation, active/idle time state machine,
timeout expiration, bounded capacity with LRU eviction, and graceful shutdown flush.
"""

from collections import deque
from dataclasses import dataclass, field
import time
from typing import Dict, List, Optional, Set, Tuple

from .packet_dissector import DissectedPacket


FlowKey = Tuple[str, str, int, int, int]  # (src_ip, dst_ip, src_port, dst_port, protocol)


@dataclass
class Flow:
    """Represents an active bidirectional network flow between two endpoints."""
    key: FlowKey
    start_time_us: float
    last_time_us: float

    # Endpoints
    fwd_src_ip: str
    fwd_dst_ip: str
    fwd_src_port: int
    fwd_dst_port: int
    protocol: int

    # Directional Packet & Byte Tracking
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0

    fwd_payload_lengths: List[int] = field(default_factory=list)
    bwd_payload_lengths: List[int] = field(default_factory=list)
    all_payload_lengths: List[int] = field(default_factory=list)

    # Header Lengths
    fwd_header_bytes: int = 0
    bwd_header_bytes: int = 0
    min_seg_size_fwd: int = 65535

    # Timestamps & Inter-Arrival Times
    all_timestamps: List[float] = field(default_factory=list)
    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)

    # TCP Flags
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    fwd_psh_count: int = 0
    fwd_urg_count: int = 0
    fwd_fin_count: int = 0
    bwd_fin_count: int = 0

    # Initial Window Sizes (0.0 for non-TCP)
    init_win_fwd: int = 0
    init_win_bwd: int = 0
    has_init_win_fwd: bool = False
    has_init_win_bwd: bool = False

    # Active / Idle State Machine (5-second threshold: 5,000,000 us)
    active_periods: List[float] = field(default_factory=list)
    idle_periods: List[float] = field(default_factory=list)
    current_active_start: float = 0.0
    current_active_last: float = 0.0

    # State
    is_closed: bool = False
    teardown_reason: str = "active"
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None

    @property
    def flow_id(self) -> str:
        return f"{self.fwd_src_ip}:{self.fwd_src_port}-{self.fwd_dst_ip}:{self.fwd_dst_port}-{self.protocol}"

    @property
    def src_ip(self) -> str:
        return self.fwd_src_ip

    @property
    def dst_ip(self) -> str:
        return self.fwd_dst_ip

    @property
    def src_port(self) -> int:
        return self.fwd_src_port

    @property
    def dst_port(self) -> int:
        return self.fwd_dst_port

    @property
    def duration_us(self) -> float:
        return max(0.0, self.last_time_us - self.start_time_us)

    @property
    def total_packets(self) -> int:
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.total_fwd_bytes + self.total_bwd_bytes

    def add_packet(self, pkt: DissectedPacket, is_forward: bool) -> None:
        """Updates flow state with an incoming dissected packet."""
        self.last_time_us = pkt.timestamp_us
        self.all_timestamps.append(pkt.timestamp_us)
        self.all_payload_lengths.append(pkt.payload_length)

        # Active / Idle state machine update
        IDLE_THRESHOLD_US = 5_000_000.0  # 5.0 seconds
        if len(self.all_timestamps) == 1:
            self.current_active_start = pkt.timestamp_us
            self.current_active_last = pkt.timestamp_us
        else:
            prev_time = self.all_timestamps[-2]
            gap = pkt.timestamp_us - prev_time
            if gap >= IDLE_THRESHOLD_US:
                # An idle gap occurred
                self.idle_periods.append(gap)
                active_duration = max(0.0, self.current_active_last - self.current_active_start)
                if active_duration > 0:
                    self.active_periods.append(active_duration)
                self.current_active_start = pkt.timestamp_us
                self.current_active_last = pkt.timestamp_us
            else:
                self.current_active_last = pkt.timestamp_us

        # Aggregate TCP flags
        if pkt.protocol == 6:  # TCP
            for flag_name, count in pkt.tcp_flags.items():
                if count > 0:
                    if flag_name == "FIN":
                        self.fin_count += count
                        if is_forward:
                            self.fwd_fin_count += count
                        else:
                            self.bwd_fin_count += count
                    elif flag_name == "SYN":
                        self.syn_count += count
                    elif flag_name == "RST":
                        self.rst_count += count
                    elif flag_name == "PSH":
                        self.psh_count += count
                        if is_forward:
                            self.fwd_psh_count += count
                    elif flag_name == "ACK":
                        self.ack_count += count
                    elif flag_name == "URG":
                        self.urg_count += count
                        if is_forward:
                            self.fwd_urg_count += count
                    elif flag_name == "CWR":
                        self.cwe_count += count
                    elif flag_name == "ECE":
                        self.ece_count += count

        # Forward vs Backward handling
        if is_forward:
            self.total_fwd_packets += 1
            self.total_fwd_bytes += pkt.payload_length
            self.fwd_payload_lengths.append(pkt.payload_length)
            self.fwd_header_bytes += pkt.total_header_length
            self.fwd_timestamps.append(pkt.timestamp_us)
            if pkt.protocol == 6:
                if not self.has_init_win_fwd:
                    self.init_win_fwd = pkt.tcp_window
                    self.has_init_win_fwd = True
                if pkt.l4_header_length < self.min_seg_size_fwd:
                    self.min_seg_size_fwd = pkt.l4_header_length
        else:
            self.total_bwd_packets += 1
            self.total_bwd_bytes += pkt.payload_length
            self.bwd_payload_lengths.append(pkt.payload_length)
            self.bwd_header_bytes += pkt.total_header_length
            self.bwd_timestamps.append(pkt.timestamp_us)
            if pkt.protocol == 6:
                if not self.has_init_win_bwd:
                    self.init_win_bwd = pkt.tcp_window
                    self.has_init_win_bwd = True

    def check_teardown(self, now_us: float, timeout_us: float = 120_000_000.0) -> bool:
        """
        Determines whether the flow should be terminated.
        Triggers:
        1. TCP mutual FIN or RST.
        2. Inactivity timeout (gap since last packet >= timeout_us).
        3. Maximum flow duration (total duration >= timeout_us).
        """
        if self.is_closed:
            return True

        if self.protocol == 6:
            # TCP RST received from either side terminates flow
            if self.rst_count >= 1:
                self.is_closed = True
                self.teardown_reason = "tcp_rst"
                self._finalize_active_period()
                return True
            # Mutual FIN received terminates flow
            if self.fwd_fin_count >= 1 and self.bwd_fin_count >= 1:
                self.is_closed = True
                self.teardown_reason = "tcp_fin_mutual"
                self._finalize_active_period()
                return True

        # Inactivity timeout
        if (now_us - self.last_time_us) >= timeout_us:
            self.is_closed = True
            self.teardown_reason = "inactivity_timeout"
            self._finalize_active_period()
            return True

        # Maximum flow duration ceiling (~120s in CICFlowMeter)
        if (self.last_time_us - self.start_time_us) >= timeout_us:
            self.is_closed = True
            self.teardown_reason = "max_duration"
            self._finalize_active_period()
            return True

        return False

    def close(self, reason: str = "manual_flush") -> None:
        """Manually closes the flow."""
        self.is_closed = True
        self.teardown_reason = reason
        self._finalize_active_period()

    def _finalize_active_period(self) -> None:
        """Finalizes the active period calculation upon closure."""
        active_duration = max(0.0, self.current_active_last - self.current_active_start)
        if active_duration > 0 and len(self.idle_periods) > 0:
            self.active_periods.append(active_duration)


class FlowTracker:
    """
    Manages the table of active flows with bounded memory capacity
    and eviction policies.
    """

    def __init__(
        self,
        max_flows: int = 20_000,
        inactivity_timeout_us: float = 120_000_000.0,  # 120 seconds
    ):
        self.max_flows = max_flows
        self.inactivity_timeout_us = inactivity_timeout_us
        self.flows: Dict[FlowKey, Flow] = {}
        self.total_flows_created = 0
        self.total_packets_processed = 0

    def process_packet(self, pkt: DissectedPacket) -> Optional[Flow]:
        """
        Ingests a dissected packet, updates or creates the flow, and returns
        the completed Flow if a teardown event was triggered.
        """
        self.total_packets_processed += 1
        fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        bwd_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

        if fwd_key in self.flows:
            flow = self.flows[fwd_key]
            flow.add_packet(pkt, is_forward=True)
            if flow.check_teardown(pkt.timestamp_us, self.inactivity_timeout_us):
                del self.flows[fwd_key]
                return flow
            return None

        if bwd_key in self.flows:
            flow = self.flows[bwd_key]
            flow.add_packet(pkt, is_forward=False)
            if flow.check_teardown(pkt.timestamp_us, self.inactivity_timeout_us):
                del self.flows[bwd_key]
                return flow
            return None

        # Check bounded capacity before allocating new flow
        if len(self.flows) >= self.max_flows:
            self._evict_oldest_flow()

        # Allocate new flow (first-packet defines FORWARD direction)
        flow = Flow(
            key=fwd_key,
            start_time_us=pkt.timestamp_us,
            last_time_us=pkt.timestamp_us,
            fwd_src_ip=pkt.src_ip,
            fwd_dst_ip=pkt.dst_ip,
            fwd_src_port=pkt.src_port,
            fwd_dst_port=pkt.dst_port,
            protocol=pkt.protocol,
        )
        flow.add_packet(pkt, is_forward=True)
        self.flows[fwd_key] = flow
        self.total_flows_created += 1

        if flow.check_teardown(pkt.timestamp_us, self.inactivity_timeout_us):
            del self.flows[fwd_key]
            return flow

        return None

    def _evict_oldest_flow(self) -> None:
        """Evicts the least recently updated flow to protect memory bounds."""
        if not self.flows:
            return
        oldest_key = min(self.flows.keys(), key=lambda k: self.flows[k].last_time_us)
        oldest_flow = self.flows.pop(oldest_key)
        oldest_flow.close(reason="lru_capacity_eviction")

    def sweep_timeouts(self, now_us: Optional[float] = None) -> List[Flow]:
        """
        Checks all active flows against the inactivity timeout and returns
        all newly expired flows.
        """
        if now_us is None:
            now_us = time.time() * 1_000_000.0

        expired: List[Flow] = []
        keys_to_remove: List[FlowKey] = []

        for key, flow in self.flows.items():
            if flow.check_teardown(now_us, self.inactivity_timeout_us):
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        return expired

    def flush_all(self, reason: str = "shutdown_flush") -> List[Flow]:
        """Flushes all surviving flows from memory on clean shutdown."""
        flushed: List[Flow] = []
        for flow in self.flows.values():
            flow.close(reason=reason)
            flushed.append(flow)
        self.flows.clear()
        return flushed
