"""
feature_extractor.py
Separately testable 63-feature extraction module.
Preserves the exact column ordering and naming contract from models/replacement_v1/selected_features.txt.

EXPERIMENTAL IMPLEMENTATION NOTICE:
This extractor implements verified arithmetic definitions (e.g., Bessel's sample standard
deviation with N-1 degrees of freedom, integer truncation for Down/Up Ratio, zero-filling
for non-TCP initial window fields), but flow state-machine thresholds and internal Java
CICFlowMeter quirks remain EXPERIMENTAL and NOT verified for byte-parity against raw PCAP ground truth.
"""

import math
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

from .flow_tracker import Flow

# Status indicator required by Work Order Milestone 1
EXTRACTOR_STATUS = "EXPERIMENTAL"
EXTRACTOR_DISCLAIMER = (
    "EXPERIMENTAL PROTOTYPE: Feature formulas implement best-effort empirical parity. "
    "Full equivalence against original Java CICFlowMeter has not been independently established."
)

SELECTED_FEATURES_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "models"
    / "replacement_v1"
    / "selected_features.txt"
)


def load_model_features() -> List[str]:
    """Loads the exact 63 selected feature names in sequence."""
    if SELECTED_FEATURES_PATH.is_file():
        lines = [
            line.strip()
            for line in SELECTED_FEATURES_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if len(lines) == 63:
            return lines

    # Fallback to the canonical 63-feature list verified in Stage 4B-0
    return [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags",
        "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
        "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
        "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
        "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max",
        "Idle Min"
    ]


ORDERED_FEATURES = load_model_features()


class FeatureExtractor:
    """Extracts exactly 63 training-compatible flow features from a Flow instance."""

    @staticmethod
    def _sample_std(values: List[float]) -> float:
        """Computes sample standard deviation with Bessel's correction (N-1)."""
        n = len(values)
        if n <= 1:
            return 0.0
        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / (n - 1)
        return math.sqrt(max(0.0, variance))

    @staticmethod
    def _sample_variance(values: List[float]) -> float:
        """Computes sample variance with Bessel's correction (N-1)."""
        n = len(values)
        if n <= 1:
            return 0.0
        mean_val = sum(values) / n
        return max(0.0, sum((x - mean_val) ** 2 for x in values) / (n - 1))

    @classmethod
    def extract_features(cls, flow: Flow) -> Dict[str, float]:
        """
        Extracts all 63 features from a Flow object in dictionary form.
        All non-finite, missing, or negative values are safely clamped to 0.0.
        """
        duration_us = max(0.0, flow.last_time_us - flow.start_time_us)
        duration_s = duration_us / 1_000_000.0

        # Inter-arrival times
        all_iats: List[float] = []
        if len(flow.all_timestamps) > 1:
            all_iats = [
                flow.all_timestamps[i] - flow.all_timestamps[i - 1]
                for i in range(1, len(flow.all_timestamps))
            ]

        fwd_iats: List[float] = []
        if len(flow.fwd_timestamps) > 1:
            fwd_iats = [
                flow.fwd_timestamps[i] - flow.fwd_timestamps[i - 1]
                for i in range(1, len(flow.fwd_timestamps))
            ]

        bwd_iats: List[float] = []
        if len(flow.bwd_timestamps) > 1:
            bwd_iats = [
                flow.bwd_timestamps[i] - flow.bwd_timestamps[i - 1]
                for i in range(1, len(flow.bwd_timestamps))
            ]

        # Rate calculations
        total_bytes = flow.total_fwd_bytes + flow.total_bwd_bytes
        total_packets = flow.total_fwd_packets + flow.total_bwd_packets
        flow_bytes_s = (total_bytes / duration_s) if duration_s > 0 else 0.0
        flow_packets_s = (total_packets / duration_s) if duration_s > 0 else 0.0
        fwd_packets_s = (flow.total_fwd_packets / duration_s) if duration_s > 0 else 0.0
        bwd_packets_s = (flow.total_bwd_packets / duration_s) if duration_s > 0 else 0.0

        # Down/Up Ratio: Integer truncation verified from dataset
        down_up_ratio = (
            float(int(flow.total_bwd_packets / flow.total_fwd_packets))
            if flow.total_fwd_packets > 0
            else 0.0
        )

        # Average packet size
        avg_packet_size = (
            (sum(flow.all_payload_lengths) / len(flow.all_payload_lengths))
            if flow.all_payload_lengths
            else 0.0
        )

        # Forward packets with payload > 0
        act_data_pkt_fwd = sum(1 for p in flow.fwd_payload_lengths if p > 0)

        # Minimum segment size forward (TCP header size)
        min_seg_size = (
            float(flow.min_seg_size_fwd)
            if flow.min_seg_size_fwd < 65535
            else (20.0 if flow.protocol == 6 else 8.0)
        )

        # Initial window values (0.0 for UDP or unseen)
        init_win_fwd = float(flow.init_win_fwd) if (flow.protocol == 6 and flow.has_init_win_fwd) else 0.0
        init_win_bwd = float(flow.init_win_bwd) if (flow.protocol == 6 and flow.has_init_win_bwd) else 0.0

        # Raw computed map
        raw_map: Dict[str, float] = {
            "Destination Port": float(flow.fwd_dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(flow.total_fwd_packets),
            "Total Backward Packets": float(flow.total_bwd_packets),
            "Total Length of Fwd Packets": float(flow.total_fwd_bytes),
            "Total Length of Bwd Packets": float(flow.total_bwd_bytes),
            "Fwd Packet Length Max": float(max(flow.fwd_payload_lengths) if flow.fwd_payload_lengths else 0.0),
            "Fwd Packet Length Min": float(min(flow.fwd_payload_lengths) if flow.fwd_payload_lengths else 0.0),
            "Fwd Packet Length Mean": float(sum(flow.fwd_payload_lengths) / len(flow.fwd_payload_lengths) if flow.fwd_payload_lengths else 0.0),
            "Fwd Packet Length Std": float(cls._sample_std(flow.fwd_payload_lengths)),
            "Bwd Packet Length Max": float(max(flow.bwd_payload_lengths) if flow.bwd_payload_lengths else 0.0),
            "Bwd Packet Length Min": float(min(flow.bwd_payload_lengths) if flow.bwd_payload_lengths else 0.0),
            "Bwd Packet Length Mean": float(sum(flow.bwd_payload_lengths) / len(flow.bwd_payload_lengths) if flow.bwd_payload_lengths else 0.0),
            "Bwd Packet Length Std": float(cls._sample_std(flow.bwd_payload_lengths)),
            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_packets_s),
            "Flow IAT Mean": float(sum(all_iats) / len(all_iats) if all_iats else 0.0),
            "Flow IAT Std": float(cls._sample_std(all_iats)),
            "Flow IAT Max": float(max(all_iats) if all_iats else 0.0),
            "Flow IAT Min": float(min(all_iats) if all_iats else 0.0),
            "Fwd IAT Total": float(sum(fwd_iats) if fwd_iats else 0.0),
            "Fwd IAT Mean": float(sum(fwd_iats) / len(fwd_iats) if fwd_iats else 0.0),
            "Fwd IAT Std": float(cls._sample_std(fwd_iats)),
            "Fwd IAT Max": float(max(fwd_iats) if fwd_iats else 0.0),
            "Fwd IAT Min": float(min(fwd_iats) if fwd_iats else 0.0),
            "Bwd IAT Total": float(sum(bwd_iats) if bwd_iats else 0.0),
            "Bwd IAT Mean": float(sum(bwd_iats) / len(bwd_iats) if bwd_iats else 0.0),
            "Bwd IAT Std": float(cls._sample_std(bwd_iats)),
            "Bwd IAT Max": float(max(bwd_iats) if bwd_iats else 0.0),
            "Bwd IAT Min": float(min(bwd_iats) if bwd_iats else 0.0),
            "Fwd PSH Flags": float(1.0 if flow.fwd_psh_count > 0 else 0.0),
            "Fwd URG Flags": float(1.0 if flow.fwd_urg_count > 0 else 0.0),
            "Fwd Header Length": float(flow.fwd_header_bytes),
            "Bwd Header Length": float(flow.bwd_header_bytes),
            "Fwd Packets/s": float(fwd_packets_s),
            "Bwd Packets/s": float(bwd_packets_s),
            "Min Packet Length": float(min(flow.all_payload_lengths) if flow.all_payload_lengths else 0.0),
            "Max Packet Length": float(max(flow.all_payload_lengths) if flow.all_payload_lengths else 0.0),
            "Packet Length Mean": float(sum(flow.all_payload_lengths) / len(flow.all_payload_lengths) if flow.all_payload_lengths else 0.0),
            "Packet Length Std": float(cls._sample_std(flow.all_payload_lengths)),
            "Packet Length Variance": float(cls._sample_variance(flow.all_payload_lengths)),
            "FIN Flag Count": float(1.0 if flow.fin_count > 0 else 0.0),
            "SYN Flag Count": float(1.0 if flow.syn_count > 0 else 0.0),
            "RST Flag Count": float(1.0 if flow.rst_count > 0 else 0.0),
            "PSH Flag Count": float(1.0 if flow.psh_count > 0 else 0.0),
            "ACK Flag Count": float(1.0 if flow.ack_count > 0 else 0.0),
            "URG Flag Count": float(1.0 if flow.urg_count > 0 else 0.0),
            "CWE Flag Count": float(1.0 if flow.cwe_count > 0 else 0.0),
            "ECE Flag Count": float(1.0 if flow.ece_count > 0 else 0.0),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_packet_size),
            "Init_Win_bytes_forward": float(init_win_fwd),
            "Init_Win_bytes_backward": float(init_win_bwd),
            "act_data_pkt_fwd": float(act_data_pkt_fwd),
            "min_seg_size_forward": float(min_seg_size),
            "Active Mean": float(sum(flow.active_periods) / len(flow.active_periods) if flow.active_periods else 0.0),
            "Active Std": float(cls._sample_std(flow.active_periods)),
            "Active Max": float(max(flow.active_periods) if flow.active_periods else 0.0),
            "Active Min": float(min(flow.active_periods) if flow.active_periods else 0.0),
            "Idle Mean": float(sum(flow.idle_periods) / len(flow.idle_periods) if flow.idle_periods else 0.0),
            "Idle Std": float(cls._sample_std(flow.idle_periods)),
            "Idle Max": float(max(flow.idle_periods) if flow.idle_periods else 0.0),
            "Idle Min": float(min(flow.idle_periods) if flow.idle_periods else 0.0),
        }

        # Build ordered dictionary adhering strictly to ORDERED_FEATURES
        ordered_dict: Dict[str, float] = {}
        for feature_name in ORDERED_FEATURES:
            val = raw_map.get(feature_name, 0.0)
            # Sanitize: ensure numeric float, zero out NaN, inf, or negative anomalies
            if math.isnan(val) or math.isinf(val) or val < 0.0:
                val = 0.0
            ordered_dict[feature_name] = float(val)

        return ordered_dict

    @classmethod
    def flows_to_dataframe(cls, flows: List[Flow]) -> pd.DataFrame:
        """Converts a batch of Flow objects into a 63-feature pandas DataFrame."""
        rows = [cls.extract_features(f) for f in flows]
        df = pd.DataFrame(rows, columns=ORDERED_FEATURES)
        return df.fillna(0.0)
