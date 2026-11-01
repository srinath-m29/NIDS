"""
NIDS Stage 4B Live Capture and Flow Extraction Package.
Provides packet dissection, bidirectional flow tracking, 63-feature extraction,
and isolated inference worker for Windows 11.
"""

from .packet_dissector import DissectedPacket, PacketDissector
from .flow_tracker import Flow, FlowTracker
from .feature_extractor import FeatureExtractor, EXTRACTOR_STATUS
from .live_capture_worker import LiveCaptureWorker

__all__ = [
    "DissectedPacket",
    "PacketDissector",
    "Flow",
    "FlowTracker",
    "FeatureExtractor",
    "EXTRACTOR_STATUS",
    "LiveCaptureWorker",
]
