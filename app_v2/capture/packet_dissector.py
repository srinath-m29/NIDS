"""
packet_dissector.py
Pure-Python Layer 2 / Layer 3 / Layer 4 Packet Dissector.
Parses Ethernet, IPv4, TCP, and UDP packet buffers using standard struct decoding.
"""

from dataclasses import dataclass, field
import socket
import struct
import time
from typing import Dict, Optional, Tuple


@dataclass
class DissectedPacket:
    timestamp_us: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
    ip_header_length: int
    l4_header_length: int
    total_header_length: int
    payload_length: int
    tcp_flags: Dict[str, int] = field(default_factory=lambda: {
        "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
        "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0
    })
    tcp_window: int = 0
    seq_num: int = 0
    ack_num: int = 0


class PacketDissector:
    """Decodes raw binary packet frames into structured DissectedPacket instances."""

    ETHERTYPE_IPV4 = 0x0800
    PROTOCOL_TCP = 6
    PROTOCOL_UDP = 17

    @staticmethod
    def current_timestamp_us() -> float:
        """Returns the current monotonic epoch timestamp in microseconds."""
        return time.time() * 1_000_000.0

    @classmethod
    def dissect_raw_ethernet(
        cls, frame: bytes, timestamp_us: Optional[float] = None
    ) -> Optional[DissectedPacket]:
        """
        Dissects an IEEE 802.3 Ethernet II frame.
        Expects 14-byte Ethernet header: 6B dst_mac, 6B src_mac, 2B ethertype.
        """
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype != cls.ETHERTYPE_IPV4:
            return None
        return cls.dissect_ipv4_packet(frame[14:], timestamp_us=timestamp_us)

    @classmethod
    def dissect_loopback_frame(
        cls, frame: bytes, timestamp_us: Optional[float] = None
    ) -> Optional[DissectedPacket]:
        """
        Dissects a Windows Npcap / BSD loopback frame (DLT_NULL).
        Expects a 4-byte address family header (AF_INET = 2) followed by IPv4 packet.
        """
        if len(frame) < 24:  # 4B loopback + 20B IPv4
            return None
        family_le = struct.unpack("<I", frame[:4])[0]
        family_be = struct.unpack(">I", frame[:4])[0]
        AF_INET = 2
        if family_le == AF_INET or family_be == AF_INET:
            return cls.dissect_ipv4_packet(frame[4:], timestamp_us=timestamp_us)
        return None

    @classmethod
    def dissect_any(
        cls, buffer: bytes, timestamp_us: Optional[float] = None
    ) -> Optional[DissectedPacket]:
        """
        Automatically detects framing (Raw IPv4, Loopback DLT_NULL, or Ethernet II)
        and parses the packet into a DissectedPacket.
        """
        if not buffer:
            return None

        # 1. Check if buffer is already a raw IPv4 packet (starts with version 4)
        if len(buffer) >= 20 and (buffer[0] >> 4) == 4:
            pkt = cls.dissect_ipv4_packet(buffer, timestamp_us=timestamp_us)
            if pkt:
                return pkt

        # 2. Check if buffer is an Npcap Loopback frame (4-byte family + IPv4)
        if len(buffer) >= 24:
            pkt = cls.dissect_loopback_frame(buffer, timestamp_us=timestamp_us)
            if pkt:
                return pkt

        # 3. Check if buffer is an Ethernet II frame (14-byte header + IPv4)
        if len(buffer) >= 34:
            pkt = cls.dissect_raw_ethernet(buffer, timestamp_us=timestamp_us)
            if pkt:
                return pkt

        return None

    @classmethod
    def check_is_ipv6(cls, buffer: bytes) -> bool:
        """Detects whether raw buffer is an IPv6 packet in raw, loopback, or Ethernet framing."""
        if not buffer:
            return False
        # Raw IPv6 packet
        if len(buffer) >= 40 and (buffer[0] >> 4) == 6:
            return True
        # Npcap Loopback frame (4-byte family + IPv6)
        if len(buffer) >= 44:
            family_le = struct.unpack("<I", buffer[:4])[0]
            family_be = struct.unpack(">I", buffer[:4])[0]
            # AF_INET6 on Windows is typically 23
            if family_le in (23, 24, 28, 30) or family_be in (23, 24, 28, 30) or (buffer[4] >> 4) == 6:
                return True
        # Ethernet II frame with EtherType 0x86DD (IPv6)
        if len(buffer) >= 14:
            ethertype = struct.unpack("!H", buffer[12:14])[0]
            if ethertype == 0x86DD:
                return True
        return False

    @classmethod
    def dissect_ipv4_packet(
        cls, ip_data: bytes, timestamp_us: Optional[float] = None
    ) -> Optional[DissectedPacket]:
        """
        Dissects an IPv4 packet buffer starting with the IPv4 header.
        """
        if len(ip_data) < 20:
            return None

        # Parse IPv4 header
        version_ihl = ip_data[0]
        version = version_ihl >> 4
        if version != 4:
            return None
        ihl = version_ihl & 0x0F
        ip_header_length = ihl * 4
        if len(ip_data) < ip_header_length:
            return None

        total_length, _, _, _, protocol = struct.unpack("!HH2sBB", ip_data[2:10])
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        if timestamp_us is None:
            timestamp_us = cls.current_timestamp_us()

        l4_data = ip_data[ip_header_length:]

        if protocol == cls.PROTOCOL_TCP:
            return cls._dissect_tcp(
                l4_data,
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_header_length=ip_header_length,
                ip_total_length=total_length,
                timestamp_us=timestamp_us,
            )
        elif protocol == cls.PROTOCOL_UDP:
            return cls._dissect_udp(
                l4_data,
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_header_length=ip_header_length,
                ip_total_length=total_length,
                timestamp_us=timestamp_us,
            )
        else:
            # Unsupported L4 protocol (e.g., ICMP, IGMP)
            return None

    @classmethod
    def _dissect_tcp(
        cls,
        l4_data: bytes,
        src_ip: str,
        dst_ip: str,
        ip_header_length: int,
        ip_total_length: int,
        timestamp_us: float,
    ) -> Optional[DissectedPacket]:
        if len(l4_data) < 20:
            return None

        src_port, dst_port, seq, ack, offset_reserved, flags_byte, window = struct.unpack(
            "!HHIIBBH", l4_data[:16]
        )
        data_offset = (offset_reserved >> 4) * 4
        if len(l4_data) < data_offset:
            return None

        # TCP flags parsing
        # bit 0: FIN, 1: SYN, 2: RST, 3: PSH, 4: ACK, 5: URG, 6: ECE, 7: CWR
        flags = {
            "FIN": 1 if (flags_byte & 0x01) else 0,
            "SYN": 1 if (flags_byte & 0x02) else 0,
            "RST": 1 if (flags_byte & 0x04) else 0,
            "PSH": 1 if (flags_byte & 0x08) else 0,
            "ACK": 1 if (flags_byte & 0x10) else 0,
            "URG": 1 if (flags_byte & 0x20) else 0,
            "ECE": 1 if (flags_byte & 0x40) else 0,
            "CWR": 1 if (flags_byte & 0x80) else 0,
        }

        # Calculate payload length
        # Prefer IP Total Length minus headers if valid, otherwise actual buffer slice
        if ip_total_length >= (ip_header_length + data_offset):
            payload_len = ip_total_length - (ip_header_length + data_offset)
        else:
            payload_len = max(0, len(l4_data) - data_offset)

        return DissectedPacket(
            timestamp_us=timestamp_us,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=cls.PROTOCOL_TCP,
            ip_header_length=ip_header_length,
            l4_header_length=data_offset,
            total_header_length=ip_header_length + data_offset,
            payload_length=payload_len,
            tcp_flags=flags,
            tcp_window=window,
            seq_num=seq,
            ack_num=ack,
        )

    @classmethod
    def _dissect_udp(
        cls,
        l4_data: bytes,
        src_ip: str,
        dst_ip: str,
        ip_header_length: int,
        ip_total_length: int,
        timestamp_us: float,
    ) -> Optional[DissectedPacket]:
        if len(l4_data) < 8:
            return None

        src_port, dst_port, udp_length, _ = struct.unpack("!HHHH", l4_data[:8])
        udp_header_length = 8
        payload_len = max(0, udp_length - udp_header_length)

        return DissectedPacket(
            timestamp_us=timestamp_us,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=cls.PROTOCOL_UDP,
            ip_header_length=ip_header_length,
            l4_header_length=udp_header_length,
            total_header_length=ip_header_length + udp_header_length,
            payload_length=payload_len,
            tcp_flags={
                "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
                "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0
            },
            tcp_window=0,
            seq_num=0,
            ack_num=0,
        )
