"""
Forensic PCAP File Parser for ForensiX (V5.2 PCAP Parsing).

Provides streaming, read-only parsing of classic PCAP network packet captures
into validated, deeply immutable NetworkEvidenceRecord instances (V5.1),
supporting both microsecond and nanosecond timestamp resolutions across
big-endian and little-endian captures.

Strict Forensic Disciplines:
1. Observed vs Derived vs Interpreted:
   - OBSERVED: frame_number, timestamps, captured/original wire lengths, link-layer
     addresses, network-layer IP addresses, transport-layer ports, and packet metadata.
   - DERIVED: deterministic record_id (RFC 4122 UUIDv5 via V5.1 model), normalized UTC timestamp.
   - INTERPRETED: Disallowed. No speculative verdicts, threat scoring, or attack labels.
2. Provenance Traceability:
   - Strictly populates source evidence path or artifact ID into every emitted record,
     ensuring deterministic IDs do not collide on the V5.1 'source:default' fallback.
   - 1-indexed frame numbering strictly preserved.
3. Immutability & Memory Safety:
   - Pure read-only streaming processing; never modifies evidence files.
   - Streams packet by packet with bounded memory consumption.
   - Validates packet lengths against configurable safety limits before allocating byte buffers.
4. Determinism & Precision:
   - Preserves exact nanosecond or microsecond integer timestamps in raw_timestamp
     without floating-point truncation.
   - Rejects unsupported PCAP-NG formats with explicit diagnostics.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import io
import ipaddress
from pathlib import Path
import struct
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple, Union

from forensix.network_models import (
    NetworkEvidenceRecord,
    create_network_evidence_record,
)


# Classic PCAP 32-bit Magic Numbers
PCAP_MAGIC_MICROSECONDS_BIG: int = 0xA1B2C3D4
PCAP_MAGIC_MICROSECONDS_LITTLE: int = 0xD4C3B2A1
PCAP_MAGIC_NANOSECONDS_BIG: int = 0xA1B23C4D
PCAP_MAGIC_NANOSECONDS_LITTLE: int = 0x4D3CB2A1

# PCAP-NG Section Header Block Magic (0x0A0D0D0A)
PCAPNG_SECTION_HEADER_MAGIC: int = 0x0A0D0D0A

# Supported Data Link Types (DLT)
DLT_NULL: int = 0          # BSD Loopback
DLT_EN10MB: int = 1        # Ethernet (10Mb, 100Mb, 1Gb+)
DLT_RAW: int = 12          # Raw IP (no link-layer header)
DLT_LINUX_SLL: int = 113   # Linux Cooked Capture v1

SUPPORTED_LINK_TYPES: Dict[int, str] = {
    DLT_NULL: "NULL",
    DLT_EN10MB: "ETHERNET",
    DLT_RAW: "RAW",
    DLT_LINUX_SLL: "LINUX_SLL",
}

# Standard PCAP Global Header size (bytes)
PCAP_GLOBAL_HEADER_SIZE: int = 24

# Standard PCAP Packet Record Header size (bytes)
PCAP_RECORD_HEADER_SIZE: int = 16

# Default maximum packet buffer allocation safety limit (256 KB)
DEFAULT_MAX_PACKET_SIZE: int = 262144


class PcapError(ValueError):
    """Base exception for all PCAP parsing failures in ForensiX."""


class PcapCorruptError(PcapError):
    """Raised when PCAP structural metadata or headers are malformed or invalid."""


class PcapTruncatedError(PcapError):
    """Raised when a PCAP file ends prematurely during header or packet reading."""


class PcapUnsupportedError(PcapError):
    """Raised when an unsupported PCAP version, link type, or PCAP-NG file is encountered."""


@dataclass(frozen=True)
class PcapGlobalHeader:
    """
    Immutable representation of a validated classic PCAP 24-byte global header.

    Attributes:
        magic: 32-bit integer magic value identifying format and byte order.
        version_major: Major format version (expected: 2).
        version_minor: Minor format version (expected: 4).
        thiszone: GMT to local correction in seconds (usually 0).
        sigfigs: Accuracy of timestamps (usually 0).
        snaplen: Maximum packet length captured in bytes.
        network: Data link layer type code (e.g. 1 for Ethernet).
        byte_order: Capture byte order ('big' or 'little').
        ts_resolution: Timestamp resolution ('microsecond' or 'nanosecond').
        link_layer: Canonical normalized link layer identifier (e.g. 'ETHERNET').
    """

    magic: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    byte_order: str
    ts_resolution: str
    link_layer: str


def _format_mac(mac_bytes: bytes) -> str:
    """Format 6 bytes as a standard lowercase colon-separated MAC address string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _dissect_ipv4_payload(
    ip_bytes: bytes,
) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[int],
    Optional[int],
    Optional[str],
    Optional[str],
    Optional[str],
    Dict[str, Any],
]:
    """
    Dissect an IPv4 datagram payload safely.

    Returns:
        (src_ip, dst_ip, src_port, dst_port, protocol, network_protocol, transport_protocol, metadata)
    """
    if len(ip_bytes) < 20:
        return (None, None, None, None, "IPV4", "IPV4", None, {})

    version_ihl = ip_bytes[0]
    version = version_ihl >> 4
    if version != 4:
        return (None, None, None, None, None, None, None, {})

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(ip_bytes) < ihl:
        return (None, None, None, None, "IPV4", "IPV4", None, {})

    try:
        src_ip = str(ipaddress.IPv4Address(ip_bytes[12:16]))
        dst_ip = str(ipaddress.IPv4Address(ip_bytes[16:20]))
    except ValueError:
        return (None, None, None, None, "IPV4", "IPV4", None, {})

    proto_num = ip_bytes[9]
    flags_frag = struct.unpack(">H", ip_bytes[6:8])[0]
    frag_offset = (flags_frag & 0x1FFF) * 8
    more_fragments = bool(flags_frag & 0x2000)

    metadata: Dict[str, Any] = {}
    if frag_offset > 0 or more_fragments:
        metadata["fragment"] = True
        metadata["fragment_offset"] = frag_offset
        if more_fragments:
            metadata["more_fragments"] = True

    # If this is a non-initial fragment, the payload does NOT contain transport headers
    if frag_offset > 0:
        proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else f"IP-{proto_num}"))
        return (src_ip, dst_ip, None, None, proto_name, "IPV4", None, metadata)

    transport_bytes = ip_bytes[ihl:]
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    protocol: str = "IPV4"

    if proto_num == 6:  # TCP
        protocol = "TCP"
        transport_protocol = "TCP"
        if len(transport_bytes) >= 4:
            src_port, dst_port = struct.unpack(">HH", transport_bytes[0:4])
        if len(transport_bytes) >= 20:
            flags_byte = transport_bytes[13]
            flags_list: List[str] = []
            if flags_byte & 0x01:
                flags_list.append("FIN")
            if flags_byte & 0x02:
                flags_list.append("SYN")
            if flags_byte & 0x04:
                flags_list.append("RST")
            if flags_byte & 0x08:
                flags_list.append("PSH")
            if flags_byte & 0x10:
                flags_list.append("ACK")
            if flags_byte & 0x20:
                flags_list.append("URG")
            if flags_list:
                metadata["tcp_flags"] = flags_list
            metadata["seq"] = struct.unpack(">I", transport_bytes[4:8])[0]
            metadata["ack"] = struct.unpack(">I", transport_bytes[8:12])[0]
            metadata["window_size"] = struct.unpack(">H", transport_bytes[14:16])[0]

    elif proto_num == 17:  # UDP
        protocol = "UDP"
        transport_protocol = "UDP"
        if len(transport_bytes) >= 4:
            src_port, dst_port = struct.unpack(">HH", transport_bytes[0:4])

    elif proto_num == 1:  # ICMP
        protocol = "ICMP"
        transport_protocol = "ICMP"
        if len(transport_bytes) >= 2:
            metadata["icmp_type"] = transport_bytes[0]
            metadata["icmp_code"] = transport_bytes[1]

    else:
        protocol = f"IP-{proto_num}"

    return (src_ip, dst_ip, src_port, dst_port, protocol, "IPV4", transport_protocol, metadata)


def _dissect_ipv6_payload(
    ip_bytes: bytes,
) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[int],
    Optional[int],
    Optional[str],
    Optional[str],
    Optional[str],
    Dict[str, Any],
]:
    """
    Dissect an IPv6 datagram payload safely.

    Returns:
        (src_ip, dst_ip, src_port, dst_port, protocol, network_protocol, transport_protocol, metadata)
    """
    if len(ip_bytes) < 40:
        return (None, None, None, None, "IPV6", "IPV6", None, {})

    version = ip_bytes[0] >> 4
    if version != 6:
        return (None, None, None, None, None, None, None, {})

    try:
        src_ip = str(ipaddress.IPv6Address(ip_bytes[8:24]))
        dst_ip = str(ipaddress.IPv6Address(ip_bytes[24:40]))
    except ValueError:
        return (None, None, None, None, "IPV6", "IPV6", None, {})

    next_hdr = ip_bytes[6]
    ext_offset = 40
    metadata: Dict[str, Any] = {}
    is_fragment = False

    # Hop through standard extension headers
    while ext_offset < len(ip_bytes):
        if next_hdr == 44:  # Fragment Header (8 bytes)
            if len(ip_bytes) >= ext_offset + 8:
                is_fragment = True
                frag_next_hdr = ip_bytes[ext_offset]
                offset_m = struct.unpack(">H", ip_bytes[ext_offset + 2:ext_offset + 4])[0]
                frag_offset = (offset_m >> 3) * 8
                m_flag = bool(offset_m & 0x01)
                metadata["fragment"] = True
                metadata["fragment_offset"] = frag_offset
                if m_flag:
                    metadata["more_fragments"] = True
                if frag_offset > 0:
                    # Non-initial fragment: cannot parse transport headers
                    proto_name = "TCP" if frag_next_hdr == 6 else ("UDP" if frag_next_hdr == 17 else ("ICMPV6" if frag_next_hdr == 58 else f"IP-{frag_next_hdr}"))
                    return (src_ip, dst_ip, None, None, proto_name, "IPV6", None, metadata)
                next_hdr = frag_next_hdr
                ext_offset += 8
            else:
                break
        elif next_hdr in (0, 43, 60):  # Hop-by-Hop, Routing, Destination Options
            if len(ip_bytes) >= ext_offset + 2:
                hdr_len = (ip_bytes[ext_offset + 1] + 1) * 8
                next_hdr = ip_bytes[ext_offset]
                ext_offset += hdr_len
            else:
                break
        else:
            break

    transport_bytes = ip_bytes[ext_offset:]
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    protocol: str = "IPV6"

    if next_hdr == 6:  # TCP
        protocol = "TCP"
        transport_protocol = "TCP"
        if len(transport_bytes) >= 4:
            src_port, dst_port = struct.unpack(">HH", transport_bytes[0:4])
        if len(transport_bytes) >= 20:
            flags_byte = transport_bytes[13]
            flags_list: List[str] = []
            if flags_byte & 0x01:
                flags_list.append("FIN")
            if flags_byte & 0x02:
                flags_list.append("SYN")
            if flags_byte & 0x04:
                flags_list.append("RST")
            if flags_byte & 0x08:
                flags_list.append("PSH")
            if flags_byte & 0x10:
                flags_list.append("ACK")
            if flags_byte & 0x20:
                flags_list.append("URG")
            if flags_list:
                metadata["tcp_flags"] = flags_list
            metadata["seq"] = struct.unpack(">I", transport_bytes[4:8])[0]
            metadata["ack"] = struct.unpack(">I", transport_bytes[8:12])[0]
            metadata["window_size"] = struct.unpack(">H", transport_bytes[14:16])[0]

    elif next_hdr == 17:  # UDP
        protocol = "UDP"
        transport_protocol = "UDP"
        if len(transport_bytes) >= 4:
            src_port, dst_port = struct.unpack(">HH", transport_bytes[0:4])

    elif next_hdr == 58:  # ICMPv6
        protocol = "ICMPV6"
        transport_protocol = "ICMPV6"
        if len(transport_bytes) >= 2:
            metadata["icmp_type"] = transport_bytes[0]
            metadata["icmp_code"] = transport_bytes[1]

    else:
        protocol = f"IP-{next_hdr}"

    return (src_ip, dst_ip, src_port, dst_port, protocol, "IPV6", transport_protocol, metadata)


def _dissect_packet(
    data: bytes,
    link_type: int,
    endianness: str,
) -> Tuple[
    Optional[str],  # link_layer
    Optional[str],  # src_mac
    Optional[str],  # dst_mac
    Optional[str],  # src_ip
    Optional[str],  # dst_ip
    Optional[int],  # src_port
    Optional[int],  # dst_port
    Optional[str],  # protocol
    Optional[str],  # network_protocol
    Optional[str],  # transport_protocol
    Dict[str, Any], # metadata
]:
    """
    Safely dissect packet payload into factual forensic attributes based on data link type.
    """
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    network_protocol: Optional[str] = None
    transport_protocol: Optional[str] = None
    metadata: Dict[str, Any] = {}

    link_layer_name = SUPPORTED_LINK_TYPES.get(link_type, "UNKNOWN")

    if link_type == DLT_EN10MB:
        if len(data) < 14:
            return (link_layer_name, None, None, None, None, None, None, None, None, None, {})

        dst_mac = _format_mac(data[0:6])
        src_mac = _format_mac(data[6:12])
        ethertype = struct.unpack(">H", data[12:14])[0]
        payload_offset = 14

        # Handle 802.1Q VLAN Tagging
        if ethertype in (0x8100, 0x88A8) and len(data) >= 18:
            vlan_tci = struct.unpack(">H", data[14:16])[0]
            metadata["vlan_id"] = vlan_tci & 0x0FFF
            ethertype = struct.unpack(">H", data[16:18])[0]
            payload_offset = 18

        payload = data[payload_offset:]

        if ethertype == 0x0800:  # IPv4
            s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv4_payload(payload)
            src_ip, dst_ip = s_ip, d_ip
            src_port, dst_port = s_p, d_p
            protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
            metadata.update(ip_meta)

        elif ethertype == 0x86DD:  # IPv6
            s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv6_payload(payload)
            src_ip, dst_ip = s_ip, d_ip
            src_port, dst_port = s_p, d_p
            protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
            metadata.update(ip_meta)

        elif ethertype == 0x0806:  # ARP
            protocol = "ARP"
            network_protocol = "ARP"
            if len(payload) >= 28:
                hw_type, p_type, hw_len, p_len, opcode = struct.unpack(">HHBBH", payload[0:8])
                metadata["arp_opcode"] = opcode
                if hw_len == 6 and p_len == 4:
                    metadata["arp_sender_mac"] = _format_mac(payload[8:14])
                    metadata["arp_target_mac"] = _format_mac(payload[18:24])

        else:
            protocol = f"ETH-0x{ethertype:04X}"

    elif link_type == DLT_RAW:
        if len(data) > 0:
            version = data[0] >> 4
            if version == 4:
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv4_payload(data)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)
            elif version == 6:
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv6_payload(data)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)

    elif link_type == DLT_NULL:
        if len(data) >= 4:
            family = struct.unpack(f"{endianness}I", data[0:4])[0]
            payload = data[4:]
            if family == 2:  # AF_INET IPv4
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv4_payload(payload)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)
            elif family in (24, 28, 30):  # AF_INET6 IPv6 variants
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv6_payload(payload)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)

    elif link_type == DLT_LINUX_SLL:
        if len(data) >= 16:
            pkt_type, arphrd, addr_len = struct.unpack(">HHH", data[0:6])
            if addr_len == 6:
                src_mac = _format_mac(data[6:12])
            proto_type = struct.unpack(">H", data[14:16])[0]
            payload = data[16:]
            if proto_type == 0x0800:
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv4_payload(payload)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)
            elif proto_type == 0x86DD:
                s_ip, d_ip, s_p, d_p, proto, net_proto, trans_proto, ip_meta = _dissect_ipv6_payload(payload)
                src_ip, dst_ip = s_ip, d_ip
                src_port, dst_port = s_p, d_p
                protocol, network_protocol, transport_protocol = proto, net_proto, trans_proto
                metadata.update(ip_meta)
            elif proto_type == 0x0806:
                protocol = "ARP"
                network_protocol = "ARP"

    return (
        link_layer_name,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        network_protocol,
        transport_protocol,
        metadata,
    )


def extract_transport_payload(
    data: bytes,
    link_type: int = DLT_EN10MB,
    endianness: str = "<",
) -> Tuple[Optional[str], Optional[int], Optional[int], bytes]:
    """
    Safely extract transport protocol, endpoint ports, and application payload bytes
    from a raw packet frame without stream reassembly.

    Returns:
        (transport_protocol, src_port, dst_port, payload_bytes)
        where transport_protocol is 'TCP', 'UDP', or None if unavailable/fragmented.
    """
    if not data:
        return (None, None, None, b"")

    payload_offset = 0
    ethertype: Optional[int] = None

    if link_type == DLT_EN10MB:
        if len(data) < 14:
            return (None, None, None, b"")
        ethertype = struct.unpack(">H", data[12:14])[0]
        payload_offset = 14
        if ethertype in (0x8100, 0x88A8) and len(data) >= 18:
            ethertype = struct.unpack(">H", data[16:18])[0]
            payload_offset = 18
    elif link_type == DLT_RAW:
        if len(data) == 0:
            return (None, None, None, b"")
        ver = data[0] >> 4
        ethertype = 0x0800 if ver == 4 else (0x86DD if ver == 6 else None)
        payload_offset = 0
    elif link_type == DLT_NULL:
        if len(data) < 4:
            return (None, None, None, b"")
        fam = struct.unpack(f"{endianness}I", data[0:4])[0]
        ethertype = 0x0800 if fam == 2 else (0x86DD if fam in (24, 28, 30) else None)
        payload_offset = 4
    elif link_type == DLT_LINUX_SLL:
        if len(data) < 16:
            return (None, None, None, b"")
        ethertype = struct.unpack(">H", data[14:16])[0]
        payload_offset = 16
    else:
        return (None, None, None, b"")

    ip_data = data[payload_offset:]

    if ethertype == 0x0800:  # IPv4
        if len(ip_data) < 20:
            return (None, None, None, b"")
        version_ihl = ip_data[0]
        if (version_ihl >> 4) != 4:
            return (None, None, None, b"")
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(ip_data) < ihl:
            return (None, None, None, b"")

        flags_frag = struct.unpack(">H", ip_data[6:8])[0]
        frag_offset = (flags_frag & 0x1FFF) * 8
        if frag_offset > 0:
            # Non-initial fragment: no transport headers present
            return (None, None, None, b"")

        proto_num = ip_data[9]
        trans_data = ip_data[ihl:]

        if proto_num == 6:  # TCP
            if len(trans_data) < 20:
                return ("TCP", None, None, b"")
            sp, dp = struct.unpack(">HH", trans_data[0:4])
            data_offset = (trans_data[12] >> 4) * 4
            if data_offset < 20 or len(trans_data) < data_offset:
                return ("TCP", sp, dp, b"")
            return ("TCP", sp, dp, trans_data[data_offset:])

        elif proto_num == 17:  # UDP
            if len(trans_data) < 8:
                return ("UDP", None, None, b"")
            sp, dp = struct.unpack(">HH", trans_data[0:4])
            return ("UDP", sp, dp, trans_data[8:])

        return (None, None, None, b"")

    elif ethertype == 0x86DD:  # IPv6
        if len(ip_data) < 40:
            return (None, None, None, b"")
        if (ip_data[0] >> 4) != 6:
            return (None, None, None, b"")

        next_hdr = ip_data[6]
        ext_offset = 40
        while ext_offset < len(ip_data):
            if next_hdr == 44:  # Fragment
                if len(ip_data) >= ext_offset + 8:
                    frag_next_hdr = ip_data[ext_offset]
                    offset_m = struct.unpack(">H", ip_data[ext_offset + 2:ext_offset + 4])[0]
                    if ((offset_m >> 3) * 8) > 0:
                        return (None, None, None, b"")
                    next_hdr = frag_next_hdr
                    ext_offset += 8
                else:
                    break
            elif next_hdr in (0, 43, 60):
                if len(ip_data) >= ext_offset + 2:
                    hdr_len = (ip_data[ext_offset + 1] + 1) * 8
                    next_hdr = ip_data[ext_offset]
                    ext_offset += hdr_len
                else:
                    break
            else:
                break

        trans_data = ip_data[ext_offset:]
        if next_hdr == 6:  # TCP
            if len(trans_data) < 20:
                return ("TCP", None, None, b"")
            sp, dp = struct.unpack(">HH", trans_data[0:4])
            data_offset = (trans_data[12] >> 4) * 4
            if data_offset < 20 or len(trans_data) < data_offset:
                return ("TCP", sp, dp, b"")
            return ("TCP", sp, dp, trans_data[data_offset:])

        elif next_hdr == 17:  # UDP
            if len(trans_data) < 8:
                return ("UDP", None, None, b"")
            sp, dp = struct.unpack(">HH", trans_data[0:4])
            return ("UDP", sp, dp, trans_data[8:])

    return (None, None, None, b"")


def _parse_global_header(raw_bytes: bytes, file_name: str) -> PcapGlobalHeader:
    """
    Validate and parse the 24-byte classic PCAP global header.

    Raises:
        PcapCorruptError: If header is malformed, truncated, or has invalid magic/snaplen.
        PcapUnsupportedError: If file is PCAP-NG, unsupported PCAP version, or unsupported link type.
    """
    if len(raw_bytes) < PCAP_GLOBAL_HEADER_SIZE:
        raise PcapCorruptError(
            f"Truncated PCAP global header in '{file_name}': expected {PCAP_GLOBAL_HEADER_SIZE} bytes, "
            f"got {len(raw_bytes)} bytes"
        )

    magic_bytes = raw_bytes[0:4]

    # Explicit rejection of PCAP-NG Section Header Block magic
    if magic_bytes == b"\x0a\x0d\x0d\x0a":
        raise PcapUnsupportedError(
            f"Unsupported PCAP-NG capture format (magic 0x0a0d0d0a) in '{file_name}'. "
            "Only classic PCAP format is supported in V5.2."
        )

    if magic_bytes == b"\xa1\xb2\xc3\xd4":
        byte_order = "big"
        endianness = ">"
        ts_resolution = "microsecond"
        magic = PCAP_MAGIC_MICROSECONDS_BIG
    elif magic_bytes == b"\xd4\xc3\xb2\xa1":
        byte_order = "little"
        endianness = "<"
        ts_resolution = "microsecond"
        magic = PCAP_MAGIC_MICROSECONDS_LITTLE
    elif magic_bytes == b"\xa1\xb2\x3c\x4d":
        byte_order = "big"
        endianness = ">"
        ts_resolution = "nanosecond"
        magic = PCAP_MAGIC_NANOSECONDS_BIG
    elif magic_bytes == b"\x4d\x3c\xb2\xa1":
        byte_order = "little"
        endianness = "<"
        ts_resolution = "nanosecond"
        magic = PCAP_MAGIC_NANOSECONDS_LITTLE
    else:
        raise PcapCorruptError(
            f"Invalid PCAP file header in '{file_name}': unrecognized magic bytes 0x{magic_bytes.hex()}"
        )

    ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
        f"{endianness}HHiIII", raw_bytes[4:24]
    )

    if ver_major != 2:
        raise PcapUnsupportedError(
            f"Unsupported PCAP version {ver_major}.{ver_minor} in '{file_name}': "
            "only version 2.x is supported"
        )

    if snaplen == 0:
        raise PcapCorruptError(
            f"Invalid PCAP global header in '{file_name}': snaplen cannot be 0"
        )

    if network not in SUPPORTED_LINK_TYPES:
        raise PcapUnsupportedError(
            f"Unsupported link-layer type {network} (DLT {network}) in '{file_name}'"
        )

    return PcapGlobalHeader(
        magic=magic,
        version_major=ver_major,
        version_minor=ver_minor,
        thiszone=thiszone,
        sigfigs=sigfigs,
        snaplen=snaplen,
        network=network,
        byte_order=byte_order,
        ts_resolution=ts_resolution,
        link_layer=SUPPORTED_LINK_TYPES[network],
    )


class PcapParser:
    """
    Streaming classic PCAP parser for ForensiX (V5.2 PCAP Parsing).

    Provides incremental, bounded-memory parsing of classic PCAP captures, emitting
    immutable NetworkEvidenceRecord instances while strictly preserving evidence integrity.
    """

    def __init__(
        self,
        source: Union[str, Path, BinaryIO],
        *,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    ) -> None:
        self._source = source
        self._source_artifact_id = source_artifact_id
        self._pcap_name_arg = pcap_name
        self._max_packet_size = max_packet_size
        self._header: Optional[PcapGlobalHeader] = None
        self._owns_stream: bool = False
        self._active_stream: Optional[BinaryIO] = None

        if isinstance(source, (str, Path)):
            self._path: Optional[Path] = Path(source).resolve()
            self._display_name: str = self._pcap_name_arg or self._path.name
        else:
            self._path = None
            self._display_name = self._pcap_name_arg or "in_memory.pcap"

    @property
    def display_name(self) -> str:
        """User-friendly display name or filename of the capture."""
        return self._display_name

    @property
    def source_path(self) -> Optional[str]:
        """Resolved filesystem path of the capture, or None for in-memory streams."""
        return str(self._path) if self._path is not None else None

    @property
    def source_artifact_id(self) -> Optional[str]:
        """Explicit tracking artifact identifier, if provided."""
        return self._source_artifact_id

    @property
    def global_header(self) -> PcapGlobalHeader:
        """
        Parsed and validated PCAP global header.
        Reads the header lazily from the source if not yet parsed.
        """
        if self._header is not None:
            return self._header

        # Read 24-byte header
        if self._path is not None:
            if not self._path.exists():
                raise FileNotFoundError(f"PCAP evidence file not found: '{self._path}'")
            if self._path.is_dir():
                raise IsADirectoryError(f"Target path is a directory, not a PCAP file: '{self._path}'")
            with open(self._path, "rb") as f:
                hdr_bytes = f.read(PCAP_GLOBAL_HEADER_SIZE)
        else:
            # Stream or BytesIO
            stream = self._source
            orig_pos = stream.tell() if hasattr(stream, "tell") else None
            hdr_bytes = stream.read(PCAP_GLOBAL_HEADER_SIZE)
            if orig_pos is not None and hasattr(stream, "seek"):
                stream.seek(orig_pos)

        self._header = _parse_global_header(hdr_bytes, self._display_name)
        return self._header

    def __iter__(self) -> Iterator[NetworkEvidenceRecord]:
        return self.read_records()

    def __enter__(self) -> "PcapParser":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._owns_stream and self._active_stream is not None:
            self._active_stream.close()
            self._active_stream = None

    def read_raw_records(
        self,
        max_packets: Optional[int] = None,
    ) -> Iterator[Tuple[NetworkEvidenceRecord, bytes]]:
        """
        Stream validated NetworkEvidenceRecord instances paired with raw packet frame bytes.

        Args:
            max_packets: Optional integer limiting the maximum number of packets emitted.

        Yields:
            Tuple[NetworkEvidenceRecord, bytes]: The parsed record and its original captured packet bytes.
        """
        should_close = False
        if self._path is not None:
            if not self._path.exists():
                raise FileNotFoundError(f"PCAP evidence file not found: '{self._path}'")
            if self._path.is_dir():
                raise IsADirectoryError(f"Target path is a directory, not a PCAP file: '{self._path}'")
            stream: BinaryIO = open(self._path, "rb")
            should_close = True
            self._owns_stream = True
            self._active_stream = stream
        else:
            stream = self._source
            if hasattr(stream, "seek") and hasattr(stream, "tell") and stream.tell() != 0:
                stream.seek(0)

        try:
            # Read and validate global header
            hdr_bytes = stream.read(PCAP_GLOBAL_HEADER_SIZE)
            header = _parse_global_header(hdr_bytes, self._display_name)
            self._header = header

            endianness = ">" if header.byte_order == "big" else "<"
            is_nano = header.ts_resolution == "nanosecond"

            # Provenance setup: ensure deterministic ID never falls back to 'source:default'
            resolved_source_path = str(self._path) if self._path is not None else None
            derived_pcap_name = self._pcap_name_arg or (self._path.name if self._path is not None else "in_memory.pcap")

            frame_number = 1
            packets_emitted = 0

            while True:
                if max_packets is not None and packets_emitted >= max_packets:
                    break

                # 1. Read 16-byte packet record header
                rec_hdr_bytes = stream.read(PCAP_RECORD_HEADER_SIZE)
                if len(rec_hdr_bytes) == 0:
                    # Normal clean EOF
                    break
                if len(rec_hdr_bytes) < PCAP_RECORD_HEADER_SIZE:
                    raise PcapTruncatedError(
                        f"Truncated packet record header at frame {frame_number} in '{self._display_name}': "
                        f"expected {PCAP_RECORD_HEADER_SIZE} bytes, got {len(rec_hdr_bytes)} bytes"
                    )

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{endianness}IIII", rec_hdr_bytes
                )

                # 2. Validate packet lengths
                if incl_len > orig_len:
                    raise PcapCorruptError(
                        f"Invalid packet length at frame {frame_number} in '{self._display_name}': "
                        f"captured length ({incl_len}) exceeds original wire length ({orig_len})"
                    )

                if incl_len > self._max_packet_size:
                    raise PcapCorruptError(
                        f"Packet captured length ({incl_len}) at frame {frame_number} in '{self._display_name}' "
                        f"exceeds maximum allocation safety limit ({self._max_packet_size} bytes)"
                    )

                # 3. Read packet bytes
                packet_data = stream.read(incl_len)
                if len(packet_data) < incl_len:
                    raise PcapTruncatedError(
                        f"Truncated packet payload at frame {frame_number} in '{self._display_name}': "
                        f"expected {incl_len} bytes, got {len(packet_data)} bytes"
                    )

                # 4. Compute high-precision timestamps without float drift
                if is_nano:
                    raw_timestamp = f"{ts_sec}.{ts_usec:09d}"
                    sec_adj, nano_rem = divmod(ts_usec, 1_000_000_000)
                    usec = nano_rem // 1_000
                else:
                    raw_timestamp = f"{ts_sec}.{ts_usec:06d}"
                    sec_adj, usec_rem = divmod(ts_usec, 1_000_000)
                    usec = usec_rem

                try:
                    norm_dt = datetime.fromtimestamp(ts_sec + sec_adj, tz=timezone.utc).replace(
                        microsecond=usec
                    )
                except (ValueError, OverflowError):
                    norm_dt = None

                # 5. Dissect packet protocols safely
                (
                    link_layer,
                    src_mac,
                    dst_mac,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    network_protocol,
                    transport_protocol,
                    pkt_metadata,
                ) = _dissect_packet(packet_data, header.network, endianness)

                # 6. Construct immutable NetworkEvidenceRecord via V5.1 factory
                record = create_network_evidence_record(
                    frame_number=frame_number,
                    timestamp=norm_dt,
                    raw_timestamp=raw_timestamp,
                    captured_length=incl_len,
                    original_length=orig_len,
                    link_layer=link_layer,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    network_protocol=network_protocol,
                    transport_protocol=transport_protocol,
                    source_path=resolved_source_path,
                    source_artifact_id=self._source_artifact_id,
                    pcap_name=derived_pcap_name,
                    packet_metadata=pkt_metadata,
                )

                yield record, packet_data
                frame_number += 1
                packets_emitted += 1

        finally:
            if should_close:
                stream.close()
                self._owns_stream = False
                self._active_stream = None

    def read_records(
        self,
        max_packets: Optional[int] = None,
    ) -> Iterator[NetworkEvidenceRecord]:
        """
        Stream validated NetworkEvidenceRecord instances one by one from the capture.

        Args:
            max_packets: Optional integer limiting the maximum number of packets emitted.

        Yields:
            NetworkEvidenceRecord: Strongly typed, deeply immutable record for each frame.

        Raises:
            PcapCorruptError: If packet headers or lengths are corrupt.
            PcapTruncatedError: If file cuts off mid-packet.
            FileNotFoundError: If evidence file is missing.
        """
        for record, _ in self.read_raw_records(max_packets=max_packets):
            yield record

    def parse_all(
        self,
        max_packets: Optional[int] = None,
    ) -> List[NetworkEvidenceRecord]:
        """Convenience method to collect all streamed records into an in-memory list."""
        return list(self.read_records(max_packets=max_packets))


def read_pcap(
    source: Union[str, Path, BinaryIO],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
) -> Iterator[NetworkEvidenceRecord]:
    """
    Stream validated NetworkEvidenceRecord instances from a classic PCAP capture.

    Args:
        source: Filesystem path or binary stream of the PCAP capture.
        source_artifact_id: Optional traceable parent artifact ID (e.g. 'ART-...').
        pcap_name: Optional explicit name of the capture file.
        max_packets: Optional packet count limit.
        max_packet_size: Configurable maximum packet buffer allocation threshold.

    Yields:
        NetworkEvidenceRecord: Strongly typed, deeply immutable forensic packet record.
    """
    parser = PcapParser(
        source,
        source_artifact_id=source_artifact_id,
        pcap_name=pcap_name,
        max_packet_size=max_packet_size,
    )
    return parser.read_records(max_packets=max_packets)


def read_pcap_raw(
    source: Union[str, Path, BinaryIO],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
) -> Iterator[Tuple[NetworkEvidenceRecord, bytes]]:
    """
    Stream validated NetworkEvidenceRecord instances paired with raw packet frame bytes.

    Args:
        source: Filesystem path or binary stream of the PCAP capture.
        source_artifact_id: Optional traceable parent artifact ID (e.g. 'ART-...').
        pcap_name: Optional explicit name of the capture file.
        max_packets: Optional packet count limit.
        max_packet_size: Configurable maximum packet buffer allocation threshold.

    Yields:
        Tuple[NetworkEvidenceRecord, bytes]: Strongly typed record and raw packet bytes.
    """
    parser = PcapParser(
        source,
        source_artifact_id=source_artifact_id,
        pcap_name=pcap_name,
        max_packet_size=max_packet_size,
    )
    return parser.read_raw_records(max_packets=max_packets)


def parse_pcap(
    source: Union[str, Path, BinaryIO],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
) -> List[NetworkEvidenceRecord]:
    """
    Parse a classic PCAP capture into a complete list of NetworkEvidenceRecord instances.

    Args:
        source: Filesystem path or binary stream of the PCAP capture.
        source_artifact_id: Optional traceable parent artifact ID (e.g. 'ART-...').
        pcap_name: Optional explicit name of the capture file.
        max_packets: Optional packet count limit.
        max_packet_size: Configurable maximum packet buffer allocation threshold.

    Returns:
        List[NetworkEvidenceRecord]: All extracted forensic packet records.
    """
    return list(
        read_pcap(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
            max_packet_size=max_packet_size,
        )
    )
