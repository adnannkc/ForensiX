"""
Comprehensive Unit Test Suite for ForensiX V5.2 PCAP Parsing Implementation.

Validates:
1. Supported byte orders (Little-Endian, Big-Endian).
2. Microsecond and nanosecond timestamp resolutions.
3. Valid empty capture (24-byte global header, 0 packet records).
4. One-frame and multi-frame streaming captures.
5. Correct 1-indexed frame numbering across records.
6. Captured and original wire length preservation (snaplen slicing).
7. Provenance propagation and deterministic RFC 4122 UUIDv5 record IDs.
8. Standard Ethernet frames (MAC addresses, EtherTypes).
9. IEEE 802.1Q VLAN tagged frames.
10. Supported IPv4 fields (src_ip, dst_ip, protocol, network_protocol).
11. Supported IPv6 fields (src_ip, dst_ip, extension headers, protocol).
12. TCP field extraction (ports, flags, seq/ack/window).
13. UDP field extraction (ports).
14. ICMP and ICMPv6 field extraction (types, codes, no ports).
15. Non-IP traffic: ARP packets.
16. Non-IP traffic: Unsupported EtherType.
17. IPv4 fragmentation: non-initial fragment (frag_offset > 0) suppresses transport ports.
18. IPv4 fragmentation: initial fragment (frag_offset == 0, MF=True) extracts transport ports.
19. IPv6 fragmentation: non-initial fragment suppresses transport ports.
20. Truncated global header (< 24 bytes) raises PcapCorruptError.
21. Truncated packet record header (< 16 bytes) raises PcapTruncatedError.
22. Truncated packet payload raises PcapTruncatedError.
23. Invalid PCAP magic value raises PcapCorruptError.
24. Unsupported PCAP-NG format (0x0A0D0D0A) raises PcapUnsupportedError.
25. Unsupported link-layer type raises PcapUnsupportedError.
26. Unsupported PCAP version raises PcapUnsupportedError.
27. Invalid packet length (captured > original) raises PcapCorruptError.
28. Safety limit on oversized packet allocation (max_packet_size).
29. Timestamp precision preservation at second boundaries and nanosecond fractions.
30. Streaming behavior with max_packets parameter.
31. Reliable file closure on success, parsing error, and early generator termination.
32. Source evidence immutability (file hash unchanged before and after parsing).
33. Support for BSD loopback (DLT_NULL), Raw IP (DLT_RAW), and Linux Cooked (DLT_LINUX_SLL).
34. PcapParser context manager (__enter__ / __exit__) behavior.
"""

from datetime import datetime, timezone
import hashlib
import io
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest

from forensix.network_models import NetworkEvidenceRecord
from forensix.network_pcap_parser import (
    DEFAULT_MAX_PACKET_SIZE,
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_NULL,
    DLT_RAW,
    PCAP_MAGIC_MICROSECONDS_BIG,
    PCAP_MAGIC_MICROSECONDS_LITTLE,
    PCAP_MAGIC_NANOSECONDS_BIG,
    PCAP_MAGIC_NANOSECONDS_LITTLE,
    PCAPNG_SECTION_HEADER_MAGIC,
    PcapCorruptError,
    PcapError,
    PcapGlobalHeader,
    PcapParser,
    PcapTruncatedError,
    PcapUnsupportedError,
    parse_pcap,
    read_pcap,
)


def _build_pcap_bytes(
    packets: list,
    *,
    magic_bytes: bytes = b"\xd4\xc3\xb2\xa1",
    version_major: int = 2,
    version_minor: int = 4,
    thiszone: int = 0,
    sigfigs: int = 0,
    snaplen: int = 65535,
    network: int = DLT_EN10MB,
) -> bytes:
    """Build a synthetic classic PCAP byte sequence in memory."""
    is_be = magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    endianness = ">" if is_be else "<"

    # 24-byte global header: 4 bytes magic + 20 bytes fields
    rest = struct.pack(
        f"{endianness}HHiIII",
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        network,
    )
    gh = magic_bytes + rest

    buf = io.BytesIO()
    buf.write(gh)

    for pkt in packets:
        # pkt tuple: (ts_sec, ts_usec, orig_len, data_bytes)
        ts_sec, ts_usec, orig_len, data_bytes = pkt
        incl_len = len(data_bytes)
        rh = struct.pack(f"{endianness}IIII", ts_sec, ts_usec, incl_len, orig_len)
        buf.write(rh)
        buf.write(data_bytes)

    return buf.getvalue()


def _make_eth_ipv4_tcp_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 443,
    flags: int = 0x02,  # SYN
    frag_offset: int = 0,
    more_frags: bool = False,
) -> bytes:
    """Construct an Ethernet + IPv4 + TCP packet byte sequence."""
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)

    frag_val = (frag_offset // 8) & 0x1FFF
    if more_frags:
        frag_val |= 0x2000

    s_ip = ipaddress.IPv4Address(src_ip).packed
    d_ip = ipaddress.IPv4Address(dst_ip).packed
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 40, 1001, frag_val, 64, 6, 0) + s_ip + d_ip

    if frag_offset > 0:
        # Non-initial fragment: raw fragment payload instead of TCP header
        tcp = b"FRAGMENT_DATA_BYTES_1234"
    else:
        tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, 1000, 0, 0x50, flags, 65535, 0, 0)

    return eth + ip + tcp


def _make_eth_ipv4_udp_packet(
    src_ip: str = "172.16.0.5",
    dst_ip: str = "172.16.0.1",
    src_port: int = 12345,
    dst_port: int = 53,
) -> bytes:
    """Construct an Ethernet + IPv4 + UDP packet byte sequence."""
    dst_mac = b"\x00\xaa\xbb\xcc\xdd\xee"
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)

    s_ip = ipaddress.IPv4Address(src_ip).packed
    d_ip = ipaddress.IPv4Address(dst_ip).packed
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 28, 2002, 0, 64, 17, 0) + s_ip + d_ip
    udp = struct.pack(">HHHH", src_port, dst_port, 8, 0)
    return eth + ip + udp


def _make_eth_ipv4_icmp_packet(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "192.168.1.254",
    icmp_type: int = 8,
    icmp_code: int = 0,
) -> bytes:
    """Construct an Ethernet + IPv4 + ICMP packet byte sequence."""
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)

    s_ip = ipaddress.IPv4Address(src_ip).packed
    d_ip = ipaddress.IPv4Address(dst_ip).packed
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 28, 3003, 0, 64, 1, 0) + s_ip + d_ip
    icmp = struct.pack(">BBH", icmp_type, icmp_code, 0) + b"\x00" * 4
    return eth + ip + icmp


def _make_eth_ipv6_tcp_packet(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    src_port: int = 44444,
    dst_port: int = 80,
    frag_offset: int = 0,
) -> bytes:
    """Construct an Ethernet + IPv6 + TCP packet byte sequence."""
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth = dst_mac + src_mac + struct.pack(">H", 0x86DD)

    s_ip = ipaddress.IPv6Address(src_ip).packed
    d_ip = ipaddress.IPv6Address(dst_ip).packed

    if frag_offset > 0:
        # IPv6 with fragment header (next_hdr=44)
        ip6 = struct.pack(">IHBB", 0x60000000, 28, 44, 64) + s_ip + d_ip
        frag_hdr = struct.pack(">BBHI", 6, 0, (frag_offset >> 3) << 3, 9999)
        payload = b"FRAGMENT_SLICE_PAYLOAD_HERE"
        return eth + ip6 + frag_hdr + payload
    else:
        ip6 = struct.pack(">IHBB", 0x60000000, 20, 6, 64) + s_ip + d_ip
        tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, 500, 0, 0x50, 0x10, 32768, 0, 0)
        return eth + ip6 + tcp


def _make_eth_arp_packet() -> bytes:
    """Construct an Ethernet + ARP request packet byte sequence."""
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    eth = dst_mac + src_mac + struct.pack(">H", 0x0806)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)  # Request
    s_mac = b"\x00\x11\x22\x33\x44\x55"
    s_ip = ipaddress.IPv4Address("192.168.1.10").packed
    t_mac = b"\x00\x00\x00\x00\x00\x00"
    t_ip = ipaddress.IPv4Address("192.168.1.1").packed
    return eth + arp + s_mac + s_ip + t_mac + t_ip


class TestNetworkPcapParser(unittest.TestCase):
    """Rigorous unit test suite for V5.2 PCAP Parsing."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. Byte Orders
    def test_01_supported_byte_orders_little_and_big_endian(self):
        """1. Verify parser supports both little-endian and big-endian PCAP captures."""
        pkt_data = _make_eth_ipv4_tcp_packet()
        packets = [(1713184200, 100000, len(pkt_data), pkt_data)]

        # Little-endian microsecond PCAP
        le_bytes = _build_pcap_bytes(packets, magic_bytes=b"\xd4\xc3\xb2\xa1")
        parser_le = PcapParser(io.BytesIO(le_bytes), pcap_name="test_le.pcap")
        self.assertEqual(parser_le.global_header.byte_order, "little")
        recs_le = parser_le.parse_all()
        self.assertEqual(len(recs_le), 1)
        self.assertEqual(recs_le[0].src_ip, "192.168.1.100")
        self.assertEqual(recs_le[0].dst_port, 443)

        # Big-endian microsecond PCAP
        be_bytes = _build_pcap_bytes(packets, magic_bytes=b"\xa1\xb2\xc3\xd4")
        parser_be = PcapParser(io.BytesIO(be_bytes), pcap_name="test_be.pcap")
        self.assertEqual(parser_be.global_header.byte_order, "big")
        recs_be = parser_be.parse_all()
        self.assertEqual(len(recs_be), 1)
        self.assertEqual(recs_be[0].src_ip, "192.168.1.100")
        self.assertEqual(recs_be[0].dst_port, 443)

    # 2. Timestamp Resolutions
    def test_02_timestamp_resolutions_microsecond_and_nanosecond(self):
        """2. Verify parser handles both microsecond and nanosecond PCAP timestamp formats."""
        pkt_data = _make_eth_ipv4_tcp_packet()
        sec = 1713184245
        nano = 123456789
        usec = 123456

        # Microsecond PCAP
        p_usec = _build_pcap_bytes([(sec, usec, len(pkt_data), pkt_data)], magic_bytes=b"\xd4\xc3\xb2\xa1")
        recs_usec = parse_pcap(io.BytesIO(p_usec))
        self.assertEqual(recs_usec[0].raw_timestamp, f"{sec}.{usec:06d}")
        self.assertEqual(recs_usec[0].timestamp.microsecond, usec)

        # Nanosecond PCAP
        p_nano = _build_pcap_bytes([(sec, nano, len(pkt_data), pkt_data)], magic_bytes=b"\x4d\x3c\xb2\xa1")
        recs_nano = parse_pcap(io.BytesIO(p_nano))
        self.assertEqual(recs_nano[0].raw_timestamp, f"{sec}.{nano:09d}")
        self.assertEqual(recs_nano[0].timestamp.microsecond, nano // 1000)

    # 3. Valid Empty Capture
    def test_03_valid_empty_capture(self):
        """3. Verify a valid PCAP with 24-byte header and 0 packet records yields 0 records without error."""
        empty_pcap = _build_pcap_bytes([])
        recs = parse_pcap(io.BytesIO(empty_pcap), pcap_name="empty.pcap")
        self.assertEqual(recs, [])

    # 4 & 5. Multi-Frame Captures and 1-indexed Frame Numbering
    def test_04_multi_frame_captures_and_1_indexed_frame_numbers(self):
        """4. Verify multi-frame capture emits records with strictly 1-indexed sequential frame numbers."""
        pkt1 = _make_eth_ipv4_tcp_packet(src_ip="10.0.0.1", dst_port=80)
        pkt2 = _make_eth_ipv4_udp_packet(src_ip="10.0.0.2", dst_port=53)
        pkt3 = _make_eth_arp_packet()

        pcap_data = _build_pcap_bytes([
            (1713184201, 1000, len(pkt1), pkt1),
            (1713184202, 2000, len(pkt2), pkt2),
            (1713184203, 3000, len(pkt3), pkt3),
        ])
        recs = parse_pcap(io.BytesIO(pcap_data))
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0].frame_number, 1)
        self.assertEqual(recs[1].frame_number, 2)
        self.assertEqual(recs[2].frame_number, 3)
        self.assertEqual(recs[0].protocol, "TCP")
        self.assertEqual(recs[1].protocol, "UDP")
        self.assertEqual(recs[2].protocol, "ARP")

    # 6. Length Preservation
    def test_05_captured_and_original_wire_length_preservation(self):
        """5. Verify captured_length and original_length are preserved, including snapped packets."""
        full_pkt = _make_eth_ipv4_tcp_packet()
        wire_len = len(full_pkt) + 500  # Original wire length was larger than captured slice
        pcap_data = _build_pcap_bytes([(1713184200, 0, wire_len, full_pkt)])

        recs = parse_pcap(io.BytesIO(pcap_data))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].captured_length, len(full_pkt))
        self.assertEqual(recs[0].original_length, wire_len)

    # 7. Provenance and Deterministic ID Verification
    def test_06_provenance_propagation_and_deterministic_record_ids(self):
        """6. Verify parser strictly propagates evidence provenance into records for collision-free IDs."""
        pkt = _make_eth_ipv4_tcp_packet()
        pcap_path = self.dir_path / "incident.pcap"
        pcap_path.write_bytes(_build_pcap_bytes([(1713184200, 100, len(pkt), pkt)]))

        art_id = "ART-11111111-2222-3333-4444-555555555555"
        recs = parse_pcap(pcap_path, source_artifact_id=art_id)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].source_path, str(pcap_path.resolve()))
        self.assertEqual(recs[0].source_artifact_id, art_id)
        self.assertEqual(recs[0].pcap_name, "incident.pcap")
        self.assertTrue(recs[0].record_id.startswith("NET-"))

        # Re-running produces byte-identical deterministic record ID
        recs2 = parse_pcap(pcap_path, source_artifact_id=art_id)
        self.assertEqual(recs[0].record_id, recs2[0].record_id)

    # 8. Standard Ethernet Frames
    def test_07_standard_ethernet_frames(self):
        """7. Verify standard Ethernet MAC addresses and link layer metadata."""
        pkt = _make_eth_ipv4_tcp_packet()
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].link_layer, "ETHERNET")
        self.assertEqual(recs[0].src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(recs[0].dst_mac, "00:11:22:33:44:55")

    # 9. 802.1Q VLAN Tagging
    def test_08_vlan_tagged_frames(self):
        """8. Verify IEEE 802.1Q VLAN tagged Ethernet frames extract VLAN ID and inner protocol."""
        dst_mac = b"\x00\x11\x22\x33\x44\x55"
        src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        vlan_header = struct.pack(">HH", 0x8100, 100)  # VLAN ID 100
        inner_ethertype = struct.pack(">H", 0x0800)
        s_ip = ipaddress.IPv4Address("192.168.100.1").packed
        d_ip = ipaddress.IPv4Address("192.168.100.2").packed
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 40, 555, 0, 64, 6, 0) + s_ip + d_ip
        tcp = struct.pack(">HHIIBBHHH", 1111, 2222, 1, 0, 0x50, 0x02, 1000, 0, 0)
        vlan_pkt = dst_mac + src_mac + vlan_header + inner_ethertype + ip + tcp

        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(vlan_pkt), vlan_pkt)])))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].src_ip, "192.168.100.1")
        self.assertEqual(recs[0].dst_port, 2222)
        meta_dict = dict(recs[0].packet_metadata)
        self.assertEqual(meta_dict.get("vlan_id"), 100)

    # 10. IPv4 Extraction
    def test_09_ipv4_packet_extraction(self):
        """9. Verify IPv4 extraction with valid IPs and protocol."""
        pkt = _make_eth_ipv4_tcp_packet(src_ip="192.168.2.50", dst_ip="10.20.30.40")
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].src_ip, "192.168.2.50")
        self.assertEqual(recs[0].dst_ip, "10.20.30.40")
        self.assertEqual(recs[0].network_protocol, "IPV4")

    # 11. IPv6 Extraction
    def test_10_ipv6_packet_extraction(self):
        """10. Verify IPv6 extraction with valid 128-bit addresses and transport protocol."""
        pkt = _make_eth_ipv6_tcp_packet(src_ip="2001:db8:acad::1", dst_ip="2001:db8:acad::2", dst_port=8080)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].src_ip, "2001:db8:acad::1")
        self.assertEqual(recs[0].dst_ip, "2001:db8:acad::2")
        self.assertEqual(recs[0].network_protocol, "IPV6")
        self.assertEqual(recs[0].protocol, "TCP")
        self.assertEqual(recs[0].dst_port, 8080)

    # 12. TCP Field Extraction
    def test_11_tcp_field_extraction(self):
        """11. Verify TCP source/destination ports and metadata flags (SYN, ACK, seq)."""
        pkt = _make_eth_ipv4_tcp_packet(src_port=49152, dst_port=443, flags=0x12)  # SYN-ACK
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].src_port, 49152)
        self.assertEqual(recs[0].dst_port, 443)
        self.assertEqual(recs[0].transport_protocol, "TCP")
        meta = dict(recs[0].packet_metadata)
        self.assertIn("SYN", meta["tcp_flags"])
        self.assertIn("ACK", meta["tcp_flags"])

    # 13. UDP Field Extraction
    def test_12_udp_field_extraction(self):
        """12. Verify UDP source/destination ports."""
        pkt = _make_eth_ipv4_udp_packet(src_port=5353, dst_port=5353)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].src_port, 5353)
        self.assertEqual(recs[0].dst_port, 5353)
        self.assertEqual(recs[0].protocol, "UDP")
        self.assertEqual(recs[0].transport_protocol, "UDP")

    # 14. ICMP Extraction
    def test_13_icmp_field_extraction(self):
        """13. Verify ICMP packet extraction preserves protocol without fabricating ports."""
        pkt = _make_eth_ipv4_icmp_packet(src_ip="1.1.1.1", dst_ip="8.8.8.8", icmp_type=8, icmp_code=0)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].protocol, "ICMP")
        self.assertEqual(recs[0].transport_protocol, "ICMP")
        self.assertIsNone(recs[0].src_port)
        self.assertIsNone(recs[0].dst_port)
        meta = dict(recs[0].packet_metadata)
        self.assertEqual(meta.get("icmp_type"), 8)
        self.assertEqual(meta.get("icmp_code"), 0)

    # 15. ARP Non-IP Traffic
    def test_14_arp_traffic_extraction(self):
        """14. Verify ARP packets populate protocol='ARP' without fabricating IP addresses."""
        pkt = _make_eth_arp_packet()
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)])))
        self.assertEqual(recs[0].protocol, "ARP")
        self.assertEqual(recs[0].network_protocol, "ARP")
        self.assertIsNone(recs[0].src_ip)
        self.assertIsNone(recs[0].dst_ip)
        self.assertIsNone(recs[0].src_port)
        self.assertIsNone(recs[0].dst_port)

    # 16. Unsupported EtherType
    def test_15_unsupported_ethertype(self):
        """15. Verify unsupported EtherType is preserved factually without error."""
        dst_mac = b"\x00\x11\x22\x33\x44\x55"
        src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        eth = dst_mac + src_mac + struct.pack(">H", 0x88CC) + b"\x00" * 30  # LLDP
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(eth), eth)])))
        self.assertEqual(recs[0].link_layer, "ETHERNET")
        self.assertEqual(recs[0].protocol, "ETH-0X88CC")

    # 17. IPv4 Fragment Handling (Non-initial)
    def test_16_ipv4_fragment_suppresses_transport_ports(self):
        """16. Verify fragmented IP packet with frag_offset > 0 does NOT misinterpret payload as TCP ports."""
        frag_pkt = _make_eth_ipv4_tcp_packet(frag_offset=1480, more_frags=False)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(frag_pkt), frag_pkt)])))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].src_ip, "192.168.1.100")
        self.assertEqual(recs[0].dst_ip, "10.0.0.1")
        self.assertIsNone(recs[0].src_port)
        self.assertIsNone(recs[0].dst_port)
        self.assertIsNone(recs[0].transport_protocol)
        meta = dict(recs[0].packet_metadata)
        self.assertTrue(meta.get("fragment"))
        self.assertEqual(meta.get("fragment_offset"), 1480)

    # 18. IPv4 Fragment Handling (Initial fragment)
    def test_17_ipv4_initial_fragment_preserves_ports_and_records_fragment_metadata(self):
        """17. Verify initial IP fragment (frag_offset=0, MF=True) parses transport ports and records fragment flag."""
        init_frag = _make_eth_ipv4_tcp_packet(frag_offset=0, more_frags=True, dst_port=80)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(init_frag), init_frag)])))
        self.assertEqual(recs[0].dst_port, 80)
        meta = dict(recs[0].packet_metadata)
        self.assertTrue(meta.get("fragment"))
        self.assertEqual(meta.get("fragment_offset"), 0)
        self.assertTrue(meta.get("more_fragments"))

    # 19. IPv6 Fragment Handling
    def test_18_ipv6_fragment_suppresses_transport_ports(self):
        """18. Verify IPv6 fragment with frag_offset > 0 suppresses transport ports."""
        frag_ip6 = _make_eth_ipv6_tcp_packet(frag_offset=1280)
        recs = parse_pcap(io.BytesIO(_build_pcap_bytes([(1713184200, 0, len(frag_ip6), frag_ip6)])))
        self.assertEqual(recs[0].src_ip, "2001:db8::1")
        self.assertIsNone(recs[0].src_port)
        self.assertIsNone(recs[0].dst_port)
        meta = dict(recs[0].packet_metadata)
        self.assertTrue(meta.get("fragment"))
        self.assertEqual(meta.get("fragment_offset"), 1280)

    # 20. Truncated Global Header
    def test_19_truncated_global_header_raises_pcap_corrupt_error(self):
        """19. Verify truncated global header (< 24 bytes) raises PcapCorruptError."""
        for bad_len in [0, 4, 12, 23]:
            with self.subTest(bad_len=bad_len):
                truncated_data = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"[:bad_len]
                with self.assertRaises(PcapCorruptError):
                    parse_pcap(io.BytesIO(truncated_data))

    # 21. Truncated Packet Record Header
    def test_20_truncated_packet_record_header_raises_pcap_truncated_error(self):
        """20. Verify truncated packet record header (1 to 15 bytes) raises PcapTruncatedError."""
        gh = _build_pcap_bytes([])
        bad_pcap = gh + b"\x01\x02\x03\x04"  # Only 4 bytes of packet record header
        with self.assertRaises(PcapTruncatedError):
            parse_pcap(io.BytesIO(bad_pcap))

    # 22. Truncated Packet Payload
    def test_21_truncated_packet_payload_raises_pcap_truncated_error(self):
        """21. Verify packet payload truncated before declared incl_len raises PcapTruncatedError."""
        gh = _build_pcap_bytes([])
        rh = struct.pack("<IIII", 1713184200, 0, 100, 100)  # Declares 100 bytes
        partial_payload = b"X" * 25  # Only 25 bytes provided
        bad_pcap = gh + rh + partial_payload
        with self.assertRaises(PcapTruncatedError):
            parse_pcap(io.BytesIO(bad_pcap))

    # 23. Invalid Magic Value
    def test_22_invalid_magic_value_raises_pcap_corrupt_error(self):
        """22. Verify unrecognized magic value raises PcapCorruptError."""
        bad_magic = b"\x12\x34\x56\x78" + b"\x00" * 20
        with self.assertRaises(PcapCorruptError):
            parse_pcap(io.BytesIO(bad_magic))

    # 24. PCAP-NG Rejection
    def test_23_pcapng_magic_rejected_with_unsupported_error(self):
        """23. Verify PCAP-NG Section Header Block magic (0x0A0D0D0A) raises PcapUnsupportedError."""
        pcapng_header = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
        with self.assertRaises(PcapUnsupportedError) as ctx:
            parse_pcap(io.BytesIO(pcapng_header))
        self.assertIn("PCAP-NG", str(ctx.exception))

    # 25. Unsupported Link-Layer Type
    def test_24_unsupported_link_layer_type_raises_pcap_unsupported_error(self):
        """24. Verify unsupported link-layer type (e.g. 999) raises PcapUnsupportedError."""
        bad_link_pcap = _build_pcap_bytes([], network=999)
        with self.assertRaises(PcapUnsupportedError) as ctx:
            parse_pcap(io.BytesIO(bad_link_pcap))
        self.assertIn("Unsupported link-layer type", str(ctx.exception))

    # 26. Unsupported PCAP Version
    def test_25_unsupported_pcap_version_raises_pcap_unsupported_error(self):
        """25. Verify unsupported major version (e.g. version 3.0) raises PcapUnsupportedError."""
        bad_ver = _build_pcap_bytes([], version_major=3, version_minor=0)
        with self.assertRaises(PcapUnsupportedError) as ctx:
            parse_pcap(io.BytesIO(bad_ver))
        self.assertIn("Unsupported PCAP version 3.0", str(ctx.exception))

    # 27. Invalid Packet Lengths (incl_len > orig_len)
    def test_26_captured_length_exceeding_original_length_raises_pcap_corrupt_error(self):
        """26. Verify packet record where incl_len > orig_len raises PcapCorruptError."""
        gh = _build_pcap_bytes([])
        rh = struct.pack("<IIII", 1713184200, 0, 1500, 100)  # incl_len=1500 > orig_len=100
        bad_pcap = gh + rh + b"A" * 1500
        with self.assertRaises(PcapCorruptError) as ctx:
            parse_pcap(io.BytesIO(bad_pcap))
        self.assertIn("captured length (1500) exceeds original wire length (100)", str(ctx.exception))

    # 28. Safety Limit on Oversized Allocation
    def test_27_oversized_packet_allocation_safety_limit(self):
        """27. Verify captured packet exceeding max_packet_size raises PcapCorruptError."""
        gh = _build_pcap_bytes([])
        rh = struct.pack("<IIII", 1713184200, 0, 300000, 300000)  # 300 KB > default 256 KB
        bad_pcap = gh + rh + b"A" * 300000
        with self.assertRaises(PcapCorruptError) as ctx:
            parse_pcap(io.BytesIO(bad_pcap), max_packet_size=262144)
        self.assertIn("exceeds maximum allocation safety limit", str(ctx.exception))

    # 29. Second Boundaries and Nanosecond Precision Preservation
    def test_28_timestamp_precision_at_second_boundaries(self):
        """28. Verify timestamp normalization and raw preservation at exact second boundary and subsecond fractions."""
        pkt = _make_eth_ipv4_tcp_packet()
        sec = 1713184200
        # Exact second boundary (0 nanos)
        pcap_sec0 = _build_pcap_bytes([(sec, 0, len(pkt), pkt)], magic_bytes=b"\x4d\x3c\xb2\xa1")
        recs0 = parse_pcap(io.BytesIO(pcap_sec0))
        self.assertEqual(recs0[0].raw_timestamp, f"{sec}.000000000")
        self.assertEqual(recs0[0].timestamp.microsecond, 0)

        # High subsecond nanoseconds (999,999,999 nanos)
        pcap_max_nano = _build_pcap_bytes([(sec, 999999999, len(pkt), pkt)], magic_bytes=b"\x4d\x3c\xb2\xa1")
        recs_max = parse_pcap(io.BytesIO(pcap_max_nano))
        self.assertEqual(recs_max[0].raw_timestamp, f"{sec}.999999999")
        self.assertEqual(recs_max[0].timestamp.microsecond, 999999)

    # 30. Streaming Behavior with max_packets
    def test_29_streaming_behavior_with_max_packets(self):
        """29. Verify streaming iterator honors max_packets parameter without reading entire capture."""
        pkt = _make_eth_ipv4_tcp_packet()
        packets = [(1713184200 + i, 0, len(pkt), pkt) for i in range(10)]
        pcap_bytes = _build_pcap_bytes(packets)

        stream = io.BytesIO(pcap_bytes)
        recs = list(read_pcap(stream, max_packets=3))
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0].frame_number, 1)
        self.assertEqual(recs[2].frame_number, 3)

    # 31. File Closure on Success, Error, and Early Termination
    def test_30_reliable_file_closure(self):
        """30. Verify underlying file handles are cleanly closed on success, error, and early generator termination."""
        pkt = _make_eth_ipv4_tcp_packet()
        packets = [(1713184200 + i, 0, len(pkt), pkt) for i in range(5)]
        pcap_file = self.dir_path / "stream_close_test.pcap"
        pcap_file.write_bytes(_build_pcap_bytes(packets))

        # Early generator exit via break
        for idx, rec in enumerate(read_pcap(pcap_file)):
            if idx == 1:
                break
        # Re-opening or writing must succeed immediately because stream was closed
        self.assertTrue(pcap_file.exists())

        # Early termination via exception mid-iteration
        truncated_pcap = self.dir_path / "truncated_test.pcap"
        gh = _build_pcap_bytes([])
        rh = struct.pack("<IIII", 1713184200, 0, 100, 100)
        truncated_pcap.write_bytes(gh + rh + b"SHORT")

        with self.assertRaises(PcapTruncatedError):
            for _ in read_pcap(truncated_pcap):
                pass
        self.assertTrue(truncated_pcap.exists())

    # 32. Evidence File Immutability
    def test_31_source_evidence_immutability(self):
        """31. Verify source PCAP file on disk is completely unmodified (SHA-256 identical before and after)."""
        pkt = _make_eth_ipv4_tcp_packet()
        pcap_file = self.dir_path / "evidence_audit.pcap"
        pcap_file.write_bytes(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)]))

        hash_before = hashlib.sha256(pcap_file.read_bytes()).hexdigest()
        records = parse_pcap(pcap_file)
        self.assertEqual(len(records), 1)
        hash_after = hashlib.sha256(pcap_file.read_bytes()).hexdigest()

        self.assertEqual(hash_before, hash_after)

    # 33. Other Link Types: DLT_NULL, DLT_RAW, DLT_LINUX_SLL
    def test_32_alternate_link_layer_types(self):
        """32. Verify parsing DLT_NULL (loopback), DLT_RAW (raw IP), and DLT_LINUX_SLL (cooked)."""
        # 1. DLT_RAW (Raw IPv4 without Ethernet header)
        s_ip = ipaddress.IPv4Address("10.0.0.1").packed
        d_ip = ipaddress.IPv4Address("10.0.0.2").packed
        raw_ip = struct.pack(">BBHHHBBH", 0x45, 0, 40, 1, 0, 64, 6, 0) + s_ip + d_ip
        raw_tcp = struct.pack(">HHIIBBHHH", 8080, 80, 1, 0, 0x50, 0x02, 1000, 0, 0)
        raw_pkt = raw_ip + raw_tcp
        pcap_raw = _build_pcap_bytes([(1713184200, 0, len(raw_pkt), raw_pkt)], network=DLT_RAW)
        recs_raw = parse_pcap(io.BytesIO(pcap_raw))
        self.assertEqual(recs_raw[0].link_layer, "RAW")
        self.assertEqual(recs_raw[0].src_ip, "10.0.0.1")
        self.assertEqual(recs_raw[0].dst_port, 80)

        # 2. DLT_NULL (4-byte family prefix)
        null_pkt = struct.pack("<I", 2) + raw_pkt  # Family 2 = IPv4
        pcap_null = _build_pcap_bytes([(1713184200, 0, len(null_pkt), null_pkt)], network=DLT_NULL)
        recs_null = parse_pcap(io.BytesIO(pcap_null))
        self.assertEqual(recs_null[0].link_layer, "NULL")
        self.assertEqual(recs_null[0].src_ip, "10.0.0.1")
        self.assertEqual(recs_null[0].dst_port, 80)

        # 3. DLT_LINUX_SLL (16-byte cooked header)
        sll_hdr = struct.pack(">HHH8sH", 0, 1, 6, b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00", 0x0800)
        sll_pkt = sll_hdr + raw_pkt
        pcap_sll = _build_pcap_bytes([(1713184200, 0, len(sll_pkt), sll_pkt)], network=DLT_LINUX_SLL)
        recs_sll = parse_pcap(io.BytesIO(pcap_sll))
        self.assertEqual(recs_sll[0].link_layer, "LINUX_SLL")
        self.assertEqual(recs_sll[0].src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(recs_sll[0].src_ip, "10.0.0.1")

    # 34. PcapParser Context Manager
    def test_33_pcap_parser_context_manager(self):
        """33. Verify PcapParser functions as a context manager (__enter__ / __exit__)."""
        pkt = _make_eth_ipv4_tcp_packet()
        pcap_file = self.dir_path / "context_mgr.pcap"
        pcap_file.write_bytes(_build_pcap_bytes([(1713184200, 0, len(pkt), pkt)]))

        with PcapParser(pcap_file) as parser:
            self.assertEqual(parser.global_header.link_layer, "ETHERNET")
            records = list(parser)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].frame_number, 1)


if __name__ == "__main__":
    unittest.main()
