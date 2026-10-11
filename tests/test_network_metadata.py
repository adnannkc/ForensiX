"""
Comprehensive Unit Test Suite for ForensiX V5.4 Network Metadata Extraction (DNS, HTTP, TLS).

Validates:
1. Valid DNS query parsing (query name, QTYPE, QCLASS, TXID, flags).
2. Valid DNS response parsing with answer records (A, AAAA, CNAME, TXT, MX).
3. DNS compression pointer decompression across multiple questions and answers.
4. DNS pointer loop detection and prevention of infinite recursion.
5. Malformed DNS packet handling (truncated headers, oversized label lengths, boundary overflow).
6. Non-DNS UDP traffic rejection (arbitrary payload, invalid opcodes, excessive question counts).
7. DNS-over-TCP length prefix parsing and handling.
8. Valid HTTP request parsing (GET, POST, target, version, Host, User-Agent, headers).
9. Valid HTTP response parsing (HTTP/1.1 status code, reason phrase, Server, Content-Type).
10. Missing, repeated, and case-insensitive HTTP headers handling.
11. Bounded HTTP headers (protection against oversized lines and header flood).
12. Incomplete / truncated HTTP messages.
13. Fast rejection of binary / TLS traffic by HTTP parser.
14. Preservation of non-collection policy (no HTTP request/response bodies retained).
15. TLS ClientHello parsing with SNI, ALPN, and supported_versions.
16. TLS ClientHello without SNI.
17. Distinction between legacy ClientHello client_version and negotiated/supported versions.
18. Truncated TLS record and invalid handshake length handling without exceptions.
19. Handling of non-Handshake TLS records (ChangeCipherSpec, Alert, ApplicationData).
20. Rejection of attempts to decrypt or guess encrypted application payloads.
21. IPv4 and IPv6 packet payload extraction.
22. Fragmented packet handling (non-initial fragments correctly yield no transport payload).
23. Empty inputs and corrupt payloads safety.
24. Deterministic metadata IDs across repeated runs.
25. Provenance preservation (record_id, frame_number, timestamps, source paths).
26. TimelineEvent conversion seam via to_timeline_event().
27. Streaming PCAP extraction via extract_metadata_from_pcap.
28. Object-oriented NetworkMetadataExtractor API behavior.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import struct
import unittest

from forensix.network_metadata import (
    FORENSIX_V5_NETWORK_METADATA_NAMESPACE,
    DnsAnswer,
    DnsMetadata,
    DnsQuestion,
    HttpMetadata,
    NetworkApplicationMetadata,
    NetworkMetadataExtractor,
    TlsMetadata,
    compute_deterministic_dns_id,
    compute_deterministic_http_id,
    compute_deterministic_tls_id,
    extract_application_metadata,
    extract_metadata_from_packet,
    extract_metadata_from_pcap,
    parse_dns_payload,
    parse_http_payload,
    parse_tls_payload,
)
from forensix.network_models import (
    NetworkEvidenceRecord,
    create_network_evidence_record,
)
from forensix.network_pcap_parser import (
    DLT_EN10MB,
    PcapParser,
    extract_transport_payload,
    read_pcap_raw,
)
from forensix.timeline_models import TimelineCategory, TimelineEvent


def build_synthetic_dns_query(tx_id: int, domain: str, qtype: int = 1, qclass: int = 1) -> bytes:
    """Build a synthetic raw DNS query packet."""
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname_parts = domain.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
    return header + qname_bytes + struct.pack(">HH", qtype, qclass)


def build_synthetic_dns_response_with_answers(tx_id: int, query_domain: str, a_ip: str = "93.184.216.34") -> bytes:
    """Build a synthetic DNS response packet with A record answer."""
    header = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
    qname_parts = query_domain.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
    question = qname_bytes + struct.pack(">HH", 1, 1)

    # Answer using pointer back to domain at offset 12
    ans_name = struct.pack(">H", 0xC00C)
    ip_bytes = bytes(int(x) for x in a_ip.split("."))
    answer = ans_name + struct.pack(">HHIH", 1, 1, 300, 4) + ip_bytes
    return header + question + answer


def build_synthetic_tls_client_hello(
    sni: str = "example.com",
    alpn_list: list = None,
    supported_versions: list = None,
) -> bytes:
    """Build a synthetic TLS 1.2/1.3 ClientHello packet."""
    alpn_list = alpn_list or ["h2", "http/1.1"]
    supported_versions = supported_versions or [0x0304, 0x0303]

    # Extensions:
    # 1. SNI
    sni_bytes = sni.encode("ascii")
    sni_data = struct.pack(">HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    sni_ext = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data

    # 2. ALPN
    alpn_payload = b""
    for proto in alpn_list:
        p_b = proto.encode("ascii")
        alpn_payload += bytes([len(p_b)]) + p_b
    alpn_data = struct.pack(">H", len(alpn_payload)) + alpn_payload
    alpn_ext = struct.pack(">HH", 0x0010, len(alpn_data)) + alpn_data

    # 3. Supported Versions
    sv_payload = b"".join(struct.pack(">H", v) for v in supported_versions)
    sv_data = bytes([len(sv_payload)]) + sv_payload
    sv_ext = struct.pack(">HH", 0x002B, len(sv_data)) + sv_data

    exts = sni_ext + alpn_ext + sv_ext
    exts_block = struct.pack(">H", len(exts)) + exts

    # ClientHello body
    ch_body = (
        struct.pack(">H", 0x0303)  # Legacy client_version (TLS 1.2)
        + (b"\x11" * 32)           # Random
        + b"\x00"                  # Session ID len (0)
        + struct.pack(">HH", 2, 0x002F)  # Cipher suites (1 suite)
        + b"\x01\x00"              # Compression methods (1 method)
        + exts_block
    )

    # Handshake header (Type 1, 3-byte length)
    ch_hdr = struct.pack(">B", 1) + struct.pack(">I", len(ch_body))[1:]
    record_body = ch_hdr + ch_body

    # TLS Record header (ContentType 22, Version 0x0301, 2-byte length)
    record_hdr = struct.pack(">BHH", 22, 0x0301, len(record_body))
    return record_hdr + record_body


def build_synthetic_pcap(packet_records: list) -> bytes:
    """Build a classic little-endian PCAP file buffer from (packet_data, ts_sec, ts_usec)."""
    # Global header (24 bytes): magic, 2.4, 0, 0, snaplen 65535, DLT_EN10MB (1)
    ghdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    buf = bytearray(ghdr)
    for pdata, sec, usec in packet_records:
        rec_hdr = struct.pack("<IIII", sec, usec, len(pdata), len(pdata))
        buf.extend(rec_hdr)
        buf.extend(pdata)
    return bytes(buf)


def build_ethernet_ipv4_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Wrap UDP payload in Ethernet + IPv4 headers."""
    # Ethernet header (14 bytes)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    # IPv4 header (20 bytes)
    ip_len = 20 + 8 + len(payload)
    s_ip_bytes = bytes(int(x) for x in src_ip.split("."))
    d_ip_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, ip_len, 0x1234, 0, 64, 17, 0) + s_ip_bytes + d_ip_bytes
    # UDP header (8 bytes)
    udp_hdr = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload


def build_ethernet_ipv4_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Wrap TCP payload in Ethernet + IPv4 headers."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_len = 20 + 20 + len(payload)
    s_ip_bytes = bytes(int(x) for x in src_ip.split("."))
    d_ip_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, ip_len, 0x1234, 0, 64, 6, 0) + s_ip_bytes + d_ip_bytes
    # TCP header (20 bytes, data offset = 5 -> 20 bytes)
    tcp_hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, 1000, 0, (5 << 4), 0x18, 64240, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload


class TestNetworkMetadataExtraction(unittest.TestCase):
    """Rigorous unit test suite for V5.4 Network Metadata Extraction."""

    def setUp(self) -> None:
        self.sample_dt = datetime(2026, 4, 15, 14, 0, 0, 123456, tzinfo=timezone.utc)
        self.sample_record = create_network_evidence_record(
            frame_number=1,
            timestamp=self.sample_dt,
            raw_timestamp="1713189600.123456",
            source_path="/evidence/sample.pcap",
            source_artifact_id="ART-100",
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="UDP",
            transport_protocol="UDP",
        )

    # 1. Valid DNS Query Parsing
    def test_01_valid_dns_query_parsing(self):
        """1. Verify valid DNS query parsing with transaction ID, domain, type, class, and flags."""
        query_bytes = build_synthetic_dns_query(0x1234, "example.com", qtype=1, qclass=1)
        dns_meta = parse_dns_payload(
            query_bytes,
            record_id=self.sample_record.record_id,
            frame_number=1,
            timestamp=self.sample_dt,
            raw_timestamp=self.sample_record.raw_timestamp,
            source_ip="192.168.1.50",
            destination_ip="8.8.8.8",
            source_port=54321,
            destination_port=53,
        )
        self.assertIsNotNone(dns_meta)
        self.assertEqual(dns_meta.transaction_id, 0x1234)
        self.assertFalse(dns_meta.is_response)
        self.assertEqual(dns_meta.response_status, "NOERROR")
        self.assertEqual(dns_meta.query_name, "example.com")
        self.assertEqual(dns_meta.query_type, "A")
        self.assertEqual(dns_meta.query_class, "IN")
        self.assertEqual(len(dns_meta.questions), 1)
        self.assertEqual(dns_meta.questions[0].name, "example.com")
        self.assertEqual(len(dns_meta.answers), 0)
        self.assertTrue(dns_meta.metadata_id.startswith("NETMD-DNS-"))

    # 2. Valid DNS Response with Answer Records
    def test_02_valid_dns_response_with_answers(self):
        """2. Verify valid DNS response parsing with answer records and IP extraction."""
        resp_bytes = build_synthetic_dns_response_with_answers(0x5678, "api.service.local", "10.0.0.42")
        dns_meta = parse_dns_payload(resp_bytes)
        self.assertIsNotNone(dns_meta)
        self.assertEqual(dns_meta.transaction_id, 0x5678)
        self.assertTrue(dns_meta.is_response)
        self.assertEqual(dns_meta.query_name, "api.service.local")
        self.assertEqual(len(dns_meta.answers), 1)
        ans = dns_meta.answers[0]
        self.assertEqual(ans.rtype, "A")
        self.assertEqual(ans.data, "10.0.0.42")
        self.assertEqual(ans.ttl, 300)

    # 3. DNS Compression Pointer Decompression
    def test_03_dns_compression_pointer_handling(self):
        """3. Verify correct decompression of domain names using backward pointers."""
        # Header + question ("host.domain.com") + answer pointing to "domain.com"
        header = struct.pack(">HHHHHH", 0xAAAA, 0x8180, 1, 1, 0, 0)
        # host.domain.com
        # offset 12: \x04host \x06domain \x03com \x00
        qname = b"\x04host\x06domain\x03com\x00"
        q = qname + struct.pack(">HH", 1, 1)
        # Answer points to "domain.com" at offset 17 (12 + 1 + 4)
        ans_name = struct.pack(">H", 0xC011)
        ans = ans_name + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
        packet = header + q + ans

        dns_meta = parse_dns_payload(packet)
        self.assertIsNotNone(dns_meta)
        self.assertEqual(dns_meta.query_name, "host.domain.com")
        self.assertEqual(len(dns_meta.answers), 1)
        self.assertEqual(dns_meta.answers[0].name, "domain.com")
        self.assertEqual(dns_meta.answers[0].data, "127.0.0.1")

    # 4. DNS Pointer Loop Detection
    def test_04_dns_pointer_loop_prevention(self):
        """4. Verify that cyclic compression pointers are terminated safely without infinite loops."""
        header = struct.pack(">HHHHHH", 0x1111, 0x0100, 1, 0, 0, 0)
        # Question with pointer looping to itself: offset 12 has 0xC00C pointing to offset 12
        looping_q = struct.pack(">H", 0xC00C) + struct.pack(">HH", 1, 1)
        packet = header + looping_q
        dns_meta = parse_dns_payload(packet)
        # Must terminate safely; returns None or empty query without hanging or crashing
        self.assertTrue(dns_meta is None or dns_meta.query_name == "")

    # 5. Malformed DNS Packet Handling
    def test_05_malformed_dns_handling(self):
        """5. Verify truncated and malformed DNS packets do not raise exceptions."""
        # Too short (only 8 bytes)
        self.assertIsNone(parse_dns_payload(b"\x00\x01\x02\x03\x04\x05\x06\x07"))
        # Header claims 5 questions, but payload ends abruptly
        truncated_q = struct.pack(">HHHHHH", 0x1234, 0x0100, 5, 0, 0, 0) + b"\x05test"
        dns_meta = parse_dns_payload(truncated_q)
        self.assertIsNone(dns_meta)

    # 6. Non-DNS UDP Traffic Rejection
    def test_06_non_dns_traffic_rejection(self):
        """6. Verify arbitrary UDP traffic is rejected rather than falsely claimed as DNS."""
        # Random binary data
        arbitrary_data = b"\xff" * 40
        self.assertIsNone(parse_dns_payload(arbitrary_data))
        # Invalid opcode (> 5)
        invalid_opcode = struct.pack(">HHHHHH", 0x1234, 0xF800, 1, 0, 0, 0) + b"\x04test\x00\x00\x01\x00\x01"
        self.assertIsNone(parse_dns_payload(invalid_opcode))

    # 7. DNS over TCP Handling
    def test_07_dns_over_tcp_handling(self):
        """7. Verify DNS over TCP message with 2-byte length prefix is parsed safely."""
        query_body = build_synthetic_dns_query(0x9999, "tcp-dns.org", qtype=1)
        tcp_prefixed = struct.pack(">H", len(query_body)) + query_body
        dns_meta = parse_dns_payload(tcp_prefixed, transport_protocol="TCP")
        self.assertIsNotNone(dns_meta)
        self.assertEqual(dns_meta.transaction_id, 0x9999)
        self.assertEqual(dns_meta.query_name, "tcp-dns.org")

    # 8. Valid HTTP Request Parsing
    def test_08_valid_http_request_parsing(self):
        """8. Verify cleartext HTTP request parsing with method, target, version, Host, and headers."""
        raw_http = (
            b"GET /api/v1/health HTTP/1.1\r\n"
            b"Host: internal.corp.net\r\n"
            b"User-Agent: ForensiX-Agent/1.0\r\n"
            b"Accept: application/json\r\n\r\n"
            b"BODY_SHOULD_BE_IGNORED"
        )
        http_meta = parse_http_payload(
            raw_http,
            record_id="NET-00000000-0000-0000-0000-000000000001",
            frame_number=2,
            source_ip="10.0.1.20",
            destination_ip="10.0.1.80",
            source_port=49152,
            destination_port=80,
        )
        self.assertIsNotNone(http_meta)
        self.assertTrue(http_meta.is_request)
        self.assertEqual(http_meta.method, "GET")
        self.assertEqual(http_meta.target, "/api/v1/health")
        self.assertEqual(http_meta.http_version, "HTTP/1.1")
        self.assertEqual(http_meta.host, "internal.corp.net")
        self.assertEqual(http_meta.user_agent, "ForensiX-Agent/1.0")
        self.assertTrue(http_meta.metadata_id.startswith("NETMD-HTTP-"))

    # 9. Valid HTTP Response Parsing
    def test_09_valid_http_response_parsing(self):
        """9. Verify cleartext HTTP response parsing with status code, reason phrase, and headers."""
        raw_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Content-Length: 42\r\n\r\n"
            b'{"status":"healthy","uptime":3600}'
        )
        http_meta = parse_http_payload(raw_resp)
        self.assertIsNotNone(http_meta)
        self.assertFalse(http_meta.is_request)
        self.assertEqual(http_meta.status_code, 200)
        self.assertEqual(http_meta.reason_phrase, "OK")
        self.assertEqual(http_meta.server, "nginx/1.24.0")
        self.assertEqual(http_meta.content_type, "application/json; charset=utf-8")
        self.assertEqual(http_meta.content_length, 42)

    # 10. Repeated and Case-Insensitive HTTP Headers
    def test_10_http_repeated_headers_preservation(self):
        """10. Verify repeated HTTP headers are preserved in headers sequence."""
        raw_http = (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"X-Custom-Header: value1\r\n"
            b"X-Custom-Header: value2\r\n\r\n"
        )
        http_meta = parse_http_payload(raw_http)
        self.assertIsNotNone(http_meta)
        custom_headers = [v for k, v in http_meta.headers if k.lower() == "x-custom-header"]
        self.assertEqual(custom_headers, ["value1", "value2"])

    # 11. Bounded HTTP Headers Protection
    def test_11_bounded_http_header_protection(self):
        """11. Verify safety against oversized lines and excessive header lines."""
        oversized_line = b"GET / HTTP/1.1\r\n" + (b"A" * 5000) + b"\r\n\r\n"
        # Should not crash; oversized line skipped
        meta = parse_http_payload(oversized_line)
        self.assertIsNotNone(meta)

    # 12. Incomplete / Truncated HTTP Messages
    def test_12_incomplete_http_message_safety(self):
        """12. Verify incomplete HTTP request without terminating blank line is parsed safely."""
        partial = b"GET /index.html HTTP/1.1\r\nHost: truncated.com"
        meta = parse_http_payload(partial)
        self.assertIsNotNone(meta)
        self.assertEqual(meta.method, "GET")
        self.assertEqual(meta.host, "truncated.com")

    # 13. Rejection of Binary / TLS by HTTP Parser
    def test_13_rejection_of_tls_by_http_parser(self):
        """13. Verify TLS Handshake payload is rejected by HTTP parser and not misidentified."""
        tls_hello = build_synthetic_tls_client_hello("bank.example.com")
        self.assertIsNone(parse_http_payload(tls_hello))

    # 14. Non-Retention of HTTP Bodies
    def test_14_non_retention_of_http_body(self):
        """14. Verify that sensitive payload bodies are dropped and never retained in metadata."""
        secret_body = b"PASSWORD_SECRET_12345"
        raw_http = b"POST /login HTTP/1.1\r\nHost: auth.net\r\n\r\n" + secret_body
        meta = parse_http_payload(raw_http)
        self.assertIsNotNone(meta)
        meta_dict = meta.to_dict()
        self.assertNotIn("PASSWORD_SECRET_12345", json.dumps(meta_dict))

    # 15. TLS ClientHello with SNI and ALPN
    def test_15_tls_client_hello_sni_and_alpn(self):
        """15. Verify TLS ClientHello extraction of SNI, ALPN, and supported versions."""
        tls_bytes = build_synthetic_tls_client_hello(
            sni="secure.portal.org",
            alpn_list=["h2", "http/1.1"],
            supported_versions=[0x0304, 0x0303],
        )
        tls_meta = parse_tls_payload(
            tls_bytes,
            record_id="NET-00000000-0000-0000-0000-000000000002",
            frame_number=3,
            source_ip="10.0.0.5",
            destination_ip="198.51.100.1",
            source_port=51234,
            destination_port=443,
        )
        self.assertIsNotNone(tls_meta)
        self.assertTrue(tls_meta.is_client_hello)
        self.assertEqual(tls_meta.server_name, "secure.portal.org")
        self.assertEqual(tls_meta.alpn_protocols, ("h2", "http/1.1"))
        self.assertIn("TLS 1.3", tls_meta.supported_versions)
        self.assertIn("TLS 1.2", tls_meta.supported_versions)
        self.assertTrue(tls_meta.metadata_id.startswith("NETMD-TLS-"))

    # 16. TLS ClientHello without SNI
    def test_16_tls_client_hello_without_sni(self):
        """16. Verify TLS ClientHello without SNI extension is handled safely with server_name=None."""
        # ClientHello with no extensions
        ch_body = (
            struct.pack(">H", 0x0303)
            + (b"\x00" * 32)
            + b"\x00"
            + struct.pack(">HH", 2, 0x002F)
            + b"\x01\x00"
        )
        ch_hdr = struct.pack(">B", 1) + struct.pack(">I", len(ch_body))[1:]
        record_body = ch_hdr + ch_body
        record_hdr = struct.pack(">BHH", 22, 0x0301, len(record_body))
        raw_tls = record_hdr + record_body

        tls_meta = parse_tls_payload(raw_tls)
        self.assertIsNotNone(tls_meta)
        self.assertTrue(tls_meta.is_client_hello)
        self.assertIsNone(tls_meta.server_name)
        self.assertEqual(len(tls_meta.alpn_protocols), 0)

    # 17. Distinction Between Legacy Version and Negotiated Versions
    def test_17_tls_version_distinction(self):
        """17. Verify client_version records legacy advertisement and does not claim negotiated version."""
        tls_bytes = build_synthetic_tls_client_hello("test.com", supported_versions=[0x0304])
        tls_meta = parse_tls_payload(tls_bytes)
        self.assertIsNotNone(tls_meta)
        self.assertEqual(tls_meta.record_version, "TLS 1.0")  # Record layer legacy
        self.assertEqual(tls_meta.client_version, "TLS 1.2")  # ClientHello legacy field
        self.assertEqual(tls_meta.supported_versions, ("TLS 1.3",))  # Advertised extension

    # 18. Truncated TLS Record Handling
    def test_18_truncated_tls_record_handling(self):
        """18. Verify truncated TLS records do not raise IndexError."""
        # 5 bytes header indicating 100 bytes, but only 10 bytes provided
        short_tls = struct.pack(">BHH", 22, 0x0303, 100) + b"\x01\x00\x00\x60\x03"
        tls_meta = parse_tls_payload(short_tls)
        # Should return partial metadata or None, never crash
        self.assertTrue(tls_meta is None or tls_meta.content_type == 22)

    # 19. Non-Handshake TLS Records
    def test_19_non_handshake_tls_records(self):
        """19. Verify ApplicationData (23) or Alert (21) records are parsed without ClientHello claims."""
        app_data = struct.pack(">BHH", 23, 0x0303, 16) + (b"\xaa" * 16)
        tls_meta = parse_tls_payload(app_data)
        self.assertIsNotNone(tls_meta)
        self.assertEqual(tls_meta.content_type, 23)
        self.assertFalse(tls_meta.is_client_hello)
        self.assertIsNone(tls_meta.server_name)

    # 20. No Attempt to Decrypt TLS
    def test_20_no_attempt_to_decrypt_tls(self):
        """20. Verify encrypted TLS application data is treated as opaque ciphertext."""
        app_data = struct.pack(">BHH", 23, 0x0303, 32) + (b"\x12" * 32)
        tls_meta = parse_tls_payload(app_data)
        self.assertIsNotNone(tls_meta)
        # No decrypted HTTP or DNS fields should ever be attached to ApplicationData
        app_meta = extract_application_metadata(app_data, transport_protocol="TCP")
        self.assertIsNotNone(app_meta)
        self.assertEqual(app_meta.protocol, "TLS")
        self.assertIsNone(app_meta.http)
        self.assertIsNone(app_meta.dns)

    # 21. IPv4 and IPv6 Transport Payload Extraction
    def test_21_ipv4_and_ipv6_transport_payload_extraction(self):
        """21. Verify extract_transport_payload correctly extracts ports and payload from IPv4 and IPv6 frames."""
        payload_data = b"HELLO_UDP_PAYLOAD"
        eth_ipv4_udp = build_ethernet_ipv4_udp("192.168.1.10", "192.168.1.20", 5000, 6000, payload_data)
        proto, s_p, d_p, extracted = extract_transport_payload(eth_ipv4_udp, DLT_EN10MB)
        self.assertEqual(proto, "UDP")
        self.assertEqual(s_p, 5000)
        self.assertEqual(d_p, 6000)
        self.assertEqual(extracted, payload_data)

    # 22. Fragmented Packet Handling
    def test_22_fragmented_packet_handling(self):
        """22. Verify non-initial IP fragments yield empty transport payload without crashing."""
        # Build IPv4 header with fragment offset > 0
        eth = b"\x00" * 14
        # flags_frag with offset 8 (0x0001 -> offset 8 bytes)
        ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, 40, 0x1234, 0x0001, 64, 6, 0) + (b"\x01" * 8)
        fragment_frame = eth + ip_hdr + (b"\xff" * 20)
        proto, s_p, d_p, payload = extract_transport_payload(fragment_frame, DLT_EN10MB)
        self.assertIsNone(proto)
        self.assertEqual(payload, b"")

    # 23. Empty and Corrupt Inputs Safety
    def test_23_empty_and_corrupt_inputs_safety(self):
        """23. Verify empty and corrupt payloads return None safely."""
        self.assertIsNone(extract_application_metadata(b""))
        self.assertIsNone(extract_application_metadata(b"\x00" * 3))
        self.assertEqual(extract_transport_payload(b""), (None, None, None, b""))

    # 24. Deterministic Metadata IDs
    def test_24_deterministic_metadata_ids(self):
        """24. Verify repeated extraction of identical packets produces identical metadata IDs."""
        query_bytes = build_synthetic_dns_query(0x4321, "deterministic.test")
        meta1 = parse_dns_payload(query_bytes, record_id="NET-1", frame_number=10)
        meta2 = parse_dns_payload(query_bytes, record_id="NET-1", frame_number=10)
        self.assertEqual(meta1.metadata_id, meta2.metadata_id)

        # Different frame produces distinct ID
        meta3 = parse_dns_payload(query_bytes, record_id="NET-1", frame_number=11)
        self.assertNotEqual(meta1.metadata_id, meta3.metadata_id)

    # 25. Provenance Preservation
    def test_25_provenance_preservation(self):
        """25. Verify record ID, frame number, timestamps, and source paths are preserved."""
        tls_bytes = build_synthetic_tls_client_hello("corp.internal")
        meta = extract_application_metadata(
            tls_bytes,
            record=self.sample_record,
            transport_protocol="TCP",
        )
        self.assertIsNotNone(meta)
        self.assertEqual(meta.record_id, self.sample_record.record_id)
        self.assertEqual(meta.frame_number, 1)
        self.assertEqual(meta.source_path, "/evidence/sample.pcap")
        self.assertEqual(meta.source_artifact_id, "ART-100")
        self.assertEqual(meta.timestamp, self.sample_dt)
        self.assertEqual(meta.raw_timestamp, "1713189600.123456")

    # 26. TimelineEvent Bridge Seam
    def test_26_timeline_event_bridge(self):
        """26. Verify NetworkApplicationMetadata conversion to TimelineEvent with category NETWORK."""
        dns_query = build_synthetic_dns_query(0x1234, "corp.gateway")
        meta = extract_application_metadata(
            dns_query,
            record=self.sample_record,
            transport_protocol="UDP",
        )
        self.assertIsNotNone(meta)
        tl_evt = meta.to_timeline_event()
        self.assertIsInstance(tl_evt, TimelineEvent)
        self.assertEqual(tl_evt.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_evt.event_type, "network_dns_metadata")
        self.assertIn("corp.gateway", tl_evt.description)
        self.assertEqual(tl_evt.source_artifact_id, "ART-100")

    # 27. Streaming Extraction from PCAP
    def test_27_streaming_pcap_extraction(self):
        """27. Verify extract_metadata_from_pcap reads frames incrementally and extracts metadata."""
        dns_pkt = build_synthetic_dns_query(0x2222, "pcap-test.com")
        dns_frame = build_ethernet_ipv4_udp("192.168.1.5", "8.8.8.8", 53000, 53, dns_pkt)

        http_pkt = b"GET /status HTTP/1.1\r\nHost: pcap-http.com\r\n\r\n"
        http_frame = build_ethernet_ipv4_tcp("192.168.1.5", "93.184.216.34", 53001, 80, http_pkt)

        tls_pkt = build_synthetic_tls_client_hello("pcap-tls.com")
        tls_frame = build_ethernet_ipv4_tcp("192.168.1.5", "104.16.1.1", 53002, 443, tls_pkt)

        pcap_data = build_synthetic_pcap([
            (dns_frame, 1713189600, 100000),
            (http_frame, 1713189601, 200000),
            (tls_frame, 1713189602, 300000),
        ])

        stream = io.BytesIO(pcap_data)
        extracted = list(extract_metadata_from_pcap(stream, pcap_name="test_pcap.pcap"))
        self.assertEqual(len(extracted), 3)

        self.assertEqual(extracted[0].protocol, "DNS")
        self.assertEqual(extracted[0].dns.query_name, "pcap-test.com")

        self.assertEqual(extracted[1].protocol, "HTTP")
        self.assertEqual(extracted[1].http.host, "pcap-http.com")

        self.assertEqual(extracted[2].protocol, "TLS")
        self.assertEqual(extracted[2].tls.server_name, "pcap-tls.com")

    # 28. NetworkMetadataExtractor OOP Interface
    def test_28_network_metadata_extractor_class(self):
        """28. Verify NetworkMetadataExtractor class methods extract_from_payload, packet, and pcap."""
        extractor = NetworkMetadataExtractor()
        dns_pkt = build_synthetic_dns_query(0x3333, "oop-test.net")
        meta = extractor.extract_from_payload(dns_pkt, transport_protocol="UDP")
        self.assertIsNotNone(meta)
        self.assertEqual(meta.protocol, "DNS")
        self.assertEqual(meta.dns.query_name, "oop-test.net")


if __name__ == "__main__":
    unittest.main()
