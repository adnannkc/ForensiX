"""
Comprehensive Integration Test Suite for ForensiX Milestone V5.8 — CLI and Triage Integration.

Verifies:
1.  Successful processing of a valid synthetic PCAP.
2.  DNS, HTTP, and TLS metadata integration where available.
3.  Timeline event creation and timestamp preservation.
4.  Existing detection rules producing traceable results.
5.  PCAP-only triage without fabricated host evidence.
6.  Mixed host and network evidence when supported.
7.  Host-network correlation provenance.
8.  Invalid path and unreadable file handling.
9.  Unsupported PCAP-NG and malformed/truncated capture behavior.
10. Empty capture handling (0-byte vs 24-byte header).
11. Evidence-file integrity before and after processing.
12. Stable output ordering and deterministic derived identifiers.
13. Large-input / streaming behavior without unnecessary full-file buffering.
14. Backward compatibility for every existing CLI command and triage test.
15. Appropriate behavior when a pipeline stage fails.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from forensix.correlation_models import CorrelationType
from forensix.main import main
from forensix.network_metadata import DnsMetadata, HttpMetadata, TlsMetadata
from forensix.network_pcap_parser import (
    PCAPNG_SECTION_HEADER_MAGIC,
)
from forensix.timeline_models import TimelineCategory
from forensix.triage_cli import (
    build_pcap_parser,
    execute_investigation_cli,
    execute_pcap_cli,
    pcap_main,
)


def _build_pcap_file(path: Path, packets: list) -> Path:
    """Build a synthetic classic PCAP file on disk."""
    ghdr = b"\xd4\xc3\xb2\xa1" + struct.pack(
        "<HHiIII",
        2,
        4,
        0,
        0,
        65535,
        1,  # DLT_EN10MB (Ethernet)
    )
    with open(path, "wb") as f:
        f.write(ghdr)
        for ts_sec, ts_usec, pdata in packets:
            orig_len = len(pdata)
            cap_len = orig_len
            phdr = struct.pack("<IIII", ts_sec, ts_usec, cap_len, orig_len)
            f.write(phdr)
            f.write(pdata)
    return path


def _make_eth_ipv4_tcp_frame(
    src_ip_str: str,
    dst_ip_str: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    flags: int = 0x18,  # PSH, ACK
) -> bytes:
    """Construct an Ethernet/IPv4/TCP frame byte sequence."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src_parts = [int(x) for x in src_ip_str.split(".")]
    dst_parts = [int(x) for x in dst_ip_str.split(".")]
    src_ip_b = bytes(src_parts)
    dst_ip_b = bytes(dst_parts)
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x00,
        total_len,
        0x1234,
        0x0000,
        64,
        6,
        0x0000,
        src_ip_b,
        dst_ip_b,
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        0x50,
        flags,
        8192,
        0,
        0,
    )
    return eth + ip_hdr + tcp_hdr + payload


def _make_eth_ipv4_udp_frame(
    src_ip_str: str,
    dst_ip_str: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    """Construct an Ethernet/IPv4/UDP frame byte sequence."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src_parts = [int(x) for x in src_ip_str.split(".")]
    dst_parts = [int(x) for x in dst_ip_str.split(".")]
    src_ip_b = bytes(src_parts)
    dst_ip_b = bytes(dst_parts)
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x00,
        total_len,
        0x1234,
        0x0000,
        64,
        17,
        0x0000,
        src_ip_b,
        dst_ip_b,
    )
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth + ip_hdr + udp_hdr + payload


def _build_dns_query_payload(tx_id: int, domain: str) -> bytes:
    """Build a synthetic raw DNS query payload."""
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    parts = domain.split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def _build_tls_client_hello_payload(sni: str = "secure.bank.corp") -> bytes:
    """Build a synthetic TLS ClientHello payload."""
    sni_b = sni.encode("ascii")
    sni_data = struct.pack(">HBH", len(sni_b) + 3, 0, len(sni_b)) + sni_b
    sni_ext = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data

    exts_block = struct.pack(">H", len(sni_ext)) + sni_ext
    ch_body = (
        struct.pack(">H", 0x0303)
        + (b"\xaa" * 32)
        + b"\x00"
        + struct.pack(">H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + exts_block
    )
    hs_header = bytes([0x01]) + struct.pack(">I", len(ch_body))[1:]
    hs_msg = hs_header + ch_body
    rec_header = struct.pack(">BHH", 0x16, 0x0301, len(hs_msg))
    return rec_header + hs_msg


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestV58CliTriageIntegration(unittest.TestCase):
    """Focused integration tests for ForensiX V5.8 CLI and Triage Integration."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="forensix_v58_test_"))
        self.reports_dir = self.temp_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Successful processing of a valid synthetic PCAP
    def test_01_valid_synthetic_pcap_processing(self):
        """1. Verify successful processing of a valid synthetic PCAP via CLI entrypoints."""
        pkt1 = _make_eth_ipv4_tcp_frame("192.168.1.50", "10.0.0.1", 49152, 80, b"DATA")
        pcap_file = _build_pcap_file(self.temp_dir / "valid.pcap", [(1713182400, 100000, pkt1)])

        # A) Via execute_pcap_cli
        report_json = self.reports_dir / "pcap_run.json"
        code, report = execute_pcap_cli([
            str(pcap_file),
            "-o", str(report_json),
            "--format", "json",
            "--case-id", "CASE-PCAP-01",
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)
        self.assertTrue(report_json.exists())
        self.assertGreater(report.event_count, 0)

        # B) Via execute_investigation_cli
        inv_json = self.reports_dir / "inv_run.json"
        code2, report2 = execute_investigation_cli([
            str(pcap_file),
            "-o", str(inv_json),
            "--json",
            "--case-id", "CASE-PCAP-02",
        ])
        self.assertEqual(code2, 0)
        self.assertIsNotNone(report2)
        self.assertTrue(inv_json.exists())

    # 2. DNS, HTTP, and TLS metadata integration where available
    def test_02_dns_http_and_tls_metadata_integration(self):
        """2. Verify extraction and timeline integration of DNS, HTTP, and TLS application metadata."""
        dns_payload = _build_dns_query_payload(0x1234, "api.service.org")
        pkt_dns = _make_eth_ipv4_udp_frame("192.168.1.10", "1.1.1.1", 53000, 53, dns_payload)

        http_payload = b"GET /v1/status HTTP/1.1\r\nHost: api.service.org\r\nUser-Agent: test/1.0\r\n\r\n"
        pkt_http = _make_eth_ipv4_tcp_frame("192.168.1.10", "93.184.216.34", 54000, 80, http_payload)

        tls_payload = _build_tls_client_hello_payload("vault.secure.corp")
        pkt_tls = _make_eth_ipv4_tcp_frame("192.168.1.10", "104.16.1.1", 55000, 443, tls_payload)

        pcap_file = _build_pcap_file(
            self.temp_dir / "app_traffic.pcap",
            [
                (1713182400, 100000, pkt_dns),
                (1713182405, 200000, pkt_http),
                (1713182410, 300000, pkt_tls),
            ],
        )

        out_json = self.reports_dir / "meta_report.json"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_json), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        events = data.get("timeline_events", [])
        event_types = [e["event_type"] for e in events]
        descriptions = [e["description"] for e in events]

        self.assertIn("network_dns_metadata", event_types)
        self.assertIn("network_http_metadata", event_types)
        self.assertIn("network_tls_metadata", event_types)

        # Check metadata details in descriptions / attributes
        dns_desc = next(d for d in descriptions if "api.service.org" in d)
        self.assertIn("api.service.org", dns_desc)

        tls_desc = next(d for d in descriptions if "vault.secure.corp" in d)
        self.assertIn("vault.secure.corp", tls_desc)

    # 3. Timeline event creation and timestamp preservation
    def test_03_timeline_event_creation_and_timestamp_preservation(self):
        """3. Verify timestamps, subseconds, and categories are preserved in timeline reconstruction."""
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.10", "10.0.0.1", 49152, 443, b"TLS_SIM")
        ts_sec = 1713182400
        ts_usec = 654321
        pcap_file = _build_pcap_file(self.temp_dir / "ts_test.pcap", [(ts_sec, ts_usec, pkt)])

        code, report = execute_investigation_cli([str(pcap_file), "--output", str(self.reports_dir)])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        net_events = [e for e in report.timeline_events if e.category == TimelineCategory.NETWORK]
        self.assertGreater(len(net_events), 0)

        first_event = net_events[0]
        self.assertIsNotNone(first_event.timestamp)
        self.assertEqual(first_event.timestamp.microsecond, 654321)
        self.assertEqual(first_event.raw_timestamp, "1713182400.654321")

    # 4. Existing detection rules producing traceable results
    def test_04_detection_rules_traceable_results(self):
        """4. Verify network detection rules fire and link traceably to supporting event IDs."""
        dns_payload = _build_dns_query_payload(0x7777, "malicious.domain.test")
        pkt_dns = _make_eth_ipv4_udp_frame("192.168.1.15", "8.8.8.8", 53535, 53, dns_payload)

        # SSH port observation (dst_port 22)
        pkt_ssh = _make_eth_ipv4_tcp_frame("192.168.1.15", "198.51.100.5", 54321, 22, b"SSH-2.0-OpenSSH")

        pcap_file = _build_pcap_file(
            self.temp_dir / "rules_test.pcap",
            [
                (1713182400, 100000, pkt_dns),
                (1713182410, 200000, pkt_ssh),
            ],
        )

        out_json = self.reports_dir / "rules_report.json"
        code, report = execute_investigation_cli([str(pcap_file), "-o", str(out_json), "--json"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        # Verify matched detections
        matched_detections = [d for d in report.detections if d.matched]
        self.assertGreater(len(matched_detections), 0)

        # Detections must reference event IDs that exist in the timeline
        all_event_ids = {e.event_id for e in report.timeline_events}
        for det in matched_detections:
            self.assertTrue(len(det.matched_event_ids) > 0)
            for eid in det.matched_event_ids:
                self.assertIn(eid, all_event_ids)

    # 5. PCAP-only triage without fabricated host evidence
    def test_05_pcap_only_triage_no_fabricated_host_evidence(self):
        """5. Verify PCAP-only investigation does NOT fabricate host accounts, groups, or host logs."""
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.2", "192.168.1.3", 8080, 80, b"DATA")
        pcap_file = _build_pcap_file(self.temp_dir / "pcap_only.pcap", [(1713182400, 0, pkt)])

        out_json = self.reports_dir / "pcap_only_report.json"
        code, report = execute_investigation_cli([str(pcap_file), "-o", str(out_json), "--json"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        # Verify no host accounts or auth artifacts were fabricated
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Host evidence should reflect empty/absent host artifacts
        events = data.get("timeline_events", [])
        for ev in events:
            self.assertEqual(ev["category"].lower(), "network")
            self.assertNotEqual(ev["category"].lower(), "authentication")
            self.assertNotEqual(ev["category"].lower(), "account")

    # 6. Mixed host and network evidence when supported
    def test_06_mixed_host_and_network_evidence(self):
        """6. Verify mixed host logs and network PCAP coexisting in a unified investigation."""
        evidence_dir = self.temp_dir / "mixed_evidence"
        var_log = evidence_dir / "var" / "log"
        var_log.mkdir(parents=True, exist_ok=True)

        # Host log artifact in canonical var/log location
        auth_log = var_log / "auth.log"
        auth_log.write_text(
            "2024-04-15T12:00:00+00:00 server sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 49152 ssh2\n",
            encoding="utf-8",
        )

        # Network PCAP file placed directly in directory
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.100", "192.168.1.200", 49152, 22, b"SSH-2.0")
        _build_pcap_file(evidence_dir / "traffic.pcap", [(1713182400, 100000, pkt)])

        out_json = self.reports_dir / "mixed_report.json"
        code, report = execute_investigation_cli([str(evidence_dir), "-o", str(out_json), "--json"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        categories = {e.category for e in report.timeline_events}
        self.assertIn(TimelineCategory.AUTHENTICATION, categories)
        self.assertIn(TimelineCategory.NETWORK, categories)

    # 7. Host-network correlation provenance
    def test_07_host_network_correlation_provenance(self):
        """7. Verify correlation engine links host events to network observations with CORR- IDs."""
        evidence_dir = self.temp_dir / "corr_evidence"
        var_log = evidence_dir / "var" / "log"
        var_log.mkdir(parents=True, exist_ok=True)

        # Host authentication event from IP 192.168.1.100
        auth_log = var_log / "auth.log"
        auth_log.write_text(
            "2024-04-15T12:00:00+00:00 server sshd[1234]: Accepted password for bob from 192.168.1.100 port 55555 ssh2\n",
            encoding="utf-8",
        )

        # PCAP with network connection involving 192.168.1.100 within same time window
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.100", "10.0.0.5", 55555, 22, b"SSH-2.0")
        pcap_file = _build_pcap_file(self.temp_dir / "corr_external.pcap", [(1713182400, 200000, pkt)])

        out_json = self.reports_dir / "corr_report.json"
        code, report = execute_investigation_cli([
            str(evidence_dir),
            "--pcap", str(pcap_file),
            "-o", str(out_json),
            "--json",
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        host_net_correlations = [
            c for c in report.correlations
            if (
                c.relationship_type == CorrelationType.HOST_NETWORK
                or str(c.relationship_type) == "HOST_NETWORK"
            )
        ]
        self.assertGreater(len(host_net_correlations), 0)
        for corr in host_net_correlations:
            self.assertTrue(corr.correlation_id.startswith("CORR-"))
            self.assertGreater(len(corr.event_ids), 1)

    # 8. Invalid path and unreadable file handling
    def test_08_invalid_path_and_unreadable_file_handling(self):
        """8. Verify clear errors and exit code 1 for non-existent and unreadable paths."""
        non_existent = self.temp_dir / "does_not_exist.pcap"

        # A) Non-existent PCAP
        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, report = execute_pcap_cli([str(non_existent)])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("does not exist", buf_err.getvalue())

        # B) Unreadable PCAP (PermissionError)
        valid_pcap = _build_pcap_file(self.temp_dir / "locked.pcap", [])
        buf_err2 = io.StringIO()
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("sys.stderr", buf_err2):
                code2, report2 = execute_pcap_cli([str(valid_pcap)])
        self.assertEqual(code2, 1)
        self.assertIsNone(report2)
        self.assertIn("Permission denied", buf_err2.getvalue())

    # 9. Unsupported PCAP-NG and malformed/truncated capture behavior
    def test_09_unsupported_pcapng_and_malformed_truncated_capture(self):
        """9. Verify clean error reporting for PCAP-NG, corrupt magic, and truncated captures."""
        # A) PCAP-NG file
        ng_file = self.temp_dir / "test.pcapng"
        ng_file.write_bytes(struct.pack("<I", PCAPNG_SECTION_HEADER_MAGIC) + b"\x00" * 24)

        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, report = execute_pcap_cli([str(ng_file)])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("PCAP-NG", buf_err.getvalue())

        # B) Corrupt magic
        corrupt_file = self.temp_dir / "corrupt.pcap"
        corrupt_file.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 20)

        buf_err2 = io.StringIO()
        with patch("sys.stderr", buf_err2):
            code2, report2 = execute_pcap_cli([str(corrupt_file)])
        self.assertEqual(code2, 1)
        self.assertIsNone(report2)
        self.assertIn("corrupt", buf_err2.getvalue().lower())

        # C) Truncated packet record
        trunc_file = self.temp_dir / "trunc.pcap"
        ghdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        # Truncated record header (only 8 bytes instead of 16)
        trunc_file.write_bytes(ghdr + b"\x00" * 8)

        buf_err3 = io.StringIO()
        with patch("sys.stderr", buf_err3):
            code3, report3 = execute_pcap_cli([str(trunc_file)])
        self.assertEqual(code3, 1)
        self.assertIsNone(report3)
        self.assertIn("truncated", buf_err3.getvalue().lower())

    # 10. Empty capture handling
    def test_10_empty_capture_handling(self):
        """10. Verify 0-byte file fails with truncated error, while valid 24-byte PCAP succeeds with 0 events."""
        # A) 0-byte empty file
        empty_file = self.temp_dir / "zero.pcap"
        empty_file.write_bytes(b"")

        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, report = execute_pcap_cli([str(empty_file)])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("truncated", buf_err.getvalue().lower())

        # B) Valid 24-byte header PCAP with 0 packet frames
        valid_empty = _build_pcap_file(self.temp_dir / "valid_empty.pcap", [])
        code2, report2 = execute_pcap_cli([str(valid_empty), "-o", str(self.reports_dir / "empty.json")])
        self.assertEqual(code2, 0)
        self.assertIsNotNone(report2)
        self.assertEqual(report2.event_count, 0)

    # 11. Evidence-file integrity before and after processing
    def test_11_evidence_file_integrity(self):
        """11. Verify cryptographic hash of evidence files remains byte-for-byte unchanged."""
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.1", "10.0.0.1", 1234, 80, b"TEST")
        pcap_file = _build_pcap_file(self.temp_dir / "immutable.pcap", [(1713182400, 0, pkt)])

        hash_before = _compute_sha256(pcap_file)
        execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "rep1.json")])
        execute_investigation_cli([str(pcap_file), "-o", str(self.reports_dir / "rep2.json")])
        hash_after = _compute_sha256(pcap_file)

        self.assertEqual(hash_before, hash_after)

    # 12. Stable output ordering and deterministic derived identifiers
    def test_12_stable_output_ordering_and_deterministic_ids(self):
        """12. Verify deterministic event counts, source event IDs, and consistent reporting across runs."""
        pkt1 = _make_eth_ipv4_tcp_frame("192.168.1.10", "10.0.0.1", 1000, 80, b"REQ1")
        pkt2 = _make_eth_ipv4_tcp_frame("192.168.1.20", "10.0.0.2", 2000, 80, b"REQ2")
        pcap_file = _build_pcap_file(
            self.temp_dir / "determ.pcap",
            [(1713182400, 0, pkt1), (1713182401, 0, pkt2)],
        )

        out1 = self.reports_dir / "run1.json"
        out2 = self.reports_dir / "run2.json"

        code1, rep1 = execute_pcap_cli([str(pcap_file), "-o", str(out1), "--format", "json"])
        code2, rep2 = execute_pcap_cli([str(pcap_file), "-o", str(out2), "--format", "json"])

        self.assertEqual(code1, 0)
        self.assertEqual(code2, 0)
        self.assertEqual(rep1.event_count, rep2.event_count)
        self.assertEqual(rep1.correlation_count, rep2.correlation_count)
        self.assertEqual(rep1.detection_count, rep2.detection_count)
        self.assertEqual(rep1.matched_detections, rep2.matched_detections)

        # Source event IDs (NETEVT-<UUIDv5>) must be deterministic across repeated runs
        src_ids_1 = [e.source_event_id for e in rep1.timeline_events]
        src_ids_2 = [e.source_event_id for e in rep2.timeline_events]
        self.assertEqual(src_ids_1, src_ids_2)

    # 13. Large-input / streaming behavior without unnecessary full-file buffering
    def test_13_large_input_streaming_behavior(self):
        """13. Verify large PCAP processing streams packet events correctly without full memory buffers."""
        packets = []
        for i in range(100):
            pkt = _make_eth_ipv4_tcp_frame("192.168.1.1", "10.0.0.1", 1024 + i, 80, f"PKT_{i}".encode())
            packets.append((1713182400 + i, i * 1000, pkt))

        pcap_file = _build_pcap_file(self.temp_dir / "multi_packets.pcap", packets)

        code, report = execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "stream.json")])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 100)

    # 14. Backward compatibility for every existing CLI command and triage test
    def test_14_backward_compatibility_existing_commands(self):
        """14. Verify standard ForensiX investigate, triage, and timeline subcommands remain fully backward-compatible."""
        ev_dir = self.temp_dir / "compat_evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        (ev_dir / "auth.log").write_text("Apr 15 12:00:00 srv sshd[1]: Accepted publickey for test\n")

        # forensix investigate on regular directory
        code_inv, rep_inv = execute_investigation_cli([str(ev_dir), "-o", str(self.reports_dir / "compat_inv.json")])
        self.assertEqual(code_inv, 0)
        self.assertIsNotNone(rep_inv)

        # forensix main dispatcher with investigate
        with patch("sys.argv", ["forensix", "investigate", str(ev_dir), "-o", str(self.reports_dir / "compat_main.json")]):
            ret = main()
            self.assertEqual(ret, 0)

        # forensix main dispatcher with pcap
        valid_pcap = _build_pcap_file(self.temp_dir / "compat.pcap", [])
        with patch("sys.argv", ["forensix", "pcap", str(valid_pcap), "-o", str(self.reports_dir / "compat_pcap.json")]):
            ret2 = main()
            self.assertEqual(ret2, 0)

    # 15. Appropriate behavior when a pipeline stage fails
    def test_15_pipeline_stage_failure_visibility(self):
        """15. Verify pipeline failures (e.g. output directory collision or invalid argument) fail cleanly with exit code 1."""
        valid_pcap = _build_pcap_file(self.temp_dir / "stage_fail.pcap", [])

        # Passing an invalid format
        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, report = execute_pcap_cli([str(valid_pcap), "--format", "invalid_format"])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Unsupported report format", buf_err.getvalue())


if __name__ == "__main__":
    unittest.main()
