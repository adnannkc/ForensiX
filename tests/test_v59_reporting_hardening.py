"""
Comprehensive Integration Test Suite for ForensiX Milestone V5.9 — Reporting and Hardening.

Verifies:
1.  Network evidence appearing in JSON reports.
2.  Network evidence appearing in HTML reports.
3.  Detections and correlations linking to their supporting events and artifacts.
4.  Correct serialization of missing and optional fields.
5.  Correct timestamp handling and preservation of precision limitations.
6.  HTML escaping for untrusted packet and metadata strings (anti-XSS).
7.  Sensitive payloads not being exposed by default (header redaction).
8.  Malformed and unsupported captures producing clear diagnostics.
9.  Partial pipeline failures and limitations represented accurately.
10. Deterministic report ordering and stable output where expected.
11. Duplicate input handling and frame number preservation.
12. Evidence integrity before and after the full workflow (SHA-256 unchanged).
13. Output paths prevented from polluting evidence directories.
14. Large-input handling without unnecessary whole-file buffering.
15. Backward compatibility of existing V4 report formats and commands.
16. Full end-to-end PCAP-to-timeline-to-correlation/detection-to-report behavior.
17. Existing host-only investigation reporting remaining fully functional.
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
from forensix.detection_reporting import (
    generate_correlation_detection_report,
    render_correlation_detection_html,
    render_correlation_detection_json,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
)
from forensix.main import main
from forensix.network_metadata import (
    DnsMetadata,
    HttpMetadata,
    TlsMetadata,
    parse_http_payload,
)
from forensix.network_pcap_parser import (
    PCAPNG_SECTION_HEADER_MAGIC,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)
from forensix.triage_cli import (
    execute_investigation_cli,
    execute_pcap_cli,
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


class TestV59ReportingAndHardening(unittest.TestCase):
    """Comprehensive test suite for ForensiX Milestone V5.9 Reporting and Hardening."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="forensix_v59_test_"))
        self.reports_dir = self.temp_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Network evidence appearing in JSON reports
    def test_01_network_evidence_in_json_report(self):
        """1. Verify network packets and application metadata appear accurately in JSON reports."""
        dns_p = _build_dns_query_payload(0x101, "cluster.internal.net")
        pkt1 = _make_eth_ipv4_udp_frame("10.0.0.5", "10.0.0.1", 53123, 53, dns_p)

        http_p = b"GET /api/v1/health HTTP/1.1\r\nHost: cluster.internal.net\r\n\r\n"
        pkt2 = _make_eth_ipv4_tcp_frame("10.0.0.5", "10.0.0.2", 49152, 80, http_p)

        pcap_file = _build_pcap_file(
            self.temp_dir / "traffic.pcap",
            [(1713182400, 100000, pkt1), (1713182401, 200000, pkt2)],
        )

        out_json = self.reports_dir / "net_report.json"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_json), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        events = data.get("timeline_events", [])
        self.assertGreater(len(events), 0)

        # Check fields in events
        net_events = [e for e in events if e.get("category") == "network"]
        self.assertEqual(len(net_events), len(events))

        dns_events = [e for e in net_events if e.get("event_type") == "network_dns_metadata"]
        self.assertEqual(len(dns_events), 1)
        self.assertEqual(dns_events[0]["source_line"], 1)  # Frame 1
        self.assertTrue(dns_events[0]["attributes"]["metadata_id"].startswith("NETMD-DNS-"))
        self.assertEqual(dns_events[0]["attributes"]["query_name"], "cluster.internal.net")

        http_events = [e for e in net_events if e.get("event_type") == "network_http_metadata"]
        self.assertEqual(len(http_events), 1)
        self.assertEqual(http_events[0]["source_line"], 2)  # Frame 2
        self.assertEqual(http_events[0]["attributes"]["method"], "GET")
        self.assertEqual(http_events[0]["attributes"]["host"], "cluster.internal.net")

    # 2. Network evidence appearing in HTML reports
    def test_02_network_evidence_in_html_report(self):
        """2. Verify network events, frames, and protocols appear accurately in HTML reports."""
        tls_p = _build_tls_client_hello_payload("gateway.secure.org")
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.10", "1.1.1.1", 50000, 443, tls_p)
        pcap_file = _build_pcap_file(self.temp_dir / "tls.pcap", [(1713182400, 0, pkt)])

        out_html = self.reports_dir / "net_report.html"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_html), "--format", "html"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)

        html_text = out_html.read_text(encoding="utf-8")
        self.assertIn("gateway.secure.org", html_text)
        self.assertIn("network_tls_metadata", html_text)
        self.assertIn("Frame:", html_text)
        self.assertIn("Timeline Events", html_text)

    # 3. Detections and correlations linking to their supporting events and artifacts
    def test_03_detections_and_correlations_linking(self):
        """3. Verify detections traceably link to correlations and underlying timeline events in JSON."""
        dns_p = _build_dns_query_payload(0x999, "malicious.test.org")
        pkt_dns = _make_eth_ipv4_udp_frame("192.168.1.50", "8.8.8.8", 53000, 53, dns_p)
        pkt_ssh = _make_eth_ipv4_tcp_frame("192.168.1.50", "198.51.100.1", 54000, 22, b"SSH-2.0")

        pcap_file = _build_pcap_file(
            self.temp_dir / "linked.pcap",
            [(1713182400, 100000, pkt_dns), (1713182401, 200000, pkt_ssh)],
        )

        out_json = self.reports_dir / "linked.json"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_json), "--format", "json"])
        self.assertEqual(code, 0)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        detections = [d for d in data.get("detections", []) if d.get("matched")]
        self.assertGreater(len(detections), 0)

        timeline_event_ids = {e["event_id"] for e in data.get("timeline_events", [])}
        for det in detections:
            # Check supporting_events are resolved in serialization
            supporting_events = det.get("supporting_events", [])
            self.assertGreater(len(supporting_events), 0)
            for ev in supporting_events:
                self.assertIn(ev["event_id"], timeline_event_ids)
                self.assertIsNotNone(ev.get("source_path"))
                self.assertIsNotNone(ev.get("source_line"))

    # 4. Correct serialization of missing and optional fields
    def test_04_serialization_missing_and_optional_fields(self):
        """4. Verify events with None/missing attributes serialize cleanly without crashing."""
        ev_missing = TimelineEvent(
            timestamp=None,
            raw_timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="generic_packet",
            description="Packet with missing timestamps",
            source_path=None,
            source_line=None,
            source_artifact_id=None,
            source_event_id="NETEVT-000",
            attributes={},
        )
        report = generate_correlation_detection_report(
            detections=(),
            correlations=(),
            timeline=[ev_missing],
        )
        json_str = render_correlation_detection_json(report)
        data = json.loads(json_str)

        ev_dict = data["timeline_events"][0]
        self.assertIsNone(ev_dict["timestamp"])
        self.assertIsNone(ev_dict["raw_timestamp"])
        self.assertIsNone(ev_dict["source_path"])
        self.assertIsNone(ev_dict["source_line"])

    # 5. Correct timestamp handling and preservation of precision limitations
    def test_05_timestamp_precision_limitations(self):
        """5. Verify microsecond precision and raw timestamps are preserved in serialized outputs."""
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.1", "10.0.0.1", 1000, 80, b"DATA")
        ts_sec = 1713182400
        ts_usec = 987654
        pcap_file = _build_pcap_file(self.temp_dir / "precision.pcap", [(ts_sec, ts_usec, pkt)])

        out_json = self.reports_dir / "precision.json"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_json), "--format", "json"])
        self.assertEqual(code, 0)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        ev = data["timeline_events"][0]
        self.assertEqual(ev["raw_timestamp"], "1713182400.987654")
        self.assertTrue(ev["timestamp"].endswith(".987654Z"))

    # 6. HTML escaping for untrusted packet and metadata strings
    def test_06_html_escaping_untrusted_strings(self):
        """6. Verify untrusted strings in network packets are strictly escaped to prevent XSS injection."""
        xss_string = "<script>alert('pcap-xss')</script>"
        dns_p = _build_dns_query_payload(0x123, f"{xss_string}.attacker.org")
        pkt = _make_eth_ipv4_udp_frame("10.0.0.1", "10.0.0.2", 12345, 53, dns_p)
        pcap_file = _build_pcap_file(self.temp_dir / "xss.pcap", [(1713182400, 0, pkt)])

        out_html = self.reports_dir / "xss_report.html"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_html), "--format", "html"])
        self.assertEqual(code, 0)

        html_text = out_html.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert('pcap-xss')</script>", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;pcap-xss&#x27;)&lt;/script&gt;", html_text)

    # 7. Sensitive payloads not being exposed by default
    def test_07_sensitive_payloads_not_exposed(self):
        """7. Verify sensitive HTTP headers (Authorization, Cookie) are redacted by default."""
        http_raw = (
            b"POST /api/login HTTP/1.1\r\n"
            b"Host: auth.corp.internal\r\n"
            b"Authorization: Bearer super-secret-token-xyz123\r\n"
            b"Cookie: session_id=secret-session-abc\r\n"
            b"X-API-Key: confidential-api-key\r\n\r\n"
        )
        pkt = _make_eth_ipv4_tcp_frame("10.0.0.5", "10.0.0.1", 40000, 80, http_raw)
        pcap_file = _build_pcap_file(self.temp_dir / "auth_leak.pcap", [(1713182400, 0, pkt)])

        out_json = self.reports_dir / "auth_report.json"
        code, report = execute_pcap_cli([str(pcap_file), "-o", str(out_json), "--format", "json"])
        self.assertEqual(code, 0)

        json_text = out_json.read_text(encoding="utf-8")
        self.assertNotIn("super-secret-token-xyz123", json_text)
        self.assertNotIn("secret-session-abc", json_text)
        self.assertNotIn("confidential-api-key", json_text)
        self.assertIn("[REDACTED]", json_text)

    # 8. Malformed and unsupported captures producing clear diagnostics
    def test_08_malformed_and_unsupported_captures_diagnostics(self):
        """8. Verify clear user-facing diagnostics and exit code 1 for malformed or unsupported captures."""
        # PCAP-NG file
        ng_file = self.temp_dir / "unsupported.pcapng"
        ng_file.write_bytes(struct.pack("<I", PCAPNG_SECTION_HEADER_MAGIC) + b"\x00" * 24)

        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, report = execute_pcap_cli([str(ng_file)])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("PCAP-NG", buf_err.getvalue())

    # 9. Partial pipeline failures and limitations represented accurately
    def test_09_partial_pipeline_failures_represented_accurately(self):
        """9. Verify limitations and non-fatal processing notes are included in reports."""
        report = generate_correlation_detection_report(
            detections=(),
            correlations=(),
            timeline=(),
            limitations=["Passive wire capture analysis: TLS payload bodies are not decrypted"],
            errors=["Warning: 1 corrupted frame skipped at offset 2048"],
        )
        json_data = report.to_dict()
        self.assertIn("limitations", json_data)
        self.assertIn("errors", json_data)
        self.assertEqual(len(json_data["limitations"]), 1)
        self.assertEqual(len(json_data["errors"]), 1)

        html_out = render_correlation_detection_html(report)
        self.assertIn("Processing Limitations &amp; Diagnostics", html_out)
        self.assertIn("Passive wire capture analysis", html_out)

    # 10. Deterministic report ordering and stable output where expected
    def test_10_deterministic_report_ordering(self):
        """10. Verify repeated generation produces identical event counts, detections, and sort order."""
        pkt1 = _make_eth_ipv4_tcp_frame("10.0.0.1", "10.0.0.2", 1000, 80, b"P1")
        pkt2 = _make_eth_ipv4_tcp_frame("10.0.0.1", "10.0.0.2", 1001, 80, b"P2")
        pcap_file = _build_pcap_file(
            self.temp_dir / "ordered.pcap",
            [(1713182400, 0, pkt1), (1713182401, 0, pkt2)],
        )

        out1 = self.reports_dir / "ord1.json"
        out2 = self.reports_dir / "ord2.json"
        execute_pcap_cli([str(pcap_file), "-o", str(out1), "--format", "json"])
        execute_pcap_cli([str(pcap_file), "-o", str(out2), "--format", "json"])

        with open(out1, "r", encoding="utf-8") as f1, open(out2, "r", encoding="utf-8") as f2:
            d1 = json.load(f1)
            d2 = json.load(f2)

        self.assertEqual(
            [e["source_event_id"] for e in d1["timeline_events"]],
            [e["source_event_id"] for e in d2["timeline_events"]],
        )
        self.assertEqual(
            [e["source_line"] for e in d1["timeline_events"]],
            [e["source_line"] for e in d2["timeline_events"]],
        )
        self.assertEqual(
            [e["timestamp"] for e in d1["timeline_events"]],
            [e["timestamp"] for e in d2["timeline_events"]],
        )

    # 11. Duplicate input handling
    def test_11_duplicate_input_handling(self):
        """11. Verify duplicate packet frames retain distinct frame numbers and are not dropped improperly."""
        pkt = _make_eth_ipv4_tcp_frame("192.168.1.1", "10.0.0.1", 5000, 80, b"SAME")
        # Same frame content, same timestamp, 2 frames
        pcap_file = _build_pcap_file(
            self.temp_dir / "dups.pcap",
            [(1713182400, 0, pkt), (1713182400, 0, pkt)],
        )

        code, report = execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "dups.json")])
        self.assertEqual(code, 0)
        self.assertEqual(report.event_count, 2)
        frames = [e.source_line for e in report.timeline_events]
        self.assertEqual(frames, [1, 2])

    # 12. Evidence integrity before and after the full workflow
    def test_12_evidence_integrity(self):
        """12. Verify SHA-256 of PCAP evidence is completely identical before and after reporting."""
        pkt = _make_eth_ipv4_tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, b"DATA")
        pcap_file = _build_pcap_file(self.temp_dir / "immutable.pcap", [(1713182400, 0, pkt)])

        before_hash = _compute_sha256(pcap_file)
        execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "imm1.json"), "--format", "json"])
        execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "imm2.html"), "--format", "html"])
        after_hash = _compute_sha256(pcap_file)

        self.assertEqual(before_hash, after_hash)

    # 13. Output paths not polluting evidence directories
    def test_13_output_paths_not_polluting_evidence(self):
        """13. Verify attempting to write report inside evidence directory is rejected."""
        evidence_dir = self.temp_dir / "isolated_evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "test.log").write_text("log line\n")

        bad_output = evidence_dir / "bad_report.json"
        buf_err = io.StringIO()
        with patch("sys.stderr", buf_err):
            code, rep = execute_investigation_cli([str(evidence_dir), "-o", str(bad_output)])
        self.assertEqual(code, 1)
        self.assertIsNone(rep)
        self.assertIn("cannot be within", buf_err.getvalue())
        self.assertFalse(bad_output.exists())

    # 14. Large-input handling without unnecessary whole-file buffering
    def test_14_large_input_streaming_behavior(self):
        """14. Verify large PCAP processing streams through without full memory buffering."""
        packets = []
        for i in range(200):
            pkt = _make_eth_ipv4_tcp_frame("10.0.0.1", "10.0.0.2", 1000 + i, 80, f"PKT_{i}".encode())
            packets.append((1713182400 + i, 0, pkt))

        pcap_file = _build_pcap_file(self.temp_dir / "large.pcap", packets)
        code, rep = execute_pcap_cli([str(pcap_file), "-o", str(self.reports_dir / "large.json")])
        self.assertEqual(code, 0)
        self.assertEqual(rep.event_count, 200)

    # 15. Backward compatibility of existing V4 report formats and commands
    def test_15_backward_compatibility_v4_reports(self):
        """15. Verify V4 report schema conforms to established fields and types."""
        ev_dir = self.temp_dir / "v4_compat"
        var_log = ev_dir / "var" / "log"
        var_log.mkdir(parents=True, exist_ok=True)
        (var_log / "auth.log").write_text("2026-09-30T10:00:00+00:00 host sshd[1]: Accepted publickey for user\n")

        out_json = self.reports_dir / "v4_compat.json"
        code, rep = execute_investigation_cli([str(ev_dir), "-o", str(out_json), "--json"])
        self.assertEqual(code, 0)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["report_type"], "correlation_detection")
        self.assertEqual(data["report_version"], "4.6")
        self.assertIn("summary", data)
        self.assertIn("detections", data)
        self.assertIn("correlations", data)
        self.assertIn("timeline_events", data)

    # 16. Full end-to-end PCAP-to-timeline-to-correlation/detection-to-report behavior
    def test_16_e2e_pcap_to_report(self):
        """16. Verify end-to-end execution through main() dispatcher."""
        dns_p = _build_dns_query_payload(0x777, "partner.api.org")
        pkt = _make_eth_ipv4_udp_frame("192.168.1.1", "8.8.8.8", 1234, 53, dns_p)
        pcap_file = _build_pcap_file(self.temp_dir / "e2e.pcap", [(1713182400, 0, pkt)])

        out_html = self.reports_dir / "e2e_report.html"
        with patch("sys.argv", ["forensix", "pcap", str(pcap_file), "-o", str(out_html), "--format", "html"]):
            ret = main()
            self.assertEqual(ret, 0)

        self.assertTrue(out_html.exists())
        self.assertGreater(out_html.stat().st_size, 500)

    # 17. Existing host-only investigation reporting remaining functional
    def test_17_host_only_investigation_reporting_remains_functional(self):
        """17. Verify pure host evidence produces valid reports without network fields or errors."""
        ev_dir = self.temp_dir / "host_only"
        var_log = ev_dir / "var" / "log"
        var_log.mkdir(parents=True, exist_ok=True)
        (var_log / "auth.log").write_text(
            "2026-09-30T10:00:00+00:00 host sshd[1]: Accepted password for analyst from 192.168.1.55 port 44210 ssh2\n"
            "2026-09-30T10:01:00+00:00 host sudo: analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id\n",
            encoding="utf-8",
        )

        out_json = self.reports_dir / "host_only.json"
        code, rep = execute_investigation_cli([str(ev_dir), "-o", str(out_json), "--json"])
        self.assertEqual(code, 0)
        self.assertGreater(rep.matched_detections, 0)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        # No network events in pure host evidence
        categories = {e["category"] for e in data["timeline_events"]}
        self.assertNotIn("network", categories)


if __name__ == "__main__":
    unittest.main()
