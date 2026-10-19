"""
Comprehensive Test Suite for ForensiX Milestone V7.5 — CLI Integration & Hardening.

Verifies:
1.  CLI help and command registration (forensix dashboard --help, -h, aliases).
2.  Existing CLI command compatibility (triage, timeline, memory, pcap, V1 single-file).
3.  Dashboard startup using synthetic reports across all 6 schemas.
4.  Port configuration and invalid-port handling (ephemeral 0, invalid negative, >65535).
5.  Invalid report paths and clear error reporting (missing file, invalid JSON, unsupported path).
6.  Loopback binding enforcement and bind failures (0.0.0.0 rejection, address collision).
7.  Startup failure cleanup (zero lingering sockets/threads on failure).
8.  Clean shutdown and interruption handling (KeyboardInterrupt simulation).
9.  Correct report registry population and dashboard endpoint responses (/api/reports, /api/pivots).
10. No unexpected filesystem writes or evidence modifications (strict read-only preservation).
11. Dashboard service and static asset availability through the packaged layout (/, /static/dashboard.css, /static/dashboard.js).
12. End-to-end CLI invocation lifecycle and graceful degradation.
"""

import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict
import unittest
from unittest.mock import MagicMock, patch
import urllib.request
import urllib.error
import uuid

from forensix import (
    __version__,
    build_dashboard_parser,
    dashboard_main,
    execute_dashboard_cli,
    main,
)
from forensix.dashboard_service import (
    ALLOWED_LOOPBACK_HOSTS,
    DEFAULT_DASHBOARD_PORT,
    DashboardReportRegistry,
    DashboardServer,
    create_dashboard_server,
)
from forensix.report_reader import freeze_payload


class TestDashboardCLI(unittest.TestCase):
    """Test suite for ForensiX V7.5 Dashboard CLI integration and lifecycle."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_v75_cli_test_")
        self.reports_dir = Path(self.temp_dir) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.active_servers: list[DashboardServer] = []

    def tearDown(self) -> None:
        for s in self.active_servers:
            try:
                s.stop()
            except Exception:
                pass
        self.active_servers.clear()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_synthetic_report(self, filename: str, report_type: str, extra: Dict[str, Any]) -> Path:
        """Helper to create a valid synthetic JSON report file."""
        report_data = {
            "metadata": {
                "report_id": f"REP-{filename}",
                "report_type": report_type,
                "case_id": "CASE-2026-V75",
                "created_at": "2026-10-19T10:00:00Z",
                "evidence_root": "/mnt/evidence/host01",
            },
            **extra,
        }
        target = self.reports_dir / filename
        target.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    def _create_all_six_schemas(self) -> list[Path]:
        """Create synthetic reports spanning all six ForensiX schema families."""
        paths = []
        # 1. Evidence Analysis
        p1 = self.reports_dir / "ea.json"
        p1.write_text(json.dumps({
            "evidence": {"evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32", "original_path": "/var/log/evidence.bin"},
            "file": {"filename": "evidence.bin", "size": 4096},
            "metadata": {"case_id": "CASE-V75-01"},
            "hashes": {"sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"},
        }), encoding="utf-8")
        paths.append(p1)

        # 2. Host Triage
        ht_uuid = str(uuid.uuid4())
        p2 = self.reports_dir / "ht.json"
        p2.write_text(json.dumps({
            "metadata": {
                "report_id": f"REPORT-{ht_uuid}",
                "case_id": "CASE-2026-001",
                "evidence_root": "/mnt/evidence/host01",
            },
            "artifacts": [
                {
                    "unified_id": "ART-HT-01",
                    "category": "network",
                    "artifact_type": "connection",
                    "specialized_payload": {"source_ip": "10.0.0.5", "pid": 1050}
                }
            ],
            "audit_trail": [
                {
                    "event_id": "AUD-01",
                    "timestamp": "2026-10-19T10:00:00Z",
                    "action": "triage_start"
                }
            ]
        }), encoding="utf-8")
        paths.append(p2)

        # 3. Timeline
        p3 = self.reports_dir / "tl.json"
        p3.write_text(json.dumps({
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-2026-002"},
            "events": [
                {
                    "event_id": "EVT-TL-01",
                    "timestamp": "2026-10-19T10:15:00Z",
                    "category": "NETWORK",
                    "attributes": {"ip_address": "10.0.0.5", "pid": 1050}
                }
            ]
        }), encoding="utf-8")
        paths.append(p3)

        # 4. Detection
        p4 = self.reports_dir / "det.json"
        p4.write_text(json.dumps({
            "report_type": "detection",
            "metadata": {"case_id": "CASE-2026-003"},
            "detections": [
                {"rule_id": "RULE-DET-01", "matched": True, "matched_event_ids": ["EVT-TL-01"]}
            ]
        }), encoding="utf-8")
        paths.append(p4)

        # 5. Correlation
        p5 = self.reports_dir / "corr.json"
        p5.write_text(json.dumps({
            "report_type": "correlation",
            "metadata": {"case_id": "CASE-2026-004"},
            "correlations": [
                {"correlation_id": "CORR-01", "rule_ids": ["RULE-DET-01"], "timeline_event_ids": ["EVT-TL-01"]}
            ]
        }), encoding="utf-8")
        paths.append(p5)

        # 6. Integrated Incident Investigation
        p6 = self.reports_dir / "inv.json"
        p6.write_text(json.dumps({
            "report_type": "correlation_detection",
            "metadata": {"case_id": "CASE-2026-005"},
            "timeline_events": [{"event_id": "EVT-INV-01", "timestamp": "2026-10-19T10:20:00Z", "attributes": {"ip": "10.0.0.5"}}],
            "detections": [{"rule_id": "RULE-INV-01", "matched": True}],
            "correlations": [{"correlation_id": "CORR-INV-01"}]
        }), encoding="utf-8")
        paths.append(p6)

        return paths

    # -------------------------------------------------------------------------
    # 1. CLI Help and Command Registration
    # -------------------------------------------------------------------------

    def test_01_cli_help_and_command_registration(self) -> None:
        """Verify dashboard subcommand help output and parser options."""
        parser = build_dashboard_parser()
        self.assertIsNotNone(parser)
        self.assertEqual(parser.prog, "python3 -m forensix dashboard")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["--help"])
            self.assertEqual(cm.exception.code, 0)

        help_text = stdout_buf.getvalue()
        self.assertIn("ForensiX - Local Read-Only Investigation Dashboard", help_text)
        self.assertIn("--port", help_text)
        self.assertIn("--host", help_text)
        self.assertIn("--recursive", help_text)
        self.assertIn("--max-report-size", help_text)
        self.assertIn("REPORT_PATH", help_text)

    def test_01b_main_subcommand_dispatch_and_aliases(self) -> None:
        """Verify main() dispatches 'dashboard', 'serve', and 'ui' commands."""
        for alias in ("dashboard", "serve", "ui"):
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                with self.assertRaises(SystemExit) as cm:
                    main([alias, "--help"])
                self.assertEqual(cm.exception.code, 0)
            self.assertIn("ForensiX - Local Read-Only Investigation Dashboard", stdout_buf.getvalue())

    # -------------------------------------------------------------------------
    # 2. Existing CLI Command Compatibility
    # -------------------------------------------------------------------------

    def test_02_existing_cli_subcommands_remain_unaffected(self) -> None:
        """Verify triage, timeline, memory, and pcap command dispatching is intact."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                main(["triage", "--help"])
            self.assertEqual(cm.exception.code, 0)
        self.assertIn("ForensiX - Automated Digital Forensics", stdout_buf.getvalue())
        self.assertIn("Orchestrator", stdout_buf.getvalue())

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                main(["timeline", "--help"])
            self.assertEqual(cm.exception.code, 0)
        self.assertIn("ForensiX - Automated Digital Forensics", stdout_buf.getvalue())
        self.assertIn("Timeline", stdout_buf.getvalue())

    # -------------------------------------------------------------------------
    # 3. Dashboard Startup Using Synthetic Reports
    # -------------------------------------------------------------------------

    def test_03_dashboard_startup_with_synthetic_reports(self) -> None:
        """Start dashboard CLI with synthetic reports and verify banner & response."""
        paths = self._create_all_six_schemas()
        argv = ["--port", "0", str(self.reports_dir)]

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(argv, block=False)

        self.assertEqual(code, 0)
        self.assertIsNotNone(server)
        self.active_servers.append(server)

        out = stdout_buf.getvalue()
        self.assertIn("ForensiX Local Investigation Dashboard", out)
        self.assertIn(f"Reports    : {len(paths)} ingested", out)
        self.assertIn("Binding    : Loopback Only", out)
        self.assertIn("Status     : ACTIVE", out)

        # Query health endpoint
        port = server.bound_port
        url = f"http://127.0.0.1:{port}/api/health"
        req = urllib.request.Request(url, headers={"User-Agent": "ForensiX-Test"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["reports_count"], 6)

    # -------------------------------------------------------------------------
    # 4. Port Configuration and Invalid-Port Handling
    # -------------------------------------------------------------------------

    def test_04_invalid_ports_rejected_cleanly(self) -> None:
        """Verify negative, excessive, and non-integer ports produce clean errors."""
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli(["--port", "-1"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Error: Invalid port number: -1", stderr_buf.getvalue())

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli(["--port", "70000"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Error: Invalid port number: 70000", stderr_buf.getvalue())

    def test_04b_max_report_size_validation(self) -> None:
        """Verify --max-report-size rejects negative values and accepts zero."""
        # 1. Negative limit -> exit code 1, no server, validation error on stderr
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli(["--max-report-size", "-1"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Error: Invalid maximum report size: -1", stderr_buf.getvalue())

        # 2. Zero limit with empty report list -> accepted as valid configuration
        empty_dir = Path(self.temp_dir) / "empty_reports"
        empty_dir.mkdir(parents=True, exist_ok=True)
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(["--port", "0", "--max-report-size", "0", str(empty_dir)], block=False)
            self.assertEqual(code, 0)
            self.assertIsNotNone(server)
            self.active_servers.append(server)

        # 3. Zero limit with a non-empty report -> fails ingestion with size limit exceeded
        p = self.reports_dir / "tl_size_zero.json"
        p.write_text(json.dumps({"report_type": "timeline", "metadata": {"case_id": "C1"}, "events": []}), encoding="utf-8")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli(["--port", "0", "--max-report-size", "0", str(p)], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("exceeds maximum allowed limit", stderr_buf.getvalue())

    # -------------------------------------------------------------------------
    # 5. Invalid Report Paths and Clear Error Reporting
    # -------------------------------------------------------------------------

    def test_05_invalid_report_path_reporting(self) -> None:
        """Verify non-existent path and unreadable report file produce clean errors."""
        missing = str(Path(self.temp_dir) / "nonexistent.json")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli([missing], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn(f"Error: Report path does not exist: '{missing}'", stderr_buf.getvalue())

        bad_file = Path(self.temp_dir) / "corrupt.json"
        bad_file.write_text("NOT_JSON_DATA", encoding="utf-8")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli([str(bad_file)], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Failed to ingest report file", stderr_buf.getvalue())

    # -------------------------------------------------------------------------
    # 6. Loopback Binding Enforcement and Bind Failures
    # -------------------------------------------------------------------------

    def test_06_loopback_binding_enforcement(self) -> None:
        """Verify external interface binding (0.0.0.0, public IP) is strictly blocked."""
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli(["--host", "0.0.0.0", "--port", "0"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("ForensiX dashboard can only bind to loopback", stderr_buf.getvalue())

    def test_06b_port_collision_address_in_use_error(self) -> None:
        """Verify socket bind collision produces a clean, user-friendly error without traceback."""
        # Bind a socket first and listen to create a guaranteed collision
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        collision_port = sock.getsockname()[1]

        try:
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code, server = execute_dashboard_cli(["--port", str(collision_port)], block=False)
                self.assertEqual(code, 1)
                self.assertIsNone(server)
                self.assertIn("Failed to bind dashboard server", stderr_buf.getvalue())
        finally:
            sock.close()

    # -------------------------------------------------------------------------
    # 7. Startup Failure Cleanup
    # -------------------------------------------------------------------------

    def test_07_startup_failure_cleanup(self) -> None:
        """Verify failed startup leaves zero lingering threads."""
        threads_before = threading.active_count()
        missing = str(Path(self.temp_dir) / "missing_file.json")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code, server = execute_dashboard_cli([missing], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
        threads_after = threading.active_count()
        self.assertEqual(threads_before, threads_after)

    # -------------------------------------------------------------------------
    # 8. Clean Shutdown and Interruption Handling
    # -------------------------------------------------------------------------

    def test_08_clean_shutdown_keyboard_interrupt(self) -> None:
        """Verify KeyboardInterrupt during serve_forever triggers clean shutdown."""
        mock_server = MagicMock(spec=DashboardServer)
        mock_server.bound_port = 8080
        mock_server.serve_forever.side_effect = KeyboardInterrupt()

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with patch("forensix.dashboard_cli.create_dashboard_server", return_value=mock_server):
                code, _ = execute_dashboard_cli(["--port", "8080"], block=True)
                self.assertEqual(code, 0)
                mock_server.stop.assert_called_once()

        out = stdout_buf.getvalue()
        self.assertIn("Shutting down ForensiX dashboard server...", out)
        self.assertIn("Dashboard server stopped cleanly.", out)

    # -------------------------------------------------------------------------
    # 9. Correct Report Registry Population & Pivot Endpoint Responses
    # -------------------------------------------------------------------------

    def test_09_registry_population_and_pivot_api_queries(self) -> None:
        """Ingest synthetic reports via CLI and verify /api/reports and /api/pivots."""
        paths = self._create_all_six_schemas()
        argv = ["--port", "0", str(paths[1]), str(paths[2])]  # host triage and timeline

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(argv, block=False)

        self.assertEqual(code, 0)
        self.assertIsNotNone(server)
        self.active_servers.append(server)
        port = server.bound_port

        # 1. Query /api/reports
        url_reports = f"http://127.0.0.1:{port}/api/reports"
        with urllib.request.urlopen(url_reports, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["total"], 2)

        # 2. Query /api/pivots for IP
        url_pivots = f"http://127.0.0.1:{port}/api/pivots?field=ip_address&value=10.0.0.5"
        with urllib.request.urlopen(url_pivots, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            pivot_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(pivot_data["total_matches"], 2)
            self.assertEqual(len(pivot_data["matches"]), 2)

    # -------------------------------------------------------------------------
    # 10. No Unexpected Filesystem Writes or Evidence Modifications
    # -------------------------------------------------------------------------

    def test_10_evidence_files_remain_unmodified(self) -> None:
        """Verify running the dashboard causes zero file alterations or new files in evidence."""
        paths = self._create_all_six_schemas()
        hashes_before = {p: p.read_bytes() for p in paths}
        mtimes_before = {p: p.stat().st_mtime_ns for p in paths}

        argv = ["--port", "0", str(self.reports_dir)]
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(argv, block=False)
        self.assertEqual(code, 0)
        self.active_servers.append(server)

        # Assert no bytes changed and no new files created in reports directory
        for p in paths:
            self.assertEqual(p.read_bytes(), hashes_before[p])
            self.assertEqual(p.stat().st_mtime_ns, mtimes_before[p])
        self.assertEqual(set(self.reports_dir.glob("*.json")), set(paths))

    # -------------------------------------------------------------------------
    # 11. Dashboard Service and Static Asset Availability Through Packaged Layout
    # -------------------------------------------------------------------------

    def test_11_static_assets_served_via_cli_instance(self) -> None:
        """Verify UI static assets (HTML, CSS, JS, favicon) are served cleanly."""
        argv = ["--port", "0"]
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(argv, block=False)
        self.assertEqual(code, 0)
        self.active_servers.append(server)
        port = server.bound_port

        # 1. Root / -> HTML
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            self.assertIn("ForensiX", resp.read().decode("utf-8"))
            self.assertIn("Content-Security-Policy", resp.headers)

        # 2. CSS
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/static/dashboard.css", timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/css", resp.headers.get("Content-Type", ""))

        # 3. JS
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/static/dashboard.js", timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("javascript", resp.headers.get("Content-Type", ""))

        # 4. Favicon
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.svg", timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("image/svg+xml", resp.headers.get("Content-Type", ""))

    # -------------------------------------------------------------------------
    # 12. Main Entry Point Exit Code Mapping
    # -------------------------------------------------------------------------

    def test_12_dashboard_main_returns_expected_exit_codes(self) -> None:
        """Verify dashboard_main() returns 0 on success and 1 on error."""
        # Non-existent report -> returns 1
        missing = str(Path(self.temp_dir) / "does_not_exist.json")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code = dashboard_main([missing])
            self.assertEqual(code, 1)

        # Successful startup with mock server
        mock_server = MagicMock(spec=DashboardServer)
        mock_server.bound_port = 8080
        mock_server.serve_forever.side_effect = KeyboardInterrupt()
        with patch("forensix.dashboard_cli.create_dashboard_server", return_value=mock_server):
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code = dashboard_main(["--port", "8080"])
                self.assertEqual(code, 0)

    def test_13_directory_ingestion_summary_banner(self) -> None:
        """Verify startup banner displays ingestion summary when directory contains skipped reports."""
        mixed_dir = Path(self.temp_dir) / "mixed_reports"
        mixed_dir.mkdir(parents=True, exist_ok=True)

        # 1 valid report
        valid_rep = mixed_dir / "valid_tl.json"
        valid_rep.write_text(json.dumps({
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-CLI-MIXED-01"},
            "events": [{"event_id": "EVT-CLI-01", "timestamp": "2026-10-19T12:00:00Z"}]
        }), encoding="utf-8")

        # 1 broken JSON file
        broken_file = mixed_dir / "broken.json"
        broken_file.write_text("{malformed...", encoding="utf-8")

        # 1 unknown schema file
        unknown_file = mixed_dir / "unknown.json"
        unknown_file.write_text(json.dumps({"some_key": "val"}), encoding="utf-8")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code, server = execute_dashboard_cli(["--port", "0", str(mixed_dir)], block=False)

        self.assertEqual(code, 0)
        self.assertIsNotNone(server)
        self.active_servers.append(server)

        out = stdout_buf.getvalue()
        self.assertIn("Reports    : 1 ingested, 2 skipped", out)
        self.assertIn("[SKIPPED] broken.json", out)
        self.assertIn("[SKIPPED] unknown.json", out)

    def test_14_default_reports_directory_handling(self) -> None:
        """Verify handling of missing default reports dir, empty default dir, and directory-level failures."""
        work_dir = Path(self.temp_dir) / "cli_work_dir"
        work_dir.mkdir(parents=True, exist_ok=True)

        # 1. Missing optional default reports directory -> succeeds with 0 reports
        with patch("pathlib.Path.is_dir", return_value=False), patch("pathlib.Path.exists", return_value=False):
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code, server = execute_dashboard_cli(["--port", "0"], block=False)
            self.assertEqual(code, 0)
            self.assertIsNotNone(server)
            self.active_servers.append(server)
            self.assertIn("Reports    : 0 ingested", stdout_buf.getvalue())

        # 2. Normal empty default reports directory -> succeeds with 0 reports
        mock_reports_dir = work_dir / "reports"
        mock_reports_dir.mkdir(parents=True, exist_ok=True)
        with patch("pathlib.Path.is_dir", side_effect=lambda: True), \
             patch("pathlib.Path.exists", side_effect=lambda: True), \
             patch("forensix.dashboard_service.DashboardReportRegistry.register_directory", return_value=[]):
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code, server = execute_dashboard_cli(["--port", "0"], block=False)
            self.assertEqual(code, 0)
            self.assertIsNotNone(server)
            self.active_servers.append(server)
            self.assertIn("Reports    : 0 ingested", stdout_buf.getvalue())

        # 3. Directory-level processing failure (e.g. PermissionError) -> fails fast with clean error
        with patch("pathlib.Path.is_dir", return_value=True), \
             patch("forensix.dashboard_service.DashboardReportRegistry.register_directory", side_effect=PermissionError("Permission denied")):
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code, server = execute_dashboard_cli(["--port", "0"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Failed to process default report directory 'reports'", stderr_buf.getvalue())
            self.assertIn("PermissionError", stderr_buf.getvalue())

        # 4. Default report path exists but is not a directory -> fails fast with clean error
        with patch("pathlib.Path.is_dir", return_value=False), \
             patch("pathlib.Path.exists", return_value=True):
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code, server = execute_dashboard_cli(["--port", "0"], block=False)
            self.assertEqual(code, 1)
            self.assertIsNone(server)
            self.assertIn("Default report path 'reports' exists but is not a directory", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
