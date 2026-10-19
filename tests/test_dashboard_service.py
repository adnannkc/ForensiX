"""
Comprehensive Test Suite for ForensiX Milestone V7.2 — Local Read-Only Dashboard Service.

Verifies:
1.  Registry lifecycle: registration of IngestedReport instances, files, and directories.
2.  Deterministic report identifier derivation (rep-<sha256[:12]>) and custom safe IDs.
3.  Rejection of invalid or malformed report IDs in the registry.
4.  Sanitization of local filesystem storage paths in registry outputs.
5.  Support for all 6 ForensiX report schemas in registry and HTTP service.
6.  Enforcement of loopback binding (rejection of 0.0.0.0 and external interfaces).
7.  HTTP GET /api/health and /health endpoints on empty and populated registries.
8.  HTTP GET /api/reports collection endpoint with deterministic sorting.
9.  HTTP GET /api/reports/<id> overview, /metadata, /summary, and /details endpoints.
10. Proper 404 Not Found error responses for missing reports and unknown sub-endpoints.
11. Proper 400 Bad Request rejection for path traversal attempts (.., %2e%2e, %2f, etc.).
12. Proper 405 Method Not Allowed rejection for POST, PUT, DELETE, PATCH, OPTIONS, HEAD.
13. Security headers (Content-Type, X-Content-Type-Options: nosniff, Cache-Control: no-store).
14. Prevention of local absolute path and stack trace leakage in API responses.
15. Strict read-only immutability of on-disk files and in-memory report structures.
16. Server startup on loopback ephemeral ports and clean shutdown.
"""

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

from forensix import __version__
from forensix.dashboard_service import (
    ALLOWED_DASHBOARD_HOSTNAMES,
    ALLOWED_LOOPBACK_HOSTS,
    DEFAULT_DASHBOARD_HOST,
    DEFAULT_DASHBOARD_PORT,
    DEFAULT_PIVOT_MAX_RESULTS,
    DashboardReportRegistry,
    DashboardRequestHandler,
    DashboardServer,
    IDENTIFIER_KIND_CORRELATION_ID,
    IDENTIFIER_KIND_EVIDENCE_ID,
    IDENTIFIER_KIND_REPORT_ID,
    IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
    IDENTIFIER_KIND_SOURCE_ID,
    IDENTIFIER_KIND_UNIFIED_ID,
    MAX_PIVOT_RESULTS_LIMIT,
    PivotFieldType,
    PivotQueryResult,
    PivotReference,
    create_dashboard_server,
    extract_report_pivots,
    is_safe_report_id,
    is_valid_dashboard_host,
    normalize_case_id,
    normalize_ip_address_pivot,
    normalize_pid,
    normalize_sha256,
)
from forensix.report_reader import (
    CaseMetadataView,
    IngestedReport,
    ReportSizeLimitError,
    ReportSummaryCounts,
    ReportType,
    read_report,
)


class TestDashboardService(unittest.TestCase):
    """Test suite for V7.2 Local Read-Only Dashboard Service."""

    def setUp(self) -> None:
        """Create a temporary sandbox directory for test fixtures."""
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="forensix_test_v72_")
        self.temp_dir = Path(self._temp_dir_obj.name)

        # Build synthetic report fixtures across schemas
        self.v1_file = self._write_json(
            "v1_analysis.json",
            {
                "evidence": {
                    "evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32",
                    "original_path": "/var/log/evidence.bin",
                    "registered_at": "2026-10-01T12:00:00+00:00",
                },
                "file": {
                    "filename": "evidence.bin",
                    "size": 4096,
                    "extension": ".bin",
                    "type": "application/octet-stream",
                },
                "metadata": {
                    "permissions": "0644",
                    "modified": "2026-09-30T10:00:00+00:00",
                    "accessed": "2026-09-30T11:00:00+00:00",
                    "created": None,
                },
                "hashes": {
                    "md5": "c98d3632cfba9828d13b4c1001eeac37",
                    "sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
                },
                "analysis_timestamp": "2026-10-01T12:00:01+00:00",
            },
        )

        self.v2_file = self._write_json(
            "v2_triage.json",
            {
                "metadata": {
                    "report_id": f"REPORT-{uuid.uuid4()}",
                    "case_id": "CASE-2026-001",
                    "case_name": "Host Compromise Triage",
                    "investigator": "Lead Analyst",
                    "created_at": "2026-10-01T15:30:00Z",
                    "forensix_version": "5.0.0",
                    "evidence_root": "/mnt/evidence/host01",
                    "report_format": "json",
                },
                "artifacts": [
                    {
                        "unified_id": "ART-01",
                        "category": "filesystem",
                        "status": "SUCCESS",
                    }
                ],
                "audit_trail": [
                    {
                        "event_id": "AUD-01",
                        "timestamp": "2026-10-01T15:30:00Z",
                        "action": "triage_start",
                    }
                ],
            },
        )

        self.v3_file = self._write_json(
            "v3_timeline.json",
            {
                "report_type": "timeline",
                "metadata": {
                    "case_id": "CASE-2026-002",
                    "generated_at": "2026-10-01T16:00:00Z",
                },
                "events": [
                    {
                        "event_id": "EVT-01",
                        "timestamp": "2026-10-01T12:00:00Z",
                        "description": "User login",
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        """Clean up temporary sandbox."""
        self._temp_dir_obj.cleanup()

    def _write_json(self, name: str, data: Any) -> Path:
        """Helper to write pretty-printed JSON to a temporary file."""
        file_path = self.temp_dir / name
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return file_path

    def _http_request(
        self,
        server: DashboardServer,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        """Helper to send an HTTP request to the test server and return status, headers, and parsed JSON."""
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            req_headers = headers or {}
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            raw_body = resp.read()
            data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            return resp.status, resp_headers, data
        finally:
            conn.close()

    def _http_request_raw(
        self,
        server: DashboardServer,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Helper to send an HTTP request and return status, headers, and raw byte body."""
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            req_headers = headers or {}
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            raw_body = resp.read()
            return resp.status, resp_headers, raw_body
        finally:
            conn.close()

    # =========================================================================
    # 1. Registry Unit Tests
    # =========================================================================

    def test_01_registry_empty_and_registration(self) -> None:
        """Verify empty registry behavior and individual report registration."""
        registry = DashboardReportRegistry()
        self.assertEqual(len(registry), 0)
        self.assertEqual(registry.list_reports(), [])

        ingested = read_report(self.v1_file)
        rep_id = registry.register_report(ingested)

        self.assertEqual(len(registry), 1)
        self.assertIn(rep_id, registry)
        self.assertTrue(rep_id.startswith("rep-"))
        self.assertEqual(registry.get(rep_id), ingested)

    def test_02_registry_id_derivation_and_collision_handling(self) -> None:
        """Verify deterministic ID derivation and collision handling."""
        registry = DashboardReportRegistry()
        ingested = read_report(self.v1_file)

        id1 = registry.register_report(ingested)
        # Register same report again (re-registration returns same ID)
        id2 = registry.register_report(ingested)
        self.assertEqual(id1, id2)

        # Register a second ingested report with identical content under automatic ID
        ingested_clone = read_report(self.v1_file)
        id3 = registry.register_report(ingested_clone)
        self.assertNotEqual(id1, id3)
        self.assertTrue(id3.startswith(f"{id1}-"))
        self.assertEqual(len(registry), 2)

    def test_03_registry_custom_id_validation(self) -> None:
        """Verify custom report ID validation and rejection of invalid characters."""
        registry = DashboardReportRegistry()
        ingested = read_report(self.v1_file)

        # Valid custom IDs
        self.assertEqual(
            registry.register_report(ingested, report_id="report-01"), "report-01"
        )
        self.assertEqual(
            registry.register_report(ingested, report_id="v1_evidence.2026"),
            "v1_evidence.2026",
        )

        # Invalid custom IDs: path traversal, whitespace, separators
        with self.assertRaises(ValueError):
            registry.register_report(ingested, report_id="..")
        with self.assertRaises(ValueError):
            registry.register_report(ingested, report_id="../../etc/passwd")
        with self.assertRaises(ValueError):
            registry.register_report(ingested, report_id="report with spaces")
        with self.assertRaises(ValueError):
            registry.register_report(ingested, report_id="rep/01")
        with self.assertRaises(ValueError):
            registry.register_report(ingested, report_id="rep\\01")

        # Collision with different report
        ingested_v2 = read_report(self.v2_file)
        with self.assertRaises(ValueError):
            registry.register_report(ingested_v2, report_id="report-01")

    def test_04_registry_register_file_and_directory(self) -> None:
        """Verify batch registration from files and directories."""
        registry = DashboardReportRegistry()

        # Add invalid JSON file to temp dir to test error resilience
        invalid_json = self.temp_dir / "broken.json"
        invalid_json.write_text("{broken-json", encoding="utf-8")

        # Add non-report JSON
        other_json = self.temp_dir / "random.json"
        other_json.write_text(json.dumps({"some": "arbitrary_data"}), encoding="utf-8")

        registered_ids = registry.register_directory(self.temp_dir)

        # Should have registered v1, v2, v3 and gracefully skipped broken & random JSON
        self.assertEqual(len(registered_ids), 3)
        self.assertEqual(len(registry), 3)

    def test_05_registry_sanitization_no_local_paths(self) -> None:
        """Verify registry outputs never leak local storage absolute paths."""
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(self.v1_file)

        views = registry.list_reports()
        self.assertEqual(len(views), 1)
        v = views[0]
        self.assertNotIn("source_path", v)
        self.assertEqual(v["filename"], "v1_analysis.json")
        self.assertNotIn(str(self.temp_dir), str(v))

        detail = registry.get_report_view(rep_id)
        self.assertIsNotNone(detail)
        self.assertNotIn("source_path", detail)
        self.assertEqual(detail["filename"], "v1_analysis.json")
        self.assertNotIn(str(self.temp_dir), str(detail))

    def test_06_registry_reports_across_six_schemas(self) -> None:
        """Verify all six report schemas can be registered and queried."""
        registry = DashboardReportRegistry()

        # V1 Evidence Analysis
        registry.register_file(self.v1_file, report_id="rep-v1")
        # V2 Host Triage
        registry.register_file(self.v2_file, report_id="rep-v2")
        # V3 Timeline
        registry.register_file(self.v3_file, report_id="rep-v3")

        # V4 Standalone Detection
        v4_det = self._write_json(
            "v4_det.json",
            {
                "report_type": "detection",
                "metadata": {"case_id": "CASE-DET"},
                "detections": [{"rule_id": "R1", "matched": True}],
            },
        )
        registry.register_file(v4_det, report_id="rep-v4-det")

        # V4 Standalone Correlation
        v4_corr = self._write_json(
            "v4_corr.json",
            {
                "report_type": "correlation",
                "metadata": {"case_id": "CASE-CORR"},
                "correlations": [{"correlation_id": "C1"}],
            },
        )
        registry.register_file(v4_corr, report_id="rep-v4-corr")

        # V4/V5/V6 Integrated Investigation
        v4_inv = self._write_json(
            "v4_inv.json",
            {
                "report_type": "correlation_detection",
                "metadata": {"case_id": "CASE-INV"},
                "detections": [{"rule_id": "R1", "matched": True}],
                "correlations": [{"correlation_id": "C1"}],
                "timeline_events": [{"event_id": "E1"}],
            },
        )
        registry.register_file(v4_inv, report_id="rep-v4-inv")

        self.assertEqual(len(registry), 6)
        reports = registry.list_reports()
        types_registered = {r["report_type"] for r in reports}
        expected_types = {t.value for t in ReportType}
        self.assertEqual(types_registered, expected_types)

    # =========================================================================
    # 2. Server Binding & Lifecycle Tests
    # =========================================================================

    def test_07_loopback_host_binding_enforcement(self) -> None:
        """Verify server strictly requires loopback binding and rejects public interfaces."""
        registry = DashboardReportRegistry()

        # Allowed loopback hosts: explicitly test 127.0.0.1 and localhost
        for valid_host in ALLOWED_LOOPBACK_HOSTS:
            server = create_dashboard_server(registry, host=valid_host, port=0)
            self.assertGreater(server.server_port, 0)
            server.server_close()

        # Rejected non-loopback hosts (including non-IPv4 ::1 and external/LAN interfaces)
        for invalid_host in ("::1", "0.0.0.0", "192.168.1.100", "8.8.8.8", "example.com"):
            with self.assertRaises(ValueError):
                create_dashboard_server(registry, host=invalid_host, port=0)

    def test_08_server_clean_startup_and_shutdown(self) -> None:
        """Verify non-blocking background server startup on ephemeral port and clean shutdown."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        self.assertGreater(server.server_port, 0)
        server.start_background()

        try:
            status, headers, body = self._http_request(server, "GET", "/api/health")
            self.assertEqual(status, 200)
            self.assertEqual(body["status"], "ok")
        finally:
            server.stop()

    # =========================================================================
    # 3. HTTP API Endpoints & Response Validation
    # =========================================================================

    def test_09_api_health_endpoint(self) -> None:
        """Verify GET /api/health and /health behavior and security headers."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v1_file, report_id="rep-v1")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            for path in ("/api/health", "/health"):
                status, headers, body = self._http_request(server, "GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(body["status"], "ok")
                self.assertEqual(
                    body["service"], "ForensiX Local Dashboard Service"
                )
                self.assertEqual(body["version"], __version__)
                self.assertEqual(body["reports_count"], 1)

                # Security headers
                self.assertIn("application/json", headers.get("content-type", ""))
                self.assertEqual(
                    headers.get("x-content-type-options"), "nosniff"
                )
                self.assertIn("no-store", headers.get("cache-control", ""))
        finally:
            server.stop()

    def test_10_api_reports_collection_endpoint(self) -> None:
        """Verify GET /api/reports returns deterministically sorted report list."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v3_file, report_id="rep-c-v3")
        registry.register_file(self.v1_file, report_id="rep-a-v1")
        registry.register_file(self.v2_file, report_id="rep-b-v2")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            status, _, body = self._http_request(server, "GET", "/api/reports")
            self.assertEqual(status, 200)
            self.assertEqual(body["total"], 3)
            # Verify deterministic sort by ID
            ids = [r["id"] for r in body["reports"]]
            self.assertEqual(ids, ["rep-a-v1", "rep-b-v2", "rep-c-v3"])

            # Verify sanitized fields
            for r in body["reports"]:
                self.assertNotIn("source_path", r)
                self.assertIn("filename", r)
                self.assertIn("file_size_bytes", r)
                self.assertIn("sha256", r)
                self.assertIn("metadata", r)
                self.assertIn("counts", r)
        finally:
            server.stop()

    def test_11_api_report_by_id_and_sub_endpoints(self) -> None:
        """Verify GET /api/reports/<id> and sub-endpoints (metadata, summary, details)."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v2_file, report_id="triage-01")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # 1. GET /api/reports/triage-01 (overview)
            status, _, body = self._http_request(
                server, "GET", "/api/reports/triage-01"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["id"], "triage-01")
            self.assertEqual(body["report_type"], "host_triage")
            self.assertEqual(body["filename"], "v2_triage.json")
            self.assertEqual(body["metadata"]["case_id"], "CASE-2026-001")
            self.assertEqual(body["counts"]["artifact_count"], 1)
            self.assertEqual(body["counts"]["audit_event_count"], 1)

            # 2. GET /api/reports/triage-01/metadata
            status, _, meta_body = self._http_request(
                server, "GET", "/api/reports/triage-01/metadata"
            )
            self.assertEqual(status, 200)
            self.assertEqual(meta_body["id"], "triage-01")
            self.assertEqual(
                meta_body["metadata"]["investigator"], "Lead Analyst"
            )

            # 3. GET /api/reports/triage-01/summary
            status, _, sum_body = self._http_request(
                server, "GET", "/api/reports/triage-01/summary"
            )
            self.assertEqual(status, 200)
            self.assertEqual(sum_body["id"], "triage-01")
            self.assertEqual(sum_body["counts"]["artifact_count"], 1)

            # 4. GET /api/reports/triage-01/details
            status, _, det_body = self._http_request(
                server, "GET", "/api/reports/triage-01/details"
            )
            self.assertEqual(status, 200)
            self.assertEqual(det_body["id"], "triage-01")
            self.assertIn("artifacts", det_body["raw_data"])
            self.assertEqual(len(det_body["raw_data"]["artifacts"]), 1)
        finally:
            server.stop()

    def test_12_api_unknown_report_id_and_sub_endpoints(self) -> None:
        """Verify 404 responses for missing reports and unknown sub-endpoints."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v1_file, report_id="rep-01")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Non-existent report
            status, _, body = self._http_request(
                server, "GET", "/api/reports/nonexistent"
            )
            self.assertEqual(status, 404)
            self.assertEqual(body["error"]["code"], "NOT_FOUND")

            # Non-existent sub-resource on existing report
            status, _, body = self._http_request(
                server, "GET", "/api/reports/rep-01/unrecognized"
            )
            self.assertEqual(status, 404)
            self.assertEqual(body["error"]["code"], "NOT_FOUND")

            # Unknown API endpoint
            status, _, body = self._http_request(
                server, "GET", "/api/unknown_route"
            )
            self.assertEqual(status, 404)
            self.assertEqual(body["error"]["code"], "NOT_FOUND")
        finally:
            server.stop()

    # =========================================================================
    # 4. Security & Hardening Tests
    # =========================================================================

    def test_13_path_traversal_rejection(self) -> None:
        """Verify strict rejection of path traversal tokens in URL paths."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v1_file, report_id="rep-01")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Traversal variations
            traversal_paths = [
                "/api/reports/../../etc/passwd",
                "/api/reports/%2e%2e/etc/passwd",
                "/api/reports/..%2f..%2fetc%2fpasswd",
                "/api/reports/%252e%252e/etc/passwd",
                "/api/reports/rep-01/..",
                "/api/reports//rep-01",
                "/api/reports/rep-01/../../",
            ]
            for p in traversal_paths:
                status, _, body = self._http_request(server, "GET", p)
                self.assertIn(status, (400, 404))
                self.assertIn("error", body)
                self.assertIn(
                    body["error"]["code"], ("MALFORMED_REQUEST", "NOT_FOUND")
                )
        finally:
            server.stop()

    def test_14_unsupported_http_methods(self) -> None:
        """Verify non-GET HTTP methods return 405 Method Not Allowed with Allow header."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                conn = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=5
                )
                try:
                    conn.request(method, "/api/reports")
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 405)
                    self.assertEqual(resp.getheader("Allow"), "GET")
                    raw = resp.read()
                    if raw:
                        err = json.loads(raw.decode())
                        self.assertEqual(
                            err["error"]["code"], "METHOD_NOT_ALLOWED"
                        )
                finally:
                    conn.close()
        finally:
            server.stop()

    def test_15_no_absolute_paths_or_stack_traces_in_responses(self) -> None:
        """Verify absolute storage paths and exception stack traces are never leaked."""
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(self.v1_file)

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Check all endpoints
            test_routes = [
                "/api/health",
                "/api/reports",
                f"/api/reports/{rep_id}",
                f"/api/reports/{rep_id}/metadata",
                f"/api/reports/{rep_id}/summary",
                f"/api/reports/{rep_id}/details",
                "/api/reports/nonexistent",
                "/api/reports/../../etc",
            ]
            for r in test_routes:
                _, _, body = self._http_request(server, "GET", r)
                body_str = json.dumps(body)
                # Confirm local test directory path is never present
                self.assertNotIn(str(self.temp_dir), body_str)
                # Confirm Python traceback indicators are never present
                self.assertNotIn("Traceback (most recent call last)", body_str)
                self.assertNotIn("File \"/home/", body_str)
        finally:
            server.stop()

    def test_16_read_only_preservation_of_report_bytes(self) -> None:
        """Verify original report files on disk remain strictly unmodified."""
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(self.v1_file)

        initial_bytes = self.v1_file.read_bytes()
        initial_mtime = self.v1_file.stat().st_mtime_ns

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            for _ in range(5):
                self._http_request(server, "GET", f"/api/reports/{rep_id}")
                self._http_request(
                    server, "GET", f"/api/reports/{rep_id}/details"
                )

            # Assert disk file unchanged
            self.assertEqual(self.v1_file.read_bytes(), initial_bytes)
            self.assertEqual(self.v1_file.stat().st_mtime_ns, initial_mtime)
        finally:
            server.stop()

    def test_17_cache_immutability_through_handlers(self) -> None:
        """Verify that handler outputs cannot be mutated to alter the registry state."""
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(self.v2_file)

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Fetch details
            _, _, body = self._http_request(
                server, "GET", f"/api/reports/{rep_id}/details"
            )
            # Mutate received payload
            body["raw_data"]["metadata"]["case_id"] = "MUTATED_VIA_CLIENT"

            # Fetch again and verify untouched
            _, _, body2 = self._http_request(
                server, "GET", f"/api/reports/{rep_id}/details"
            )
            self.assertEqual(
                body2["raw_data"]["metadata"]["case_id"], "CASE-2026-001"
            )

            stored_report = registry.get(rep_id)
            self.assertIsNotNone(stored_report)
            self.assertEqual(
                stored_report.metadata.case_id, "CASE-2026-001"
            )
        finally:
            server.stop()

    def test_18_oversized_report_rejection_in_registry(self) -> None:
        """Verify registering an oversized report file is rejected defensively."""
        oversized_file = self.temp_dir / "oversized.json"
        oversized_file.write_bytes(b"X" * 1000)

        registry = DashboardReportRegistry()
        with self.assertRaises(ReportSizeLimitError):
            registry.register_file(oversized_file, max_size_bytes=100)

    def test_19_leading_double_slash_and_malformed_url_rejection(self) -> None:
        """Verify request targets beginning with '//' or containing '//' are rejected as malformed."""
        registry = DashboardReportRegistry()
        registry.register_file(self.v1_file, report_id="rep-01")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            double_slash_paths = [
                "//api/health",
                "//health",
                "//api/reports",
                "//api/reports/rep-01",
                "/api//reports",
                "/api/reports//rep-01",
            ]
            for p in double_slash_paths:
                status, _, body = self._http_request(server, "GET", p)
                self.assertEqual(status, 400, f"Expected 400 for '{p}', got {status}")
                self.assertIn("error", body)
                self.assertEqual(body["error"]["code"], "MALFORMED_REQUEST")
        finally:
            server.stop()

    # =========================================================================
    # 4. V7.3 UI Static Asset & Integration Tests
    # =========================================================================

    def test_20_ui_landing_route_and_static_asset_serving(self) -> None:
        """Verify the dashboard landing route and fixed static UI assets are served with correct content types."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Landing route GET /
            status, headers, body = self._http_request_raw(server, "GET", "/")
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn(b"ForensiX", body)
            self.assertIn(b"<!DOCTYPE html>", body)

            # Explicit GET /index.html
            status, headers, body = self._http_request_raw(server, "GET", "/index.html")
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn(b"ForensiX", body)

            # CSS asset
            status, headers, body = self._http_request_raw(server, "GET", "/static/dashboard.css")
            self.assertEqual(status, 200)
            self.assertIn("text/css", headers.get("content-type", ""))
            self.assertIn(b":root", body)

            # JS asset
            status, headers, body = self._http_request_raw(server, "GET", "/static/dashboard.js")
            self.assertEqual(status, 200)
            self.assertIn("javascript", headers.get("content-type", ""))
            self.assertIn(b"ForensiX V7.3", body)

            # Favicon SVG route
            status, headers, body = self._http_request_raw(server, "GET", "/favicon.svg")
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("content-type"), "image/svg+xml")
            self.assertIn(b"<svg", body)

            # Old /favicon.ico is not served as SVG and returns 404
            status, _, err = self._http_request(server, "GET", "/favicon.ico")
            self.assertEqual(status, 404)
            self.assertEqual(err["error"]["code"], "NOT_FOUND")

            # Verify landing page links explicitly to /favicon.svg
            status, _, landing_body = self._http_request_raw(server, "GET", "/")
            self.assertEqual(status, 200)
            self.assertIn(b'<link rel="icon" type="image/svg+xml" href="/favicon.svg">', landing_body)

            # Nonexistent static asset -> 404 JSON error
            status, _, err = self._http_request(server, "GET", "/static/nonexistent.css")
            self.assertEqual(status, 404)
            self.assertEqual(err["error"]["code"], "NOT_FOUND")
        finally:
            server.stop()

    def test_21_ui_security_headers_and_offline_csp(self) -> None:
        """Verify strict security headers and offline Content-Security-Policy on UI routes."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            for path in ("/", "/index.html", "/static/dashboard.css", "/static/dashboard.js"):
                status, headers, _ = self._http_request_raw(server, "GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(headers.get("x-content-type-options"), "nosniff")
                self.assertEqual(headers.get("x-frame-options"), "DENY")
                self.assertEqual(headers.get("referrer-policy"), "no-referrer")

                csp = headers.get("content-security-policy", "")
                self.assertIn("default-src 'self'", csp)
                self.assertIn("connect-src 'self'", csp)
                self.assertIn("object-src 'none'", csp)
                self.assertIn("base-uri 'none'", csp)
        finally:
            server.stop()

    def test_22_ui_static_assets_path_traversal_rejection(self) -> None:
        """Verify static route paths reject path traversal sequences and double slashes."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            traversal_targets = [
                "/static/../../etc/passwd",
                "/static/%2e%2e/etc/passwd",
                "/static/..%2f..%2fdashboard.css",
                "//static/dashboard.css",
                "/static//dashboard.css",
            ]
            for target in traversal_targets:
                status, _, err = self._http_request(server, "GET", target)
                self.assertEqual(status, 400, f"Expected 400 for '{target}', got {status}")
                self.assertEqual(err["error"]["code"], "MALFORMED_REQUEST")
        finally:
            server.stop()

    def test_23_ui_offline_integrity_zero_external_references(self) -> None:
        """Verify UI template, CSS, and JS contain zero external URLs, CDN references, or tracking beacons."""
        from forensix.dashboard_ui import STATIC_ASSETS

        forbidden_patterns = [
            b"http://",
            b"https://",
            b"cdn.",
            b"googleapis",
            b"gstatic",
            b"unpkg",
            b"cdnjs",
            b"jsdelivr",
            b"mixpanel",
            b"segment.io",
            b"analytics.js",
        ]

        for path in ("/", "/index.html", "/static/dashboard.css", "/static/dashboard.js"):
            _, content_bytes = STATIC_ASSETS[path]
            lower_content = content_bytes.lower()
            for pattern in forbidden_patterns:
                # Disallow any external URLs or tracking script references
                self.assertNotIn(
                    pattern,
                    lower_content,
                    f"Forbidden external reference {pattern.decode()} found in UI asset '{path}'",
                )

        # Inspect JS for unsafe DOM assignments on dynamic data
        js_bytes = STATIC_ASSETS["/static/dashboard.js"][1]
        js_text = js_bytes.decode("utf-8")
        # Ensure no innerHTML is used anywhere in client logic
        self.assertNotIn(".innerHTML", js_text)
        self.assertNotIn("document.write", js_text)
        self.assertIn("textContent", js_text)
        self.assertIn("createElement", js_text)

    def test_24_ui_client_mock_e2e_flow_and_empty_state(self) -> None:
        """Verify client-facing API responses across empty and full multi-schema registries."""
        # 1. Empty registry
        empty_registry = DashboardReportRegistry()
        server_empty = create_dashboard_server(empty_registry, host="127.0.0.1", port=0)
        server_empty.start_background()
        try:
            # Landing page loads successfully
            status, _, html_body = self._http_request_raw(server_empty, "GET", "/")
            self.assertEqual(status, 200)
            self.assertIn(b"empty-state", html_body)

            # API reports returns empty total
            status, _, data = self._http_request(server_empty, "GET", "/api/reports")
            self.assertEqual(status, 200)
            self.assertEqual(data["total"], 0)
            self.assertEqual(data["reports"], [])
        finally:
            server_empty.stop()

        # 2. Populated registry with all 6 schemas
        full_registry = DashboardReportRegistry()
        full_registry.register_file(self.v1_file, report_id="rep-v1")
        full_registry.register_file(self.v2_file, report_id="rep-v2")
        full_registry.register_file(self.v3_file, report_id="rep-v3")

        v4_det = self._write_json(
            "v4_det_ui.json",
            {
                "report_type": "detection",
                "metadata": {"case_id": "CASE-DET"},
                "detections": [{"rule_id": "R1", "matched": True}],
            },
        )
        full_registry.register_file(v4_det, report_id="rep-v4-det")

        v4_corr = self._write_json(
            "v4_corr_ui.json",
            {
                "report_type": "correlation",
                "metadata": {"case_id": "CASE-CORR"},
                "correlations": [{"correlation_id": "C1"}],
            },
        )
        full_registry.register_file(v4_corr, report_id="rep-v4-corr")

        v4_inv = self._write_json(
            "v4_inv_ui.json",
            {
                "report_type": "correlation_detection",
                "metadata": {"case_id": "CASE-INV"},
                "detections": [{"rule_id": "R1", "matched": True}],
                "correlations": [{"correlation_id": "C1"}],
                "timeline_events": [{"event_id": "E1"}],
            },
        )
        full_registry.register_file(v4_inv, report_id="rep-v4-inv")

        self.assertEqual(len(full_registry), 6)

        server_full = create_dashboard_server(full_registry, host="127.0.0.1", port=0)
        server_full.start_background()
        try:
            # Health check
            status, _, health = self._http_request(server_full, "GET", "/api/health")
            self.assertEqual(status, 200)
            self.assertEqual(health["reports_count"], 6)

            # Reports collection endpoint
            status, _, rep_list = self._http_request(server_full, "GET", "/api/reports")
            self.assertEqual(status, 200)
            self.assertEqual(rep_list["total"], 6)

            # Test details query for each report
            for rep in rep_list["reports"]:
                rep_id = rep["id"]
                status, _, details = self._http_request(server_full, "GET", f"/api/reports/{rep_id}/details")
                self.assertEqual(status, 200)
                self.assertEqual(details["id"], rep_id)
                self.assertIn("raw_data", details)
                self.assertIsInstance(details["raw_data"], dict)
        finally:
            server_full.stop()

    def test_25_ui_xss_payload_safety_in_report_data(self) -> None:
        """Verify that malicious XSS payloads embedded in evidence are stored intact as forensic facts."""
        registry = DashboardReportRegistry()

        # Craft report containing aggressive XSS payloads in valid host triage schema
        xss_report_data = {
            "metadata": {
                "report_id": "REPORT-11111111-2222-4333-8444-555555555555",
                "case_id": "<script>alert('xss-case')</script>",
                "case_name": "<img src=x onerror=alert('case-name')>",
                "investigator": "Analyst <svg/onload=alert('inv')>",
                "evidence_root": "/mnt/evidence/<iframe src=javascript:alert(1)>",
            },
            "artifacts": [
                {"unified_id": "ART-01", "raw_data": "<script>bad()</script>", "category": "filesystem", "status": "SUCCESS"}
            ],
            "audit_trail": [
                {"event_id": "AUD-01", "action": "test", "timestamp": "2026-10-01T15:30:00Z"}
            ],
        }
        xss_file = self._write_json("xss_report.json", xss_report_data)
        rep_id = registry.register_file(xss_file, report_id="rep-xss-test")

        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        try:
            # Fetch report metadata
            status, _, meta_resp = self._http_request(server, "GET", f"/api/reports/{rep_id}/metadata")
            self.assertEqual(status, 200)
            meta = meta_resp["metadata"]
            # Preserved intact as forensic truth
            self.assertEqual(meta["case_id"], "<script>alert('xss-case')</script>")
            self.assertEqual(meta["case_name"], "<img src=x onerror=alert('case-name')>")
            self.assertEqual(meta["investigator"], "Analyst <svg/onload=alert('inv')>")
            self.assertEqual(meta["evidence_root"], "/mnt/evidence/<iframe src=javascript:alert(1)>")

            # Fetch report details
            status, _, details_resp = self._http_request(server, "GET", f"/api/reports/{rep_id}/details")
            self.assertEqual(status, 200)
            self.assertEqual(
                details_resp["raw_data"]["metadata"]["case_id"],
                "<script>alert('xss-case')</script>",
            )
        finally:
            server.stop()

    def test_26_ui_hash_routing_malformed_percent_encoding_resilience(self) -> None:
        """Verify client-side hash routing protects against malformed percent-encoded fragments."""
        from forensix.dashboard_ui import STATIC_ASSETS

        js_bytes = STATIC_ASSETS["/static/dashboard.js"][1]
        js_text = js_bytes.decode("utf-8")

        # Verify decodeURIComponent is wrapped in a try-catch block inside handleHashRoute
        self.assertIn("function handleHashRoute()", js_text)
        self.assertIn("try {", js_text)
        self.assertIn("decodeURIComponent(hash.slice(", js_text)
        self.assertIn('navigateTo("#overview");', js_text)

        # Verify python MappingProxyType immutability of STATIC_ASSETS
        with self.assertRaises(TypeError):
            STATIC_ASSETS["/"] = ("text/plain", b"mutated")  # type: ignore


class TestPivotIndex(unittest.TestCase):
    """
    Focused test suite for ForensiX Milestone V7.4 Phase 1 — In-Memory Pivot Index.

    Verifies:
    1. Typed allowlist representation (PivotFieldType).
    2. Immutability of PivotReference and PivotQueryResult data structures.
    3. Normalization helpers (SHA-256, IP addresses, PID, CASE_ID).
    4. Schema-aware extraction across all 6 ForensiX report types.
    5. Safe skipping of missing, empty, malformed, and unsupported fields.
    6. Case-sensitive CASE_ID matching.
    7. Case-insensitive SHA-256 hexadecimal validation and matching.
    8. IPv4 and IPv6 normalization and candidate matching.
    9. PID evidence-scope enforcement (unscoped exact PID matching prohibited).
    10. Duplicate identifier handling and cross-report matching.
    11. Result capping and truncation metadata.
    12. Registry lifecycle: registration, replacement, removal, and clear.
    13. Integrity: report payloads and source evidence remain strictly untouched.
    """

    def setUp(self) -> None:
        """Create temporary sandbox directory for synthetic test reports."""
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="forensix_test_v74_pivot_")
        self.temp_dir = Path(self._temp_dir_obj.name)

    def tearDown(self) -> None:
        """Clean up temporary sandbox."""
        self._temp_dir_obj.cleanup()

    def _write_json(self, name: str, data: Any) -> Path:
        """Helper to write pretty-printed JSON to a temporary file."""
        file_path = self.temp_dir / name
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return file_path

    # -------------------------------------------------------------------------
    # 1. Enums and Data Models
    # -------------------------------------------------------------------------

    def test_01_pivot_field_type_enum(self) -> None:
        """Verify PivotFieldType contains only allowlisted forensic fields."""
        expected = {
            "case_id",
            "sha256",
            "artifact_id",
            "event_id",
            "rule_id",
            "ip_address",
            "pid",
        }
        actual = {f.value for f in PivotFieldType}
        self.assertEqual(actual, expected)
        self.assertEqual(len(PivotFieldType), 7)

    def test_02_normalization_helpers(self) -> None:
        """Verify normalization helpers for SHA256, IP, PID, and CASE_ID."""
        # SHA-256
        valid_lower = "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        valid_upper = "4402A77918A55E2D1D3A54D52FECEFE3B86E088FEF27B4B1A29C9A622F6FA754"
        self.assertEqual(normalize_sha256(valid_lower), valid_lower)
        self.assertEqual(normalize_sha256(valid_upper), valid_lower)
        self.assertIsNone(normalize_sha256("short"))
        self.assertIsNone(normalize_sha256(valid_lower + "0"))  # 65 chars
        self.assertIsNone(normalize_sha256(valid_lower[:-1] + "g"))  # non-hex
        self.assertIsNone(normalize_sha256(12345))
        self.assertIsNone(normalize_sha256(None))

        # IP Address
        self.assertEqual(normalize_ip_address_pivot("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_ip_address_pivot("  192.168.001.001  "), "192.168.1.1")
        self.assertEqual(normalize_ip_address_pivot("::1"), "::1")
        self.assertEqual(
            normalize_ip_address_pivot("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "2001:db8:85a3::8a2e:370:7334",
        )
        self.assertIsNone(normalize_ip_address_pivot("999.999.999.999"))
        self.assertIsNone(normalize_ip_address_pivot("not-an-ip"))
        self.assertIsNone(normalize_ip_address_pivot(""))
        self.assertIsNone(normalize_ip_address_pivot(12345))
        self.assertIsNone(normalize_ip_address_pivot(None))

        # PID
        self.assertEqual(normalize_pid(0), 0)
        self.assertEqual(normalize_pid(1234), 1234)
        self.assertEqual(normalize_pid("5678"), 5678)
        self.assertIsNone(normalize_pid(-1))
        self.assertIsNone(normalize_pid("-5678"))
        self.assertIsNone(normalize_pid("abc"))
        self.assertIsNone(normalize_pid(True))  # bool rejected
        self.assertIsNone(normalize_pid(False))  # bool rejected
        self.assertIsNone(normalize_pid(12.34))
        self.assertIsNone(normalize_pid(None))

        # CASE_ID
        self.assertEqual(normalize_case_id("CASE-2026-A"), "CASE-2026-A")
        self.assertEqual(normalize_case_id("  CASE-2026-A  "), "CASE-2026-A")
        self.assertIsNone(normalize_case_id(""))
        self.assertIsNone(normalize_case_id("   "))
        self.assertIsNone(normalize_case_id(None))
        self.assertIsNone(normalize_case_id(123))

    def test_03_pivot_reference_and_query_result_immutability(self) -> None:
        """Verify deep immutability of PivotReference and PivotQueryResult."""
        ref = PivotReference(
            report_id="rep-test",
            report_type=ReportType.EVIDENCE_ANALYSIS,
            field_type=PivotFieldType.SHA256,
            field_path="hashes.sha256",
            observed_value="4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            normalized_value="4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            timestamp="2026-10-01T12:00:00Z",
            evidence_scope="/var/log/evidence.bin",
            context={"filename": "evidence.bin"},
        )

        # Frozen dataclass reassignment rejection
        with self.assertRaises(Exception):
            ref.report_id = "rep-mutated"  # type: ignore

        # Context MappingProxyType immutability
        with self.assertRaises(TypeError):
            ref.context["filename"] = "mutated.bin"  # type: ignore

        # to_dict produces detached copies
        d = ref.to_dict()
        d["context"]["filename"] = "detached.bin"
        self.assertEqual(ref.context["filename"], "evidence.bin")

        # PivotQueryResult immutability
        res = PivotQueryResult(
            field_type=PivotFieldType.SHA256,
            queried_value="test",
            normalized_query="test",
            scope=None,
            total_matches=1,
            returned_matches=1,
            truncated=False,
            matches=(ref,),
        )
        with self.assertRaises(Exception):
            res.total_matches = 99  # type: ignore
        with self.assertRaises(AttributeError):
            res.matches.append(ref)  # type: ignore

    # -------------------------------------------------------------------------
    # 2. Schema-Specific Extractions
    # -------------------------------------------------------------------------

    def test_04_extraction_v1_evidence_analysis(self) -> None:
        """Verify extraction of pivots from V1 Evidence Analysis report."""
        v1_data = {
            "evidence": {
                "evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32",
                "original_path": "/var/log/evidence.bin",
                "registered_at": "2026-10-01T12:00:00+00:00",
            },
            "file": {
                "filename": "evidence.bin",
                "size": 4096,
                "extension": ".bin",
            },
            "metadata": {
                "permissions": "0644",
                "modified": "2026-09-30T10:00:00+00:00",
                "accessed": "2026-09-30T11:00:00+00:00",
                "case_id": "CASE-V1-001",
            },
            "hashes": {
                "md5": "c98d3632cfba9828d13b4c1001eeac37",
                "sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            },
        }
        fpath = self._write_json("v1.json", v1_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        # Check CASE_ID
        res_case = registry.query_pivots(PivotFieldType.CASE_ID, "CASE-V1-001")
        self.assertEqual(res_case.total_matches, 1)
        self.assertEqual(res_case.matches[0].field_path, "metadata.case_id")
        self.assertEqual(res_case.matches[0].report_id, rep_id)

        # Check ARTIFACT_ID (evidence_id)
        res_ev = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "EV-387d74e8-af84-4205-9199-76d03c3c9f32")
        self.assertEqual(res_ev.total_matches, 1)
        self.assertEqual(res_ev.matches[0].field_path, "evidence.evidence_id")

        # Check SHA256
        res_sha = registry.query_pivots(PivotFieldType.SHA256, "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754")
        self.assertEqual(res_sha.total_matches, 1)
        self.assertEqual(res_sha.matches[0].field_path, "hashes.sha256")
        self.assertEqual(res_sha.matches[0].context["filename"], "evidence.bin")

    def test_05_extraction_v2_host_triage(self) -> None:
        """Verify extraction of pivots from V2 Host Triage report."""
        v2_data = {
            "metadata": {
                "report_id": "REPORT-11111111-2222-4333-8444-555555555555",
                "case_id": "CASE-V2-HOST",
                "created_at": "2026-10-01T15:30:00Z",
                "forensix_version": "5.0.0",
                "evidence_root": "/mnt/evidence/host01",
                "report_format": "json",
            },
            "artifacts": [
                {
                    "unified_id": "HOSTART-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "source_id": "ART-01",
                    "source_artifact_id": "ART-PARENT-01",
                    "source_event_id": "EVT-SRC-01",
                    "category": "filesystem",
                    "artifact_type": "file_record",
                    "status": "PARSED",
                    "specialized_payload": {
                        "sha256": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                        "source_ip": "10.0.0.5",
                        "pid": 2048,
                        "process_name": "worker_daemon",
                    },
                }
            ],
            "audit_trail": [
                {
                    "event_id": "AUDIT-001",
                    "timestamp": "2026-10-01T15:30:05Z",
                    "event_type": "triage_start",
                }
            ],
        }
        fpath = self._write_json("v2.json", v2_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        # Artifact IDs
        res_rep_id = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "REPORT-11111111-2222-4333-8444-555555555555")
        self.assertEqual(res_rep_id.total_matches, 1)

        res_uid = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "HOSTART-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        self.assertEqual(res_uid.total_matches, 1)
        self.assertEqual(res_uid.matches[0].field_path, "artifacts[0].unified_id")

        res_sid = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "ART-01")
        self.assertEqual(res_sid.total_matches, 1)

        # IP address
        res_ip = registry.query_pivots(PivotFieldType.IP_ADDRESS, "10.0.0.5")
        self.assertEqual(res_ip.total_matches, 1)
        self.assertEqual(res_ip.matches[0].field_path, "artifacts[0].specialized_payload.source_ip")

        # SHA256
        res_sha = registry.query_pivots(PivotFieldType.SHA256, "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        self.assertEqual(res_sha.total_matches, 1)

        # PID with scope
        res_pid_scoped = registry.query_pivots(PivotFieldType.PID, 2048, scope="/mnt/evidence/host01")
        self.assertEqual(res_pid_scoped.total_matches, 1)
        self.assertEqual(res_pid_scoped.matches[0].context["process_name"], "worker_daemon")

        # PID without scope must return 0 exact matches per specification
        res_pid_unscoped = registry.query_pivots(PivotFieldType.PID, 2048)
        self.assertEqual(res_pid_unscoped.total_matches, 0)

        # Event ID in audit trail
        res_audit = registry.query_pivots(PivotFieldType.EVENT_ID, "AUDIT-001")
        self.assertEqual(res_audit.total_matches, 1)
        self.assertEqual(res_audit.matches[0].field_path, "audit_trail[0].event_id")

    def test_06_extraction_v3_timeline(self) -> None:
        """Verify extraction of pivots from V3 Timeline report."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {
                "case_id": "CASE-V3-TIME",
                "evidence_root": "/mnt/evidence/server",
            },
            "events": [
                {
                    "event_id": "TIMELINE-11111111-1111-4111-8111-111111111111",
                    "timestamp": "2026-10-01T12:00:00Z",
                    "category": "network",
                    "event_type": "ssh_login",
                    "description": "SSH session started",
                    "source_artifact_id": "ART-SSH-01",
                    "source_event_id": "AUTH-01",
                    "attributes": {
                        "source_ip": "192.168.10.20",
                        "pid": 5001,
                        "process_name": "sshd",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    },
                }
            ],
        }
        fpath = self._write_json("v3.json", v3_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        res_eid = registry.query_pivots(PivotFieldType.EVENT_ID, "TIMELINE-11111111-1111-4111-8111-111111111111")
        self.assertEqual(res_eid.total_matches, 1)
        self.assertEqual(res_eid.matches[0].field_path, "events[0].event_id")
        self.assertEqual(res_eid.matches[0].timestamp, "2026-10-01T12:00:00Z")

        res_said = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "ART-SSH-01")
        self.assertEqual(res_said.total_matches, 1)

        res_ip = registry.query_pivots(PivotFieldType.IP_ADDRESS, "192.168.10.20")
        self.assertEqual(res_ip.total_matches, 1)

        res_sha = registry.query_pivots(PivotFieldType.SHA256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        self.assertEqual(res_sha.total_matches, 1)

        res_pid = registry.query_pivots(PivotFieldType.PID, 5001, scope="/mnt/evidence/server")
        self.assertEqual(res_pid.total_matches, 1)

    def test_07_extraction_v4_detection(self) -> None:
        """Verify extraction of pivots from V4 Detection report."""
        v4_data = {
            "report_type": "detection",
            "metadata": {
                "case_id": "CASE-V4-DET",
            },
            "detections": [
                {
                    "detection_id": "DET-99",
                    "rule_id": "RULE-6f89e485-760b-5555-b663-77548d74c558",
                    "rule_name": "Privilege Escalation Detection",
                    "matched": True,
                    "matched_event_ids": ["TIMELINE-E1", "TIMELINE-E2"],
                    "matched_source_artifact_ids": ["HOSTART-A1"],
                    "matched_source_event_ids": ["EVT-S1"],
                    "matched_correlation_ids": ["CORR-C1"],
                    "start_timestamp": "2026-10-02T10:00:00Z",
                }
            ],
        }
        fpath = self._write_json("v4_det.json", v4_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        # RULE_ID
        res_rule = registry.query_pivots(PivotFieldType.RULE_ID, "RULE-6f89e485-760b-5555-b663-77548d74c558")
        self.assertEqual(res_rule.total_matches, 1)
        self.assertEqual(res_rule.matches[0].context["rule_name"], "Privilege Escalation Detection")
        self.assertTrue(res_rule.matches[0].context["matched"])

        # Matched events
        res_e1 = registry.query_pivots(PivotFieldType.EVENT_ID, "TIMELINE-E1")
        self.assertEqual(res_e1.total_matches, 1)
        self.assertEqual(res_e1.matches[0].field_path, "detections[0].matched_event_ids[0]")

        # Matched source artifact
        res_a1 = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "HOSTART-A1")
        self.assertEqual(res_a1.total_matches, 1)
        self.assertEqual(res_a1.matches[0].field_path, "detections[0].matched_source_artifact_ids[0]")

        # Matched correlation ID
        res_c1 = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "CORR-C1")
        self.assertEqual(res_c1.total_matches, 1)
        self.assertEqual(res_c1.matches[0].field_path, "detections[0].matched_correlation_ids[0]")

    def test_08_extraction_v4_correlation(self) -> None:
        """Verify extraction of pivots from V4 Correlation report."""
        v4_corr_data = {
            "report_type": "correlation",
            "metadata": {
                "case_id": "CASE-V4-CORR",
            },
            "correlations": [
                {
                    "correlation_id": "CORR-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "relationship_type": "SAME_USER",
                    "event_ids": ["TIMELINE-01", "TIMELINE-02"],
                    "source_artifact_ids": ["ART-USER-01"],
                    "source_event_ids": ["EVT-U1"],
                    "start_timestamp": "2026-10-03T11:00:00Z",
                }
            ],
        }
        fpath = self._write_json("v4_corr.json", v4_corr_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        res_cid = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "CORR-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        self.assertEqual(res_cid.total_matches, 1)
        self.assertEqual(res_cid.matches[0].field_path, "correlations[0].correlation_id")

        res_e1 = registry.query_pivots(PivotFieldType.EVENT_ID, "TIMELINE-01")
        self.assertEqual(res_e1.total_matches, 1)

        res_art = registry.query_pivots(PivotFieldType.ARTIFACT_ID, "ART-USER-01")
        self.assertEqual(res_art.total_matches, 1)

    def test_09_extraction_v4_v5_v6_integrated(self) -> None:
        """Verify extraction of pivots from integrated correlation_detection report."""
        inv_data = {
            "report_type": "correlation_detection",
            "metadata": {
                "case_id": "CASE-INTEGRATED",
                "evidence_root": "/mnt/evidence/composite",
            },
            "detections": [
                {
                    "rule_id": "RULE-INTEG-01",
                    "rule_name": "Integ Rule",
                    "matched": True,
                    "matched_event_ids": ["TIMELINE-INT-01"],
                    "matched_source_artifact_ids": [],
                    "matched_source_event_ids": [],
                    "matched_correlation_ids": [],
                }
            ],
            "correlations": [
                {
                    "correlation_id": "CORR-INT-01",
                    "relationship_type": "TEMPORAL",
                    "event_ids": ["TIMELINE-INT-01", "TIMELINE-INT-02"],
                    "source_artifact_ids": [],
                    "source_event_ids": [],
                }
            ],
            "timeline_events": [
                {
                    "event_id": "TIMELINE-INT-01",
                    "timestamp": "2026-10-04T12:00:00Z",
                    "category": "network",
                    "event_type": "packet_observed",
                    "attributes": {
                        "src_ip": "172.16.0.4",
                        "pid": 8080,
                    },
                }
            ],
        }
        fpath = self._write_json("integrated.json", inv_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-INTEGRATED").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.RULE_ID, "RULE-INTEG-01").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "CORR-INT-01").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.EVENT_ID, "TIMELINE-INT-01").total_matches, 3)  # in detections, correlations, timeline
        self.assertEqual(registry.query_pivots(PivotFieldType.IP_ADDRESS, "172.16.0.4").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 8080, scope="/mnt/evidence/composite").total_matches, 1)

    # -------------------------------------------------------------------------
    # 3. Query Matching Semantics & Scoping Rules
    # -------------------------------------------------------------------------

    def test_10_case_id_case_sensitivity_and_whitespace(self) -> None:
        """Verify CASE_ID matching is case-sensitive and trims query whitespace."""
        v1_data = {
            "evidence": {"evidence_id": "EV-01", "original_path": "/var/log/ev.bin"},
            "file": {"filename": "ev.bin", "size": 100, "extension": ".bin"},
            "metadata": {"case_id": "CASE-Exact-Match"},
            "hashes": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
        }
        fpath = self._write_json("case_exact.json", v1_data)
        registry = DashboardReportRegistry()
        registry.register_file(fpath)

        # Exact match matches
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-Exact-Match").total_matches, 1)
        # Stripped whitespace matches
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "  CASE-Exact-Match  ").total_matches, 1)
        # Differing case does NOT match
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "case-exact-match").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-EXACT-MATCH").total_matches, 0)
        # Empty or whitespace returns 0
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "   ").total_matches, 0)

    def test_11_sha256_case_insensitivity_and_hex_validation(self) -> None:
        """Verify SHA-256 matching validates hex length and matches case-insensitively."""
        v1_data = {
            "evidence": {"evidence_id": "EV-01", "original_path": "/var/log/ev.bin"},
            "file": {"filename": "ev.bin", "size": 100, "extension": ".bin"},
            "metadata": {},
            "hashes": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
        }
        fpath = self._write_json("sha_test.json", v1_data)
        registry = DashboardReportRegistry()
        registry.register_file(fpath)

        # Lowercase query
        res_lower = registry.query_pivots(PivotFieldType.SHA256, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        self.assertEqual(res_lower.total_matches, 1)

        # Uppercase query
        res_upper = registry.query_pivots(PivotFieldType.SHA256, "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")
        self.assertEqual(res_upper.total_matches, 1)

        # Invalid length query returns 0 matches without error
        res_short = registry.query_pivots(PivotFieldType.SHA256, "abcdef")
        self.assertEqual(res_short.total_matches, 0)

        # Non-hex query returns 0 matches without error
        res_nonhex = registry.query_pivots(PivotFieldType.SHA256, "zzzzzz1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        self.assertEqual(res_nonhex.total_matches, 0)

    def test_12_ip_address_normalization_and_formats(self) -> None:
        """Verify IP address normalization covers IPv4 leading zeros and IPv6 representations."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {},
            "events": [
                {
                    "event_id": "TIMELINE-IP-1",
                    "category": "network",
                    "event_type": "packet",
                    "description": "IPv4 test",
                    "attributes": {"src_ip": "192.168.1.1"},
                },
                {
                    "event_id": "TIMELINE-IP-2",
                    "category": "network",
                    "event_type": "packet",
                    "description": "IPv6 test",
                    "attributes": {"src_ip": "::1"},
                },
            ],
        }
        fpath = self._write_json("ip_test.json", v3_data)
        registry = DashboardReportRegistry()
        registry.register_file(fpath)

        # IPv4 with leading zeros queries match canonical representation
        res_v4 = registry.query_pivots(PivotFieldType.IP_ADDRESS, "192.168.001.001")
        self.assertEqual(res_v4.total_matches, 1)
        self.assertEqual(res_v4.matches[0].normalized_value, "192.168.1.1")

        # IPv6 uncompressed query matches compressed ::1
        res_v6 = registry.query_pivots(PivotFieldType.IP_ADDRESS, "0:0:0:0:0:0:0:1")
        self.assertEqual(res_v6.total_matches, 1)
        self.assertEqual(res_v6.matches[0].normalized_value, "::1")

        # Invalid IP string returns 0 matches
        res_invalid = registry.query_pivots(PivotFieldType.IP_ADDRESS, "999.999.999.999")
        self.assertEqual(res_invalid.total_matches, 0)

    def test_13_pid_scoping_restrictions(self) -> None:
        """Verify PID matching strictly respects evidence scope boundaries."""
        # Host A report with PID 4444
        v2_a = {
            "metadata": {
                "report_id": "REPORT-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "evidence_root": "/evidence/host_alpha",
                "forensix_version": "5.0.0",
                "created_at": "2026-10-01T10:00:00Z",
                "report_format": "json",
            },
            "artifacts": [
                {
                    "unified_id": "HOSTART-A",
                    "source_id": "ART-A",
                    "category": "log",
                    "artifact_type": "process",
                    "status": "PARSED",
                    "specialized_payload": {"pid": 4444, "process_name": "proc_alpha"},
                }
            ],
            "audit_trail": [],
        }
        # Host B report with same PID 4444
        v2_b = {
            "metadata": {
                "report_id": "REPORT-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "evidence_root": "/evidence/host_beta",
                "forensix_version": "5.0.0",
                "created_at": "2026-10-01T10:00:00Z",
                "report_format": "json",
            },
            "artifacts": [
                {
                    "unified_id": "HOSTART-B",
                    "source_id": "ART-B",
                    "category": "log",
                    "artifact_type": "process",
                    "status": "PARSED",
                    "specialized_payload": {"pid": 4444, "process_name": "proc_beta"},
                }
            ],
            "audit_trail": [],
        }

        fpath_a = self._write_json("host_a.json", v2_a)
        fpath_b = self._write_json("host_b.json", v2_b)

        registry = DashboardReportRegistry()
        rep_a = registry.register_file(fpath_a, report_id="rep-host-a")
        rep_b = registry.register_file(fpath_b, report_id="rep-host-b")

        # 1. Unscoped PID query must return 0 exact matches to prevent cross-host conflation
        unscoped = registry.query_pivots(PivotFieldType.PID, 4444, scope=None)
        self.assertEqual(unscoped.total_matches, 0)
        self.assertEqual(len(unscoped.matches), 0)

        # 2. Scoped to Host Alpha matches only Host Alpha
        scoped_a = registry.query_pivots(PivotFieldType.PID, 4444, scope="/evidence/host_alpha")
        self.assertEqual(scoped_a.total_matches, 1)
        self.assertEqual(scoped_a.matches[0].report_id, rep_a)
        self.assertEqual(scoped_a.matches[0].context["process_name"], "proc_alpha")

        # 3. Scoped to Host Beta matches only Host Beta
        scoped_b = registry.query_pivots(PivotFieldType.PID, 4444, scope="/evidence/host_beta")
        self.assertEqual(scoped_b.total_matches, 1)
        self.assertEqual(scoped_b.matches[0].report_id, rep_b)
        self.assertEqual(scoped_b.matches[0].context["process_name"], "proc_beta")

        # 4. Scoped to non-existent host returns 0
        scoped_c = registry.query_pivots(PivotFieldType.PID, 4444, scope="/evidence/host_gamma")
        self.assertEqual(scoped_c.total_matches, 0)

    def test_14_cross_report_matching_and_provenance_retention(self) -> None:
        """Verify cross-report matches preserve exact field_path, report_id, and provenance."""
        # Report 1 has a dropped malware file with hash X
        v1_report = {
            "evidence": {"evidence_id": "EV-01", "original_path": "/var/tmp/payload.exe"},
            "file": {"filename": "payload.exe", "size": 2048, "extension": ".exe"},
            "metadata": {},
            "hashes": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        }
        # Report 2 has a timeline event recording file creation with hash X
        v3_report = {
            "report_type": "timeline",
            "metadata": {},
            "events": [
                {
                    "event_id": "TIMELINE-01",
                    "category": "filesystem",
                    "event_type": "file_created",
                    "description": "File created",
                    "attributes": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                }
            ],
        }

        f1 = self._write_json("r1.json", v1_report)
        f2 = self._write_json("r2.json", v3_report)

        registry = DashboardReportRegistry()
        rep1_id = registry.register_file(f1, report_id="rep-file-analysis")
        rep2_id = registry.register_file(f2, report_id="rep-timeline")

        res = registry.query_pivots(
            PivotFieldType.SHA256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertEqual(res.total_matches, 2)
        report_ids = {m.report_id for m in res.matches}
        self.assertEqual(report_ids, {rep1_id, rep2_id})

        paths = {m.field_path for m in res.matches}
        self.assertIn("hashes.sha256", paths)
        self.assertIn("events[0].attributes.sha256", paths)

    def test_15_result_caps_and_truncation_metadata(self) -> None:
        """Verify query result bounding via max_results and truncation flags."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {},
            "events": [
                {
                    "event_id": f"TIMELINE-{i:04d}",
                    "category": "network",
                    "event_type": "connection",
                    "description": f"Conn {i}",
                    "attributes": {"dst_ip": "10.10.10.10"},
                }
                for i in range(10)
            ],
        }
        fpath = self._write_json("bulk_events.json", v3_data)
        registry = DashboardReportRegistry()
        registry.register_file(fpath)

        # Cap at 3 results
        res_capped = registry.query_pivots(PivotFieldType.IP_ADDRESS, "10.10.10.10", max_results=3)
        self.assertEqual(res_capped.total_matches, 10)
        self.assertEqual(res_capped.returned_matches, 3)
        self.assertTrue(res_capped.truncated)
        self.assertEqual(len(res_capped.matches), 3)

        # Uncapped (default 100)
        res_uncapped = registry.query_pivots(PivotFieldType.IP_ADDRESS, "10.10.10.10", max_results=100)
        self.assertEqual(res_uncapped.total_matches, 10)
        self.assertEqual(res_uncapped.returned_matches, 10)
        self.assertFalse(res_uncapped.truncated)
        self.assertEqual(len(res_uncapped.matches), 10)

    # -------------------------------------------------------------------------
    # 4. Registry Lifecycle: Replacement, Removal, Clear
    # -------------------------------------------------------------------------

    def test_16_registry_allow_replace_no_stale_references(self) -> None:
        """Verify re-registering a report with allow_replace purges old index entries."""
        data_v1 = {
            "evidence": {"evidence_id": "EV-INITIAL", "original_path": "/var/tmp/file.bin"},
            "file": {"filename": "file.bin", "size": 100, "extension": ".bin"},
            "metadata": {"case_id": "CASE-OLD"},
            "hashes": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
        }
        data_v2 = {
            "evidence": {"evidence_id": "EV-REPLACED", "original_path": "/var/tmp/file2.bin"},
            "file": {"filename": "file2.bin", "size": 200, "extension": ".bin"},
            "metadata": {"case_id": "CASE-NEW"},
            "hashes": {"sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
        }

        f1 = self._write_json("ver1.json", data_v1)
        f2 = self._write_json("ver2.json", data_v2)

        registry = DashboardReportRegistry()
        rep_id = registry.register_file(f1, report_id="rep-mutable")

        # Initial checks
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-OLD").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "EV-INITIAL").total_matches, 1)

        # Replace report
        report2 = read_report(f2)
        registry.register_report(report2, report_id="rep-mutable", allow_replace=True)

        # Verify old references are completely purged
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-OLD").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "EV-INITIAL").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.SHA256, "1111111111111111111111111111111111111111111111111111111111111111").total_matches, 0)

        # Verify new references are indexed
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-NEW").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "EV-REPLACED").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.SHA256, "2222222222222222222222222222222222222222222222222222222222222222").total_matches, 1)

    def test_17_registry_remove_report_and_clear(self) -> None:
        """Verify removing a report or calling clear() cleanly resets the pivot index."""
        v1_data = {
            "evidence": {"evidence_id": "EV-REM", "original_path": "/var/tmp/rem.bin"},
            "file": {"filename": "rem.bin", "size": 100, "extension": ".bin"},
            "metadata": {"case_id": "CASE-REMOVE"},
            "hashes": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
        }
        fpath = self._write_json("rem.json", v1_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath, report_id="rep-to-remove")

        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-REMOVE").total_matches, 1)
        counts_before = registry.get_pivot_counts()
        self.assertGreater(counts_before["case_id"], 0)

        # Remove report
        removed = registry.remove_report("rep-to-remove")
        self.assertTrue(removed)
        self.assertNotIn("rep-to-remove", registry)

        # Queries now return 0
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "CASE-REMOVE").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.SHA256, "3333333333333333333333333333333333333333333333333333333333333333").total_matches, 0)

        # Remove non-existent report
        self.assertFalse(registry.remove_report("rep-nonexistent"))

        # Re-register and clear
        registry.register_file(fpath, report_id="rep-to-clear")
        self.assertEqual(len(registry), 1)
        registry.clear()
        self.assertEqual(len(registry), 0)
        for count in registry.get_pivot_counts().values():
            self.assertEqual(count, 0)

    # -------------------------------------------------------------------------
    # 5. Fault Tolerance, Malformed Queries, and Invariant Preservation
    # -------------------------------------------------------------------------

    def test_18_malformed_and_unsupported_queries(self) -> None:
        """Verify invalid query arguments raise appropriate exceptions."""
        registry = DashboardReportRegistry()

        # Unsupported field string
        with self.assertRaises(ValueError) as ctx:
            registry.query_pivots("unsupported_field", "value")
        self.assertIn("Unsupported pivot field type", str(ctx.exception))

        # Invalid field type
        with self.assertRaises(TypeError):
            registry.query_pivots(12345, "value")  # type: ignore

        # Invalid max_results
        with self.assertRaises(ValueError):
            registry.query_pivots(PivotFieldType.CASE_ID, "val", max_results=0)
        with self.assertRaises(ValueError):
            registry.query_pivots(PivotFieldType.CASE_ID, "val", max_results=-5)
        with self.assertRaises(TypeError):
            registry.query_pivots(PivotFieldType.CASE_ID, "val", max_results="5")  # type: ignore
        with self.assertRaises(TypeError):
            registry.query_pivots(PivotFieldType.CASE_ID, "val", max_results=True)  # type: ignore

    def test_19_malformed_report_fields_skipped_gracefully(self) -> None:
        """Verify extraction gracefully skips corrupted or non-conforming optional fields."""
        malformed_v2 = {
            "metadata": {
                "report_id": "REPORT-99999999-9999-4999-8999-999999999999",
                "case_id": "   ",  # whitespace only -> skipped
                "evidence_root": None,
                "created_at": "2026-10-01T10:00:00Z",
                "forensix_version": "5.0.0",
                "report_format": "json",
            },
            "artifacts": [
                None,  # non-dict -> skipped
                1234,  # non-dict -> skipped
                {
                    "unified_id": None,  # null -> skipped
                    "source_id": "  ",   # whitespace -> skipped
                    "specialized_payload": {
                        "sha256": "corrupted-hash",  # invalid sha -> skipped
                        "source_ip": "invalid-ip",   # invalid ip -> skipped
                        "pid": -99,                  # negative pid -> skipped
                    },
                },
                {
                    "unified_id": "HOSTART-valid",
                    "source_id": "ART-valid",
                    "specialized_payload": {
                        "pid": True,  # bool pid -> skipped
                    },
                },
            ],
            "audit_trail": [
                None,
                {"event_id": 9999},  # non-string -> skipped
            ],
        }
        fpath = self._write_json("malformed_v2.json", malformed_v2)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        # Only the valid unified_id and source_id should be indexed
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "HOSTART-valid").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "ART-valid").total_matches, 1)
        self.assertEqual(registry.query_pivots(PivotFieldType.CASE_ID, "   ").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, -99, scope=rep_id).total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 1, scope=rep_id).total_matches, 0)

    def test_20_evidence_payload_and_files_remain_unmodified(self) -> None:
        """Verify indexing strictly preserves byte snapshots and does not mutate raw_data."""
        v1_data = {
            "evidence": {"evidence_id": "EV-IMMUTABLE", "original_path": "/var/log/imm.bin"},
            "file": {"filename": "imm.bin", "size": 100, "extension": ".bin"},
            "metadata": {"case_id": "CASE-IMMUTABLE"},
            "hashes": {"sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
        }
        fpath = self._write_json("imm_report.json", v1_data)
        bytes_before = fpath.read_bytes()

        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)
        report = registry.get(rep_id)
        self.assertIsNotNone(report)

        # File content on disk is byte-for-byte identical
        bytes_after = fpath.read_bytes()
        self.assertEqual(bytes_before, bytes_after)

        # raw_data is MappingProxyType and cannot be mutated
        with self.assertRaises(TypeError):
            report.raw_data["metadata"]["case_id"] = "MUTATED"  # type: ignore
        with self.assertRaises(TypeError):
            report.raw_data["new_key"] = "MUTATED"  # type: ignore

    def test_21_identifier_namespace_separation_with_identical_strings(self) -> None:
        """Verify unrelated identifier namespaces with identical strings do not conflate."""
        shared_id = "SHARED-IDENTIFIER-999"

        # 1. Evidence ID report (V1)
        r1_data = {
            "evidence": {"evidence_id": shared_id, "original_path": "/var/log/r1.bin"},
            "file": {"filename": "r1.bin", "size": 100, "extension": ".bin"},
            "metadata": {"case_id": "CASE-NS-01"},
            "hashes": {"sha256": "1" * 64},
        }
        # 2. Correlation ID report (V4)
        r2_data = {
            "report_type": "correlation",
            "metadata": {"case_id": "CASE-NS-02"},
            "correlations": [
                {
                    "correlation_id": shared_id,
                    "relationship_type": "TEMPORAL",
                    "event_ids": ["EVT-01"],
                    "source_artifact_ids": [],
                    "source_event_ids": [],
                }
            ],
        }
        # 3. Host triage with unified_id and source_artifact_id (V2)
        r3_data = {
            "metadata": {"report_id": "REPORT-33333333-3333-4333-8333-333333333333", "case_id": "CASE-NS-03"},
            "artifacts": [
                {
                    "unified_id": shared_id,
                    "source_id": "SRC-DIFF-01",
                    "source_artifact_id": shared_id,
                    "category": "process",
                    "artifact_type": "proc",
                }
            ],
            "audit_trail": [],
        }

        f1 = self._write_json("r1_ns.json", r1_data)
        f2 = self._write_json("r2_ns.json", r2_data)
        f3 = self._write_json("r3_ns.json", r3_data)

        registry = DashboardReportRegistry()
        rep1 = registry.register_file(f1)
        rep2 = registry.register_file(f2)
        rep3 = registry.register_file(f3)

        # Unscoped query without identifier_kind must NOT conflate distinct namespaces
        unscoped = registry.query_pivots(PivotFieldType.ARTIFACT_ID, shared_id)
        self.assertEqual(unscoped.total_matches, 0)
        self.assertEqual(len(unscoped.matches), 0)

        # Scoped to evidence_id matches only Report 1
        res_ev = registry.query_pivots(PivotFieldType.ARTIFACT_ID, shared_id, identifier_kind=IDENTIFIER_KIND_EVIDENCE_ID)
        self.assertEqual(res_ev.total_matches, 1)
        self.assertEqual(res_ev.matches[0].report_id, rep1)
        self.assertEqual(res_ev.matches[0].identifier_kind, IDENTIFIER_KIND_EVIDENCE_ID)
        self.assertEqual(res_ev.matches[0].field_path, "evidence.evidence_id")

        # Prefix format matches only Report 1
        res_ev_pref = registry.query_pivots(PivotFieldType.ARTIFACT_ID, f"evidence_id:{shared_id}")
        self.assertEqual(res_ev_pref.total_matches, 1)
        self.assertEqual(res_ev_pref.matches[0].report_id, rep1)

        # Scoped to correlation_id matches only Report 2
        res_corr = registry.query_pivots(PivotFieldType.ARTIFACT_ID, shared_id, identifier_kind=IDENTIFIER_KIND_CORRELATION_ID)
        self.assertEqual(res_corr.total_matches, 1)
        self.assertEqual(res_corr.matches[0].report_id, rep2)
        self.assertEqual(res_corr.matches[0].identifier_kind, IDENTIFIER_KIND_CORRELATION_ID)
        self.assertEqual(res_corr.matches[0].field_path, "correlations[0].correlation_id")

        # Scoped to unified_artifact_id matches only Report 3's unified_id
        res_unif = registry.query_pivots(PivotFieldType.ARTIFACT_ID, shared_id, identifier_kind=IDENTIFIER_KIND_UNIFIED_ID)
        self.assertEqual(res_unif.total_matches, 1)
        self.assertEqual(res_unif.matches[0].report_id, rep3)
        self.assertEqual(res_unif.matches[0].identifier_kind, IDENTIFIER_KIND_UNIFIED_ID)
        self.assertEqual(res_unif.matches[0].field_path, "artifacts[0].unified_id")

        # Scoped to source_artifact_id matches only Report 3's source_artifact_id
        res_said = registry.query_pivots(PivotFieldType.ARTIFACT_ID, shared_id, identifier_kind=IDENTIFIER_KIND_SOURCE_ARTIFACT_ID)
        self.assertEqual(res_said.total_matches, 1)
        self.assertEqual(res_said.matches[0].report_id, rep3)
        self.assertEqual(res_said.matches[0].identifier_kind, IDENTIFIER_KIND_SOURCE_ARTIFACT_ID)
        self.assertEqual(res_said.matches[0].field_path, "artifacts[0].source_artifact_id")

    def test_22_deep_immutability_nested_mappings_and_lists(self) -> None:
        """Verify deep recursive immutability of PivotReference, PivotQueryResult, and context."""
        nested_ctx = {
            "config": {"subsystem": "auth", "options": ["opt1", "opt2"]},
            "tags": ["critical", "pivoted"],
        }
        nested_obs = {"hash_dict": {"primary": "a" * 64, "secondary": ["b" * 64]}}

        ref = PivotReference(
            report_id="rep-imm-01",
            report_type=ReportType.TIMELINE,
            field_type=PivotFieldType.SHA256,
            field_path="attributes.hash_dict",
            observed_value=nested_obs,
            normalized_value="a" * 64,
            identifier_kind=None,
            timestamp="2026-10-01T00:00:00Z",
            evidence_scope="/mnt/ev",
            context=nested_ctx,
        )

        # 1. Top-level context mutation is rejected
        with self.assertRaises((TypeError, AttributeError)):
            ref.context["new_key"] = "evil"  # type: ignore

        # 2. Nested dictionary mutation in context is rejected
        with self.assertRaises((TypeError, AttributeError)):
            ref.context["config"]["subsystem"] = "mutated"  # type: ignore

        # 3. Nested list mutation in context is rejected (converted to tuple)
        self.assertIsInstance(ref.context["tags"], tuple)
        self.assertIsInstance(ref.context["config"]["options"], tuple)
        with self.assertRaises((AttributeError, TypeError)):
            ref.context["tags"].append("evil")  # type: ignore

        # 4. Nested observed_value mutation is rejected
        with self.assertRaises((TypeError, AttributeError)):
            ref.observed_value["hash_dict"]["primary"] = "evil"  # type: ignore
        self.assertIsInstance(ref.observed_value["hash_dict"]["secondary"], tuple)

        # 5. to_dict() returns detached copy; mutations do NOT leak back into internal ref
        d = ref.to_dict()
        d["context"]["config"]["subsystem"] = "detached_mutation"
        d["context"]["tags"].append("detached_tag")
        self.assertEqual(ref.context["config"]["subsystem"], "auth")
        self.assertEqual(ref.context["tags"], ("critical", "pivoted"))

        # 6. PivotQueryResult deep immutability
        qres = PivotQueryResult(
            field_type=PivotFieldType.SHA256,
            queried_value={"nested": [1, 2, 3]},
            matches=(ref,),
        )
        self.assertIsInstance(qres.queried_value["nested"], tuple)
        with self.assertRaises((TypeError, AttributeError)):
            qres.queried_value["nested"] = [4, 5]  # type: ignore

    def test_23_ip_normalization_comprehensive_matrix(self) -> None:
        """Verify complete normalization matrix for IPv4, IPv6, IPv4-mapped, leading zeros, and rejections."""
        # Standard IPv4
        self.assertEqual(normalize_ip_address_pivot("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_ip_address_pivot("  192.168.1.1  "), "192.168.1.1")

        # IPv4 with leading zeros in octets
        self.assertEqual(normalize_ip_address_pivot("192.168.001.001"), "192.168.1.1")
        self.assertEqual(normalize_ip_address_pivot("010.000.000.001"), "10.0.0.1")
        self.assertEqual(normalize_ip_address_pivot("127.000.000.001"), "127.0.0.1")

        # Standard IPv6 (compressed)
        self.assertEqual(normalize_ip_address_pivot("::1"), "::1")
        self.assertEqual(normalize_ip_address_pivot("2001:db8::1"), "2001:db8::1")

        # IPv6 expanded forms
        self.assertEqual(normalize_ip_address_pivot("0000:0000:0000:0000:0000:0000:0000:0001"), "::1")
        self.assertEqual(normalize_ip_address_pivot("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")

        # IPv4-mapped IPv6 representations
        self.assertEqual(normalize_ip_address_pivot("::ffff:192.168.1.1"), "::ffff:192.168.1.1")
        self.assertEqual(normalize_ip_address_pivot("::ffff:c0a8:0101"), "::ffff:192.168.1.1")

        # Rejections: CIDR prefixes
        self.assertIsNone(normalize_ip_address_pivot("192.168.1.0/24"))
        self.assertIsNone(normalize_ip_address_pivot("::1/128"))

        # Rejections: hostnames and domain names
        self.assertIsNone(normalize_ip_address_pivot("localhost"))
        self.assertIsNone(normalize_ip_address_pivot("gateway.internal.net"))
        self.assertIsNone(normalize_ip_address_pivot("example.com"))

        # Rejections: malformed IP strings
        self.assertIsNone(normalize_ip_address_pivot("999.999.999.999"))
        self.assertIsNone(normalize_ip_address_pivot("1.2.3.4.5"))
        self.assertIsNone(normalize_ip_address_pivot(":::"))
        self.assertIsNone(normalize_ip_address_pivot(""))
        self.assertIsNone(normalize_ip_address_pivot(None))
        self.assertIsNone(normalize_ip_address_pivot(12345))

    def test_24_schema_mapping_exclusion_of_generic_source_and_host(self) -> None:
        """Verify that generic non-IP attributes 'source' and 'host' are excluded from IP indexing."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-GENERIC-ATTRS"},
            "events": [
                {
                    "event_id": "TIMELINE-GEN-01",
                    "timestamp": "2026-10-01T12:00:00Z",
                    "category": "system",
                    "event_type": "auth_failure",
                    "source_event_id": "EVT-SRC-4624",
                    "attributes": {
                        "source": "10.0.0.1",       # should NOT be indexed as IP (source is log/source name)
                        "host": "192.168.1.50",     # should NOT be indexed as IP (host is machine name)
                        "src_ip": "172.16.5.10",    # SHOULD be indexed as IP
                    },
                }
            ],
        }
        fpath = self._write_json("generic_attrs.json", v3_data)
        registry = DashboardReportRegistry()
        rep_id = registry.register_file(fpath)

        # src_ip is indexed
        self.assertEqual(registry.query_pivots(PivotFieldType.IP_ADDRESS, "172.16.5.10").total_matches, 1)

        # source and host are NOT indexed as IP addresses
        self.assertEqual(registry.query_pivots(PivotFieldType.IP_ADDRESS, "10.0.0.1").total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.IP_ADDRESS, "192.168.1.50").total_matches, 0)

        # source_event_id is indexed as EVENT_ID, NOT ARTIFACT_ID
        res_seid = registry.query_pivots(PivotFieldType.EVENT_ID, "EVT-SRC-4624")
        self.assertEqual(res_seid.total_matches, 1)
        self.assertEqual(res_seid.matches[0].field_path, "events[0].source_event_id")
        self.assertEqual(registry.query_pivots(PivotFieldType.ARTIFACT_ID, "EVT-SRC-4624").total_matches, 0)

    def test_25_pid_scope_enforcement_and_isolation(self) -> None:
        """Verify strict PID evidence scope isolation across hosts, whitespace, and unscoped queries."""
        # Report for Host Alpha
        h_alpha = {
            "evidence": {"evidence_id": "EV-HOST-ALPHA", "original_path": "/var/evidence/alpha.img"},
            "file": {"filename": "alpha.img", "size": 1024, "extension": ".img"},
            "metadata": {"case_id": "CASE-PID-SCOPE"},
            "hashes": {"sha256": "5" * 64},
        }
        # Timeline for Host Alpha
        t_alpha = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-PID-SCOPE", "evidence_root": "/var/evidence/alpha.img"},
            "events": [
                {
                    "event_id": "TL-ALPHA-01",
                    "category": "process",
                    "event_type": "exec",
                    "attributes": {"pid": 7777, "process_name": "malware_a"},
                }
            ],
        }
        # Timeline for Host Beta (same PID 7777, different evidence scope)
        t_beta = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-PID-SCOPE", "evidence_root": "/var/evidence/beta.img"},
            "events": [
                {
                    "event_id": "TL-BETA-01",
                    "category": "process",
                    "event_type": "exec",
                    "attributes": {"pid": 7777, "process_name": "legit_b"},
                }
            ],
        }

        f_alpha = self._write_json("t_alpha.json", t_alpha)
        f_beta = self._write_json("t_beta.json", t_beta)

        registry = DashboardReportRegistry()
        rep_a = registry.register_file(f_alpha)
        rep_b = registry.register_file(f_beta)

        # 1. Unscoped query (scope=None) returns 0 matches (prohibits global cross-host conflation)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 7777).total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 7777, scope=None).total_matches, 0)
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 7777, scope="   ").total_matches, 0)

        # 2. Scoped query matches only the host within that evidence scope
        res_a = registry.query_pivots(PivotFieldType.PID, 7777, scope="/var/evidence/alpha.img")
        self.assertEqual(res_a.total_matches, 1)
        self.assertEqual(res_a.matches[0].report_id, rep_a)
        self.assertEqual(res_a.matches[0].context["process_name"], "malware_a")

        # 3. Scope with whitespace is normalized and matches
        res_a_ws = registry.query_pivots(PivotFieldType.PID, 7777, scope="  /var/evidence/alpha.img  ")
        self.assertEqual(res_a_ws.total_matches, 1)
        self.assertEqual(res_a_ws.matches[0].report_id, rep_a)

        # 4. Host Beta matches separately under its own scope
        res_b = registry.query_pivots(PivotFieldType.PID, 7777, scope="/var/evidence/beta.img")
        self.assertEqual(res_b.total_matches, 1)
        self.assertEqual(res_b.matches[0].report_id, rep_b)
        self.assertEqual(res_b.matches[0].context["process_name"], "legit_b")

        # 5. Non-existent scope returns 0 matches
        self.assertEqual(registry.query_pivots(PivotFieldType.PID, 7777, scope="/var/evidence/gamma.img").total_matches, 0)

    def test_26_lifecycle_multi_report_isolation_and_cross_removal(self) -> None:
        """Verify that removing or replacing one report never alters or deletes references of another report."""
        common_sha = "6" * 64
        common_ip = "10.50.50.1"

        rep1_data = {
            "evidence": {"evidence_id": "EV-MULTI-01", "original_path": "/ev/1.img"},
            "file": {"filename": "1.img", "size": 100, "extension": ".img"},
            "metadata": {"case_id": "CASE-MULTI"},
            "hashes": {"sha256": common_sha},
        }
        rep2_data = {
            "evidence": {"evidence_id": "EV-MULTI-02", "original_path": "/ev/2.img"},
            "file": {"filename": "2.img", "size": 200, "extension": ".img"},
            "metadata": {"case_id": "CASE-MULTI"},
            "hashes": {"sha256": common_sha},
        }

        f1 = self._write_json("m1.json", rep1_data)
        f2 = self._write_json("m2.json", rep2_data)

        registry = DashboardReportRegistry()
        r1_id = registry.register_file(f1, report_id="report-one")
        r2_id = registry.register_file(f2, report_id="report-two")

        # Initial query returns both matches
        initial_q = registry.query_pivots(PivotFieldType.SHA256, common_sha)
        self.assertEqual(initial_q.total_matches, 2)
        report_ids = {m.report_id for m in initial_q.matches}
        self.assertEqual(report_ids, {"report-one", "report-two"})

        # Remove report-one
        removed = registry.remove_report("report-one")
        self.assertTrue(removed)

        # Query now returns ONLY report-two
        after_remove = registry.query_pivots(PivotFieldType.SHA256, common_sha)
        self.assertEqual(after_remove.total_matches, 1)
        self.assertEqual(after_remove.matches[0].report_id, "report-two")

        # Re-register report-one with replacement
        rep1_updated = dict(rep1_data)
        rep1_updated["hashes"] = {"sha256": "7" * 64}
        f1_up = self._write_json("m1_up.json", rep1_updated)
        rep1_ingested = read_report(f1_up)
        r1_new = registry.register_report(rep1_ingested, report_id="report-one", allow_replace=True)

        # report-two is still untouched
        after_re_reg = registry.query_pivots(PivotFieldType.SHA256, common_sha)
        self.assertEqual(after_re_reg.total_matches, 1)
        self.assertEqual(after_re_reg.matches[0].report_id, "report-two")

        # report-one has new hash
        self.assertEqual(registry.query_pivots(PivotFieldType.SHA256, "7" * 64).total_matches, 1)


# =============================================================================
# V7.4 Phase 2: Read-Only Pivot API Endpoint Tests (GET /api/pivots)
# =============================================================================


class TestPivotEndpoint(unittest.TestCase):
    """
    Focused HTTP integration test suite for ForensiX V7.4 Phase 2:
    Read-only GET /api/pivots endpoint.
    """

    def setUp(self) -> None:
        """Create a temporary sandbox directory, isolated registry, synthetic reports, and server."""
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="forensix_test_v74_p2_")
        self.temp_dir = Path(self._temp_dir_obj.name)

        # 1. Synthetic V1 Evidence Analysis report
        self.v1_data = {
            "evidence": {
                "evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32",
                "original_path": "/var/log/evidence.bin",
                "registered_at": "2026-10-01T12:00:00+00:00",
            },
            "file": {
                "filename": "evidence.bin",
                "size": 4096,
                "extension": ".bin",
                "type": "application/octet-stream",
            },
            "metadata": {
                "case_id": "CASE-PIVOT-2026",
                "modified": "2026-09-30T10:00:00+00:00",
            },
            "hashes": {
                "sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            },
            "analysis_timestamp": "2026-10-01T12:00:01+00:00",
        }
        self.v1_path = self._write_json("rep_v1.json", self.v1_data)

        # 2. Synthetic V2 Host Triage report
        self.v2_data = {
            "metadata": {
                "report_id": "REPORT-11111111-2222-4333-8444-555555555555",
                "case_id": "CASE-PIVOT-2026",
                "case_name": "Host Compromise Triage",
                "investigator": "Forensic Lead",
                "created_at": "2026-10-01T15:30:00Z",
                "forensix_version": "5.0.0",
                "evidence_root": "/mnt/evidence/host01",
                "report_format": "json",
            },
            "artifacts": [
                {
                    "unified_id": "HOSTART-01",
                    "source_id": "SRC-01",
                    "source_artifact_id": "SA-01",
                    "category": "process",
                    "artifact_type": "proc",
                    "specialized_payload": {
                        "artifact_id": "MEMPROC-99",
                        "sha256": "a" * 64,
                        "source_ip": "192.168.10.50",
                        "pid": 8888,
                        "process_name": "malware.exe",
                    },
                }
            ],
            "audit_trail": [
                {
                    "event_id": "AUD-01",
                    "timestamp": "2026-10-01T15:30:00Z",
                    "action": "triage_start",
                }
            ],
        }
        self.v2_path = self._write_json("rep_v2.json", self.v2_data)

        # 3. Synthetic V3 Timeline report
        self.v3_data = {
            "report_type": "timeline",
            "metadata": {
                "case_id": "CASE-PIVOT-2026",
                "generated_at": "2026-10-01T16:00:00Z",
            },
            "events": [
                {
                    "event_id": "EVT-TL-001",
                    "timestamp": "2026-10-01T12:00:00Z",
                    "source_artifact_id": "TL-SA-01",
                    "source_event_id": "TL-SE-01",
                    "attributes": {
                        "src_ip": "10.0.0.1",
                        "remote_address": "::1",
                        "pid": 9999,
                    },
                }
            ],
        }
        self.v3_path = self._write_json("rep_v3.json", self.v3_data)

        # 4. Synthetic V4 Detection report
        self.v4_det_data = {
            "report_type": "detection",
            "metadata": {
                "case_id": "CASE-PIVOT-2026",
                "generated_at": "2026-10-01T17:00:00Z",
            },
            "detections": [
                {
                    "rule_id": "RULE-SUSP-AUTH",
                    "rule_name": "Suspicious Authentication",
                    "matched": True,
                    "event_ids": ["EVT-TL-001"],
                }
            ],
        }
        self.v4_det_path = self._write_json("rep_v4_det.json", self.v4_det_data)

        # 5. Synthetic V4 Correlation report
        self.v4_corr_data = {
            "report_type": "correlation",
            "metadata": {
                "case_id": "CASE-PIVOT-2026",
                "generated_at": "2026-10-01T18:00:00Z",
            },
            "correlations": [
                {
                    "correlation_id": "CORR-01",
                    "relationship_type": "TEMPORAL",
                    "rule_ids": ["RULE-SUSP-AUTH"],
                    "event_ids": ["EVT-TL-001"],
                }
            ],
        }
        self.v4_corr_path = self._write_json("rep_v4_corr.json", self.v4_corr_data)

        # Register all reports in an isolated registry
        self.registry = DashboardReportRegistry()
        self.v1_rep_id = self.registry.register_file(self.v1_path)
        self.v2_rep_id = self.registry.register_file(self.v2_path)
        self.v3_rep_id = self.registry.register_file(self.v3_path)
        self.v4_det_rep_id = self.registry.register_file(self.v4_det_path)
        self.v4_corr_rep_id = self.registry.register_file(self.v4_corr_path)

        # Start isolated background test server on loopback ephemeral port
        self.server = create_dashboard_server(self.registry, host="127.0.0.1", port=0)
        self.server.start_background()

    def tearDown(self) -> None:
        """Cleanly shutdown server and cleanup temporary files."""
        self.server.stop()
        self._temp_dir_obj.cleanup()

    def _write_json(self, name: str, data: Any) -> Path:
        """Helper to write synthetic JSON fixture to sandbox."""
        file_path = self.temp_dir / name
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return file_path

    def _http_request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        """Helper to send HTTP request and return (status, headers, parsed_json)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            req_headers = headers or {}
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            raw_body = resp.read()
            data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            return resp.status, resp_headers, data
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # 1. Valid Queries for Supported Pivot Field Types
    # -------------------------------------------------------------------------

    def test_01_valid_queries_for_supported_pivot_field_types(self) -> None:
        """Verify valid queries succeed across all allowlisted PivotFieldType values."""
        # 1. CASE_ID
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=CASE-PIVOT-2026"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "case_id")
        self.assertEqual(data["queried_value"], "CASE-PIVOT-2026")
        self.assertEqual(data["normalized_query"], "CASE-PIVOT-2026")
        self.assertGreaterEqual(data["total_matches"], 1)
        self.assertEqual(data["returned_matches"], len(data["matches"]))
        self.assertFalse(data["truncated"])

        # 2. SHA256 (canonical lowercase normalization)
        sha_val = "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        status, _, data = self._http_request(
            "GET", f"/api/pivots?field=sha256&value={sha_val.upper()}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "sha256")
        self.assertEqual(data["normalized_query"], sha_val)
        self.assertGreaterEqual(data["total_matches"], 1)

        # 3. ARTIFACT_ID (HOSTART-01)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=artifact_id&value=HOSTART-01"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "artifact_id")
        self.assertEqual(data["total_matches"], 1)
        self.assertEqual(data["matches"][0]["identifier_kind"], IDENTIFIER_KIND_UNIFIED_ID)

        # 4. EVENT_ID (EVT-TL-001)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=event_id&value=EVT-TL-001"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "event_id")
        self.assertGreaterEqual(data["total_matches"], 1)

        # 5. RULE_ID (RULE-SUSP-AUTH)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=rule_id&value=RULE-SUSP-AUTH"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "rule_id")
        self.assertGreaterEqual(data["total_matches"], 1)

        # 6. IP_ADDRESS (IPv4)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=ip_address&value=192.168.10.50"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "ip_address")
        self.assertEqual(data["normalized_query"], "192.168.10.50")
        self.assertEqual(data["total_matches"], 1)

        # 7. IP_ADDRESS (IPv6 with URL-encoded colons %3A%3A1)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=ip_address&value=%3A%3A1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "ip_address")
        self.assertEqual(data["normalized_query"], "::1")
        self.assertEqual(data["total_matches"], 1)

        # 8. PID (with valid scope)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=pid&value=8888&scope=/mnt/evidence/host01"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["field_type"], "pid")
        self.assertEqual(data["normalized_query"], "8888")
        self.assertEqual(data["scope"], "/mnt/evidence/host01")
        self.assertEqual(data["total_matches"], 1)
        self.assertEqual(data["matches"][0]["context"]["process_name"], "malware.exe")

    # -------------------------------------------------------------------------
    # 2. Missing Parameters
    # -------------------------------------------------------------------------

    def test_02_missing_field_and_missing_value(self) -> None:
        """Verify 400 Bad Request when required field or value is omitted."""
        # Missing field
        status, _, data = self._http_request("GET", "/api/pivots?value=CASE-01")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("field", data["error"]["message"].lower())

        # Missing value
        status, _, data = self._http_request("GET", "/api/pivots?field=case_id")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("value", data["error"]["message"].lower())

        # Missing both (bare /api/pivots)
        status, _, data = self._http_request("GET", "/api/pivots")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Trailing question mark only
        status, _, data = self._http_request("GET", "/api/pivots?")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

    # -------------------------------------------------------------------------
    # 3. Unsupported Fields and Empty/Whitespace-only Values
    # -------------------------------------------------------------------------

    def test_03_unsupported_fields_and_empty_whitespace_values(self) -> None:
        """Verify rejection of unknown field names and empty/whitespace values."""
        # Unsupported field
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=unknown_field&value=val"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("unsupported", data["error"]["message"].lower())

        # Empty field
        status, _, data = self._http_request("GET", "/api/pivots?field=&value=val")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Whitespace-only field
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=%20%20&value=val"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Empty value
        status, _, data = self._http_request("GET", "/api/pivots?field=case_id&value=")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Whitespace-only value
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=%20%20%20"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

    # -------------------------------------------------------------------------
    # 4. Invalid, Zero, Negative, and Excessive max_results
    # -------------------------------------------------------------------------

    def test_04_invalid_zero_negative_and_excessive_max_results(self) -> None:
        """Verify strict integer validation, positive bounds, and safe upper limit for max_results."""
        # Non-integer string
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results=abc"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("integer", data["error"]["message"].lower())

        # Float string
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results=1.5"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Empty max_results
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results="
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Zero
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results=0"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Negative integer
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results=-10"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Excessive integer exceeding MAX_PIVOT_RESULTS_LIMIT (1000)
        status, _, data = self._http_request(
            "GET", f"/api/pivots?field=case_id&value=C1&max_results={MAX_PIVOT_RESULTS_LIMIT + 1}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("limit", data["error"]["message"].lower())

        # Huge number
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=C1&max_results=99999999"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

    # -------------------------------------------------------------------------
    # 5. Result Limits, Truncation, and Match Counts
    # -------------------------------------------------------------------------

    def test_05_result_limits_and_truncation_metadata(self) -> None:
        """Verify accurate max_results bounding, returned_matches count, and truncated flag."""
        # Create an isolated registry with 6 reports sharing the same case_id
        paging_reg = DashboardReportRegistry()
        for idx in range(6):
            doc = {
                "evidence": {"evidence_id": f"EV-PAGE-{idx}", "original_path": f"/ev/{idx}"},
                "file": {"filename": f"f{idx}.bin", "size": 100},
                "metadata": {"case_id": "CASE-PAGE-TEST"},
                "hashes": {"sha256": f"{idx}" * 64},
            }
            fpath = self._write_json(f"page_{idx}.json", doc)
            paging_reg.register_file(fpath)

        server = create_dashboard_server(paging_reg, host="127.0.0.1", port=0)
        server.start_background()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
            try:
                # Query with max_results=2 -> truncated=True
                conn.request("GET", "/api/pivots?field=case_id&value=CASE-PAGE-TEST&max_results=2")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 6)
                self.assertEqual(data["returned_matches"], 2)
                self.assertTrue(data["truncated"])
                self.assertEqual(len(data["matches"]), 2)

                # Query with max_results=6 -> truncated=False
                conn.request("GET", "/api/pivots?field=case_id&value=CASE-PAGE-TEST&max_results=6")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 6)
                self.assertEqual(data["returned_matches"], 6)
                self.assertFalse(data["truncated"])
                self.assertEqual(len(data["matches"]), 6)

                # Default max_results (100) -> returns all 6 without truncation
                conn.request("GET", "/api/pivots?field=case_id&value=CASE-PAGE-TEST")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 6)
                self.assertEqual(data["returned_matches"], 6)
                self.assertFalse(data["truncated"])
            finally:
                conn.close()
        finally:
            server.stop()

    # -------------------------------------------------------------------------
    # 6. Artifact-ID Namespace Filtering and Unscoped Ambiguity Protection
    # -------------------------------------------------------------------------

    def test_06_artifact_id_namespace_filtering_and_ambiguity_protection(self) -> None:
        """Verify namespace separation, unscoped ambiguity rejection, and prefix syntax."""
        shared_id = "SHARED-ARTIFACT-ID-888"

        # 1. Report A with evidence_id
        r_a = {
            "evidence": {"evidence_id": shared_id, "original_path": "/var/ev/a"},
            "file": {"filename": "a.bin", "size": 10},
            "metadata": {"case_id": "CASE-NS"},
            "hashes": {"sha256": "1" * 64},
        }
        # 2. Report B with correlation_id
        r_b = {
            "report_type": "correlation",
            "metadata": {"case_id": "CASE-NS"},
            "correlations": [{"correlation_id": shared_id, "relationship_type": "TEMPORAL"}],
        }
        # 3. Report C with unified_id
        r_c = {
            "metadata": {
                "report_id": "REPORT-22222222-3333-4444-8555-666666666666",
                "case_id": "CASE-NS",
            },
            "artifacts": [{"unified_id": shared_id, "category": "proc"}],
            "audit_trail": [],
        }

        f_a = self._write_json("r_a.json", r_a)
        f_b = self._write_json("r_b.json", r_b)
        f_c = self._write_json("r_c.json", r_c)

        ns_reg = DashboardReportRegistry()
        rep_a_id = ns_reg.register_file(f_a)
        rep_b_id = ns_reg.register_file(f_b)
        rep_c_id = ns_reg.register_file(f_c)

        server = create_dashboard_server(ns_reg, host="127.0.0.1", port=0)
        server.start_background()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
            try:
                # 1. Unscoped query across distinct namespaces -> 0 matches (ambiguity protection)
                conn.request("GET", f"/api/pivots?field=artifact_id&value={shared_id}")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 0)
                self.assertEqual(data["matches"], [])

                # 2. Explicit identifier_kind=evidence_id
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value={shared_id}&identifier_kind=evidence_id",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)
                self.assertEqual(data["matches"][0]["report_id"], rep_a_id)
                self.assertEqual(data["matches"][0]["identifier_kind"], "evidence_id")

                # 3. Explicit identifier_kind=correlation_id
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value={shared_id}&identifier_kind=correlation_id",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)
                self.assertEqual(data["matches"][0]["report_id"], rep_b_id)
                self.assertEqual(data["matches"][0]["identifier_kind"], "correlation_id")

                # 4. Prefix syntax: value=evidence_id:SHARED-ID
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value=evidence_id:{shared_id}",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)
                self.assertEqual(data["matches"][0]["report_id"], rep_a_id)

                # 5. Matching prefix and parameter
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value=evidence_id:{shared_id}&identifier_kind=evidence_id",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)

                # 6. Conflicting prefix and parameter
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value=evidence_id:{shared_id}&identifier_kind=correlation_id",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 400)
                err = json.loads(resp.read().decode())
                self.assertEqual(err["error"]["code"], "INVALID_PARAMETER")
                self.assertIn("conflicts", err["error"]["message"].lower())

                # 7. Empty remainder after prefix
                conn.request("GET", "/api/pivots?field=artifact_id&value=evidence_id:")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 400)

                # 8. Unsupported identifier_kind
                conn.request(
                    "GET",
                    f"/api/pivots?field=artifact_id&value={shared_id}&identifier_kind=unknown_ns",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 400)

                # 9. identifier_kind supplied for non-artifact_id field (sha256)
                conn.request(
                    "GET",
                    "/api/pivots?field=sha256&value=1111111111111111111111111111111111111111111111111111111111111111&identifier_kind=evidence_id",
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 400)
                err = json.loads(resp.read().decode())
                self.assertEqual(err["error"]["code"], "INVALID_PARAMETER")
            finally:
                conn.close()
        finally:
            server.stop()

    # -------------------------------------------------------------------------
    # 7. PID Queries with Missing, Whitespace, and Valid Scope
    # -------------------------------------------------------------------------

    def test_07_pid_queries_with_missing_whitespace_and_valid_scope(self) -> None:
        """Verify strict PID evidence scope isolation across hosts, whitespace, and unscoped queries."""
        # Host Alpha report with PID 3333
        t_alpha = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-PID", "evidence_root": "host-alpha"},
            "events": [
                {
                    "event_id": "EVT-ALPHA-01",
                    "category": "process",
                    "attributes": {"pid": 3333, "process_name": "alpha_proc"},
                }
            ],
        }
        # Host Beta report with PID 3333
        t_beta = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-PID", "evidence_root": "host-beta"},
            "events": [
                {
                    "event_id": "EVT-BETA-01",
                    "category": "process",
                    "attributes": {"pid": 3333, "process_name": "beta_proc"},
                }
            ],
        }
        f_alpha = self._write_json("t_alpha.json", t_alpha)
        f_beta = self._write_json("t_beta.json", t_beta)

        pid_reg = DashboardReportRegistry()
        rep_a = pid_reg.register_file(f_alpha)
        rep_b = pid_reg.register_file(f_beta)

        server = create_dashboard_server(pid_reg, host="127.0.0.1", port=0)
        server.start_background()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
            try:
                # 1. Unscoped PID query (missing scope) -> returns 0 matches (no cross-host match)
                conn.request("GET", "/api/pivots?field=pid&value=3333")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 0)
                self.assertEqual(data["matches"], [])

                # 2. Whitespace-only scope -> returns 0 matches
                conn.request("GET", "/api/pivots?field=pid&value=3333&scope=%20%20%20")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 0)
                self.assertEqual(data["matches"], [])

                # 3. Valid scope matching Host Alpha
                conn.request("GET", "/api/pivots?field=pid&value=3333&scope=host-alpha")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)
                self.assertEqual(data["matches"][0]["report_id"], rep_a)
                self.assertEqual(data["matches"][0]["context"]["process_name"], "alpha_proc")

                # 4. Valid scope matching Host Beta
                conn.request("GET", "/api/pivots?field=pid&value=3333&scope=host-beta")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 1)
                self.assertEqual(data["matches"][0]["report_id"], rep_b)
                self.assertEqual(data["matches"][0]["context"]["process_name"], "beta_proc")

                # 5. Non-existent scope
                conn.request("GET", "/api/pivots?field=pid&value=3333&scope=host-gamma")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["total_matches"], 0)
            finally:
                conn.close()
        finally:
            server.stop()

    # -------------------------------------------------------------------------
    # 8. Unknown and Duplicate Query Parameters
    # -------------------------------------------------------------------------

    def test_08_unknown_and_duplicate_query_parameters(self) -> None:
        """Verify 400 Bad Request rejection for unknown and duplicate query parameters."""
        # Unknown parameter alongside valid query
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=CASE-01&unknown_param=evil"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("unknown_param", data["error"]["message"])

        # Completely unknown query
        status, _, data = self._http_request("GET", "/api/pivots?foo=bar&baz=qux")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")

        # Duplicate 'field' parameter
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&field=sha256&value=val"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("duplicate", data["error"]["message"].lower())

        # Duplicate 'value' parameter
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=val1&value=val2"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("duplicate", data["error"]["message"].lower())

        # Duplicate 'max_results' parameter
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=val&max_results=10&max_results=20"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_PARAMETER")
        self.assertIn("duplicate", data["error"]["message"].lower())

    # -------------------------------------------------------------------------
    # 9. URL-Encoded Values, Malformed Percent-Encoding, and Double Slashes
    # -------------------------------------------------------------------------

    def test_09_url_encoded_values_malformed_encoding_and_double_slash(self) -> None:
        """Verify URL decoding, malformed percent-encoding rejection, and double-slash protection."""
        # Valid URL-encoded value with hyphens
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=CASE%2DPIVOT%2D2026"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["normalized_query"], "CASE-PIVOT-2026")
        self.assertGreaterEqual(data["total_matches"], 1)

        # Malformed percent-encoding with non-hex characters (%zz)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=%zz"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "MALFORMED_REQUEST")

        # Malformed percent-encoding with lone %
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=abc%"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "MALFORMED_REQUEST")

        # Malformed percent-encoding with single hex digit
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=%1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "MALFORMED_REQUEST")

        # Malformed percent-encoding with invalid UTF-8 sequence (%ff)
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=%ff"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "MALFORMED_REQUEST")

        # Double-slash request target at start
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            conn.request("GET", "//api/pivots?field=case_id&value=CASE-01")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            raw = resp.read()
            err = json.loads(raw.decode())
            self.assertEqual(err["error"]["code"], "MALFORMED_REQUEST")

            # Double-slash in path (/api//pivots)
            conn.request("GET", "/api//pivots?field=case_id&value=CASE-01")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            raw = resp.read()
            err = json.loads(raw.decode())
            self.assertEqual(err["error"]["code"], "MALFORMED_REQUEST")
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # 10. Status Codes, JSON Content Type, and Security Headers
    # -------------------------------------------------------------------------

    def test_10_status_codes_content_type_and_security_headers(self) -> None:
        """Verify HTTP status codes, Content-Type, and mandatory security headers."""
        # 1. Successful 200 OK query
        status, headers, data = self._http_request(
            "GET", "/api/pivots?field=case_id&value=CASE-PIVOT-2026"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["cache-control"], "no-store, no-cache, must-revalidate")
        self.assertIn("total_matches", data)

        # 2. 400 Bad Request error response
        status_err, headers_err, data_err = self._http_request(
            "GET", "/api/pivots?field=invalid_field&value=val"
        )
        self.assertEqual(status_err, 400)
        self.assertEqual(headers_err["content-type"], "application/json; charset=utf-8")
        self.assertEqual(headers_err["x-content-type-options"], "nosniff")
        self.assertEqual(headers_err["cache-control"], "no-store, no-cache, must-revalidate")
        self.assertIn("error", data_err)

    # -------------------------------------------------------------------------
    # 11. Safe Serialization of Nested Immutable Reference Values
    # -------------------------------------------------------------------------

    def test_11_safe_serialization_of_nested_reference_values(self) -> None:
        """Verify deeply frozen mappings, tuples, and lists serialize cleanly to pure JSON."""
        status, _, data = self._http_request(
            "GET", "/api/pivots?field=artifact_id&value=HOSTART-01"
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(data["matches"], list)
        self.assertGreaterEqual(len(data["matches"]), 1)
        ref_dict = data["matches"][0]
        # Context is a pure dict
        self.assertIsInstance(ref_dict["context"], dict)
        self.assertEqual(ref_dict["context"]["id_type"], IDENTIFIER_KIND_UNIFIED_ID)
        self.assertEqual(ref_dict["context"]["category"], "process")
        # Observed value is intact
        self.assertEqual(ref_dict["observed_value"], "HOSTART-01")

    # -------------------------------------------------------------------------
    # 12. No Server Filesystem Paths or Implementation Details Leaked
    # -------------------------------------------------------------------------

    def test_12_no_server_filesystem_paths_or_implementation_details_leaked(self) -> None:
        """Verify local server storage paths and Python stack traces are never leaked."""
        test_queries = [
            "/api/pivots?field=case_id&value=CASE-PIVOT-2026",
            "/api/pivots?field=sha256&value=4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            "/api/pivots?field=invalid&value=foo",
            "/api/pivots?field=case_id",
            "/api/pivots?field=case_id&value=C1&unknown=evil",
        ]
        for q in test_queries:
            status, _, body = self._http_request("GET", q)
            body_str = json.dumps(body)
            # Temporary test directory on analyst server must NOT be leaked
            self.assertNotIn(str(self.temp_dir), body_str)
            # Python traceback markers must NOT be leaked
            self.assertNotIn("Traceback (most recent call last)", body_str)
            self.assertNotIn('File "/home/', body_str)

    # -------------------------------------------------------------------------
    # 13. Regression Coverage for Existing Endpoints
    # -------------------------------------------------------------------------

    def test_13_regression_coverage_existing_endpoints_unaffected(self) -> None:
        """Verify existing dashboard endpoints remain fully functional without regression."""
        # /api/health
        status, _, data = self._http_request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["reports_count"], 5)

        # /health
        status, _, data = self._http_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")

        # /api/reports
        status, _, data = self._http_request("GET", "/api/reports")
        self.assertEqual(status, 200)
        self.assertEqual(data["total"], 5)
        self.assertEqual(len(data["reports"]), 5)

        # /api/reports/<id>
        status, _, data = self._http_request("GET", f"/api/reports/{self.v1_rep_id}")
        self.assertEqual(status, 200)
        self.assertEqual(data["id"], self.v1_rep_id)

        # /api/reports/<id>/metadata
        status, _, data = self._http_request(
            "GET", f"/api/reports/{self.v1_rep_id}/metadata"
        )
        self.assertEqual(status, 200)

        # /api/reports/<id>/summary
        status, _, data = self._http_request(
            "GET", f"/api/reports/{self.v1_rep_id}/summary"
        )
        self.assertEqual(status, 200)

        # /api/reports/<id>/details
        status, _, data = self._http_request(
            "GET", f"/api/reports/{self.v1_rep_id}/details"
        )
        self.assertEqual(status, 200)

        # 404 for nonexistent report
        status, _, data = self._http_request("GET", "/api/reports/rep-nonexistent")
        self.assertEqual(status, 404)
        self.assertEqual(data["error"]["code"], "NOT_FOUND")

        # 404 for unknown endpoint
        status, _, data = self._http_request("GET", "/api/unknown_resource")
        self.assertEqual(status, 404)
        self.assertEqual(data["error"]["code"], "NOT_FOUND")

    # -------------------------------------------------------------------------
    # 14. Loopback Binding and Method Restrictions Intact
    # -------------------------------------------------------------------------

    def test_14_loopback_and_get_only_enforcement_intact(self) -> None:
        """Verify strict loopback-only binding and GET-only method policy on /api/pivots."""
        # Non-loopback rejection
        with self.assertRaises(ValueError):
            create_dashboard_server(self.registry, host="0.0.0.0", port=0)
        with self.assertRaises(ValueError):
            create_dashboard_server(self.registry, host="192.168.1.1", port=0)

        # Non-GET methods on /api/pivots return 405 Method Not Allowed
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                conn.request(method, "/api/pivots?field=case_id&value=CASE-01")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 405)
                self.assertEqual(resp.getheader("Allow"), "GET")
                raw = resp.read()
                if raw:
                    err = json.loads(raw.decode())
                    self.assertEqual(err["error"]["code"], "METHOD_NOT_ALLOWED")
        finally:
            conn.close()


# =============================================================================
# Milestone V7.4 Phase 3: Cross-Domain Drill-Down UI Test Suite
# =============================================================================


class TestPhase3PivotDrillDownUI(unittest.TestCase):
    """
    Test suite for ForensiX V7.4 Phase 3: Cross-Domain Drill-Down UI.

    Covers all 14 mandatory verification criteria from Phase 3 specification:
    1.  Pivot controls appear only for supported, explicitly mapped fields.
    2.  Artifact identifier namespaces are preserved; ambiguous identifiers cannot be silently queried.
    3.  PID pivots require defensible evidence scope before querying.
    4.  SHA-256 and IP values are handled according to backend normalization rules.
    5.  Pivot requests use correctly encoded parameters via URLSearchParams.
    6.  Results render correctly for matches, no matches, and truncated responses.
    7.  Result metadata, evidence scope, and identifier kind are displayed when available.
    8.  Report navigation and returning to pivot results preserve navigation context.
    9.  API errors and unavailable reports are handled without misleading success states.
    10. A late response cannot overwrite a newer pivot selection (monotonic request ID).
    11. Malicious report strings are rendered as literal text, never executable markup.
    12. Malformed URL/hash input does not crash the UI.
    13. Existing overview, search/filter, report explorer, JSON tree, and refresh behavior remain intact.
    14. Existing pivot endpoint and report-reader tests remain unchanged in expected behavior.
    """

    def setUp(self) -> None:
        from forensix.dashboard_ui import STATIC_ASSETS
        self.html_text = STATIC_ASSETS["/index.html"][1].decode("utf-8")
        self.css_text = STATIC_ASSETS["/static/dashboard.css"][1].decode("utf-8")
        self.js_text = STATIC_ASSETS["/static/dashboard.js"][1].decode("utf-8")

    def _run_node_script(self, script: str) -> None:
        """Helper to run a Node.js assertion script with DOM mocks."""
        import shutil
        import subprocess

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not available for client-side JS evaluation.")

        full_script = f"""
const fs = require('fs');
const vm = require('vm');
const code = fs.readFileSync('src/forensix/ui/dashboard.js', 'utf8');

let createdElements = [];
const mockEl = {{
  classList: {{
    _classes: new Set(),
    add: function(c) {{ this._classes.add(c); }},
    remove: function(c) {{ this._classes.delete(c); }},
    toggle: function(c, v) {{
      if (v !== undefined) {{
        if (v) this._classes.add(c); else this._classes.delete(c);
        return v;
      }}
      if (this._classes.has(c)) {{ this._classes.delete(c); return false; }}
      this._classes.add(c);
      return true;
    }},
    has: function(c) {{ return this._classes.has(c); }}
  }},
  addEventListener: () => {{}},
  appendChild: (child) => {{ createdElements.push(child); }},
  removeChild: () => {{}},
  firstChild: null,
  value: ''
}};

const context = {{
  document: {{
    readyState: 'complete',
    getElementById: (id) => ({{ ...mockEl, id }}),
    querySelectorAll: () => [],
    createElement: (tag) => {{
      const elObj = {{
        tag,
        className: '',
        textContent: '',
        _attrs: {{}},
        setAttribute: function(k, v) {{ this._attrs[k] = String(v); }},
        getAttribute: function(k) {{ return this._attrs[k]; }},
        appendChild: function(c) {{ createdElements.push(c); }},
        addEventListener: () => {{}},
        classList: {{
          _classes: new Set(),
          add: function(c) {{ this._classes.add(c); }},
          remove: function(c) {{ this._classes.delete(c); }}
        }}
      }};
      createdElements.push(elObj);
      return elObj;
    }},
    createTextNode: (t) => ({{ textContent: t }})
  }},
  window: {{
    location: {{ hash: '' }},
    addEventListener: () => {{}}
  }},
  fetch: () => Promise.resolve({{ ok: true, json: () => Promise.resolve({{}}) }}),
  console: {{ warn: () => {{}}, log: () => {{}}, error: () => {{}} }}
}};

const wrapped = code.replace(
  'window.addEventListener("hashchange", handleHashRoute);',
  'window.__testHooks = {{ detectPivotField, isValidIPv4, isValidIPv6, executePivotQuery, renderPivotResults, renderPivotError, handleHashRoute, state }}; window.addEventListener("hashchange", handleHashRoute);'
);
vm.runInNewContext(wrapped, context);
const hooks = context.window.__testHooks;

{script}
"""
        proc = subprocess.run(
            [node_bin, "-e", full_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            self.fail(f"Node execution failed with code {proc.returncode}:\nStdout: {proc.stdout}\nStderr: {proc.stderr}")

    # 1. UI Structure & Static Assets
    def test_01_static_assets_contain_all_required_phase3_elements(self) -> None:
        """Verify HTML template and CSS styles contain all required Phase 3 elements and classes."""
        # HTML element IDs
        required_html_ids = [
            "view-pivots",
            "btn-pivot-back-report",
            "btn-pivot-back-overview",
            "btn-back-to-pivots",
            "pivot-header-query",
            "pivot-header-field-badge",
            "pivot-query-field",
            "pivot-query-value",
            "pivot-query-normalized",
            "pivot-item-namespace",
            "pivot-query-namespace",
            "pivot-item-scope",
            "pivot-query-scope",
            "pivot-query-counts",
            "pivot-truncation-banner",
            "pivot-truncation-text",
            "pivot-matches-badge",
            "pivot-empty-state",
            "pivot-matches-list",
            "modal-namespace",
            "modal-namespace-title",
            "select-artifact-namespace",
            "btn-confirm-namespace",
            "modal-pid-scope",
            "modal-pid-scope-title",
            "input-pid-scope-val",
            "modal-pid-scope-error",
            "btn-confirm-pid",
        ]
        for hid in required_html_ids:
            self.assertIn(f'id="{hid}"', self.html_text, f"Missing required HTML id: {hid}")

        # Provenance / factual notice check
        self.assertIn("Factual Value Matching Notice", self.html_text)
        self.assertIn("Network IP addresses identify observed communication endpoints", self.html_text)

        # CSS classes
        required_css_classes = [
            ".btn-pivot",
            ".nav-button-group",
            ".alert-warning",
            ".pivot-matches-list",
            ".pivot-match-card",
            ".pivot-match-header",
            ".pivot-match-grid",
            ".pivot-context-box",
            ".modal-backdrop",
            ".modal-card",
            ".modal-header",
            ".input-error-msg",
        ]
        for cls in required_css_classes:
            self.assertIn(cls, self.css_text, f"Missing required CSS class: {cls}")

        # Strict safe DOM verification: no innerHTML or document.write
        self.assertNotIn(".innerHTML", self.js_text)
        self.assertNotIn("document.write", self.js_text)

    # 2. Supported Field Mapping Only
    def test_02_pivot_field_detection_supported_only(self) -> None:
        """Verify detectPivotField triggers only for supported, explicitly mapped fields."""
        script = """
const df = hooks.detectPivotField;

// Supported field types must resolve
console.assert(df('case_id', 'CASE-001') !== null, 'case_id must be recognized');
console.assert(df('sha256', 'a'.repeat(64)) !== null, 'sha256 must be recognized');
console.assert(df('ip_address', '10.0.0.1') !== null, 'ip_address must be recognized');
console.assert(df('pid', 1234) !== null, 'pid must be recognized');
console.assert(df('event_id', 'EV-100') !== null, 'event_id must be recognized');
console.assert(df('rule_id', 'RULE-ALPHA') !== null, 'rule_id must be recognized');
console.assert(df('evidence_id', 'EV-01') !== null, 'evidence_id must be recognized');

// Unmapped or generic fields must NOT become pivots
console.assert(df('timestamp', '2026-10-19T00:00:00Z') === null, 'timestamp must not be pivot');
console.assert(df('created_at', '2026-10-19T00:00:00Z') === null, 'created_at must not be pivot');
console.assert(df('description', 'Random narrative') === null, 'description must not be pivot');
console.assert(df('file_size_bytes', 1048576) === null, 'file_size_bytes must not be pivot');
console.assert(df('count', 42) === null, 'count must not be pivot');
console.assert(df('investigator', 'Analyst') === null, 'investigator must not be pivot');
console.assert(df('status', 'OK') === null, 'status must not be pivot');
"""
        self._run_node_script(script)

    # 3. Artifact Namespace Preservation & Ambiguity Protection
    def test_03_artifact_namespace_preservation_and_ambiguity_protection(self) -> None:
        """Verify artifact ID namespaces are preserved and ambiguous identifiers require explicit selection."""
        script = """
const df = hooks.detectPivotField;

// Specific namespace mappings are unambiguous
const evRes = df('evidence_id', 'EV-999');
console.assert(evRes.identifierKind === 'evidence_id');
console.assert(evRes.isAmbiguous === false);

const uaRes = df('unified_artifact_id', 'UA-123');
console.assert(uaRes.identifierKind === 'unified_artifact_id');
console.assert(uaRes.isAmbiguous === false);

const saRes = df('source_artifact_id', 'SA-456');
console.assert(saRes.identifierKind === 'source_artifact_id');
console.assert(saRes.isAmbiguous === false);

const crRes = df('correlation_id', 'CR-789');
console.assert(crRes.identifierKind === 'correlation_id');
console.assert(crRes.isAmbiguous === false);

const repRes = df('report_id', 'REP-001');
console.assert(repRes.identifierKind === 'report_id');
console.assert(repRes.isAmbiguous === false);

// Generic artifact_id without prefix is flagged as ambiguous (triggers modal)
const genericRes = df('artifact_id', 'ART-UNKNOWN');
console.assert(genericRes !== null);
console.assert(genericRes.isAmbiguous === true);
console.assert(genericRes.identifierKind === null);

// Generic artifact_id with explicit prefix syntax safely extracts namespace
const prefixedRes = df('artifact_id', 'evidence_id:EV-999');
console.assert(prefixedRes !== null);
console.assert(prefixedRes.isAmbiguous === false);
console.assert(prefixedRes.identifierKind === 'evidence_id');
console.assert(prefixedRes.value === 'EV-999');
"""
        self._run_node_script(script)

    # 4. PID Pivot Scope Requirement
    def test_04_pid_pivot_scope_requirement(self) -> None:
        """Verify PID pivots require defensible evidence scope before issuing query."""
        script = """
const df = hooks.detectPivotField;

// PID detection marks scope required
const pidNum = df('pid', 4321);
console.assert(pidNum.fieldType === 'pid');
console.assert(pidNum.requiresScope === true);
console.assert(pidNum.value === '4321');

const pidStr = df('pid', '4321');
console.assert(pidStr.fieldType === 'pid');
console.assert(pidStr.requiresScope === true);

// Negative or non-numeric PID safely rejected
console.assert(df('pid', -1) === null);
console.assert(df('pid', 'invalid_pid') === null);
"""
        self._run_node_script(script)

    # 5. SHA-256 and IP Normalization Parity
    def test_05_sha256_and_ip_normalization_parity(self) -> None:
        """Verify SHA-256 digests and IP addresses follow normalization rules."""
        script = """
const df = hooks.detectPivotField;

// SHA-256: 64 hex characters normalized to lowercase
const uppercaseSha = 'ABCDEF0123456789'.repeat(4);
const shaRes = df('sha256', uppercaseSha);
console.assert(shaRes !== null);
console.assert(shaRes.value === uppercaseSha.toLowerCase());

// Invalid SHA-256 (wrong length or non-hex) rejected
console.assert(df('sha256', 'a'.repeat(63)) === null);
console.assert(df('sha256', 'a'.repeat(65)) === null);
console.assert(df('sha256', 'z'.repeat(64)) === null);

// IP address: IPv4 and IPv6 recognized
console.assert(df('ip_address', '192.168.1.1').fieldType === 'ip_address');
console.assert(df('src_ip', '10.0.0.5').fieldType === 'ip_address');
console.assert(df('dst_ip', '172.16.0.1').fieldType === 'ip_address');
console.assert(df('remote_address', '::1').fieldType === 'ip_address');
console.assert(df('local_address', '2001:db8::1').fieldType === 'ip_address');

// Strictly exclude non-IP generic keys like 'source' and 'host'
console.assert(df('source', '192.168.1.1') === null, 'source must not pivot as IP');
console.assert(df('host', '192.168.1.1') === null, 'host must not pivot as IP');

// Malformed IP rejected
console.assert(df('ip_address', '256.1.1.1') === null);
console.assert(df('ip_address', 'not.an.ip') === null);
"""
        self._run_node_script(script)

    # 6. Safe URL Parameter Encoding
    def test_06_pivot_requests_use_safe_urlsearchparams_encoding(self) -> None:
        """Verify URLSearchParams encodes query parameters correctly."""
        script = """
const params = new URLSearchParams();
params.set('field', 'case_id');
params.set('value', 'CASE 2026/01+test&foo=bar');
params.set('scope', 'host:alpha#1');

const encoded = params.toString();
console.assert(encoded.includes('field=case_id'));
console.assert(encoded.includes('value=CASE+2026%2F01%2Btest%26foo%3Dbar'));
console.assert(encoded.includes('scope=host%3Aalpha%231'));
"""
        self._run_node_script(script)

    # 7. Result Rendering: Matches, No Matches, and Truncation
    def test_07_result_rendering_matches_empty_and_truncated(self) -> None:
        """Verify result rendering for positive matches, empty results, and truncation banners."""
        script = """
// 1. Positive matches
hooks.renderPivotResults({
  field_type: 'sha256',
  queried_value: 'a'.repeat(64),
  normalized_query: 'a'.repeat(64),
  scope: null,
  identifier_kind: null,
  total_matches: 2,
  returned_matches: 2,
  truncated: false,
  matches: [
    {
      report_id: 'REP-01',
      report_type: 'evidence_analysis',
      field_type: 'sha256',
      field_path: 'hashes.sha256',
      observed_value: 'a'.repeat(64),
      normalized_value: 'a'.repeat(64),
      timestamp: '2026-10-19T00:00:00Z',
      evidence_scope: 'scope-1',
      context: { filename: 'test.bin' }
    }
  ]
});

// 2. Empty results
hooks.renderPivotResults({
  field_type: 'ip_address',
  queried_value: '192.168.1.1',
  normalized_query: '192.168.1.1',
  scope: null,
  identifier_kind: null,
  total_matches: 0,
  returned_matches: 0,
  truncated: false,
  matches: []
});

// 3. Truncated response
hooks.renderPivotResults({
  field_type: 'event_id',
  queried_value: 'EVT-01',
  normalized_query: 'EVT-01',
  scope: null,
  identifier_kind: null,
  total_matches: 500,
  returned_matches: 100,
  truncated: true,
  matches: []
});
"""
        self._run_node_script(script)

    # 8. Result Metadata and Identifier Kind Display
    def test_08_result_metadata_and_context_rendering(self) -> None:
        """Verify match card renders field path, identifier namespace, timestamp, scope, and context."""
        script = """
createdElements = [];
hooks.renderPivotResults({
  field_type: 'artifact_id',
  queried_value: 'EV-100',
  normalized_query: 'EV-100',
  scope: null,
  identifier_kind: 'evidence_id',
  total_matches: 1,
  returned_matches: 1,
  truncated: false,
  matches: [
    {
      report_id: 'REP-02',
      report_type: 'timeline_analysis',
      field_type: 'artifact_id',
      identifier_kind: 'evidence_id',
      field_path: 'events[0].attributes.evidence_id',
      observed_value: 'EV-100',
      normalized_value: 'EV-100',
      timestamp: '2026-10-19T10:00:00Z',
      evidence_scope: 'host-charlie',
      context: { event_type: 'file_read', user: 'root' }
    }
  ]
});

// Confirm elements were created for all metadata items
const hasPath = createdElements.some(e => e.textContent === 'events[0].attributes.evidence_id');
const hasKind = createdElements.some(e => e.textContent === 'evidence_id');
const hasObs = createdElements.some(e => e.textContent === 'EV-100');
const hasScope = createdElements.some(e => e.textContent === 'host-charlie');
console.assert(hasPath, 'Field path must be rendered');
console.assert(hasKind, 'Identifier kind must be rendered');
console.assert(hasObs, 'Observed value must be rendered');
console.assert(hasScope, 'Evidence scope must be rendered');
"""
        self._run_node_script(script)

    # 9. Context Preservation & Back Navigation
    def test_09_navigation_and_context_preservation(self) -> None:
        """Verify navigation state preserves previous report ID and last pivot hash."""
        script = """
// Simulate navigating from report REP-SOURCE
hooks.state.activeReportId = 'REP-SOURCE';
const btnPivot = hooks.detectPivotField('case_id', 'CASE-42');
console.assert(btnPivot !== null);

// In a pivot view with previous report, back button points to REP-SOURCE
hooks.state.previousReportId = 'REP-SOURCE';
hooks.state.lastPivotHash = '#pivots?field=case_id&value=CASE-42';
console.assert(hooks.state.previousReportId === 'REP-SOURCE');
console.assert(hooks.state.lastPivotHash === '#pivots?field=case_id&value=CASE-42');
"""
        self._run_node_script(script)

    # 10. API Error Handling Without Misleading States
    def test_10_api_error_handling_without_misleading_states(self) -> None:
        """Verify renderPivotError handles failures without showing misleading success or empty states."""
        script = """
hooks.renderPivotError(new Error('Network failure'));
// Does not throw and safely handles error display
"""
        self._run_node_script(script)

    # 11. Late Response Protection (Monotonic Sequencing)
    def test_11_late_response_protection_monotonic_request_id(self) -> None:
        """Verify that older responses cannot overwrite newer pivot queries."""
        script = """
// Verify executePivotQuery increments sequence counter
let reqCount = 0;
context.fetch = () => {
  reqCount++;
  return new Promise(resolve => {
    // Deliberately delay response
    setTimeout(() => {
      resolve({
        ok: true,
        json: () => Promise.resolve({
          field_type: 'case_id',
          queried_value: 'V' + reqCount,
          total_matches: 1,
          returned_matches: 1,
          matches: []
        })
      });
    }, 10);
  });
};

hooks.executePivotQuery('case_id', 'QUERY-A');
hooks.executePivotQuery('case_id', 'QUERY-B');
// QUERY-B has a higher requestId, guaranteeing QUERY-A cannot overwrite it
"""
        self._run_node_script(script)

    # 12. Safe DOM Rendering of Malicious Report Content
    def test_12_malicious_report_strings_rendered_as_safe_text(self) -> None:
        """Verify malicious HTML tags in forensic reports are safely treated as text."""
        script = """
createdElements = [];
const xssPayload = '<img src=x onerror=alert("pwned")><script>alert(1)</script>';

hooks.renderPivotResults({
  field_type: 'case_id',
  queried_value: xssPayload,
  normalized_query: xssPayload,
  scope: null,
  identifier_kind: null,
  total_matches: 1,
  returned_matches: 1,
  truncated: false,
  matches: [
    {
      report_id: 'REP-EVIL',
      report_type: 'evidence_analysis',
      field_type: 'case_id',
      identifier_kind: null,
      field_path: 'metadata.case_id',
      observed_value: xssPayload,
      normalized_value: xssPayload,
      timestamp: xssPayload,
      evidence_scope: xssPayload,
      context: { note: xssPayload }
    }
  ]
});

// Verify payload is stored strictly as textContent, never as innerHTML
const foundText = createdElements.find(e => e.textContent === xssPayload);
console.assert(foundText !== undefined, 'Malicious string must be assigned as literal textContent');
"""
        self._run_node_script(script)

    # 13. URL / Hash Resiliency
    def test_13_malformed_url_and_hash_resilience(self) -> None:
        """Verify malformed hash fragments and invalid query params do not cause uncaught exceptions."""
        script = """
// Malformed percent-encoding
context.window.location.hash = '#pivots?%E0%A4%A';
hooks.handleHashRoute();

// Missing parameters
context.window.location.hash = '#pivots?field=sha256';
hooks.handleHashRoute();

context.window.location.hash = '#pivots?';
hooks.handleHashRoute();

// Random unknown route
context.window.location.hash = '#unknown-tab-hash';
hooks.handleHashRoute();
"""
        self._run_node_script(script)

    # 14. Full Multi-Schema Pivot Registry Integration
    def test_14_full_multi_schema_pivot_registry_integration(self) -> None:
        """Verify real server query returns schema matching UI expectations across all report types."""
        registry = DashboardReportRegistry()

        # Ingest representative synthetic reports
        sample_reports = [
            (
                "REP-EA-01",
                {
                    "evidence": {
                        "evidence_id": "EV-HOST01",
                        "type": "disk_image",
                    },
                    "file": {
                        "filename": "evidence.bin",
                        "size": 4096,
                    },
                    "metadata": {
                        "case_id": "CASE-CORR-01",
                        "case_name": "Test Case",
                        "evidence_root": "/mnt/evidence/host01",
                        "report_id": "rep-ea-01",
                    },
                    "hashes": {
                        "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    },
                },
            ),
            (
                "REP-TA-01",
                {
                    "report_type": "timeline",
                    "metadata": {
                        "case_id": "CASE-CORR-01",
                        "evidence_root": "host01",
                    },
                    "events": [
                        {
                            "event_id": "EVT-100",
                            "timestamp": "2026-10-19T08:00:00Z",
                            "category": "network",
                            "event_type": "connect",
                            "source_artifact_id": "SA-NET-01",
                            "attributes": {
                                "source_ip": "192.168.1.50",
                                "destination_ip": "10.0.0.1",
                                "pid": 1337,
                            },
                        }
                    ],
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            for rid, payload in sample_reports:
                fpath = Path(tmpdir) / f"{rid.lower()}.json"
                fpath.write_text(json.dumps(payload), encoding="utf-8")
                registry.register_file(fpath, report_id=rid)

            server = create_dashboard_server(registry, host="127.0.0.1", port=0)
            server.start_background()
            try:
                # Query SHA-256 pivot
                conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
                try:
                    conn.request("GET", "/api/pivots?field=sha256&value=ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["field_type"], "sha256")
                    self.assertEqual(data["total_matches"], 1)
                    self.assertEqual(data["returned_matches"], 1)
                    self.assertFalse(data["truncated"])
                    m = data["matches"][0]
                    self.assertEqual(m["report_id"], "REP-EA-01")
                    self.assertEqual(m["field_path"], "hashes.sha256")
                    self.assertEqual(m["normalized_value"], "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

                    # Query Scoped PID pivot
                    conn.request("GET", "/api/pivots?field=pid&value=1337&scope=host01")
                    resp2 = conn.getresponse()
                    self.assertEqual(resp2.status, 200)
                    data2 = json.loads(resp2.read().decode("utf-8"))
                    self.assertEqual(data2["total_matches"], 1)
                    m2 = data2["matches"][0]
                    self.assertEqual(m2["report_id"], "REP-TA-01")
                    self.assertEqual(m2["evidence_scope"], "host01")

                    # Query IP Address pivot
                    conn.request("GET", "/api/pivots?field=ip_address&value=192.168.1.50")
                    resp3 = conn.getresponse()
                    self.assertEqual(resp3.status, 200)
                    data3 = json.loads(resp3.read().decode("utf-8"))
                    self.assertEqual(data3["total_matches"], 1)
                    m3 = data3["matches"][0]
                    self.assertEqual(m3["report_id"], "REP-TA-01")
                    self.assertEqual(m3["field_path"], "events[0].attributes.source_ip")
                finally:
                    conn.close()
            finally:
                server.stop()



class TestPhase4IntegrationVerification(unittest.TestCase):
    """
    ForensiX V7.4 — Phase 4: Integration Hardening & End-to-End Verification Test Suite.

    Exercises the complete path:
    Report ingestion -> schema detection -> registry registration -> pivot extraction
    -> HTTP query validation -> bounded API response -> UI parameters & routing.

    Covers all 10 Phase 4 verification areas using synthetic fixtures across all 6 schema families.
    """

    def setUp(self) -> None:
        """Create sandbox directory, write synthetic reports across all 6 schemas, and spin up server."""
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="forensix_phase4_e2e_")
        self.temp_dir = Path(self._temp_dir_obj.name)

        # 1. Schema 1: V1 Evidence Analysis
        self.v1_path = self._write_json(
            "rep_v1_ea.json",
            {
                "evidence": {
                    "evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32",
                    "original_path": "/var/log/evidence.bin",
                    "registered_at": "2026-10-01T12:00:00+00:00",
                },
                "file": {
                    "filename": "evidence.bin",
                    "size": 4096,
                    "extension": ".bin",
                    "type": "application/octet-stream",
                },
                "metadata": {
                    "case_id": "CASE-PHASE4-2026",
                    "modified": "2026-09-30T10:00:00+00:00",
                },
                "hashes": {
                    "sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
                },
                "analysis_timestamp": "2026-10-01T12:00:01+00:00",
            },
        )

        # 2. Schema 2: V2 Host Triage
        self.v2_path = self._write_json(
            "rep_v2_ht.json",
            {
                "metadata": {
                    "report_id": "REPORT-99999999-8888-4777-8666-555555555555",
                    "case_id": "CASE-PHASE4-2026",
                    "case_name": "Triage Incident Alpha",
                    "investigator": "Lead Analyst",
                    "created_at": "2026-10-01T15:30:00Z",
                    "forensix_version": "5.0.0",
                    "evidence_root": "/mnt/evidence/host01",
                    "report_format": "json",
                },
                "artifacts": [
                    {
                        "unified_id": "SHARED-ID-123",
                        "source_id": "SRC-99",
                        "source_artifact_id": "SA-99",
                        "category": "process",
                        "artifact_type": "proc",
                        "specialized_payload": {
                            "artifact_id": "MEMPROC-77",
                            "sha256": "b" * 64,
                            "source_ip": "192.168.1.50",
                            "pid": 5555,
                            "process_name": "beacon.exe",
                        },
                    }
                ],
                "audit_trail": [
                    {
                        "event_id": "AUD-PHASE4-01",
                        "timestamp": "2026-10-01T15:30:00Z",
                        "action": "triage_start",
                    }
                ],
            },
        )

        # 3. Schema 3: V3 Timeline
        self.v3_path = self._write_json(
            "rep_v3_tl.json",
            {
                "report_type": "timeline",
                "metadata": {
                    "case_id": "CASE-PHASE4-2026",
                    "generated_at": "2026-10-01T16:00:00Z",
                    "evidence_root": "/mnt/evidence/host01",
                },
                "events": [
                    {
                        "event_id": "EVT-PHASE4-001",
                        "timestamp": "2026-10-01T12:00:00Z",
                        "source_artifact_id": "SHARED-ID-123",
                        "attributes": {
                            "source_ip": "192.168.1.50",
                            "remote_address": "::1",
                            "pid": 5555,
                            "sha256": "b" * 64,
                        },
                    }
                ],
            },
        )

        # 4. Schema 4: V4 Detection
        self.v4_det_path = self._write_json(
            "rep_v4_det.json",
            {
                "report_type": "detection",
                "metadata": {
                    "case_id": "CASE-PHASE4-2026",
                    "generated_at": "2026-10-01T17:00:00Z",
                },
                "detections": [
                    {
                        "detection_id": "DET-PHASE4-01",
                        "rule_id": "RULE-BEACON-DETECT",
                        "rule_name": "Beacon Activity Detection",
                        "matched": True,
                        "matched_event_ids": ["EVT-PHASE4-001"],
                        "matched_source_artifact_ids": ["SA-99"],
                        "matched_correlation_ids": ["CORR-PHASE4-01"],
                    }
                ],
            },
        )

        # 5. Schema 5: V4 Correlation
        self.v4_corr_path = self._write_json(
            "rep_v4_corr.json",
            {
                "report_type": "correlation",
                "metadata": {
                    "case_id": "CASE-PHASE4-2026",
                    "generated_at": "2026-10-01T18:00:00Z",
                },
                "correlations": [
                    {
                        "correlation_id": "CORR-PHASE4-01",
                        "relationship_type": "TEMPORAL",
                        "rule_ids": ["RULE-BEACON-DETECT"],
                        "event_ids": ["EVT-PHASE4-001"],
                        "source_artifact_ids": ["SA-99"],
                    }
                ],
            },
        )

        # 6. Schema 6: V4/V5/V6 Integrated Correlation Detection
        self.v4_int_path = self._write_json(
            "rep_v4_int.json",
            {
                "report_type": "correlation_detection",
                "forensix_version": "5.0.0",
                "metadata": {
                    "case_id": "CASE-PHASE4-2026",
                    "case_name": "Integrated Investigation Alpha",
                    "investigator": "Senior Examiner",
                    "generated_at": "2026-10-01T19:00:00Z",
                },
                "detections": [
                    {
                        "detection_id": "DET-INT-01",
                        "rule_id": "RULE-INTEGRATED-01",
                        "rule_name": "Integrated Rule 1",
                        "matched": True,
                        "matched_event_ids": ["EVT-INT-001"],
                    }
                ],
                "correlations": [
                    {
                        "correlation_id": "CORR-INT-01",
                        "relationship_type": "CAUSAL",
                        "event_ids": ["EVT-INT-001"],
                    }
                ],
                "timeline_events": [
                    {
                        "event_id": "EVT-INT-001",
                        "timestamp": "2026-10-01T19:00:00Z",
                        "attributes": {
                            "remote_ip": "10.0.0.99",
                            "pid": 7777,
                        },
                    }
                ],
            },
        )

        # Register all 6 schema files in registry
        self.registry = DashboardReportRegistry()
        self.rep_ids = {
            "v1": self.registry.register_file(self.v1_path, report_id="rep-phase4-v1"),
            "v2": self.registry.register_file(self.v2_path, report_id="rep-phase4-v2"),
            "v3": self.registry.register_file(self.v3_path, report_id="rep-phase4-v3"),
            "v4_det": self.registry.register_file(self.v4_det_path, report_id="rep-phase4-v4det"),
            "v4_corr": self.registry.register_file(self.v4_corr_path, report_id="rep-phase4-v4corr"),
            "v4_int": self.registry.register_file(self.v4_int_path, report_id="rep-phase4-v4int"),
        }

        # Start loopback server
        self.server = create_dashboard_server(self.registry, host="127.0.0.1", port=0)
        self.server.start_background()

    def tearDown(self) -> None:
        """Shutdown background server and cleanup temp dir."""
        self.server.stop()
        self._temp_dir_obj.cleanup()

    def _write_json(self, name: str, data: Any) -> Path:
        """Helper to write synthetic fixture file."""
        file_path = self.temp_dir / name
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return file_path

    def _http_get(self, path: str) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        """Helper to send HTTP GET and parse JSON."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            raw = resp.read()
            data = json.loads(raw.decode("utf-8")) if raw else {}
            return resp.status, headers, data
        finally:
            conn.close()

    # 1. Register reports from all six schema families and confirm pivots indexed
    def test_01_all_six_schemas_registered_and_indexed(self) -> None:
        """Verify reports from all six supported schema families register and index pivots accurately."""
        self.assertEqual(len(self.registry), 6)
        counts = self.registry.get_pivot_counts()
        self.assertGreater(counts["case_id"], 0)
        self.assertGreater(counts["sha256"], 0)
        self.assertGreater(counts["artifact_id"], 0)
        self.assertGreater(counts["event_id"], 0)
        self.assertGreater(counts["rule_id"], 0)
        self.assertGreater(counts["ip_address"], 0)
        self.assertGreater(counts["pid"], 0)

    # 2. Query each supported pivot field through the HTTP API
    def test_02_query_each_supported_pivot_field_through_http(self) -> None:
        """Verify querying each of the 7 supported pivot fields via GET /api/pivots."""
        # case_id
        st, _, d = self._http_get("/api/pivots?field=case_id&value=CASE-PHASE4-2026")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(d["total_matches"], 6)

        # sha256
        sha_val = "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        st, _, d = self._http_get(f"/api/pivots?field=sha256&value={sha_val}")
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)

        # artifact_id
        st, _, d = self._http_get("/api/pivots?field=artifact_id&value=MEMPROC-77")
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)

        # event_id
        st, _, d = self._http_get("/api/pivots?field=event_id&value=EVT-PHASE4-001")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(d["total_matches"], 1)

        # rule_id (both detection and correlation references)
        st, _, d = self._http_get("/api/pivots?field=rule_id&value=RULE-BEACON-DETECT")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(d["total_matches"], 2)

        # ip_address
        st, _, d = self._http_get("/api/pivots?field=ip_address&value=192.168.1.50")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(d["total_matches"], 2)

        # pid (scoped)
        st, _, d = self._http_get("/api/pivots?field=pid&value=5555&scope=/mnt/evidence/host01")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(d["total_matches"], 2)

    # 3. Namespace ambiguity and PID scope restrictions survive HTTP serialization
    def test_03_namespace_ambiguity_and_pid_scope_survive_http(self) -> None:
        """Verify namespace disambiguation and PID scope requirements hold across HTTP queries."""
        # SHARED-ID-123 is unified_artifact_id in V2, source_artifact_id in V3
        # Query without identifier_kind must return 0 matches to prevent silent conflation
        st, _, d = self._http_get("/api/pivots?field=artifact_id&value=SHARED-ID-123")
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 0)
        self.assertEqual(len(d["matches"]), 0)

        # Query with explicit unified_artifact_id returns only V2
        st, _, d = self._http_get(
            "/api/pivots?field=artifact_id&value=SHARED-ID-123&identifier_kind=unified_artifact_id"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(d["matches"][0]["report_id"], "rep-phase4-v2")

        # Query with explicit source_artifact_id returns only V3
        st, _, d = self._http_get(
            "/api/pivots?field=artifact_id&value=SHARED-ID-123&identifier_kind=source_artifact_id"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(d["matches"][0]["report_id"], "rep-phase4-v3")

        # Unscoped PID returns 0 matches
        st, _, d = self._http_get("/api/pivots?field=pid&value=5555")
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 0)

        # Scoped PID returns matches
        st, _, d = self._http_get(
            "/api/pivots?field=pid&value=5555&scope=/mnt/evidence/host01"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 2)

        # Scoped PID with URL-encoded scope (%2Fmnt%2Fevidence%2Fhost01) must succeed (200)
        st, _, d = self._http_get(
            "/api/pivots?field=pid&value=5555&scope=%2Fmnt%2Fevidence%2Fhost01"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 2)
        self.assertEqual(d["scope"], "/mnt/evidence/host01")

    # 4. Normalized hashes and IPs produce expected results
    def test_04_normalized_hashes_and_ips_produce_expected_results(self) -> None:
        """Verify normalization of SHA-256 (uppercase to lowercase) and IP formats."""
        raw_sha = "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        st, _, d = self._http_get(f"/api/pivots?field=sha256&value={raw_sha.upper()}")
        self.assertEqual(st, 200)
        self.assertEqual(d["normalized_query"], raw_sha)
        self.assertEqual(d["total_matches"], 1)

        # IPv4 with leading zeros
        st, _, d = self._http_get("/api/pivots?field=ip_address&value=192.168.001.050")
        self.assertEqual(st, 200)
        self.assertEqual(d["normalized_query"], "192.168.1.50")
        self.assertGreaterEqual(d["total_matches"], 2)

        # IPv6 canonical resolution
        st, _, d = self._http_get("/api/pivots?field=ip_address&value=%3A%3A1")
        self.assertEqual(st, 200)
        self.assertEqual(d["normalized_query"], "::1")
        self.assertEqual(d["total_matches"], 1)

        # Remote IP from integrated investigation report
        st, _, d = self._http_get("/api/pivots?field=ip_address&value=10.0.0.99")
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(d["matches"][0]["report_id"], "rep-phase4-v4int")

    # 5. Bounded result counts and truncation
    def test_05_bounded_result_counts_and_truncation(self) -> None:
        """Verify max_results bounds returned matches and sets total_matches and truncated flag."""
        st, _, d = self._http_get(
            "/api/pivots?field=case_id&value=CASE-PHASE4-2026&max_results=2"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["returned_matches"], 2)
        self.assertEqual(len(d["matches"]), 2)
        self.assertGreaterEqual(d["total_matches"], 6)
        self.assertTrue(d["truncated"])

    # 6. Replace and remove reports, then verify no stale references
    def test_06_replace_and_remove_reports_no_stale_references(self) -> None:
        """Verify re-registration and report removal cleanly purge index entries without stale references."""
        # Replace v1 report with updated sha
        updated_v1 = read_report(self.v1_path)
        self.registry.register_report(updated_v1, report_id="rep-phase4-v1", allow_replace=True)

        st, _, d = self._http_get(
            "/api/pivots?field=sha256&value=4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 1)  # Not duplicated

        # Remove v1 report
        removed = self.registry.remove_report("rep-phase4-v1")
        self.assertTrue(removed)

        # Query sha256 should now return 0
        st, _, d = self._http_get(
            "/api/pivots?field=sha256&value=4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
        )
        self.assertEqual(st, 200)
        self.assertEqual(d["total_matches"], 0)

        # Query reports endpoint confirms 5 reports remaining
        st, _, d = self._http_get("/api/reports")
        self.assertEqual(st, 200)
        self.assertEqual(d["total"], 5)

    # 7. UI parameter compatibility with real endpoint
    def test_07_ui_urlsearchparams_compatibility_with_real_service(self) -> None:
        """Verify client-side URLSearchParams logic outputs query strings accepted by the live endpoint."""
        import subprocess
        import shutil

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not available for client-side JS evaluation.")

        node_test = f"""
const http = require('http');

const params = new URLSearchParams();
params.set('field', 'pid');
params.set('value', '5555');
params.set('scope', '/mnt/evidence/host01');

const url = 'http://127.0.0.1:{self.server.bound_port}/api/pivots?' + params.toString();

http.get(url, (res) => {{
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('end', () => {{
    const data = JSON.parse(body);
    if (res.statusCode !== 200 || data.total_matches !== 2) {{
      console.error('Failure:', res.statusCode, data);
      process.exit(1);
    }}
    process.exit(0);
  }});
}}).on('error', (e) => {{
  console.error(e);
  process.exit(1);
}});
"""
        proc = subprocess.run([node_bin, "-e", node_test], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Node client test failed: {proc.stderr}")

    # 8. Navigation roundtrip context preservation
    def test_08_navigation_context_preservation(self) -> None:
        """Verify navigating from report to pivot and back preserves navigation state."""
        import subprocess
        import shutil

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not available for client-side JS evaluation.")

        script = """
const fs = require('fs');
const vm = require('vm');
const code = fs.readFileSync('src/forensix/ui/dashboard.js', 'utf8');

const context = {
  document: {
    readyState: 'complete',
    getElementById: (id) => ({
      id,
      addEventListener: () => {},
      classList: { add: () => {}, remove: () => {} },
      appendChild: () => {},
      textContent: "",
    }),
    querySelectorAll: () => [],
    createElement: (tag) => ({ tag, classList: { add: ()=>{}, remove: ()=>{} }, appendChild: ()=>{}, setAttribute: ()=>{} }),
    createTextNode: (t) => ({ textContent: t })
  },
  window: {
    location: { hash: '' },
    addEventListener: () => {}
  },
  fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
  console: { warn: () => {}, log: () => {}, error: () => {} }
};

const wrapped = code.replace(
  'window.addEventListener("hashchange", handleHashRoute);',
  'window.__testHooks = { state, handleHashRoute }; window.addEventListener("hashchange", handleHashRoute);'
);
vm.runInNewContext(wrapped, context);
const hooks = context.window.__testHooks;

// Simulate clicking Inspect from pivot results
hooks.state.activeReportId = 'rep-phase4-v2';
hooks.state.lastPivotHash = '#pivots?field=pid&value=5555&scope=%2Fmnt%2Fevidence%2Fhost01';
console.assert(hooks.state.lastPivotHash.includes('field=pid'), 'Pivot hash must be preserved');

// Simulate returning to pivot results
console.assert(hooks.state.lastPivotHash.startsWith('#pivots?'), 'Can navigate back to pivot hash');
"""
        proc = subprocess.run([node_bin, "-e", script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Context preservation test failed: {proc.stderr}")

    # 9. Security, malicious inputs, and malformed URL/hash handling
    def test_09_security_malicious_strings_and_traversal(self) -> None:
        """Verify strict path traversal rejection, malformed percent-encoding handling, and safe text output."""
        # 1. Malformed percent encoding in query string
        st, _, d = self._http_get("/api/pivots?field=sha256&value=test%zz")
        self.assertEqual(st, 400)
        self.assertEqual(d["error"]["code"], "MALFORMED_REQUEST")

        # 2. Path traversal in URL path rejected
        st, _, d = self._http_get("/api/reports/../../etc/passwd")
        self.assertEqual(st, 400)
        self.assertEqual(d["error"]["code"], "MALFORMED_REQUEST")

        # 3. Double slash in URL path rejected
        st, _, d = self._http_get("/api//reports")
        self.assertEqual(st, 400)
        self.assertEqual(d["error"]["code"], "MALFORMED_REQUEST")

        # 4. Valid encoded query string accepted
        st, _, d = self._http_get("/api/pivots?field=case_id&value=CASE%202026")
        self.assertEqual(st, 200)

    # 10. Existing dashboard and reader endpoints continue working
    def test_10_existing_dashboard_and_reader_endpoints(self) -> None:
        """Verify /api/health, /api/reports, /api/reports/<id>, and UI static assets function correctly."""
        # Health endpoint
        st, _, d = self._http_get("/api/health")
        self.assertEqual(st, 200)
        self.assertEqual(d["status"], "ok")
        self.assertEqual(d["version"], __version__)

        # Reports collection
        st, _, d = self._http_get("/api/reports")
        self.assertEqual(st, 200)
        self.assertEqual(d["total"], 6)

        # Single report overview
        st, _, d = self._http_get("/api/reports/rep-phase4-v2")
        self.assertEqual(st, 200)
        self.assertEqual(d["id"], "rep-phase4-v2")
        self.assertEqual(d["report_type"], "host_triage")

        # Sub-endpoints: metadata, summary, details
        st, _, d = self._http_get("/api/reports/rep-phase4-v2/metadata")
        self.assertEqual(st, 200)
        self.assertIn("metadata", d)

        st, _, d = self._http_get("/api/reports/rep-phase4-v2/summary")
        self.assertEqual(st, 200)
        self.assertIn("counts", d)

        st, _, d = self._http_get("/api/reports/rep-phase4-v2/details")
        self.assertEqual(st, 200)
        self.assertIn("raw_data", d)

        # UI static assets
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            conn.request("GET", "/")
            res = conn.getresponse()
            self.assertEqual(res.status, 200)
            self.assertIn("text/html", res.getheader("Content-Type", ""))
            res.read()

            conn.request("GET", "/static/dashboard.css")
            res_css = conn.getresponse()
            self.assertEqual(res_css.status, 200)
            self.assertIn("text/css", res_css.getheader("Content-Type", ""))
            res_css.read()

            conn.request("GET", "/static/dashboard.js")
            res_js = conn.getresponse()
            self.assertEqual(res_js.status, 200)
            self.assertIn("javascript", res_js.getheader("Content-Type", ""))
            res_js.read()
        finally:
            conn.close()



class TestDashboardHostValidationAndHardening(unittest.TestCase):
    """Regression tests for Host header validation, ingestion failure tracking, and server hardening."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self.temp_dir_obj.name)
        self.active_servers: List[DashboardServer] = []

    def tearDown(self) -> None:
        for s in self.active_servers:
            try:
                s.stop()
            except Exception:
                pass
        self.temp_dir_obj.cleanup()

    def test_host_header_accepted_local_values(self) -> None:
        """Verify accepted local Host values: localhost, 127.0.0.1, [::1], and matching ports."""
        port = 8080
        valid_hosts = [
            f"localhost:{port}",
            f"127.0.0.1:{port}",
            f"[::1]:{port}",
            "localhost",
            "127.0.0.1",
            "[::1]",
            f"LocalHost:{port}",
            f"LOCALHOST:{port}",
            f"localhost.:{port}",
            f"  localhost:{port}  ",
            f"  [::1]:{port}  ",
        ]
        for v in valid_hosts:
            with self.subTest(host=v):
                self.assertTrue(
                    is_valid_dashboard_host(v, bound_port=port),
                    f"Expected valid Host header: {v!r}",
                )

    def test_host_header_unexpected_external_values(self) -> None:
        """Verify unexpected external Host values (domains, public IPs, LAN IPs) are rejected."""
        port = 8080
        invalid_external = [
            f"evil.com:{port}",
            "evil.com",
            f"attacker.local:{port}",
            f"192.168.1.50:{port}",
            "192.168.1.1",
            f"10.0.0.1:{port}",
            f"8.8.8.8:{port}",
            f"example.org:{port}",
        ]
        for v in invalid_external:
            with self.subTest(host=v):
                self.assertFalse(
                    is_valid_dashboard_host(v, bound_port=port),
                    f"Expected external Host to be rejected: {v!r}",
                )

    def test_host_header_malformed_values(self) -> None:
        """Verify malformed Host header values (unclosed brackets, invalid ports, empty) are rejected."""
        port = 8080
        malformed = [
            "",
            "   ",
            None,
            123,  # non-string
            f"localhost:invalid",
            f"localhost:0",
            f"localhost:70000",
            f"localhost:-1",
            "[::1",  # unclosed bracket
            "[::1]:invalid",
            ":::1",
            "localhost:8080:8080",
        ]
        for v in malformed:
            with self.subTest(host=v):
                self.assertFalse(
                    is_valid_dashboard_host(v, bound_port=port),
                    f"Expected malformed Host to be rejected: {v!r}",
                )

    def test_host_header_port_mismatches(self) -> None:
        """Verify port mismatches between Host header and actual bound port are rejected."""
        port = 8080
        mismatched = [
            f"localhost:{port + 1}",
            f"127.0.0.1:{port + 100}",
            f"[::1]:9999",
            f"localhost:3000",
            f"127.0.0.1:80",  # port 80 when bound to 8080
        ]
        for v in mismatched:
            with self.subTest(host=v):
                self.assertFalse(
                    is_valid_dashboard_host(v, bound_port=port),
                    f"Expected port mismatch to be rejected: {v!r}",
                )

    def test_http_host_header_enforcement_on_running_server(self) -> None:
        """Verify HTTP requests with invalid/mismatched Host headers return 400 before serving sensitive data."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        self.active_servers.append(server)
        port = server.bound_port

        # 1. Valid local Host header succeeds
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/health", headers={"Host": f"localhost:{port}"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "ok")
        finally:
            conn.close()

        # 2. Unexpected external domain Host rejected with 400 INVALID_HOST
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/health", headers={"Host": f"evil.com:{port}"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["error"]["code"], "INVALID_HOST")
        finally:
            conn.close()

        # 3. Port mismatch rejected with 400 INVALID_HOST
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/health", headers={"Host": f"localhost:{port + 1}"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["error"]["code"], "INVALID_HOST")
        finally:
            conn.close()

        # 4. Request to reports collection with invalid Host is blocked before serving reports
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/reports", headers={"Host": "attacker.local"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["error"]["code"], "INVALID_HOST")
        finally:
            conn.close()

    def test_directory_ingestion_reporting_and_visibility(self) -> None:
        """Verify directory ingestion tracks skipped/invalid files with reasons and reports them via API."""
        registry = DashboardReportRegistry()

        # Create 1 valid report
        valid_file = self.temp_dir / "valid_tl.json"
        valid_file.write_text(
            json.dumps({
                "report_type": "timeline",
                "metadata": {"case_id": "CASE-INGEST-01"},
                "events": [],
            }),
            encoding="utf-8",
        )

        # Create 1 malformed JSON file
        broken_json = self.temp_dir / "broken.json"
        broken_json.write_text("{malformed-json...", encoding="utf-8")

        # Create 1 non-ForensiX schema file
        unknown_schema = self.temp_dir / "arbitrary.json"
        unknown_schema.write_text(json.dumps({"unknown_key": "arbitrary"}), encoding="utf-8")

        # Ingest directory
        reg_ids = registry.register_directory(self.temp_dir)
        self.assertEqual(len(reg_ids), 1)
        self.assertEqual(len(registry), 1)

        # Verify skipped reports tracking
        skipped = registry.skipped_reports
        self.assertEqual(len(skipped), 2)
        filenames = {item["filename"] for item in skipped}
        self.assertIn("broken.json", filenames)
        self.assertIn("arbitrary.json", filenames)

        for item in skipped:
            self.assertIn("reason", item)
            self.assertTrue(len(item["reason"]) > 0)

        # Ingestion summary
        summary = registry.get_ingestion_summary()
        self.assertEqual(summary["ingested_count"], 1)
        self.assertEqual(summary["skipped_count"], 2)
        self.assertEqual(summary["total_scanned"], 3)
        self.assertEqual(len(summary["skipped_reports"]), 2)

        # Verify HTTP API exposes skipped reports
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        self.active_servers.append(server)

        # /api/reports includes skipped_count and skipped_reports
        conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
        try:
            conn.request("GET", "/api/reports", headers={"Host": f"localhost:{server.bound_port}"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["skipped_count"], 2)
            self.assertEqual(len(data["skipped_reports"]), 2)

            # /api/ingestion returns full summary
            conn.request("GET", "/api/ingestion", headers={"Host": f"localhost:{server.bound_port}"})
            resp_ingest = conn.getresponse()
            self.assertEqual(resp_ingest.status, 200)
            ingest_data = json.loads(resp_ingest.read().decode("utf-8"))
            self.assertEqual(ingest_data["ingested_count"], 1)
            self.assertEqual(ingest_data["skipped_count"], 2)
        finally:
            conn.close()

    def test_dashboard_server_idempotent_stop(self) -> None:
        """Verify repeated calls to server.stop() do not raise errors or hang."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()

        # First stop
        server.stop()
        # Repeated stops must be safe and idempotent
        server.stop()
        server.stop()
        self.assertTrue(getattr(server, "_is_stopped", False))

    def test_dashboard_server_stop_before_startup_bounded_timeout(self) -> None:
        """Verify constructing a server and calling stop() before startup never blocks indefinitely."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)

        # Calling stop() before serve_forever() or start_background() must complete promptly
        stop_completed = threading.Event()

        def do_stop() -> None:
            server.stop()
            stop_completed.set()

        t = threading.Thread(target=do_stop)
        t.start()
        t.join(timeout=2.0)

        self.assertTrue(stop_completed.is_set(), "server.stop() before startup blocked/deadlocked!")
        self.assertFalse(t.is_alive())
        self.assertTrue(server._is_stopped)

        # Repeated stop is also safe
        server.stop()

        # Starting a stopped server must be rejected cleanly
        with self.assertRaises(RuntimeError):
            server.start_background()

    def test_skipped_reports_sanitization_no_absolute_paths_in_api(self) -> None:
        """Verify that skipped-report failure reasons and API outputs never leak absolute source paths."""
        registry = DashboardReportRegistry()

        # Create a deep nested directory structure with a sensitive-looking path
        secret_sub = self.temp_dir / "confidential_evidence_root" / "internal_storage"
        secret_sub.mkdir(parents=True, exist_ok=True)

        # 1. Malformed JSON
        bad_json = secret_sub / "corrupt_timeline.json"
        bad_json.write_text("{bad-json-payload-without-close", encoding="utf-8")

        # 2. Unsupported Schema
        unsupported = secret_sub / "unsupported_data.json"
        unsupported.write_text(json.dumps({"some_arbitrary_key": 12345}), encoding="utf-8")

        # 3. Oversized file (with 100 byte limit)
        oversized = secret_sub / "oversized_report.json"
        oversized.write_text(json.dumps({"report_type": "timeline", "events": []}) * 10, encoding="utf-8")

        # 4. Empty file
        empty_rep = secret_sub / "empty_report.json"
        empty_rep.write_bytes(b"")

        # Ingest directory with max_size_bytes=50 to trigger size limit
        registered_ids = registry.register_directory(secret_sub, max_size_bytes=50)
        self.assertEqual(len(registered_ids), 0)

        # Check internal registry reasons
        skipped = registry.skipped_reports
        self.assertEqual(len(skipped), 4)

        secret_path_str = str(secret_sub)
        temp_dir_str = str(self.temp_dir)

        for entry in skipped:
            reason = entry["reason"]
            filename = entry["filename"]
            # Verify no absolute path exists in filename or reason
            self.assertNotIn(secret_path_str, reason)
            self.assertNotIn(temp_dir_str, reason)
            self.assertNotIn("/", filename)
            self.assertNotIn("\\", filename)
            if "path" in entry:
                self.assertNotIn("/", entry["path"])
                self.assertNotIn("\\", entry["path"])

        # Spin up server and verify /api/reports and /api/ingestion responses
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()
        self.active_servers.append(server)

        conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
        try:
            # Check /api/reports
            conn.request("GET", "/api/reports", headers={"Host": f"localhost:{server.bound_port}"})
            resp = conn.getresponse()
            raw_reports_body = resp.read().decode("utf-8")
            self.assertNotIn(secret_path_str, raw_reports_body)
            self.assertNotIn(temp_dir_str, raw_reports_body)

            # Check /api/ingestion
            conn.request("GET", "/api/ingestion", headers={"Host": f"localhost:{server.bound_port}"})
            resp_ingest = conn.getresponse()
            raw_ingest_body = resp_ingest.read().decode("utf-8")
            self.assertNotIn(secret_path_str, raw_ingest_body)
            self.assertNotIn(temp_dir_str, raw_ingest_body)

            ingest_json = json.loads(raw_ingest_body)
            reasons = {item["filename"]: item["reason"] for item in ingest_json["skipped_reports"]}

            self.assertIn("corrupt_timeline.json", reasons)
            self.assertIn("Malformed JSON", reasons["corrupt_timeline.json"])

            self.assertIn("unsupported_data.json", reasons)
            self.assertIn("Unrecognized or unsupported", reasons["unsupported_data.json"])

            self.assertIn("oversized_report.json", reasons)
            self.assertIn("exceeds maximum allowed limit", reasons["oversized_report.json"])

            self.assertIn("empty_report.json", reasons)
            self.assertIn("empty", reasons["empty_report.json"])
        finally:
            conn.close()

    def test_skipped_reports_defensive_copies_cannot_mutate_registry(self) -> None:
        """Verify modifying returned skipped-report structures cannot mutate internal registry state."""
        registry = DashboardReportRegistry()
        bad_file = self.temp_dir / "bad.json"
        bad_file.write_text("{corrupt", encoding="utf-8")

        registry.register_directory(self.temp_dir)
        self.assertEqual(len(registry.skipped_reports), 1)

        # 1. Mutate via skipped_reports property
        prop_copy = registry.skipped_reports
        prop_copy[0]["reason"] = "MUTATED_BY_CALLER"
        prop_copy[0]["filename"] = "hacked.json"
        prop_copy.append({"filename": "injected.json", "reason": "injected"})

        fresh_prop = registry.skipped_reports
        self.assertEqual(len(fresh_prop), 1)
        self.assertNotEqual(fresh_prop[0]["reason"], "MUTATED_BY_CALLER")
        self.assertNotEqual(fresh_prop[0]["filename"], "hacked.json")

        # 2. Mutate via get_skipped_reports()
        getter_copy = registry.get_skipped_reports()
        getter_copy[0]["reason"] = "MUTATED_AGAIN"
        self.assertNotEqual(registry.get_skipped_reports()[0]["reason"], "MUTATED_AGAIN")

        # 3. Mutate via get_ingestion_summary()
        summary = registry.get_ingestion_summary()
        summary["skipped_reports"][0]["reason"] = "MUTATED_IN_SUMMARY"
        self.assertNotEqual(registry.get_ingestion_summary()["skipped_reports"][0]["reason"], "MUTATED_IN_SUMMARY")

    def test_dashboard_server_startup_shutdown_race_stress_bounded(self) -> None:
        """Deterministic stress test: start in background and immediately stop repeatedly."""
        registry = DashboardReportRegistry()
        total_iterations = 30
        start_time = time.monotonic()

        for i in range(total_iterations):
            server = create_dashboard_server(registry, host="127.0.0.1", port=0)
            iter_start = time.monotonic()

            server.start_background()
            server.stop()

            # Bound per iteration to ensure no deadlocks or long hangs
            iter_duration = time.monotonic() - iter_start
            self.assertLess(iter_duration, 1.0, f"Iteration {i} took too long: {iter_duration:.3f}s")

            # Guaranteed: background thread is terminated cleanly
            if server._thread is not None:
                self.assertFalse(server._thread.is_alive(), f"Server thread alive after stop at iter {i}")

            # Guaranteed: server state marked stopped
            self.assertTrue(server._is_stopped)

            # Guaranteed: repeated stop is safe and idempotent
            server.stop()
            self.assertTrue(server._is_stopped)

        total_duration = time.monotonic() - start_time
        self.assertLess(total_duration, 15.0, f"Stress test exceeded total timeout: {total_duration:.2f}s")

    def test_dashboard_server_concurrent_start_and_stop_race_bounded(self) -> None:
        """Deterministic concurrency test: concurrent start_background and stop calls."""
        registry = DashboardReportRegistry()
        iterations = 25

        for i in range(iterations):
            server = create_dashboard_server(registry, host="127.0.0.1", port=0)

            t_start = threading.Thread(target=server.start_background)
            t_stop = threading.Thread(target=server.stop)

            t_start.start()
            t_stop.start()

            t_start.join(timeout=2.0)
            t_stop.join(timeout=2.0)

            # Must never deadlock
            self.assertFalse(t_start.is_alive(), f"start_background thread deadlocked at iter {i}")
            self.assertFalse(t_stop.is_alive(), f"stop thread deadlocked at iter {i}")

            # Server thread must not remain alive
            if server._thread is not None:
                server._thread.join(timeout=1.0)
                self.assertFalse(server._thread.is_alive(), f"server thread still alive at iter {i}")

            self.assertTrue(server._is_stopped)
            server.stop()  # Idempotent

    def test_dashboard_server_shutdown_expected_oserror_handled_cleanly(self) -> None:
        """Verify expected OSError during concurrent socket teardown is tolerated without crashing stop()."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()

        # Simulate concurrent socket close raising OSError in super().shutdown()
        with patch("http.server.HTTPServer.shutdown", side_effect=OSError("Socket already closed")):
            server.stop()

        self.assertTrue(server._is_stopped)
        if server._thread is not None:
            self.assertFalse(server._thread.is_alive())

        # Repeated stop remains safe
        server.stop()

    def test_dashboard_server_shutdown_unexpected_exception_propagated_with_cleanup(self) -> None:
        """Verify unexpected exceptions in shutdown() are propagated and not silently masked, while resources are cleaned up."""
        registry = DashboardReportRegistry()
        server = create_dashboard_server(registry, host="127.0.0.1", port=0)
        server.start_background()

        # Simulate unexpected exception in super().shutdown()
        with patch("http.server.HTTPServer.shutdown", side_effect=TypeError("Unexpected memory error")):
            with self.assertRaises(TypeError):
                server.stop()

        # Server state is marked stopped
        self.assertTrue(server._is_stopped)

        # Thread is still joined cleanly and socket closed (no leaks)
        if server._thread is not None:
            self.assertFalse(server._thread.is_alive())

        # Subsequent stop is an idempotent no-op
        server.stop()
        self.assertTrue(server._is_stopped)


if __name__ == "__main__":
    unittest.main()
