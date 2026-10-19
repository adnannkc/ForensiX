"""
Comprehensive Test Suite for ForensiX Milestone V7.1 — Read-Only Report Ingestion Layer.

Verifies:
1.  Ingestion of all recognized ForensiX report schemas:
    - V1 Single-File Evidence Analysis
    - V2 Host Triage ForensicReport
    - V3 Chronological TimelineReport
    - V4 Standalone DetectionReport
    - V4 Standalone CorrelationReport
    - V4/V5/V6 Integrated CorrelationDetectionReport
2.  Accurate schema detection and validation.
3.  Rejection of unknown, ambiguous, or incomplete schemas.
4.  Rejection of malformed or corrupted JSON.
5.  Handling of empty files, empty JSON objects, and missing sections.
6.  Handling of missing optional metadata without errors.
7.  Handling of missing report files, directories, and broken symlinks.
8.  Strict enforcement of input-size limits.
9.  Safe resolution and handling of symlinks and relative paths.
10. Preservation of source path, file size, and cryptographic SHA-256.
11. Strict read-only immutability of input report files.
12. Stable and accurate summary counts.
13. Seamless round-trip compatibility with existing ForensiX serializers.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import types
import unittest
from unittest.mock import MagicMock, patch
import uuid

from forensix.report_reader import (
    DEFAULT_MAX_REPORT_SIZE_BYTES,
    CaseMetadataView,
    IngestedReport,
    ReportInvalidFileError,
    ReportNotFoundError,
    ReportParseError,
    ReportReaderError,
    ReportSchemaError,
    ReportSizeLimitError,
    ReportSummaryCounts,
    ReportType,
    detect_report_schema,
    freeze_payload,
    read_report,
    unfreeze_payload,
)


class TestReportReader(unittest.TestCase):
    """Test suite for V7.1 read-only report ingestion layer."""

    def setUp(self) -> None:
        """Create a temporary sandbox directory for test fixtures."""
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="forensix_test_v71_")
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

    # =========================================================================
    # 1. Supported Schema Detection & Ingestion
    # =========================================================================

    def test_01_read_v1_evidence_analysis_report(self) -> None:
        """Verify ingestion of V1 single-file analysis JSON reports."""
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
        }
        report_path = self._write_json("v1_report.json", v1_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.EVIDENCE_ANALYSIS)
        self.assertTrue(ingested.is_evidence_analysis)
        self.assertFalse(ingested.is_timeline)
        self.assertEqual(ingested.source_path, report_path.resolve())
        self.assertEqual(ingested.metadata.report_id, "EV-387d74e8-af84-4205-9199-76d03c3c9f32")
        self.assertEqual(ingested.metadata.evidence_root, "/var/log/evidence.bin")
        self.assertEqual(ingested.metadata.created_at, "2026-10-01T12:00:00+00:00")
        self.assertEqual(ingested.counts.artifact_count, 1)
        self.assertEqual(ingested.counts.event_count, 0)

        # Also verify with on-disk V1 report in reports/ if present
        repo_v1 = Path("reports/EV-80a7a18d-6fe5-4241-a739-3ffa70ece3b0.json")
        if repo_v1.exists():
            repo_ingested = read_report(repo_v1)
            self.assertEqual(repo_ingested.report_type, ReportType.EVIDENCE_ANALYSIS)
            self.assertEqual(repo_ingested.metadata.report_id, "EV-80a7a18d-6fe5-4241-a739-3ffa70ece3b0")
            self.assertEqual(repo_ingested.counts.artifact_count, 1)

    def test_02_read_v2_host_triage_report(self) -> None:
        """Verify ingestion of V2 automated host triage ForensicReport JSON."""
        v2_data = {
            "metadata": {
                "report_id": "REPORT-2f0858e7-f8e1-45ab-858a-aef234f95b5c",
                "case_id": "CASE-2026-001",
                "case_name": "Host Compromise Triage",
                "investigator": "Forensic Lead",
                "created_at": "2026-10-01T15:30:00Z",
                "forensix_version": "5.0.0",
                "evidence_root": "/mnt/evidence/host01",
                "report_format": "json",
                "triage_id": "TRIAGE-937dcfe0-65ea-44a0-ba07-2c9398f5a544",
            },
            "summary": {
                "total_artifacts": 2,
                "category_breakdown": {"filesystem": 1, "log": 1},
                "status_breakdown": {"SUCCESS": 2},
                "audit_events_count": 3,
            },
            "artifacts": [
                {
                    "unified_id": "HOSTART-01",
                    "source_id": "ART-01",
                    "category": "filesystem",
                    "artifact_type": "file_record",
                    "source_path": "/etc/passwd",
                    "line_number": None,
                    "raw_data": None,
                    "status": "SUCCESS",
                    "warnings": [],
                    "specialized_payload": {},
                },
                {
                    "unified_id": "HOSTART-02",
                    "source_id": "EVT-01",
                    "category": "log",
                    "artifact_type": "syslog_entry",
                    "source_path": "/var/log/syslog",
                    "line_number": 10,
                    "raw_data": "systemd started",
                    "status": "SUCCESS",
                    "warnings": [],
                    "specialized_payload": {},
                },
            ],
            "audit_trail": [
                {
                    "audit_id": "AUDIT-01",
                    "event_type": "TRIAGE_STARTED",
                    "timestamp": "2026-10-01T15:00:00Z",
                    "description": "Triage started",
                },
                {
                    "audit_id": "AUDIT-02",
                    "event_type": "ARTIFACT_COLLECTION_COMPLETED",
                    "timestamp": "2026-10-01T15:10:00Z",
                    "description": "Artifacts collected",
                },
                {
                    "audit_id": "AUDIT-03",
                    "event_type": "TRIAGE_COMPLETED",
                    "timestamp": "2026-10-01T15:20:00Z",
                    "description": "Triage finished",
                },
            ],
        }
        report_path = self._write_json("v2_report.json", v2_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.HOST_TRIAGE)
        self.assertTrue(ingested.is_triage)
        self.assertEqual(ingested.metadata.case_id, "CASE-2026-001")
        self.assertEqual(ingested.metadata.case_name, "Host Compromise Triage")
        self.assertEqual(ingested.metadata.investigator, "Forensic Lead")
        self.assertEqual(ingested.metadata.report_id, "REPORT-2f0858e7-f8e1-45ab-858a-aef234f95b5c")
        self.assertEqual(ingested.metadata.triage_id, "TRIAGE-937dcfe0-65ea-44a0-ba07-2c9398f5a544")
        self.assertEqual(ingested.metadata.evidence_root, "/mnt/evidence/host01")
        self.assertEqual(ingested.counts.artifact_count, 2)
        self.assertEqual(ingested.counts.audit_event_count, 3)
        self.assertEqual(ingested.counts.event_count, 0)

    def test_03_read_v3_timeline_report(self) -> None:
        """Verify ingestion of V3 chronological TimelineReport JSON."""
        v3_data = {
            "report_type": "timeline",
            "report_version": "3.6",
            "forensix_version": "5.0.0",
            "metadata": {
                "case_id": "CASE-V3-TEST",
                "case_name": "Timeline Reconstruction Test",
                "investigator": "Analyst Alice",
                "generated_at": "2026-10-02T10:00:00Z",
                "query": None,
            },
            "summary": {
                "event_count": 2,
                "categories": {"filesystem": 1, "log": 1},
                "event_types": {"file_modified": 1, "service_start": 1},
                "timestamp_coverage": {"total_events": 2, "timestamped_events": 2},
            },
            "events": [
                {
                    "event_id": "TIMELINE-01",
                    "timestamp": "2026-10-02T08:00:00Z",
                    "raw_timestamp": "2026-10-02T08:00:00Z",
                    "category": "filesystem",
                    "event_type": "file_modified",
                    "description": "File modified",
                    "source_path": "/etc/shadow",
                    "source_line": 1,
                    "source_artifact_id": "ART-01",
                    "source_event_id": None,
                    "raw_data": None,
                    "attributes": {},
                },
                {
                    "event_id": "TIMELINE-02",
                    "timestamp": "2026-10-02T08:05:00Z",
                    "raw_timestamp": "2026-10-02T08:05:00Z",
                    "category": "log",
                    "event_type": "service_start",
                    "description": "SSH service started",
                    "source_path": "/var/log/auth.log",
                    "source_line": 42,
                    "source_artifact_id": "ART-02",
                    "source_event_id": "EVT-02",
                    "raw_data": "sshd started",
                    "attributes": {},
                },
            ],
        }
        report_path = self._write_json("v3_report.json", v3_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.TIMELINE)
        self.assertTrue(ingested.is_timeline)
        self.assertEqual(ingested.metadata.case_id, "CASE-V3-TEST")
        self.assertEqual(ingested.metadata.investigator, "Analyst Alice")
        self.assertEqual(ingested.counts.event_count, 2)
        self.assertEqual(ingested.counts.detection_count, 0)
        self.assertEqual(ingested.counts.correlation_count, 0)

        # Also verify with on-disk V3 report in reports/
        repo_v3 = Path("reports/v3_manual_timeline.json")
        if repo_v3.exists():
            repo_ingested = read_report(repo_v3)
            self.assertEqual(repo_ingested.report_type, ReportType.TIMELINE)
            self.assertEqual(repo_ingested.metadata.case_id, "CASE-V3-MANUAL-JSON")
            self.assertEqual(repo_ingested.counts.event_count, 2)

    def test_04_read_v4_standalone_detection_report(self) -> None:
        """Verify ingestion of V4 standalone DetectionReport JSON."""
        det_data = {
            "report_type": "detection",
            "report_version": "4.6",
            "forensix_version": "5.0.0",
            "metadata": {
                "case_id": "CASE-DET-01",
                "case_name": "Detection Only",
                "investigator": "Examiner Bob",
                "generated_at": "2026-10-03T12:00:00Z",
            },
            "summary": {
                "total_detections": 2,
                "matched_detections": 1,
                "rule_counts": {"RULE-01": 2},
            },
            "detections": [
                {
                    "detection_id": "DET-01",
                    "rule_id": "RULE-01",
                    "rule_name": "SSH Brute Force",
                    "matched": True,
                    "matched_event_ids": ["TIMELINE-01"],
                    "matched_source_event_ids": [],
                    "matched_source_artifact_ids": [],
                    "matched_correlation_ids": [],
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "time_delta_seconds": None,
                    "explanation": "Observed multiple SSH failures",
                    "attributes": {},
                },
                {
                    "detection_id": "DET-02",
                    "rule_id": "RULE-01",
                    "rule_name": "SSH Brute Force",
                    "matched": False,
                    "matched_event_ids": ["TIMELINE-02"],
                    "matched_source_event_ids": [],
                    "matched_source_artifact_ids": [],
                    "matched_correlation_ids": [],
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "time_delta_seconds": None,
                    "explanation": "Condition not met",
                    "attributes": {},
                },
            ],
        }
        report_path = self._write_json("detection_report.json", det_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.DETECTION)
        self.assertEqual(ingested.metadata.case_id, "CASE-DET-01")
        self.assertEqual(ingested.counts.detection_count, 2)
        self.assertEqual(ingested.counts.matched_detection_count, 1)
        self.assertEqual(ingested.counts.correlation_count, 0)
        self.assertEqual(ingested.counts.event_count, 0)

    def test_05_read_v4_standalone_correlation_report(self) -> None:
        """Verify ingestion of V4 standalone CorrelationReport JSON."""
        corr_data = {
            "report_type": "correlation",
            "report_version": "4.6",
            "forensix_version": "5.0.0",
            "metadata": {
                "case_id": "CASE-CORR-01",
                "case_name": "Correlation Only",
                "investigator": "Examiner Carol",
                "generated_at": "2026-10-03T13:00:00Z",
            },
            "summary": {
                "total_correlations": 1,
                "relationship_counts": {"SAME_USER": 1},
            },
            "correlations": [
                {
                    "correlation_id": "CORR-01",
                    "relationship_type": "SAME_USER",
                    "event_ids": ["TIMELINE-01", "TIMELINE-02"],
                    "source_event_ids": [],
                    "source_artifact_ids": [],
                    "start_timestamp": "2026-10-03T10:00:00Z",
                    "end_timestamp": "2026-10-03T10:05:00Z",
                    "time_delta_seconds": 300.0,
                    "description": "Events share user root",
                    "attributes": {},
                }
            ],
        }
        report_path = self._write_json("correlation_report.json", corr_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.CORRELATION)
        self.assertEqual(ingested.metadata.case_id, "CASE-CORR-01")
        self.assertEqual(ingested.counts.correlation_count, 1)
        self.assertEqual(ingested.counts.detection_count, 0)
        self.assertEqual(ingested.counts.event_count, 0)

    def test_06_read_v4_v5_v6_investigation_report(self) -> None:
        """Verify ingestion of V4/V5/V6 integrated CorrelationDetectionReport JSON."""
        inv_data = {
            "report_type": "correlation_detection",
            "report_version": "4.6",
            "forensix_version": "5.0.0",
            "metadata": {
                "case_id": "CASE-INV-99",
                "case_name": "Integrated Investigation Test",
                "investigator": "Senior Analyst",
                "generated_at": "2026-10-04T09:00:00Z",
            },
            "summary": {
                "event_count": 3,
                "correlation_count": 1,
                "detection_count": 2,
                "matched_detections": 1,
                "rule_counts": {"RULE-01": 2},
                "relationship_counts": {"SAME_USER": 1},
            },
            "detections": [
                {
                    "detection_id": "DET-01",
                    "rule_id": "RULE-01",
                    "rule_name": "SSH Sudo Execution",
                    "matched": True,
                    "matched_event_ids": ["TIMELINE-01", "TIMELINE-02"],
                    "matched_source_event_ids": [],
                    "matched_source_artifact_ids": [],
                    "matched_correlation_ids": ["CORR-01"],
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "time_delta_seconds": None,
                    "explanation": "Matched SSH sudo rule",
                    "attributes": {},
                },
                {
                    "detection_id": "DET-02",
                    "rule_id": "RULE-02",
                    "rule_name": "Cron Persistence",
                    "matched": False,
                    "matched_event_ids": ["TIMELINE-03"],
                    "matched_source_event_ids": [],
                    "matched_source_artifact_ids": [],
                    "matched_correlation_ids": [],
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "time_delta_seconds": None,
                    "explanation": "No persistence observed",
                    "attributes": {},
                },
            ],
            "correlations": [
                {
                    "correlation_id": "CORR-01",
                    "relationship_type": "SAME_USER",
                    "event_ids": ["TIMELINE-01", "TIMELINE-02"],
                    "source_event_ids": [],
                    "source_artifact_ids": [],
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "time_delta_seconds": None,
                    "description": "Same user observed",
                    "attributes": {},
                }
            ],
            "timeline_events": [
                {
                    "event_id": "TIMELINE-01",
                    "timestamp": "2026-10-04T08:00:00Z",
                    "raw_timestamp": "2026-10-04T08:00:00Z",
                    "category": "authentication",
                    "event_type": "ssh_login",
                    "description": "SSH Login",
                    "source_path": "/var/log/auth.log",
                    "source_line": 1,
                    "source_artifact_id": "ART-01",
                    "source_event_id": "EVT-01",
                    "raw_data": "Accepted publickey",
                    "attributes": {},
                },
                {
                    "event_id": "TIMELINE-02",
                    "timestamp": "2026-10-04T08:01:00Z",
                    "raw_timestamp": "2026-10-04T08:01:00Z",
                    "category": "authentication",
                    "event_type": "sudo_elevation",
                    "description": "Sudo Elevation",
                    "source_path": "/var/log/auth.log",
                    "source_line": 2,
                    "source_artifact_id": "ART-01",
                    "source_event_id": "EVT-02",
                    "raw_data": "COMMAND=/bin/bash",
                    "attributes": {},
                },
                {
                    "event_id": "TIMELINE-03",
                    "timestamp": "2026-10-04T08:05:00Z",
                    "raw_timestamp": "2026-10-04T08:05:00Z",
                    "category": "persistence",
                    "event_type": "cron_entry",
                    "description": "Cron checked",
                    "source_path": "/etc/crontab",
                    "source_line": 5,
                    "source_artifact_id": "ART-02",
                    "source_event_id": None,
                    "raw_data": None,
                    "attributes": {},
                },
            ],
        }
        report_path = self._write_json("investigation_report.json", inv_data)

        ingested = read_report(report_path)

        self.assertEqual(ingested.report_type, ReportType.CORRELATION_DETECTION)
        self.assertTrue(ingested.is_investigation)
        self.assertEqual(ingested.metadata.case_id, "CASE-INV-99")
        self.assertEqual(ingested.counts.event_count, 3)
        self.assertEqual(ingested.counts.correlation_count, 1)
        self.assertEqual(ingested.counts.detection_count, 2)
        self.assertEqual(ingested.counts.matched_detection_count, 1)

        # Also verify with on-disk triage_investigation.json
        repo_inv = Path("reports/triage_investigation.json")
        if repo_inv.exists():
            repo_ingested = read_report(repo_inv)
            self.assertEqual(repo_ingested.report_type, ReportType.CORRELATION_DETECTION)
            self.assertEqual(repo_ingested.counts.detection_count, 5)
            self.assertEqual(repo_ingested.counts.matched_detection_count, 5)
            self.assertEqual(repo_ingested.counts.event_count, 10)
            self.assertEqual(repo_ingested.counts.correlation_count, 114)

    # =========================================================================
    # 2. Schema Rejection & Error Handling
    # =========================================================================

    def test_07_unknown_or_ambiguous_schema_rejection(self) -> None:
        """Verify clear rejection of unknown schemas or arbitrary JSON dictionaries."""
        # Arbitrary object
        p1 = self._write_json("unknown_dict.json", {"foo": "bar", "data": [1, 2, 3]})
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(p1)
        self.assertIn("Unrecognized or unsupported ForensiX report schema", str(ctx.exception))

        # Root is a list
        p2 = self._write_json("list_root.json", [{"item": 1}, {"item": 2}])
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(p2)
        self.assertIn("must be an object/dict", str(ctx.exception))

        # Unknown report_type
        p3 = self._write_json("bad_report_type.json", {"report_type": "threat_intel_feed"})
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(p3)
        self.assertIn("Unrecognized 'report_type' value: 'threat_intel_feed'", str(ctx.exception))

    def test_08_malformed_json_rejection(self) -> None:
        """Verify actionable rejection of malformed or truncated JSON."""
        bad_json_path = self.temp_dir / "truncated.json"
        bad_json_path.write_text('{"report_type": "timeline", "events": [', encoding="utf-8")

        with self.assertRaises(ReportParseError) as ctx:
            read_report(bad_json_path)
        self.assertIn("Malformed JSON", str(ctx.exception))

    def test_09_empty_and_incomplete_reports(self) -> None:
        """Verify rejection of empty files, empty objects, and missing required sections."""
        # Empty file (0 bytes)
        empty_file = self.temp_dir / "zero_bytes.json"
        empty_file.write_text("", encoding="utf-8")
        with self.assertRaises(ReportParseError):
            read_report(empty_file)

        # Empty object ({})
        empty_obj = self._write_json("empty_obj.json", {})
        with self.assertRaises(ReportSchemaError):
            read_report(empty_obj)

        # Timeline report missing events section
        missing_events = self._write_json(
            "incomplete_timeline.json",
            {"report_type": "timeline", "metadata": {}},
        )
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(missing_events)
        self.assertIn("missing 'events' section", str(ctx.exception))

        # Timeline report with non-list events section
        bad_events_type = self._write_json(
            "bad_events_type.json",
            {"report_type": "timeline", "events": "not-a-list"},
        )
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(bad_events_type)
        self.assertIn("'events' section must be a list", str(ctx.exception))

        # Investigation report missing correlations
        missing_corrs = self._write_json(
            "incomplete_investigation.json",
            {
                "report_type": "correlation_detection",
                "detections": [],
                "timeline_events": [],
            },
        )
        with self.assertRaises(ReportSchemaError) as ctx:
            read_report(missing_corrs)
        self.assertIn("missing required sections", str(ctx.exception))

    def test_10_missing_optional_metadata(self) -> None:
        """Verify report with null or missing optional metadata is parsed cleanly."""
        data = {
            "report_type": "timeline",
            "metadata": {
                "case_id": None,
                "case_name": None,
                "investigator": None,
                "generated_at": None,
            },
            "events": [],
        }
        report_path = self._write_json("null_meta.json", data)
        ingested = read_report(report_path)

        self.assertIsNone(ingested.metadata.case_id)
        self.assertIsNone(ingested.metadata.case_name)
        self.assertIsNone(ingested.metadata.investigator)
        self.assertIsNone(ingested.metadata.created_at)
        self.assertEqual(ingested.counts.event_count, 0)

    # =========================================================================
    # 3. Safe File Handling, Path Resolution & Size Limits
    # =========================================================================

    def test_11_missing_file_and_invalid_file_rejection(self) -> None:
        """Verify handling of missing files, directories, and broken symlinks."""
        # Non-existent file
        non_existent = self.temp_dir / "does_not_exist.json"
        with self.assertRaises(ReportNotFoundError):
            read_report(non_existent)

        # None path
        with self.assertRaises(ReportNotFoundError):
            read_report(None)  # type: ignore

        # Directory input
        sub_dir = self.temp_dir / "sub_directory"
        sub_dir.mkdir()
        with self.assertRaises(ReportInvalidFileError) as ctx:
            read_report(sub_dir)
        self.assertIn("target is a directory", str(ctx.exception))

        # Broken symlink
        broken_target = self.temp_dir / "deleted_target.json"
        symlink_path = self.temp_dir / "broken_symlink.json"
        try:
            os.symlink(broken_target, symlink_path)
            with self.assertRaises(ReportNotFoundError):
                read_report(symlink_path)
        finally:
            if symlink_path.is_symlink():
                symlink_path.unlink()

    def test_12_input_size_limit_enforcement(self) -> None:
        """Verify strict defensive input size bounding."""
        data = {"report_type": "timeline", "events": []}
        report_path = self._write_json("size_check.json", data)
        actual_size = report_path.stat().st_size

        # Test with limit lower than actual size -> raises ReportSizeLimitError
        with self.assertRaises(ReportSizeLimitError) as ctx:
            read_report(report_path, max_size_bytes=actual_size - 1)
        self.assertIn("exceeds maximum allowed limit", str(ctx.exception))

        # Test with limit equal or greater -> succeeds
        ingested = read_report(report_path, max_size_bytes=actual_size)
        self.assertEqual(ingested.file_size_bytes, actual_size)

    def test_12b_invalid_max_size_bytes_rejected(self) -> None:
        """Verify invalid max_size_bytes arguments raise ReportSizeLimitError before file operations."""
        data = {"report_type": "timeline", "events": []}
        report_path = self._write_json("size_check_invalid.json", data)

        invalid_values = [-1, True, False, 1.5, "100", None]
        for val in invalid_values:
            with self.subTest(invalid_val=val):
                with self.assertRaises(ReportSizeLimitError) as ctx:
                    read_report(report_path, max_size_bytes=val)
                self.assertIn("must be a non-negative integer", str(ctx.exception))

    def test_12c_max_size_bytes_zero_allowed(self) -> None:
        """Verify max_size_bytes=0 is accepted as valid limit, allowing empty files to reach JSON parsing."""
        empty_file = self.temp_dir / "empty_report.json"
        empty_file.write_bytes(b"")

        # An empty file (0 bytes) with max_size_bytes=0 must pass size bounding
        # and proceed to JSON parsing, raising ReportParseError rather than ReportSizeLimitError.
        with self.assertRaises(ReportParseError) as ctx:
            read_report(empty_file, max_size_bytes=0)
        self.assertIn("Malformed JSON", str(ctx.exception))

        # A non-empty file with max_size_bytes=0 must fail size bounding with ReportSizeLimitError.
        data = {"report_type": "timeline", "events": []}
        non_empty = self._write_json("non_empty.json", data)
        with self.assertRaises(ReportSizeLimitError) as ctx:
            read_report(non_empty, max_size_bytes=0)
        self.assertIn("exceeds maximum allowed limit", str(ctx.exception))

    def test_13_path_and_symlink_handling(self) -> None:
        """Verify that valid symlinks and relative paths are resolved accurately."""
        data = {"report_type": "timeline", "events": []}
        real_file = self._write_json("real_report.json", data)
        symlink_file = self.temp_dir / "symlink_report.json"

        try:
            os.symlink(real_file, symlink_file)
            ingested = read_report(symlink_file)
            # source_path must be the canonical resolved path
            self.assertEqual(ingested.source_path, real_file.resolve())
            self.assertEqual(ingested.report_type, ReportType.TIMELINE)
        finally:
            if symlink_file.is_symlink():
                symlink_file.unlink()

    def test_14_provenance_and_integrity_preservation(self) -> None:
        """Verify cryptographic SHA-256 and file size match disk attributes exactly."""
        data = {
            "report_type": "timeline",
            "metadata": {"case_id": "INTEGRITY-01"},
            "events": [],
        }
        report_path = self._write_json("integrity.json", data)
        content_bytes = report_path.read_bytes()
        expected_sha256 = hashlib.sha256(content_bytes).hexdigest()
        expected_size = len(content_bytes)

        ingested = read_report(report_path)

        self.assertEqual(ingested.sha256, expected_sha256)
        self.assertEqual(ingested.file_size_bytes, expected_size)
        self.assertEqual(ingested.source_path, report_path.resolve())

    def test_15_read_only_immutability_verification(self) -> None:
        """Verify input file bytes and modification timestamps are never altered."""
        data = {"report_type": "timeline", "events": []}
        report_path = self._write_json("readonly_test.json", data)

        before_bytes = report_path.read_bytes()
        before_stat = report_path.stat()
        before_sha256 = hashlib.sha256(before_bytes).hexdigest()

        # Perform multiple reads
        _ = read_report(report_path)
        _ = read_report(report_path)
        _ = read_report(report_path)

        after_bytes = report_path.read_bytes()
        after_stat = report_path.stat()
        after_sha256 = hashlib.sha256(after_bytes).hexdigest()

        self.assertEqual(before_sha256, after_sha256)
        self.assertEqual(before_bytes, after_bytes)
        self.assertEqual(before_stat.st_mtime, after_stat.st_mtime)

    # =========================================================================
    # 4. IngestedReport API & Serialization
    # =========================================================================

    def test_16_ingested_report_to_dict_and_properties(self) -> None:
        """Verify to_dict conversion and helper properties on IngestedReport."""
        metadata = CaseMetadataView(
            case_id="CASE-01",
            case_name="Test Case",
            investigator="Lead",
            created_at="2026-10-01T00:00:00Z",
        )
        counts = ReportSummaryCounts(
            artifact_count=5,
            event_count=10,
            correlation_count=2,
            detection_count=1,
            matched_detection_count=1,
            audit_event_count=4,
        )
        report = IngestedReport(
            report_type=ReportType.CORRELATION_DETECTION,
            source_path=Path("/tmp/fake_report.json"),
            file_size_bytes=1024,
            sha256="abcdef1234567890",
            metadata=metadata,
            counts=counts,
            raw_data={"test": "data"},
            warnings=("test warning",),
        )

        self.assertTrue(report.is_investigation)
        self.assertFalse(report.is_timeline)
        self.assertFalse(report.is_triage)
        self.assertFalse(report.is_evidence_analysis)

        d = report.to_dict()
        self.assertEqual(d["report_type"], "correlation_detection")
        self.assertEqual(d["source_path"], "/tmp/fake_report.json")
        self.assertEqual(d["file_size_bytes"], 1024)
        self.assertEqual(d["sha256"], "abcdef1234567890")
        self.assertEqual(d["metadata"]["case_id"], "CASE-01")
        self.assertEqual(d["counts"]["detection_count"], 1)
        self.assertEqual(d["counts"]["matched_detection_count"], 1)
        self.assertEqual(d["warnings"], ["test warning"])

    # =========================================================================
    # 5. Round-Trip Compatibility with ForensiX Report Serializers
    # =========================================================================

    def test_17_roundtrip_timeline_serializer_compatibility(self) -> None:
        """Verify reading a report directly serialized by write_timeline_json_report."""
        from forensix.timeline_models import TimelineCategory, TimelineEvent
        from forensix.timeline_reporting import write_timeline_json_report

        ev1 = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="Accessed /tmp/test",
            source_path="/tmp/test",
        )
        output_file = self.temp_dir / "serialized_timeline.json"
        write_timeline_json_report(
            timeline=[ev1],
            output_path=output_file,
            case_id="CASE-SERIALIZED-TL",
        )

        ingested = read_report(output_file)
        self.assertEqual(ingested.report_type, ReportType.TIMELINE)
        self.assertEqual(ingested.metadata.case_id, "CASE-SERIALIZED-TL")
        self.assertEqual(ingested.counts.event_count, 1)

    # =========================================================================
    # 6. Security & Regression Tests (SEC-01, SEC-02, IMM-01, SCH-01, MET-01)
    # =========================================================================

    def test_18_sec_01_single_snapshot_hash_content_consistency(self) -> None:
        """Verify SHA-256 equals the cryptographic hash of the exact bytes parsed into raw_data."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {
                "case_id": "CASE-SEC-01",
                "generated_at": "2026-10-19T08:00:00Z",
            },
            "events": [
                {
                    "event_id": "EVT-01",
                    "timestamp": "2026-10-19T08:00:00Z",
                    "description": "User login",
                }
            ],
        }
        report_path = self._write_json("sec01_snapshot.json", v3_data)
        raw_bytes = report_path.read_bytes()
        expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        ingested = read_report(report_path)

        self.assertEqual(ingested.sha256, expected_sha256)
        self.assertEqual(ingested.file_size_bytes, len(raw_bytes))
        self.assertEqual(ingested.raw_data["metadata"]["case_id"], "CASE-SEC-01")
        self.assertEqual(len(ingested.raw_data["events"]), 1)

    def test_19_sec_02_bounded_read_enforces_byte_limit_during_read(self) -> None:
        """Verify the read path enforces byte limit during read even if initial stat was small."""
        v3_data = {
            "report_type": "timeline",
            "metadata": {"case_id": "CASE-GROWING"},
            "events": [{"event_id": "EVT-01", "description": "A" * 200}],
        }
        report_path = self._write_json("growing_report.json", v3_data)
        actual_size = report_path.stat().st_size
        self.assertGreater(actual_size, 100)

        # Mock stat() to simulate a file that reports a small initial size (e.g. 50 bytes)
        # but actually contains > 100 bytes when read.
        real_stat = Path.stat

        def mock_stat(p_self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
            if p_self.resolve() == report_path.resolve():
                real = real_stat(p_self, *args, **kwargs)
                return os.stat_result((
                    real.st_mode, real.st_ino, real.st_dev, real.st_nlink,
                    real.st_uid, real.st_gid, 50, real.st_atime, real.st_mtime, real.st_ctime
                ))
            return real_stat(p_self, *args, **kwargs)

        with patch.object(Path, "stat", side_effect=mock_stat, autospec=True):
            with self.assertRaises(ReportSizeLimitError) as ctx:
                read_report(report_path, max_size_bytes=80)
            self.assertIn("exceeds maximum allowed limit", str(ctx.exception))

    def test_20_sec_02_oversized_file_rejected_without_reading_entire_file(self) -> None:
        """Verify oversized file is rejected without reading entire file into memory."""
        oversized_path = self.temp_dir / "large_oversized.json"
        oversized_path.write_bytes(b"X" * 5000)

        real_stat = Path.stat

        def mock_stat(p_self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
            if p_self.resolve() == oversized_path.resolve():
                real = real_stat(p_self, *args, **kwargs)
                return os.stat_result((
                    real.st_mode, real.st_ino, real.st_dev, real.st_nlink,
                    real.st_uid, real.st_gid, 50, real.st_atime, real.st_mtime, real.st_ctime
                ))
            return real_stat(p_self, *args, **kwargs)

        with patch.object(Path, "stat", side_effect=mock_stat, autospec=True):
            with patch("builtins.open", wraps=open) as mock_open:
                with self.assertRaises(ReportSizeLimitError):
                    read_report(oversized_path, max_size_bytes=100)
                mock_open.assert_called_once()

    def test_21_imm_01_payload_deep_immutability(self) -> None:
        """Verify IngestedReport.raw_data cannot be mutated in-place at top or nested levels."""
        v2_data = {
            "metadata": {
                "report_id": f"REPORT-{uuid.uuid4()}",
                "case_id": "CASE-IMM-01",
                "created_at": "2026-10-19T08:00:00Z",
                "forensix_version": "5.0.0",
                "report_format": "json",
            },
            "summary": {"total_artifacts": 1},
            "artifacts": [
                {
                    "unified_id": "ART-01",
                    "category": "filesystem",
                    "status": "SUCCESS",
                }
            ],
            "audit_trail": [],
        }
        report_path = self._write_json("imm_test.json", v2_data)
        ingested = read_report(report_path)

        # 1. Top-level mapping mutation
        with self.assertRaises(TypeError):
            ingested.raw_data["metadata"] = {}  # type: ignore[index]
        with self.assertRaises(TypeError):
            ingested.raw_data["evil_key"] = "evil"  # type: ignore[index]
        with self.assertRaises(AttributeError):
            ingested.raw_data.pop("metadata")  # type: ignore[attr-defined]

        # 2. Nested dictionary mutation
        with self.assertRaises(TypeError):
            ingested.raw_data["metadata"]["case_id"] = "MUTATED"  # type: ignore[index]
        with self.assertRaises(TypeError):
            ingested.raw_data["metadata"]["injected"] = 123  # type: ignore[index]

        # 3. Nested list/sequence mutation
        with self.assertRaises(TypeError):
            ingested.raw_data["artifacts"][0] = {}  # type: ignore[index]
        with self.assertRaises(AttributeError):
            ingested.raw_data["artifacts"].append({})  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            ingested.raw_data["artifacts"][0]["category"] = "MUTATED"  # type: ignore[index]

        # Verify values remain original
        self.assertEqual(ingested.raw_data["metadata"]["case_id"], "CASE-IMM-01")
        self.assertEqual(ingested.raw_data["artifacts"][0]["category"], "filesystem")

        # 4. Caller mutation of source dictionary passed to IngestedReport constructor
        external_data = {
            "report_type": "timeline",
            "metadata": {"case_id": "ORIGINAL"},
            "events": [{"id": 1}],
        }
        report = IngestedReport(
            report_type=ReportType.TIMELINE,
            source_path=Path("/tmp/test.json"),
            file_size_bytes=100,
            sha256="abc",
            metadata=CaseMetadataView(case_id="ORIGINAL"),
            counts=ReportSummaryCounts(event_count=1),
            raw_data=external_data,
        )
        external_data["metadata"]["case_id"] = "MUTATED_EXTERNALLY"
        external_data["events"].append({"id": 2})

        self.assertEqual(report.raw_data["metadata"]["case_id"], "ORIGINAL")
        self.assertEqual(len(report.raw_data["events"]), 1)

    def test_22_imm_01_to_dict_and_raw_dict_isolation(self) -> None:
        """Verify to_dict() and raw_dict() do not provide mutation backdoors and serialize cleanly."""
        v2_data = {
            "metadata": {
                "report_id": f"REPORT-{uuid.uuid4()}",
                "case_id": "CASE-TO-DICT",
                "created_at": "2026-10-19T08:00:00Z",
                "forensix_version": "5.0.0",
                "report_format": "json",
            },
            "artifacts": [{"id": "ART-01"}],
            "audit_trail": [],
        }
        report_path = self._write_json("to_dict_isolation.json", v2_data)
        ingested = read_report(report_path)

        # 1. Standard to_dict() isolation
        d = ingested.to_dict()
        d["metadata"]["case_id"] = "HACKED"
        d["counts"]["artifact_count"] = 9999
        d["warnings"].append("HACKED")

        self.assertEqual(ingested.metadata.case_id, "CASE-TO-DICT")
        self.assertEqual(ingested.counts.artifact_count, 1)
        self.assertNotIn("HACKED", ingested.warnings)

        # 2. to_dict(include_raw=True) isolation
        d_full = ingested.to_dict(include_raw=True)
        self.assertIn("raw_data", d_full)
        d_full["raw_data"]["metadata"]["case_id"] = "HACKED_RAW"
        d_full["raw_data"]["artifacts"].append({"id": "INJECTED"})

        self.assertEqual(ingested.raw_data["metadata"]["case_id"], "CASE-TO-DICT")
        self.assertEqual(len(ingested.raw_data["artifacts"]), 1)

        # 3. raw_dict() isolation and JSON serialization
        raw_copy = ingested.raw_dict()
        self.assertIsInstance(raw_copy, dict)
        raw_copy["metadata"]["case_id"] = "HACKED_RAW_COPY"
        self.assertEqual(ingested.raw_data["metadata"]["case_id"], "CASE-TO-DICT")

        # Must be valid for json.dumps without TypeError
        json_output = json.dumps(raw_copy)
        self.assertIn("HACKED_RAW_COPY", json_output)
        json_full = json.dumps(d_full)
        self.assertIn("CASE-TO-DICT", json_full)

    def test_23_sch_01_host_triage_valid_and_invalid_report_ids(self) -> None:
        """Verify strict canonical REPORT-<UUIDv4> validation for HOST_TRIAGE schema."""
        valid_v4 = f"REPORT-{uuid.uuid4()}"
        base_host_triage = {
            "metadata": {
                "report_id": valid_v4,
                "case_id": "CASE-TRIAGE-SCH",
                "created_at": "2026-10-19T08:00:00Z",
                "forensix_version": "5.0.0",
                "report_format": "json",
            },
            "artifacts": [],
            "audit_trail": [],
        }

        # Positive 1: Standard lowercase UUIDv4
        self.assertEqual(detect_report_schema(base_host_triage), ReportType.HOST_TRIAGE)

        # Positive 2: Uppercase UUIDv4
        upper_v4 = valid_v4.upper()
        base_host_triage["metadata"]["report_id"] = upper_v4
        self.assertEqual(detect_report_schema(base_host_triage), ReportType.HOST_TRIAGE)

        # Negative 1: Numeric report_id
        base_host_triage["metadata"]["report_id"] = 12345
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 2: Arbitrary string (not REPORT-<UUIDv4>)
        base_host_triage["metadata"]["report_id"] = "REPORT-12345"
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 3: UUIDv1 (version 1, not version 4)
        v1_report_id = f"REPORT-{uuid.uuid1()}"
        base_host_triage["metadata"]["report_id"] = v1_report_id
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 4: UUIDv4 without hyphens
        no_hyphen_v4 = "REPORT-" + str(uuid.uuid4()).replace("-", "")
        base_host_triage["metadata"]["report_id"] = no_hyphen_v4
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 5: Missing report_id
        del base_host_triage["metadata"]["report_id"]
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 6: None / null report_id
        base_host_triage["metadata"]["report_id"] = None
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

        # Negative 7: Empty string report_id
        base_host_triage["metadata"]["report_id"] = "   "
        with self.assertRaises(ReportSchemaError):
            detect_report_schema(base_host_triage)

    def test_24_met_01_whitespace_metadata_normalization(self) -> None:
        """Verify whitespace-only metadata strings are normalized to None and strings trimmed."""
        # 1. Timeline report with whitespace case metadata
        tl_data = {
            "report_type": "timeline",
            "metadata": {
                "case_id": "   ",                  # Whitespace-only -> None
                "case_name": "  Incident Alpha  ", # Meaningful -> trimmed
                "investigator": "\t \n",           # Whitespace-only -> None
                "generated_at": " 2026-10-19T00:00:00Z ",
            },
            "events": [],
        }
        report_path = self._write_json("whitespace_tl.json", tl_data)
        ingested = read_report(report_path)

        self.assertIsNone(ingested.metadata.case_id)
        self.assertEqual(ingested.metadata.case_name, "Incident Alpha")
        self.assertIsNone(ingested.metadata.investigator)
        self.assertEqual(ingested.metadata.created_at, "2026-10-19T00:00:00Z")

        # 2. Host Triage report with whitespace case_id
        ht_data = {
            "metadata": {
                "report_id": f"REPORT-{uuid.uuid4()}",
                "case_id": "  \t  ",
                "case_name": " Host Compromise ",
                "created_at": "2026-10-19T00:00:00Z",
                "forensix_version": "5.0.0",
                "evidence_root": "   ",
                "triage_id": "  TRIAGE-123  ",
            },
            "artifacts": [],
            "audit_trail": [],
        }
        ht_path = self._write_json("whitespace_ht.json", ht_data)
        ht_ingested = read_report(ht_path)

        self.assertIsNone(ht_ingested.metadata.case_id)
        self.assertEqual(ht_ingested.metadata.case_name, "Host Compromise")
        self.assertIsNone(ht_ingested.metadata.evidence_root)
        self.assertEqual(ht_ingested.metadata.triage_id, "TRIAGE-123")

        # 3. Evidence Analysis report: non-string metadata preservation
        ea_data = {
            "evidence": {
                "evidence_id": "EV-123",
                "original_path": "  /evidence/disk.img  ",
            },
            "file": {
                "filename": "disk.img",
                "size": 65536,  # integer must be preserved
                "type": "application/octet-stream",
            },
            "metadata": {},
            "hashes": {"sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"},
        }
        ea_path = self._write_json("ea_meta.json", ea_data)
        ea_ingested = read_report(ea_path)

        self.assertEqual(ea_ingested.metadata.report_id, "EV-123")
        self.assertEqual(ea_ingested.metadata.evidence_root, "/evidence/disk.img")
        extra_dict = dict(ea_ingested.metadata.extra_metadata)
        self.assertEqual(extra_dict["size_bytes"], 65536)
        self.assertIsInstance(extra_dict["size_bytes"], int)

    def test_25_roundtrip_host_triage_serializer_compatibility(self) -> None:
        """Verify round-trip ingestion with V2 build_forensic_report and write_json_report."""
        from forensix.report_builder import build_forensic_report
        from forensix.report_json import write_json_report
        from forensix.unified_adapter import build_host_artifact_collection
        from forensix.artifacts import ArtifactRecord

        art = ArtifactRecord(
            artifact_id="ART-001",
            relative_path="etc/hosts",
            source_path="/evidence/etc/hosts",
            category="network",
            artifact_type="hosts",
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-10-01T00:00:00Z",
            accessed="2026-10-01T00:00:00Z",
            created="2026-10-01T00:00:00Z",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754",
            status="collected",
        )
        coll = build_host_artifact_collection(
            evidence_root="/evidence",
            records=[art],
            collected_at="2026-10-01T00:00:00Z",
        )
        report = build_forensic_report(
            source=coll,
            case_id="CASE-V2-SERIALIZER",
            case_name="V2 Serializer Roundtrip Test",
            investigator="Forensics Lead",
        )
        output_file = self.temp_dir / "v2_serialized_report.json"
        write_json_report(report, output_path=output_file)

        ingested = read_report(output_file)
        self.assertEqual(ingested.report_type, ReportType.HOST_TRIAGE)
        self.assertTrue(ingested.is_triage)
        self.assertEqual(ingested.metadata.case_id, "CASE-V2-SERIALIZER")
        self.assertEqual(ingested.metadata.case_name, "V2 Serializer Roundtrip Test")
        self.assertEqual(ingested.metadata.investigator, "Forensics Lead")
        self.assertTrue(ingested.metadata.report_id.startswith("REPORT-"))
        self.assertEqual(ingested.counts.artifact_count, 1)


if __name__ == "__main__":
    unittest.main()
