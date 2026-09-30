"""
Comprehensive Test Suite for ForensiX Milestone V2.9.4 — V2.8 Reporting Integration.

Verifies:
1.  Successful JSON report integration
2.  Successful CSV report integration
3.  Successful HTML report integration
4.  Multiple requested report formats
5.  Report format selection
6.  Report output directory
7.  Report file paths propagated to TriageResult
8.  Case information propagation
9.  Triage ID propagation
10. Stage result propagation
11. Artifact data propagation
12. InvestigationResultSet propagation
13. Traceability propagation
14. Audit trail propagation
15. Failed stage represented correctly in report
16. Skipped stage represented correctly
17. Partial stage represented correctly
18. Reporting-stage failure handling
19. No analyzer rerun
20. No evidence mutation
21. No subprocess execution
22. No network activity
23. HTML escaping regression
24. Deterministic JSON
25. Deterministic CSV ordering
26. Deterministic HTML artifact ordering
27. Empty investigation result
28. Empty artifact collection
29. Report generation disabled
30. Deep/source immutability
31. Existing V2.8 tests remain compatible
32. Existing V2.9.1–V2.9.3 behavior remains compatible
33. Full regression V1–V2.9.3
"""

import csv
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import patch

from forensix.audit import AuditEvent, AuditEventType, create_audit_event
from forensix.investigation import (
    ArtifactQuery,
    HostArtifactInvestigator,
    InvestigationResultSet,
)
from forensix.report_builder import build_forensic_report
from forensix.report_csv import render_csv_report
from forensix.report_html import render_html_report
from forensix.report_json import render_json_report
from forensix.report_models import ForensicReport, ReportFormat, ReportMetadata
from forensix.triage_models import (
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageTraceRecord,
)
from forensix.triage_orchestrator import (
    ALL_TRIAGE_STAGES,
    StageExecutionContext,
    TriageOrchestrator,
    sort_audit_events,
)
from forensix.account_models import UserAccount
from forensix.unified_adapter import to_host_artifact
from forensix.unified_models import (
    HostArtifact,
    HostArtifactCategory,
    HostArtifactCollection,
)


class TestTriageReporting(unittest.TestCase):
    """Test suite for V2.9.4 V2.8 Reporting Integration."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="forensix_test_v294_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"

        # Populate minimal valid evidence with standard layout
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.auth_log = log_dir / "auth.log"
        self.auth_log.write_text(
            "Sep 30 10:00:00 test-host sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2\n"
            "Sep 30 10:05:00 test-host sshd[1235]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2\n",
            encoding="utf-8",
        )
        self.passwd_file = etc_dir / "passwd"
        self.passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n",
            encoding="utf-8",
        )
        self.group_file = etc_dir / "group"
        self.group_file.write_text("root:x:0:\nalice:x:1001:\n", encoding="utf-8")

        self.cron_dir = etc_dir / "cron.d"
        self.cron_dir.mkdir(parents=True, exist_ok=True)
        (self.cron_dir / "test_job").write_text("* * * * * root /usr/bin/backup.sh\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _hash_dir(self, directory: Path) -> Dict[str, str]:
        hashes = {}
        for p in sorted(directory.rglob("*")):
            if p.is_file():
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                hashes[str(p.relative_to(directory))] = h
        return hashes

    # -------------------------------------------------------------------------
    # Test 1: Successful JSON report integration
    # -------------------------------------------------------------------------
    def test_01_successful_json_report_integration(self):
        """1. Verify successful JSON report generation and valid JSON file output on disk."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-JSON-01",
            output_dir=str(self.output_dir),
            report_formats=("json",),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertIsNotNone(result.report)
        self.assertEqual(len(result.report_files), 1)
        self.assertEqual(result.report_files[0][0], "json")

        json_path = Path(result.report_files[0][1])
        self.assertTrue(json_path.exists())
        self.assertEqual(json_path.name, "forensix_report_CASE-JSON-01.json")

        content = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertIn("metadata", content)
        self.assertIn("summary", content)
        self.assertIn("artifacts", content)
        self.assertIn("audit_trail", content)
        self.assertEqual(content["metadata"]["case_id"], "CASE-JSON-01")

    # -------------------------------------------------------------------------
    # Test 2: Successful CSV report integration
    # -------------------------------------------------------------------------
    def test_02_successful_csv_report_integration(self):
        """2. Verify successful CSV report generation and valid RFC 4180 CSV output on disk."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-CSV-02",
            output_dir=str(self.output_dir),
            report_formats=("csv",),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertIsNotNone(result.report)
        self.assertEqual(len(result.report_files), 1)
        self.assertEqual(result.report_files[0][0], "csv")

        csv_path = Path(result.report_files[0][1])
        self.assertTrue(csv_path.exists())
        self.assertEqual(csv_path.name, "forensix_report_CASE-CSV-02.csv")

        lines = csv_path.read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(lines), 1)
        self.assertIn("unified_id", lines[0])
        self.assertIn("category", lines[0])

    # -------------------------------------------------------------------------
    # Test 3: Successful HTML report integration
    # -------------------------------------------------------------------------
    def test_03_successful_html_report_integration(self):
        """3. Verify successful standalone HTML report generation on disk with required sections."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-HTML-03",
            output_dir=str(self.output_dir),
            report_formats=("html",),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertIsNotNone(result.report)
        self.assertEqual(len(result.report_files), 1)
        self.assertEqual(result.report_files[0][0], "html")

        html_path = Path(result.report_files[0][1])
        self.assertTrue(html_path.exists())
        self.assertEqual(html_path.name, "forensix_report_CASE-HTML-03.html")

        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("1. Case Information", html_text)
        self.assertIn("2. Investigation Summary", html_text)
        self.assertIn("3. Artifact Statistics", html_text)
        self.assertIn("4. Artifacts", html_text)
        self.assertIn("5. Source / Lineage Information", html_text)
        self.assertIn("6. Audit Information", html_text)

    # -------------------------------------------------------------------------
    # Test 4: Multiple requested report formats
    # -------------------------------------------------------------------------
    def test_04_multiple_requested_report_formats(self):
        """4. Verify JSON, CSV, and HTML generated together when all requested in report_formats."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-MULTI-04",
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertEqual(len(result.report_files), 3)
        fmts = [f[0] for f in result.report_files]
        self.assertEqual(fmts, ["json", "csv", "html"])

        for _, file_path in result.report_files:
            self.assertTrue(Path(file_path).exists())

    # -------------------------------------------------------------------------
    # Test 5: Report format selection
    # -------------------------------------------------------------------------
    def test_05_report_format_selection(self):
        """5. Verify only requested formats are generated."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-SEL-05",
            output_dir=str(self.output_dir),
            report_formats=("json",),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertEqual(len(result.report_files), 1)
        self.assertEqual(result.report_files[0][0], "json")
        self.assertFalse((self.output_dir / "forensix_report_CASE-SEL-05.csv").exists())
        self.assertFalse((self.output_dir / "forensix_report_CASE-SEL-05.html").exists())

    # -------------------------------------------------------------------------
    # Test 6: Report output directory
    # -------------------------------------------------------------------------
    def test_06_report_output_directory(self):
        """6. Verify reports are written to configured output_dir and parents created."""
        nested_dir = self.output_dir / "sub" / "reports_dir"
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-DIR-06",
            output_dir=str(nested_dir),
            report_formats=("json",),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(nested_dir.exists())
        self.assertTrue((nested_dir / "forensix_report_CASE-DIR-06.json").exists())

    # -------------------------------------------------------------------------
    # Test 7: Report file paths propagated to TriageResult
    # -------------------------------------------------------------------------
    def test_07_report_file_paths_propagated_to_triage_result(self):
        """7. Verify report_files contains exact (format, path) pairs in TriageResult."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-TRACK-07",
            output_dir=str(self.output_dir),
            report_formats=("json", "html"),
        )
        result = TriageOrchestrator(cfg).run()
        file_dict = dict(result.report_files)
        self.assertIn("json", file_dict)
        self.assertIn("html", file_dict)
        self.assertTrue(Path(file_dict["json"]).is_file())
        self.assertTrue(Path(file_dict["html"]).is_file())

    # -------------------------------------------------------------------------
    # Test 8: Case information propagation
    # -------------------------------------------------------------------------
    def test_08_case_information_propagation(self):
        """8. Verify case_id, case_name, and investigator propagate to report.metadata."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-PROP-08",
            case_name="Incident Alpha",
            investigator="Agent 47",
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        meta = result.report.metadata
        self.assertEqual(meta.case_id, "CASE-PROP-08")
        self.assertEqual(meta.case_name, "Incident Alpha")
        self.assertEqual(meta.investigator, "Agent 47")

    # -------------------------------------------------------------------------
    # Test 9: Triage ID propagation
    # -------------------------------------------------------------------------
    def test_09_triage_id_propagation(self):
        """9. Verify triage_id propagates to report.metadata.triage_id."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertIsNotNone(result.report.metadata.triage_id)
        self.assertEqual(result.report.metadata.triage_id, result.triage_id)

    # -------------------------------------------------------------------------
    # Test 10: Stage result propagation
    # -------------------------------------------------------------------------
    def test_10_stage_result_propagation(self):
        """10. Verify pipeline stage results are attached to report.stage_results."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        report = result.report
        self.assertGreater(len(report.stage_results), 0)
        stage_ids = [s.stage_id for s in report.stage_results]
        self.assertIn(TriageStage.EVIDENCE_VALIDATION.value, stage_ids)
        self.assertIn(TriageStage.FILESYSTEM_COLLECTION.value, stage_ids)

    # -------------------------------------------------------------------------
    # Test 11: Artifact data propagation
    # -------------------------------------------------------------------------
    def test_11_artifact_data_propagation(self):
        """11. Verify canonical HostArtifact instances propagate to report.artifacts."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertGreater(result.report.total_artifacts, 0)
        self.assertEqual(len(result.report.artifacts), result.report.total_artifacts)
        for art in result.report.artifacts:
            self.assertIsInstance(art, HostArtifact)
            self.assertTrue(art.unified_id.startswith("HOSTART-"))

    # -------------------------------------------------------------------------
    # Test 12: InvestigationResultSet propagation
    # -------------------------------------------------------------------------
    def test_12_investigation_result_set_propagation(self):
        """12. Verify InvestigationResultSet summary is preserved in report when present."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        if result.investigation_result:
            self.assertIsNotNone(result.report.investigation_summary)
            self.assertIn("total_matches", result.report.investigation_summary)

    # -------------------------------------------------------------------------
    # Test 13: Traceability propagation
    # -------------------------------------------------------------------------
    def test_13_traceability_propagation(self):
        """13. Verify TriageTraceRecord instances propagate to report.trace_records."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertGreater(len(result.report.trace_records), 0)
        for tr in result.report.trace_records:
            self.assertIsInstance(tr, TriageTraceRecord)
            self.assertEqual(tr.triage_id, result.triage_id)

    # -------------------------------------------------------------------------
    # Test 14: Audit trail propagation
    # -------------------------------------------------------------------------
    def test_14_audit_trail_propagation(self):
        """14. Verify audit trail propagates to report.audit_trail."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertGreater(len(result.report.audit_trail), 0)
        ev_types = [e.event_type for e in result.report.audit_trail]
        self.assertIn(AuditEventType.TRIAGE_STARTED.value, ev_types)

    # -------------------------------------------------------------------------
    # Test 15: Failed stage represented correctly in report
    # -------------------------------------------------------------------------
    def test_15_failed_stage_represented_correctly_in_report(self):
        """15. Verify that when a stage fails, the failure is factually represented in report."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )

        def failing_log_parser(ctx: StageExecutionContext) -> TriageStageResult:
            raise ValueError("Corrupt log format")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.LOG_PARSING.value: failing_log_parser},
        )
        result = orchestrator.run()
        self.assertIsNotNone(result.report)
        log_res = next(
            (s for s in result.report.stage_results if s.stage_id == TriageStage.LOG_PARSING.value),
            None,
        )
        self.assertIsNotNone(log_res)
        self.assertEqual(log_res.status, "FAILED")
        self.assertEqual(len(log_res.errors), 1)
        self.assertIn("Corrupt log format", log_res.errors[0].error_message)

    # -------------------------------------------------------------------------
    # Test 16: Skipped stage represented correctly
    # -------------------------------------------------------------------------
    def test_16_skipped_stage_represented_correctly(self):
        """16. Verify that skipped stages are accurately captured in report.stage_results."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            enabled_stages=(
                TriageStage.EVIDENCE_VALIDATION.value,
                TriageStage.FILESYSTEM_COLLECTION.value,
                TriageStage.UNIFIED_HOST_MODEL.value,
                TriageStage.REPORTING.value,
            ),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        log_res = next(
            (s for s in result.report.stage_results if s.stage_id == TriageStage.LOG_PARSING.value),
            None,
        )
        self.assertIsNotNone(log_res)
        self.assertEqual(log_res.status, "SKIPPED")

    # -------------------------------------------------------------------------
    # Test 17: Partial stage represented correctly
    # -------------------------------------------------------------------------
    def test_17_partial_stage_represented_correctly(self):
        """17. Verify that partial stages with warnings are represented in report."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )

        def partial_fs(ctx: StageExecutionContext) -> TriageStageResult:
            return TriageStageResult(
                stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
                stage_name="Filesystem Artifact Collection",
                status=TriageStageStatus.PARTIAL,
                records_produced=2,
                warnings=("Permission denied on 1 directory",),
            )

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.FILESYSTEM_COLLECTION.value: partial_fs},
        )
        result = orchestrator.run()
        fs_res = next(
            (s for s in result.report.stage_results if s.stage_id == TriageStage.FILESYSTEM_COLLECTION.value),
            None,
        )
        self.assertIsNotNone(fs_res)
        self.assertEqual(fs_res.status, "PARTIAL")
        self.assertIn("Permission denied on 1 directory", fs_res.warnings)

    # -------------------------------------------------------------------------
    # Test 18: Reporting-stage failure handling
    # -------------------------------------------------------------------------
    def test_18_reporting_stage_failure_handling(self):
        """18. Verify that if one format fails to write, status is PARTIAL and other formats succeed."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "html"),
        )

        with patch("forensix.triage_orchestrator.write_html_report", side_effect=IOError("Disk write error")):
            result = TriageOrchestrator(cfg).run()
            rep_res = next(s for s in result.stage_results if s.stage_id == TriageStage.REPORTING.value)
            self.assertEqual(rep_res.status, "PARTIAL")
            self.assertEqual(len(rep_res.errors), 1)
            self.assertIn("Disk write error", rep_res.errors[0].error_message)

            # JSON should have succeeded
            self.assertEqual(len(result.report_files), 1)
            self.assertEqual(result.report_files[0][0], "json")
            self.assertTrue(Path(result.report_files[0][1]).exists())

    # -------------------------------------------------------------------------
    # Test 19: No analyzer rerun
    # -------------------------------------------------------------------------
    def test_19_no_analyzer_rerun(self):
        """19. Verify reporting consumes in-memory objects and does not re-invoke log parsing or scanning."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        with patch("forensix.triage_orchestrator.scan_evidence_directory") as mock_scan:
            mock_scan.side_effect = Exception("Should not call scan more than once")
            # We run with customized handler for filesystem to verify reporting doesn't call scan
            def noop_fs(ctx: StageExecutionContext) -> TriageStageResult:
                return TriageStageResult(
                    stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
                    stage_name="FS",
                    status=TriageStageStatus.COMPLETED,
                    records_produced=0,
                )
            orch = TriageOrchestrator(cfg, custom_handlers={TriageStage.FILESYSTEM_COLLECTION.value: noop_fs})
            result = orch.run()
            # scan_evidence_directory was NEVER called
            self.assertEqual(mock_scan.call_count, 0)

    # -------------------------------------------------------------------------
    # Test 20: No evidence mutation
    # -------------------------------------------------------------------------
    def test_20_no_evidence_mutation(self):
        """20. Verify evidence files remain completely unmodified."""
        pre_hashes = self._hash_dir(self.evidence_dir)
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        _ = TriageOrchestrator(cfg).run()
        post_hashes = self._hash_dir(self.evidence_dir)
        self.assertEqual(pre_hashes, post_hashes)

    # -------------------------------------------------------------------------
    # Test 21: No subprocess execution
    # -------------------------------------------------------------------------
    def test_21_no_subprocess_execution(self):
        """21. Verify zero subprocess executions occur during report generation."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
            _ = TriageOrchestrator(cfg).run()
            self.assertEqual(mock_popen.call_count, 0)
            self.assertEqual(mock_run.call_count, 0)

    # -------------------------------------------------------------------------
    # Test 22: No network activity
    # -------------------------------------------------------------------------
    def test_22_no_network_activity(self):
        """22. Verify zero network socket operations during report generation."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        with patch("socket.socket") as mock_socket:
            _ = TriageOrchestrator(cfg).run()
            self.assertEqual(mock_socket.call_count, 0)

    def test_23_html_escaping_regression(self):
        """23. Verify malicious HTML tags in paths, warnings, and errors are safely escaped."""
        (self.evidence_dir / "var" / "log" / "auth.log").write_text(
            "Sep 30 10:00:00 host sshd[1]: <script>alert('xss')</script> <img src=x onerror=alert(1)>\n",
            encoding="utf-8",
        )

        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("html",),
        )
        result = TriageOrchestrator(cfg).run()
        html_file = Path(result.report_files[0][1])
        html_text = html_file.read_text(encoding="utf-8")

        self.assertNotIn("<script>alert('xss')</script>", html_text)
        self.assertNotIn("<img src=x onerror=alert(1)>", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_text)

    # -------------------------------------------------------------------------
    # Test 24: Deterministic JSON
    # -------------------------------------------------------------------------
    def test_24_deterministic_json(self):
        """24. Verify identical ForensicReport renders bit-for-bit identical JSON."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        report = result.report
        json_1 = render_json_report(report)
        json_2 = render_json_report(report)
        self.assertEqual(json_1, json_2)

    # -------------------------------------------------------------------------
    # Test 25: Deterministic CSV ordering
    # -------------------------------------------------------------------------
    def test_25_deterministic_csv_ordering(self):
        """25. Verify identical ForensicReport renders bit-for-bit identical CSV rows."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        report = result.report
        csv_1 = render_csv_report(report)
        csv_2 = render_csv_report(report)
        self.assertEqual(csv_1, csv_2)

    # -------------------------------------------------------------------------
    # Test 26: Deterministic HTML artifact ordering
    # -------------------------------------------------------------------------
    def test_26_deterministic_html_artifact_ordering(self):
        """26. Verify identical ForensicReport renders identical HTML artifact rows."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        report = result.report
        html_1 = render_html_report(report)
        html_2 = render_html_report(report)
        self.assertEqual(html_1, html_2)

    # -------------------------------------------------------------------------
    # Test 27: Empty investigation result
    # -------------------------------------------------------------------------
    def test_27_empty_investigation_result(self):
        """27. Verify reporting cleanly handles an empty InvestigationResultSet."""
        empty_res = InvestigationResultSet(
            query=ArtifactQuery(),
            artifacts=(),
            total_matches=0,
            category_breakdown=(),
            status_breakdown=(),
        )
        report = build_forensic_report(source=empty_res)
        self.assertEqual(report.total_artifacts, 0)
        self.assertEqual(len(report.artifacts), 0)
        self.assertEqual(report.investigation_summary["total_matches"], 0)

    # -------------------------------------------------------------------------
    # Test 28: Empty artifact collection
    # -------------------------------------------------------------------------
    def test_28_empty_artifact_collection(self):
        """28. Verify reporting cleanly handles an empty HostArtifactCollection."""
        empty_coll = HostArtifactCollection(
            evidence_root="/empty",
            artifacts=(),
            total_artifacts=0,
            category_counts=(),
            status_counts=(),
            collected_at="2026-09-30T10:00:00Z",
        )
        report = build_forensic_report(source=empty_coll)
        self.assertEqual(report.total_artifacts, 0)
        self.assertEqual(len(report.artifacts), 0)

    # -------------------------------------------------------------------------
    # Test 29: Report generation disabled
    # -------------------------------------------------------------------------
    def test_29_report_generation_disabled(self):
        """29. Verify skip_reports=True causes reporting stage to be SKIPPED and no files written."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            skip_reports=True,
        )
        result = TriageOrchestrator(cfg).run()
        self.assertIsNone(result.report)
        self.assertEqual(len(result.report_files), 0)
        rep_stage = next(s for s in result.stage_results if s.stage_id == TriageStage.REPORTING.value)
        self.assertEqual(rep_stage.status, "SKIPPED")
        self.assertIn("Reporting skipped by configuration", rep_stage.warnings)

    # -------------------------------------------------------------------------
    # Test 30: Deep/source immutability
    # -------------------------------------------------------------------------
    def test_30_deep_source_immutability(self):
        """30. Verify ForensicReport, ReportMetadata, and contained tuples are deeply immutable."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        report = result.report
        self.assertIsNotNone(report)

        with self.assertRaises(Exception):
            report.total_artifacts = 9999  # type: ignore

        with self.assertRaises(Exception):
            report.artifacts = ()  # type: ignore

        with self.assertRaises(Exception):
            report.metadata.case_id = "MUTATED"  # type: ignore

        with self.assertRaises(Exception):
            report.stage_results = ()  # type: ignore

        with self.assertRaises(Exception):
            report.trace_records = ()  # type: ignore

    # -------------------------------------------------------------------------
    # Test 31: Existing V2.8 tests remain compatible
    # -------------------------------------------------------------------------
    def test_31_existing_v28_tests_remain_compatible(self):
        """31. Verify build_forensic_report works seamlessly without any triage parameters."""
        user = UserAccount(
            user_id="USER-1",
            source_artifact_id=None,
            source_path="/test",
            line_number=1,
            username="testuser",
            uid=1000,
            gid=1000,
            gecos="",
            home_directory="/home/testuser",
            login_shell="/bin/bash",
            is_privileged=False,
            primary_group="testuser",
            supplementary_groups=(),
            raw_line="testuser:x:1000:1000::/home/testuser:/bin/bash",
        )
        host_art = to_host_artifact(user)
        report = build_forensic_report([host_art])
        self.assertEqual(report.total_artifacts, 1)
        self.assertIsNone(report.metadata.triage_id)
        self.assertEqual(report.stage_results, ())
        self.assertEqual(report.trace_records, ())

    # -------------------------------------------------------------------------
    # Test 32: Existing V2.9.1–V2.9.3 behavior remains compatible
    # -------------------------------------------------------------------------
    def test_32_existing_v291_v293_behavior_remains_compatible(self):
        """32. Verify all models from V2.9.1 to V2.9.3 remain intact and compatible."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.triage_id.startswith("TRIAGE-"))
        self.assertEqual(len(result.stage_results), 9)
        self.assertEqual(len(result.trace_records), 9)
        self.assertGreater(len(result.audit_trail), 0)

    # -------------------------------------------------------------------------
    # Test 33: Full regression V1–V2.9.3
    # -------------------------------------------------------------------------
    def test_33_full_regression_v1_v293(self):
        """33. Verify end-to-end full pipeline execution with all reporting formats."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-FULL-33",
            case_name="End-to-End Regression",
            investigator="Chief Investigator",
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.summary.is_success)
        self.assertEqual(result.summary.stages_completed, 9)
        self.assertEqual(result.summary.stages_failed, 0)
        self.assertEqual(result.summary.stages_skipped, 0)
        self.assertEqual(len(result.report_files), 3)

        # Verify all 3 files exist and are non-empty
        for fmt, p in result.report_files:
            file_obj = Path(p)
            self.assertTrue(file_obj.is_file())
            self.assertGreater(file_obj.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
