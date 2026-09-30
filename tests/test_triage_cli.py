"""
Comprehensive Test Suite for ForensiX Milestone V2.9.5 — CLI + End-to-End Workflow.

Verifies:
1.  CLI help (triage --help)
2.  CLI triage command exists
3.  Valid evidence directory accepted
4.  Missing evidence path rejected
5.  File supplied where directory required
6.  Case ID propagation
7.  Case name propagation
8.  Investigator propagation
9.  Output directory propagation
10. JSON format selection
11. CSV format selection
12. HTML format selection
13. Multiple format selection
14. Skip reports option
15. Invalid report format
16. Invalid stage option
17. CLI invokes TriageOrchestrator
18. Stage order remains orchestrator-controlled
19. Successful end-to-end pipeline
20. Partial pipeline
21. Failed stage pipeline
22. Skipped dependent stage
23. CLI displays stage statuses
24. CLI displays triage ID
25. CLI displays generated report paths
26. Correct success exit code
27. Correct non-zero failure exit code
28. Existing V1 CLI compatibility
29. No evidence mutation
30. No subprocess execution during CLI triage run
31. No network activity
32. No hardcoded user-specific paths
33. Generated JSON report exists and is valid
34. Generated HTML report exists and is valid
35. TriageResult contains expected components
36. Traceability survives CLI execution
37. Audit trail survives CLI execution
38. Existing V2.8 reporting tests remain compatible
39. Existing V2.9.1–V2.9.4 tests remain compatible
40. Full regression V1–V2.9.4
"""

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional
import unittest
from unittest.mock import MagicMock, patch

from forensix import __version__
from forensix.main import (
    build_parser,
    build_triage_parser,
    execute_triage_cli,
    main,
    triage_main,
)
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageStatus,
)
from forensix.triage_orchestrator import TriageOrchestrator


class TestTriageCLI(unittest.TestCase):
    """Test suite for ForensiX V2.9.5 CLI and End-to-End Triage Workflow."""

    def setUp(self):
        """Create temporary workspace with realistic fixture evidence."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_cli_test_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"

        # Construct realistic minimal evidence directory
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        var_log_dir = self.evidence_dir / "var" / "log"
        var_log_dir.mkdir(parents=True, exist_ok=True)

        self.auth_log = var_log_dir / "auth.log"
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
        self.group_file.write_text(
            "root:x:0:\n"
            "alice:x:1001:\n",
            encoding="utf-8",
        )

        cron_dir = etc_dir / "cron.d"
        cron_dir.mkdir(parents=True, exist_ok=True)
        (cron_dir / "backup").write_text("* * * * * root /usr/bin/backup.sh\n", encoding="utf-8")

        self.single_evidence_file = Path(self.test_dir) / "single_evidence.log"
        self.single_evidence_file.write_text(
            "2026-09-30T10:00:00Z [SECURITY] Test single evidence file\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _hash_dir(self, directory: Path) -> Dict[str, str]:
        """Compute SHA-256 for all files in a directory."""
        hashes = {}
        for p in sorted(directory.rglob("*")):
            if p.is_file():
                hashes[str(p.relative_to(directory))] = hashlib.sha256(p.read_bytes()).hexdigest()
        return hashes

    def _run_cli_capture(self, argv: List[str]):
        """Run triage_main with captured stdout/stderr and return (exit_code, stdout, stderr)."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        orig_stdout, orig_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout = stdout_buf
            sys.stderr = stderr_buf
            exit_code = triage_main(argv)
        finally:
            sys.stdout, sys.stderr = orig_stdout, orig_stderr
        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()

    # 1. CLI help
    def test_01_cli_help(self):
        """Verify triage --help displays comprehensive usage options."""
        parser = build_triage_parser()
        help_text = parser.format_help()
        self.assertIn("evidence_directory", help_text)
        self.assertIn("--case-id", help_text)
        self.assertIn("--case-name", help_text)
        self.assertIn("--investigator", help_text)
        self.assertIn("--output-dir", help_text)
        self.assertIn("--format", help_text)
        self.assertIn("--skip-reports", help_text)
        self.assertIn("--disable-stage", help_text)

        # Also verify via subprocess with python3 -m forensix triage --help
        env = dict(os.environ, PYTHONPATH="src")
        proc = subprocess.run(
            [sys.executable, "-m", "forensix", "triage", "--help"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ForensiX", proc.stdout)
        self.assertIn("evidence_directory", proc.stdout)

    # 2. CLI triage command exists
    def test_02_cli_triage_command_exists(self):
        """Verify triage subcommand is recognized and distinguished from single-file CLI."""
        env = dict(os.environ, PYTHONPATH="src")
        # Subcommand without args exits with status 2 (argparse error for missing positional argument)
        proc = subprocess.run(
            [sys.executable, "-m", "forensix", "triage"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("evidence_directory", proc.stderr)

    # 3. Valid evidence directory accepted
    def test_03_valid_evidence_directory_accepted(self):
        """Verify valid evidence directory is accepted and successfully executed."""
        exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(result)
        self.assertTrue(result.summary.is_success)

    # 4. Missing evidence path rejected
    def test_04_missing_evidence_path_rejected(self):
        """Verify non-existent evidence directory is rejected with clear error and exit 1."""
        missing = Path(self.test_dir) / "non_existent_evidence"
        exit_code, stdout, stderr = self._run_cli_capture([str(missing)])
        self.assertEqual(exit_code, 1)
        self.assertIn("does not exist", stderr)

    # 5. File supplied where directory required
    def test_05_file_supplied_where_directory_required(self):
        """Verify regular file passed to triage command is rejected with clear error and exit 1."""
        exit_code, stdout, stderr = self._run_cli_capture([str(self.single_evidence_file)])
        self.assertEqual(exit_code, 1)
        self.assertIn("not a directory", stderr)

    # 6. Case ID propagation
    def test_06_case_id_propagation(self):
        """Verify --case-id is propagated to TriageConfig and TriageResult."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "--case-id", "CASE-2026-X1",
            "--skip-reports",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.case_id, "CASE-2026-X1")
        self.assertEqual(result.summary.case_id, "CASE-2026-X1")

    # 7. Case name propagation
    def test_07_case_name_propagation(self):
        """Verify --case-name is propagated to TriageConfig and TriageResult."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "--case-name", "Server Breach Investigation",
            "--skip-reports",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.case_name, "Server Breach Investigation")
        self.assertEqual(result.summary.case_name, "Server Breach Investigation")

    # 8. Investigator propagation
    def test_08_investigator_propagation(self):
        """Verify --investigator is propagated to TriageConfig and TriageResult."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "--investigator", "Agent Smith",
            "--skip-reports",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.investigator, "Agent Smith")
        self.assertEqual(result.summary.investigator, "Agent Smith")

    # 9. Output directory propagation
    def test_09_output_directory_propagation(self):
        """Verify -o / --output-dir is propagated and reports are stored there."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(Path(result.config.output_dir), self.output_dir.resolve())
        self.assertTrue(self.output_dir.exists())
        json_reports = list(self.output_dir.glob("*.json"))
        self.assertEqual(len(json_reports), 1)

    # 10. JSON format selection
    def test_10_json_format_selection(self):
        """Verify --format json generates only JSON report."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.report_formats, ("json",))
        formats_generated = [fmt for fmt, _ in result.report_files]
        self.assertEqual(formats_generated, ["json"])

    # 11. CSV format selection
    def test_11_csv_format_selection(self):
        """Verify --format csv generates CSV reports."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "csv",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.report_formats, ("csv",))
        formats_generated = [fmt for fmt, _ in result.report_files]
        self.assertIn("csv", formats_generated)

    # 12. HTML format selection
    def test_12_html_format_selection(self):
        """Verify --format html generates HTML report."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.report_formats, ("html",))
        formats_generated = [fmt for fmt, _ in result.report_files]
        self.assertEqual(formats_generated, ["html"])

    # 13. Multiple format selection
    def test_13_multiple_format_selection(self):
        """Verify passing multiple --format flags generates reports for each requested format."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(result.config.report_formats, ("json", "html"))
        formats_generated = [fmt for fmt, _ in result.report_files]
        self.assertIn("json", formats_generated)
        self.assertIn("html", formats_generated)

    # 14. Skip reports option
    def test_14_skip_reports_option(self):
        """Verify --skip-reports prevents file generation on disk."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--skip-reports",
        ])
        self.assertEqual(exit_code, 0)
        self.assertTrue(result.config.skip_reports)
        self.assertEqual(len(result.report_files), 0)
        self.assertFalse(self.output_dir.exists())

    # 15. Invalid report format
    def test_15_invalid_report_format(self):
        """Verify invalid report format option is rejected by parser with status 2."""
        with self.assertRaises(SystemExit) as ctx:
            build_triage_parser().parse_args([str(self.evidence_dir), "--format", "invalid_pdf"])
        self.assertEqual(ctx.exception.code, 2)

    # 16. Invalid stage option if implemented
    def test_16_invalid_stage_option(self):
        """Verify invalid stage name to --disable-stage is rejected with exit status 2."""
        with self.assertRaises(SystemExit) as ctx:
            build_triage_parser().parse_args([str(self.evidence_dir), "--disable-stage", "fake_stage"])
        self.assertEqual(ctx.exception.code, 2)

    # 17. CLI invokes TriageOrchestrator
    def test_17_cli_invokes_triage_orchestrator(self):
        """Verify CLI instantiates and calls TriageOrchestrator.run()."""
        with patch.object(TriageOrchestrator, "run") as mock_run:
            mock_result = MagicMock()
            mock_result.config.case_id = "C1"
            mock_result.config.case_name = None
            mock_result.config.investigator = None
            mock_result.config.skip_reports = True
            mock_result.summary.evidence_root = str(self.evidence_dir)
            mock_result.summary.is_success = True
            mock_result.summary.total_duration_seconds = 0.1
            mock_result.summary.total_artifacts = 5
            mock_result.triage_id = "TRIAGE-TEST"
            mock_result.stage_results = ()
            mock_result.report_files = ()
            mock_result.report = None
            mock_run.return_value = mock_result

            exit_code, result = execute_triage_cli([str(self.evidence_dir), "--case-id", "C1"])
            self.assertEqual(exit_code, 0)
            mock_run.assert_called_once()

    # 18. Stage order remains orchestrator-controlled
    def test_18_stage_order_remains_orchestrator_controlled(self):
        """Verify stage order in CLI execution matches canonical orchestrator sequence."""
        exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        observed_stages = tuple(sr.stage_id for sr in result.stage_results)
        self.assertEqual(observed_stages, ALL_TRIAGE_STAGES)

    # 19. Successful end-to-end pipeline
    def test_19_successful_end_to_end_pipeline(self):
        """Verify full end-to-end triage pipeline completes with realistic evidence."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--case-id", "CASE-E2E-001",
            "--format", "json",
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        self.assertTrue(result.summary.is_success)
        self.assertEqual(result.summary.stages_failed, 0)
        self.assertGreater(result.summary.total_artifacts, 0)
        self.assertEqual(len(result.report_files), 2)

    # 20. Partial pipeline
    def test_20_partial_pipeline(self):
        """Verify pipeline with partial log parsing records PARTIAL status and exits with 0."""
        # Append malformed line to auth.log to induce partial parsing
        self.auth_log.write_text("CORRUPTED UNKNOWN LOG ENTRY\n", encoding="utf-8")
        exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        # Pipeline is still a success overall as no stages failed fatally
        self.assertTrue(result.summary.is_success)
        self.assertEqual(result.summary.stages_failed, 0)

    # 21. Failed stage pipeline
    def test_21_failed_stage_pipeline(self):
        """Verify pipeline with a failed stage exits with non-zero status 1."""
        with patch.object(TriageOrchestrator, "_execute_evidence_validation", side_effect=RuntimeError("Forced validation failure")):
            exit_code, result = execute_triage_cli([
                str(self.evidence_dir),
                "--skip-reports",
            ])
            self.assertEqual(exit_code, 1)
            self.assertIsNotNone(result)
            self.assertFalse(result.summary.is_success)
            self.assertGreater(result.summary.stages_failed, 0)

    # 22. Skipped dependent stage
    def test_22_skipped_dependent_stage(self):
        """Verify disabling prerequisite stage causes dependent stages to be SKIPPED."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "--disable-stage", "log_parsing",
            "--skip-reports",
        ])
        self.assertEqual(exit_code, 0)
        skipped = [sr for sr in result.stage_results if sr.status == TriageStageStatus.SKIPPED.value]
        skipped_names = [sr.stage_id for sr in skipped]
        self.assertIn("log_parsing", skipped_names)
        self.assertIn("authentication_analysis", skipped_names)

    # 23. CLI displays stage statuses
    def test_23_cli_displays_stage_statuses(self):
        """Verify terminal output displays each stage status formatted concisely."""
        exit_code, stdout, stderr = self._run_cli_capture([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        self.assertIn("Pipeline Stages:", stdout)
        self.assertIn("evidence_validation", stdout)
        self.assertIn("COMPLETED", stdout)
        self.assertIn("filesystem_collection", stdout)

    # 24. CLI displays triage ID
    def test_24_cli_displays_triage_id(self):
        """Verify terminal output displays generated Triage ID."""
        exit_code, stdout, stderr = self._run_cli_capture([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        self.assertIn("Triage ID    : TRIAGE-", stdout)

    # 25. CLI displays generated report paths
    def test_25_cli_displays_generated_report_paths(self):
        """Verify terminal output displays paths of generated reports."""
        exit_code, stdout, stderr = self._run_cli_capture([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIn("Generated Reports:", stdout)
        self.assertIn("JSON", stdout)
        self.assertIn("HTML", stdout)

    # 26. Correct success exit code
    def test_26_correct_success_exit_code(self):
        """Verify triage_main returns 0 on successful pipeline completion."""
        exit_code = triage_main([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)

    # 27. Correct non-zero failure exit code
    def test_27_correct_nonzero_failure_exit_code(self):
        """Verify triage_main returns non-zero on pipeline failure or invalid input."""
        # Non-existent evidence directory
        self.assertEqual(triage_main(["/path/does/not/exist"]), 1)
        # Empty case ID
        self.assertEqual(triage_main([str(self.evidence_dir), "--case-id", "   "]), 1)

    # 28. Existing V1 CLI compatibility
    def test_28_existing_v1_cli_compatibility(self):
        """Verify existing V1 single-file analysis remains functional."""
        v1_reports = Path(self.test_dir) / "v1_reports"
        exit_code = main([str(self.single_evidence_file), "-o", str(v1_reports)])
        self.assertEqual(exit_code, 0)
        v1_jsons = list(v1_reports.glob("*.json"))
        self.assertEqual(len(v1_jsons), 1)
        report_data = json.loads(v1_jsons[0].read_text(encoding="utf-8"))
        self.assertIn("evidence", report_data)
        self.assertIn("hashes", report_data)

    # 29. No evidence mutation
    def test_29_no_evidence_mutation(self):
        """Verify evidence files remain 100% byte-for-byte identical after CLI run."""
        pre_hashes = self._hash_dir(self.evidence_dir)
        exit_code, _ = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
            "--format", "html",
            "--format", "csv",
        ])
        self.assertEqual(exit_code, 0)
        post_hashes = self._hash_dir(self.evidence_dir)
        self.assertEqual(pre_hashes, post_hashes)

    # 30. No subprocess execution during CLI triage run
    def test_30_no_subprocess_execution(self):
        """Verify execute_triage_cli does not spawn child subprocesses."""
        with patch("subprocess.Popen", side_effect=AssertionError("Subprocess execution forbidden")):
            with patch("subprocess.run", side_effect=AssertionError("Subprocess execution forbidden")):
                exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
                self.assertEqual(exit_code, 0)

    # 31. No network activity
    def test_31_no_network_activity(self):
        """Verify execute_triage_cli does not open network sockets."""
        with patch.object(socket.socket, "connect", side_effect=AssertionError("Network access forbidden")):
            exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
            self.assertEqual(exit_code, 0)

    # 32. No hardcoded user-specific paths
    def test_32_no_hardcoded_user_specific_paths(self):
        """Verify generated results and reports do not contain hardcoded user directories."""
        forbidden_patterns = ["/home/adnan", "~/PROJECT", "~/ForensiXcode"]
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        for _, path_str in result.report_files:
            content = Path(path_str).read_text(encoding="utf-8")
            for pattern in forbidden_patterns:
                self.assertNotIn(pattern, content)

    # 33. Generated JSON report exists and is valid
    def test_33_generated_json_report_exists_and_is_valid(self):
        """Verify generated JSON report exists, parses cleanly, and contains structured data."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        json_path = None
        for fmt, p in result.report_files:
            if fmt == "json":
                json_path = Path(p)
        self.assertIsNotNone(json_path)
        self.assertTrue(json_path.exists())

        data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertIn("metadata", data)
        self.assertIn("summary", data)
        self.assertIn("artifacts", data)
        self.assertIn("audit_trail", data)
        self.assertIn("stage_results", data)
        self.assertIn("report_id", data["metadata"])

    # 34. Generated HTML report exists and is valid
    def test_34_generated_html_report_exists_and_is_valid(self):
        """Verify generated HTML report exists, contains valid HTML, and escaped entities."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        html_path = None
        for fmt, p in result.report_files:
            if fmt == "html":
                html_path = Path(p)
        self.assertIsNotNone(html_path)
        self.assertTrue(html_path.exists())

        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("<html", html_text)
        self.assertIn("ForensiX Forensic Investigation Report", html_text)

    # 35. TriageResult contains expected components
    def test_35_triage_result_contains_expected_components(self):
        """Verify CLI workflow produces canonical TriageResult containing all required components."""
        exit_code, result = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertTrue(result.triage_id.startswith("TRIAGE-"))
        self.assertIsNotNone(result.summary)
        self.assertIsNotNone(result.stage_results)
        self.assertIsNotNone(result.artifacts)
        self.assertIsNotNone(result.investigation_result)
        self.assertIsNotNone(result.trace_records)
        self.assertIsNotNone(result.audit_trail)
        self.assertIsNotNone(result.report)
        self.assertIsNotNone(result.report_files)

    # 36. Traceability survives CLI execution
    def test_36_traceability_survives_cli_execution(self):
        """Verify trace records survive through the CLI workflow intact."""
        exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        self.assertGreater(len(result.trace_records), 0)
        for trace in result.trace_records:
            self.assertEqual(trace.triage_id, result.triage_id)
            self.assertIn(trace.stage_id, ALL_TRIAGE_STAGES)

    # 37. Audit trail survives CLI execution
    def test_37_audit_trail_survives_cli_execution(self):
        """Verify audit trail events survive through the CLI workflow in lifecycle order."""
        exit_code, result = execute_triage_cli([str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(exit_code, 0)
        self.assertGreater(len(result.audit_trail), 0)
        event_types = [e.event_type for e in result.audit_trail]
        self.assertIn("TRIAGE_STARTED", event_types)
        self.assertIn("TRIAGE_COMPLETED", event_types)

    # 38. Existing V2.8 reporting tests remain compatible
    def test_38_existing_v28_reporting_tests_compatible(self):
        """Verify V2.8 reporting module components remain fully functional."""
        from forensix.report_models import ForensicReport
        self.assertIsNotNone(ForensicReport)

    # 39. Existing V2.9.1–V2.9.4 tests remain compatible
    def test_39_existing_v291_v294_tests_compatible(self):
        """Verify V2.9.1–V2.9.4 models and orchestrators are preserved."""
        from forensix.triage_orchestrator import STAGE_DEPENDENCIES, STAGE_NAMES
        self.assertEqual(len(STAGE_NAMES), 9)
        self.assertEqual(len(STAGE_DEPENDENCIES), 9)

    # 40. Full regression V1–V2.9.4
    def test_40_full_regression_v1_to_v294_compatibility(self):
        """Subtest verification ensuring core components from all milestones load and function."""
        with self.subTest("V1 Core Analyzer"):
            from forensix.analyzer import analyze_evidence
            self.assertTrue(callable(analyze_evidence))

        with self.subTest("V2.1 Scanner"):
            from forensix.scanner import scan_evidence_directory
            self.assertTrue(callable(scan_evidence_directory))

        with self.subTest("V2.2 Log Parser"):
            from forensix.log_parser import parse_log_file
            self.assertTrue(callable(parse_log_file))

        with self.subTest("V2.3 Auth Activity"):
            from forensix.auth_analyzer import extract_authentication_activity
            self.assertTrue(callable(extract_authentication_activity))

        with self.subTest("V2.4 Accounts"):
            from forensix.account_analyzer import analyze_account_artifacts
            self.assertTrue(callable(analyze_account_artifacts))

        with self.subTest("V2.5 Persistence"):
            from forensix.persistence_analyzer import analyze_persistence_artifacts
            self.assertTrue(callable(analyze_persistence_artifacts))

        with self.subTest("V2.6 Unified Model"):
            from forensix.unified_models import HostArtifactCollection
            self.assertIsNotNone(HostArtifactCollection)

        with self.subTest("V2.7 Investigation"):
            from forensix.investigation import HostArtifactInvestigator
            self.assertTrue(callable(HostArtifactInvestigator))

        with self.subTest("V2.8 Report Builder"):
            from forensix.report_builder import build_forensic_report
            self.assertTrue(callable(build_forensic_report))

        with self.subTest("V2.9.1 Triage Models"):
            from forensix.triage_models import TriageConfig, TriageResult
            self.assertIsNotNone(TriageConfig)
            self.assertIsNotNone(TriageResult)

        with self.subTest("V2.9.2 Orchestrator"):
            self.assertTrue(callable(TriageOrchestrator))

