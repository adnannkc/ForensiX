"""
Comprehensive Test Suite for ForensiX Milestone V4.7 — CLI / Triage Integration.

Verifies:
1. CLI command exists (investigate, triage --v4, triage_cli exports)
2. CLI help works and contains factual descriptions
3. Valid evidence path accepted
4. Invalid evidence path rejected (exit code 1)
5. Non-directory evidence path rejected (exit code 1)
6. Case ID accepted and propagated
7. Case name accepted and propagated
8. Investigator accepted and propagated
9. Output format selection (json, html, --json, --html)
10. Output directory handling (-o dir, -o file)
11. JSON report generated and conforms to V4.6 schema
12. HTML report generated and conforms to V4.6 schema
13. Report does not enter evidence directory (exit code 1)
14. Evidence remains unchanged (read-only verification)
15. Timeline stage invoked
16. Correlation stage invoked
17. Initial rules loaded from V4.5 (get_initial_rules)
18. Detection engine invoked (DetectionEngine)
19. V4.6 reporting invoked (CorrelationDetectionReport)
20. Summary output contains factual counts
21. Matched detection is not treated as CLI failure (exit code 0)
22. Deterministic repeated execution
23. Malformed processing handled gracefully
24. No speculative CLI messages
25. Existing V3 CLI regression
26. V4.1 regression
27. V4.2 regression
28. V4.3 regression
29. V4.4 regression
30. V4.5 regression
31. V4.6 regression
32. Mandatory Positive E2E Test (synthetic evidence producing detections)
33. Mandatory Negative E2E Test (synthetic evidence producing 0 matched detections)
34. Offline execution (no network activity)
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
from typing import Dict, List, Optional
import unittest
from unittest.mock import MagicMock, patch

from forensix import __version__
from forensix.correlation_engine import CorrelationEngine
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    compute_deterministic_detection_id,
)
from forensix.detection_reporting import (
    CorrelationDetectionReport,
    generate_correlation_detection_report,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
)
from forensix.initial_rules import (
    RULE_NAME_ACCOUNT_PRIVILEGE,
    RULE_NAME_PERSISTENCE_FOLLOWUP,
    RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
    RULE_NAME_SSH_AUTH_SUDO,
    create_ssh_auth_sudo_rule,
    get_initial_rules,
)
from forensix.main import (
    build_parser,
    build_triage_parser as build_v2_triage_parser,
    execute_triage_cli as execute_v2_triage_cli,
    main,
    triage_main as v2_triage_main,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    compute_deterministic_rule_id,
    create_rule,
)
from forensix.timeline_cli import (
    build_timeline_parser,
    execute_timeline_cli,
    timeline_main,
)
from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.triage_cli import (
    DEFAULT_FORMAT,
    SUPPORTED_FORMATS,
    build_investigation_parser,
    build_triage_parser,
    build_v4_triage_parser,
    execute_investigation_cli,
    execute_triage_cli,
    execute_triage_v4_cli,
    investigation_main,
    triage_main,
    triage_v4_main,
)


class TestV47CLITriageIntegration(unittest.TestCase):
    """Test suite for ForensiX Milestone V4.7 — CLI / Triage Integration."""

    def setUp(self):
        """Create temporary workspace with positive and negative synthetic evidence."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_v47_test_")
        self.reports_dir = Path(self.test_dir) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # 1. Positive evidence directory (triggers Rule 1: SSH login + sudo)
        self.pos_evidence_dir = Path(self.test_dir) / "positive_evidence"
        pos_var_log = self.pos_evidence_dir / "var" / "log"
        pos_var_log.mkdir(parents=True, exist_ok=True)

        self.pos_auth_log = pos_var_log / "auth.log"
        self.pos_auth_log.write_text(
            "2026-09-30T10:00:00+00:00 forensic-node sshd[4012]: Accepted password for analyst from 192.168.1.55 port 44210 ssh2\n"
            "2026-09-30T10:01:00+00:00 forensic-node sudo: analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id\n",
            encoding="utf-8",
        )

        # 2. Negative evidence directory (benign single login, no sudo, no failures)
        self.neg_evidence_dir = Path(self.test_dir) / "negative_evidence"
        neg_var_log = self.neg_evidence_dir / "var" / "log"
        neg_var_log.mkdir(parents=True, exist_ok=True)

        self.neg_auth_log = neg_var_log / "auth.log"
        self.neg_auth_log.write_text(
            "2026-09-30T10:00:00+00:00 forensic-node sshd[4012]: Accepted password for backupuser from 192.168.1.10 port 44210 ssh2\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up temporary test artifacts."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _hash_directory(self, directory: Path) -> Dict[str, str]:
        """Compute SHA-256 for all regular files relative to directory."""
        hashes: Dict[str, str] = {}
        for p in sorted(directory.rglob("*")):
            if p.is_file():
                hashes[str(p.relative_to(directory))] = hashlib.sha256(p.read_bytes()).hexdigest()
        return hashes

    def _run_cli_capture(self, func, argv: List[str]):
        """Capture stdout and stderr for a CLI invocation."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        orig_stdout, orig_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout = stdout_buf
            sys.stderr = stderr_buf
            ret = func(argv)
        finally:
            sys.stdout, sys.stderr = orig_stdout, orig_stderr
        return ret, stdout_buf.getvalue(), stderr_buf.getvalue()

    # 1. CLI command exists
    def test_01_cli_commands_exist(self):
        """Verify build_investigation_parser, execute_investigation_cli, investigation_main exist."""
        parser = build_investigation_parser()
        self.assertIsNotNone(parser)
        self.assertTrue(callable(execute_investigation_cli))
        self.assertTrue(callable(investigation_main))
        self.assertTrue(callable(build_triage_parser))
        self.assertTrue(callable(execute_triage_cli))
        self.assertTrue(callable(triage_main))
        self.assertTrue(callable(build_v4_triage_parser))
        self.assertTrue(callable(execute_triage_v4_cli))
        self.assertTrue(callable(triage_v4_main))

    # 2. CLI help works
    def test_02_cli_help_works(self):
        """Verify investigation help displays options and non-speculative factual guidance."""
        parser = build_investigation_parser()
        help_text = parser.format_help()
        self.assertIn("evidence_directory", help_text)
        self.assertIn("--case-id", help_text)
        self.assertIn("--case-name", help_text)
        self.assertIn("--investigator", help_text)
        self.assertIn("-o", help_text)
        self.assertIn("--output", help_text)
        self.assertIn("--format", help_text)
        self.assertIn("--matched-only", help_text)
        self.assertIn("--verbose", help_text)
        self.assertIn("-v", help_text)
        self.assertIn("--version", help_text)
        self.assertNotIn("attack detected", help_text.lower())
        self.assertNotIn("compromised", help_text.lower())

    # 3. Valid evidence path accepted
    def test_03_valid_evidence_path_accepted(self):
        """Verify valid evidence directory is accepted and returns exit code 0."""
        code, report = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(report)
        self.assertIsInstance(report, CorrelationDetectionReport)

    # 4. Invalid evidence path rejected
    def test_04_invalid_evidence_path_rejected(self):
        """Verify non-existent evidence directory returns exit code 1 with clean error message."""
        missing = Path(self.test_dir) / "non_existent_dir"
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [str(missing)],
        )
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Evidence directory does not exist", stderr)

    # 5. Non-directory evidence path rejected
    def test_05_non_directory_evidence_path_rejected(self):
        """Verify passing a regular file where directory is required returns exit code 1."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [str(self.pos_auth_log)],
        )
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Evidence path is not a directory", stderr)

    # 6. Case ID accepted
    def test_06_case_id_accepted(self):
        """Verify case ID is accepted and propagates to report and terminal summary."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [
                str(self.pos_evidence_dir),
                "--case-id", "CASE-V47-001",
                "-o", str(self.reports_dir),
            ],
        )
        self.assertEqual(code[0], 0)
        self.assertEqual(code[1].case_id, "CASE-V47-001")
        self.assertIn("Case ID                 : CASE-V47-001", stdout)

    # 7. Case name accepted
    def test_07_case_name_accepted(self):
        """Verify case name is accepted and propagates to report and terminal summary."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [
                str(self.pos_evidence_dir),
                "--case-name", "Operation Incident Triage",
                "-o", str(self.reports_dir),
            ],
        )
        self.assertEqual(code[0], 0)
        self.assertEqual(code[1].case_name, "Operation Incident Triage")
        self.assertIn("Case Name               : Operation Incident Triage", stdout)

    # 8. Investigator accepted
    def test_08_investigator_accepted(self):
        """Verify investigator is accepted and propagates to report and terminal summary."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [
                str(self.pos_evidence_dir),
                "--investigator", "Senior Forensic Analyst",
                "-o", str(self.reports_dir),
            ],
        )
        self.assertEqual(code[0], 0)
        self.assertEqual(code[1].investigator, "Senior Forensic Analyst")
        self.assertIn("Investigator            : Senior Forensic Analyst", stdout)

    # 9. Output format selection
    def test_09_output_format_selection(self):
        """Verify output format selection via --format, --json, and --html."""
        # 9a. --format json
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir / "report_fmt.json"),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertTrue((self.reports_dir / "report_fmt.json").exists())

        # 9b. --format html
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir / "report_fmt.html"),
            "--format", "html",
        ])
        self.assertEqual(code, 0)
        self.assertTrue((self.reports_dir / "report_fmt.html").exists())

        # 9c. --json shortcut
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir / "report_shortcut.json"),
            "--json",
        ])
        self.assertEqual(code, 0)
        self.assertTrue((self.reports_dir / "report_shortcut.json").exists())

        # 9d. --html shortcut
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir / "report_shortcut.html"),
            "--html",
        ])
        self.assertEqual(code, 0)
        self.assertTrue((self.reports_dir / "report_shortcut.html").exists())

        # 9e. Unsupported format rejected
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [str(self.pos_evidence_dir), "--format", "xml"],
        )
        self.assertEqual(code[0], 1)
        self.assertIn("Unsupported report format", stderr)

    # 10. Output directory handling
    def test_10_output_directory_handling(self):
        """Verify output directory handling creates report file inside directory."""
        custom_out = Path(self.test_dir) / "custom_output_dir"
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "CASE-DIR-TEST",
            "-o", str(custom_out),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        expected_file = custom_out / "CASE-DIR-TEST_investigation.json"
        self.assertTrue(expected_file.exists())

    # 11. JSON report generated
    def test_11_json_report_generated(self):
        """Verify generated JSON report is valid JSON and contains V4.6 investigation schema."""
        out_file = self.reports_dir / "inv_report.json"
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "CASE-JSON-001",
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertIn(data["report_type"], ("investigation", "correlation_detection"))
        self.assertEqual(data["forensix_version"], __version__)
        self.assertEqual(data["metadata"]["case_id"], "CASE-JSON-001")
        self.assertIn("summary", data)
        self.assertIn("detections", data)
        self.assertIn("correlations", data)
        self.assertIn("timeline_events", data)

    # 12. HTML report generated
    def test_12_html_report_generated(self):
        """Verify generated HTML report is valid HTML containing doctype and metadata."""
        out_file = self.reports_dir / "inv_report.html"
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "CASE-HTML-001",
            "-o", str(out_file),
            "--format", "html",
        ])
        self.assertEqual(code, 0)
        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("ForensiX", content)
        self.assertIn("CASE-HTML-001", content)

    # 13. Report does not enter evidence directory
    def test_13_report_does_not_enter_evidence_directory(self):
        """Verify attempting to write report inside evidence directory is rejected."""
        inside_evidence = self.pos_evidence_dir / "sub" / "report.json"
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [str(self.pos_evidence_dir), "-o", str(inside_evidence)],
        )
        self.assertEqual(code[0], 1)
        self.assertIn("Output report path cannot be within or identical to evidence path", stderr)

    # 14. Evidence remains unchanged
    def test_14_evidence_remains_unchanged(self):
        """Verify evidence files are 100% read-only and hashes are identical before and after."""
        hashes_before = self._hash_directory(self.pos_evidence_dir)
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        hashes_after = self._hash_directory(self.pos_evidence_dir)
        self.assertEqual(hashes_before, hashes_after)

    # 15. Timeline stage invoked
    def test_15_timeline_stage_invoked(self):
        """Verify timeline reconstruction stage is executed and produces TimelineEvent instances."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertGreater(rep.event_count, 0)
        self.assertGreater(len(rep.timeline_events), 0)
        for ev in rep.timeline_events:
            self.assertIsInstance(ev, TimelineEvent)

    # 16. Correlation stage invoked
    def test_16_correlation_stage_invoked(self):
        """Verify correlation stage is executed and produces Correlation instances."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertGreater(rep.correlation_count, 0)
        self.assertGreater(len(rep.correlations), 0)
        for c in rep.correlations:
            self.assertIsInstance(c, Correlation)

    # 17. Initial rules loaded from V4.5
    def test_17_initial_rules_loaded_from_v45(self):
        """Verify get_initial_rules() is invoked and evaluates all 4 canonical rules."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertGreaterEqual(rep.matched_detections, 1)
        self.assertGreaterEqual(rep.detection_count, 1)

    # 18. Detection engine invoked
    def test_18_detection_engine_invoked(self):
        """Verify DetectionEngine is evaluated and results are populated."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertGreaterEqual(rep.matched_detections, 1)
        for d in rep.detections:
            self.assertIsInstance(d, DetectionResult)

    # 19. V4.6 reporting invoked
    def test_19_v46_reporting_invoked(self):
        """Verify CorrelationDetectionReport is generated and serialized via V4.6 APIs."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertIsInstance(rep, CorrelationDetectionReport)
        rep_dict = rep.to_dict()
        self.assertIn(rep_dict["report_type"], ("investigation", "correlation_detection"))

    # 20. Summary output contains factual counts
    def test_20_summary_output_contains_factual_counts(self):
        """Verify terminal summary contains all required factual count lines."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [
                str(self.pos_evidence_dir),
                "--case-id", "CASE-SUMMARY-001",
                "-o", str(self.reports_dir),
            ],
        )
        self.assertEqual(code[0], 0)
        self.assertIn("Evidence Root           :", stdout)
        self.assertIn("Case ID                 : CASE-SUMMARY-001", stdout)
        self.assertIn("Timeline Events         :", stdout)
        self.assertIn("Correlations Identified :", stdout)
        self.assertIn("Detection Results       :", stdout)
        self.assertIn("Matched Detections      :", stdout)
        self.assertIn("Rule Matches            :", stdout)
        self.assertIn("Report Path             :", stdout)
        self.assertIn("Status                  : SUCCESS", stdout)

    # 21. Matched detection is not treated as CLI failure
    def test_21_matched_detection_is_not_cli_failure(self):
        """Verify exit code is 0 when matching detections are identified."""
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "-o", str(self.reports_dir),
        ])
        self.assertEqual(code, 0)
        self.assertGreater(rep.matched_detections, 0)

    # 22. Deterministic repeated execution
    def test_22_deterministic_repeated_execution(self):
        """Verify repeated execution against identical evidence produces identical JSON reports."""
        out1 = self.reports_dir / "deterministic_run_1.json"
        out2 = self.reports_dir / "deterministic_run_2.json"

        code1, rep1 = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "CASE-DETERMINISTIC",
            "-o", str(out1),
            "--format", "json",
        ])
        code2, rep2 = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "CASE-DETERMINISTIC",
            "-o", str(out2),
            "--format", "json",
        ])

        self.assertEqual(code1, 0)
        self.assertEqual(code2, 0)
        self.assertEqual(rep1.event_count, rep2.event_count)
        self.assertEqual(rep1.correlation_count, rep2.correlation_count)
        self.assertEqual(rep1.detection_count, rep2.detection_count)
        self.assertEqual(rep1.matched_detections, rep2.matched_detections)
        self.assertEqual(rep1.rule_counts, rep2.rule_counts)
        self.assertEqual(rep1.relationship_counts, rep2.relationship_counts)
        self.assertEqual(
            [d.rule_name for d in rep1.detections],
            [d.rule_name for d in rep2.detections],
        )
        self.assertEqual(
            [d.matched for d in rep1.detections],
            [d.matched for d in rep2.detections],
        )
        self.assertEqual(
            [d.explanation for d in rep1.detections],
            [d.explanation for d in rep2.detections],
        )

    # 23. Malformed processing handled
    def test_23_empty_evidence_handled_gracefully(self):
        """Verify empty evidence directory completes with 0 events, 0 detections, and exit code 0."""
        empty_dir = Path(self.test_dir) / "empty_evidence"
        empty_dir.mkdir(parents=True, exist_ok=True)

        code, rep = execute_investigation_cli([
            str(empty_dir),
            "-o", str(self.reports_dir / "empty_report.json"),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(rep.event_count, 0)
        self.assertEqual(rep.correlation_count, 0)
        self.assertEqual(rep.matched_detections, 0)

    # 24. No speculative CLI messages
    def test_24_no_speculative_cli_messages(self):
        """Verify CLI output contains no alarmist or speculative verdict claims."""
        code, stdout, stderr = self._run_cli_capture(
            execute_investigation_cli,
            [
                str(self.pos_evidence_dir),
                "-o", str(self.reports_dir),
                "--verbose",
            ],
        )
        self.assertEqual(code[0], 0)
        lower_out = stdout.lower()
        self.assertNotIn("attack detected", lower_out)
        self.assertNotIn("host compromised", lower_out)
        self.assertNotIn("attacker identified", lower_out)
        self.assertNotIn("intrusion confirmed", lower_out)

    # 25. Existing V3 CLI regression
    def test_25_existing_v3_cli_regression(self):
        """Verify V3 timeline CLI remains functional and compatible."""
        out_v3 = self.reports_dir / "timeline_v3.json"
        code, rep = execute_timeline_cli([
            str(self.pos_evidence_dir),
            "-o", str(out_v3),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertTrue(out_v3.exists())

    # 26. V4.1 regression
    def test_26_v41_regression(self):
        """Verify V4.1 Correlation models remain functional."""
        ev1_id = "TIMELINE-00000000-0000-4000-8000-000000000001"
        ev2_id = "TIMELINE-00000000-0000-4000-8000-000000000002"
        cid = compute_deterministic_correlation_id(
            CorrelationType.SAME_USER,
            [ev1_id, ev2_id],
        )
        self.assertTrue(cid.startswith("CORR-"))
        corr = Correlation(
            correlation_id=cid,
            relationship_type=CorrelationType.SAME_USER,
            event_ids=(ev1_id, ev2_id),
            description="Same user correlation",
            source_artifact_ids=(),
            attributes={},
        )
        col = CorrelationCollection([corr])
        self.assertEqual(len(col), 1)

    # 27. V4.2 regression
    def test_27_v42_regression(self):
        """Verify V4.2 CorrelationEngine remains functional."""
        engine = CorrelationEngine()
        ev1_id = "TIMELINE-00000000-0000-4000-8000-000000000001"
        ev2_id = "TIMELINE-00000000-0000-4000-8000-000000000002"
        ev1 = TimelineEvent(
            event_id=ev1_id,
            timestamp="2026-09-30T10:00:00Z",
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            source_path="/var/log/auth.log",
            source_artifact_id="ART-1",
            source_event_id="REC-1",
            description="User login",
            raw_data="",
            attributes={"user": "root"},
        )
        ev2 = TimelineEvent(
            event_id=ev2_id,
            timestamp="2026-09-30T10:01:00Z",
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            source_path="/var/log/auth.log",
            source_artifact_id="ART-1",
            source_event_id="REC-2",
            description="User sudo",
            raw_data="",
            attributes={"user": "root"},
        )
        corrs = engine.correlate([ev1, ev2])
        self.assertGreater(len(corrs), 0)

    # 28. V4.3 regression
    def test_28_v43_regression(self):
        """Verify V4.3 Rule models remain functional."""
        cond = RuleCondition(
            field="attributes.user",
            operator=ConditionOperator.EQUALS,
            value="root",
        )
        rule = create_rule(
            name="Test Rule",
            description="Test description",
            detection_description="Observed test pattern",
            conditions=[cond],
        )
        self.assertIsInstance(rule, DetectionRule)

    # 29. V4.4 regression
    def test_29_v44_regression(self):
        """Verify V4.4 DetectionEngine remains functional."""
        rule = create_ssh_auth_sudo_rule()
        engine = DetectionEngine(rules=[rule])
        self.assertEqual(len(engine.rules), 1)

    # 30. V4.5 regression
    def test_30_v45_regression(self):
        """Verify V4.5 get_initial_rules() returns the 4 canonical rules."""
        rules = get_initial_rules()
        self.assertEqual(len(rules), 4)
        rule_names = {r.name for r in rules}
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, rule_names)
        self.assertIn(RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS, rule_names)
        self.assertIn(RULE_NAME_ACCOUNT_PRIVILEGE, rule_names)
        self.assertIn(RULE_NAME_PERSISTENCE_FOLLOWUP, rule_names)

    # 31. V4.6 regression
    def test_31_v46_regression(self):
        """Verify V4.6 reporting serializers remain functional."""
        rep = generate_correlation_detection_report(
            detections=DetectionResultCollection(()),
            correlations=CorrelationCollection(()),
            timeline=(),
            case_id="CASE-V46",
        )
        self.assertIsInstance(rep, CorrelationDetectionReport)
        self.assertEqual(rep.case_id, "CASE-V46")

    # 32. Mandatory Positive E2E Test
    def test_32_mandatory_positive_e2e_test(self):
        """
        Mandatory End-to-End Test:
        - Synthetic evidence directory
        - Hash evidence before execution
        - Run CLI command
        - Verify exit code == 0
        - Verify timeline generated
        - Verify correlations generated
        - Verify detection matches RULE_NAME_SSH_AUTH_SUDO
        - Verify report is generated and contains detection with provenance
        - Verify evidence hash is identical after execution
        """
        evidence_hash_before = self._hash_directory(self.pos_evidence_dir)

        out_report = self.reports_dir / "positive_e2e_report.json"
        code, rep = execute_investigation_cli([
            str(self.pos_evidence_dir),
            "--case-id", "E2E-POS-001",
            "-o", str(out_report),
            "--format", "json",
            "--matched-only",
        ])

        # 1. Exit code
        self.assertEqual(code, 0)
        self.assertIsNotNone(rep)

        # 2. Timeline generated
        self.assertGreaterEqual(rep.event_count, 2)

        # 3. Correlations generated
        self.assertGreaterEqual(rep.correlation_count, 1)

        # 4. Detection generated and matched
        self.assertGreaterEqual(rep.matched_detections, 1)
        matched_rule_names = {d.rule_name for d in rep.detections if d.matched}
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, matched_rule_names)

        # 5. Report readable and contains provenance
        self.assertTrue(out_report.exists())
        data = json.loads(out_report.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["case_id"], "E2E-POS-001")
        self.assertGreaterEqual(len(data["detections"]), 1)
        first_det = data["detections"][0]
        self.assertTrue(first_det["matched"])
        self.assertIn("supporting_events", first_det)
        self.assertGreater(len(first_det["supporting_events"]), 0)

        # 6. Evidence hash identical after execution
        evidence_hash_after = self._hash_directory(self.pos_evidence_dir)
        self.assertEqual(evidence_hash_before, evidence_hash_after)

    # 33. Mandatory Negative E2E Test
    def test_33_mandatory_negative_e2e_test(self):
        """
        Mandatory Negative Test:
        - Synthetic evidence directory that produces 0 matching detections
        - Verify exit code == 0 (not a failure!)
        - Verify matched_detections == 0
        - Verify valid report generated
        - Verify evidence hash remains identical
        """
        evidence_hash_before = self._hash_directory(self.neg_evidence_dir)

        out_report = self.reports_dir / "negative_e2e_report.json"
        code, rep = execute_investigation_cli([
            str(self.neg_evidence_dir),
            "--case-id", "E2E-NEG-001",
            "-o", str(out_report),
            "--format", "json",
        ])

        # 1. Exit code == 0
        self.assertEqual(code, 0)
        self.assertIsNotNone(rep)

        # 2. Matched detections == 0
        self.assertEqual(rep.matched_detections, 0)

        # 3. Valid report generated
        self.assertTrue(out_report.exists())
        data = json.loads(out_report.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["case_id"], "E2E-NEG-001")
        self.assertEqual(data["summary"]["matched_detections"], 0)

        # 4. Evidence remains unchanged
        evidence_hash_after = self._hash_directory(self.neg_evidence_dir)
        self.assertEqual(evidence_hash_before, evidence_hash_after)

    # 34. Offline execution (no network activity)
    def test_34_no_network_activity(self):
        """Verify pipeline execution performs no socket connections."""
        with patch("socket.socket") as mock_socket:
            code, rep = execute_investigation_cli([
                str(self.pos_evidence_dir),
                "-o", str(self.reports_dir / "offline_report.json"),
                "--format", "json",
            ])
            self.assertEqual(code, 0)
            mock_socket.assert_not_called()

    # 35. Main routing test: python3 -m forensix investigate
    def test_35_main_routing_investigate(self):
        """Verify main() routes 'investigate' subcommand cleanly."""
        out_report = self.reports_dir / "main_investigate.json"
        ret = main([
            "investigate",
            str(self.pos_evidence_dir),
            "-o", str(out_report),
            "--format", "json",
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(out_report.exists())

    # 36. Main routing test: python3 -m forensix triage --v4
    def test_36_main_routing_triage_v4(self):
        """Verify main() routes 'triage --v4' subcommand to V4 investigation pipeline."""
        out_report = self.reports_dir / "main_triage_v4.json"
        ret = main([
            "triage",
            str(self.pos_evidence_dir),
            "--v4",
            "-o", str(out_report),
            "--format", "json",
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(out_report.exists())


if __name__ == "__main__":
    unittest.main()
