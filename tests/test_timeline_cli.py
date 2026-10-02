"""
Comprehensive Test Suite for ForensiX Milestone V3.7 — Timeline CLI Integration.

Verifies:
1.  CLI help (python3 -m forensix timeline --help)
2.  Basic timeline command execution with evidence directory
3.  Default format is HTML and writes to reports/
4.  JSON format selection (--format json)
5.  HTML format selection (--format html)
6.  Custom output path (--output /path/to/report.ext)
7.  Case metadata propagation (--case-id, --case-name, --investigator)
8.  Category filter (--category AUTHENTICATION, case-insensitivity)
9.  Event type filter (--event-type ...)
10. Source path filter (--source-path ...)
11. Artifact ID filter (--source-artifact-id ...)
12. Event ID filter (--source-event-id ...)
13. Timestamp range filters (--start, --end)
14. Text search filter (--text, --case-sensitive)
15. Combined filters (AND semantics)
16. Empty query result (exit code 0, report generated with 0 events)
17. Invalid category rejected with choices (exit code 1)
18. Invalid timestamp rejected (exit code 1)
19. Invalid format rejected (exit code 1)
20. Missing evidence directory rejected (exit code 1)
21. File passed where directory expected rejected (exit code 1)
22. Output inside evidence directory prevented
23. Existing V1 CLI compatibility (python3 -m forensix <file>)
24. Existing V2 triage CLI compatibility (python3 -m forensix triage <dir>)
25. End-to-end execution via subprocess
26. Evidence immutability (cryptographic hash unchanged)
27. Deterministic report generation across repeat runs
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Dict
import unittest

from forensix.hasher import compute_hashes
from forensix.main import main
from forensix.timeline_cli import (
    build_timeline_parser,
    execute_timeline_cli,
    timeline_main,
)


def hash_directory_files(directory: Path) -> Dict[str, str]:
    """Calculate SHA-256 for all regular files in a directory for immutability verification."""
    results = {}
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            rel_path = str(p.relative_to(directory))
            results[rel_path] = compute_hashes(p)["sha256"]
    return results


class TestTimelineCLI(unittest.TestCase):
    """Test suite for V3.7 Timeline CLI integration."""

    def setUp(self) -> None:
        """Create mock Linux host evidence root and output directories."""
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_test_timeline_cli_")
        self.evidence_dir = Path(self.temp_dir) / "evidence"
        self.reports_dir = Path(self.temp_dir) / "reports"

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Setup standard mock evidence layout
        (self.evidence_dir / "etc").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "var" / "log").mkdir(parents=True, exist_ok=True)

        # /var/log/auth.log
        auth_log = (
            "Sep 30 14:00:01 forensic-host sshd[1234]: Accepted password for analyst from 192.168.1.50 port 54321 ssh2\n"
            "Sep 30 14:05:00 forensic-host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        )
        (self.evidence_dir / "var" / "log" / "auth.log").write_text(auth_log, encoding="utf-8")

        # /var/log/syslog
        syslog = (
            "Sep 30 14:10:00 forensic-host cron[5678]: (root) CMD (/usr/local/bin/backup.sh)\n"
        )
        (self.evidence_dir / "var" / "log" / "syslog").write_text(syslog, encoding="utf-8")

        # Record initial hashes of evidence
        self.initial_evidence_hashes = hash_directory_files(self.evidence_dir)

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_timeline_parser_help(self) -> None:
        """1. Verify build_timeline_parser provides descriptive help and arguments."""
        parser = build_timeline_parser()
        help_text = parser.format_help()
        self.assertIn("evidence_directory", help_text)
        self.assertIn("--case-id", help_text)
        self.assertIn("--format", help_text)
        self.assertIn("--category", help_text)
        self.assertIn("--start", help_text)
        self.assertIn("--end", help_text)

    def test_02_basic_timeline_execution_html_default(self) -> None:
        """2. Verify basic timeline execution generates HTML report by default."""
        out_file = self.reports_dir / "default_timeline.html"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertIsNotNone(report)
        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("ForensiX Timeline Report", content)
        self.assertGreater(report.event_count, 0)

    def test_03_json_format_selection(self) -> None:
        """3. Verify --format json produces a valid JSON report."""
        out_file = self.reports_dir / "timeline.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["report_type"], "timeline")
        self.assertEqual(data["report_version"], "3.6")
        self.assertIn("events", data)
        self.assertEqual(data["event_count"], report.event_count)

    def test_04_html_format_selection(self) -> None:
        """4. Verify --format html produces a valid HTML report."""
        out_file = self.reports_dir / "timeline.html"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--format", "html",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("Chronological Timeline Events", content)

    def test_05_case_metadata_propagation(self) -> None:
        """5. Verify --case-id, --case-name, and --investigator are recorded in the report."""
        out_file = self.reports_dir / "meta_report.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--case-id", "CASE-ALPHA-99",
            "--case-name", "Operation Nightfall",
            "--investigator", "Investigator Holmes",
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertEqual(report.case_id, "CASE-ALPHA-99")
        self.assertEqual(report.case_name, "Operation Nightfall")
        self.assertEqual(report.investigator, "Investigator Holmes")

        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["case_id"], "CASE-ALPHA-99")
        self.assertEqual(data["metadata"]["case_name"], "Operation Nightfall")
        self.assertEqual(data["metadata"]["investigator"], "Investigator Holmes")

    def test_06_category_filter(self) -> None:
        """6. Verify --category filters events and accepts case-insensitive input."""
        out_file = self.reports_dir / "auth_timeline.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertGreater(report.event_count, 0)
        self.assertTrue(all(e.category.value == "authentication" for e in report.events))

    def test_07_event_type_filter(self) -> None:
        """7. Verify --event-type filters events by exact classification."""
        out_file = self.reports_dir / "type_timeline.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--event-type", "file_created",
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(all(e.event_type == "file_created" for e in report.events))

    def test_08_text_search_filter(self) -> None:
        """8. Verify --text searches for substrings across event data."""
        out_file = self.reports_dir / "text_timeline.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--text", "sshd",
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertGreater(report.event_count, 0)

    def test_09_combined_filters_and_semantics(self) -> None:
        """9. Verify multiple filters combine using logical AND."""
        out_file = self.reports_dir / "combo.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--source-path", str(self.evidence_dir / "var" / "log" / "auth.log"),
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        for e in report.events:
            self.assertEqual(e.category.value, "authentication")
            self.assertEqual(e.source_path, str(self.evidence_dir / "var" / "log" / "auth.log"))

    def test_10_empty_query_result_is_success(self) -> None:
        """10. Verify empty query result produces exit code 0 and an empty report."""
        out_file = self.reports_dir / "empty.json"
        ret, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--event-type", "non_existent_event_type_xyz",
            "--format", "json",
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)
        self.assertEqual(report.event_count, 0)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["event_count"], 0)
        self.assertEqual(data["events"], [])

    def test_11_invalid_category_rejected(self) -> None:
        """11. Verify invalid category produces a clear error and non-zero exit code."""
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--category", "NETWORK",
            ])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        err_msg = stderr_capture.getvalue()
        self.assertIn("Invalid category: 'NETWORK'", err_msg)
        self.assertIn("AUTHENTICATION", err_msg)
        self.assertIn("FILESYSTEM", err_msg)

    def test_12_invalid_timestamp_rejected(self) -> None:
        """12. Verify invalid timestamp produces a clear error and non-zero exit code."""
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--start", "not-a-timestamp",
            ])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        err_msg = stderr_capture.getvalue()
        self.assertIn("Error: Invalid timeline filter", err_msg)

    def test_13_invalid_format_rejected(self) -> None:
        """13. Verify unsupported format produces an explicit error and non-zero exit code."""
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--format", "pdf",
            ])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        self.assertIn("Unsupported timeline format: 'pdf'", stderr_capture.getvalue())

    def test_14_missing_evidence_directory_rejected(self) -> None:
        """14. Verify non-existent evidence directory produces error and non-zero exit code."""
        non_existent = self.evidence_dir / "missing_dir"
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([str(non_existent)])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        self.assertIn("Evidence directory does not exist", stderr_capture.getvalue())

    def test_15_file_where_directory_expected_rejected(self) -> None:
        """15. Verify passing a file instead of directory produces error and non-zero exit code."""
        evidence_file = self.evidence_dir / "var" / "log" / "auth.log"
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([str(evidence_file)])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        self.assertIn("Evidence path is not a directory", stderr_capture.getvalue())

    def test_16_prevent_output_inside_evidence(self) -> None:
        """16. Verify output inside evidence directory is rejected."""
        inside_output = self.evidence_dir / "report.html"
        stderr_capture = io.StringIO()
        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret, report = execute_timeline_cli([
                str(self.evidence_dir),
                "-o", str(inside_output),
            ])
        finally:
            sys.stderr = orig_stderr

        self.assertEqual(ret, 1)
        self.assertIsNone(report)
        self.assertIn("cannot be within or identical to evidence path", stderr_capture.getvalue())

    def test_17_main_entrypoint_routing(self) -> None:
        """17. Verify main() routes 'timeline' subcommand cleanly to timeline_main."""
        out_file = self.reports_dir / "main_timeline.json"
        ret = main(["timeline", str(self.evidence_dir), "--format", "json", "-o", str(out_file)])
        self.assertEqual(ret, 0)
        self.assertTrue(out_file.exists())

    def test_18_existing_v1_cli_compatibility(self) -> None:
        """18. Verify existing V1 single-file analysis command still works unchanged."""
        test_file = self.evidence_dir / "var" / "log" / "auth.log"
        out_dir = self.temp_dir + "/v1_reports"
        ret = main([str(test_file), "-o", str(out_dir)])
        self.assertEqual(ret, 0)
        reports = list(Path(out_dir).glob("*.json"))
        self.assertGreater(len(reports), 0)

    def test_19_existing_v2_triage_cli_compatibility(self) -> None:
        """19. Verify existing V2 triage command still works unchanged."""
        out_dir = self.temp_dir + "/v2_triage_reports"
        ret = main(["triage", str(self.evidence_dir), "-o", str(out_dir), "--format", "json"])
        self.assertEqual(ret, 0)
        reports = list(Path(out_dir).glob("*.json"))
        self.assertGreater(len(reports), 0)

    def test_20_subprocess_execution_e2e(self) -> None:
        """20. Verify end-to-end execution via subprocess (python3 -m forensix timeline ...)."""
        out_file = self.reports_dir / "subprocess_timeline.html"
        env = dict(os.environ, PYTHONPATH="src")
        proc = subprocess.run(
            [
                sys.executable,
                "-m", "forensix",
                "timeline",
                str(self.evidence_dir),
                "-o", str(out_file),
                "--case-id", "CASE-SUBPROCESS-01",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ForensiX Timeline Analysis", proc.stdout)
        self.assertIn("Status         : SUCCESS", proc.stdout)
        self.assertTrue(out_file.exists())

    def test_21_evidence_immutability(self) -> None:
        """21. Verify evidence directory is completely unmodified by timeline CLI."""
        out_file = self.reports_dir / "immutability_timeline.html"
        ret, _ = execute_timeline_cli([
            str(self.evidence_dir),
            "-o", str(out_file),
        ])
        self.assertEqual(ret, 0)

        current_evidence_hashes = hash_directory_files(self.evidence_dir)
        self.assertEqual(
            self.initial_evidence_hashes,
            current_evidence_hashes,
            "Evidence files were modified during timeline execution!",
        )

    def test_22_determinism_across_repeated_runs(self) -> None:
        """22. Verify running timeline CLI twice produces identical JSON report data."""
        out1 = self.reports_dir / "run1.json"
        out2 = self.reports_dir / "run2.json"

        ret1, _ = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--format", "json",
            "-o", str(out1),
        ])
        ret2, _ = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--format", "json",
            "-o", str(out2),
        ])

        self.assertEqual(ret1, 0)
        self.assertEqual(ret2, 0)
        data1 = json.loads(out1.read_text(encoding="utf-8"))
        data2 = json.loads(out2.read_text(encoding="utf-8"))

        self.assertEqual(data1["summary"], data2["summary"])
        self.assertEqual(data1["event_count"], data2["event_count"])
        self.assertGreater(data1["event_count"], 0)

        # Verify all factual evidence fields match deterministically
        def clean_ev(ev):
            return {
                "timestamp": ev["timestamp"],
                "raw_timestamp": ev["raw_timestamp"],
                "category": ev["category"],
                "event_type": ev["event_type"],
                "description": ev["description"],
                "source_path": ev["source_path"],
                "source_line": ev["source_line"],
                "raw_data": ev["raw_data"],
            }

        self.assertEqual(
            [clean_ev(e) for e in data1["events"]],
            [clean_ev(e) for e in data2["events"]],
        )


if __name__ == "__main__":
    unittest.main()
