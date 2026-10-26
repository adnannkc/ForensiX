"""
Unit and Integration Tests for ForensiX V9 Pipeline CLI.

Validates:
1. --help displays command description, options, and exit codes.
2. Direct execution via --config <path> to JSON case specification.
3. Direct execution via command-line flags (--case-id, --host-dir, --output-dir).
4. CLI validation failure (missing evidence) exits with code 1.
5. Manifest discrepancy yields exit code 2.
6. Dispatch from forensix.main:main(['run', ...]) and forensix.main:main(['pipeline', ...]).
"""

import io
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from forensix.main import main
from forensix.pipeline_cli import execute_pipeline_cli, pipeline_main, print_pipeline_findings
from forensix.pipeline_engine import PipelineExecutionResult


def _create_synthetic_pcap(path: Path) -> None:
    """Create minimal valid classic PCAP file."""
    global_hdr = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack(">IIII", 1760000000, 500000, 54, 54)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0x4000, 64, 6, 0,
        bytes([192, 0, 2, 10]), bytes([198, 51, 100, 25]),
    )
    tcp = struct.pack(">HHIIBBHHH", 54321, 22, 100, 0, 0x50, 0x02, 64240, 0, 0)
    path.write_bytes(global_hdr + pkt_hdr + eth + ip + tcp)


def _create_synthetic_host(root: Path) -> None:
    """Create minimal synthetic host structure."""
    etc_dir = root / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    (etc_dir / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nanalyst:x:1001:1001::/home/analyst:/bin/bash\n")
    (etc_dir / "group").write_text("root:x:0:\nanalyst:x:1001:\n")


class TestPipelineCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.host_dir = self.base_dir / "evidence_host"
        _create_synthetic_host(self.host_dir)

        self.pcap_file = self.base_dir / "traffic.pcap"
        _create_synthetic_pcap(self.pcap_file)

        self.out_dir = self.base_dir / "reports_out"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_help_flag(self):
        """Prove --help displays usage and exits with SystemExit(0)."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                pipeline_main(["--help"])
            self.assertEqual(cm.exception.code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("ForensiX V9", output)
        self.assertIn("--config", output)
        self.assertIn("Exit Codes", output)

    def test_direct_flags_run(self):
        """Prove pipeline CLI runs successfully with direct command line flags."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--case-id", "CLI-DIRECT-01",
                "--evidence-host-dir", str(self.host_dir),
                "--evidence-pcap", str(self.pcap_file),
                "-o", str(self.out_dir),
                "--overwrite",
            ])
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())
        self.assertIn("Execution Summary", stdout_buf.getvalue())
        self.assertIn("CLI-DIRECT-01", stdout_buf.getvalue())

    def test_config_file_run(self):
        """Prove pipeline CLI runs successfully via --config JSON file."""
        case_data = {
            "case_id": "CLI-CONFIG-01",
            "case_name": "Config File Test",
            "investigator": "Test Analyst",
            "evidence_host_dir": str(self.host_dir),
            "output_dir": str(self.out_dir),
            "overwrite": True,
        }
        cfg_path = self.base_dir / "case.json"
        cfg_path.write_text(json.dumps(case_data, indent=2), encoding="utf-8")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main(["--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())
        self.assertIn("CLI-CONFIG-01", stdout_buf.getvalue())

    def test_validation_error_missing_evidence(self):
        """Prove missing evidence inputs produce validation error and exit code 1."""
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = pipeline_main([
                "--case-id", "NO-EVIDENCE",
                "-o", str(self.out_dir),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("Case configuration must declare at least one evidence input", stderr_buf.getvalue())

    def test_main_dispatch_run_and_pipeline(self):
        """Prove forensix.main:main correctly routes 'run' and 'pipeline' subcommands."""
        # Test routing for 'run'
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code_run = main([
                "run",
                "--case-id", "MAIN-RUN-01",
                "--evidence-host-dir", str(self.host_dir),
                "-o", str(self.out_dir),
                "--overwrite",
            ])
        self.assertEqual(code_run, 0)

        # Test routing for 'pipeline' alias
        out_dir_2 = self.base_dir / "out2"
        with patch("sys.stdout", stdout_buf):
            code_pipeline = main([
                "pipeline",
                "--case-id", "MAIN-PIPELINE-01",
                "--evidence-host-dir", str(self.host_dir),
                "-o", str(out_dir_2),
                "--overwrite",
            ])
        self.assertEqual(code_pipeline, 0)
        self.assertTrue((out_dir_2 / "pipeline_manifest.json").exists())

    def test_show_findings_default_off(self):
        """Without --show-findings, terminal output equals the standard summary without findings block."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--config", "examples/case-synthetic/case.json",
                "-o", str(self.out_dir),
                "--overwrite",
            ])
        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("Execution Summary", output)
        self.assertNotIn("ForensiX V9 - Observed Rule Matches", output)
        self.assertNotIn("Matches are observations to review", output)

    def test_terminal_findings_match_json_report(self):
        """With --show-findings, every rule_name in JSON report details['detections'] appears with same match count."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--config", "examples/case-synthetic/case.json",
                "-o", str(self.out_dir),
                "--overwrite",
                "--show-findings",
            ])
        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()

        # Read the generated JSON report
        report_path = self.out_dir / "report_CASE-2026-SYNTHETIC-001.json"
        self.assertTrue(report_path.exists())
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        detections = data.get("details", {}).get("detections", [])
        expected_counts = {}
        for d in detections:
            if d.get("matched", True):
                name = d.get("rule_name")
                expected_counts[name] = expected_counts.get(name, 0) + 1

        self.assertGreater(len(expected_counts), 0)
        for rule_name, count in expected_counts.items():
            self.assertIn(rule_name, output)
            time_word = "time" if count == 1 else "times"
            self.assertIn(f"{rule_name} ({count} {time_word})", output)

        self.assertIn("Matches are observations to review, not conclusions about compromise.", output)

    def test_terminal_findings_wording(self):
        """Scan stdout for forbidden words: attack, malicious, compromised, intrusion, infected, severity, critical, high, medium, low."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--config", "examples/case-synthetic/case.json",
                "-o", str(self.out_dir),
                "--overwrite",
                "--show-findings",
            ])
        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()

        pattern = r"\b(attack|malicious|compromised|intrusion|infected|severity|critical|high|medium|low)\b"
        matches = re.findall(pattern, output, flags=re.IGNORECASE)
        self.assertEqual(matches, [], f"Forbidden words found in output: {matches}")

    def test_terminal_findings_timestamps_utc(self):
        """Ensure every printed timestamp in the findings section is followed by UTC."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--config", "examples/case-synthetic/case.json",
                "-o", str(self.out_dir),
                "--overwrite",
                "--show-findings",
            ])
        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()

        self.assertIn("ForensiX - What was found", output)
        findings_block = output.split("ForensiX - What was found", 1)[1]

        # Within the "What was found" block only, find every timestamp matching YYYY-MM-DD HH:MM:SS
        ts_matches = list(re.finditer(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b", findings_block))
        self.assertGreater(len(ts_matches), 0, "No timestamps found in findings block")
        for m in ts_matches:
            line_after = findings_block[m.end():findings_block.find("\n", m.end())]
            self.assertIn("UTC", line_after, f"Timestamp at position {m.start()} not followed by UTC on its line")

    def test_terminal_findings_truncation(self):
        """With more than 25 rules, output displays exactly 25 rules and the truncation notice."""
        # Synthesize a result with 30 distinct rules
        mock_report = MagicMock()
        mock_report.details = {
            "detections": [
                {
                    "rule_name": f"Observation Rule {i:02d}",
                    "matched": True,
                    "start_timestamp": "2026-01-01T10:00:00Z",
                    "end_timestamp": "2026-01-01T10:05:00Z",
                    "explanation": f"Observed rule {i:02d}",
                }
                for i in range(1, 31)
            ]
        }
        mock_manifest = MagicMock()
        mock_manifest.case_id = "TRUNCATION-TEST"
        mock_manifest.run_status = "SUCCESS"

        result = PipelineExecutionResult(
            run_manifest=mock_manifest,
            report=mock_report,
            exit_code=0,
            output_files=(Path("/tmp/report_test.html"), Path("/tmp/report_test.json")),
        )

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            print_pipeline_findings(result)

        output = stdout_buf.getvalue()
        numbered_rule_lines = [
            line for line in output.splitlines()
            if re.match(r"^\s+\d+\.\s+", line)
        ]
        self.assertEqual(len(numbered_rule_lines), 25)
        self.assertIn("1. Observation Rule 01", output)
        self.assertIn("25. Observation Rule 25", output)
        self.assertNotIn("26. Observation Rule 26", output)
        self.assertIn("... and 5 more kinds not shown. See the report for the full list.", output)

    def test_terminal_times_whole_seconds(self):
        """Displayed times are whole seconds truncated, without microseconds."""
        mock_report = MagicMock()
        mock_report.details = {
            "detections": [
                {
                    "rule_name": "SSH Subsecond Test",
                    "matched": True,
                    "start_timestamp": "2025-10-21T07:12:00.100000+00:00",
                    "end_timestamp": "2025-10-21T07:12:00.100000+00:00",
                    "explanation": "Observed SSH subsecond 1.",
                },
                {
                    "rule_name": "SSH Subsecond Test",
                    "matched": True,
                    "start_timestamp": "2025-10-21T07:12:15.400000+00:00",
                    "end_timestamp": "2025-10-21T07:12:15.400000+00:00",
                    "explanation": "Observed SSH subsecond 2.",
                },
            ]
        }
        mock_manifest = MagicMock()
        mock_manifest.case_id = "SUBSECOND-TEST"
        mock_manifest.run_status = "SUCCESS"

        result = PipelineExecutionResult(
            run_manifest=mock_manifest,
            report=mock_report,
            exit_code=0,
            output_files=(Path("/tmp/report_test.html"), Path("/tmp/report_test.json")),
        )

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            print_pipeline_findings(result)

        output = stdout_buf.getvalue()
        self.assertIn("Between 2025-10-21 07:12:00 and 2025-10-21 07:12:15 UTC", output)

        # Assert findings block does not contain "." followed by six digits
        findings_block = output.split("ForensiX - What was found", 1)[1]
        self.assertIsNone(re.search(r"\.\d{6}", findings_block))

    def test_terminal_first_last_sorted_by_time(self):
        """Rule with start timestamps out of order sorts by datetime for First and Last range."""
        mock_report = MagicMock()
        mock_report.details = {
            "detections": [
                {
                    "rule_name": "Out of Order SSH Observation",
                    "matched": True,
                    "start_timestamp": "2026-10-21T07:15:00Z",
                    "end_timestamp": "2026-10-21T07:15:00Z",
                    "explanation": "Observed SSH activity.",
                },
                {
                    "rule_name": "Out of Order SSH Observation",
                    "matched": True,
                    "start_timestamp": "2026-10-21T07:10:00Z",
                    "end_timestamp": "2026-10-21T07:10:00Z",
                    "explanation": "Observed SSH activity.",
                },
                {
                    "rule_name": "Out of Order SSH Observation",
                    "matched": True,
                    "start_timestamp": "2026-10-21T07:12:00Z",
                    "end_timestamp": "2026-10-21T07:12:00Z",
                    "explanation": "Observed SSH activity.",
                },
            ]
        }
        mock_manifest = MagicMock()
        mock_manifest.case_id = "SORT-ORDER-TEST"
        mock_manifest.run_status = "SUCCESS"

        result = PipelineExecutionResult(
            run_manifest=mock_manifest,
            report=mock_report,
            exit_code=0,
            output_files=(Path("/tmp/report_test.html"), Path("/tmp/report_test.json")),
        )

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            print_pipeline_findings(result)

        output = stdout_buf.getvalue()
        self.assertIn("Between 2026-10-21 07:10:00 and 2026-10-21 07:15:00 UTC.", output)

    def test_terminal_findings_no_report(self):
        """When result.report is None, prints the no-findings message and preserves exit code."""
        mock_manifest = MagicMock()
        mock_manifest.case_id = "NO-REPORT-TEST"
        mock_manifest.run_status = "FAILURE"
        result = PipelineExecutionResult(
            run_manifest=mock_manifest,
            report=None,
            exit_code=2,
        )

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            print_pipeline_findings(result)

        output = stdout_buf.getvalue()
        self.assertIn("No report findings were generated for this run.", output)

    def test_show_findings_exit_code_unchanged(self):
        """Prove exit code with and without --show-findings is identical."""
        out1 = self.base_dir / "out_code_1"
        out2 = self.base_dir / "out_code_2"
        code_without = pipeline_main([
            "--config", "examples/case-synthetic/case.json",
            "-o", str(out1),
            "--overwrite",
        ])
        code_with = pipeline_main([
            "--config", "examples/case-synthetic/case.json",
            "-o", str(out2),
            "--overwrite",
            "--show-findings",
        ])
        self.assertEqual(code_without, code_with)
        self.assertEqual(code_with, 0)

        # Also test on validation error
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code_err_without = pipeline_main(["--case-id", "FAIL-CASE"])
            code_err_with = pipeline_main(["--case-id", "FAIL-CASE", "--show-findings"])
        self.assertEqual(code_err_without, code_err_with)
        self.assertEqual(code_err_with, 1)


if __name__ == "__main__":
    unittest.main()
