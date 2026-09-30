"""
Unit and integration tests for ForensiX Command-Line Interface (main.py).
"""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from forensix.hasher import compute_hashes
from forensix.main import main


class TestCLI(unittest.TestCase):
    """Test suite for CLI execution and argument parsing in src/forensix/main.py."""

    def setUp(self):
        """Create a temporary workspace for test evidence and reports."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

        self.evidence_file = self.test_dir_path / "triage_sample.log"
        self.sample_content = b"2026-09-29T21:40:00Z [SECURITY] Privilege escalation detected\n"
        self.evidence_file.write_bytes(self.sample_content)

        self.reports_dir = self.test_dir_path / "cli_reports"

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_help_flag_via_subprocess(self):
        """Verify python3 -m forensix --help outputs usage description and exits with 0."""
        env = dict(os.environ, PYTHONPATH="src")
        proc = subprocess.run(
            [sys.executable, "-m", "forensix", "--help"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ForensiX - Automated Digital Forensics", proc.stdout)
        self.assertIn("evidence_file", proc.stdout)
        self.assertIn("--output-dir", proc.stdout)

    def test_successful_cli_execution_via_main_function(self):
        """Verify successful end-to-end execution through main()."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        orig_stdout, orig_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            ret = main([str(self.evidence_file), "-o", str(self.reports_dir)])
        finally:
            sys.stdout, sys.stderr = orig_stdout, orig_stderr

        self.assertEqual(ret, 0)
        output = stdout_capture.getvalue()

        # Check required terminal summary elements
        self.assertIn("ForensiX Analysis Complete", output)
        self.assertIn("Evidence ID : EV-", output)
        self.assertIn("File        : triage_sample.log", output)
        self.assertIn(f"Size        : {len(self.sample_content)} bytes", output)
        self.assertIn("MD5         :", output)
        self.assertIn("SHA-256     :", output)
        self.assertIn("Report      :", output)

        # Verify JSON report was created on disk
        reports = list(self.reports_dir.glob("*.json"))
        self.assertEqual(len(reports), 1)
        report_data = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(report_data["file"]["filename"], "triage_sample.log")

    def test_successful_cli_execution_via_module_subprocess(self):
        """Verify python3 -m forensix <file> runs via subprocess end-to-end."""
        env = dict(os.environ, PYTHONPATH="src")
        proc = subprocess.run(
            [sys.executable, "-m", "forensix", str(self.evidence_file), "-o", str(self.reports_dir)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ForensiX Analysis Complete", proc.stdout)
        self.assertIn("SHA-256", proc.stdout)
        self.assertIn("EV-", proc.stdout)

    def test_missing_evidence_file_returns_nonzero_exit_status(self):
        """Verify non-existent file produces concise error and non-zero exit status."""
        missing = self.test_dir_path / "does_not_exist.raw"
        stderr_capture = io.StringIO()

        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret = main([str(missing)])
        finally:
            sys.stderr = orig_stderr

        self.assertNotEqual(ret, 0)
        err_output = stderr_capture.getvalue()
        self.assertIn("Error: Evidence file does not exist", err_output)
        self.assertNotIn("Traceback", err_output)

    def test_directory_supplied_returns_nonzero_exit_status(self):
        """Verify directory target produces concise error and non-zero exit status."""
        sub_dir = self.test_dir_path / "sub_folder"
        sub_dir.mkdir()
        stderr_capture = io.StringIO()

        orig_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            ret = main([str(sub_dir)])
        finally:
            sys.stderr = orig_stderr

        self.assertNotEqual(ret, 0)
        err_output = stderr_capture.getvalue()
        self.assertIn("Error: Expected a regular evidence file, but target is a directory", err_output)
        self.assertNotIn("Traceback", err_output)

    def test_original_evidence_remains_unchanged_after_cli_run(self):
        """Verify CLI execution leaves evidence bytes and metadata completely untouched."""
        pre_hashes = compute_hashes(self.evidence_file)
        pre_stat = self.evidence_file.stat()

        stdout_capture = io.StringIO()
        orig_stdout = sys.stdout
        try:
            sys.stdout = stdout_capture
            _ = main([str(self.evidence_file), "-o", str(self.reports_dir)])
        finally:
            sys.stdout = orig_stdout

        post_hashes = compute_hashes(self.evidence_file)
        post_stat = self.evidence_file.stat()

        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(pre_hashes["md5"], post_hashes["md5"])
        self.assertEqual(pre_stat.st_size, post_stat.st_size)
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime)


if __name__ == "__main__":
    unittest.main()
