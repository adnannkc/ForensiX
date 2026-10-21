"""
Unit and integration tests for ForensiX Advanced Forensic Triage CLI (V8.5).

Verifies:
- Standard exit code contract (0, 1, 2, 3, 4).
- Terminal output formatting and diagnostic privacy (no raw stack traces).
- Subcommand routing via main.py ('advanced' and 'report8').
- Argument parsing and flag validations.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from forensix.advanced_cli import (
    EXIT_CONFIG_ERROR,
    EXIT_CUSTODY_FAILURE,
    EXIT_FILESYSTEM_IO_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_DISCREPANCY,
    advanced_main,
    build_advanced_parser,
    execute_advanced_cli,
)
from forensix.custody_ledger import CustodyLedger
from forensix.custody_models import CustodyActionType, CustodyActor
from forensix.main import main
from forensix.manifest_models import generate_manifest_id


class TestAdvancedCLI(unittest.TestCase):
    """Test suite for ForensiX Advanced Forensic Triage CLI."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)

        # Evidence target
        self.ev_dir = self.test_root / "sample_evidence"
        self.ev_dir.mkdir(parents=True, exist_ok=True)

        self.test_file = self.ev_dir / "audit.log"
        self.content = b"Oct 20 12:00:00 auth SUCCESS user=analyst\n"
        self.test_file.write_bytes(self.content)
        self.sha256 = hashlib.sha256(self.content).hexdigest()

        # Output dir
        self.out_dir = self.test_root / "cli_reports"
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_manifest(self, sha256_hash: str, case_id: str = "CASE-CLI-01") -> Path:
        """Helper to create a manifest JSON file."""
        man_path = self.test_root / "cli_manifest.json"
        data = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "case_id": case_id,
            "investigator": "Test Analyst",
            "entries": [
                {
                    "relative_path": "audit.log",
                    "size_bytes": len(self.content),
                    "hashes": {"sha256": sha256_hash},
                }
            ],
        }
        man_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return man_path

    # =========================================================================
    # 1. Exit Code 0: Successful Operation
    # =========================================================================

    def test_cli_success_exit_code_0(self):
        """Verify successful triage invocation returns exit code 0 and prints summary."""
        man_path = self._create_manifest(self.sha256)
        argv = [
            str(self.ev_dir),
            "-m", str(man_path),
            "-o", str(self.out_dir),
            "--case-id", "CASE-CLI-01",
            "--case-name", "Project Aegis",
            "--investigator", "Agent Smith",
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsNotNone(result)
        self.assertTrue(result.execution_success)

        output = stdout_capture.getvalue()
        self.assertIn("ForensiX Advanced Forensic Triage Summary", output)
        self.assertIn("CASE-CLI-01", output)
        self.assertIn("VERIFIED (1/1 matched", output)
        self.assertIn("Custody Chain      : VERIFIED", output)

    # =========================================================================
    # 2. Exit Code 2: Verification Discrepancy
    # =========================================================================

    def test_cli_verification_discrepancy_exit_code_2(self):
        """Verify that manifest mismatch returns exit code 2 and notice."""
        alt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
        man_path = self._create_manifest(alt_sha256)
        argv = [
            str(self.ev_dir),
            "-m", str(man_path),
            "-o", str(self.out_dir),
            "--case-id", "CASE-CLI-01",
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_VERIFICATION_DISCREPANCY)
        self.assertIsNotNone(result)
        self.assertFalse(result.execution_success)

        err_output = stderr_capture.getvalue()
        self.assertIn("Manifest integrity verification detected discrepancies", err_output)

    # =========================================================================
    # 3. Exit Code 3: Custody Integrity Failure
    # =========================================================================

    def test_cli_custody_failure_exit_code_3(self):
        """Verify that attempting to resume a tampered ledger returns exit code 3."""
        ledger = CustodyLedger(case_id="CASE-CLI-01")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="sample_evidence",
            actor=CustodyActor(declared_identity="Analyst"),
        )
        ledger_path = self.test_root / "tampered_cli_ledger.json"
        ledger.save_to_file(ledger_path)

        # Alter event action on disk without re-hashing
        raw = json.loads(ledger_path.read_text(encoding="utf-8"))
        raw["events"][0]["action_type"] = "CUSTODY_TRANSFERRED"
        ledger_path.write_text(json.dumps(raw), encoding="utf-8")

        argv = [
            str(self.ev_dir),
            "-l", str(ledger_path),
            "-o", str(self.out_dir),
            "--case-id", "CASE-CLI-01",
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_CUSTODY_FAILURE)
        self.assertIsNone(result)
        self.assertIn("Custody Integrity Failure", stderr_capture.getvalue())

    # =========================================================================
    # 4. Exit Code 1: Configuration / Case ID Conflict Error
    # =========================================================================

    def test_cli_config_error_exit_code_1(self):
        """Verify conflicting case IDs return exit code 1."""
        man_path = self._create_manifest(self.sha256, case_id="CASE-DIFFERENT")
        argv = [
            str(self.ev_dir),
            "-m", str(man_path),
            "-o", str(self.out_dir),
            "--case-id", "CASE-CLI-01",
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)
        self.assertIn("Configuration Error: Conflicting case_id", stderr_capture.getvalue())

    # =========================================================================
    # 5. Exit Code 4: Filesystem Error
    # =========================================================================

    def test_cli_filesystem_error_exit_code_4(self):
        """Verify nonexistent evidence directory returns exit code 4."""
        nonexistent = self.test_root / "does_not_exist"
        argv = [
            str(nonexistent),
            "-o", str(self.out_dir),
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIsNone(result)
        self.assertIn("Filesystem Error: Evidence directory does not exist", stderr_capture.getvalue())

    def test_cli_output_overlap_security_rejection_exit_code_1(self):
        """Verify setting output inside evidence root triggers exit code 1 (Configuration Error)."""
        inside_out = self.ev_dir / "forbidden_out"
        argv = [
            str(self.ev_dir),
            "-o", str(inside_out),
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_advanced_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIn("Forensic safety violation", stderr_capture.getvalue())

    # =========================================================================
    # 6. Subcommand Dispatch via main.py
    # =========================================================================

    def test_main_dispatch_advanced(self):
        """Verify python3 -m forensix advanced routes correctly."""
        argv = ["advanced", str(self.ev_dir), "-o", str(self.out_dir)]
        exit_code = main(argv)
        self.assertEqual(exit_code, EXIT_SUCCESS)

    def test_main_dispatch_report8(self):
        """Verify python3 -m forensix report8 alias routes correctly."""
        argv = ["report8", str(self.ev_dir), "-o", str(self.out_dir), "--format", "json"]
        exit_code = main(argv)
        self.assertEqual(exit_code, EXIT_SUCCESS)


if __name__ == "__main__":
    unittest.main()
