"""
Focused tests for ForensiX Manifest CLI (V8.6).

Tests cover:
- CLI subcommand 'create': success (exit 0), options (-o, --case-id, --investigator, --algorithms, --overwrite).
- CLI subcommand 'create' error conditions: nonexistent dir (exit 4), output overlap (exit 1), no-clobber (exit 4).
- CLI subcommand 'verify': 100% matched baseline (exit 0).
- CLI subcommand 'verify' discrepancies: hash mismatch (exit 2), missing evidence file (exit 2).
- CLI subcommand 'verify' error conditions: missing manifest file (exit 4), nonexistent evidence dir (exit 4), malformed manifest JSON (exit 1).
- CLI syntax errors: missing subcommand (exit 1), missing required -m flag (exit 1), unknown arguments (exit 1).
- main.py subcommand dispatch routing for 'manifest'.
"""

import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from forensix.main import main
from forensix.manifest_cli import (
    EXIT_CONFIG_ERROR,
    EXIT_FILESYSTEM_IO_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_DISCREPANCY,
    build_manifest_parser,
    execute_manifest_cli,
    manifest_main,
)
from forensix.manifest_generator import generate_manifest
from forensix.manifest_models import ManifestRecord
from forensix.manifest_verifier import ManifestVerificationResult


class TestManifestCLI(unittest.TestCase):
    """Test CLI parser, execution, error containment, and exact exit-code contract."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_man_cli_")
        self.test_root = Path(self.temp_dir).resolve()
        self.ev_dir = self.test_root / "evidence"
        self.ev_dir.mkdir(parents=True)
        self.out_dir = self.test_root / "output"
        self.out_dir.mkdir(parents=True)

        # Populate sample evidence
        self.file1 = self.ev_dir / "sample1.txt"
        self.file1.write_bytes(b"Sample evidence 1")
        self.file2 = self.ev_dir / "sample2.txt"
        self.file2.write_bytes(b"Sample evidence 2")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_cli(self, argv):
        """Helper to run execute_manifest_cli capturing stdout and stderr."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_manifest_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr
        return exit_code, result, stdout_capture.getvalue(), stderr_capture.getvalue()

    # -------------------------------------------------------------------------
    # 1. Manifest Create Subcommand
    # -------------------------------------------------------------------------

    def test_manifest_create_success(self):
        """Verify 'manifest create' writes manifest JSON and returns exit code 0."""
        out_path = self.out_dir / "manifest.json"
        argv = [
            "create",
            str(self.ev_dir),
            "-o", str(out_path),
            "--case-id", "CASE-2026-CLI",
            "--investigator", "Agent Smith",
            "--algorithms", "both",
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, ManifestRecord)
        self.assertTrue(out_path.exists())
        self.assertIn("ForensiX Forensic Manifest Generation Summary", stdout)
        self.assertIn("CASE-2026-CLI", stdout)
        self.assertIn("Agent Smith", stdout)
        self.assertEqual(stderr, "")

    def test_manifest_create_without_output_flag(self):
        """Verify 'manifest create' without -o returns exit code 0 and displays summary."""
        argv = [
            "create",
            str(self.ev_dir),
            "--algorithms", "sha256",
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, ManifestRecord)
        self.assertIn("ForensiX Forensic Manifest Generation Summary", stdout)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(stderr, "")

    def test_manifest_create_nonexistent_evidence_dir_exit_4(self):
        """Verify 'manifest create' on nonexistent evidence directory returns exit code 4."""
        nonexistent = self.test_root / "nonexistent"
        argv = ["create", str(nonexistent)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIsNone(result)
        self.assertIn("Filesystem Error:", stderr)
        self.assertIn("does not exist", stderr)

    def test_manifest_create_output_overlap_exit_1(self):
        """Verify 'manifest create' with output inside evidence directory returns exit code 1."""
        bad_out = self.ev_dir / "overlap_manifest.json"
        argv = ["create", str(self.ev_dir), "-o", str(bad_out)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)
        self.assertIn("Configuration Error:", stderr)
        self.assertIn("overlaps or resides inside evidence directory", stderr)

    def test_manifest_create_no_clobber_exit_4(self):
        """Verify 'manifest create' without --overwrite on existing target returns exit code 4."""
        existing_out = self.out_dir / "existing.json"
        existing_out.write_text("{}", encoding="utf-8")

        argv = ["create", str(self.ev_dir), "-o", str(existing_out)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIsNone(result)
        self.assertIn("Filesystem Error:", stderr)
        self.assertIn("already exists and overwrite is False", stderr)

    def test_manifest_create_overwrite_success(self):
        """Verify 'manifest create' with --overwrite replaces existing file with exit code 0."""
        existing_out = self.out_dir / "existing.json"
        existing_out.write_text("old", encoding="utf-8")

        argv = ["create", str(self.ev_dir), "-o", str(existing_out), "--overwrite"]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, ManifestRecord)
        with existing_out.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["manifest_version"], "8.0")

    # -------------------------------------------------------------------------
    # 2. Manifest Verify Subcommand
    # -------------------------------------------------------------------------

    def test_manifest_verify_matching_exit_0(self):
        """Verify 'manifest verify' returns exit code 0 when evidence matches 100%."""
        manifest_path = self.out_dir / "valid_manifest.json"
        generate_manifest(self.ev_dir, output_path=manifest_path)

        argv = [
            "verify",
            str(self.ev_dir),
            "-m", str(manifest_path),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, ManifestVerificationResult)
        self.assertTrue(result.overall_status)
        self.assertIn("VERIFIED (Zero Discrepancies)", stdout)
        self.assertEqual(result.verified_count, 2)
        self.assertEqual(result.mismatch_count, 0)
        self.assertEqual(stderr, "")

    def test_manifest_verify_hash_mismatch_exit_2(self):
        """Verify 'manifest verify' returns exit code 2 when an evidence file is modified."""
        manifest_path = self.out_dir / "valid_manifest.json"
        generate_manifest(self.ev_dir, output_path=manifest_path)

        # Alter file1 to trigger hash mismatch
        self.file1.write_bytes(b"Modified content causing hash mismatch")

        argv = [
            "verify",
            str(self.ev_dir),
            "-m", str(manifest_path),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_VERIFICATION_DISCREPANCY)
        self.assertIsInstance(result, ManifestVerificationResult)
        self.assertFalse(result.overall_status)
        self.assertEqual(result.verified_count, 1)
        self.assertEqual(result.mismatch_count, 1)
        self.assertIn("DISCREPANCY DETECTED", stdout)
        self.assertIn("Notice: Manifest verification detected discrepancies", stderr)

    def test_manifest_verify_missing_file_exit_2(self):
        """Verify 'manifest verify' returns exit code 2 when an evidence file is missing."""
        manifest_path = self.out_dir / "valid_manifest.json"
        generate_manifest(self.ev_dir, output_path=manifest_path)

        # Delete file2 to trigger missing file condition
        self.file2.unlink()

        argv = [
            "verify",
            str(self.ev_dir),
            "-m", str(manifest_path),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_VERIFICATION_DISCREPANCY)
        self.assertIsInstance(result, ManifestVerificationResult)
        self.assertFalse(result.overall_status)
        self.assertEqual(result.verified_count, 1)
        self.assertEqual(result.missing_count, 1)
        self.assertIn("DISCREPANCY DETECTED", stdout)
        self.assertIn("Notice: Manifest verification detected discrepancies", stderr)

    def test_manifest_verify_missing_manifest_file_exit_4(self):
        """Verify 'manifest verify' with nonexistent manifest file returns exit code 4."""
        nonexistent_man = self.test_root / "does_not_exist.json"
        argv = [
            "verify",
            str(self.ev_dir),
            "-m", str(nonexistent_man),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIsNone(result)
        self.assertIn("Filesystem Error:", stderr)
        self.assertIn("Manifest file does not exist", stderr)

    def test_manifest_verify_malformed_manifest_exit_1(self):
        """Verify 'manifest verify' with malformed JSON manifest returns exit code 1."""
        corrupt_man = self.out_dir / "corrupt.json"
        corrupt_man.write_text("{invalid json", encoding="utf-8")

        argv = [
            "verify",
            str(self.ev_dir),
            "-m", str(corrupt_man),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)
        self.assertIn("Configuration Error:", stderr)
        self.assertIn("Failed to parse manifest JSON", stderr)

    # -------------------------------------------------------------------------
    # 3. Argument Parsing & Syntax Validation
    # -------------------------------------------------------------------------

    def test_cli_missing_subcommand_exit_1(self):
        """Verify running CLI with no subcommand returns exit code 1."""
        exit_code, result, stdout, stderr = self._run_cli([])
        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)

    def test_cli_missing_required_manifest_arg_exit_1(self):
        """Verify 'manifest verify' without -m returns exit code 1."""
        exit_code, result, stdout, stderr = self._run_cli(["verify", str(self.ev_dir)])
        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)

    def test_cli_invalid_argument_exit_1(self):
        """Verify passing unrecognized flag returns exit code 1."""
        exit_code, result, stdout, stderr = self._run_cli(["create", str(self.ev_dir), "--unknown-option"])
        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIsNone(result)

    def test_manifest_main_entrypoint(self):
        """Verify manifest_main helper returns integer exit code."""
        code = manifest_main(["--help"])
        self.assertEqual(code, 0)

    # -------------------------------------------------------------------------
    # 4. main.py Subcommand Dispatch
    # -------------------------------------------------------------------------

    def test_main_py_dispatch_manifest_create(self):
        """Verify python3 -m forensix manifest create dispatches properly through main.py."""
        out_path = self.out_dir / "main_dispatched_manifest.json"
        argv = [
            "manifest",
            "create",
            str(self.ev_dir),
            "-o", str(out_path),
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(code, 0)
        self.assertTrue(out_path.exists())
        self.assertIn("ForensiX Forensic Manifest Generation Summary", stdout_capture.getvalue())

    def test_main_py_dispatch_manifest_verify(self):
        """Verify python3 -m forensix manifest verify dispatches properly through main.py."""
        man_path = self.out_dir / "verify_dispatch.json"
        generate_manifest(self.ev_dir, output_path=man_path)

        argv = [
            "manifest",
            "verify",
            str(self.ev_dir),
            "-m", str(man_path),
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr

        self.assertEqual(code, 0)
        self.assertIn("VERIFIED (Zero Discrepancies)", stdout_capture.getvalue())


if __name__ == "__main__":
    unittest.main()
