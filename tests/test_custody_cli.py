"""
Comprehensive Integration Tests for ForensiX Custody CLI (V8.7).

Covers all approved V8.7 requirements:
- CLI command dispatch via main.py ('custody').
- Subcommand 'init': success (exit 0), no-clobber (exit 4), overwrite (exit 0).
- Subcommand 'transfer': valid transfer commit (exit 0), text & JSON receipts,
  post-commit receipt write failure handling (exit 4 with dual reporting).
- Subcommand 'audit': verified status (exit 0), discrepancy & incomplete history (exit 2),
  tampered chain (exit 3), filesystem IO errors (exit 4), JSON format output.
- CLI argument errors, missing flags, and invalid syntax (exit 1).
"""

import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from forensix.custody_cli import (
    EXIT_AUDIT_DISCREPANCY,
    EXIT_CONFIG_ERROR,
    EXIT_CUSTODY_FAILURE,
    EXIT_FILESYSTEM_IO_ERROR,
    EXIT_SUCCESS,
    build_custody_parser,
    custody_main,
    execute_custody_cli,
)
from forensix.custody_ledger import CustodyLedger
from forensix.custody_models import CustodyActionType, CustodyActor, CustodyEvent
from forensix.custody_transfer import CustodyAuditResult, CustodyTransferRecord, record_transfer
from forensix.main import main


class TestCustodyCLI(unittest.TestCase):
    """Test suite for ForensiX Custody Command-Line Interface."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_custody_cli_")
        self.test_root = Path(self.temp_dir).resolve()
        self.ledger_file = self.test_root / "case_ledger.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_cli(self, argv):
        """Helper to run execute_custody_cli capturing stdout and stderr."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code, result = execute_custody_cli(argv)
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr
        return exit_code, result, stdout_capture.getvalue(), stderr_capture.getvalue()

    # -------------------------------------------------------------------------
    # 1. custody init Subcommand
    # -------------------------------------------------------------------------

    def test_cli_init_success(self):
        """Verify 'custody init' creates an empty, valid Schema 8.0 ledger JSON file."""
        argv = [
            "init",
            "-o", str(self.ledger_file),
            "--case-id", "CASE-2026-CLI",
            "--description", "Incident Triage Intake",
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, CustodyLedger)
        self.assertTrue(self.ledger_file.exists())
        self.assertIn("SUCCESS: Initialized empty ForensiX Schema 8.0 custody ledger", stdout)
        self.assertIn("CASE-2026-CLI", stdout)
        self.assertEqual(stderr, "")

        # Verify on-disk file content
        with self.ledger_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "8.0")
        self.assertEqual(data["total_events"], 0)
        self.assertIn("ledger_digest", data)

    def test_cli_init_no_clobber_exit_4(self):
        """Verify 'custody init' on existing target without --overwrite exits with code 4."""
        self.ledger_file.write_text("{}", encoding="utf-8")
        argv = ["init", "-o", str(self.ledger_file)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIsNone(result)
        self.assertIn("Filesystem Error:", stderr)
        self.assertIn("already exists", stderr)

    def test_cli_init_overwrite_success(self):
        """Verify 'custody init' with --overwrite replaces existing file."""
        self.ledger_file.write_text("old", encoding="utf-8")
        argv = ["init", "-o", str(self.ledger_file), "--overwrite"]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertTrue(self.ledger_file.exists())

    def test_cli_init_missing_output_arg_exit_1(self):
        """Verify 'custody init' without required -o flag exits with code 1."""
        argv = ["init"]
        exit_code, result, stdout, stderr = self._run_cli(argv)
        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIn("the following arguments are required", stderr)

    # -------------------------------------------------------------------------
    # 2. custody transfer Subcommand
    # -------------------------------------------------------------------------

    def test_cli_transfer_success_and_receipt(self):
        """Verify 'custody transfer' commits transfer to ledger and writes receipt."""
        # Setup initial ledger with intake event
        actor = CustodyActor(declared_identity="Officer Alice")
        ledger = CustodyLedger(case_id="CASE-CLI-TRANSFER")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-HDD-01",
            actor=actor,
            source_location="Locker A",
            timestamp="2026-10-21T08:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        receipt_txt = self.test_root / "receipt.txt"
        receipt_json = self.test_root / "receipt.json"

        argv = [
            "transfer",
            "-l", str(self.ledger_file),
            "--evidence-id", "EV-HDD-01",
            "--from-name", "Officer Alice",
            "--from-role", "Evidence Custodian",
            "--to-name", "Examiner Bob",
            "--to-role", "Forensic Analyst",
            "--from-loc", "Locker A",
            "--to-loc", "Forensic Lab Room 2",
            "--reason", "Physical disk extraction",
            "--auth", "Warrant-2026-88",
            "--sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "--receipt-out", str(receipt_txt),
            "--receipt-json", str(receipt_json),
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIn("SUCCESS: Committed formal custody transfer", stdout)
        self.assertIn("Officer Alice", stdout)
        self.assertIn("Examiner Bob", stdout)
        self.assertEqual(stderr, "")

        # Verify receipt files were generated
        self.assertTrue(receipt_txt.exists())
        self.assertTrue(receipt_json.exists())
        self.assertIn("FORENSIX FORMAL CUSTODY TRANSFER RECEIPT", receipt_txt.read_text(encoding="utf-8"))

        # Verify updated ledger on disk has 2 events
        updated_ledger = CustodyLedger.load_from_file(self.ledger_file)
        self.assertEqual(len(updated_ledger), 2)
        self.assertEqual(updated_ledger.events[1].action_type, CustodyActionType.CUSTODY_TRANSFERRED)

    def test_cli_transfer_missing_required_args_exit_1(self):
        """Verify 'custody transfer' missing required flags exits with code 1."""
        argv = [
            "transfer",
            "-l", str(self.ledger_file),
            "--evidence-id", "EV-1",
            # missing --from-name, --to-name, etc.
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)
        self.assertEqual(exit_code, EXIT_CONFIG_ERROR)
        self.assertIn("the following arguments are required", stderr)

    def test_cli_transfer_nonexistent_ledger_exit_4(self):
        """Verify 'custody transfer' on nonexistent ledger file exits with code 4."""
        nonexistent = self.test_root / "nonexistent.json"
        argv = [
            "transfer",
            "-l", str(nonexistent),
            "--evidence-id", "EV-1",
            "--from-name", "A", "--to-name", "B",
            "--from-loc", "L1", "--to-loc", "L2",
            "--reason", "Test",
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)
        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        self.assertIn("Filesystem Error:", stderr)

    def test_cli_transfer_post_commit_receipt_failure_exit_4(self):
        """Verify dual-status reporting and exit 4 when receipt write fails after ledger commit."""
        actor = CustodyActor(declared_identity="Officer Alice")
        ledger = CustodyLedger(case_id="CASE-FAIL-RECEIPT")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T08:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        # Unwritable receipt path: pass an existing directory as receipt_out
        unwritable_receipt = self.test_root / "unwritable_dir"
        unwritable_receipt.mkdir()

        argv = [
            "transfer",
            "-l", str(self.ledger_file),
            "--evidence-id", "EV-1",
            "--from-name", "Officer Alice",
            "--to-name", "Examiner Bob",
            "--from-loc", "L1",
            "--to-loc", "L2",
            "--reason", "Test post-commit fail",
            "--receipt-out", str(unwritable_receipt),  # Directory will cause IsADirectoryError / PermissionError
        ]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_FILESYSTEM_IO_ERROR)
        # Confirms dual-status messaging: ledger was committed, receipt write failed
        self.assertIn("SUCCESS: Transfer", stdout)
        self.assertIn("committed to ledger", stdout)
        self.assertIn("ERROR: Failed to write text receipt", stderr)
        self.assertIn("NOTE: The transfer record is committed and safely preserved in the ledger file.", stderr)

        # Confirm ledger on disk was indeed committed (now has 2 events!)
        reloaded = CustodyLedger.load_from_file(self.ledger_file)
        self.assertEqual(len(reloaded), 2)

    # -------------------------------------------------------------------------
    # 3. custody audit Subcommand
    # -------------------------------------------------------------------------

    def test_cli_audit_verified_exit_0(self):
        """Verify 'custody audit' on clean verified ledger returns exit code 0."""
        actor_a = CustodyActor(declared_identity="Officer Alice")
        actor_b = CustodyActor(declared_identity="Examiner Bob")
        ledger = CustodyLedger(case_id="CASE-AUDIT-01")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-AUDIT",
            actor=actor_a,
            source_location="Locker",
            timestamp="2026-10-21T08:00:00Z",
        )
        record_transfer(
            ledger=ledger,
            evidence_id="EV-AUDIT",
            releasing_actor=actor_a,
            receiving_actor=actor_b,
            source_location="Locker",
            destination_location="Lab",
            reason="Analysis",
            timestamp="2026-10-21T09:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        argv = ["audit", "-l", str(self.ledger_file)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIsInstance(result, CustodyAuditResult)
        self.assertEqual(result.audit_status, "VERIFIED")
        self.assertIn("Audit Outcome:           VERIFIED", stdout)
        self.assertIn("Overall Valid:           YES", stdout)

    def test_cli_audit_discrepancy_exit_2(self):
        """Verify 'custody audit' on ledger with possession break returns exit code 2."""
        actor_a = CustodyActor(declared_identity="Officer Alice")
        actor_c = CustodyActor(declared_identity="Unauthorized Charlie")
        actor_b = CustodyActor(declared_identity="Examiner Bob")
        ledger = CustodyLedger(case_id="CASE-AUDIT-DISC")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-DISC",
            actor=actor_a,
            timestamp="2026-10-21T08:00:00Z",
        )
        # Possession break: Charlie releases when Alice holds it
        record_transfer(
            ledger=ledger,
            evidence_id="EV-DISC",
            releasing_actor=actor_c,
            receiving_actor=actor_b,
            source_location="L1",
            destination_location="L2",
            reason="Move",
            timestamp="2026-10-21T09:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        argv = ["audit", "-l", str(self.ledger_file)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_AUDIT_DISCREPANCY)
        self.assertIsInstance(result, CustodyAuditResult)
        self.assertEqual(result.audit_status, "DISCREPANCY_DETECTED")
        self.assertIn("Audit Outcome:           DISCREPANCY_DETECTED", stdout)
        self.assertIn("POSSESSION_CONTINUITY_BREAK", stdout)

    def test_cli_audit_incomplete_history_exit_2(self):
        """Verify 'custody audit' on ledger with missing intake returns exit code 2."""
        actor_a = CustodyActor(declared_identity="Officer Alice")
        actor_b = CustodyActor(declared_identity="Examiner Bob")
        ledger = CustodyLedger(case_id="CASE-AUDIT-INC")
        record_transfer(
            ledger=ledger,
            evidence_id="EV-INC",
            releasing_actor=actor_a,
            receiving_actor=actor_b,
            source_location="L1",
            destination_location="L2",
            reason="Transfer with missing intake",
            timestamp="2026-10-21T09:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        argv = ["audit", "-l", str(self.ledger_file)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_AUDIT_DISCREPANCY)
        self.assertIsInstance(result, CustodyAuditResult)
        self.assertEqual(result.audit_status, "INCOMPLETE_HISTORY")
        self.assertIn("Audit Outcome:           INCOMPLETE_HISTORY", stdout)

    def test_cli_audit_tampered_exit_3(self):
        """Verify 'custody audit' on cryptographically tampered ledger returns exit code 3."""
        actor = CustodyActor(declared_identity="Officer Alice")
        ledger = CustodyLedger(case_id="CASE-TAMPER")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T08:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        # Directly tamper with the saved JSON file on disk
        with self.ledger_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        data["events"][0]["notes"] = "MALICIOUSLY TAMPERED CONTENT"
        with self.ledger_file.open("w", encoding="utf-8") as f:
            json.dump(data, f)

        argv = ["audit", "-l", str(self.ledger_file)]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_CUSTODY_FAILURE)
        self.assertIsInstance(result, CustodyAuditResult)
        self.assertEqual(result.audit_status, "TAMPERED")

    def test_cli_audit_json_flag_output(self):
        """Verify 'custody audit --json' emits parseable JSON to stdout."""
        actor = CustodyActor(declared_identity="Officer Alice")
        ledger = CustodyLedger(case_id="CASE-JSON")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T08:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        argv = ["audit", "-l", str(self.ledger_file), "--json"]
        exit_code, result, stdout, stderr = self._run_cli(argv)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        parsed = json.loads(stdout)
        self.assertEqual(parsed["audit_status"], "VERIFIED")
        self.assertTrue(parsed["is_valid"])

    # -------------------------------------------------------------------------
    # 4. main.py Subcommand Dispatch Routing
    # -------------------------------------------------------------------------

    def test_main_dispatch_custody_subcommand(self):
        """Verify python3 -m forensix custody routes correctly through main()."""
        raw_argv = ["custody", "init", "-o", str(self.ledger_file)]
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            exit_code = main(raw_argv)
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertTrue(self.ledger_file.exists())
        self.assertIn("SUCCESS: Initialized empty", stdout_capture.getvalue())


if __name__ == "__main__":
    unittest.main()
