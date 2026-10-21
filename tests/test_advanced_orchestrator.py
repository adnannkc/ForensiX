"""
Unit and integration tests for ForensiX Advanced Forensic Triage Orchestrator (V8.5).

Verifies:
- End-to-end orchestration with matching manifests.
- Manifest discrepancy handling (mismatches and missing files) with status fidelity.
- Workflow without manifest (clean omission recording).
- Safe custody ledger resumption (chain validation, history preservation, case-ID reconciliation).
- Rejection of invalid or tampered ledgers without modification.
- Custody event ordering and explicit pre-publication terminal hash boundary.
- Evidence directory separation and overlap security rejection.
- Strict evidence immutability (zero file modifications).
- No-clobber and overwrite semantics.
- Partial-write failure cleanup.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from forensix.advanced_orchestrator import (
    AdvancedTriageConfig,
    AdvancedTriageOrchestrator,
    AdvancedTriageResult,
    CustodyIntegrityError,
    run_advanced_triage,
)
from forensix.advanced_report_models import (
    ADVANCED_REPORT_SCHEMA_VERSION,
    AdvancedReport,
    FindingsSummary,
)
from forensix.custody_ledger import (
    CustodyLedger,
    compute_ledger_digest,
)
from forensix.custody_models import (
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    GENESIS_PREV_HASH,
)
from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    generate_manifest_id,
)


class TestAdvancedOrchestrator(unittest.TestCase):
    """Test suite for ForensiX Advanced Forensic Triage Orchestrator."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)

        # Setup evidence directory
        self.ev_dir = self.test_root / "evidence_data"
        self.ev_dir.mkdir(parents=True, exist_ok=True)

        self.file1_rel = "var/log/syslog"
        self.file1_path = self.ev_dir / self.file1_rel
        self.file1_path.parent.mkdir(parents=True, exist_ok=True)
        self.file1_content = b"Oct 20 12:00:00 host kernel: [    0.000000] Linux version 6.8.0\n"
        self.file1_path.write_bytes(self.file1_content)
        self.file1_sha256 = hashlib.sha256(self.file1_content).hexdigest()
        self.file1_md5 = hashlib.md5(self.file1_content).hexdigest()

        self.file2_rel = "etc/passwd"
        self.file2_path = self.ev_dir / self.file2_rel
        self.file2_path.parent.mkdir(parents=True, exist_ok=True)
        self.file2_content = b"root:x:0:0:root:/root:/bin/bash\n"
        self.file2_path.write_bytes(self.file2_content)
        self.file2_sha256 = hashlib.sha256(self.file2_content).hexdigest()
        self.file2_md5 = hashlib.md5(self.file2_content).hexdigest()

        # Output directory
        self.out_dir = self.test_root / "reports"
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.case_meta = {
            "case_id": "CASE-2026-V85",
            "case_name": "ForensiX V8.5 Pipeline Verification",
            "investigator": "Lead Investigator",
        }
        self.actor = CustodyActor(
            declared_identity="Forensic Examiner A",
            role="Lead Analyst",
            organization="Forensic Lab",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_manifest_file(
        self,
        entries: list,
        case_id: str = "CASE-2026-V85",
        filename: str = "manifest.json",
    ) -> Path:
        """Helper to create a serialized manifest JSON file."""
        man_path = self.test_root / filename
        data = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "case_id": case_id,
            "investigator": "Lead Investigator",
            "entries": entries,
        }
        man_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return man_path

    # =========================================================================
    # 1. Matching Manifest Workflow
    # =========================================================================

    def test_matching_manifest_workflow(self):
        """Verify successful end-to-end triage with a matching manifest."""
        entries = [
            {
                "relative_path": self.file1_rel,
                "size_bytes": len(self.file1_content),
                "hashes": {"sha256": self.file1_sha256, "md5": self.file1_md5},
                "artifact_type": "evidence",
            },
            {
                "relative_path": self.file2_rel,
                "size_bytes": len(self.file2_content),
                "hashes": {"sha256": self.file2_sha256, "md5": self.file2_md5},
                "artifact_type": "evidence",
            },
        ]
        man_path = self._create_manifest_file(entries)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
            actor=self.actor,
            formats=("json", "html"),
        )

        result = run_advanced_triage(config)

        # Check result object
        self.assertTrue(result.execution_success)
        self.assertIsNotNone(result.manifest_verification)
        self.assertTrue(result.manifest_verification.overall_status)
        self.assertEqual(result.manifest_verification.verified_count, 2)
        self.assertEqual(result.manifest_verification.mismatch_count, 0)
        self.assertEqual(result.manifest_verification.missing_count, 0)

        # Check report
        self.assertIsInstance(result.report, AdvancedReport)
        self.assertEqual(result.report.report_schema, ADVANCED_REPORT_SCHEMA_VERSION)
        self.assertEqual(result.report.case_metadata["case_id"], "CASE-2026-V85")
        self.assertEqual(len(result.report.evidence_inventory), 2)
        for item in result.report.evidence_inventory:
            self.assertEqual(item.verification_status, "VERIFIED")

        # Check files written
        self.assertIsNotNone(result.json_report_path)
        self.assertIsNotNone(result.html_report_path)
        self.assertIsNotNone(result.ledger_path)
        self.assertTrue(result.json_report_path.exists())
        self.assertTrue(result.html_report_path.exists())
        self.assertTrue(result.ledger_path.exists())

        # Check custody chain
        self.assertTrue(result.custody_verification.is_valid)
        self.assertEqual(result.custody_verification.integrity_status, "VERIFIED")
        actions = [e.action_type for e in result.custody_ledger.events]
        self.assertEqual(
            actions,
            [
                CustodyActionType.EVIDENCE_RECEIVED.value,
                CustodyActionType.INTEGRITY_VERIFIED.value,
                CustodyActionType.REPORT_GENERATED.value,
            ],
        )

    # =========================================================================
    # 2. Manifest Discrepancy Workflows
    # =========================================================================

    def test_manifest_mismatch_workflow(self):
        """Verify that manifest hash mismatch records discrepancy faithfully in report and ledger."""
        alt_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
        entries = [
            {
                "relative_path": self.file1_rel,
                "size_bytes": len(self.file1_content),
                "hashes": {"sha256": alt_sha256},
                "artifact_type": "evidence",
            },
        ]
        man_path = self._create_manifest_file(entries)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
            actor=self.actor,
        )

        result = run_advanced_triage(config)

        # Discrepancy detected
        self.assertFalse(result.execution_success)
        self.assertIsNotNone(result.manifest_verification)
        self.assertFalse(result.manifest_verification.overall_status)
        self.assertEqual(result.manifest_verification.mismatch_count, 1)

        # Inventory item recorded as MISMATCH
        self.assertEqual(result.report.evidence_inventory[0].verification_status, "MISMATCH")

        # Discrepancy warning present in report limitations
        self.assertTrue(any("mismatch" in w.lower() for w in result.report.limitations.warnings))

        # Ledger recorded INTEGRITY_MISMATCH_DETECTED
        actions = [e.action_type for e in result.custody_ledger.events]
        self.assertIn(CustodyActionType.INTEGRITY_MISMATCH_DETECTED.value, actions)

    def test_manifest_missing_file_workflow(self):
        """Verify missing evidence file is recorded as discrepancy without crashing."""
        entries = [
            {
                "relative_path": "missing/file.raw",
                "size_bytes": 1024,
                "hashes": {"sha256": self.file1_sha256},
                "artifact_type": "evidence",
            },
        ]
        man_path = self._create_manifest_file(entries)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
        )

        result = run_advanced_triage(config)
        self.assertFalse(result.execution_success)
        self.assertEqual(result.manifest_verification.missing_count, 1)
        self.assertEqual(result.report.evidence_inventory[0].verification_status, "FILE_MISSING")

    # =========================================================================
    # 3. Missing Manifest Workflow
    # =========================================================================

    def test_workflow_without_manifest(self):
        """Verify workflow runs cleanly when no manifest is provided."""
        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=None,
        )

        result = run_advanced_triage(config)
        self.assertTrue(result.execution_success)
        self.assertIsNone(result.manifest_verification)
        self.assertEqual(len(result.report.evidence_inventory), 0)
        self.assertTrue(any("Evidence inventory was not provided" in o for o in result.report.limitations.omissions))

        # Ledger records RECEIVED and REPORT_GENERATED
        actions = [e.action_type for e in result.custody_ledger.events]
        self.assertEqual(
            actions,
            [
                CustodyActionType.EVIDENCE_RECEIVED.value,
                CustodyActionType.REPORT_GENERATED.value,
            ],
        )

    # =========================================================================
    # 4. Custody Event Ordering & Terminal Hash Boundary
    # =========================================================================

    def test_custody_event_ordering_and_terminal_hash_boundary(self):
        """Verify report custody summary captures pre-publication terminal hash and omission documents boundary."""
        entries = [
            {
                "relative_path": self.file1_rel,
                "size_bytes": len(self.file1_content),
                "hashes": {"sha256": self.file1_sha256},
            },
        ]
        man_path = self._create_manifest_file(entries)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
            actor=self.actor,
        )

        result = run_advanced_triage(config)

        # 1. Check pre-report terminal hash captured in report
        rep_custody = result.report.custody_summary
        self.assertIsNotNone(rep_custody)
        # Pre-report state had 2 events: EVIDENCE_RECEIVED and INTEGRITY_VERIFIED
        self.assertEqual(rep_custody.total_events, 2)
        pre_report_hash = rep_custody.terminal_hash

        # 2. Check final ledger on disk has 3 events (including REPORT_GENERATED)
        final_ledger = result.custody_ledger
        self.assertEqual(len(final_ledger), 3)
        self.assertEqual(final_ledger.events[2].action_type, CustodyActionType.REPORT_GENERATED.value)
        self.assertEqual(final_ledger.events[2].prev_event_hash, pre_report_hash)

        # 3. Check explicit limitation text in report documents the boundary
        boundary_omission = [o for o in result.report.limitations.omissions if "Embedded custody summary certifies" in o]
        self.assertEqual(len(boundary_omission), 1)
        self.assertIn(pre_report_hash, boundary_omission[0])
        self.assertIn("REPORT_GENERATED", boundary_omission[0])

    # =========================================================================
    # 5. Safe Ledger Resumption & Tamper Rejection
    # =========================================================================

    def test_safe_ledger_resumption(self):
        """Resume an existing valid ledger, preserving prior history and appending new events."""
        # Create initial ledger with prior custody event
        initial_ledger = CustodyLedger(case_id="CASE-2026-V85")
        initial_ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_COPIED,
            evidence_id="DISK-IMG-001",
            actor=self.actor,
            notes="Initial forensic bitstream copy created at acquisition site",
        )
        prior_event_id = initial_ledger.events[0].event_id
        prior_record_hash = initial_ledger.events[0].record_hash

        ledger_file = self.test_root / "existing_ledger.json"
        initial_ledger.save_to_file(ledger_file)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            custody_ledger_path=ledger_file,
            actor=self.actor,
        )

        result = run_advanced_triage(config)
        self.assertTrue(result.execution_success)

        # History preserved
        events = result.custody_ledger.events
        self.assertEqual(events[0].event_id, prior_event_id)
        self.assertEqual(events[0].record_hash, prior_record_hash)
        self.assertEqual(events[0].action_type, CustodyActionType.EVIDENCE_COPIED.value)

        # New events appended sequentially
        self.assertEqual(events[1].action_type, CustodyActionType.EVIDENCE_RECEIVED.value)
        self.assertEqual(events[1].prev_event_hash, prior_record_hash)
        self.assertEqual(events[2].action_type, CustodyActionType.REPORT_GENERATED.value)

        # Complete chain is valid
        self.assertTrue(result.custody_verification.is_valid)

    def test_tampered_ledger_rejection(self):
        """Reject resumption of a tampered ledger without modifying it."""
        initial_ledger = CustodyLedger(case_id="CASE-2026-V85")
        initial_ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
        )
        ledger_file = self.test_root / "tampered_ledger.json"
        initial_ledger.save_to_file(ledger_file)

        # Tamper with the file on disk by modifying action_type while keeping old hashes
        raw_data = json.loads(ledger_file.read_text(encoding="utf-8"))
        raw_data["events"][0]["action_type"] = "EVIDENCE_COPIED"
        ledger_file.write_text(json.dumps(raw_data), encoding="utf-8")

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            custody_ledger_path=ledger_file,
        )

        with self.assertRaises(ValueError):
            run_advanced_triage(config)

    # =========================================================================
    # 6. Case ID Conflict Rejection
    # =========================================================================

    def test_conflicting_case_id_rejection(self):
        """Reject execution if config case_id conflicts with manifest case_id."""
        entries = [{"relative_path": self.file1_rel, "size_bytes": 10, "hashes": {"sha256": self.file1_sha256}}]
        man_path = self._create_manifest_file(entries, case_id="CASE-CONFLICT-999")

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata={"case_id": "CASE-2026-V85"},
            manifest_path=man_path,
        )

        with self.assertRaises(ValueError) as ctx:
            run_advanced_triage(config)
        self.assertIn("Conflicting case_id", str(ctx.exception))

    # =========================================================================
    # 7. Filesystem Safety & Evidence Overlap Rejection
    # =========================================================================

    def test_evidence_root_overlap_rejection(self):
        """Strictly reject output directory that resides inside or overlaps evidence root."""
        inside_evidence_out = self.ev_dir / "forbidden_reports"
        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=inside_evidence_out,
            case_metadata=self.case_meta,
        )

        with self.assertRaises(ValueError) as ctx:
            run_advanced_triage(config)
        self.assertIn("overlaps or resides inside evidence directory", str(ctx.exception))
        # Ensure zero files written inside evidence root
        self.assertFalse(inside_evidence_out.exists())

    def test_evidence_byte_immutability(self):
        """Verify evidence files are strictly unmodified in bytes, size, and mtime."""
        initial_f1_stat = self.file1_path.stat()
        initial_f1_bytes = self.file1_path.read_bytes()

        entries = [{"relative_path": self.file1_rel, "size_bytes": len(self.file1_content), "hashes": {"sha256": self.file1_sha256}}]
        man_path = self._create_manifest_file(entries)

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
        )
        run_advanced_triage(config)

        current_f1_stat = self.file1_path.stat()
        self.assertEqual(self.file1_path.read_bytes(), initial_f1_bytes)
        self.assertEqual(current_f1_stat.st_size, initial_f1_stat.st_size)
        self.assertEqual(current_f1_stat.st_mtime_ns, initial_f1_stat.st_mtime_ns)

    # =========================================================================
    # 8. No-Clobber & Overwrite Semantics
    # =========================================================================

    def test_no_clobber_and_overwrite_semantics(self):
        """Verify overwrite=False refuses to clobber existing output, while overwrite=True replaces atomically."""
        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            overwrite=False,
        )
        result1 = run_advanced_triage(config)
        self.assertTrue(result1.json_report_path.exists())

        # Second run without overwrite should fail with FileExistsError
        with self.assertRaises(FileExistsError):
            run_advanced_triage(config)

        # Run with overwrite=True should succeed
        config_overwrite = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            overwrite=True,
        )
        result2 = run_advanced_triage(config_overwrite)
        self.assertTrue(result2.execution_success)

    # =========================================================================
    # 9. Verify-Only Execution
    # =========================================================================

    def test_verify_only_execution(self):
        """Verify that verify_only=True suppresses caller analysis inputs and documents omission."""
        entries = [{"relative_path": self.file1_rel, "size_bytes": len(self.file1_content), "hashes": {"sha256": self.file1_sha256}}]
        man_path = self._create_manifest_file(entries)

        # Supply non-empty analysis findings and details
        caller_findings = FindingsSummary(total_host_artifacts=25)
        caller_details = {"scanner_module": "v2_audit", "metrics": {"observed": 100}}

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            manifest_path=man_path,
            findings_summary=caller_findings,
            details=caller_details,
            verify_only=True,
        )
        result = run_advanced_triage(config)
        self.assertTrue(result.execution_success)

        # Analysis findings must be suppressed so total_host_artifacts is 0 and details is None
        self.assertEqual(result.report.findings_summary.total_host_artifacts, 0)
        self.assertIsNone(result.report.details)

        # Omission must explicitly state that analysis was skipped per verify_only flag
        expected_omission = (
            "Investigation analysis skipped per verify_only flag; report reflects "
            "evidence inventory and custody ledger verification."
        )
        self.assertIn(expected_omission, result.report.limitations.omissions)

        # Verify evidence inventory and custody validation are still fully performed
        self.assertEqual(len(result.report.evidence_inventory), 1)
        self.assertEqual(result.report.evidence_inventory[0].verification_status, "VERIFIED")
        self.assertTrue(result.custody_verification.is_valid)

        # Verify caller objects and config were not mutated
        self.assertEqual(caller_findings.total_host_artifacts, 25)
        self.assertEqual(config.findings_summary.total_host_artifacts, 25)

    # =========================================================================
    # 10. Output Destination Collision Rejection
    # =========================================================================

    def test_output_destination_collision_json_and_ledger(self):
        """Reject execution if JSON report and custody ledger target the identical file path."""
        colliding_name = "unified_output.json"
        target_path = self.out_dir / colliding_name

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            json_output_name=colliding_name,
            ledger_output_name=colliding_name,
            formats=("json",),
        )

        with self.assertRaises(ValueError) as ctx:
            run_advanced_triage(config)
        self.assertIn("Output destination collision", str(ctx.exception))
        # Prove rejection occurred before any file was created
        self.assertFalse(target_path.exists())

    def test_output_destination_collision_json_and_html(self):
        """Reject execution if JSON and HTML destinations collide on the same path."""
        colliding_name = "report_target.dat"
        target_path = self.out_dir / colliding_name

        config = AdvancedTriageConfig(
            evidence_directory=self.ev_dir,
            output_dir=self.out_dir,
            case_metadata=self.case_meta,
            json_output_name=colliding_name,
            html_output_name=colliding_name,
            formats=("json", "html"),
        )

        with self.assertRaises(ValueError) as ctx:
            run_advanced_triage(config)
        self.assertIn("Output destination collision", str(ctx.exception))
        # Prove rejection occurred before any file was created
        self.assertFalse(target_path.exists())


if __name__ == "__main__":
    unittest.main()
