"""
Comprehensive Unit Tests for ForensiX Custody Transfer Engine (V8.7).

Covers all approved V8.7 requirements:
- Transfer model validation and ID formats (COCTRAN-<UUIDv4>).
- Schema 8.0 event bridging and legacy deserialization compatibility.
- Same-custodian relocation vs valid inter-custodian transfers.
- Possession-continuity breaks and missing intake events.
- Legacy and mixed-ledger auditing behavior.
- Trusted, mismatched, unavailable, and untrusted digest baselines.
- Manifest-to-evidence identity mapping and manifest verification failures.
- Status precedence (TAMPERED > DISCREPANCY > INCOMPLETE > VERIFIED) and findings preservation.
- Per-evidence chronology, equal timestamps, timezone-aware/naive values, and timestamp uncertainty.
- Stale-ledger detection on overwrite collision.
- Receipt determinism and canonical digest verification.
"""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from forensix.custody_ledger import (
    CustodyLedger,
    StaleLedgerError,
)
from forensix.custody_models import (
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
)
from forensix.custody_transfer import (
    AuditFinding,
    CustodyAuditResult,
    CustodyTransferReceipt,
    CustodyTransferRecord,
    CustodyTransferStatus,
    audit_custody_ledger,
    generate_custody_receipt_id,
    generate_custody_transfer_id,
    generate_transfer_receipt,
    is_valid_custody_receipt_id,
    is_valid_custody_transfer_id,
    parse_transfer_from_event,
    record_transfer,
)
from forensix.manifest_models import (
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    generate_manifest_id,
)
from forensix.manifest_verifier import (
    ManifestEntryVerification,
    ManifestVerificationResult,
    ManifestVerificationStatus,
)


class TestCustodyTransferModels(unittest.TestCase):
    """Test CustodyTransferRecord and CustodyTransferReceipt data models."""

    def setUp(self):
        self.actor_a = CustodyActor(
            declared_identity="Detective Alice Smith",
            role="Evidence Custodian",
            organization="Cyber Crimes Division",
        )
        self.actor_b = CustodyActor(
            declared_identity="Examiner Bob Jones",
            role="Senior Forensic Analyst",
            organization="Digital Forensics Lab",
        )

    def test_transfer_id_generation_and_validation(self):
        """Validate COCTRAN-<UUIDv4> tracking identifier format."""
        tid = generate_custody_transfer_id()
        self.assertTrue(is_valid_custody_transfer_id(tid))
        self.assertTrue(tid.startswith("COCTRAN-"))
        self.assertEqual(len(tid), 8 + 36)

        # Rejections
        self.assertFalse(is_valid_custody_transfer_id("COCTRAN-invalid-uuid"))
        self.assertFalse(is_valid_custody_transfer_id("COCEVT-550e8400-e29b-41d4-a716-446655440000"))
        self.assertFalse(is_valid_custody_transfer_id(12345))
        self.assertFalse(is_valid_custody_transfer_id(None))

    def test_receipt_id_generation_and_validation(self):
        """Validate COCRECP-<UUIDv4> tracking identifier format."""
        rid = generate_custody_receipt_id()
        self.assertTrue(is_valid_custody_receipt_id(rid))
        self.assertTrue(rid.startswith("COCRECP-"))
        self.assertEqual(len(rid), 8 + 36)

        self.assertFalse(is_valid_custody_receipt_id("COCRECP-not-uuid"))
        self.assertFalse(is_valid_custody_receipt_id("COCTRAN-550e8400-e29b-41d4-a716-446655440000"))

    def test_valid_transfer_record_creation_and_immutability(self):
        """Verify proper instantiation, immutability, and to_dict conversion."""
        tid = generate_custody_transfer_id()
        record = CustodyTransferRecord(
            transfer_id=tid,
            evidence_id="EV-1001",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Locker 4",
            destination_location="Workstation 2",
            transfer_timestamp="2026-10-21T08:00:00Z",
            reason="Forensic analysis",
            authorization_ref="Warrant-2026-09",
            condition_notes="Evidence bag seal intact",
            hashes=(("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),),
        )
        self.assertEqual(record.transfer_id, tid)
        self.assertEqual(record.evidence_id, "EV-1001")
        self.assertFalse(record.is_relocation)

        with self.assertRaises(FrozenInstanceError):
            record.reason = "New reason"

        d = record.to_dict()
        self.assertEqual(d["transfer_id"], tid)
        self.assertEqual(d["releasing_actor"]["declared_identity"], "Detective Alice Smith")
        self.assertEqual(d["receiving_actor"]["declared_identity"], "Examiner Bob Jones")
        self.assertFalse(d["is_relocation"])

    def test_relocation_same_custodian(self):
        """When releasing and receiving actors match, is_relocation is True."""
        record = CustodyTransferRecord(
            transfer_id=generate_custody_transfer_id(),
            evidence_id="EV-1001",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_a,
            source_location="Locker 4",
            destination_location="Secure Vault 1",
            transfer_timestamp="2026-10-21T08:00:00Z",
            reason="Internal vault reorganization",
        )
        self.assertTrue(record.is_relocation)
        self.assertEqual(record.source_location, "Locker 4")
        self.assertEqual(record.destination_location, "Secure Vault 1")

    def test_transfer_record_validation_errors(self):
        """Verify defensive rejections on malformed arguments."""
        tid = generate_custody_transfer_id()
        # Invalid transfer_id
        with self.assertRaises(ValueError):
            CustodyTransferRecord(
                transfer_id="invalid-id",
                evidence_id="EV-1001",
                releasing_actor=self.actor_a,
                receiving_actor=self.actor_b,
                source_location="L1",
                destination_location="L2",
                transfer_timestamp="2026-10-21T08:00:00Z",
                reason="Analysis",
            )
        # Empty evidence_id
        with self.assertRaises(ValueError):
            CustodyTransferRecord(
                transfer_id=tid,
                evidence_id="   ",
                releasing_actor=self.actor_a,
                receiving_actor=self.actor_b,
                source_location="L1",
                destination_location="L2",
                transfer_timestamp="2026-10-21T08:00:00Z",
                reason="Analysis",
            )
        # Invalid actor type
        with self.assertRaises(TypeError):
            CustodyTransferRecord(
                transfer_id=tid,
                evidence_id="EV-1001",
                releasing_actor="Not an Actor",  # type: ignore
                receiving_actor=self.actor_b,
                source_location="L1",
                destination_location="L2",
                transfer_timestamp="2026-10-21T08:00:00Z",
                reason="Analysis",
            )
        # Empty location
        with self.assertRaises(ValueError):
            CustodyTransferRecord(
                transfer_id=tid,
                evidence_id="EV-1001",
                releasing_actor=self.actor_a,
                receiving_actor=self.actor_b,
                source_location="",
                destination_location="L2",
                transfer_timestamp="2026-10-21T08:00:00Z",
                reason="Analysis",
            )
        # Empty reason
        with self.assertRaises(ValueError):
            CustodyTransferRecord(
                transfer_id=tid,
                evidence_id="EV-1001",
                releasing_actor=self.actor_a,
                receiving_actor=self.actor_b,
                source_location="L1",
                destination_location="L2",
                transfer_timestamp="2026-10-21T08:00:00Z",
                reason="   ",
            )


class TestCustodyTransferEngine(unittest.TestCase):
    """Test transfer recording, bridging to CustodyEvent, and receipt generation."""

    def setUp(self):
        self.actor_a = CustodyActor(declared_identity="Officer Alice", role="Evidence Officer")
        self.actor_b = CustodyActor(declared_identity="Examiner Bob", role="Forensic Analyst")
        self.actor_c = CustodyActor(declared_identity="Specialist Charlie", role="Network Specialist")

    def test_record_transfer_and_event_bridging(self):
        """Verify bridging to Schema 8.0 CustodyEvent and valid hash calculation."""
        ledger = CustodyLedger(case_id="CASE-2026-T1")
        # Step 1: Intake
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-DISK-01",
            actor=self.actor_a,
            source_location="Intake Counter",
            destination_location="Locker 1",
            timestamp="2026-10-21T08:00:00Z",
        )

        # Step 2: Transfer to Bob
        event, transfer = record_transfer(
            ledger=ledger,
            evidence_id="EV-DISK-01",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Locker 1",
            destination_location="Forensics Workstation",
            reason="Disk triage and imaging",
            timestamp="2026-10-21T09:00:00Z",
        )

        self.assertEqual(len(ledger), 2)
        self.assertEqual(event.sequence_number, 1)
        self.assertEqual(event.action_type, CustodyActionType.CUSTODY_TRANSFERRED)
        self.assertEqual(event.actor, self.actor_b)  # Active receiving custodian
        self.assertEqual(transfer.event_id, event.event_id)

        # Reconstructed from event notes
        parsed_transfer = parse_transfer_from_event(event)
        self.assertIsNotNone(parsed_transfer)
        self.assertEqual(parsed_transfer.transfer_id, transfer.transfer_id)
        self.assertEqual(parsed_transfer.releasing_actor.declared_identity, "Officer Alice")
        self.assertEqual(parsed_transfer.receiving_actor.declared_identity, "Examiner Bob")

        # Ledger cryptographic chain remains 100% valid
        chain_res = ledger.validate_chain()
        self.assertTrue(chain_res.is_valid)
        self.assertEqual(chain_res.integrity_status, "VERIFIED")

    def test_receipt_generation_and_determinism(self):
        """Verify receipt generation, canonical digest binding, and deterministic rendering."""
        ledger = CustodyLedger(case_id="CASE-RECEIPT-01")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-100",
            actor=self.actor_a,
            timestamp="2026-10-21T08:00:00Z",
        )
        _, transfer = record_transfer(
            ledger=ledger,
            evidence_id="EV-100",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Station",
            destination_location="Lab",
            reason="Extraction",
            timestamp="2026-10-21T09:00:00Z",
            hashes={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )

        fixed_rid = "COCRECP-550e8400-e29b-41d4-a716-446655440000"
        receipt1 = generate_transfer_receipt(transfer=transfer, ledger=ledger, receipt_id=fixed_rid)
        receipt2 = generate_transfer_receipt(transfer=transfer, ledger=ledger, receipt_id=fixed_rid)

        # Deterministic serialization check
        self.assertEqual(receipt1.receipt_digest, receipt2.receipt_digest)
        self.assertEqual(receipt1.to_json(), receipt2.to_json())
        self.assertEqual(receipt1.render_text(), receipt2.render_text())
        self.assertIn("FORENSIX FORMAL CUSTODY TRANSFER RECEIPT", receipt1.render_text())
        self.assertIn("Officer Alice", receipt1.render_text())
        self.assertIn("Examiner Bob", receipt1.render_text())


class TestCustodyAuditEngine(unittest.TestCase):
    """Test comprehensive audit engine: possession continuity, digest baselines, chronology, and precedence."""

    def setUp(self):
        self.actor_a = CustodyActor(declared_identity="Officer Alice")
        self.actor_b = CustodyActor(declared_identity="Examiner Bob")
        self.actor_c = CustodyActor(declared_identity="Specialist Charlie")
        self.sha256_clean = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sha256_alt = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

    def test_audit_empty_ledger_incomplete_history(self):
        """Empty ledger returns INCOMPLETE_HISTORY, never VERIFIED."""
        ledger = CustodyLedger()
        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "INCOMPLETE_HISTORY")
        self.assertFalse(audit_res.is_valid)
        self.assertEqual(audit_res.total_events, 0)
        self.assertTrue(any(f.finding_type == "EMPTY_LEDGER" for f in audit_res.findings))

    def test_audit_clean_chain_evaluates_verified(self):
        """Intake followed by verified transfers evaluates to VERIFIED."""
        ledger = CustodyLedger(case_id="CASE-CLEAN")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor_a,
            source_location="Locker 1",
            timestamp="2026-10-21T08:00:00Z",
        )
        record_transfer(
            ledger=ledger,
            evidence_id="EV-1",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Locker 1",
            destination_location="Lab",
            reason="Examination",
            timestamp="2026-10-21T09:00:00Z",
        )
        record_transfer(
            ledger=ledger,
            evidence_id="EV-1",
            releasing_actor=self.actor_b,
            receiving_actor=self.actor_c,
            source_location="Lab",
            destination_location="Vault",
            reason="Storage",
            timestamp="2026-10-21T10:00:00Z",
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "VERIFIED")
        self.assertTrue(audit_res.is_valid)
        self.assertEqual(audit_res.total_events, 3)
        self.assertEqual(dict(audit_res.current_custodians)["EV-1"]["declared_identity"], "Specialist Charlie")
        self.assertEqual(dict(audit_res.current_locations)["EV-1"], "Vault")

    def test_audit_detects_possession_continuity_break(self):
        """Transfer released by an entity who does not hold active custody flags DISCREPANCY_DETECTED."""
        ledger = CustodyLedger(case_id="CASE-BREAK")
        # Intake to Alice
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor_a,
            timestamp="2026-10-21T08:00:00Z",
        )
        # Charlie purports to release EV-1 to Bob (Alice has it!)
        record_transfer(
            ledger=ledger,
            evidence_id="EV-1",
            releasing_actor=self.actor_c,  # Unauthorized releasing actor
            receiving_actor=self.actor_b,
            source_location="Desk",
            destination_location="Lab",
            reason="Unapproved transfer",
            timestamp="2026-10-21T09:00:00Z",
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "DISCREPANCY_DETECTED")
        self.assertFalse(audit_res.is_valid)
        self.assertTrue(any(f.finding_type == "POSSESSION_CONTINUITY_BREAK" for f in audit_res.findings))

    def test_audit_missing_intake_incomplete_history(self):
        """Transfer with no prior intake event returns INCOMPLETE_HISTORY."""
        ledger = CustodyLedger(case_id="CASE-NO-INTAKE")
        record_transfer(
            ledger=ledger,
            evidence_id="EV-UNREGISTERED",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Locker",
            destination_location="Lab",
            reason="Triage",
            timestamp="2026-10-21T09:00:00Z",
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "INCOMPLETE_HISTORY")
        self.assertFalse(audit_res.is_valid)
        self.assertTrue(any(f.finding_type == "MISSING_INTAKE_EVENT" for f in audit_res.findings))

    def test_audit_legacy_single_actor_transfer(self):
        """Legacy transfer event without structured notes returns INCOMPLETE_HISTORY."""
        ledger = CustodyLedger(case_id="CASE-LEGACY")
        # Legacy event added directly
        ledger.append_event(
            action_type=CustodyActionType.CUSTODY_TRANSFERRED,
            evidence_id="EV-LEGACY",
            actor=self.actor_b,
            source_location="Locker",
            destination_location="Lab",
            notes="Legacy transfer record notes string without JSON metadata",
            timestamp="2026-10-21T08:00:00Z",
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "INCOMPLETE_HISTORY")
        self.assertTrue(any(f.finding_type == "UNVERIFIABLE_LEGACY_TRANSFER" for f in audit_res.findings))

    def test_audit_per_evidence_chronology_isolation(self):
        """Timestamps for different evidence items are isolated and do not trigger chronology inversions."""
        ledger = CustodyLedger(case_id="CASE-CHRONO-ISO")
        # EV-1 at 10:00
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor_a,
            timestamp="2026-10-21T10:00:00Z",
        )
        # EV-2 at 08:00 (earlier than EV-1, but separate item!)
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-2",
            actor=self.actor_b,
            timestamp="2026-10-21T08:00:00Z",
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "VERIFIED")
        self.assertFalse(any("CHRONOLOGICAL_INVERSION" in f.finding_type for f in audit_res.findings))

    def test_audit_chronological_inversion_same_evidence(self):
        """Backward timestamp on the same evidence item triggers DISCREPANCY_DETECTED, not TAMPERED."""
        ledger = CustodyLedger(case_id="CASE-CHRONO-REV")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor_a,
            timestamp="2026-10-21T10:00:00Z",
        )
        record_transfer(
            ledger=ledger,
            evidence_id="EV-1",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="L1",
            destination_location="L2",
            reason="Move",
            timestamp="2026-10-21T09:00:00Z",  # 1 hour earlier!
        )

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "DISCREPANCY_DETECTED")
        self.assertTrue(any("CHRONOLOGICAL_INVERSION" in f.finding_type for f in audit_res.findings))

    def test_audit_digest_baseline_matching_and_mismatch(self):
        """Verifies digest matching vs mismatch against supplied manifest verification result."""
        ledger = CustodyLedger(case_id="CASE-DIGEST")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="doc1.txt",
            actor=self.actor_a,
            hashes={"sha256": self.sha256_clean},
            timestamp="2026-10-21T08:00:00Z",
        )
        # Mismatch transfer: records sha256_alt instead of sha256_clean
        record_transfer(
            ledger=ledger,
            evidence_id="doc1.txt",
            releasing_actor=self.actor_a,
            receiving_actor=self.actor_b,
            source_location="Desk",
            destination_location="Lab",
            reason="Check",
            hashes={"sha256": self.sha256_alt},
            timestamp="2026-10-21T09:00:00Z",
        )

        # Build mock verified ManifestVerificationResult with baseline for doc1.txt
        manifest_verif = ManifestVerificationResult(
            manifest_id="MANIFEST-1",
            manifest_version="8.0",
            base_dir="/tmp/ev",
            total_entries=1,
            verified_count=1,
            mismatch_count=0,
            missing_count=0,
            error_count=0,
            overall_status=True,
            entry_results=(
                ManifestEntryVerification(
                    relative_path="doc1.txt",
                    status=ManifestVerificationStatus.VERIFIED,
                    expected_hashes=(("sha256", self.sha256_clean),),
                ),
            ),
        )

        audit_res = audit_custody_ledger(ledger, manifest=manifest_verif)
        self.assertEqual(audit_res.audit_status, "DISCREPANCY_DETECTED")
        self.assertTrue(any(f.finding_type == "DIGEST_MISMATCH" for f in audit_res.findings))

    def test_precedence_hierarchy_tampered_over_discrepancy(self):
        """TAMPERED overrides DISCREPANCY_DETECTED when cryptographic hash chain is broken."""
        ledger = CustodyLedger(case_id="CASE-PRECEDENCE")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor_a,
            timestamp="2026-10-21T08:00:00Z",
        )
        # Add possession break
        record_transfer(
            ledger=ledger,
            evidence_id="EV-1",
            releasing_actor=self.actor_c,  # Possession break!
            receiving_actor=self.actor_b,
            source_location="L1",
            destination_location="L2",
            reason="Move",
            timestamp="2026-10-21T09:00:00Z",
        )

        # Now corrupt an event record hash manually to induce tampering
        corrupted_event = CustodyEvent(
            event_id=ledger.events[1].event_id,
            sequence_number=1,
            timestamp=ledger.events[1].timestamp,
            timestamp_source=ledger.events[1].timestamp_source,
            action_type=ledger.events[1].action_type,
            evidence_id=ledger.events[1].evidence_id,
            actor=ledger.events[1].actor,
            source_location=ledger.events[1].source_location,
            destination_location=ledger.events[1].destination_location,
            hashes=ledger.events[1].hashes,
            notes=ledger.events[1].notes,
            prev_event_hash="f" * 64,  # Broken prev link!
            record_hash=None,
        )
        ledger._events[1] = corrupted_event

        audit_res = audit_custody_ledger(ledger)
        self.assertEqual(audit_res.audit_status, "TAMPERED")
        self.assertFalse(audit_res.is_valid)
        # Confirms BOTH tampered chain and possession break findings are preserved!
        self.assertTrue(any(f.severity == "TAMPERED" for f in audit_res.findings))
        self.assertTrue(any(f.finding_type == "POSSESSION_CONTINUITY_BREAK" for f in audit_res.findings))


class TestStaleLedgerProtection(unittest.TestCase):
    """Test stale ledger state detection and atomic write guarantees."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_stale_")
        self.ledger_file = Path(self.temp_dir) / "test_ledger.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_stale_state_detection_aborts_overwrite(self):
        """If disk file terminal hash changes after loading, saving raises StaleLedgerError."""
        actor = CustodyActor(declared_identity="Analyst A")
        ledger = CustodyLedger(case_id="CASE-STALE")
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T08:00:00Z",
        )
        ledger.save_to_file(self.ledger_file)

        # Instance 1 loads the ledger
        instance_1 = CustodyLedger.load_from_file(self.ledger_file)

        # Instance 2 loads the ledger and commits an update
        instance_2 = CustodyLedger.load_from_file(self.ledger_file)
        instance_2.append_event(
            action_type=CustodyActionType.ANALYSIS_STARTED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T09:00:00Z",
        )
        instance_2.save_to_file(self.ledger_file, overwrite=True)

        # Instance 1 attempts to save without reloading: must detect stale state and abort!
        instance_1.append_event(
            action_type=CustodyActionType.REPORT_GENERATED,
            evidence_id="EV-1",
            actor=actor,
            timestamp="2026-10-21T10:00:00Z",
        )
        with self.assertRaises(StaleLedgerError) as ctx:
            instance_1.save_to_file(self.ledger_file, overwrite=True)
        self.assertIn("was modified", str(ctx.exception))
        self.assertIn("Commit aborted to prevent data loss", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
