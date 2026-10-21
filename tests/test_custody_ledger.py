"""
Unit and integration tests for ForensiX Runtime Chain-of-Custody Ledger Engine (custody_ledger.py).

Covers all approved V8.3 requirements:
- Genesis & sequential event chaining.
- Ledger header digest computation and verification.
- Anti-silent-regeneration on import (rejection of missing, malformed, or mismatched record_hash).
- Rejection of missing, malformed, or mismatched ledger_digest on import.
- Atomic append failure semantics (zero mutation of state on failed append).
- Chain integrity verification and discrepancy reporting.
- Status classification ('VERIFIED', 'UNVERIFIED', 'TAMPERED').
- Report summary bridge integration (CustodySummary).
- Persistence safety, existing destination policies (overwrite=False/True), and atomic writes.
- Evidence-root containment validation (rejection of collision with or placement within evidence directory).
- Safe cleanup of temporary files upon persistence failures.
- Immutability of returned events and containers.
- Evidence bytes and st_mtime_ns immutability.
"""

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from forensix.advanced_report_models import CustodySummary
from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    compute_event_record_hash,
    generate_custody_event_id,
)
from forensix.custody_ledger import (
    CUSTODY_LEDGER_SCHEMA_VERSION,
    CustodyChainVerificationResult,
    CustodyLedger,
    compute_canonical_ledger_header_json,
    compute_canonical_ledger_header_payload,
    compute_ledger_digest,
    generate_custody_ledger_id,
    is_valid_custody_ledger_id,
)


class TestCustodyLedgerBasics(unittest.TestCase):
    """Test standard ledger initialization, event appending, and accessors."""

    def setUp(self):
        self.actor = CustodyActor(
            declared_identity="Detective Inspector John Vance",
            role="Lead Digital Forensic Examiner",
            organization="Major Cyber Crimes Bureau",
        )
        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_ledger_id_generation_and_validation(self):
        """Verify canonical COCLEDGER-<UUIDv4> format."""
        lid = generate_custody_ledger_id()
        self.assertTrue(is_valid_custody_ledger_id(lid))
        self.assertTrue(lid.startswith("COCLEDGER-"))

        # Rejections
        self.assertFalse(is_valid_custody_ledger_id("COCLEDGER-not-a-uuid"))
        self.assertFalse(is_valid_custody_ledger_id("COCEVT-550e8400-e29b-41d4-a716-446655440000"))
        self.assertFalse(is_valid_custody_ledger_id(123))

    def test_empty_ledger_initialization(self):
        """Verify initial state of an empty ledger."""
        ledger = CustodyLedger(case_id="CASE-2026-001", description="Incident Triage Ledger")
        self.assertTrue(is_valid_custody_ledger_id(ledger.ledger_id))
        self.assertEqual(ledger.case_id, "CASE-2026-001")
        self.assertEqual(ledger.description, "Incident Triage Ledger")
        self.assertEqual(len(ledger), 0)
        self.assertEqual(len(ledger.events), 0)
        self.assertIsNone(ledger.terminal_hash)

    def test_append_genesis_event(self):
        """Appending first event automatically links to GENESIS_PREV_HASH."""
        ledger = CustodyLedger()
        ev = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1001",
            actor=self.actor,
            hashes={"sha256": self.sample_sha256},
            timestamp="2026-10-20T08:00:00Z",
        )

        self.assertEqual(len(ledger), 1)
        self.assertEqual(ev.sequence_number, 0)
        self.assertEqual(ev.prev_event_hash, GENESIS_PREV_HASH)
        self.assertEqual(ledger.terminal_hash, ev.record_hash)
        self.assertEqual(ledger[0], ev)

    def test_append_multiple_sequential_events(self):
        """Appending sequential events links to prior event record_hash."""
        ledger = CustodyLedger()
        ev0 = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1001",
            actor=self.actor,
            timestamp="2026-10-20T08:00:00Z",
        )
        ev1 = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-1001",
            actor=self.actor,
            timestamp="2026-10-20T08:30:00Z",
        )
        ev2 = ledger.append_event(
            action_type=CustodyActionType.ANALYSIS_STARTED,
            evidence_id="EV-1001",
            actor=self.actor,
            timestamp="2026-10-20T09:00:00Z",
        )

        self.assertEqual(len(ledger), 3)
        self.assertEqual(ev0.sequence_number, 0)
        self.assertEqual(ev0.prev_event_hash, GENESIS_PREV_HASH)

        self.assertEqual(ev1.sequence_number, 1)
        self.assertEqual(ev1.prev_event_hash, ev0.record_hash)

        self.assertEqual(ev2.sequence_number, 2)
        self.assertEqual(ev2.prev_event_hash, ev1.record_hash)

        self.assertEqual(ledger.terminal_hash, ev2.record_hash)

    def test_events_tuple_immutability(self):
        """ledger.events returns an immutable tuple; events themselves are frozen."""
        ledger = CustodyLedger()
        ev = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1001",
            actor=self.actor,
            timestamp="2026-10-20T08:00:00Z",
        )

        events_view = ledger.events
        self.assertIsInstance(events_view, tuple)

        with self.assertRaises(FrozenInstanceError):
            ev.evidence_id = "EV-TAMPERED"


class TestCustodyLedgerHeaderDigest(unittest.TestCase):
    """Test ledger-level canonical header digest calculation."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Analyst Smith")
        self.ledger = CustodyLedger(
            ledger_id="COCLEDGER-00000000-0000-4000-8000-000000000001",
            created_at="2026-10-20T10:00:00Z",
            case_id="CASE-ALPHA",
            description="Header Digest Test",
        )

    def test_canonical_header_payload_fields(self):
        """Verify exact field composition of header payload."""
        payload = compute_canonical_ledger_header_payload(self.ledger)
        self.assertEqual(
            set(payload.keys()),
            {"case_id", "created_at", "description", "ledger_id", "terminal_hash", "total_events"},
        )
        self.assertEqual(payload["case_id"], "CASE-ALPHA")
        self.assertEqual(payload["created_at"], "2026-10-20T10:00:00Z")
        self.assertEqual(payload["description"], "Header Digest Test")
        self.assertEqual(payload["ledger_id"], "COCLEDGER-00000000-0000-4000-8000-000000000001")
        self.assertEqual(payload["terminal_hash"], GENESIS_PREV_HASH)
        self.assertEqual(payload["total_events"], 0)

    def test_header_digest_changes_on_metadata_mutation(self):
        """Altering metadata produces a different header digest."""
        digest1 = self.ledger.ledger_digest

        ledger2 = CustodyLedger(
            ledger_id=self.ledger.ledger_id,
            created_at=self.ledger.created_at,
            case_id="CASE-BETA",  # Changed case_id
            description=self.ledger.description,
        )
        self.assertNotEqual(digest1, ledger2.ledger_digest)

    def test_header_digest_changes_when_events_appended(self):
        """Appending an event changes total_events and terminal_hash in header digest."""
        initial_digest = self.ledger.ledger_digest
        self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
            timestamp="2026-10-20T10:05:00Z",
        )
        self.assertNotEqual(initial_digest, self.ledger.ledger_digest)


class TestCustodyLedgerImportAntiSilentRegeneration(unittest.TestCase):
    """Test strict import validation and anti-silent-regeneration rules."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Analyst Smith")
        self.ledger = CustodyLedger(
            ledger_id="COCLEDGER-00000000-0000-4000-8000-000000000002",
            created_at="2026-10-20T10:00:00Z",
        )
        self.ev0 = self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
            timestamp="2026-10-20T10:05:00Z",
        )

    def test_import_rejects_missing_event_record_hash(self):
        """Deserialization strictly rejects event missing 'record_hash' (no silent generation)."""
        data = self.ledger.to_dict()
        del data["events"][0]["record_hash"]

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("missing required 'record_hash'", str(ctx.exception))

    def test_import_rejects_null_event_record_hash(self):
        """Deserialization strictly rejects event with null 'record_hash'."""
        data = self.ledger.to_dict()
        data["events"][0]["record_hash"] = None

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("missing required 'record_hash'", str(ctx.exception))

    def test_import_rejects_malformed_event_record_hash(self):
        """Deserialization strictly rejects non-64-hex 'record_hash'."""
        data = self.ledger.to_dict()
        data["events"][0]["record_hash"] = "short-hash"

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("malformed record_hash", str(ctx.exception))

    def test_import_rejects_mismatched_event_record_hash(self):
        """Deserialization strictly rejects event whose record_hash does not match payload."""
        data = self.ledger.to_dict()
        data["events"][0]["record_hash"] = "f" * 64

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("does not match computed canonical SHA-256 digest", str(ctx.exception))

    def test_import_rejects_missing_ledger_digest(self):
        """Deserialization strictly rejects ledger missing 'ledger_digest'."""
        data = self.ledger.to_dict()
        del data["ledger_digest"]

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("missing required 'ledger_digest'", str(ctx.exception))

    def test_import_rejects_mismatched_ledger_digest(self):
        """Deserialization strictly rejects ledger with tampered 'ledger_digest'."""
        data = self.ledger.to_dict()
        data["ledger_digest"] = "e" * 64

        with self.assertRaises(ValueError) as ctx:
            CustodyLedger.from_dict(data)
        self.assertIn("does not match computed canonical header digest", str(ctx.exception))

    def test_successful_round_trip_preserves_exact_hashes(self):
        """Valid import reproduces exact original hashes without alteration."""
        original_dict = self.ledger.to_dict()
        restored = CustodyLedger.from_dict(original_dict)

        self.assertEqual(restored.ledger_id, self.ledger.ledger_id)
        self.assertEqual(restored.terminal_hash, self.ledger.terminal_hash)
        self.assertEqual(restored.ledger_digest, self.ledger.ledger_digest)
        self.assertEqual(restored[0].record_hash, self.ev0.record_hash)


class TestCustodyLedgerAtomicAppend(unittest.TestCase):
    """Test atomic in-memory append behavior: failures cause zero mutation."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Analyst Smith")
        self.ledger = CustodyLedger()
        self.ev0 = self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
            timestamp="2026-10-20T10:00:00Z",
        )

    def test_failed_append_invalid_action_leaves_ledger_unchanged(self):
        """Failed append due to invalid action type leaves ledger state intact."""
        initial_len = len(self.ledger)
        initial_hash = self.ledger.terminal_hash
        initial_events = self.ledger.events

        with self.assertRaises(ValueError):
            self.ledger.append_event(
                action_type="INVALID_ACTION_NAME",
                evidence_id="EV-1",
                actor=self.actor,
            )

        self.assertEqual(len(self.ledger), initial_len)
        self.assertEqual(self.ledger.terminal_hash, initial_hash)
        self.assertEqual(self.ledger.events, initial_events)

    def test_failed_append_invalid_timestamp_leaves_ledger_unchanged(self):
        """Failed append due to invalid timestamp leaves ledger state intact."""
        initial_len = len(self.ledger)
        initial_hash = self.ledger.terminal_hash

        with self.assertRaises(ValueError):
            self.ledger.append_event(
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-1",
                actor=self.actor,
                timestamp="NOT_A_TIMESTAMP",
            )

        self.assertEqual(len(self.ledger), initial_len)
        self.assertEqual(self.ledger.terminal_hash, initial_hash)

    def test_failed_append_duplicate_event_id_leaves_ledger_unchanged(self):
        """Failed append due to duplicate event_id leaves ledger state intact."""
        initial_len = len(self.ledger)
        initial_hash = self.ledger.terminal_hash

        with self.assertRaises(ValueError) as ctx:
            self.ledger.append_event(
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-1",
                actor=self.actor,
                event_id=self.ev0.event_id,  # Duplicate
            )
        self.assertIn("Duplicate event_id", str(ctx.exception))
        self.assertEqual(len(self.ledger), initial_len)
        self.assertEqual(self.ledger.terminal_hash, initial_hash)

    def test_failed_add_event_wrong_sequence_leaves_ledger_unchanged(self):
        """Failed add_event due to non-sequential sequence_number leaves ledger intact."""
        initial_len = len(self.ledger)
        initial_hash = self.ledger.terminal_hash

        bad_event = CustodyEvent(
            event_id=generate_custody_event_id(),
            sequence_number=99,  # Expected 1
            timestamp="2026-10-20T11:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.ANALYSIS_STARTED,
            evidence_id="EV-1",
            actor=self.actor,
            prev_event_hash=self.ev0.record_hash,
        )

        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_event(bad_event)
        self.assertIn("Invalid sequence_number 99", str(ctx.exception))
        self.assertEqual(len(self.ledger), initial_len)
        self.assertEqual(self.ledger.terminal_hash, initial_hash)


class TestCustodyLedgerChainValidation(unittest.TestCase):
    """Test chain verification, discrepancy detection, and TAMPERED classification."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Analyst Smith")
        self.ledger = CustodyLedger()
        self.ev0 = self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
            timestamp="2026-10-20T10:00:00Z",
        )
        self.ev1 = self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-1",
            actor=self.actor,
            timestamp="2026-10-20T10:30:00Z",
        )

    def test_empty_ledger_validation(self):
        """Empty ledger evaluates to UNVERIFIED and is_valid=True."""
        empty_ledger = CustodyLedger()
        res = empty_ledger.validate_chain()
        self.assertTrue(res.is_valid)
        self.assertEqual(res.integrity_status, "UNVERIFIED")
        self.assertEqual(res.total_events, 0)
        self.assertIsNone(res.terminal_hash)
        self.assertEqual(len(res.discrepancies), 0)

    def test_valid_chain_validation(self):
        """Valid populated chain evaluates to VERIFIED and is_valid=True."""
        res = self.ledger.validate_chain()
        self.assertTrue(res.is_valid)
        self.assertEqual(res.integrity_status, "VERIFIED")
        self.assertEqual(res.total_events, 2)
        self.assertEqual(res.terminal_hash, self.ev1.record_hash)
        self.assertEqual(len(res.discrepancies), 0)
        self.assertEqual(res.evidentiary_notice, CUSTODY_LIMITATIONS_DISCLAIMER)

    def test_validation_detects_sequence_gap(self):
        """Manually constructed chain with sequence gap evaluates to TAMPERED."""
        ev2_tampered = CustodyEvent(
            event_id=generate_custody_event_id(),
            sequence_number=3,  # Gap: expected 2
            timestamp="2026-10-20T11:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.ANALYSIS_STARTED,
            evidence_id="EV-1",
            actor=self.actor,
            prev_event_hash=self.ev1.record_hash,
        )
        tampered_ledger = CustodyLedger()
        tampered_ledger._events = [self.ev0, self.ev1, ev2_tampered]

        res = tampered_ledger.validate_chain()
        self.assertFalse(res.is_valid)
        self.assertEqual(res.integrity_status, "TAMPERED")
        self.assertTrue(any("Sequence error at index 2" in d for d in res.discrepancies))

    def test_validation_detects_broken_chain_link(self):
        """Chain with broken intermediate prev_event_hash evaluates to TAMPERED."""
        broken_ev1 = CustodyEvent(
            event_id=generate_custody_event_id(),
            sequence_number=1,
            timestamp="2026-10-20T10:30:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-1",
            actor=self.actor,
            prev_event_hash="1" * 64,  # Does not match ev0.record_hash
        )
        tampered_ledger = CustodyLedger()
        tampered_ledger._events = [self.ev0, broken_ev1]

        res = tampered_ledger.validate_chain()
        self.assertFalse(res.is_valid)
        self.assertEqual(res.integrity_status, "TAMPERED")
        self.assertTrue(any("Chain linkage mismatch at index 1" in d for d in res.discrepancies))

    def test_validation_detects_duplicate_event_id(self):
        """Chain with duplicate event_id evaluates to TAMPERED."""
        dup_ev1 = CustodyEvent(
            event_id=self.ev0.event_id,  # Duplicate
            sequence_number=1,
            timestamp="2026-10-20T10:30:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-1",
            actor=self.actor,
            prev_event_hash=self.ev0.record_hash,
        )
        tampered_ledger = CustodyLedger()
        tampered_ledger._events = [self.ev0, dup_ev1]

        res = tampered_ledger.validate_chain()
        self.assertFalse(res.is_valid)
        self.assertEqual(res.integrity_status, "TAMPERED")
        self.assertTrue(any("Duplicate event_id detected" in d for d in res.discrepancies))

    def test_validation_is_strictly_read_only(self):
        """validate_chain() does not mutate stored events."""
        evs_before = self.ledger.events
        self.ledger.validate_chain()
        self.assertEqual(self.ledger.events, evs_before)


class TestCustodyLedgerReportSummaryBridge(unittest.TestCase):
    """Test get_custody_summary() integration with CustodySummary model."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Examiner")

    def test_empty_ledger_summary(self):
        """Empty ledger returns UNVERIFIED CustodySummary."""
        ledger = CustodyLedger(ledger_id="COCLEDGER-00000000-0000-4000-8000-000000000010")
        summary = ledger.get_custody_summary()

        self.assertIsInstance(summary, CustodySummary)
        self.assertEqual(summary.ledger_id, ledger.ledger_id)
        self.assertEqual(summary.total_events, 0)
        self.assertEqual(summary.terminal_hash, GENESIS_PREV_HASH)
        self.assertEqual(summary.chain_integrity, "UNVERIFIED")

    def test_valid_ledger_summary(self):
        """Valid populated ledger returns VERIFIED CustodySummary."""
        ledger = CustodyLedger()
        ev = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
        )
        summary = ledger.get_custody_summary()

        self.assertIsInstance(summary, CustodySummary)
        self.assertEqual(summary.total_events, 1)
        self.assertEqual(summary.terminal_hash, ev.record_hash)
        self.assertEqual(summary.chain_integrity, "VERIFIED")

    def test_tampered_ledger_summary(self):
        """Tampered ledger returns TAMPERED CustodySummary."""
        ledger = CustodyLedger()
        ev0 = ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
        )
        broken_ev1 = CustodyEvent(
            event_id=generate_custody_event_id(),
            sequence_number=1,
            timestamp="2026-10-20T10:30:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-1",
            actor=self.actor,
            prev_event_hash="0" * 63 + "1",
        )
        ledger._events.append(broken_ev1)

        summary = ledger.get_custody_summary()
        self.assertEqual(summary.chain_integrity, "TAMPERED")


class TestCustodyLedgerPersistenceAndSafety(unittest.TestCase):
    """Test file persistence, atomic writes, overwrite policy, and evidence separation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Isolated mock evidence root
        self.evidence_dir = self.base_dir / "evidence_root"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_file = self.evidence_dir / "target.img"
        self.evidence_file.write_bytes(b"Evidence bytes 12345")
        self.evidence_mtime = self.evidence_file.stat().st_mtime_ns
        self.evidence_bytes = self.evidence_file.read_bytes()

        self.actor = CustodyActor(declared_identity="Examiner")
        self.ledger = CustodyLedger(case_id="CASE-PERSIST")
        self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_to_file_creates_file_and_directories(self):
        """save_to_file creates target file and parent directories."""
        dest = self.base_dir / "reports" / "custody" / "ledger.json"
        saved_path = self.ledger.save_to_file(dest)

        self.assertTrue(saved_path.exists())
        self.assertTrue(saved_path.is_file())

    def test_save_to_file_rejects_existing_file_when_overwrite_false(self):
        """save_to_file raises FileExistsError if file exists and overwrite=False."""
        dest = self.base_dir / "existing_ledger.json"
        dest.write_text("existing content")

        with self.assertRaises(FileExistsError) as ctx:
            self.ledger.save_to_file(dest, overwrite=False)
        self.assertIn("already exists", str(ctx.exception))
        # Content remains untouched
        self.assertEqual(dest.read_text(), "existing content")

    def test_save_to_file_replaces_file_when_overwrite_true(self):
        """save_to_file replaces existing file atomically when overwrite=True."""
        dest = self.base_dir / "existing_ledger.json"
        dest.write_text("existing content")

        self.ledger.save_to_file(dest, overwrite=True)
        self.assertNotEqual(dest.read_text(), "existing content")

        loaded = CustodyLedger.load_from_file(dest)
        self.assertEqual(loaded.ledger_id, self.ledger.ledger_id)

    def test_save_to_file_rejects_directory_destination(self):
        """save_to_file raises IsADirectoryError if path is an existing directory."""
        dest_dir = self.base_dir / "a_directory"
        dest_dir.mkdir(parents=True, exist_ok=True)

        with self.assertRaises(IsADirectoryError):
            self.ledger.save_to_file(dest_dir)

    def test_evidence_root_collision_rejections(self):
        """save_to_file rejects overwriting evidence root or writing inside it."""
        # Collision with root itself
        with self.assertRaises(ValueError) as ctx:
            self.ledger.save_to_file(self.evidence_dir, evidence_root=self.evidence_dir)
        self.assertIn("cannot overwrite evidence root", str(ctx.exception))

        # Writing inside evidence root
        inside_path = self.evidence_dir / "sub" / "ledger.json"
        with self.assertRaises(ValueError) as ctx:
            self.ledger.save_to_file(inside_path, evidence_root=self.evidence_dir)
        self.assertIn("cannot reside within evidence directory", str(ctx.exception))

    def test_evidence_bytes_and_mtime_remain_unchanged(self):
        """Evidence file is never touched during custody persistence operations."""
        dest = self.base_dir / "valid_ledger.json"
        self.ledger.save_to_file(dest, evidence_root=self.evidence_dir)

        # Assert evidence remains 100% unaltered
        self.assertEqual(self.evidence_file.read_bytes(), self.evidence_bytes)
        self.assertEqual(self.evidence_file.stat().st_mtime_ns, self.evidence_mtime)

    def test_load_from_file_round_trip(self):
        """load_from_file correctly restores saved ledger."""
        dest = self.base_dir / "test_roundtrip.json"
        self.ledger.save_to_file(dest)

        loaded = CustodyLedger.load_from_file(dest)
        self.assertEqual(loaded.ledger_id, self.ledger.ledger_id)
        self.assertEqual(loaded.terminal_hash, self.ledger.terminal_hash)
        self.assertEqual(loaded.ledger_digest, self.ledger.ledger_digest)
        self.assertEqual(len(loaded), len(self.ledger))


class TestCustodyLedgerVerifySerialized(unittest.TestCase):
    """Test verify_serialized_ledger() without unhandled exceptions."""

    def setUp(self):
        self.actor = CustodyActor(declared_identity="Examiner")
        self.ledger = CustodyLedger()
        self.ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-1",
            actor=self.actor,
        )

    def test_verify_valid_dict(self):
        """verify_serialized_ledger returns VERIFIED on valid dict."""
        res = CustodyLedger.verify_serialized_ledger(self.ledger.to_dict())
        self.assertTrue(res.is_valid)
        self.assertEqual(res.integrity_status, "VERIFIED")

    def test_verify_tampered_event_hash(self):
        """verify_serialized_ledger returns TAMPERED on mismatched event hash."""
        data = self.ledger.to_dict()
        data["events"][0]["record_hash"] = "0" * 64
        res = CustodyLedger.verify_serialized_ledger(data)

        self.assertFalse(res.is_valid)
        self.assertEqual(res.integrity_status, "TAMPERED")
        self.assertTrue(any("Deserialization integrity failure" in d for d in res.discrepancies))

    def test_verify_missing_file(self):
        """verify_serialized_ledger returns TAMPERED on non-existent path."""
        res = CustodyLedger.verify_serialized_ledger(Path("/tmp/nonexistent_xyz_123.json"))
        self.assertFalse(res.is_valid)
        self.assertEqual(res.integrity_status, "TAMPERED")
        self.assertTrue(any("does not exist" in d for d in res.discrepancies))


if __name__ == "__main__":
    unittest.main()
