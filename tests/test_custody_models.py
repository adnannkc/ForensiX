"""
Unit tests for ForensiX Chain-of-Custody Data Models (custody_models.py).
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    compute_canonical_event_json,
    compute_canonical_event_payload,
    compute_event_record_hash,
    generate_custody_event_id,
    is_valid_custody_event_id,
)


class TestCustodyModels(unittest.TestCase):
    """Test suite for CustodyActor, CustodyEvent, canonical hashing, and validation."""

    def setUp(self):
        self.sample_actor = CustodyActor(
            declared_identity="Analyst Jane Doe",
            role="Lead Investigator",
            organization="Forensics Incident Response",
            contact_info="jane.doe@example.org",
        )
        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_md5 = "d41d8cd98f00b204e9800998ecf8427e"

    def test_custody_disclaimer_presence(self):
        """Ensure non-empty, explicit evidentiary limitations disclaimer is defined."""
        self.assertIsInstance(CUSTODY_LIMITATIONS_DISCLAIMER, str)
        self.assertIn("Cryptographic hash chaining detects modifications", CUSTODY_LIMITATIONS_DISCLAIMER)
        self.assertIn("does NOT authenticate human actor identity", CUSTODY_LIMITATIONS_DISCLAIMER)

    def test_custody_actor_valid(self):
        """Verify valid CustodyActor construction and immutability."""
        actor = CustodyActor(
            declared_identity=" John Doe ",
            role=" Examiner ",
            organization=None,
            contact_info=" ",
        )
        self.assertEqual(actor.declared_identity, "John Doe")
        self.assertEqual(actor.role, "Examiner")
        self.assertIsNone(actor.organization)
        self.assertIsNone(actor.contact_info)

        with self.assertRaises(FrozenInstanceError):
            actor.declared_identity = "New Identity"

    def test_custody_actor_invalid_identity(self):
        """Verify that empty, whitespace-only, or non-string declared_identity raises."""
        with self.assertRaises(ValueError):
            CustodyActor(declared_identity="")
        with self.assertRaises(ValueError):
            CustodyActor(declared_identity="   ")
        with self.assertRaises(TypeError):
            CustodyActor(declared_identity=123)  # type: ignore

    def test_custody_actor_serialization(self):
        """Verify CustodyActor to_dict conversion."""
        d = self.sample_actor.to_dict()
        self.assertEqual(d["declared_identity"], "Analyst Jane Doe")
        self.assertEqual(d["role"], "Lead Investigator")
        self.assertEqual(d["organization"], "Forensics Incident Response")
        self.assertEqual(d["contact_info"], "jane.doe@example.org")

    def test_generate_and_validate_custody_event_id(self):
        """Verify UUIDv4 format enforcement for COCEVT-<UUIDv4>."""
        eid = generate_custody_event_id()
        self.assertTrue(is_valid_custody_event_id(eid))
        self.assertTrue(eid.startswith("COCEVT-"))
        self.assertEqual(len(eid), 7 + 36)

        # Invalid cases
        self.assertFalse(is_valid_custody_event_id("COCEVT-not-a-uuid"))
        self.assertFalse(is_valid_custody_event_id("INVALID-550e8400-e29b-41d4-a716-446655440000"))
        # UUIDv1 (non-version 4)
        self.assertFalse(is_valid_custody_event_id("COCEVT-550e8400-e29b-11d4-a716-446655440000"))
        # Uppercase
        self.assertFalse(is_valid_custody_event_id(eid.upper()))
        self.assertFalse(is_valid_custody_event_id(123))
        self.assertFalse(is_valid_custody_event_id(None))

    def test_valid_genesis_custody_event(self):
        """Verify genesis event (sequence_number=0) requiring 64-zero prev_event_hash."""
        eid = generate_custody_event_id()
        event = CustodyEvent(
            event_id=eid,
            sequence_number=0,
            timestamp="2026-10-20T08:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            prev_event_hash=GENESIS_PREV_HASH,
            hashes={"sha256": self.sample_sha256, "md5": self.sample_md5},
        )
        self.assertEqual(event.sequence_number, 0)
        self.assertEqual(event.prev_event_hash, GENESIS_PREV_HASH)
        self.assertIsNotNone(event.record_hash)
        self.assertEqual(len(event.record_hash), 64)
        # Confirm hashes are stored as immutable tuple of pairs
        self.assertIsInstance(event.hashes, tuple)

    def test_valid_subsequent_custody_event(self):
        """Verify subsequent event (sequence_number > 0) with valid 64-hex prev_event_hash."""
        eid0 = generate_custody_event_id()
        event0 = CustodyEvent(
            event_id=eid0,
            sequence_number=0,
            timestamp="2026-10-20T08:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            prev_event_hash=GENESIS_PREV_HASH,
        )

        eid1 = generate_custody_event_id()
        event1 = CustodyEvent(
            event_id=eid1,
            sequence_number=1,
            timestamp="2026-10-20T09:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.ANALYSIS_STARTED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            prev_event_hash=event0.record_hash,
        )
        self.assertEqual(event1.sequence_number, 1)
        self.assertEqual(event1.prev_event_hash, event0.record_hash)

    def test_genesis_rejects_nonzero_prev_hash(self):
        """Genesis event must reject any non-zero prev_event_hash."""
        eid = generate_custody_event_id()
        with self.assertRaises(ValueError) as ctx:
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                prev_event_hash=self.sample_sha256,
            )
        self.assertIn("Genesis event (sequence_number=0) must have prev_event_hash", str(ctx.exception))

    def test_nongenesis_rejects_allzero_prev_hash(self):
        """Non-genesis event must reject all-zero prev_event_hash."""
        eid = generate_custody_event_id()
        with self.assertRaises(ValueError) as ctx:
            CustodyEvent(
                event_id=eid,
                sequence_number=1,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.ANALYSIS_STARTED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                prev_event_hash=GENESIS_PREV_HASH,
            )
        self.assertIn("Non-genesis event", str(ctx.exception))
        self.assertIn("cannot have an all-zero prev_event_hash", str(ctx.exception))

    def test_sequence_number_type_and_bounds(self):
        """Verify strict integer validation for sequence_number; reject booleans and negatives."""
        eid = generate_custody_event_id()
        with self.assertRaises(TypeError):
            CustodyEvent(
                event_id=eid,
                sequence_number=True,  # bool is subclass of int
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
            )
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=-1,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
            )

    def test_timestamp_validation(self):
        """Verify ISO-8601 validation; reject invalid dates and time-less strings."""
        eid = generate_custody_event_id()
        # Missing time component rejected
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
            )
        # Empty string rejected
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="   ",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
            )

    def test_hash_pair_lengths_and_validation(self):
        """Verify SHA-256 (64 hex) and MD5 (32 hex) exact lengths and character sets."""
        eid = generate_custody_event_id()
        # SHA-256 too short
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                hashes={"sha256": "abcd"},
            )
        # SHA-256 non-hex
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                hashes={"sha256": "g" * 64},
            )
        # MD5 invalid length
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                hashes={"md5": "a" * 31},
            )
        # Unsupported algorithm
        with self.assertRaises(ValueError):
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                hashes={"sha1": "a" * 40},
            )

    def test_defensive_immutability_caller_mutation(self):
        """Mutating the dictionary or list passed into CustodyEvent must not alter the event."""
        mutable_hashes = {"sha256": self.sample_sha256}
        eid = generate_custody_event_id()
        event = CustodyEvent(
            event_id=eid,
            sequence_number=0,
            timestamp="2026-10-20T08:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            hashes=mutable_hashes,
        )
        # Mutate caller dictionary
        mutable_hashes["sha256"] = "0" * 64
        mutable_hashes["extra"] = "value"
        # Verify event remains unchanged
        self.assertEqual(event.hashes, (("sha256", self.sample_sha256),))

        # Modifying attribute on frozen event raises
        with self.assertRaises(FrozenInstanceError):
            event.sequence_number = 10

    def test_canonical_json_and_record_hash_determinism(self):
        """Verify canonical JSON and SHA-256 hash are 100% deterministic and byte-for-byte reproducible."""
        eid = generate_custody_event_id()
        event = CustodyEvent(
            event_id=eid,
            sequence_number=0,
            timestamp="2026-10-20T08:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            notes="Initial intake note",
            hashes={"sha256": self.sample_sha256, "md5": self.sample_md5},
        )
        json1 = compute_canonical_event_json(event)
        json2 = compute_canonical_event_json(event)
        self.assertEqual(json1, json2)

        # Keys in json string must be sorted
        parsed = json.loads(json1)
        self.assertEqual(list(parsed.keys()), sorted(parsed.keys()))

        hash1 = compute_event_record_hash(event)
        hash2 = compute_event_record_hash(event)
        self.assertEqual(hash1, hash2)
        self.assertEqual(event.record_hash, hash1)

    def test_supplied_record_hash_mismatch_raises(self):
        """Supplying an incorrect record_hash must raise ValueError."""
        eid = generate_custody_event_id()
        with self.assertRaises(ValueError) as ctx:
            CustodyEvent(
                event_id=eid,
                sequence_number=0,
                timestamp="2026-10-20T08:00:00Z",
                timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
                action_type=CustodyActionType.EVIDENCE_REGISTERED,
                evidence_id="EV-12345678",
                actor=self.sample_actor,
                record_hash="f" * 64,  # Incorrect hash
            )
        self.assertIn("does not match computed canonical SHA-256 digest", str(ctx.exception))

    def test_to_dict_round_trip(self):
        """Verify to_dict produces pure JSON-serializable dictionary with expected keys."""
        eid = generate_custody_event_id()
        event = CustodyEvent(
            event_id=eid,
            sequence_number=0,
            timestamp="2026-10-20T08:00:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-12345678",
            actor=self.sample_actor,
            hashes={"sha256": self.sample_sha256},
        )
        d = event.to_dict()
        self.assertEqual(d["event_id"], eid)
        self.assertEqual(d["sequence_number"], 0)
        self.assertEqual(d["hashes"], {"sha256": self.sample_sha256})
        self.assertEqual(d["actor"]["declared_identity"], "Analyst Jane Doe")
        # Ensure json.dumps succeeds without error
        serialized = json.dumps(d)
        self.assertIn(eid, serialized)


if __name__ == "__main__":
    unittest.main()
