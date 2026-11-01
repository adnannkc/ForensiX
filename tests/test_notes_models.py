"""
Unit tests for investigator notes domain models (forensix.notes_models).
"""

import re
import unittest
import uuid

from forensix.notes_models import (
    InvestigatorNote,
    NotesDocument,
    is_valid_note_id,
    validate_target,
)


class TestNotesModels(unittest.TestCase):
    """Test suite for InvestigatorNote and NotesDocument."""

    def test_note_id_is_uuid4_prefixed(self):
        """note_id matches canonical NOTE-<UUIDv4> format."""
        note = InvestigatorNote(
            author="Examiner A",
            target="case",
            text="Initial case review started.",
        )
        self.assertTrue(note.note_id.startswith("NOTE-"))
        raw_uuid = note.note_id[5:]
        parsed = uuid.UUID(raw_uuid)
        self.assertEqual(parsed.version, 4)
        self.assertTrue(is_valid_note_id(note.note_id))

        # Rejects malformed IDs
        self.assertFalse(is_valid_note_id("NOTE-not-a-uuid"))
        self.assertFalse(is_valid_note_id("INVALID-12345678-1234-4234-8234-123456789abc"))
        self.assertFalse(is_valid_note_id(None))

    def test_created_at_is_utc_iso8601(self):
        """created_at strictly ends in Z or +00:00."""
        note = InvestigatorNote(
            author="Examiner A",
            target="case",
            text="Checking timestamps.",
        )
        self.assertTrue(
            note.created_at.endswith("Z") or note.created_at.endswith("+00:00"),
            f"Expected UTC timestamp ending in Z or +00:00, got {note.created_at}",
        )

    def test_author_required_and_bounded(self):
        """Empty author rejected; author over 128 characters rejected."""
        # Empty or whitespace
        with self.assertRaises(ValueError):
            InvestigatorNote(author="", target="case", text="Some notes")
        with self.assertRaises(ValueError):
            InvestigatorNote(author="   ", target="case", text="Some notes")

        # Over 128 characters
        long_author = "A" * 129
        with self.assertRaises(ValueError):
            InvestigatorNote(author=long_author, target="case", text="Some notes")

        # 128 characters is valid
        valid_author = "A" * 128
        note = InvestigatorNote(author=valid_author, target="case", text="Some notes")
        self.assertEqual(note.author, valid_author)

    def test_text_bounded(self):
        """Text over 2000 characters rejected; valid text bounded."""
        long_text = "T" * 2001
        with self.assertRaises(ValueError):
            InvestigatorNote(author="Examiner A", target="case", text=long_text)

        # Empty text rejected
        with self.assertRaises(ValueError):
            InvestigatorNote(author="Examiner A", target="case", text="")
        with self.assertRaises(ValueError):
            InvestigatorNote(author="Examiner A", target="case", text="   ")

        # 2000 characters is accepted
        exact_text = "T" * 2000
        note = InvestigatorNote(author="Examiner A", target="case", text=exact_text)
        self.assertEqual(len(note.text), 2000)

    def test_target_accepts_only_three_forms(self):
        """'case', 'evidence:<name>', 'finding:<rule_name>' accepted; others rejected."""
        # Valid forms
        n1 = InvestigatorNote(author="Examiner", target="case", text="General case note")
        self.assertEqual(n1.target, "case")

        n2 = InvestigatorNote(
            author="Examiner", target="evidence:traffic_incident.pcap", text="Capture note"
        )
        self.assertEqual(n2.target, "evidence:traffic_incident.pcap")

        n3 = InvestigatorNote(
            author="Examiner", target="finding:ANOMALOUS_FAILED_LOGINS", text="Finding review"
        )
        self.assertEqual(n3.target, "finding:ANOMALOUS_FAILED_LOGINS")

        # Invalid forms
        invalid_targets = [
            "",
            "   ",
            "report",
            "evidence:",
            "finding:",
            "evidence:   ",
            "finding:   ",
            "verdict:compromised",
            "suspect:user1",
            "case:123",
            "anything_else",
        ]
        for inv in invalid_targets:
            with self.subTest(target=inv):
                with self.assertRaises(ValueError):
                    InvestigatorNote(author="Examiner", target=inv, text="Testing invalid target")

    def test_no_verdict_field_allowed(self):
        """A note dict containing any key outside allowed set is rejected."""
        valid_dict = {
            "note_id": f"NOTE-{uuid.uuid4()}",
            "created_at": "2026-11-01T16:00:00.000000+00:00",
            "author": "Examiner A",
            "target": "case",
            "text": "Valid note text",
        }
        # Allowed dict works
        note = InvestigatorNote.from_dict(valid_dict)
        self.assertEqual(note.author, "Examiner A")

        # Extraneous fields (such as verdict, guilt, severity) strictly rejected
        forbidden_keys = [
            "verdict",
            "conclusion",
            "guilt",
            "innocence",
            "severity",
            "status",
            "confidence",
        ]
        for key in forbidden_keys:
            bad_dict = dict(valid_dict)
            bad_dict[key] = "compromised"
            with self.subTest(forbidden_key=key):
                with self.assertRaises(ValueError):
                    InvestigatorNote.from_dict(bad_dict)


if __name__ == "__main__":
    unittest.main()
