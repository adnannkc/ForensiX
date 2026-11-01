"""
Unit tests for investigator notes storage and persistence (forensix.notes_storage).
"""

import json
from pathlib import Path
import tempfile
import unittest

from forensix.notes_models import InvestigatorNote, NotesDocument
from forensix.notes_storage import add_note, load_notes, save_notes


class TestNotesStorage(unittest.TestCase):
    """Test suite for loading, saving, and appending notes safely."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.results_dir = self.temp_path / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.temp_path / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_creates_notes_file_outside_evidence(self):
        """The notes file is created safely in the results folder outside evidence."""
        doc = NotesDocument(case_id="CASE-001")
        note = InvestigatorNote(author="Examiner A", target="case", text="Note 1")
        doc.append_note(note)

        saved_path = save_notes(
            doc,
            output_dir=self.results_dir,
            evidence_roots=[self.evidence_dir],
        )

        self.assertTrue(saved_path.exists())
        self.assertEqual(saved_path.name, "notes_CASE-001.json")
        self.assertEqual(saved_path.parent, self.results_dir.resolve())

    def test_save_rejects_path_inside_evidence_root(self):
        """save_notes raises ValueError if the destination resides within or equals an evidence root."""
        doc = NotesDocument(case_id="CASE-001")

        # Attempting to save inside the evidence directory
        with self.assertRaises(ValueError) as ctx:
            save_notes(
                doc,
                output_dir=self.evidence_dir,
                evidence_roots=[self.evidence_dir],
            )
        self.assertIn("evidence", str(ctx.exception).lower())

        # Subdirectory of evidence
        sub_ev = self.evidence_dir / "subdir"
        sub_ev.mkdir()
        with self.assertRaises(ValueError):
            save_notes(
                doc,
                output_dir=sub_ev,
                evidence_roots=[self.evidence_dir],
            )

    def test_add_appends_and_never_replaces(self):
        """Adding note A then note B leaves both present in order."""
        note_a = InvestigatorNote(author="Examiner A", target="case", text="First note")
        note_b = InvestigatorNote(author="Examiner B", target="case", text="Second note")

        path = add_note(
            case_id="CASE-001",
            note=note_a,
            output_dir=self.results_dir,
            evidence_roots=[self.evidence_dir],
        )

        add_note(
            case_id="CASE-001",
            note=note_b,
            output_dir=self.results_dir,
            evidence_roots=[self.evidence_dir],
        )

        reloaded = load_notes(path)
        self.assertEqual(len(reloaded.notes), 2)
        self.assertEqual(reloaded.notes[0].text, "First note")
        self.assertEqual(reloaded.notes[1].text, "Second note")
        self.assertEqual(reloaded.notes[0].note_id, note_a.note_id)
        self.assertEqual(reloaded.notes[1].note_id, note_b.note_id)

    def test_existing_notes_survive_second_add(self):
        """After a second add, the first note representation is byte-identical."""
        note_1 = InvestigatorNote(
            author="Examiner 1",
            target="evidence:capture.pcap",
            text="Initial capture analysis.",
        )
        path = add_note(
            case_id="CASE-001",
            note=note_1,
            output_dir=self.results_dir,
            evidence_roots=[self.evidence_dir],
        )

        raw_first_add = json.loads(path.read_text(encoding="utf-8"))
        first_note_dict = raw_first_add["notes"][0]

        note_2 = InvestigatorNote(
            author="Examiner 2",
            target="finding:ANOMALOUS_LOGINS",
            text="Suspicious activity confirmed.",
        )
        add_note(
            case_id="CASE-001",
            note=note_2,
            output_dir=self.results_dir,
            evidence_roots=[self.evidence_dir],
        )

        raw_second_add = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(raw_second_add["notes"][0], first_note_dict)

    def test_file_is_valid_json_with_schema_version(self):
        """Saved file is valid JSON and contains schema_version '1.0'."""
        doc = NotesDocument(case_id="CASE-XYZ")
        doc.append_note(InvestigatorNote(author="Examiner", target="case", text="Checking schema"))

        saved_path = save_notes(doc, output_dir=self.results_dir)
        with saved_path.open(encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("schema_version"), "1.0")
        self.assertEqual(data.get("case_id"), "CASE-XYZ")
        self.assertIsInstance(data.get("notes"), list)
        self.assertEqual(len(data["notes"]), 1)


if __name__ == "__main__":
    unittest.main()
