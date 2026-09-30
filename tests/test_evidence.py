"""
Unit tests for ForensiX evidence registration module (evidence.py).
"""

from datetime import datetime
from pathlib import Path
import tempfile
import unittest

from forensix.evidence import EvidenceRecord, generate_evidence_id, register_evidence
from forensix.hasher import compute_hashes


class TestEvidence(unittest.TestCase):
    """Test suite for evidence registration in src/forensix/evidence.py."""

    def setUp(self):
        """Create a temporary directory and sample file for testing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)
        self.sample_file = self.test_dir_path / "disk_dump.raw"
        self.sample_content = b"Sample disk sector bitstream for evidence testing"
        self.sample_file.write_bytes(self.sample_content)

    def tearDown(self):
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_successful_evidence_registration(self):
        """Test 1: Successful evidence registration returns EvidenceRecord."""
        record = register_evidence(self.sample_file)
        self.assertIsInstance(record, EvidenceRecord)

        as_dict = record.to_dict()
        self.assertEqual(as_dict["evidence_id"], record.evidence_id)
        self.assertEqual(as_dict["original_path"], record.original_path)
        self.assertEqual(as_dict["registered_at"], record.registered_at)

    def test_evidence_id_is_generated(self):
        """Test 2: Evidence ID starts with 'EV-' and contains valid UUID."""
        record = register_evidence(self.sample_file)
        self.assertTrue(record.evidence_id.startswith("EV-"))
        # Verify length / structure of EV-<UUID4>
        raw_uuid = record.evidence_id.removeprefix("EV-")
        self.assertEqual(len(raw_uuid), 36)

    def test_two_registrations_produce_different_ids(self):
        """Test 3: Consecutive registrations produce distinct unique IDs."""
        record1 = register_evidence(self.sample_file)
        record2 = register_evidence(self.sample_file)
        self.assertNotEqual(record1.evidence_id, record2.evidence_id)

    def test_original_path_is_recorded_correctly(self):
        """Test 4: Original path is recorded as the canonical resolved path."""
        record = register_evidence(self.sample_file)
        self.assertEqual(record.original_path, str(self.sample_file.resolve()))

    def test_registration_timestamp_is_valid_iso8601(self):
        """Test 5: Registration timestamp is a valid timezone-aware ISO 8601 string."""
        record = register_evidence(self.sample_file)
        dt = datetime.fromisoformat(record.registered_at)
        self.assertIsNotNone(dt.tzinfo)

    def test_missing_evidence_path_raises_filenotfounderror(self):
        """Test 6: Missing evidence path produces FileNotFoundError."""
        missing_path = self.test_dir_path / "nonexistent_evidence.img"
        with self.assertRaises(FileNotFoundError):
            register_evidence(missing_path)

    def test_directory_supplied_as_evidence_raises_isadirectoryerror(self):
        """Test 7: Directory path produces IsADirectoryError."""
        sub_dir = self.test_dir_path / "nested_dir"
        sub_dir.mkdir()
        with self.assertRaises(IsADirectoryError):
            register_evidence(sub_dir)

    def test_registration_does_not_modify_evidence(self):
        """Test 8: Verify evidence registration does not modify file contents or metadata."""
        initial_hashes = compute_hashes(self.sample_file)
        initial_stat = self.sample_file.stat()

        record = register_evidence(self.sample_file)

        post_hashes = compute_hashes(self.sample_file)
        post_stat = self.sample_file.stat()

        # Hashes remain identical
        self.assertEqual(initial_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(initial_hashes["md5"], post_hashes["md5"])

        # Size, mtime, and mode remain identical
        self.assertEqual(initial_stat.st_size, post_stat.st_size)
        self.assertEqual(initial_stat.st_mtime, post_stat.st_mtime)
        self.assertEqual(initial_stat.st_mode, post_stat.st_mode)

    def test_custom_evidence_id(self):
        """Test providing a custom evidence ID (e.g., case-assigned tag)."""
        custom_id = "CASE-2026-ITEM-001"
        record = register_evidence(self.sample_file, evidence_id=custom_id)
        self.assertEqual(record.evidence_id, custom_id)


if __name__ == "__main__":
    unittest.main()
