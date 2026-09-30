"""
Unit tests for ForensiX unified forensic analysis result structure (Milestone 4).
"""

from dataclasses import FrozenInstanceError
from datetime import datetime
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from forensix.analyzer import (
    FileInfo,
    FileMetadata,
    ForensicAnalysisResult,
    HashResult,
    analyze_evidence,
)
from forensix.evidence import EvidenceRecord


class TestUnifiedResult(unittest.TestCase):
    """Test suite for ForensicAnalysisResult and orchestration."""

    def setUp(self):
        """Create a temporary directory and test evidence file."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

        self.sample_file = self.test_dir_path / "incident_evidence.log"
        self.sample_content = b"2026-09-29T21:00:00Z [AUTH] Failed root login attempt\n"
        self.sample_file.write_bytes(self.sample_content)
        os.chmod(self.sample_file, 0o644)

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_construction_of_unified_result(self):
        """Verify analyze_evidence produces a complete ForensicAnalysisResult."""
        result = analyze_evidence(self.sample_file)

        self.assertIsInstance(result, ForensicAnalysisResult)
        self.assertIsInstance(result.evidence, EvidenceRecord)
        self.assertIsInstance(result.file, FileInfo)
        self.assertIsInstance(result.metadata, FileMetadata)
        self.assertIsInstance(result.hashes, HashResult)

    def test_evidence_section_correctness(self):
        """Verify evidence section fields and values."""
        custom_id = "EV-INCIDENT-2026-0042"
        result = analyze_evidence(self.sample_file, evidence_id=custom_id)

        self.assertEqual(result.evidence.evidence_id, custom_id)
        self.assertEqual(result.evidence.original_path, str(self.sample_file.resolve()))
        # Verify registered_at is valid ISO 8601
        dt = datetime.fromisoformat(result.evidence.registered_at)
        self.assertIsNotNone(dt.tzinfo)

    def test_file_section_correctness(self):
        """Verify file identification section fields."""
        result = analyze_evidence(self.sample_file)

        self.assertEqual(result.file.filename, "incident_evidence.log")
        self.assertEqual(result.file.size, len(self.sample_content))
        self.assertEqual(result.file.extension, ".log")
        self.assertIsNone(result.file.type)
        self.assertEqual(result.file.mime_type, result.file.type)

    def test_metadata_section_correctness(self):
        """Verify metadata permissions and timestamps."""
        result = analyze_evidence(self.sample_file)

        self.assertEqual(result.metadata.permissions, "0644")
        # Ensure modified and accessed are valid ISO 8601
        mod_dt = datetime.fromisoformat(result.metadata.modified)
        acc_dt = datetime.fromisoformat(result.metadata.accessed)
        self.assertIsNotNone(mod_dt.tzinfo)
        self.assertIsNotNone(acc_dt.tzinfo)

        # On standard Linux, created is None
        st = self.sample_file.stat()
        if not hasattr(st, "st_birthtime"):
            self.assertIsNone(result.metadata.created)
        else:
            self.assertIsNotNone(result.metadata.created)

    def test_hashes_section_correctness(self):
        """Verify cryptographic hash values match independent calculation."""
        expected_md5 = hashlib.md5(self.sample_content, usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(self.sample_content).hexdigest()

        result = analyze_evidence(self.sample_file)

        self.assertEqual(result.hashes.md5, expected_md5)
        self.assertEqual(result.hashes.sha256, expected_sha256)

    def test_dictionary_conversion(self):
        """Verify to_dict() returns expected nested dictionary structure."""
        result = analyze_evidence(self.sample_file)
        data = result.to_dict()

        self.assertIsInstance(data, dict)
        self.assertIn("evidence", data)
        self.assertIn("file", data)
        self.assertIn("metadata", data)
        self.assertIn("hashes", data)

        # Check nested keys
        self.assertIn("evidence_id", data["evidence"])
        self.assertIn("original_path", data["evidence"])
        self.assertIn("registered_at", data["evidence"])

        self.assertIn("filename", data["file"])
        self.assertIn("size", data["file"])
        self.assertIn("extension", data["file"])
        self.assertIn("type", data["file"])

        self.assertIn("permissions", data["metadata"])
        self.assertIn("modified", data["metadata"])
        self.assertIn("accessed", data["metadata"])
        self.assertIn("created", data["metadata"])

        self.assertIn("md5", data["hashes"])
        self.assertIn("sha256", data["hashes"])

    def test_immutability(self):
        """Verify that result dataclasses are immutable (frozen)."""
        result = analyze_evidence(self.sample_file)

        with self.assertRaises(FrozenInstanceError):
            result.evidence = "tampered"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            result.file = "tampered"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            result.hashes.sha256 = "tampered"  # type: ignore

    def test_evidence_integrity_during_unified_analysis(self):
        """Verify that running unified analysis does not alter evidence file on disk."""
        initial_stat = self.sample_file.stat()
        initial_hash = hashlib.sha256(self.sample_content).hexdigest()

        _ = analyze_evidence(self.sample_file)

        post_stat = self.sample_file.stat()
        post_content = self.sample_file.read_bytes()
        post_hash = hashlib.sha256(post_content).hexdigest()

        self.assertEqual(initial_hash, post_hash)
        self.assertEqual(initial_stat.st_size, post_stat.st_size)
        self.assertEqual(initial_stat.st_mtime, post_stat.st_mtime)


if __name__ == "__main__":
    unittest.main()
