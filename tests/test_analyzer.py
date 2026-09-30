"""
Unit tests for ForensiX file metadata and identification analyzer (analyzer.py).
"""

from datetime import datetime
import os
from pathlib import Path
import tempfile
import unittest

from forensix.analyzer import (
    analyze_file_metadata,
    extract_file_info,
    extract_metadata,
)
from forensix.hasher import compute_hashes


class TestAnalyzer(unittest.TestCase):
    """Test suite for metadata and file identification in src/forensix/analyzer.py."""

    def setUp(self):
        """Create a temporary directory for test evidence files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

    def tearDown(self):
        """Clean up the temporary directory."""
        self.test_dir.cleanup()

    def test_normal_text_file(self):
        """Test 1: Normal text file metadata and identification."""
        sample = self.test_dir_path / "evidence_log.txt"
        content = b"Forensic log entry sample content\n"
        sample.write_bytes(content)

        result = analyze_file_metadata(sample)

        self.assertEqual(result["file"]["filename"], "evidence_log.txt")
        self.assertEqual(result["file"]["size"], len(content))
        self.assertEqual(result["file"]["extension"], ".txt")
        self.assertEqual(result["file"]["mime_type"], "text/plain")
        self.assertEqual(result["file"]["path"], str(sample.resolve()))

    def test_empty_file(self):
        """Test 2: Empty file size and identification."""
        empty = self.test_dir_path / "empty_evidence.raw"
        empty.write_bytes(b"")

        result = analyze_file_metadata(empty)

        self.assertEqual(result["file"]["filename"], "empty_evidence.raw")
        self.assertEqual(result["file"]["size"], 0)
        self.assertEqual(result["file"]["extension"], ".raw")

    def test_file_with_no_extension(self):
        """Test 3: File with no extension."""
        no_ext = self.test_dir_path / "artifact_without_ext"
        no_ext.write_bytes(b"some binary payload")

        result = analyze_file_metadata(no_ext)

        self.assertEqual(result["file"]["filename"], "artifact_without_ext")
        self.assertEqual(result["file"]["extension"], "")
        self.assertIsNone(result["file"]["mime_type"])

    def test_hidden_file(self):
        """Test 4: Hidden file (leading dot)."""
        hidden = self.test_dir_path / ".config"
        hidden.write_bytes(b"hidden configuration data")

        result = analyze_file_metadata(hidden)

        self.assertEqual(result["file"]["filename"], ".config")
        # In pathlib, .config has stem '.config' and empty suffix ''
        self.assertEqual(result["file"]["extension"], "")

    def test_multiple_suffixes(self):
        """Test 5: File with multiple suffixes (e.g. archive.tar.gz)."""
        tar_gz = self.test_dir_path / "evidence_backup.tar.gz"
        tar_gz.write_bytes(b"dummy archive data")

        result = analyze_file_metadata(tar_gz)

        self.assertEqual(result["file"]["filename"], "evidence_backup.tar.gz")
        self.assertEqual(result["file"]["extension"], ".gz")
        # Python mimetypes module guesses 'application/x-tar' for .tar.gz
        self.assertEqual(result["file"]["mime_type"], "application/x-tar")

    def test_metadata_extraction(self):
        """Test 6: Structure and presence of metadata fields."""
        sample = self.test_dir_path / "metadata_test.bin"
        sample.write_bytes(b"forensic analysis test")

        metadata = extract_metadata(sample)

        self.assertIn("permissions", metadata)
        self.assertIn("modified", metadata)
        self.assertIn("accessed", metadata)
        self.assertIn("created", metadata)

    def test_permission_extraction(self):
        """Test 7: Permission extraction matches expected octal format."""
        sample = self.test_dir_path / "perm_test.bin"
        sample.write_bytes(b"test permissions")
        # Set explicitly to 0644 (rw-r--r--)
        os.chmod(sample, 0o644)

        metadata = extract_metadata(sample)
        self.assertEqual(metadata["permissions"], "0644")

        # Set explicitly to 0755 (rwxr-xr-x)
        os.chmod(sample, 0o755)
        metadata = extract_metadata(sample)
        self.assertEqual(metadata["permissions"], "0755")

    def test_timestamp_extraction(self):
        """Test 8: Timestamps are valid ISO 8601 strings in UTC."""
        sample = self.test_dir_path / "timestamp_test.txt"
        sample.write_bytes(b"timestamp check")

        metadata = extract_metadata(sample)

        # Parse ISO 8601 to ensure proper format
        mod_dt = datetime.fromisoformat(metadata["modified"])
        acc_dt = datetime.fromisoformat(metadata["accessed"])

        self.assertIsNotNone(mod_dt.tzinfo)
        self.assertIsNotNone(acc_dt.tzinfo)

    def test_birthtime_behavior_when_unavailable(self):
        """Test 9: Creation/birth time returns None when not provided by OS/fs."""
        sample = self.test_dir_path / "birthtime_test.txt"
        sample.write_bytes(b"birthtime check")

        st = sample.stat()
        metadata = extract_metadata(sample)

        if not hasattr(st, "st_birthtime"):
            self.assertIsNone(metadata["created"])
        else:
            self.assertIsNotNone(metadata["created"])

    def test_metadata_collection_does_not_modify_evidence(self):
        """Test 10: Verify metadata collection does not modify file content, size, or mtime."""
        sample = self.test_dir_path / "immutable_evidence.bin"
        original_bytes = b"Evidence bitstream integrity verification payload"
        sample.write_bytes(original_bytes)

        initial_hash = compute_hashes(sample)
        initial_stat = sample.stat()

        # Run metadata analysis
        _ = analyze_file_metadata(sample)

        post_hash = compute_hashes(sample)
        post_stat = sample.stat()

        # Content integrity verified via hashes
        self.assertEqual(initial_hash["sha256"], post_hash["sha256"])
        self.assertEqual(initial_hash["md5"], post_hash["md5"])

        # Filesystem attributes untouched
        self.assertEqual(initial_stat.st_size, post_stat.st_size)
        self.assertEqual(initial_stat.st_mtime, post_stat.st_mtime)
        self.assertEqual(initial_stat.st_mode, post_stat.st_mode)

    def test_error_handling_missing_and_directory(self):
        """Verify error handling for missing paths and directories."""
        missing = self.test_dir_path / "nonexistent.file"
        with self.assertRaises(FileNotFoundError):
            analyze_file_metadata(missing)

        sub_dir = self.test_dir_path / "sub_folder"
        sub_dir.mkdir()
        with self.assertRaises(IsADirectoryError):
            analyze_file_metadata(sub_dir)


if __name__ == "__main__":
    unittest.main()
