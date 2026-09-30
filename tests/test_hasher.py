"""
Unit tests for the ForensiX forensic hashing engine (hasher.py).
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from forensix.hasher import compute_hashes, DEFAULT_CHUNK_SIZE


class TestHasher(unittest.TestCase):
    """Test suite for compute_hashes in src/forensix/hasher.py."""

    def setUp(self):
        """Create a temporary directory for test evidence files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

    def tearDown(self):
        """Clean up the temporary directory."""
        self.test_dir.cleanup()

    def test_known_empty_file_hashes(self):
        """Verify MD5 and SHA-256 for an empty file match standard known test vectors."""
        empty_file = self.test_dir_path / "empty.txt"
        empty_file.write_bytes(b"")

        # Standard known cryptographic test vectors for empty input
        expected_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        result = compute_hashes(empty_file)

        self.assertEqual(result["md5"], expected_md5)
        self.assertEqual(result["sha256"], expected_sha256)

    def test_known_content_hashes(self):
        """Verify MD5 and SHA-256 for known sample text."""
        sample_file = self.test_dir_path / "sample.txt"
        sample_content = b"The quick brown fox jumps over the lazy dog"
        sample_file.write_bytes(sample_content)

        expected_md5 = hashlib.md5(sample_content, usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(sample_content).hexdigest()

        # Known precomputed values:
        # MD5("The quick brown fox jumps over the lazy dog") = 9e107d9d372bb6826bd81d3542a419d6
        # SHA-256("The quick brown fox jumps over the lazy dog") = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
        self.assertEqual(expected_md5, "9e107d9d372bb6826bd81d3542a419d6")
        self.assertEqual(
            expected_sha256,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        )

        result = compute_hashes(sample_file)
        self.assertEqual(result["md5"], "9e107d9d372bb6826bd81d3542a419d6")
        self.assertEqual(
            result["sha256"],
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        )

    def test_chunked_reading_consistency(self):
        """Verify that different chunk sizes produce identical hash results across boundaries."""
        large_file = self.test_dir_path / "large_sample.bin"
        # Generate 150 KB of deterministic binary data (crosses standard 64KB boundary multiple times)
        sample_data = bytes(i % 256 for i in range(150 * 1024))
        large_file.write_bytes(sample_data)

        # Hash with tiny chunk size (512 bytes)
        result_tiny = compute_hashes(large_file, chunk_size=512)
        # Hash with standard chunk size (64 KB)
        result_default = compute_hashes(large_file, chunk_size=DEFAULT_CHUNK_SIZE)
        # Hash with huge chunk size (1 MB)
        result_large = compute_hashes(large_file, chunk_size=1024 * 1024)

        self.assertEqual(result_tiny["md5"], result_default["md5"])
        self.assertEqual(result_tiny["sha256"], result_default["sha256"])
        self.assertEqual(result_default["md5"], result_large["md5"])
        self.assertEqual(result_default["sha256"], result_large["sha256"])

    def test_missing_file_raises_filenotfounderror(self):
        """Verify that passing a nonexistent file raises FileNotFoundError."""
        nonexistent = self.test_dir_path / "does_not_exist.raw"
        with self.assertRaises(FileNotFoundError):
            compute_hashes(nonexistent)

    def test_directory_raises_isadirectoryerror(self):
        """Verify that passing a directory path raises IsADirectoryError."""
        sub_dir = self.test_dir_path / "subdir"
        sub_dir.mkdir()
        with self.assertRaises(IsADirectoryError):
            compute_hashes(sub_dir)

    def test_invalid_chunk_size_raises_valueerror(self):
        """Verify that non-positive chunk sizes raise ValueError."""
        sample_file = self.test_dir_path / "sample.txt"
        sample_file.write_bytes(b"content")

        with self.assertRaises(ValueError):
            compute_hashes(sample_file, chunk_size=0)
        with self.assertRaises(ValueError):
            compute_hashes(sample_file, chunk_size=-1)


if __name__ == "__main__":
    unittest.main()
