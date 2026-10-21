"""
Unit and integration tests for ForensiX Manifest Integrity Verification Engine (manifest_verifier.py).

Covers all mandatory V8.2 requirements:
- Matching SHA-256 and MD5 (single and dual).
- Single and multiple manifest entries.
- Hash mismatch and multi-hash disagreement.
- Missing files.
- Unsupported algorithms (alone and combined with supported ones).
- Path traversal and invalid relative paths.
- Default symlink rejection (targets, parent dirs, broken).
- In-root allowed symlinks and out-of-root / broken symlink rejection.
- Directories and non-regular file targets.
- Permission-denied error handling.
- Empty manifests and overall status semantics.
- Deterministic ordering and count consistency.
- Evidence bytes and mtime immutability.
- Bounded-memory streaming with custom chunk sizes.
- Manifest inputs (ManifestRecord, dict, JSON file) and serialization compatibility.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    ManifestVerificationStatus,
    generate_manifest_id,
)
from forensix.manifest_verifier import (
    MANIFEST_VERIFICATION_NOTICE,
    ManifestEntryVerification,
    ManifestVerificationResult,
    verify_manifest,
)


class TestManifestVerifierBasic(unittest.TestCase):
    """Test standard verification flows with matching digests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Create sample evidence files
        self.file1_rel = "evidence/disk.img"
        self.file1_path = self.base_dir / self.file1_rel
        self.file1_path.parent.mkdir(parents=True, exist_ok=True)
        self.file1_content = b"ForensiX Evidence Data Block 001 - Critical System Log"
        self.file1_path.write_bytes(self.file1_content)
        self.file1_sha256 = hashlib.sha256(self.file1_content).hexdigest()
        self.file1_md5 = hashlib.md5(self.file1_content).hexdigest()

        self.file2_rel = "evidence/memory.dmp"
        self.file2_path = self.base_dir / self.file2_rel
        self.file2_path.parent.mkdir(parents=True, exist_ok=True)
        self.file2_content = b"Volatile memory artifact sample block"
        self.file2_path.write_bytes(self.file2_content)
        self.file2_sha256 = hashlib.sha256(self.file2_content).hexdigest()
        self.file2_md5 = hashlib.md5(self.file2_content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_matching_single_sha256(self):
        """Single manifest entry matching SHA-256."""
        entry = ManifestEntry(
            relative_path=self.file1_rel,
            size_bytes=len(self.file1_content),
            hashes={"sha256": self.file1_sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertTrue(result.overall_status)
        self.assertEqual(result.total_entries, 1)
        self.assertEqual(result.verified_count, 1)
        self.assertEqual(result.mismatch_count, 0)
        self.assertEqual(result.missing_count, 0)
        self.assertEqual(result.error_count, 0)

        ev = result.entry_results[0]
        self.assertEqual(ev.relative_path, self.file1_rel)
        self.assertEqual(ev.status, ManifestVerificationStatus.VERIFIED)
        self.assertTrue(ev.is_verified)
        self.assertEqual(ev.file_size_bytes, len(self.file1_content))
        self.assertIsNone(ev.error_message)

    def test_matching_dual_sha256_and_md5(self):
        """Single entry with both SHA-256 and MD5 matching."""
        entry = ManifestEntry(
            relative_path=self.file1_rel,
            size_bytes=len(self.file1_content),
            hashes={"sha256": self.file1_sha256, "md5": self.file1_md5},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertTrue(result.overall_status)
        self.assertEqual(result.verified_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.VERIFIED)
        self.assertEqual(dict(ev.algorithm_matches), {"md5": True, "sha256": True})

    def test_matching_multiple_entries(self):
        """Multiple manifest entries all matching."""
        entry1 = ManifestEntry(
            relative_path=self.file1_rel,
            size_bytes=len(self.file1_content),
            hashes={"sha256": self.file1_sha256},
        )
        entry2 = ManifestEntry(
            relative_path=self.file2_rel,
            size_bytes=len(self.file2_content),
            hashes={"sha256": self.file2_sha256, "md5": self.file2_md5},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry1, entry2],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertTrue(result.overall_status)
        self.assertEqual(result.total_entries, 2)
        self.assertEqual(result.verified_count, 2)

    def test_evidentiary_notice_present(self):
        """Result contains the mandatory evidentiary limitation notice."""
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        result = verify_manifest(record, base_dir=self.base_dir)
        self.assertEqual(result.evidentiary_notice, MANIFEST_VERIFICATION_NOTICE)
        self.assertIn("Cryptographic verification confirms", result.evidentiary_notice)


class TestManifestVerifierMismatches(unittest.TestCase):
    """Test cryptographic mismatch detection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.file_rel = "logs/auth.log"
        self.file_path = self.base_dir / self.file_rel
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_content = b"Accepted publickey for root from 192.168.1.100"
        self.file_path.write_bytes(self.file_content)
        self.real_sha256 = hashlib.sha256(self.file_content).hexdigest()
        self.real_md5 = hashlib.md5(self.file_content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_single_bit_sha256_mismatch(self):
        """Single-character corruption in recorded digest triggers MISMATCH."""
        corrupted_sha256 = ("0" if self.real_sha256[0] != "0" else "1") + self.real_sha256[1:]
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.file_content),
            hashes={"sha256": corrupted_sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.mismatch_count, 1)
        self.assertEqual(result.verified_count, 0)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.MISMATCH)
        self.assertFalse(ev.is_verified)
        self.assertIn("mismatch", ev.error_message.lower())

    def test_multi_hash_disagreement(self):
        """Multi-hash disagreement: SHA-256 matches but MD5 mismatches -> MISMATCH."""
        corrupted_md5 = "0" * 32
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.file_content),
            hashes={"sha256": self.real_sha256, "md5": corrupted_md5},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.mismatch_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.MISMATCH)
        self.assertEqual(dict(ev.algorithm_matches), {"md5": False, "sha256": True})

    def test_both_hashes_mismatch(self):
        """Both SHA-256 and MD5 mismatch."""
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.file_content),
            hashes={"sha256": "0" * 64, "md5": "0" * 32},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.mismatch_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(dict(ev.algorithm_matches), {"md5": False, "sha256": False})


class TestManifestVerifierMissingAndNonRegular(unittest.TestCase):
    """Test missing files and non-regular target handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_file_classified(self):
        """Missing evidence file produces FILE_MISSING."""
        entry = ManifestEntry(
            relative_path="evidence/absent_drive.dd",
            size_bytes=1024,
            hashes={"sha256": "a" * 64},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.missing_count, 1)
        self.assertEqual(result.entry_results[0].status, ManifestVerificationStatus.FILE_MISSING)
        self.assertIn("not found", result.entry_results[0].error_message.lower())

    def test_directory_target_rejected(self):
        """Directory target in place of a regular evidence file produces PERMISSION_DENIED."""
        dir_rel = "evidence/subfolder"
        (self.base_dir / dir_rel).mkdir(parents=True, exist_ok=True)

        entry = ManifestEntry(
            relative_path=dir_rel,
            size_bytes=4096,
            hashes={"sha256": "b" * 64},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.PERMISSION_DENIED)
        self.assertIn("directory", ev.error_message.lower())

    def test_fifo_pipe_rejected(self):
        """Non-regular FIFO pipe rejected as PERMISSION_DENIED."""
        fifo_rel = "evidence/stream.pipe"
        fifo_path = self.base_dir / fifo_rel
        fifo_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkfifo(fifo_path)
        except (AttributeError, OSError):
            self.skipTest("mkfifo not supported on this platform/filesystem")

        entry = ManifestEntry(
            relative_path=fifo_rel,
            size_bytes=0,
            hashes={"sha256": "c" * 64},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        self.assertEqual(result.entry_results[0].status, ManifestVerificationStatus.PERMISSION_DENIED)


class TestManifestVerifierSymlinks(unittest.TestCase):
    """Test safe symlink containment and rejection policies."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Real evidence file inside root
        self.real_rel = "data/real_file.bin"
        self.real_path = self.base_dir / self.real_rel
        self.real_path.parent.mkdir(parents=True, exist_ok=True)
        self.content = b"Symlink target test payload"
        self.real_path.write_bytes(self.content)
        self.sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_symlink_rejection_target(self):
        """By default (allow_symlinks=False), target symlink is rejected with SYMLINK_REJECTED."""
        link_rel = "links/file_link.bin"
        link_path = self.base_dir / link_rel
        link_path.parent.mkdir(parents=True, exist_ok=True)
        link_path.symlink_to(self.real_path)

        entry = ManifestEntry(
            relative_path=link_rel,
            size_bytes=len(self.content),
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=False)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.SYMLINK_REJECTED)
        self.assertIn("symlink", ev.error_message.lower())

    def test_default_symlink_rejection_parent_dir(self):
        """By default, symlink intermediate directory is rejected with SYMLINK_REJECTED."""
        real_sub = self.base_dir / "real_sub"
        real_sub.mkdir(parents=True, exist_ok=True)
        file_in_sub = real_sub / "artifact.raw"
        file_in_sub.write_bytes(self.content)

        link_dir = self.base_dir / "linked_sub"
        link_dir.symlink_to(real_sub)

        entry = ManifestEntry(
            relative_path="linked_sub/artifact.raw",
            size_bytes=len(self.content),
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=False)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.SYMLINK_REJECTED)

    def test_default_broken_symlink_rejection(self):
        """By default, broken symlinks are rejected with SYMLINK_REJECTED."""
        broken_rel = "links/broken_link.bin"
        broken_path = self.base_dir / broken_rel
        broken_path.parent.mkdir(parents=True, exist_ok=True)
        broken_path.symlink_to(self.base_dir / "nonexistent.raw")

        entry = ManifestEntry(
            relative_path=broken_rel,
            size_bytes=100,
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=False)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.SYMLINK_REJECTED)

    def test_allowed_in_root_symlink(self):
        """When allow_symlinks=True, safe in-root symlinks are verified successfully."""
        link_rel = "links/allowed_file_link.bin"
        link_path = self.base_dir / link_rel
        link_path.parent.mkdir(parents=True, exist_ok=True)
        link_path.symlink_to(self.real_path)

        entry = ManifestEntry(
            relative_path=link_rel,
            size_bytes=len(self.content),
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=True)

        self.assertTrue(result.overall_status)
        self.assertEqual(result.verified_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.VERIFIED)

    def test_allowed_out_of_root_symlink_rejected(self):
        """When allow_symlinks=True, symlink pointing outside base_dir yields PATH_TRAVERSAL_DETECTED."""
        with tempfile.NamedTemporaryFile() as ext_file:
            ext_file.write(b"External file outside evidence root")
            ext_file.flush()

            escape_link = self.base_dir / "links/escape.bin"
            escape_link.parent.mkdir(parents=True, exist_ok=True)
            escape_link.symlink_to(ext_file.name)

            entry = ManifestEntry(
                relative_path="links/escape.bin",
                size_bytes=10,
                hashes={"sha256": "d" * 64},
            )
            record = ManifestRecord(
                manifest_id=generate_manifest_id(),
                manifest_version=MANIFEST_SCHEMA_VERSION,
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[entry],
            )

            result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=True)

            self.assertFalse(result.overall_status)
            self.assertEqual(result.error_count, 1)
            ev = result.entry_results[0]
            self.assertEqual(ev.status, ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED)
            self.assertIn("outside", ev.error_message.lower())

    def test_allowed_broken_symlink_in_root(self):
        """When allow_symlinks=True, broken symlink pointing within root yields FILE_MISSING."""
        broken_rel = "links/broken_in_root.bin"
        broken_path = self.base_dir / broken_rel
        broken_path.parent.mkdir(parents=True, exist_ok=True)
        broken_path.symlink_to(self.base_dir / "data/missing_target.bin")

        entry = ManifestEntry(
            relative_path=broken_rel,
            size_bytes=100,
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=True)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.missing_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.FILE_MISSING)

    def test_allowed_broken_symlink_out_of_root(self):
        """When allow_symlinks=True, broken symlink pointing outside root yields PATH_TRAVERSAL_DETECTED."""
        broken_rel = "links/broken_out.bin"
        broken_path = self.base_dir / broken_rel
        broken_path.parent.mkdir(parents=True, exist_ok=True)
        broken_path.symlink_to(Path("/tmp/external_missing_target_xyz_123.bin"))

        entry = ManifestEntry(
            relative_path=broken_rel,
            size_bytes=100,
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir, allow_symlinks=True)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED)


class TestManifestVerifierSecurityAndContainment(unittest.TestCase):
    """Test containment escape prevention and invalid path classification."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_traversal_path_in_dict_manifest(self):
        """Path traversal '..' in manifest dict is classified as PATH_TRAVERSAL_DETECTED."""
        manifest_dict = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "entries": [
                {
                    "relative_path": "../etc/passwd",
                    "size_bytes": 100,
                    "hashes": {"sha256": "e" * 64},
                }
            ],
        }

        result = verify_manifest(manifest_dict, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED)
        self.assertEqual(ev.relative_path, "../etc/passwd")

    def test_absolute_path_in_dict_manifest(self):
        """Leading '/' in manifest relative path is classified as PATH_TRAVERSAL_DETECTED."""
        manifest_dict = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "entries": [
                {
                    "relative_path": "/var/log/syslog",
                    "size_bytes": 500,
                    "hashes": {"sha256": "f" * 64},
                }
            ],
        }

        result = verify_manifest(manifest_dict, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED)

    def test_backslash_path_in_dict_manifest(self):
        """Backslashes in manifest relative path are classified as PATH_TRAVERSAL_DETECTED."""
        manifest_dict = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "entries": [
                {
                    "relative_path": "evidence\\dump.raw",
                    "size_bytes": 100,
                    "hashes": {"sha256": "0" * 64},
                }
            ],
        }

        result = verify_manifest(manifest_dict, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED)


class TestManifestVerifierAlgorithms(unittest.TestCase):
    """Test hash algorithm compatibility and handling of unsupported algorithms."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.file_rel = "evidence/sample.bin"
        self.file_path = self.base_dir / self.file_rel
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.content = b"Cryptographic algorithm test content"
        self.file_path.write_bytes(self.content)
        self.sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unsupported_algorithm_alone(self):
        """Entry with unsupported algorithm (sha512) is classified as UNSUPPORTED_ALGORITHM."""
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.content),
            hashes={"sha512": "a" * 128},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.UNSUPPORTED_ALGORITHM)
        self.assertIn("unsupported", ev.error_message.lower())

    def test_unsupported_algorithm_combined_with_supported(self):
        """Unsupported algorithm combined with matching SHA-256 is NOT marked VERIFIED."""
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.content),
            hashes={"sha256": self.sha256, "sha512": "b" * 128},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.error_count, 1)
        self.assertEqual(result.verified_count, 0)
        ev = result.entry_results[0]
        self.assertEqual(ev.status, ManifestVerificationStatus.UNSUPPORTED_ALGORITHM)
        self.assertFalse(ev.is_verified)


class TestManifestVerifierPermissionsAndErrors(unittest.TestCase):
    """Test filesystem error handling and permission denial."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unreadable_file_permission_denied(self):
        """Unreadable file (mode 0o000) produces PERMISSION_DENIED without uncaught exception."""
        unreadable_rel = "secret/unreadable.bin"
        unreadable_path = self.base_dir / unreadable_rel
        unreadable_path.parent.mkdir(parents=True, exist_ok=True)
        unreadable_path.write_bytes(b"Classified data block")

        # Strip read permissions
        try:
            os.chmod(unreadable_path, 0o000)
        except OSError:
            self.skipTest("chmod 0o000 not supported in test environment")

        try:
            entry = ManifestEntry(
                relative_path=unreadable_rel,
                size_bytes=21,
                hashes={"sha256": "1" * 64},
            )
            record = ManifestRecord(
                manifest_id=generate_manifest_id(),
                manifest_version=MANIFEST_SCHEMA_VERSION,
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[entry],
            )

            result = verify_manifest(record, base_dir=self.base_dir)

            if os.geteuid() == 0:
                # Root bypasses file permissions on POSIX
                self.assertIn(result.entry_results[0].status, (
                    ManifestVerificationStatus.MISMATCH,
                    ManifestVerificationStatus.PERMISSION_DENIED,
                ))
            else:
                self.assertFalse(result.overall_status)
                self.assertEqual(result.error_count, 1)
                ev = result.entry_results[0]
                self.assertEqual(ev.status, ManifestVerificationStatus.PERMISSION_DENIED)
                self.assertIn("permission", ev.error_message.lower())
        finally:
            # Restore permissions so tearDown cleanup succeeds
            try:
                os.chmod(unreadable_path, 0o644)
            except OSError:
                pass

    def test_base_dir_does_not_exist(self):
        """Non-existent base directory raises FileNotFoundError."""
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        with self.assertRaises(FileNotFoundError):
            verify_manifest(record, base_dir=self.base_dir / "nonexistent_dir_xyz")

    def test_base_dir_not_a_directory(self):
        """File passed as base_dir raises NotADirectoryError."""
        fake_file = self.base_dir / "fake_dir.txt"
        fake_file.write_text("not a directory")
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        with self.assertRaises(NotADirectoryError):
            verify_manifest(record, base_dir=fake_file)

    def test_invalid_chunk_size(self):
        """Invalid non-positive chunk_size raises ValueError."""
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        with self.assertRaises(ValueError):
            verify_manifest(record, base_dir=self.base_dir, chunk_size=0)
        with self.assertRaises(ValueError):
            verify_manifest(record, base_dir=self.base_dir, chunk_size=-1024)


class TestManifestVerifierDeterminismAndState(unittest.TestCase):
    """Test deterministic result behavior, count invariants, and immutability."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Create 3 files
        self.files = {}
        for name in ["zeta.bin", "alpha.bin", "mu.bin"]:
            p = self.base_dir / name
            content = f"Content for {name}".encode("utf-8")
            p.write_bytes(content)
            self.files[name] = {
                "path": p,
                "content": content,
                "sha256": hashlib.sha256(content).hexdigest(),
                "mtime": p.stat().st_mtime_ns,
            }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_manifest_overall_status_false(self):
        """An empty manifest has total_entries=0 and overall_status=False."""
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertFalse(result.overall_status)
        self.assertEqual(result.total_entries, 0)
        self.assertEqual(result.verified_count, 0)
        self.assertEqual(result.mismatch_count, 0)
        self.assertEqual(result.missing_count, 0)
        self.assertEqual(result.error_count, 0)

    def test_deterministic_ordering_of_entries(self):
        """Result entries are deterministically sorted by relative_path regardless of input order."""
        # Provide entries in unordered order: zeta, alpha, mu
        entries = [
            ManifestEntry(
                relative_path="zeta.bin",
                size_bytes=len(self.files["zeta.bin"]["content"]),
                hashes={"sha256": self.files["zeta.bin"]["sha256"]},
            ),
            ManifestEntry(
                relative_path="alpha.bin",
                size_bytes=len(self.files["alpha.bin"]["content"]),
                hashes={"sha256": self.files["alpha.bin"]["sha256"]},
            ),
            ManifestEntry(
                relative_path="mu.bin",
                size_bytes=len(self.files["mu.bin"]["content"]),
                hashes={"sha256": self.files["mu.bin"]["sha256"]},
            ),
        ]
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=entries,
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        returned_paths = [e.relative_path for e in result.entry_results]
        self.assertEqual(returned_paths, ["alpha.bin", "mu.bin", "zeta.bin"])

    def test_count_consistency_invariants(self):
        """Invariant: verified + mismatch + missing + error == total_entries."""
        entries = [
            # 1. Verified
            ManifestEntry(
                relative_path="alpha.bin",
                size_bytes=len(self.files["alpha.bin"]["content"]),
                hashes={"sha256": self.files["alpha.bin"]["sha256"]},
            ),
            # 2. Mismatch
            ManifestEntry(
                relative_path="zeta.bin",
                size_bytes=len(self.files["zeta.bin"]["content"]),
                hashes={"sha256": "0" * 64},
            ),
            # 3. Missing
            ManifestEntry(
                relative_path="nonexistent.bin",
                size_bytes=50,
                hashes={"sha256": "1" * 64},
            ),
            # 4. Error (unsupported algorithm)
            ManifestEntry(
                relative_path="mu.bin",
                size_bytes=len(self.files["mu.bin"]["content"]),
                hashes={"sha512": "2" * 128},
            ),
        ]
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=entries,
        )

        result = verify_manifest(record, base_dir=self.base_dir)

        self.assertEqual(result.total_entries, 4)
        self.assertEqual(result.verified_count, 1)
        self.assertEqual(result.mismatch_count, 1)
        self.assertEqual(result.missing_count, 1)
        self.assertEqual(result.error_count, 1)
        self.assertEqual(
            result.verified_count + result.mismatch_count + result.missing_count + result.error_count,
            result.total_entries,
        )
        self.assertFalse(result.overall_status)

    def test_evidence_bytes_and_mtime_remain_unchanged(self):
        """Strict read-only verification: evidence files are never modified or rewritten."""
        target_path = self.files["alpha.bin"]["path"]
        mtime_before = target_path.stat().st_mtime_ns
        bytes_before = target_path.read_bytes()

        entry = ManifestEntry(
            relative_path="alpha.bin",
            size_bytes=len(bytes_before),
            hashes={"sha256": self.files["alpha.bin"]["sha256"]},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)
        self.assertTrue(result.overall_status)

        mtime_after = target_path.stat().st_mtime_ns
        bytes_after = target_path.read_bytes()

        self.assertEqual(bytes_before, bytes_after)
        self.assertEqual(mtime_before, mtime_after)

    def test_bounded_memory_streaming(self):
        """File larger than chunk_size verified in streaming chunks."""
        large_file = self.base_dir / "large.bin"
        # 128 KB of synthetic pattern data
        chunk_pattern = b"0123456789abcdef" * 64  # 1 KB
        data = chunk_pattern * 128  # 128 KB
        large_file.write_bytes(data)
        expected_sha = hashlib.sha256(data).hexdigest()

        entry = ManifestEntry(
            relative_path="large.bin",
            size_bytes=len(data),
            hashes={"sha256": expected_sha},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        # Run with tiny chunk_size to exercise multi-chunk iteration
        result = verify_manifest(record, base_dir=self.base_dir, chunk_size=2048)
        self.assertTrue(result.overall_status)
        self.assertEqual(result.entry_results[0].file_size_bytes, 128 * 1024)


class TestManifestVerifierInputsAndSerialization(unittest.TestCase):
    """Test polymorphic manifest input ingestion and JSON serialization."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.file_rel = "audit.log"
        self.file_path = self.base_dir / self.file_rel
        self.content = b"Audit event log entry"
        self.file_path.write_bytes(self.content)
        self.sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verify_from_json_file(self):
        """verify_manifest accepts path to valid manifest JSON file."""
        manifest_data = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "entries": [
                {
                    "relative_path": self.file_rel,
                    "size_bytes": len(self.content),
                    "hashes": {"sha256": self.sha256},
                }
            ],
        }
        json_path = self.base_dir / "manifest.json"
        json_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        result = verify_manifest(json_path, base_dir=self.base_dir)
        self.assertTrue(result.overall_status)
        self.assertEqual(result.verified_count, 1)

    def test_verify_from_dict(self):
        """verify_manifest accepts deserialized dict."""
        manifest_dict = {
            "manifest_id": generate_manifest_id(),
            "manifest_version": "8.0",
            "created_at": "2026-10-20T10:00:00Z",
            "forensix_version": "5.0.0",
            "entries": [
                {
                    "relative_path": self.file_rel,
                    "size_bytes": len(self.content),
                    "hashes": {"sha256": self.sha256},
                }
            ],
        }
        result = verify_manifest(manifest_dict, base_dir=self.base_dir)
        self.assertTrue(result.overall_status)

    def test_to_dict_json_serializable(self):
        """Result models serialize to pure JSON-serializable dictionaries."""
        entry = ManifestEntry(
            relative_path=self.file_rel,
            size_bytes=len(self.content),
            hashes={"sha256": self.sha256},
        )
        record = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry],
        )

        result = verify_manifest(record, base_dir=self.base_dir)
        d = result.to_dict()

        serialized = json.dumps(d)
        deserialized = json.loads(serialized)

        self.assertEqual(deserialized["manifest_id"], record.manifest_id)
        self.assertEqual(deserialized["overall_status"], True)
        self.assertEqual(len(deserialized["entry_results"]), 1)
        self.assertEqual(deserialized["entry_results"][0]["status"], "VERIFIED")

    def test_malformed_manifest_json_file(self):
        """Malformed/invalid JSON manifest file raises ValueError."""
        bad_json = self.base_dir / "bad.json"
        bad_json.write_text("{ unclosed json", encoding="utf-8")

        with self.assertRaises(ValueError):
            verify_manifest(bad_json, base_dir=self.base_dir)

    def test_missing_manifest_file(self):
        """Non-existent manifest file path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            verify_manifest(self.base_dir / "nonexistent_manifest.json", base_dir=self.base_dir)

    def test_invalid_manifest_type(self):
        """Passing unsupported type raises TypeError."""
        with self.assertRaises(TypeError):
            verify_manifest(12345, base_dir=self.base_dir)


if __name__ == "__main__":
    unittest.main()
