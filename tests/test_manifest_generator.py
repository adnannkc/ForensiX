"""
Focused tests for ForensiX Manifest Generator Engine (V8.6).

Tests cover:
- ManifestGeneratorConfig validation and immutability.
- NIST/RFC cryptographic hash vectors for empty and known byte sequences.
- Deterministic POSIX entry sorting and nested directory recursion.
- Single-pass bounded streaming and algorithm subsets.
- Read-only preservation of evidence file contents and timestamps.
- Symlink policies: default skipping, in-root resolution, out-of-root escape rejection, broken links, cycle pruning.
- Output containment, no-clobber, atomic overwrite, and temp-file cleanup.
- Full round-trip integration with verify_manifest.
"""

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest

from forensix.manifest_generator import (
    ManifestGeneratorConfig,
    generate_manifest,
    save_manifest,
    _stream_hashes_and_size,
)
from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
)
from forensix.manifest_verifier import (
    ManifestVerificationStatus,
    verify_manifest,
)


class TestManifestGeneratorConfig(unittest.TestCase):
    """Test defensive validation and immutability of ManifestGeneratorConfig."""

    def test_default_config_valid(self):
        cfg = ManifestGeneratorConfig(evidence_directory="/tmp/evidence")
        self.assertEqual(cfg.evidence_directory, "/tmp/evidence")
        self.assertIsNone(cfg.output_path)
        self.assertIsNone(cfg.case_id)
        self.assertIsNone(cfg.investigator)
        self.assertEqual(cfg.algorithms, ("sha256", "md5"))
        self.assertFalse(cfg.allow_symlinks)
        self.assertEqual(cfg.chunk_size, 65536)
        self.assertFalse(cfg.overwrite)

    def test_empty_evidence_directory_raises(self):
        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="")

    def test_algorithms_validation(self):
        with self.assertRaises(TypeError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", algorithms="sha256")  # string not seq

        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", algorithms=[])

        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", algorithms=("sha256", "invalid_algo"))

        # Case normalization and deduplication
        cfg = ManifestGeneratorConfig(
            evidence_directory="/tmp/evidence",
            algorithms=("SHA256", "sha256", "MD5"),
        )
        self.assertEqual(cfg.algorithms, ("sha256", "md5"))

    def test_chunk_size_validation(self):
        with self.assertRaises(TypeError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", chunk_size="65536")
        with self.assertRaises(TypeError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", chunk_size=True)
        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", chunk_size=0)
        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", chunk_size=-100)

    def test_config_whitespace_output_rejection(self):
        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", output_path="   ")
        with self.assertRaises(ValueError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", output_path="")
        with self.assertRaises(TypeError):
            ManifestGeneratorConfig(evidence_directory="/tmp/evidence", output_path=123)

    def test_immutability(self):
        cfg = ManifestGeneratorConfig(evidence_directory="/tmp/evidence")
        with self.assertRaises(FrozenInstanceError):
            cfg.allow_symlinks = True


class TestManifestGeneratorEngine(unittest.TestCase):
    """Test manifest generation, hashing correctness, directory traversal, and safety."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_man_gen_")
        self.test_root = Path(self.temp_dir).resolve()
        self.ev_dir = self.test_root / "evidence"
        self.ev_dir.mkdir(parents=True)
        self.out_dir = self.test_root / "output"
        self.out_dir.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Cryptographic Hash Vectors & Streaming
    # -------------------------------------------------------------------------

    def test_known_byte_vectors_empty_and_text(self):
        """Verify SHA-256 and MD5 against standard RFC/NIST known vectors."""
        # 1. Empty file
        empty_file = self.ev_dir / "empty.txt"
        empty_file.write_bytes(b"")

        # 2. Known string
        known_bytes = b"The quick brown fox jumps over the lazy dog"
        known_file = self.ev_dir / "known.txt"
        known_file.write_bytes(known_bytes)

        manifest = generate_manifest(self.ev_dir)

        entries_by_path = {e.relative_path: e for e in manifest.entries}
        self.assertIn("empty.txt", entries_by_path)
        self.assertIn("known.txt", entries_by_path)

        empty_entry = entries_by_path["empty.txt"]
        self.assertEqual(empty_entry.size_bytes, 0)
        empty_hashes = dict(empty_entry.hashes)
        self.assertEqual(
            empty_hashes["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(
            empty_hashes["md5"],
            "d41d8cd98f00b204e9800998ecf8427e",
        )

        known_entry = entries_by_path["known.txt"]
        self.assertEqual(known_entry.size_bytes, len(known_bytes))
        known_hashes = dict(known_entry.hashes)
        self.assertEqual(
            known_hashes["sha256"],
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        )
        self.assertEqual(
            known_hashes["md5"],
            "9e107d9d372bb6826bd81d3542a419d6",
        )

    def test_bounded_streaming_with_small_chunks(self):
        """Verify that multi-chunk streaming calculates exact digests across chunk boundaries."""
        data = os.urandom(10000)
        test_file = self.ev_dir / "streaming.bin"
        test_file.write_bytes(data)

        expected_sha = hashlib.sha256(data).hexdigest()
        expected_md5 = hashlib.md5(data).hexdigest()

        # Stream with 37-byte chunk size to force odd chunk boundaries
        size, digests = _stream_hashes_and_size(
            test_file,
            algorithms=["sha256", "md5"],
            chunk_size=37,
        )
        self.assertEqual(size, 10000)
        self.assertEqual(digests["sha256"], expected_sha)
        self.assertEqual(digests["md5"], expected_md5)

    def test_configured_algorithm_subsets(self):
        """Verify only configured algorithms are computed and stored."""
        test_file = self.ev_dir / "single_algo.txt"
        test_file.write_bytes(b"forensic evidence bytes")

        # SHA-256 only
        m_sha = generate_manifest(self.ev_dir, algorithms=("sha256",))
        self.assertEqual(len(m_sha.entries), 1)
        self.assertEqual(set(dict(m_sha.entries[0].hashes).keys()), {"sha256"})

        # MD5 only
        m_md5 = generate_manifest(self.ev_dir, algorithms=("md5",))
        self.assertEqual(len(m_md5.entries), 1)
        self.assertEqual(set(dict(m_md5.entries[0].hashes).keys()), {"md5"})

    # -------------------------------------------------------------------------
    # Deterministic Traversal, Nested Directories & Empty Directories
    # -------------------------------------------------------------------------

    def test_nested_files_empty_dirs_and_deterministic_sorting(self):
        """Verify deterministic POSIX sorting, handling of empty dirs, and nested structure."""
        (self.ev_dir / "z_dir").mkdir()
        (self.ev_dir / "empty_dir").mkdir()  # empty dir: should not create entry
        (self.ev_dir / "a_dir" / "sub_dir").mkdir(parents=True)

        (self.ev_dir / "z_dir" / "file_2.txt").write_bytes(b"file 2")
        (self.ev_dir / "root_file.txt").write_bytes(b"root")
        (self.ev_dir / "a_dir" / "sub_dir" / "file_1.txt").write_bytes(b"file 1")

        manifest = generate_manifest(self.ev_dir)

        paths = [e.relative_path for e in manifest.entries]
        expected_order = [
            "a_dir/sub_dir/file_1.txt",
            "root_file.txt",
            "z_dir/file_2.txt",
        ]
        self.assertEqual(paths, expected_order)

        # Ensure POSIX format (no backslashes)
        for p in paths:
            self.assertNotIn("\\", p)
            self.assertFalse(p.startswith("/"))

    # -------------------------------------------------------------------------
    # Evidence Read-Only Behavior & Metadata Immutability
    # -------------------------------------------------------------------------

    def test_evidence_bytes_and_metadata_immutability(self):
        """Verify evidence files are read strictly in binary mode with zero changes to content or timestamps."""
        file_path = self.ev_dir / "immutable.dat"
        file_content = b"Critical forensic evidence bytes"
        file_path.write_bytes(file_content)

        # Set specific permissions and timestamps
        os.chmod(file_path, 0o444)  # Read-only
        st_before = file_path.stat()

        time.sleep(0.05)
        generate_manifest(self.ev_dir)

        st_after = file_path.stat()
        self.assertEqual(file_path.read_bytes(), file_content)
        self.assertEqual(st_before.st_mtime, st_after.st_mtime)
        self.assertEqual(st_before.st_size, st_after.st_size)
        self.assertEqual(st_before.st_mode, st_after.st_mode)

    # -------------------------------------------------------------------------
    # Symlink Policies & Safety
    # -------------------------------------------------------------------------

    def test_symlink_default_skipped(self):
        """By default (allow_symlinks=False), symlinks are ignored and regular files are retained."""
        reg_file = self.ev_dir / "real.txt"
        reg_file.write_bytes(b"real content")

        link_file = self.ev_dir / "link.txt"
        try:
            link_file.symlink_to(reg_file)
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        manifest = generate_manifest(self.ev_dir, allow_symlinks=False)
        paths = [e.relative_path for e in manifest.entries]
        self.assertIn("real.txt", paths)
        self.assertNotIn("link.txt", paths)

    def test_symlink_allowed_in_root_resolution(self):
        """When allow_symlinks=True, symlinks pointing inside root are cataloged."""
        reg_file = self.ev_dir / "real.txt"
        reg_file.write_bytes(b"target content")

        link_file = self.ev_dir / "link.txt"
        try:
            link_file.symlink_to(reg_file)
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        manifest = generate_manifest(self.ev_dir, allow_symlinks=True)
        paths = [e.relative_path for e in manifest.entries]
        self.assertIn("link.txt", paths)
        self.assertIn("real.txt", paths)

    def test_symlink_outside_root_rejected(self):
        """When allow_symlinks=True, symlinks escaping the evidence root raise ValueError."""
        outside_file = self.test_root / "outside.txt"
        outside_file.write_bytes(b"outside target")

        escaping_link = self.ev_dir / "escape.txt"
        try:
            escaping_link.symlink_to(outside_file)
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        with self.assertRaises(ValueError) as ctx:
            generate_manifest(self.ev_dir, allow_symlinks=True)
        self.assertIn("Symlink escape detected", str(ctx.exception))

    def test_broken_symlink_rejected_when_allowed(self):
        """When allow_symlinks=True, broken symlinks raise ValueError."""
        broken_link = self.ev_dir / "broken.txt"
        try:
            broken_link.symlink_to(self.ev_dir / "nonexistent.txt")
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        with self.assertRaises(ValueError) as ctx:
            generate_manifest(self.ev_dir, allow_symlinks=True)
        self.assertIn("Broken symlink detected", str(ctx.exception))

    def test_directory_symlink_loop_cycle_detection(self):
        """When allow_symlinks=True, directory cycles are pruned without infinite recursion."""
        sub_dir = self.ev_dir / "sub"
        sub_dir.mkdir()
        loop_link = sub_dir / "cycle"
        try:
            loop_link.symlink_to(self.ev_dir)
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        reg_file = sub_dir / "regular.txt"
        reg_file.write_bytes(b"data")

        # Must terminate and catalog regular.txt without recursion error
        manifest = generate_manifest(self.ev_dir, allow_symlinks=True)
        paths = [e.relative_path for e in manifest.entries]
        self.assertIn("sub/regular.txt", paths)

    # -------------------------------------------------------------------------
    # Output Containment, No-Clobber, and Atomic Overwrite
    # -------------------------------------------------------------------------

    def test_output_path_inside_evidence_rejected(self):
        """Rejects writing manifest inside evidence directory."""
        bad_out = self.ev_dir / "manifest.json"
        with self.assertRaises(ValueError) as ctx:
            generate_manifest(self.ev_dir, output_path=bad_out)
        self.assertIn("overlaps or resides inside evidence directory", str(ctx.exception))

    def test_output_path_overlapping_evidence_root_rejected(self):
        """Rejects writing manifest to the evidence root itself."""
        with self.assertRaises(ValueError) as ctx:
            generate_manifest(self.ev_dir, output_path=self.ev_dir)
        self.assertIn("overlaps or resides inside evidence directory", str(ctx.exception))

    def test_output_is_directory_rejected(self):
        """Rejects directory target as output path."""
        (self.ev_dir / "test.txt").write_bytes(b"content")
        m = generate_manifest(self.ev_dir)
        with self.assertRaises(IsADirectoryError):
            save_manifest(m, output_path=self.out_dir, overwrite=True)

    def test_preflight_is_directory_rejection(self):
        """Immediately raises IsADirectoryError in generate_manifest if output_path is an existing directory."""
        with self.assertRaises(IsADirectoryError):
            generate_manifest(self.ev_dir, output_path=self.out_dir, overwrite=True)
        with self.assertRaises(IsADirectoryError):
            generate_manifest(self.ev_dir, output_path=self.out_dir, overwrite=False)

    def test_directory_symlink_prune_warning_stderr(self):
        """When allow_symlinks=True, directory symlinks are pruned and emit stderr warning."""
        sub_dir = self.ev_dir / "sub_test"
        sub_dir.mkdir()
        target_dir = self.ev_dir / "target_dir"
        target_dir.mkdir()
        link_dir = sub_dir / "link_to_target"
        try:
            link_dir.symlink_to(target_dir)
        except OSError:
            self.skipTest("Symlinks not supported in environment")

        import io
        import sys
        captured_stderr = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured_stderr
            manifest = generate_manifest(self.ev_dir, allow_symlinks=True)
        finally:
            sys.stderr = old_stderr

        self.assertIn("[WARNING] Directory symlink", captured_stderr.getvalue())
        self.assertIn("pruned from traversal per ForensiX symlink policy", captured_stderr.getvalue())

    def test_no_clobber_when_overwrite_false(self):
        """Refuses to overwrite existing manifest when overwrite=False."""
        out_file = self.out_dir / "manifest.json"
        out_file.write_text("existing content", encoding="utf-8")

        (self.ev_dir / "data.txt").write_bytes(b"evidence")
        with self.assertRaises(FileExistsError):
            generate_manifest(self.ev_dir, output_path=out_file, overwrite=False)

        # Ensure original file was not modified
        self.assertEqual(out_file.read_text(encoding="utf-8"), "existing content")

    def test_atomic_overwrite_and_temp_cleanup(self):
        """Allows atomic replacement when overwrite=True and cleans temp files."""
        out_file = self.out_dir / "manifest.json"
        out_file.write_text("old version", encoding="utf-8")

        (self.ev_dir / "file.txt").write_bytes(b"hello")
        generate_manifest(self.ev_dir, output_path=out_file, overwrite=True)

        # File content updated to valid manifest JSON
        with out_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["manifest_version"], "8.0")
        self.assertEqual(len(data["entries"]), 1)

        # Verify no orphan temp files remain in out_dir
        leftovers = [p.name for p in self.out_dir.iterdir() if p.name.startswith(".tmp.")]
        self.assertEqual(leftovers, [])

    # -------------------------------------------------------------------------
    # Full Verification Round-Trip
    # -------------------------------------------------------------------------

    def test_manifest_generation_and_verification_round_trip(self):
        """Generate a manifest and verify that verify_manifest confirms 100% integrity."""
        (self.ev_dir / "doc1.txt").write_bytes(b"First evidence document")
        (self.ev_dir / "doc2.txt").write_bytes(b"Second evidence document")
        out_manifest = self.out_dir / "baseline_manifest.json"

        manifest = generate_manifest(
            self.ev_dir,
            output_path=out_manifest,
            case_id="CASE-ROUNDTRIP-01",
            investigator="Lead Analyst",
        )

        self.assertEqual(len(manifest.entries), 2)
        self.assertTrue(out_manifest.exists())

        # Verify against generated manifest file
        v_result = verify_manifest(manifest=out_manifest, base_dir=self.ev_dir)
        self.assertTrue(v_result.overall_status)
        self.assertEqual(v_result.total_entries, 2)
        self.assertEqual(v_result.verified_count, 2)
        self.assertEqual(v_result.mismatch_count, 0)
        self.assertEqual(v_result.missing_count, 0)
        self.assertEqual(v_result.error_count, 0)

        # Tamper with an evidence file and verify discrepancy detected
        (self.ev_dir / "doc1.txt").write_bytes(b"Tampered document content")
        tampered_result = verify_manifest(manifest=out_manifest, base_dir=self.ev_dir)
        self.assertFalse(tampered_result.overall_status)
        self.assertEqual(tampered_result.verified_count, 1)
        self.assertEqual(tampered_result.mismatch_count, 1)


if __name__ == "__main__":
    unittest.main()
