"""
Unit and integration tests for Filesystem Artifact Scanner (scanner.py).
"""

import os
from pathlib import Path
import tempfile
import unittest

from forensix.artifacts import ArtifactCategory, ArtifactStatus, ArtifactType
from forensix.hasher import compute_hashes
from forensix.scanner import scan_evidence_directory


class TestArtifactScanner(unittest.TestCase):
    """Test suite for evidence directory traversal, artifact extraction, and safety."""

    def setUp(self):
        """Create a temporary workspace for isolated evidence trees."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_dir = Path(self.temp_dir.name) / "linux_evidence"
        self.evidence_dir.mkdir()

    def tearDown(self):
        """Clean up temporary directory and restore permissions if modified."""
        # Ensure any read-only/chmod 000 files can be removed
        for root, dirs, files in os.walk(self.temp_dir.name):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o755)
                except OSError:
                    pass
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o644)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_valid_evidence_directory_scanning(self):
        """1. Verify standard Linux evidence directory is scanned and structured properly."""
        # Create standard layout
        (self.evidence_dir / "etc").mkdir(parents=True)
        (self.evidence_dir / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
        (self.evidence_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")

        (self.evidence_dir / "var" / "log").mkdir(parents=True)
        (self.evidence_dir / "var" / "log" / "auth.log").write_text("Sep 30 10:00:00 sshd: Accepted publickey\n")

        (self.evidence_dir / "home" / "analyst").mkdir(parents=True)
        (self.evidence_dir / "home" / "analyst" / ".bashrc").write_text("export PATH=$PATH:/usr/local/bin\n")

        result = scan_evidence_directory(self.evidence_dir)

        self.assertTrue(result.evidence_id.startswith("EV-"))
        self.assertEqual(result.total_artifacts, 4)
        self.assertEqual(result.known_artifacts, 4)
        self.assertEqual(result.generic_artifacts, 0)
        self.assertEqual(result.unreadable_artifacts, 0)

        rel_paths = [a.relative_path for a in result.artifacts]
        self.assertIn("etc/passwd", rel_paths)
        self.assertIn("etc/hosts", rel_paths)
        self.assertIn("var/log/auth.log", rel_paths)
        self.assertIn("home/analyst/.bashrc", rel_paths)

        # Check passwd item specifically
        passwd_art = next(a for a in result.artifacts if a.relative_path == "etc/passwd")
        self.assertEqual(passwd_art.category, ArtifactCategory.ACCOUNT.value)
        self.assertEqual(passwd_art.artifact_type, ArtifactType.PASSWD.value)
        self.assertTrue(passwd_art.is_known)
        self.assertEqual(passwd_art.status, ArtifactStatus.COLLECTED.value)
        self.assertIsNotNone(passwd_art.md5)
        self.assertIsNotNone(passwd_art.sha256)
        self.assertIsNotNone(passwd_art.permissions)

    def test_empty_evidence_directory(self):
        """2. Verify empty evidence directory returns clean 0-artifact collection."""
        empty_dir = Path(self.temp_dir.name) / "empty_dir"
        empty_dir.mkdir()

        result = scan_evidence_directory(empty_dir)
        self.assertEqual(result.total_artifacts, 0)
        self.assertEqual(result.known_artifacts, 0)
        self.assertEqual(result.generic_artifacts, 0)
        self.assertEqual(result.unreadable_artifacts, 0)
        self.assertEqual(len(result.artifacts), 0)

    def test_nested_directories_handling(self):
        """3. Verify nested directories are fully traversed."""
        deep_file = self.evidence_dir / "level1" / "level2" / "level3" / "data.log"
        deep_file.parent.mkdir(parents=True)
        deep_file.write_text("nested content\n")

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        self.assertEqual(result.artifacts[0].relative_path, "level1/level2/level3/data.log")

    def test_known_vs_unknown_artifact_handling(self):
        """4 & 5. Verify known artifacts are distinguished from unknown generic files."""
        (self.evidence_dir / "etc").mkdir(parents=True)
        (self.evidence_dir / "etc" / "group").write_text("root:x:0:\n")

        (self.evidence_dir / "opt" / "myapp").mkdir(parents=True)
        (self.evidence_dir / "opt" / "myapp" / "custom.dat").write_text("binary blob\n")

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 2)
        self.assertEqual(result.known_artifacts, 1)
        self.assertEqual(result.generic_artifacts, 1)

        group_art = next(a for a in result.artifacts if a.relative_path == "etc/group")
        self.assertTrue(group_art.is_known)
        self.assertEqual(group_art.category, ArtifactCategory.ACCOUNT.value)

        custom_art = next(a for a in result.artifacts if a.relative_path == "opt/myapp/custom.dat")
        self.assertFalse(custom_art.is_known)
        self.assertEqual(custom_art.category, ArtifactCategory.GENERIC.value)
        self.assertEqual(custom_art.artifact_type, ArtifactType.GENERIC_FILE.value)

    def test_missing_directory_raises_file_not_found(self):
        """6. Verify nonexistent evidence directory raises FileNotFoundError."""
        missing = Path(self.temp_dir.name) / "does_not_exist"
        with self.assertRaises(FileNotFoundError):
            scan_evidence_directory(missing)

    def test_file_passed_as_directory_raises_not_a_directory(self):
        """Verify passing a regular file to directory scanner raises NotADirectoryError."""
        regular_file = self.evidence_dir / "some_file.txt"
        regular_file.write_text("hello\n")
        with self.assertRaises(NotADirectoryError):
            scan_evidence_directory(regular_file)

    def test_unreadable_artifact_handling(self):
        """7. Verify unreadable files are recorded with error and do not halt the scan."""
        normal_file = self.evidence_dir / "normal.txt"
        normal_file.write_text("readable\n")

        unreadable_file = self.evidence_dir / "locked.txt"
        unreadable_file.write_text("secret\n")
        # Remove read permissions
        os.chmod(unreadable_file, 0o000)

        # In case test runs as root (Kali root), check if we can simulate unreadable
        if os.access(unreadable_file, os.R_OK):
            # Running as root, chmod 000 is still readable by superuser
            # We can still assert that scan succeeds
            result = scan_evidence_directory(self.evidence_dir)
            self.assertEqual(result.total_artifacts, 2)
        else:
            result = scan_evidence_directory(self.evidence_dir)
            self.assertEqual(result.total_artifacts, 2)
            locked_art = next(a for a in result.artifacts if a.relative_path == "locked.txt")
            self.assertEqual(locked_art.status, ArtifactStatus.PERMISSION_DENIED.value)
            self.assertIsNotNone(locked_art.error)

    def test_zero_byte_artifact_handling(self):
        """8. Verify zero-byte files are cataloged, classified, and hashed accurately."""
        empty_file = self.evidence_dir / "etc" / "empty_conf"
        empty_file.parent.mkdir(parents=True)
        empty_file.touch()

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        art = result.artifacts[0]
        self.assertEqual(art.size, 0)
        self.assertEqual(art.md5, "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(art.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(art.status, ArtifactStatus.COLLECTED.value)

    def test_unicode_filenames_handling(self):
        """9. Verify non-ASCII Unicode filenames and directory structures are handled."""
        unicode_dir = self.evidence_dir / "home" / "utilisateur_测试"
        unicode_dir.mkdir(parents=True)
        unicode_file = unicode_dir / "journal_sécurité_2026.log"
        unicode_file.write_text("Unicode forensic test content\n", encoding="utf-8")

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        self.assertEqual(result.artifacts[0].relative_path, "home/utilisateur_测试/journal_sécurité_2026.log")
        self.assertEqual(result.artifacts[0].status, ArtifactStatus.COLLECTED.value)

    def test_deep_directory_structure(self):
        """10. Verify deep directory trees (10+ levels) are fully scanned."""
        current = self.evidence_dir
        for i in range(12):
            current = current / f"sub_{i}"
        current.mkdir(parents=True)
        leaf_file = current / "deep_artifact.txt"
        leaf_file.write_text("deep\n")

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        self.assertTrue(result.artifacts[0].relative_path.endswith("deep_artifact.txt"))

    def test_broken_symlink_handling(self):
        """Verify broken symlinks are detected without crashing the scan."""
        broken_link = self.evidence_dir / "broken_link.log"
        broken_link.symlink_to(self.evidence_dir / "nonexistent_target.log")

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        art = result.artifacts[0]
        self.assertEqual(art.status, ArtifactStatus.BROKEN_SYMLINK.value)
        self.assertIn("target does not exist", art.error)

    def test_symlink_out_of_bounds_containment(self):
        """Verify symlinks pointing outside evidence directory are blocked and isolated."""
        # Link targeting /etc/passwd or /tmp outside evidence directory
        outside_target = Path(self.temp_dir.name) / "outside_secret.txt"
        outside_target.write_text("external confidential host data\n")

        leak_link = self.evidence_dir / "etc" / "leaked_passwd"
        leak_link.parent.mkdir(parents=True)
        leak_link.symlink_to(outside_target)

        result = scan_evidence_directory(self.evidence_dir)
        self.assertEqual(result.total_artifacts, 1)
        art = result.artifacts[0]
        self.assertEqual(art.status, ArtifactStatus.OUT_OF_BOUNDS_SYMLINK.value)
        self.assertIn("outside evidence directory", art.error)
        self.assertIsNone(art.md5)
        self.assertIsNone(art.sha256)

    def test_deterministic_sorting(self):
        """12. Verify scanner traversal order is deterministic across runs."""
        # Create multiple files in arbitrary order
        (self.evidence_dir / "z_file.txt").write_text("z")
        (self.evidence_dir / "a_file.txt").write_text("a")
        (self.evidence_dir / "m_file.txt").write_text("m")

        res1 = scan_evidence_directory(self.evidence_dir)
        res2 = scan_evidence_directory(self.evidence_dir)

        order1 = [a.relative_path for a in res1.artifacts]
        order2 = [a.relative_path for a in res2.artifacts]

        self.assertEqual(order1, ["a_file.txt", "m_file.txt", "z_file.txt"])
        self.assertEqual(order1, order2)

    def test_evidence_immutability(self):
        """11. Verify scanning does not modify evidence files or metadata."""
        (self.evidence_dir / "etc").mkdir(parents=True)
        target_file = self.evidence_dir / "etc" / "passwd"
        target_file.write_text("root:x:0:0:root:/root:/bin/bash\n")

        pre_stat = target_file.stat()
        pre_hashes = compute_hashes(target_file)

        # Run scanner multiple times
        _ = scan_evidence_directory(self.evidence_dir)
        _ = scan_evidence_directory(self.evidence_dir)

        post_stat = target_file.stat()
        post_hashes = compute_hashes(target_file)

        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(pre_hashes["md5"], post_hashes["md5"])
        self.assertEqual(pre_stat.st_size, post_stat.st_size)
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime)


if __name__ == "__main__":
    unittest.main()
