"""
Unit tests for ForensiX Artifact Identifier (identifier.py).
"""

from pathlib import Path, PurePosixPath
import unittest

from forensix.artifacts import ArtifactCategory, ArtifactType
from forensix.identifier import identify_artifact, normalize_relative_path


class TestArtifactIdentifier(unittest.TestCase):
    """Test suite for path normalization and artifact classification rules."""

    def test_path_normalization(self):
        """Verify various path formats normalize to clean relative POSIX paths."""
        self.assertEqual(normalize_relative_path("etc/passwd"), "etc/passwd")
        self.assertEqual(normalize_relative_path("/etc/passwd"), "etc/passwd")
        self.assertEqual(normalize_relative_path("./etc/passwd"), "etc/passwd")
        self.assertEqual(normalize_relative_path("etc\\passwd"), "etc/passwd")
        self.assertEqual(normalize_relative_path(Path("var/log/auth.log")), "var/log/auth.log")
        self.assertEqual(normalize_relative_path(PurePosixPath("/var/log/auth.log")), "var/log/auth.log")

    def test_account_artifacts_identification(self):
        """Verify account artifacts are correctly identified."""
        cat, atype, known = identify_artifact("etc/passwd")
        self.assertEqual(cat, ArtifactCategory.ACCOUNT)
        self.assertEqual(atype, ArtifactType.PASSWD)
        self.assertTrue(known)

        cat, atype, known = identify_artifact("etc/group")
        self.assertEqual(cat, ArtifactCategory.ACCOUNT)
        self.assertEqual(atype, ArtifactType.GROUP)
        self.assertTrue(known)

        cat, atype, known = identify_artifact("etc/shadow")
        self.assertEqual(cat, ArtifactCategory.ACCOUNT)
        self.assertEqual(atype, ArtifactType.SHADOW)
        self.assertTrue(known)

    def test_host_config_artifacts_identification(self):
        """Verify host configuration artifacts are identified."""
        test_cases = [
            ("etc/hosts", ArtifactType.HOSTS),
            ("etc/hostname", ArtifactType.HOSTNAME),
            ("etc/resolv.conf", ArtifactType.RESOLV_CONF),
            ("etc/os-release", ArtifactType.OS_RELEASE),
            ("etc/issue", ArtifactType.ISSUE),
        ]
        for path, expected_type in test_cases:
            with self.subTest(path=path):
                cat, atype, known = identify_artifact(path)
                self.assertEqual(cat, ArtifactCategory.HOST_CONFIG)
                self.assertEqual(atype, expected_type)
                self.assertTrue(known)

    def test_log_artifacts_identification(self):
        """Verify system and auth logs (including rotated logs) are identified."""
        test_cases = [
            ("var/log/auth.log", ArtifactCategory.LOG, ArtifactType.AUTH_LOG),
            ("var/log/auth.log.1", ArtifactCategory.LOG, ArtifactType.AUTH_LOG),
            ("var/log/secure", ArtifactCategory.LOG, ArtifactType.AUTH_LOG),
            ("var/log/syslog", ArtifactCategory.LOG, ArtifactType.SYSLOG),
            ("var/log/syslog.2.gz", ArtifactCategory.LOG, ArtifactType.SYSLOG),
            ("var/log/messages", ArtifactCategory.LOG, ArtifactType.MESSAGES),
        ]
        for path, expected_cat, expected_type in test_cases:
            with self.subTest(path=path):
                cat, atype, known = identify_artifact(path)
                self.assertEqual(cat, expected_cat)
                self.assertEqual(atype, expected_type)
                self.assertTrue(known)

    def test_ssh_artifacts_identification(self):
        """Verify SSH host configurations, keys, and user SSH files."""
        test_cases = [
            ("etc/ssh/sshd_config", ArtifactType.SSH_CONFIG),
            ("etc/ssh/ssh_config", ArtifactType.SSH_CONFIG),
            ("home/analyst/.ssh/authorized_keys", ArtifactType.SSH_AUTHORIZED_KEYS),
            ("root/.ssh/authorized_keys", ArtifactType.SSH_AUTHORIZED_KEYS),
            ("home/analyst/.ssh/known_hosts", ArtifactType.SSH_KNOWN_HOSTS),
            ("home/analyst/.ssh/id_rsa", ArtifactType.SSH_KEY),
            ("root/.ssh/id_ed25519", ArtifactType.SSH_KEY),
            ("home/analyst/.ssh/config", ArtifactType.SSH_CONFIG),
        ]
        for path, expected_type in test_cases:
            with self.subTest(path=path):
                cat, atype, known = identify_artifact(path)
                self.assertEqual(cat, ArtifactCategory.SSH)
                self.assertEqual(atype, expected_type)
                self.assertTrue(known)

    def test_user_fs_artifacts_identification(self):
        """Verify user directory files are categorized as USER_FS."""
        cat, atype, known = identify_artifact("home/analyst/.bashrc")
        self.assertEqual(cat, ArtifactCategory.USER_FS)
        self.assertEqual(atype, ArtifactType.USER_FILE)
        self.assertTrue(known)

        cat, atype, known = identify_artifact("root/.bash_history")
        self.assertEqual(cat, ArtifactCategory.USER_FS)
        self.assertEqual(atype, ArtifactType.USER_FILE)
        self.assertTrue(known)

    def test_generic_fallback_for_unknown_paths(self):
        """Verify unknown or unclassified paths safely fall back to generic filesystem artifacts."""
        unknown_paths = [
            "opt/custom_tool/bin/app",
            "var/data/cache.db",
            "tmp/scratch.txt",
            "usr/local/bin/script.py",
        ]
        for path in unknown_paths:
            with self.subTest(path=path):
                cat, atype, known = identify_artifact(path)
                self.assertEqual(cat, ArtifactCategory.GENERIC)
                self.assertEqual(atype, ArtifactType.GENERIC_FILE)
                self.assertFalse(known)


if __name__ == "__main__":
    unittest.main()
