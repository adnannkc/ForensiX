"""
Unit and integration tests for Linux Account, Group, and Privilege Analysis (V2.4).
"""

import os
from pathlib import Path
import tempfile
import unittest

from forensix.account_analyzer import (
    analyze_account_artifacts,
    parse_authorized_keys_file,
    parse_group_file,
    parse_passwd_file,
    parse_shadow_file,
    parse_sudoers_file,
    parse_sudoers_line,
    resolve_user_group_relationships,
)
from forensix.account_models import (
    AccountCollectionResult,
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.hasher import compute_hashes


class TestAccountAnalyzer(unittest.TestCase):
    """Test suite for /etc/passwd, /etc/group, shadow, sudoers, and SSH key parsing."""

    def setUp(self):
        """Create a temporary workspace for isolated test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_root = Path(self.temp_dir.name) / "linux_evidence"
        self.evidence_root.mkdir()
        (self.evidence_root / "etc").mkdir(parents=True)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_01_to_07_valid_passwd_parsing_and_fields(self):
        """1-7. Verify valid /etc/passwd parsing, multiple users, fields, and UID 0 identification."""
        passwd_content = (
            "# Standard passwd test file\n"
            "root:x:0:0:root superuser:/root:/bin/bash\n"
            "daemon:x:1:1:daemon user:/usr/sbin:/usr/sbin/nologin\n"
            "analyst:x:1000:1000:Forensic Analyst,,,:/home/analyst:/bin/zsh\n"
            "toor:x:0:0:alternative root:/root:/bin/sh\n"
        )
        passwd_file = self.evidence_root / "etc" / "passwd"
        passwd_file.write_text(passwd_content)

        users = parse_passwd_file(passwd_file)
        self.assertEqual(len(users), 4)

        root = next(u for u in users if u.username == "root")
        self.assertTrue(root.user_id.startswith("USER-"))
        self.assertEqual(len(root.user_id.split("-")), 6)  # USER-<UUIDv4>
        self.assertEqual(root.uid, 0)
        self.assertEqual(root.gid, 0)
        self.assertEqual(root.gecos, "root superuser")
        self.assertEqual(root.home_directory, "/root")
        self.assertEqual(root.login_shell, "/bin/bash")
        self.assertTrue(root.is_privileged)
        self.assertEqual(root.line_number, 2)

        analyst = next(u for u in users if u.username == "analyst")
        self.assertEqual(analyst.uid, 1000)
        self.assertEqual(analyst.gid, 1000)
        self.assertEqual(analyst.gecos, "Forensic Analyst,,,")
        self.assertEqual(analyst.home_directory, "/home/analyst")
        self.assertEqual(analyst.login_shell, "/bin/zsh")
        self.assertFalse(analyst.is_privileged)

        # Alternative UID 0 account
        toor = next(u for u in users if u.username == "toor")
        self.assertEqual(toor.uid, 0)
        self.assertTrue(toor.is_privileged)

    def test_08_to_10_valid_group_parsing_and_members(self):
        """8-10. Verify /etc/group parsing, multiple members, and empty group handling."""
        group_content = (
            "root:x:0:\n"
            "sudo:x:27:analyst,admin\n"
            "analyst:x:1000:\n"
            "docker:x:999:analyst\n"
        )
        group_file = self.evidence_root / "etc" / "group"
        group_file.write_text(group_content)

        groups = parse_group_file(group_file)
        self.assertEqual(len(groups), 4)

        root_grp = next(g for g in groups if g.group_name == "root")
        self.assertEqual(root_grp.gid, 0)
        self.assertEqual(root_grp.members, ())

        sudo_grp = next(g for g in groups if g.group_name == "sudo")
        self.assertEqual(sudo_grp.gid, 27)
        self.assertEqual(sudo_grp.members, ("analyst", "admin"))
        self.assertTrue(sudo_grp.group_id.startswith("GRP-"))

    def test_11_user_group_relationship_resolution(self):
        """11. Verify resolution of primary and supplementary groups for each user."""
        passwd_content = (
            "root:x:0:0::/root:/bin/bash\n"
            "analyst:x:1000:1000::/home/analyst:/bin/bash\n"
        )
        group_content = (
            "root:x:0:\n"
            "analyst:x:1000:\n"
            "sudo:x:27:analyst\n"
            "wireshark:x:150:analyst\n"
        )
        passwd_file = self.evidence_root / "etc" / "passwd"
        group_file = self.evidence_root / "etc" / "group"
        passwd_file.write_text(passwd_content)
        group_file.write_text(group_content)

        users = parse_passwd_file(passwd_file)
        groups = parse_group_file(group_file)

        linked_users = resolve_user_group_relationships(users, groups)
        analyst = next(u for u in linked_users if u.username == "analyst")

        self.assertEqual(analyst.primary_group, "analyst")
        self.assertEqual(analyst.supplementary_groups, ("sudo", "wireshark"))

    def test_12_missing_optional_artifacts_handled_gracefully(self):
        """12. Verify analysis succeeds cleanly even when shadow or sudoers are absent."""
        # Only passwd exists
        (self.evidence_root / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")

        result = analyze_account_artifacts(self.evidence_root)
        self.assertEqual(result.total_users, 1)
        self.assertEqual(result.total_groups, 0)
        self.assertEqual(result.total_shadow_records, 0)
        self.assertEqual(result.total_sudo_rules, 0)
        self.assertEqual(result.total_ssh_keys, 0)

    def test_13_and_14_malformed_lines_graceful_skipping(self):
        """13 & 14. Verify malformed lines in passwd and group are skipped without crash."""
        corrupted_passwd = (
            "corrupted line with no colons\n"
            "root:x:0:0::/root:/bin/bash\n"
            "bad_uid:x:not_a_number:100::/home:/bin/sh\n"
            "valid_user:x:1001:1001::/home/valid:/bin/bash\n"
        )
        passwd_file = self.evidence_root / "etc" / "passwd"
        passwd_file.write_text(corrupted_passwd)

        users = parse_passwd_file(passwd_file)
        self.assertEqual(len(users), 2)
        names = [u.username for u in users]
        self.assertIn("root", names)
        self.assertIn("valid_user", names)

        corrupted_group = (
            "corrupted group line\n"
            "bad_gid:x:not_int:user1\n"
            "sudo:x:27:analyst\n"
        )
        group_file = self.evidence_root / "etc" / "group"
        group_file.write_text(corrupted_group)

        groups = parse_group_file(group_file)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].group_name, "sudo")

    def test_15_invalid_utf8_input(self):
        """15. Verify invalid UTF-8 bytes are handled via replacement without exception."""
        raw_passwd = b"root:x:0:0:Superuser \xff\xfe:/root:/bin/bash\n"
        passwd_file = self.evidence_root / "etc" / "passwd"
        passwd_file.write_bytes(raw_passwd)

        users = parse_passwd_file(passwd_file)
        self.assertEqual(len(users), 1)
        self.assertIn("\ufffd", users[0].gecos)

    def test_16_and_17_shadow_parsing_and_credential_protection(self):
        """16 & 17. Verify /etc/shadow metadata extraction with strict password hash protection."""
        shadow_content = (
            "root:$6$salt123$hashhashhash:19000:0:99999:7:::\n"
            "locked_user:!$y$salt456$hashhash:19001:0:99999:7:::\n"
            "empty_user::19002:0:99999:7:::\n"
            "disabled_user:*:19003:0:99999:7:::\n"
        )
        shadow_file = self.evidence_root / "etc" / "shadow"
        shadow_file.write_text(shadow_content)

        shadow_records = parse_shadow_file(shadow_file)
        self.assertEqual(len(shadow_records), 4)

        root = next(s for s in shadow_records if s.username == "root")
        self.assertTrue(root.has_password)
        self.assertFalse(root.is_locked)
        self.assertFalse(root.is_empty)
        self.assertEqual(root.hash_algorithm, "SHA-512 ($6$)")
        self.assertEqual(root.last_changed_days, 19000)
        # CRITICAL: Verify raw hash string is not present in raw_line_redacted
        self.assertNotIn("hashhashhash", root.raw_line_redacted)
        self.assertIn("[REDACTED]", root.raw_line_redacted)

        locked = next(s for s in shadow_records if s.username == "locked_user")
        self.assertTrue(locked.is_locked)
        self.assertEqual(locked.hash_algorithm, "yescrypt ($y$)")

        empty = next(s for s in shadow_records if s.username == "empty_user")
        self.assertTrue(empty.is_empty)
        self.assertFalse(empty.has_password)

    def test_18_sudoers_configuration_handling(self):
        """18. Verify valid sudoers rules are parsed accurately."""
        sudo_content = (
            "# /etc/sudoers\n"
            "root ALL=(ALL:ALL) ALL\n"
            "%sudo ALL=(ALL:ALL) ALL\n"
            "analyst ALL=(ALL) NOPASSWD: /usr/bin/cat, /usr/bin/ls\n"
        )
        sudoers_file = self.evidence_root / "etc" / "sudoers"
        sudoers_file.write_text(sudo_content)

        rules = parse_sudoers_file(sudoers_file)
        self.assertEqual(len(rules), 3)

        root_rule = next(r for r in rules if r.user_spec == "root")
        self.assertTrue(root_rule.is_parsed)
        self.assertEqual(root_rule.host_spec, "ALL")
        self.assertEqual(root_rule.runas_spec, "(ALL:ALL)")
        self.assertEqual(root_rule.commands, ("ALL",))

        analyst_rule = next(r for r in rules if r.user_spec == "analyst")
        self.assertTrue(analyst_rule.is_parsed)
        self.assertIn("NOPASSWD", analyst_rule.options)
        self.assertEqual(analyst_rule.commands, ("/usr/bin/cat", "/usr/bin/ls"))

    def test_19_sudoers_d_directory_handling(self):
        """19. Verify parsing multiple rule files within /etc/sudoers.d/."""
        sudoers_d = self.evidence_root / "etc" / "sudoers.d"
        sudoers_d.mkdir(parents=True)
        (sudoers_d / "01_analyst").write_text("analyst ALL=(ALL) NOPASSWD: ALL\n")
        (sudoers_d / "02_admin").write_text("admin ALL=(ALL:ALL) ALL\n")

        result = analyze_account_artifacts(self.evidence_root)
        self.assertEqual(result.total_sudo_rules, 2)
        specs = [r.user_spec for r in result.sudo_rules]
        self.assertIn("analyst", specs)
        self.assertIn("admin", specs)

    def test_20_unsupported_complex_sudoers_syntax_remains_unparsed(self):
        """20. Verify complex syntax and aliases remain is_parsed=False with user_spec='UNPARSED'."""
        rule_alias = parse_sudoers_line("User_Alias ADMINS = alice, bob", 1, "/etc/sudoers")
        self.assertIsNotNone(rule_alias)
        self.assertFalse(rule_alias.is_parsed)
        self.assertEqual(rule_alias.user_spec, "UNPARSED")
        self.assertIsNone(rule_alias.host_spec)
        self.assertEqual(rule_alias.commands, ())
        self.assertEqual(rule_alias.raw_line, "User_Alias ADMINS = alice, bob")

        rule_cmnd = parse_sudoers_line("Cmnd_Alias DUMP = /usr/bin/tcpdump", 2, "/etc/sudoers")
        self.assertFalse(rule_cmnd.is_parsed)
        self.assertEqual(rule_cmnd.user_spec, "UNPARSED")

        rule_irregular = parse_sudoers_line("some completely invalid sudo grammar = = =", 3, "/etc/sudoers")
        self.assertFalse(rule_irregular.is_parsed)
        self.assertEqual(rule_irregular.user_spec, "UNPARSED")

    def test_21_source_traceability_preservation(self):
        """21. Verify all records preserve source_path, line_number, raw_line, and UUIDs."""
        passwd_file = self.evidence_root / "etc" / "passwd"
        passwd_file.write_text("root:x:0:0::/root:/bin/bash\n")

        result = analyze_account_artifacts(self.evidence_root)
        user = result.users[0]

        self.assertTrue(user.user_id.startswith("USER-"))
        self.assertEqual(user.source_path, str(passwd_file.resolve()))
        self.assertEqual(user.line_number, 1)
        self.assertEqual(user.raw_line, "root:x:0:0::/root:/bin/bash")

    def test_22_ssh_authorized_keys_extraction(self):
        """Verify SSH authorized_keys parsing across user home directories and root."""
        root_ssh = self.evidence_root / "root" / ".ssh"
        root_ssh.mkdir(parents=True)
        (root_ssh / "authorized_keys").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@workstation\n"
        )

        user_ssh = self.evidence_root / "home" / "analyst" / ".ssh"
        user_ssh.mkdir(parents=True)
        (user_ssh / "authorized_keys").write_text(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... analyst@laptop\n"
        )

        result = analyze_account_artifacts(self.evidence_root)
        self.assertEqual(result.total_ssh_keys, 2)

        root_key = next(k for k in result.ssh_keys if k.associated_user == "root")
        self.assertEqual(root_key.key_type, "ssh-ed25519")
        self.assertEqual(root_key.comment, "admin@workstation")

        analyst_key = next(k for k in result.ssh_keys if k.associated_user == "analyst")
        self.assertEqual(analyst_key.key_type, "ssh-rsa")
        self.assertEqual(analyst_key.comment, "analyst@laptop")

    def test_23_evidence_immutability(self):
        """22. Verify account and privilege analysis never modifies evidence files."""
        passwd_file = self.evidence_root / "etc" / "passwd"
        passwd_file.write_text("root:x:0:0::/root:/bin/bash\n")
        group_file = self.evidence_root / "etc" / "group"
        group_file.write_text("root:x:0:\n")

        pre_passwd_hashes = compute_hashes(passwd_file)
        pre_passwd_stat = passwd_file.stat()
        pre_group_hashes = compute_hashes(group_file)

        # Run analysis multiple times
        _ = analyze_account_artifacts(self.evidence_root)
        _ = analyze_account_artifacts(self.evidence_root)

        post_passwd_hashes = compute_hashes(passwd_file)
        post_passwd_stat = passwd_file.stat()
        post_group_hashes = compute_hashes(group_file)

        self.assertEqual(pre_passwd_hashes["sha256"], post_passwd_hashes["sha256"])
        self.assertEqual(pre_group_hashes["sha256"], post_group_hashes["sha256"])
        self.assertEqual(pre_passwd_stat.st_size, post_passwd_stat.st_size)
        self.assertEqual(pre_passwd_stat.st_mtime, post_passwd_stat.st_mtime)

    def test_24_deterministic_output(self):
        """23. Verify identical results across repeated runs."""
        (self.evidence_root / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
        (self.evidence_root / "etc" / "group").write_text("root:x:0:\n")

        res1 = analyze_account_artifacts(self.evidence_root)
        res2 = analyze_account_artifacts(self.evidence_root)

        self.assertEqual(res1.summary, res2.summary)
        self.assertEqual(res1.users[0].username, res2.users[0].username)


if __name__ == "__main__":
    unittest.main()
