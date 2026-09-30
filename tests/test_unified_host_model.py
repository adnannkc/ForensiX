"""
Unit tests for ForensiX Unified Host Artifact Model and Adapters (V2.6).

Verifies:
- Adaptation of all 9 supported specialized V2 models into HostArtifact
- Exact preservation of source IDs, cross-references (EVT, ART), source paths, and line numbers
- No unnecessary duplication of specialized fields into generic structures
- Zero injection of artificial privilege/risk assessments
- Strict enforcement of supported SpecializedPayload types (TypeError on invalid types)
- Deep immutability of HostArtifact and HostArtifactCollection
- Genuinely JSON-serializable to_dict() outputs for every payload type and collection (tested with json.dumps)
- Deterministic artifact and summary ordering
- Pure in-memory adapter operation without filesystem I/O
"""

import json
from pathlib import Path
import unittest

from forensix.account_models import (
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.artifacts import ArtifactRecord
from forensix.auth_models import AuthenticationRecord
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.unified_adapter import (
    artifact_record_to_host_artifact,
    auth_record_to_host_artifact,
    build_host_artifact_collection,
    group_record_to_host_artifact,
    log_event_to_host_artifact,
    persistence_record_to_host_artifact,
    shadow_record_to_host_artifact,
    ssh_key_to_host_artifact,
    sudo_rule_to_host_artifact,
    to_host_artifact,
    user_account_to_host_artifact,
)
from forensix.unified_models import (
    HostArtifact,
    HostArtifactCategory,
    HostArtifactCollection,
    generate_host_artifact_id,
)


class TestUnifiedHostModel(unittest.TestCase):
    """Test suite for V2.6 Unified Host Artifact Model and Adapters."""

    def setUp(self):
        """Create sample specialized records for testing."""
        self.artifact_rec = ArtifactRecord(
            artifact_id="ART-11111111-1111-1111-1111-111111111111",
            relative_path="etc/passwd",
            source_path="/evidence/etc/passwd",
            category="account",
            artifact_type="passwd",
            is_known=True,
            size=1024,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-30T10:00:00Z",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="collected",
        )

        self.log_evt = LogEvent(
            event_id="EVT-22222222-2222-2222-2222-222222222222",
            source_artifact_id="ART-00000000-0000-0000-0000-000000000000",
            source_path="/evidence/var/log/auth.log",
            line_number=42,
            raw_timestamp="Sep 30 10:15:00",
            normalized_timestamp=None,
            hostname="forensic-srv",
            service="sshd",
            pid=1234,
            event_type="ssh_login_success",
            attributes={"user": "analyst", "src_ip": "192.168.1.100"},
            raw_message="Accepted publickey for analyst from 192.168.1.100 port 54321 ssh2",
            raw_line="Sep 30 10:15:00 forensic-srv sshd[1234]: Accepted publickey for analyst from 192.168.1.100 port 54321 ssh2",
        )

        self.auth_rec = AuthenticationRecord(
            auth_id="AUTH-33333333-3333-3333-3333-333333333333",
            event_id="EVT-22222222-2222-2222-2222-222222222222",
            source_artifact_id="ART-00000000-0000-0000-0000-000000000000",
            source_path="/evidence/var/log/auth.log",
            line_number=42,
            raw_timestamp="Sep 30 10:15:00",
            normalized_timestamp=None,
            hostname="forensic-srv",
            service="sshd",
            event_type="ssh_login_success",
            status="SUCCESS",
            username="analyst",
            source_ip="192.168.1.100",
            source_port=54321,
            authentication_method="publickey",
            attributes={"key_type": "ssh-ed25519"},
            raw_message="Accepted publickey for analyst from 192.168.1.100 port 54321 ssh2",
            raw_line="Sep 30 10:15:00 forensic-srv sshd[1234]: Accepted publickey for analyst from 192.168.1.100 port 54321 ssh2",
        )

        self.user_acc = UserAccount(
            user_id="USER-44444444-4444-4444-4444-444444444444",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111111",
            source_path="/evidence/etc/passwd",
            line_number=1,
            username="root",
            uid=0,
            gid=0,
            gecos="root",
            home_directory="/root",
            login_shell="/bin/bash",
            is_privileged=True,
            primary_group="root",
            supplementary_groups=(),
            raw_line="root:x:0:0:root:/root:/bin/bash",
        )

        self.group_rec = GroupRecord(
            group_id="GRP-55555555-5555-5555-5555-555555555555",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111112",
            source_path="/evidence/etc/group",
            line_number=1,
            group_name="sudo",
            gid=27,
            members=("analyst",),
            raw_line="sudo:x:27:analyst",
        )

        self.shadow_rec = ShadowRecord(
            shadow_id="SHAD-66666666-6666-6666-6666-666666666666",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111113",
            source_path="/evidence/etc/shadow",
            line_number=1,
            username="root",
            has_password=True,
            is_locked=False,
            is_empty=False,
            hash_algorithm="sha512",
            last_changed_days=19000,
            raw_line_redacted="root:[REDACTED]:19000:0:99999:7:::",
        )

        self.sudo_rule = SudoRule(
            rule_id="SUDO-77777777-7777-7777-7777-777777777777",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111114",
            source_path="/evidence/etc/sudoers",
            line_number=20,
            is_parsed=True,
            user_spec="%sudo",
            host_spec="ALL",
            runas_spec="ALL:ALL",
            commands=("ALL",),
            options=(),
            raw_line="%sudo ALL=(ALL:ALL) ALL",
        )

        self.ssh_key = SshKeyInfo(
            key_id="SSHKEY-88888888-8888-8888-8888-888888888888",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111115",
            source_path="/evidence/root/.ssh/authorized_keys",
            line_number=1,
            associated_user="root",
            key_type="ssh-ed25519",
            comment="admin@workstation",
            raw_line="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@workstation",
        )

        self.persist_rec = PersistenceRecord(
            persistence_id="PERSIST-99999999-9999-9999-9999-999999999999",
            source_artifact_id="ART-11111111-1111-1111-1111-111111111116",
            source_path="/evidence/etc/crontab",
            line_number=10,
            category="cron",
            mechanism="crontab",
            scope="system",
            target_user="root",
            trigger_or_schedule="0 2 * * *",
            command_or_path="/usr/sbin/backup",
            attributes=(("command", "/usr/sbin/backup"),),
            status="PARSED",
            raw_line="0 2 * * * root /usr/sbin/backup",
        )

    def test_01_artifact_record_adaptation(self):
        """1. Verify ArtifactRecord is correctly adapted into HostArtifact."""
        art = artifact_record_to_host_artifact(self.artifact_rec)
        self.assertTrue(art.unified_id.startswith("HOSTART-"))
        self.assertEqual(art.source_id, self.artifact_rec.artifact_id)
        self.assertIsNone(art.source_event_id)
        self.assertEqual(art.source_artifact_id, self.artifact_rec.artifact_id)
        self.assertEqual(art.category, HostArtifactCategory.FILESYSTEM.value)
        self.assertEqual(art.artifact_type, "passwd")
        self.assertEqual(art.source_path, "/evidence/etc/passwd")
        self.assertIsNone(art.line_number)
        self.assertIsNone(art.raw_data)
        self.assertEqual(art.status, "collected")
        self.assertIs(art.specialized_payload, self.artifact_rec)

    def test_02_log_event_adaptation(self):
        """2. Verify LogEvent is correctly adapted into HostArtifact."""
        art = log_event_to_host_artifact(self.log_evt)
        self.assertTrue(art.unified_id.startswith("HOSTART-"))
        self.assertEqual(art.source_id, self.log_evt.event_id)
        self.assertEqual(art.source_event_id, self.log_evt.event_id)
        self.assertEqual(art.source_artifact_id, self.log_evt.source_artifact_id)
        self.assertEqual(art.category, HostArtifactCategory.LOG.value)
        self.assertEqual(art.artifact_type, "ssh_login_success")
        self.assertEqual(art.source_path, "/evidence/var/log/auth.log")
        self.assertEqual(art.line_number, 42)
        self.assertEqual(art.raw_data, self.log_evt.raw_line)
        self.assertEqual(art.status, "PARSED")
        self.assertIs(art.specialized_payload, self.log_evt)

    def test_03_auth_record_adaptation(self):
        """3. Verify AuthenticationRecord is correctly adapted into HostArtifact."""
        art = auth_record_to_host_artifact(self.auth_rec)
        self.assertTrue(art.unified_id.startswith("HOSTART-"))
        self.assertEqual(art.source_id, self.auth_rec.auth_id)
        self.assertEqual(art.source_event_id, self.auth_rec.event_id)
        self.assertEqual(art.source_artifact_id, self.auth_rec.source_artifact_id)
        self.assertEqual(art.category, HostArtifactCategory.AUTHENTICATION.value)
        self.assertEqual(art.artifact_type, "ssh_login_success")
        self.assertEqual(art.status, "SUCCESS")
        self.assertEqual(art.source_path, "/evidence/var/log/auth.log")
        self.assertEqual(art.line_number, 42)
        self.assertIs(art.specialized_payload, self.auth_rec)

    def test_04_user_account_adaptation(self):
        """4. Verify UserAccount is correctly adapted into HostArtifact."""
        art = user_account_to_host_artifact(self.user_acc)
        self.assertEqual(art.category, HostArtifactCategory.ACCOUNT.value)
        self.assertEqual(art.source_id, self.user_acc.user_id)
        self.assertEqual(art.source_artifact_id, self.user_acc.source_artifact_id)
        self.assertIsNone(art.source_event_id)
        self.assertEqual(art.source_path, "/evidence/etc/passwd")
        self.assertEqual(art.line_number, 1)
        self.assertIs(art.specialized_payload, self.user_acc)

    def test_05_group_record_adaptation(self):
        """5. Verify GroupRecord is correctly adapted into HostArtifact."""
        art = group_record_to_host_artifact(self.group_rec)
        self.assertEqual(art.category, HostArtifactCategory.GROUP.value)
        self.assertEqual(art.source_id, self.group_rec.group_id)
        self.assertEqual(art.source_artifact_id, self.group_rec.source_artifact_id)
        self.assertIsNone(art.source_event_id)
        self.assertEqual(art.source_path, "/evidence/etc/group")
        self.assertEqual(art.line_number, 1)

    def test_06_shadow_record_adaptation(self):
        """6. Verify ShadowRecord is correctly adapted into HostArtifact."""
        art = shadow_record_to_host_artifact(self.shadow_rec)
        self.assertEqual(art.category, HostArtifactCategory.CREDENTIAL_METADATA.value)
        self.assertEqual(art.source_id, self.shadow_rec.shadow_id)
        self.assertEqual(art.source_artifact_id, self.shadow_rec.source_artifact_id)
        self.assertEqual(art.raw_data, self.shadow_rec.raw_line_redacted)

    def test_07_sudo_rule_adaptation(self):
        """7. Verify SudoRule is correctly adapted into HostArtifact."""
        art = sudo_rule_to_host_artifact(self.sudo_rule)
        self.assertEqual(art.category, HostArtifactCategory.PRIVILEGE.value)
        self.assertEqual(art.source_id, self.sudo_rule.rule_id)
        self.assertEqual(art.status, "PARSED")
        self.assertEqual(art.warnings, ())

        # Unparsed sudo rule
        unparsed_rule = SudoRule(
            rule_id="SUDO-00000000-0000-0000-0000-000000000000",
            source_artifact_id=None,
            source_path="/etc/sudoers",
            line_number=5,
            is_parsed=False,
            user_spec="UNPARSED",
            host_spec=None,
            runas_spec=None,
            commands=(),
            options=(),
            raw_line="User_Alias ADMINS = alice, bob",
        )
        art_unparsed = sudo_rule_to_host_artifact(unparsed_rule)
        self.assertEqual(art_unparsed.status, "UNPARSED")
        self.assertTrue(len(art_unparsed.warnings) > 0)

    def test_08_ssh_key_adaptation(self):
        """8. Verify SshKeyInfo is correctly adapted into HostArtifact."""
        art = ssh_key_to_host_artifact(self.ssh_key)
        self.assertEqual(art.category, HostArtifactCategory.SSH_KEY.value)
        self.assertEqual(art.source_id, self.ssh_key.key_id)
        self.assertEqual(art.source_artifact_id, self.ssh_key.source_artifact_id)

    def test_09_persistence_record_adaptation(self):
        """9. Verify PersistenceRecord is correctly adapted into HostArtifact."""
        art = persistence_record_to_host_artifact(self.persist_rec)
        self.assertEqual(art.category, HostArtifactCategory.PERSISTENCE.value)
        self.assertEqual(art.source_id, self.persist_rec.persistence_id)
        self.assertEqual(art.artifact_type, "crontab")
        self.assertEqual(art.status, "PARSED")
        self.assertIs(art.specialized_payload, self.persist_rec)

    def test_10_preservation_of_specialized_identifiers(self):
        """10. Verify specialized IDs (ART-, EVT-, AUTH-, USER-, GRP-, SHAD-, SUDO-, SSHKEY-, PERSIST-) are preserved."""
        for rec, prefix in [
            (self.artifact_rec, "ART-"),
            (self.log_evt, "EVT-"),
            (self.auth_rec, "AUTH-"),
            (self.user_acc, "USER-"),
            (self.group_rec, "GRP-"),
            (self.shadow_rec, "SHAD-"),
            (self.sudo_rule, "SUDO-"),
            (self.ssh_key, "SSHKEY-"),
            (self.persist_rec, "PERSIST-"),
        ]:
            with self.subTest(record_type=type(rec).__name__):
                art = to_host_artifact(rec)
                self.assertTrue(art.source_id.startswith(prefix))

    def test_11_unified_id_generation(self):
        """11. Verify unified_id adheres to HOSTART-<UUIDv4> format and uniqueness."""
        id1 = generate_host_artifact_id()
        id2 = generate_host_artifact_id()
        self.assertTrue(id1.startswith("HOSTART-"))
        self.assertTrue(id2.startswith("HOSTART-"))
        self.assertNotEqual(id1, id2)

    def test_12_cross_references_preservation(self):
        """12. Verify cross-reference chain (AUTH -> EVT -> ART) is preserved."""
        art = to_host_artifact(self.auth_rec)
        self.assertEqual(art.source_id, "AUTH-33333333-3333-3333-3333-333333333333")
        self.assertEqual(art.source_event_id, "EVT-22222222-2222-2222-2222-222222222222")
        self.assertEqual(art.source_artifact_id, "ART-00000000-0000-0000-0000-000000000000")

    def test_13_source_path_exact_preservation(self):
        """13. Verify source paths are preserved verbatim without re-normalization."""
        path_test = "custom/path/with/../segment/./file.conf"
        modified_rec = PersistenceRecord(
            persistence_id="PERSIST-11111111-1111-1111-1111-111111111111",
            source_artifact_id=None,
            source_path=path_test,
            line_number=1,
            category="cron",
            mechanism="crontab",
            scope="system",
            target_user=None,
            trigger_or_schedule=None,
            command_or_path=None,
            attributes=(),
            status="PARSED",
            raw_line=None,
        )
        art = to_host_artifact(modified_rec)
        self.assertEqual(art.source_path, path_test)

    def test_14_no_unnecessary_data_duplication(self):
        """14. Verify common indexable fields exist on HostArtifact and detailed attributes stay in payload."""
        art = to_host_artifact(self.persist_rec)
        # HostArtifact does not have direct cron attributes flattened onto top-level
        self.assertFalse(hasattr(art, "trigger_or_schedule"))
        self.assertFalse(hasattr(art, "command_or_path"))
        # But payload has them cleanly intact
        self.assertEqual(art.specialized_payload.trigger_or_schedule, "0 2 * * *")
        self.assertEqual(art.specialized_payload.command_or_path, "/usr/sbin/backup")

    def test_15_no_new_privilege_or_risk_assessments(self):
        """15. Verify V2.6 does not introduce risk scores or new privilege assessments."""
        art = to_host_artifact(self.user_acc)
        # HostArtifact should not introduce artificial fields like 'risk_score' or 'high_risk'
        self.assertFalse(hasattr(art, "risk_score"))
        self.assertFalse(hasattr(art, "high_risk"))
        self.assertFalse(hasattr(art, "threat_level"))
        d = art.to_dict()
        self.assertNotIn("risk_score", d)
        self.assertNotIn("high_risk", d)

    def test_16_enforcement_of_supported_specialized_payload_types(self):
        """16. Verify unsupported objects passed to to_host_artifact or HostArtifact raise TypeError."""
        with self.assertRaises(TypeError):
            to_host_artifact({"dict": "not_a_model"})  # type: ignore

        with self.assertRaises(TypeError):
            to_host_artifact("string_not_a_model")  # type: ignore

        with self.assertRaises(TypeError):
            HostArtifact(
                unified_id="HOSTART-1",
                source_id="1",
                source_event_id=None,
                source_artifact_id=None,
                category="test",
                artifact_type="test",
                source_path="/test",
                line_number=None,
                raw_data=None,
                specialized_payload=object(),  # type: ignore
                status="TEST",
            )

    def test_17_malformed_and_unparsed_status_preservation(self):
        """17. Verify malformed and unparsed statuses from analyzers are preserved as-is."""
        malformed_persist = PersistenceRecord(
            persistence_id="PERSIST-malformed",
            source_artifact_id=None,
            source_path="/etc/crontab",
            line_number=5,
            category="cron",
            mechanism="crontab",
            scope="system",
            target_user=None,
            trigger_or_schedule=None,
            command_or_path=None,
            attributes=(),
            status="MALFORMED",
            raw_line="bad cron line without schedule",
        )
        art = to_host_artifact(malformed_persist)
        self.assertEqual(art.status, "MALFORMED")

    def test_18_deep_immutability(self):
        """18. Verify deep immutability on HostArtifact and HostArtifactCollection."""
        art = to_host_artifact(self.log_evt)
        # Attempting to reassign an attribute on frozen dataclass
        with self.assertRaises(Exception):
            art.status = "MUTATED"  # type: ignore

        records = [self.log_evt, self.auth_rec]
        col = build_host_artifact_collection("/evidence", records)

        with self.assertRaises(Exception):
            col.total_artifacts = 999  # type: ignore

        self.assertIsInstance(col.artifacts, tuple)
        self.assertIsInstance(col.category_counts, tuple)
        self.assertIsInstance(col.status_counts, tuple)

    def test_19_json_serialization_all_types(self):
        """19. Verify json.dumps(to_dict()) works for every supported payload type and collection."""
        records = [
            self.artifact_rec,
            self.log_evt,
            self.auth_rec,
            self.user_acc,
            self.group_rec,
            self.shadow_rec,
            self.sudo_rule,
            self.ssh_key,
            self.persist_rec,
        ]

        for rec in records:
            with self.subTest(record_type=type(rec).__name__):
                art = to_host_artifact(rec)
                art_dict = art.to_dict()
                # Must serialize to JSON without throwing TypeError
                serialized = json.dumps(art_dict)
                self.assertIsInstance(serialized, str)
                loaded = json.loads(serialized)
                self.assertEqual(loaded["source_id"], art.source_id)
                self.assertEqual(loaded["category"], art.category)

        # Test HostArtifactCollection JSON serialization
        collection = build_host_artifact_collection(
            evidence_root="/evidence",
            records=records,
            collected_at="2026-09-30T12:00:00Z",
        )
        col_dict = collection.to_dict()
        col_json = json.dumps(col_dict)
        self.assertIsInstance(col_json, str)
        col_loaded = json.loads(col_json)
        self.assertEqual(col_loaded["evidence_root"], "/evidence")
        self.assertEqual(col_loaded["summary"]["total_artifacts"], len(records))

    def test_20_deterministic_sorting_and_count_ordering(self):
        """20. Verify deterministic sorting of artifacts and stable ordering of metrics."""
        records = [
            self.persist_rec,
            self.user_acc,
            self.log_evt,
            self.auth_rec,
            self.artifact_rec,
        ]

        col1 = build_host_artifact_collection("/evidence", records, collected_at="2026-09-30T10:00:00Z")
        col2 = build_host_artifact_collection("/evidence", list(reversed(records)), collected_at="2026-09-30T10:00:00Z")

        # Ordering of artifacts must match regardless of input list order
        sources1 = [a.source_id for a in col1.artifacts]
        sources2 = [a.source_id for a in col2.artifacts]
        self.assertEqual(sources1, sources2)

        # Metric summary counts must match
        self.assertEqual(col1.category_counts, col2.category_counts)
        self.assertEqual(col1.status_counts, col2.status_counts)
        self.assertEqual(col1.summary, col2.summary)

    def test_21_no_filesystem_io_in_adapters(self):
        """21. Verify adapter and collection building perform no disk I/O."""
        # Using completely synthetic paths that do not exist on disk
        fake_log = LogEvent(
            event_id="EVT-fake",
            source_artifact_id=None,
            source_path="/nonexistent/root/var/log/missing.log",
            line_number=1,
            raw_timestamp="Jan 1 00:00:00",
            normalized_timestamp=None,
            hostname="host",
            service="svc",
            pid=1,
            event_type="generic_syslog",
            attributes={},
            raw_message="hello",
            raw_line="Jan 1 00:00:00 host svc[1]: hello",
        )
        # Should adapt cleanly without trying to stat, read, or open the path
        art = to_host_artifact(fake_log)
        self.assertEqual(art.source_path, "/nonexistent/root/var/log/missing.log")
        col = build_host_artifact_collection("/nonexistent/root", [fake_log])
        self.assertEqual(col.total_artifacts, 1)


if __name__ == "__main__":
    unittest.main()
