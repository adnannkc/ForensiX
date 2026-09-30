"""
Unit tests for ForensiX Investigation & Analysis Interface Layer (V2.7).

Verifies:
- In-memory querying, filtering, indexing, and text search over HostArtifacts
- Strict canonical artifact type matching
- Exact vs substring source path filtering without path normalization
- Factual cross-reference relationship traversal (AUTH -> EVT -> ART) without speculative correlation
- Explicit searchable fields for textual search
- Deep immutability of results and source artifact preservation
- Deterministic ordering of artifacts and metric summaries
- Full JSON serialization via json.dumps(result.to_dict())
- Concrete TypeError and ValueError handling
- Zero filesystem I/O and zero command execution
"""

import json
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
from forensix.investigation import (
    ArtifactQuery,
    HostArtifactInvestigator,
    InvestigationResultSet,
)
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.unified_adapter import (
    build_host_artifact_collection,
    to_host_artifact,
)
from forensix.unified_models import (
    HostArtifact,
    HostArtifactCategory,
    HostArtifactCollection,
)


class TestInvestigationInterface(unittest.TestCase):
    """Test suite for V2.7 HostArtifactInvestigator and query models."""

    def setUp(self):
        """Set up representative host artifacts across all V2 categories."""
        # 1. Filesystem Artifact
        self.art_file = ArtifactRecord(
            artifact_id="ART-1111",
            relative_path="etc/passwd",
            source_path="/evidence/etc/passwd",
            category="account",
            artifact_type="passwd",
            is_known=True,
            size=2048,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-30T10:00:00Z",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="collected",
        )
        self.host_art_file = to_host_artifact(self.art_file)

        # 2. Log Event
        self.log_evt = LogEvent(
            event_id="EVT-2222",
            source_artifact_id="ART-9999",
            source_path="/evidence/var/log/auth.log",
            line_number=100,
            raw_timestamp="Sep 30 11:00:00",
            normalized_timestamp=None,
            hostname="target-host",
            service="sshd",
            pid=4567,
            event_type="ssh_login_success",
            attributes={"user": "investigator", "src_ip": "10.0.0.5"},
            raw_message="Accepted publickey for investigator from 10.0.0.5 port 2222 ssh2",
            raw_line="Sep 30 11:00:00 target-host sshd[4567]: Accepted publickey for investigator from 10.0.0.5 port 2222 ssh2",
        )
        self.host_log_evt = to_host_artifact(self.log_evt)

        # 3. Authentication Record (Derived from LogEvent EVT-2222)
        self.auth_rec = AuthenticationRecord(
            auth_id="AUTH-3333",
            event_id="EVT-2222",
            source_artifact_id="ART-9999",
            source_path="/evidence/var/log/auth.log",
            line_number=100,
            raw_timestamp="Sep 30 11:00:00",
            normalized_timestamp=None,
            hostname="target-host",
            service="sshd",
            event_type="ssh_login_success",
            status="SUCCESS",
            username="investigator",
            source_ip="10.0.0.5",
            source_port=2222,
            authentication_method="publickey",
            attributes={},
            raw_message="Accepted publickey for investigator from 10.0.0.5 port 2222 ssh2",
            raw_line="Sep 30 11:00:00 target-host sshd[4567]: Accepted publickey for investigator from 10.0.0.5 port 2222 ssh2",
        )
        self.host_auth_rec = to_host_artifact(self.auth_rec)

        # 4. User Account
        self.user_acc = UserAccount(
            user_id="USER-4444",
            source_artifact_id="ART-1111",
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
        self.host_user_acc = to_host_artifact(self.user_acc)

        # 5. Group Record
        self.group_rec = GroupRecord(
            group_id="GRP-5555",
            source_artifact_id="ART-1112",
            source_path="/evidence/etc/group",
            line_number=5,
            group_name="sudo",
            gid=27,
            members=("investigator",),
            raw_line="sudo:x:27:investigator",
        )
        self.host_group_rec = to_host_artifact(self.group_rec)

        # 6. Sudo Rule
        self.sudo_rule = SudoRule(
            rule_id="SUDO-6666",
            source_artifact_id="ART-1113",
            source_path="/evidence/etc/sudoers",
            line_number=15,
            is_parsed=True,
            user_spec="%sudo",
            host_spec="ALL",
            runas_spec="ALL:ALL",
            commands=("/usr/bin/apt", "/usr/bin/systemctl"),
            options=(),
            raw_line="%sudo ALL=(ALL:ALL) /usr/bin/apt, /usr/bin/systemctl",
        )
        self.host_sudo_rule = to_host_artifact(self.sudo_rule)

        # 7. Persistence Record
        self.persist_rec = PersistenceRecord(
            persistence_id="PERSIST-7777",
            source_artifact_id="ART-1114",
            source_path="/evidence/etc/cron.d/sync_service",
            line_number=2,
            category="cron",
            mechanism="cron_job",
            scope="system",
            target_user="root",
            trigger_or_schedule="*/15 * * * *",
            command_or_path="/opt/sync/backup.sh",
            attributes=(("command", "/opt/sync/backup.sh"),),
            status="PARSED",
            raw_line="*/15 * * * * root /opt/sync/backup.sh",
        )
        self.host_persist_rec = to_host_artifact(self.persist_rec)

        # Build HostArtifactCollection
        self.all_artifacts = [
            self.host_art_file,
            self.host_log_evt,
            self.host_auth_rec,
            self.host_user_acc,
            self.host_group_rec,
            self.host_sudo_rule,
            self.host_persist_rec,
        ]
        self.collection = build_host_artifact_collection(
            evidence_root="/evidence",
            records=[
                self.art_file,
                self.log_evt,
                self.auth_rec,
                self.user_acc,
                self.group_rec,
                self.sudo_rule,
                self.persist_rec,
            ],
            collected_at="2026-09-30T12:00:00Z",
        )
        self.investigator = HostArtifactInvestigator(self.collection)

    def test_01_category_filtering(self):
        """1. Verify filtering by HostArtifactCategory enum and string."""
        res_enum = self.investigator.filter_by_category(HostArtifactCategory.LOG)
        self.assertEqual(len(res_enum), 1)
        self.assertEqual(res_enum[0].category, "log")

        res_str = self.investigator.filter_by_category("account")
        self.assertEqual(len(res_str), 1)
        self.assertEqual(res_str[0].artifact_type, "user_account")

    def test_02_artifact_type_filtering(self):
        """2. Verify filtering strictly against canonical V2.6 artifact_type."""
        res = self.investigator.filter_by_type("ssh_login_success")
        # Matches both the LogEvent and the AuthenticationRecord which share this canonical type
        self.assertEqual(len(res), 2)
        for art in res:
            self.assertEqual(art.artifact_type, "ssh_login_success")

    def test_03_source_path_filtering_exact_vs_substring(self):
        """3. Verify source_path filtering with exact=True and exact=False."""
        # Exact matching
        res_exact = self.investigator.filter_by_source_path("/evidence/etc/passwd", exact=True)
        self.assertEqual(len(res_exact), 2)  # ArtifactRecord and UserAccount

        # Non-matching exact path
        res_none = self.investigator.filter_by_source_path("/evidence/etc", exact=True)
        self.assertEqual(len(res_none), 0)

        # Substring matching
        res_sub = self.investigator.filter_by_source_path("cron", exact=False)
        self.assertEqual(len(res_sub), 1)
        self.assertEqual(res_sub[0].source_id, "PERSIST-7777")

    def test_04_source_id_lookup(self):
        """4. Verify direct retrieval by source_id across subsystems."""
        arts = self.investigator.get_by_source_id("USER-4444")
        self.assertEqual(len(arts), 1)
        self.assertEqual(arts[0].source_id, "USER-4444")

        # Unknown ID returns empty tuple
        self.assertEqual(self.investigator.get_by_source_id("UNKNOWN-ID"), ())

    def test_05_unified_id_lookup(self):
        """5. Verify direct retrieval by unified_id (HOSTART-xxx)."""
        target_art = self.investigator._artifacts[0]
        target_uid = target_art.unified_id
        # Re-fetch via investigator
        art = self.investigator.get_by_unified_id(target_uid)
        self.assertIsNotNone(art)
        self.assertEqual(art.unified_id, target_uid)
        self.assertEqual(art.source_id, target_art.source_id)

        # Nonexistent unified_id returns None
        self.assertIsNone(self.investigator.get_by_unified_id("HOSTART-nonexistent"))

    def test_06_status_filtering(self):
        """6. Verify filtering by status (PARSED, COLLECTED, etc.)."""
        res_parsed = self.investigator.filter_by_status("PARSED")
        self.assertTrue(len(res_parsed) >= 4)
        for art in res_parsed:
            self.assertEqual(art.status, "PARSED")

        res_coll = self.investigator.filter_by_status("collected")
        self.assertEqual(len(res_coll), 1)
        self.assertEqual(res_coll[0].source_id, "ART-1111")

    def test_07_line_number_filtering(self):
        """7. Verify filtering by exact line number."""
        res = self.investigator.filter_by_line(100)
        self.assertEqual(len(res), 2)  # LogEvent and AuthenticationRecord at line 100
        for art in res:
            self.assertEqual(art.line_number, 100)

        # File-level artifacts (line_number is None) are excluded
        self.assertEqual(len(self.investigator.filter_by_line(9999)), 0)

    def test_08_text_search_explicit_fields(self):
        """8. Verify text search over documented factual fields with case sensitivity."""
        # Case-insensitive search on username
        res_user = self.investigator.search_text("INVESTIGATOR", case_sensitive=False)
        self.assertTrue(len(res_user) >= 2)  # Auth, Log, Group

        # Case-sensitive search
        res_case = self.investigator.search_text("INVESTIGATOR", case_sensitive=True)
        self.assertEqual(len(res_case), 0)

        res_case_match = self.investigator.search_text("investigator", case_sensitive=True)
        self.assertTrue(len(res_case_match) >= 2)

        # Search persistence command
        res_cron = self.investigator.search_text("backup.sh")
        self.assertEqual(len(res_cron), 1)
        self.assertEqual(res_cron[0].source_id, "PERSIST-7777")

    def test_09_compound_query_filtering(self):
        """9. Verify combining multiple criteria with logical AND."""
        query = ArtifactQuery(
            category=HostArtifactCategory.AUTHENTICATION,
            artifact_type="ssh_login_success",
            status="SUCCESS",
            search_text="10.0.0.5",
        )
        res = self.investigator.query(query)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source_id, "AUTH-3333")

        # Non-matching compound condition
        query_mismatch = ArtifactQuery(
            category=HostArtifactCategory.AUTHENTICATION,
            artifact_type="ssh_login_success",
            status="FAILURE",
        )
        self.assertEqual(len(self.investigator.query(query_mismatch)), 0)

    def test_10_query_composability_and_chaining(self):
        """10. Verify method chaining on InvestigationResultSet preserves determinism and immutability."""
        res = (
            self.investigator.filter_by_category("log")
            .filter_by_type("ssh_login_success")
            .search_text("investigator")
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source_id, "EVT-2222")
        self.assertIsInstance(res, InvestigationResultSet)

    def test_11_cross_reference_relationship_traversal(self):
        """11. Verify factual relationship traversal (AUTH -> EVT -> ART) without speculative correlation."""
        # Traversal from EVT-2222 retrieves both LogEvent (as source_id) and AuthenticationRecord (as source_event_id)
        related_to_evt = self.investigator.get_related_artifacts("EVT-2222")
        self.assertEqual(len(related_to_evt), 2)
        source_ids = {a.source_id for a in related_to_evt}
        self.assertIn("EVT-2222", source_ids)
        self.assertIn("AUTH-3333", source_ids)

        # Traversal from parent evidence file ART-1111 retrieves both file artifact and user account
        related_to_art = self.investigator.get_related_artifacts("ART-1111")
        self.assertEqual(len(related_to_art), 2)
        source_ids = {a.source_id for a in related_to_art}
        self.assertIn("ART-1111", source_ids)
        self.assertIn("USER-4444", source_ids)

    def test_12_empty_query_results(self):
        """12. Verify queries with zero matches return empty InvestigationResultSet cleanly."""
        res = self.investigator.filter_by_type("nonexistent_type")
        self.assertEqual(len(res), 0)
        self.assertEqual(res.total_matches, 0)
        self.assertEqual(res.artifacts, ())
        self.assertEqual(res.category_breakdown, ())
        self.assertEqual(res.status_breakdown, ())

    def test_13_type_error_and_value_error_enforcement(self):
        """13. Verify strict enforcement of TypeErrors and ValueErrors on invalid query inputs."""
        # Bad investigator target
        with self.assertRaises(TypeError):
            HostArtifactInvestigator("not_a_collection")  # type: ignore

        # Invalid category string
        with self.assertRaises(ValueError):
            ArtifactQuery(category="invalid_category_string")

        # Invalid category type
        with self.assertRaises(TypeError):
            ArtifactQuery(category=123)  # type: ignore

        # Empty/whitespace search_text
        with self.assertRaises(ValueError):
            ArtifactQuery(search_text="   ")

        # Non-string search_text
        with self.assertRaises(TypeError):
            ArtifactQuery(search_text=12345)  # type: ignore

        # Boolean passed as line_number
        with self.assertRaises(TypeError):
            ArtifactQuery(line_number=True)  # type: ignore

        # Negative or zero line number
        with self.assertRaises(ValueError):
            ArtifactQuery(line_number=0)
        with self.assertRaises(ValueError):
            ArtifactQuery(line_number=-5)

        # Passing both query object and kwargs to investigator.query()
        with self.assertRaises(ValueError):
            self.investigator.query(query=ArtifactQuery(status="PARSED"), status="PARSED")

    def test_14_deep_immutability(self):
        """14. Verify InvestigationResultSet rejects attribute mutation."""
        res = self.investigator.filter_by_category("account")
        with self.assertRaises(Exception):
            res.total_matches = 999  # type: ignore
        with self.assertRaises(Exception):
            res.artifacts = ()  # type: ignore

        self.assertIsInstance(res.artifacts, tuple)
        self.assertIsInstance(res.category_breakdown, tuple)
        self.assertIsInstance(res.status_breakdown, tuple)

    def test_15_source_immutability(self):
        """15. Verify source artifacts and collection remain untouched after queries."""
        pre_count = len(self.collection.artifacts)
        pre_ids = [a.unified_id for a in self.collection.artifacts]

        _ = self.investigator.filter_by_category("log")
        _ = self.investigator.search_text("root")
        _ = self.investigator.get_related_artifacts("EVT-2222")

        post_count = len(self.collection.artifacts)
        post_ids = [a.unified_id for a in self.collection.artifacts]

        self.assertEqual(pre_count, post_count)
        self.assertEqual(pre_ids, post_ids)

    def test_16_deterministic_ordering(self):
        """16. Verify deterministic ordering regardless of original sequence order."""
        inv1 = HostArtifactInvestigator(self.all_artifacts)
        inv2 = HostArtifactInvestigator(list(reversed(self.all_artifacts)))

        res1 = inv1.query()
        res2 = inv2.query()

        self.assertEqual([a.source_id for a in res1.artifacts], [a.source_id for a in res2.artifacts])
        self.assertEqual(res1.category_breakdown, res2.category_breakdown)
        self.assertEqual(res1.status_breakdown, res2.status_breakdown)

    def test_17_full_json_serialization(self):
        """17. Verify json.dumps(to_dict()) works cleanly on query results."""
        res = self.investigator.query(category="account")
        d = res.to_dict()
        serialized = json.dumps(d)
        self.assertIsInstance(serialized, str)
        loaded = json.loads(serialized)
        self.assertEqual(loaded["total_matches"], 1)
        self.assertEqual(loaded["artifacts"][0]["category"], "account")

    def test_18_zero_filesystem_io(self):
        """18. Verify investigator operates with purely synthetic non-existent paths."""
        synthetic_log = LogEvent(
            event_id="EVT-synth",
            source_artifact_id=None,
            source_path="/completely/fake/synthetic/path.log",
            line_number=1,
            raw_timestamp="Jan 1 00:00:00",
            normalized_timestamp=None,
            hostname="synth",
            service="svc",
            pid=1,
            event_type="generic_syslog",
            attributes={},
            raw_message="synthetic message",
            raw_line="synthetic raw line",
        )
        art = to_host_artifact(synthetic_log)
        inv = HostArtifactInvestigator([art])
        res = inv.filter_by_source_path("/completely/fake/synthetic/path.log")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source_id, "EVT-synth")

    def test_19_introspection_helpers(self):
        """19. Verify summary metrics and count helpers."""
        self.assertEqual(self.investigator.total_artifacts(), len(self.all_artifacts))
        cat_counts = self.investigator.get_category_counts()
        self.assertEqual(cat_counts.get("log"), 1)
        self.assertEqual(cat_counts.get("account"), 1)
        stat_counts = self.investigator.get_status_counts()
        self.assertTrue(stat_counts.get("PARSED", 0) >= 1)


if __name__ == "__main__":
    unittest.main()
