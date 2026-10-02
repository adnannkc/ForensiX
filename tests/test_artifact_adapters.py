"""
Focused Unit Test Suite for ForensiX V3.3 Artifact Adapters.

Covers:
1. FilesystemAdapter:
   - Valid ArtifactRecord produces correct TimelineEvents.
   - mtime produces file_modified event.
   - atime produces file_accessed event.
   - crtime / birthtime / created produces file_created event.
   - ctime / metadata_changed produces file_metadata_changed event.
   - Missing optional timestamps do not create fabricated timestamps.
   - All timestamps None produces empty tuple () without error.
   - Multiple timestamps produce separate factual events in canonical order.
   - Source path is preserved.
   - Source artifact ID is preserved when available.
   - Raw timestamp is preserved verbatim.
   - Normalized timestamp is correct typed datetime.
   - Attributes (size, permissions, hashes, relative_path, status, mime_type) are preserved.
   - ForensicAnalysisResult and FileMetadata adaptation.
   - Filesystem dictionary adaptation.

2. LogAdapter:
   - Valid LogEvent produces TimelineCategory.LOG event.
   - Normalized ISO timestamp is parsed to UTC datetime.
   - Yearless BSD syslog raw timestamp keeps timestamp=None without guessing.
   - Provenance preservation (source_path, line_number, source_artifact_id, source_event_id, raw_line).
   - Attributes preservation (service, pid, hostname, attributes).
   - Log dictionary adaptation.

3. AuthenticationAdapter:
   - Valid AuthenticationRecord produces TimelineCategory.AUTHENTICATION event.
   - Provenance preservation (source_path, line_number, source_artifact_id, source_event_id = auth_id, raw_line).
   - Attributes preservation (username, source_ip, source_port, authentication_method, status).
   - Auth dictionary adaptation.

4. Timestamp Normalization Integration:
   - Timezone-aware timestamp (e.g. 2026-09-30T14:30:00+05:30) normalized to UTC.
   - Timezone-naive timestamp (e.g. 2026-09-30 14:30:00) preserved as naive.
   - Invalid timestamp strings rejected with ValueError.
   - Date-only strings rejected with ValueError (preventing fabricated midnight).
   - Numeric epoch timestamps supported.

5. Unified HostArtifact Adaptation:
   - HostArtifact with ArtifactRecord payload routes to FilesystemAdapter.
   - HostArtifact with LogEvent payload routes to LogAdapter.
   - HostArtifact with AuthenticationRecord payload routes to AuthenticationAdapter.
   - HostArtifact with non-timeline payload (e.g. UserAccount) raises TypeError.

6. Polymorphic Dispatcher (adapt_artifact, can_adapt_artifact, adapt_artifacts):
   - Automatic type detection and routing.
   - adapt_artifacts adapts sequence in order without sorting or dedup.
   - can_adapt_artifact returns True for supported, False for unsupported/None.

7. Event Semantics:
   - Factual observations only, no speculative classifications.
   - No risk score, severity, threat level, or confidence fields.

8. Determinism:
   - Repeated adaptation of identical input produces identical event content.

9. Error Handling:
   - None input raises ValueError.
   - Unsupported types raise TypeError.
   - Malformed filesystem dict missing source_path raises ValueError.
   - Non-timeline V2 models raise TypeError.
"""

from datetime import datetime, timezone
from pathlib import Path
import unittest

from forensix.account_models import (
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.analyzer import FileInfo, FileMetadata, ForensicAnalysisResult, HashResult
from forensix.artifact_adapters import (
    AuthenticationAdapter,
    BaseArtifactAdapter,
    FilesystemAdapter,
    LogAdapter,
    adapt_artifact,
    adapt_artifacts,
    adapt_auth_artifact,
    adapt_filesystem_artifact,
    adapt_log_artifact,
    can_adapt_artifact,
    compute_deterministic_artifact_id,
)
from forensix.artifacts import ArtifactRecord, ArtifactStatus, generate_artifact_id
from forensix.auth_models import AuthenticationRecord
from forensix.evidence import EvidenceRecord
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.unified_adapter import (
    artifact_record_to_host_artifact,
    auth_record_to_host_artifact,
    log_event_to_host_artifact,
    user_account_to_host_artifact,
)
from forensix.unified_models import HostArtifact


class TestArtifactAdapters(unittest.TestCase):
    """Rigorous unit tests for ForensiX V3.3 Artifact Adapters."""

    def setUp(self) -> None:
        self.fs_adapter = FilesystemAdapter()
        self.log_adapter = LogAdapter()
        self.auth_adapter = AuthenticationAdapter()

        # Sample test data
        self.sample_art_record = ArtifactRecord(
            artifact_id="ART-11111111-2222-4333-8444-555555555555",
            relative_path="etc/passwd",
            source_path="/evidence/target/etc/passwd",
            category="account",
            artifact_type="passwd",
            is_known=True,
            size=2048,
            permissions="0644",
            modified="2026-09-30T14:30:00+05:30",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-29T08:00:00Z",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="collected",
            mime_type="text/plain",
        )

        self.sample_log_event = LogEvent(
            event_id="EVT-22222222-3333-4444-8555-666666666666",
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_path="/var/log/auth.log",
            line_number=42,
            raw_timestamp="2026-09-30T14:30:00+05:30",
            normalized_timestamp="2026-09-30T09:00:00Z",
            hostname="host1",
            service="sshd",
            pid=1234,
            event_type="ssh_login_success",
            attributes={"user": "ubuntu", "src_ip": "192.168.1.50"},
            raw_message="Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
            raw_line="Sep 30 14:30:00 host1 sshd[1234]: Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
        )

        self.sample_auth_record = AuthenticationRecord(
            auth_id="AUTH-33333333-4444-4555-8666-777777777777",
            event_id="EVT-22222222-3333-4444-8555-666666666666",
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_path="/var/log/auth.log",
            line_number=42,
            raw_timestamp="2026-09-30T14:30:00+05:30",
            normalized_timestamp="2026-09-30T09:00:00Z",
            hostname="host1",
            service="sshd",
            event_type="ssh_login_success",
            status="SUCCESS",
            username="ubuntu",
            source_ip="192.168.1.50",
            source_port=54321,
            authentication_method="publickey",
            attributes={"user": "ubuntu", "key_type": "ssh-ed25519"},
            raw_message="Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
            raw_line="Sep 30 14:30:00 host1 sshd[1234]: Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
        )

    # =========================================================================
    # 1. Filesystem Adapter Tests
    # =========================================================================

    def test_01_filesystem_adapter_can_adapt(self):
        """Verify FilesystemAdapter detects supported and unsupported types."""
        self.assertTrue(self.fs_adapter.can_adapt(self.sample_art_record))
        self.assertFalse(self.fs_adapter.can_adapt(self.sample_log_event))
        self.assertFalse(self.fs_adapter.can_adapt(self.sample_auth_record))
        self.assertFalse(self.fs_adapter.can_adapt(None))
        self.assertFalse(self.fs_adapter.can_adapt("string_path"))

    def test_02_filesystem_adapter_artifact_record_multiple_timestamps(self):
        """Verify ArtifactRecord with created, modified, accessed emits 3 events in canonical order."""
        events = self.fs_adapter.adapt(self.sample_art_record)
        self.assertEqual(len(events), 3)

        # 1. file_created
        evt_created = events[0]
        self.assertEqual(evt_created.category, TimelineCategory.FILESYSTEM)
        self.assertEqual(evt_created.event_type, "file_created")
        self.assertEqual(evt_created.description, "File created: /evidence/target/etc/passwd")
        self.assertEqual(evt_created.timestamp, datetime(2026, 9, 29, 8, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt_created.raw_timestamp, "2026-09-29T08:00:00Z")
        self.assertEqual(evt_created.source_path, "/evidence/target/etc/passwd")
        expected_v3_id = compute_deterministic_artifact_id(
            path=self.sample_art_record.source_path,
            relative_path=self.sample_art_record.relative_path,
            sha256=self.sample_art_record.sha256,
        )
        self.assertEqual(evt_created.source_artifact_id, expected_v3_id)
        self.assertEqual(dict(evt_created.attributes)["v2_artifact_id"], "ART-11111111-2222-4333-8444-555555555555")
        self.assertIsNone(evt_created.source_line)
        self.assertIsNone(evt_created.source_event_id)
        self.assertIsNone(evt_created.raw_data)

        # 2. file_modified (converted from UTC+05:30 to UTC)
        evt_modified = events[1]
        self.assertEqual(evt_modified.category, TimelineCategory.FILESYSTEM)
        self.assertEqual(evt_modified.event_type, "file_modified")
        self.assertEqual(evt_modified.description, "File modified: /evidence/target/etc/passwd")
        self.assertEqual(evt_modified.timestamp, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt_modified.raw_timestamp, "2026-09-30T14:30:00+05:30")
        self.assertEqual(evt_modified.source_path, "/evidence/target/etc/passwd")

        # 3. file_accessed
        evt_accessed = events[2]
        self.assertEqual(evt_accessed.category, TimelineCategory.FILESYSTEM)
        self.assertEqual(evt_accessed.event_type, "file_accessed")
        self.assertEqual(evt_accessed.description, "File accessed: /evidence/target/etc/passwd")
        self.assertEqual(evt_accessed.timestamp, datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt_accessed.raw_timestamp, "2026-09-30T10:00:00Z")

    def test_03_filesystem_adapter_single_mtime_only(self):
        """Verify file with only modified timestamp emits exactly 1 event (no fabricated created/accessed)."""
        rec = ArtifactRecord(
            artifact_id="ART-SINGLE-MTIME",
            relative_path="var/log/test.log",
            source_path="/var/log/test.log",
            category="log",
            artifact_type="syslog",
            is_known=True,
            size=100,
            permissions="0640",
            modified="2026-09-30T12:00:00Z",
            accessed=None,
            created=None,
            md5=None,
            sha256=None,
            status="collected",
        )
        events = self.fs_adapter.adapt(rec)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "file_modified")
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc))

    def test_04_filesystem_adapter_no_timestamps_emits_empty(self):
        """Verify file with all timestamps None produces empty tuple without error."""
        rec = ArtifactRecord(
            artifact_id="ART-NO-TS",
            relative_path="dev/null",
            source_path="/dev/null",
            category="generic",
            artifact_type="generic_file",
            is_known=False,
            size=0,
            permissions="0666",
            modified=None,
            accessed=None,
            created=None,
            md5=None,
            sha256=None,
            status="unreadable",
        )
        events = self.fs_adapter.adapt(rec)
        self.assertEqual(events, ())

    def test_05_filesystem_adapter_metadata_change_ctime_event(self):
        """Verify ctime/metadata_changed produces file_metadata_changed event."""
        data = {
            "source_path": "/etc/shadow",
            "artifact_id": "ART-SHADOW-1",
            "ctime": "2026-09-30T12:30:00Z",
            "permissions": "0600",
        }
        events = self.fs_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "file_metadata_changed")
        self.assertEqual(events[0].description, "File metadata changed: /etc/shadow")
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 30, 12, 30, 0, tzinfo=timezone.utc))
        self.assertEqual(events[0].source_artifact_id, "ART-SHADOW-1")

    def test_06_filesystem_adapter_forensic_analysis_result(self):
        """Verify ForensicAnalysisResult from V1 analyzer is correctly adapted."""
        ev = EvidenceRecord("EV-1", Path("/evidence/sample.txt"), "2026-09-30T00:00:00Z")
        fi = FileInfo("sample.txt", 500, ".txt", "text/plain")
        fm = FileMetadata("0644", "2026-09-30T11:00:00Z", "2026-09-30T10:00:00Z", "2026-09-29T09:00:00Z")
        hr = HashResult("md5hex", "sha256hex")
        res = ForensicAnalysisResult(ev, fi, fm, hr)

        events = self.fs_adapter.adapt(res)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].event_type, "file_created")
        self.assertEqual(events[1].event_type, "file_modified")
        self.assertEqual(events[2].event_type, "file_accessed")
        self.assertEqual(events[1].source_path, "/evidence/sample.txt")
        self.assertEqual(events[1].source_artifact_id, "EV-1")

    def test_07_filesystem_adapter_file_metadata_object(self):
        """Verify FileMetadata object is directly adapted."""
        fm = FileMetadata("0755", "2026-09-30T12:00:00Z", "2026-09-30T11:00:00Z", None)
        events = self.fs_adapter.adapt(fm)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "file_modified")
        self.assertEqual(events[1].event_type, "file_accessed")

    def test_08_filesystem_adapter_attributes_preserved(self):
        """Verify auxiliary attributes (size, permissions, hashes, relative_path) are preserved."""
        events = self.fs_adapter.adapt(self.sample_art_record)
        evt = events[0]
        attr_dict = dict(evt.attributes)
        self.assertEqual(attr_dict["file_size"], 2048)
        self.assertEqual(attr_dict["permissions"], "0644")
        self.assertEqual(attr_dict["relative_path"], "etc/passwd")
        self.assertEqual(attr_dict["artifact_type"], "passwd")
        self.assertEqual(attr_dict["artifact_category"], "account")
        self.assertEqual(attr_dict["status"], "collected")
        self.assertEqual(attr_dict["mime_type"], "text/plain")
        self.assertEqual(attr_dict["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(attr_dict["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(attr_dict["v2_artifact_id"], self.sample_art_record.artifact_id)

    # =========================================================================
    # 2. Log Adapter Tests
    # =========================================================================

    def test_09_log_adapter_valid_log_event(self):
        """Verify LogEvent is correctly adapted into TimelineCategory.LOG event."""
        events = self.log_adapter.adapt(self.sample_log_event)
        self.assertEqual(len(events), 1)
        evt = events[0]

        self.assertEqual(evt.category, TimelineCategory.LOG)
        self.assertEqual(evt.event_type, "ssh_login_success")
        self.assertEqual(evt.description, "Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2")
        self.assertEqual(evt.timestamp, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt.raw_timestamp, "2026-09-30T14:30:00+05:30")
        self.assertEqual(evt.source_path, "/var/log/auth.log")
        self.assertEqual(evt.source_line, 42)
        self.assertEqual(evt.source_artifact_id, "ART-11111111-2222-4333-8444-555555555555")
        self.assertEqual(evt.source_event_id, "EVT-22222222-3333-4444-8555-666666666666")
        self.assertEqual(evt.raw_data, self.sample_log_event.raw_line)

        attr_dict = dict(evt.attributes)
        self.assertEqual(attr_dict["service"], "sshd")
        self.assertEqual(attr_dict["pid"], 1234)
        self.assertEqual(attr_dict["hostname"], "host1")
        self.assertEqual(attr_dict["user"], "ubuntu")

    def test_10_log_adapter_yearless_syslog_timestamp_handling(self):
        """Verify yearless BSD syslog timestamp leaves timestamp=None without guessing."""
        evt = LogEvent(
            event_id="EVT-YEARLESS",
            source_artifact_id=None,
            source_path="/var/log/syslog",
            line_number=10,
            raw_timestamp="Sep 30 14:30:00",
            normalized_timestamp=None,
            hostname="host1",
            service="cron",
            pid=555,
            event_type="generic_syslog",
            attributes={},
            raw_message="CRON job started",
            raw_line="Sep 30 14:30:00 host1 cron[555]: CRON job started",
        )
        events = self.log_adapter.adapt(evt)
        self.assertEqual(len(events), 1)
        res = events[0]
        self.assertIsNone(res.timestamp)
        self.assertEqual(res.raw_timestamp, "Sep 30 14:30:00")
        self.assertEqual(res.source_path, "/var/log/syslog")
        self.assertEqual(res.source_line, 10)

    def test_11_log_adapter_dictionary_input(self):
        """Verify log event dictionary input is adapted correctly."""
        data = {
            "source_path": "/var/log/auth.log",
            "line_number": 5,
            "raw_timestamp": "2026-09-30T10:00:00Z",
            "event_type": "sudo_command",
            "raw_message": "sudo: user executed /bin/ls",
            "raw_line": "Sep 30 10:00:00 host sudo: user executed /bin/ls",
            "service": "sudo",
        }
        events = self.log_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, TimelineCategory.LOG)
        self.assertEqual(events[0].event_type, "sudo_command")
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc))

    # =========================================================================
    # 3. Authentication Adapter Tests
    # =========================================================================

    def test_12_auth_adapter_valid_auth_record(self):
        """Verify AuthenticationRecord is correctly adapted into TimelineCategory.AUTHENTICATION event."""
        events = self.auth_adapter.adapt(self.sample_auth_record)
        self.assertEqual(len(events), 1)
        evt = events[0]

        self.assertEqual(evt.category, TimelineCategory.AUTHENTICATION)
        self.assertEqual(evt.event_type, "ssh_login_success")
        self.assertEqual(evt.description, "Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2")
        self.assertEqual(evt.timestamp, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt.raw_timestamp, "2026-09-30T14:30:00+05:30")
        self.assertEqual(evt.source_path, "/var/log/auth.log")
        self.assertEqual(evt.source_line, 42)
        self.assertEqual(evt.source_artifact_id, "ART-11111111-2222-4333-8444-555555555555")
        self.assertEqual(evt.source_event_id, "AUTH-33333333-4444-4555-8666-777777777777")
        self.assertEqual(evt.raw_data, self.sample_auth_record.raw_line)

        attr_dict = dict(evt.attributes)
        self.assertEqual(attr_dict["username"], "ubuntu")
        self.assertEqual(attr_dict["source_ip"], "192.168.1.50")
        self.assertEqual(attr_dict["source_port"], 54321)
        self.assertEqual(attr_dict["authentication_method"], "publickey")
        self.assertEqual(attr_dict["status"], "SUCCESS")
        self.assertEqual(attr_dict["log_event_id"], "EVT-22222222-3333-4444-8555-666666666666")

    def test_13_auth_adapter_dictionary_input(self):
        """Verify authentication dictionary input is adapted correctly."""
        data = {
            "source_path": "/var/log/auth.log",
            "line_number": 99,
            "raw_timestamp": "2026-09-30T11:00:00Z",
            "event_type": "ssh_login_failure",
            "status": "FAILURE",
            "username": "root",
            "source_ip": "10.0.0.1",
            "auth_id": "AUTH-SAMPLE-DICT",
            "raw_message": "Failed password for root from 10.0.0.1 port 2222",
            "raw_line": "Sep 30 11:00:00 server sshd[999]: Failed password for root from 10.0.0.1 port 2222",
        }
        events = self.auth_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, TimelineCategory.AUTHENTICATION)
        self.assertEqual(events[0].event_type, "ssh_login_failure")
        self.assertEqual(events[0].source_event_id, "AUTH-SAMPLE-DICT")
        self.assertEqual(dict(events[0].attributes)["username"], "root")

    # =========================================================================
    # 4. Timestamp Normalization Integration Tests
    # =========================================================================

    def test_14_timestamp_normalization_aware_to_utc(self):
        """Verify timezone-aware timestamps (+05:30) normalize deterministically to UTC."""
        data = {
            "source_path": "/test/file",
            "modified": "2026-09-30T14:30:00+05:30",
        }
        events = self.fs_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(events[0].raw_timestamp, "2026-09-30T14:30:00+05:30")

    def test_15_timestamp_normalization_naive_remains_naive(self):
        """Verify timezone-naive timestamps remain strictly naive without synthetic timezone."""
        data = {
            "source_path": "/test/file",
            "modified": "2026-09-30 14:30:00",
        }
        events = self.fs_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].timestamp.tzinfo)
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 30, 14, 30, 0))
        self.assertEqual(events[0].raw_timestamp, "2026-09-30 14:30:00")

    def test_16_timestamp_normalization_date_only_rejected(self):
        """Verify date-only string without time component raises ValueError (prevents midnight fabrication)."""
        data = {
            "source_path": "/test/file",
            "modified": "2026-09-30",
        }
        with self.assertRaises(ValueError) as ctx:
            self.fs_adapter.adapt(data)
        self.assertIn("lacks a time component", str(ctx.exception))

    def test_17_timestamp_normalization_invalid_date_rejected(self):
        """Verify impossible calendar date raises ValueError."""
        data = {
            "source_path": "/test/file",
            "modified": "2026-02-30 12:00:00",
        }
        with self.assertRaises(ValueError):
            self.fs_adapter.adapt(data)

    def test_18_timestamp_numeric_epoch_handled(self):
        """Verify POSIX numeric timestamp is converted and normalized safely."""
        data = {
            "source_path": "/test/file",
            "mtime": 1727704200.0,  # 2024-09-30 13:50:00 UTC
        }
        events = self.fs_adapter.adapt(data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "file_modified")
        self.assertEqual(events[0].timestamp.tzinfo, timezone.utc)

    # =========================================================================
    # 5. Unified HostArtifact Adaptation Tests
    # =========================================================================

    def test_19_host_artifact_filesystem_payload_adaptation(self):
        """Verify HostArtifact containing ArtifactRecord routes to FilesystemAdapter."""
        host_art = artifact_record_to_host_artifact(self.sample_art_record)
        events = adapt_artifact(host_art)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].category, TimelineCategory.FILESYSTEM)
        expected_v3_id = compute_deterministic_artifact_id(
            path=self.sample_art_record.source_path,
            relative_path=self.sample_art_record.relative_path,
            sha256=self.sample_art_record.sha256,
        )
        self.assertEqual(events[0].source_artifact_id, expected_v3_id)
        self.assertEqual(dict(events[0].attributes)["v2_artifact_id"], self.sample_art_record.artifact_id)

    def test_20_host_artifact_log_payload_adaptation(self):
        """Verify HostArtifact containing LogEvent routes to LogAdapter."""
        host_art = log_event_to_host_artifact(self.sample_log_event)
        events = adapt_artifact(host_art)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, TimelineCategory.LOG)
        self.assertEqual(events[0].source_event_id, self.sample_log_event.event_id)

    def test_21_host_artifact_auth_payload_adaptation(self):
        """Verify HostArtifact containing AuthenticationRecord routes to AuthenticationAdapter."""
        host_art = auth_record_to_host_artifact(self.sample_auth_record)
        events = adapt_artifact(host_art)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, TimelineCategory.AUTHENTICATION)
        self.assertEqual(events[0].source_event_id, self.sample_auth_record.auth_id)

    def test_22_host_artifact_non_timeline_payload_raises_type_error(self):
        """Verify HostArtifact without chronological timestamps raises TypeError."""
        user = UserAccount(
            user_id="USER-1",
            source_artifact_id="ART-1",
            source_path="/etc/passwd",
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
        host_art = user_account_to_host_artifact(user)
        with self.assertRaises(TypeError) as ctx:
            adapt_artifact(host_art)
        self.assertIn("does not contain factual chronological timestamps", str(ctx.exception))

    # =========================================================================
    # 6. Polymorphic Dispatcher Tests
    # =========================================================================

    def test_23_can_adapt_artifact(self):
        """Verify can_adapt_artifact returns True for supported and False for unsupported."""
        self.assertTrue(can_adapt_artifact(self.sample_art_record))
        self.assertTrue(can_adapt_artifact(self.sample_log_event))
        self.assertTrue(can_adapt_artifact(self.sample_auth_record))
        self.assertFalse(can_adapt_artifact(None))
        self.assertFalse(can_adapt_artifact("some string"))
        self.assertFalse(can_adapt_artifact(12345))

    def test_24_adapt_artifact_convenience_functions(self):
        """Verify specific convenience adapters function identically."""
        fs_evts = adapt_filesystem_artifact(self.sample_art_record)
        self.assertEqual(len(fs_evts), 3)

        log_evts = adapt_log_artifact(self.sample_log_event)
        self.assertEqual(len(log_evts), 1)

        auth_evts = adapt_auth_artifact(self.sample_auth_record)
        self.assertEqual(len(auth_evts), 1)

    def test_25_adapt_artifacts_sequence(self):
        """Verify adapt_artifacts adapts multiple heterogeneous artifacts preserving sequence order."""
        arts = [self.sample_art_record, self.sample_log_event, self.sample_auth_record]
        all_events = adapt_artifacts(arts)
        self.assertEqual(len(all_events), 5)  # 3 fs + 1 log + 1 auth
        self.assertEqual(all_events[0].category, TimelineCategory.FILESYSTEM)
        self.assertEqual(all_events[1].category, TimelineCategory.FILESYSTEM)
        self.assertEqual(all_events[2].category, TimelineCategory.FILESYSTEM)
        self.assertEqual(all_events[3].category, TimelineCategory.LOG)
        self.assertEqual(all_events[4].category, TimelineCategory.AUTHENTICATION)

    def test_26_adapt_artifacts_ignore_unsupported(self):
        """Verify adapt_artifacts with ignore_unsupported=True skips non-timeline records."""
        user = UserAccount(
            user_id="USER-1",
            source_artifact_id="ART-1",
            source_path="/etc/passwd",
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
        arts = [self.sample_art_record, user, self.sample_log_event]
        events = adapt_artifacts(arts, ignore_unsupported=True)
        self.assertEqual(len(events), 4)  # 3 fs + 1 log (user skipped)

    # =========================================================================
    # 7. Event Semantics and Safety Boundaries
    # =========================================================================

    def test_27_event_semantics_factual_only(self):
        """Verify no speculative classifications or detection concepts are generated."""
        events = self.fs_adapter.adapt(self.sample_art_record)
        for evt in events:
            # Factual types only
            self.assertIn(evt.event_type, ("file_created", "file_modified", "file_accessed", "file_metadata_changed"))
            # No risk or security scoring
            self.assertFalse(hasattr(evt, "risk_score"))
            self.assertFalse(hasattr(evt, "severity"))
            self.assertFalse(hasattr(evt, "threat_level"))
            self.assertFalse(hasattr(evt, "confidence"))
            # Attributes do not contain speculative detection terms
            attr_keys = [k.lower() for k, _ in evt.attributes]
            self.assertNotIn("threat", attr_keys)
            self.assertNotIn("malware", attr_keys)
            self.assertNotIn("compromise", attr_keys)

    def test_28_descriptions_factual(self):
        """Verify descriptions are factual and objective."""
        events = self.fs_adapter.adapt(self.sample_art_record)
        self.assertTrue(events[0].description.startswith("File created:"))
        self.assertTrue(events[1].description.startswith("File modified:"))
        self.assertTrue(events[2].description.startswith("File accessed:"))

    # =========================================================================
    # 8. Determinism Tests
    # =========================================================================

    def test_29_determinism_identical_input_identical_output(self):
        """Verify identical inputs produce equivalent event content and deterministic ordering."""
        events_run1 = self.fs_adapter.adapt(self.sample_art_record)
        events_run2 = self.fs_adapter.adapt(self.sample_art_record)

        self.assertEqual(len(events_run1), len(events_run2))
        for e1, e2 in zip(events_run1, events_run2):
            self.assertEqual(e1.timestamp, e2.timestamp)
            self.assertEqual(e1.raw_timestamp, e2.raw_timestamp)
            self.assertEqual(e1.category, e2.category)
            self.assertEqual(e1.event_type, e2.event_type)
            self.assertEqual(e1.description, e2.description)
            self.assertEqual(e1.source_path, e2.source_path)
            self.assertEqual(e1.source_artifact_id, e2.source_artifact_id)
            self.assertEqual(e1.attributes, e2.attributes)

    # =========================================================================
    # 9. Error Handling and Edge Cases
    # =========================================================================

    def test_30_none_artifact_raises_value_error(self):
        """Verify adapt_artifact(None) raises ValueError."""
        with self.assertRaises(ValueError):
            adapt_artifact(None)
        with self.assertRaises(ValueError):
            self.fs_adapter.adapt(None)
        with self.assertRaises(ValueError):
            self.log_adapter.adapt(None)
        with self.assertRaises(ValueError):
            self.auth_adapter.adapt(None)

    def test_31_unsupported_type_raises_type_error(self):
        """Verify unsupported artifact type raises TypeError."""
        with self.assertRaises(TypeError):
            adapt_artifact("not_an_artifact")
        with self.assertRaises(TypeError):
            adapt_artifact(42)

    def test_32_non_timeline_v2_models_raise_type_error(self):
        """Verify V2 models without timestamps raise informative TypeError."""
        user = UserAccount(
            user_id="USER-1",
            source_artifact_id="ART-1",
            source_path="/etc/passwd",
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
        with self.assertRaises(TypeError) as ctx:
            adapt_artifact(user)
        self.assertIn("does not contain factual chronological timestamps", str(ctx.exception))

        group = GroupRecord(
            group_id="GRP-1",
            source_artifact_id="ART-1",
            source_path="/etc/group",
            line_number=1,
            group_name="root",
            gid=0,
            members=(),
            raw_line="root:x:0:",
        )
        with self.assertRaises(TypeError):
            adapt_artifact(group)

        persist = PersistenceRecord(
            persistence_id="PERSIST-1",
            source_artifact_id=None,
            source_path="/etc/cron.d/job",
            line_number=1,
            category="cron",
            mechanism="crontab",
            scope="system",
            target_user="root",
            trigger_or_schedule="* * * * *",
            command_or_path="/bin/true",
            attributes=(),
            status="PARSED",
            raw_line="* * * * * root /bin/true",
        )
        with self.assertRaises(TypeError):
            adapt_artifact(persist)

    def test_33_dict_missing_source_path_raises_value_error(self):
        """Verify filesystem dict missing source_path raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.fs_adapter.adapt({"modified": "2026-09-30T10:00:00Z"})
        self.assertIn("missing required 'source_path'", str(ctx.exception))

    def test_34_adapt_artifacts_none_raises_value_error(self):
        """Verify adapt_artifacts(None) raises ValueError."""
        with self.assertRaises(ValueError):
            adapt_artifacts(None)

    # =========================================================================
    # 10. Deterministic V3 Provenance & Cross-Run Stability Tests
    # =========================================================================

    def test_35_deterministic_artifact_id_identical_facts_across_runs(self):
        """Verify identical ArtifactRecord facts across separate runs produce the same V3 source_artifact_id."""
        # Simulate Run 1: Scanner generates random ART-UUIDv4
        rec_run1 = ArtifactRecord(
            artifact_id="ART-11111111-aaaa-4bbb-8ccc-111111111111",
            source_path="/evidence/run1/var/log/auth.log",
            relative_path="var/log/auth.log",
            artifact_type="log",
            category="log",
            is_known=True,
            size=4096,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed=None,
            created=None,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            status="collected",
        )
        # Simulate Run 2: Scanner generates a completely different random ART-UUIDv4
        rec_run2 = ArtifactRecord(
            artifact_id="ART-22222222-dddd-4eee-8fff-222222222222",
            source_path="/evidence/run2/var/log/auth.log",
            relative_path="var/log/auth.log",
            artifact_type="log",
            category="log",
            is_known=True,
            size=4096,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed=None,
            created=None,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            status="collected",
        )

        events_run1 = self.fs_adapter.adapt(rec_run1)
        events_run2 = self.fs_adapter.adapt(rec_run2)

        self.assertEqual(len(events_run1), 1)
        self.assertEqual(len(events_run2), 1)

        # Stable V3 provenance identity must match across both independent runs
        self.assertEqual(events_run1[0].source_artifact_id, events_run2[0].source_artifact_id)
        self.assertTrue(events_run1[0].source_artifact_id.startswith("ART-"))

        # Original V2 random artifact IDs must remain preserved in attributes for traceability
        self.assertEqual(dict(events_run1[0].attributes)["v2_artifact_id"], "ART-11111111-aaaa-4bbb-8ccc-111111111111")
        self.assertEqual(dict(events_run2[0].attributes)["v2_artifact_id"], "ART-22222222-dddd-4eee-8fff-222222222222")

    def test_36_deterministic_artifact_id_different_facts_do_not_collapse(self):
        """Verify different artifact facts do not accidentally collapse to the same identity."""
        # 1. Different relative paths with identical content (e.g. two identical empty files)
        sha_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        id_gitkeep = compute_deterministic_artifact_id(relative_path=".gitkeep", sha256=sha_empty)
        id_empty_txt = compute_deterministic_artifact_id(relative_path="empty.txt", sha256=sha_empty)
        self.assertNotEqual(id_gitkeep, id_empty_txt)

        # 2. Same path with different content (modified file)
        id_v1 = compute_deterministic_artifact_id(relative_path="etc/hosts", sha256="1111111111111111111111111111111111111111111111111111111111111111")
        id_v2 = compute_deterministic_artifact_id(relative_path="etc/hosts", sha256="2222222222222222222222222222222222222222222222222222222222222222")
        self.assertNotEqual(id_v1, id_v2)

        # 3. Different paths without hashes
        id_unhash1 = compute_deterministic_artifact_id(relative_path="dev/urandom")
        id_unhash2 = compute_deterministic_artifact_id(relative_path="dev/random")
        self.assertNotEqual(id_unhash1, id_unhash2)

    def test_37_v2_scanner_artifact_id_semantics_unchanged(self):
        """Verify V2 generate_artifact_id continues to emit random ART-<UUIDv4> identifiers."""
        id1 = generate_artifact_id()
        id2 = generate_artifact_id()
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("ART-"))
        self.assertTrue(id2.startswith("ART-"))
        # Verify UUIDv4 format (6 parts when split by hyphen: ART + 5 UUID segments)
        parts = id1.split("-")
        self.assertEqual(len(parts), 6)

    def test_38_log_and_auth_provenance_links_to_parent_deterministic_id(self):
        """Verify log and auth provenance correctly resolves to the parent log file deterministic ID."""
        # Evidence log file scanned in Run 1 (with V2 random artifact_id)
        log_file_rec = ArtifactRecord(
            artifact_id="ART-V2-SCANNER-LOG-RANDOM-UUID",
            source_path="/evidence/var/log/auth.log",
            relative_path="var/log/auth.log",
            category="log",
            artifact_type="log",
            is_known=True,
            size=1024,
            permissions="0640",
            modified="2026-09-30T14:30:00Z",
            accessed=None,
            created=None,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            status="collected",
        )
        # Parsed log event from that file carrying the log file's V2 artifact_id
        log_evt = LogEvent(
            event_id="EVT-1",
            source_artifact_id="ART-V2-SCANNER-LOG-RANDOM-UUID",
            source_path="/evidence/var/log/auth.log",
            line_number=1,
            raw_timestamp="2026-09-30T14:30:00Z",
            normalized_timestamp="2026-09-30T14:30:00Z",
            hostname="host1",
            service="sshd",
            pid=100,
            event_type="ssh_login_success",
            attributes={},
            raw_message="Accepted publickey for alice",
            raw_line="Sep 30 14:30:00 host1 sshd[100]: Accepted publickey for alice",
        )
        # Authentication record extracted from that log event
        auth_rec = AuthenticationRecord(
            auth_id="AUTH-1",
            event_id="EVT-1",
            source_artifact_id="ART-V2-SCANNER-LOG-RANDOM-UUID",
            source_path="/evidence/var/log/auth.log",
            line_number=1,
            raw_timestamp="2026-09-30T14:30:00Z",
            normalized_timestamp="2026-09-30T14:30:00Z",
            hostname="host1",
            service="sshd",
            event_type="ssh_login_success",
            status="SUCCESS",
            username="alice",
            source_ip="192.168.1.50",
            source_port=54321,
            authentication_method="publickey",
            attributes={},
            raw_message="Accepted publickey for alice",
            raw_line="Sep 30 14:30:00 host1 sshd[100]: Accepted publickey for alice",
        )

        all_events = adapt_artifacts([log_file_rec, log_evt, auth_rec])
        self.assertEqual(len(all_events), 3)

        fs_event = all_events[0]
        log_event = all_events[1]
        auth_event = all_events[2]

        expected_parent_id = compute_deterministic_artifact_id(
            path=log_file_rec.source_path,
            relative_path=log_file_rec.relative_path,
            sha256=log_file_rec.sha256,
        )

        # All 3 events must share the parent log file's deterministic V3 source_artifact_id
        self.assertEqual(fs_event.source_artifact_id, expected_parent_id)
        self.assertEqual(log_event.source_artifact_id, expected_parent_id)
        self.assertEqual(auth_event.source_artifact_id, expected_parent_id)

        # All events must retain the original V2 artifact ID in attributes for audit traceability
        self.assertEqual(dict(fs_event.attributes)["v2_artifact_id"], "ART-V2-SCANNER-LOG-RANDOM-UUID")
        self.assertEqual(dict(log_event.attributes)["v2_artifact_id"], "ART-V2-SCANNER-LOG-RANDOM-UUID")
        self.assertEqual(dict(auth_event.attributes)["v2_artifact_id"], "ART-V2-SCANNER-LOG-RANDOM-UUID")


if __name__ == "__main__":
    unittest.main()
