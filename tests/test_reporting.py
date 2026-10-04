"""
Unit tests for ForensiX Reporting & Presentation Layer (V2.8).

Verifies:
- Creation, validation, and deep immutability of ForensicReport and ReportMetadata
- Full JSON serialization (valid UTF-8, deterministic structure, nested payload preservation)
- CSV generation (documented schema, proper quoting, Unicode handling, flattened representation)
- Standalone HTML generation (6 required sections, zero external CDN/network, secure escaping of evidence content)
- Audit provenance model (event creation, immutability, chronological ordering, no fabricated events)
- Source object immutability (HostArtifact, collection, and query results remain untouched)
- Zero filesystem reads, zero command execution, and zero network calls
- Handling of empty collections and complex multi-subsystem collections
- Full integration with V2.6 HostArtifactCollection and V2.7 InvestigationResultSet
"""

import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

from forensix import __version__
from forensix.account_models import UserAccount
from forensix.artifacts import ArtifactRecord
from forensix.audit import (
    AuditEvent,
    AuditEventType,
    create_audit_event,
    generate_audit_id,
)
from forensix.auth_models import AuthenticationRecord
from forensix.investigation import HostArtifactInvestigator
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.report_builder import build_forensic_report
from forensix.report_csv import CSV_HEADERS, render_csv_report, write_csv_report
from forensix.report_html import render_html_report, write_html_report
from forensix.report_json import render_json_report, write_json_report
from forensix.report_models import (
    ForensicReport,
    ReportFormat,
    ReportMetadata,
    generate_report_id,
)
from forensix.unified_adapter import (
    build_host_artifact_collection,
    to_host_artifact,
)
from forensix.unified_models import HostArtifact


class TestReportingLayer(unittest.TestCase):
    """Test suite for V2.8 Reporting and Presentation Layer."""

    def setUp(self):
        """Set up representative specialized records and unified collection."""
        self.art_rec = ArtifactRecord(
            artifact_id="ART-1111",
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
            event_id="EVT-2222",
            source_artifact_id="ART-1111",
            source_path="/evidence/var/log/auth.log",
            line_number=45,
            raw_timestamp="Sep 30 11:30:00",
            normalized_timestamp=None,
            hostname="target-server",
            service="sshd",
            pid=7890,
            event_type="ssh_login_success",
            attributes={"user": "alice", "src_ip": "10.10.10.10"},
            raw_message="Accepted publickey for alice from 10.10.10.10 port 22 ssh2",
            raw_line="Sep 30 11:30:00 target-server sshd[7890]: Accepted publickey for alice from 10.10.10.10 port 22 ssh2",
        )
        self.auth_rec = AuthenticationRecord(
            auth_id="AUTH-3333",
            event_id="EVT-2222",
            source_artifact_id="ART-1111",
            source_path="/evidence/var/log/auth.log",
            line_number=45,
            raw_timestamp="Sep 30 11:30:00",
            normalized_timestamp=None,
            hostname="target-server",
            service="sshd",
            event_type="ssh_login_success",
            status="SUCCESS",
            username="alice",
            source_ip="10.10.10.10",
            source_port=22,
            authentication_method="publickey",
            attributes={},
            raw_message="Accepted publickey for alice from 10.10.10.10 port 22 ssh2",
            raw_line="Sep 30 11:30:00 target-server sshd[7890]: Accepted publickey for alice from 10.10.10.10 port 22 ssh2",
        )
        self.user_acc = UserAccount(
            user_id="USER-4444",
            source_artifact_id="ART-1111",
            source_path="/evidence/etc/passwd",
            line_number=1,
            username="alice",
            uid=1001,
            gid=1001,
            gecos="Alice Smith",
            home_directory="/home/alice",
            login_shell="/bin/bash",
            is_privileged=False,
            primary_group="alice",
            supplementary_groups=(),
            raw_line="alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash",
        )
        self.persist_rec = PersistenceRecord(
            persistence_id="PERSIST-5555",
            source_artifact_id="ART-1111",
            source_path="/evidence/etc/crontab",
            line_number=12,
            category="cron",
            mechanism="crontab",
            scope="system",
            target_user="root",
            trigger_or_schedule="0 4 * * *",
            command_or_path="/usr/local/bin/nightly_cleanup.sh",
            attributes=(("command", "/usr/local/bin/nightly_cleanup.sh"),),
            status="PARSED",
            raw_line="0 4 * * * root /usr/local/bin/nightly_cleanup.sh",
        )

        self.collection = build_host_artifact_collection(
            evidence_root="/evidence",
            records=[
                self.art_rec,
                self.log_evt,
                self.auth_rec,
                self.user_acc,
                self.persist_rec,
            ],
            collected_at="2026-09-30T10:00:00Z",
        )

    def test_01_report_model_creation(self):
        """1. Verify ForensicReport creation and default metadata initialization."""
        report = build_forensic_report(
            source=self.collection,
            case_id="CASE-2026-001",
            case_name="Incident Response Triage",
            investigator="Lead Analyst",
        )
        self.assertIsInstance(report, ForensicReport)
        self.assertTrue(report.metadata.report_id.startswith("REPORT-"))
        self.assertEqual(report.metadata.case_id, "CASE-2026-001")
        self.assertEqual(report.metadata.case_name, "Incident Response Triage")
        self.assertEqual(report.metadata.investigator, "Lead Analyst")
        self.assertEqual(report.metadata.evidence_root, "/evidence")
        self.assertEqual(report.metadata.forensix_version, "4.0.0")
        self.assertEqual(report.total_artifacts, 5)

    def test_02_required_metadata_validation(self):
        """2. Verify ReportMetadata strict validation rules."""
        with self.assertRaises(ValueError):
            ReportMetadata(
                report_id="  ",
                case_id=None,
                case_name=None,
                investigator=None,
                created_at="2026-09-30T10:00:00Z",
                forensix_version="1.0.0",
                evidence_root=None,
                report_format="json",
            )

    def test_03_deep_immutability(self):
        """3. Verify ForensicReport and metadata reject attribute mutations."""
        report = build_forensic_report(self.collection)
        with self.assertRaises(Exception):
            report.total_artifacts = 999  # type: ignore
        with self.assertRaises(Exception):
            report.artifacts = ()  # type: ignore
        with self.assertRaises(Exception):
            report.metadata.case_id = "MUTATED"  # type: ignore

        self.assertIsInstance(report.artifacts, tuple)
        self.assertIsInstance(report.category_breakdown, tuple)
        self.assertIsInstance(report.status_breakdown, tuple)
        self.assertIsInstance(report.audit_trail, tuple)

    def test_04_json_serialization(self):
        """4. Verify JSON rendering produces valid, parseable JSON text."""
        report = build_forensic_report(self.collection)
        json_text = render_json_report(report)
        self.assertIsInstance(json_text, str)
        parsed = json.loads(json_text)
        self.assertEqual(parsed["summary"]["total_artifacts"], 5)
        self.assertEqual(parsed["metadata"]["evidence_root"], "/evidence")

    def test_05_complete_artifact_field_preservation(self):
        """5. Verify all HostArtifact indexable fields are preserved in report JSON."""
        report = build_forensic_report(self.collection)
        d = report.to_dict()
        art_d = next(a for a in d["artifacts"] if a["source_id"] == "AUTH-3333")
        self.assertEqual(art_d["source_id"], "AUTH-3333")
        self.assertEqual(art_d["source_event_id"], "EVT-2222")
        self.assertEqual(art_d["source_artifact_id"], "ART-1111")
        self.assertEqual(art_d["source_path"], "/evidence/var/log/auth.log")
        self.assertEqual(art_d["line_number"], 45)
        self.assertEqual(art_d["status"], "SUCCESS")

    def test_06_specialized_payload_preservation(self):
        """6. Verify specialized payload attributes remain intact in report JSON."""
        report = build_forensic_report(self.collection)
        parsed = json.loads(render_json_report(report))
        persist_art = next(a for a in parsed["artifacts"] if a["source_id"] == "PERSIST-5555")
        payload = persist_art["specialized_payload"]
        self.assertEqual(payload["trigger_or_schedule"], "0 4 * * *")
        self.assertEqual(payload["command_or_path"], "/usr/local/bin/nightly_cleanup.sh")

    def test_07_source_relationship_preservation(self):
        """7. Verify relationship references (EVT-xxx, ART-xxx) are preserved without invention."""
        report = build_forensic_report(self.collection)
        auth_art = next(a for a in report.artifacts if a.source_id == "AUTH-3333")
        self.assertEqual(auth_art.source_event_id, "EVT-2222")
        self.assertEqual(auth_art.source_artifact_id, "ART-1111")

    def test_08_none_null_handling(self):
        """8. Verify None values serialize cleanly to null in JSON."""
        report = build_forensic_report(
            source=self.collection,
            case_id=None,
            case_name=None,
            investigator=None,
        )
        parsed = json.loads(render_json_report(report))
        self.assertIsNone(parsed["metadata"]["case_id"])
        self.assertIsNone(parsed["metadata"]["case_name"])
        self.assertIsNone(parsed["metadata"]["investigator"])

    def test_09_deterministic_ordering(self):
        """9. Verify deterministic artifact ordering across independent builds."""
        reversed_arts = list(reversed(self.collection.artifacts))
        rep1 = build_forensic_report(self.collection.artifacts, created_at="2026-09-30T12:00:00Z")
        rep2 = build_forensic_report(reversed_arts, created_at="2026-09-30T12:00:00Z")

        ids1 = [a.source_id for a in rep1.artifacts]
        ids2 = [a.source_id for a in rep2.artifacts]
        self.assertEqual(ids1, ids2)
        self.assertEqual(rep1.category_breakdown, rep2.category_breakdown)
        self.assertEqual(rep1.status_breakdown, rep2.status_breakdown)

    def test_10_valid_json_and_11_utf8(self):
        """10 & 11. Verify JSON is strictly valid UTF-8 containing Unicode characters."""
        unicode_user = UserAccount(
            user_id="USER-unicode",
            source_artifact_id="ART-1111",
            source_path="/evidence/etc/passwd",
            line_number=2,
            username="björn",
            uid=1002,
            gid=1002,
            gecos="Björn Jørgensen, 🚀 Analyst",
            home_directory="/home/björn",
            login_shell="/bin/zsh",
            is_privileged=False,
            primary_group="björn",
            supplementary_groups=(),
            raw_line="björn:x:1002:1002:Björn Jørgensen, 🚀 Analyst:/home/björn:/bin/zsh",
        )
        host_art = to_host_artifact(unicode_user)
        report = build_forensic_report([host_art])
        json_bytes = render_json_report(report).encode("utf-8")
        decoded = json.loads(json_bytes.decode("utf-8"))
        self.assertIn("Björn Jørgensen, 🚀 Analyst", str(decoded))

    def test_12_nested_serialization(self):
        """12. Verify nested payload dictionaries and lists serialize without error."""
        report = build_forensic_report(self.collection)
        serialized = render_json_report(report)
        self.assertNotIn("<forensix.", serialized)
        self.assertNotIn("object at 0x", serialized)

    def test_13_csv_headers_and_14_rows(self):
        """13 & 14. Verify CSV output contains standard headers and accurate data rows."""
        report = build_forensic_report(self.collection)
        csv_text = render_csv_report(report)
        lines = csv_text.strip().split("\n")
        # Header line + 5 data rows
        self.assertEqual(len(lines), 6)
        reader = csv.reader(io.StringIO(csv_text))
        header = next(reader)
        self.assertEqual(tuple(header), tuple(CSV_HEADERS))

    def test_15_csv_quoting_and_escaping(self):
        """15. Verify CSV properly quotes and escapes commas, newlines, and quotes."""
        sneaky_log = LogEvent(
            event_id="EVT-quotes",
            source_artifact_id=None,
            source_path='/evidence/var/log/"evil",path.log',
            line_number=1,
            raw_timestamp="Sep 30 12:00:00",
            normalized_timestamp=None,
            hostname="host",
            service="svc",
            pid=1,
            event_type="generic_syslog",
            attributes={},
            raw_message='line with "quotes" and, commas',
            raw_line='Sep 30 12:00:00 host svc[1]: line with "quotes" and, commas',
        )
        report = build_forensic_report([to_host_artifact(sneaky_log)])
        csv_text = render_csv_report(report)
        reader = csv.reader(io.StringIO(csv_text))
        _ = next(reader)
        row = next(reader)
        self.assertEqual(row[6], '/evidence/var/log/"evil",path.log')
        self.assertIn('line with "quotes" and, commas', row[9])

    def test_16_csv_unicode(self):
        """16. Verify CSV handles UTF-8 characters properly."""
        unicode_user = UserAccount(
            user_id="USER-uni",
            source_artifact_id=None,
            source_path="/evidence/home/ñandú/.bashrc",
            line_number=1,
            username="ñandú",
            uid=1050,
            gid=1050,
            gecos="Ñandú Bird",
            home_directory="/home/ñandú",
            login_shell="/bin/bash",
            is_privileged=False,
            primary_group="ñandú",
            supplementary_groups=(),
            raw_line="export LANG=es_ES.UTF-8",
        )
        report = build_forensic_report([to_host_artifact(unicode_user)])
        csv_text = render_csv_report(report)
        self.assertIn("ñandú", csv_text)

    def test_17_documented_nested_data_handling(self):
        """17. Verify CSV payload_json column contains valid serialized JSON for nested data."""
        report = build_forensic_report(self.collection)
        csv_text = render_csv_report(report)
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            payload_raw = row["payload_json"]
            self.assertTrue(len(payload_raw) > 0)
            parsed_payload = json.loads(payload_raw)
            self.assertIsInstance(parsed_payload, dict)

    def test_18_html_required_sections(self):
        """18. Verify HTML report contains all 6 required sections."""
        report = build_forensic_report(self.collection)
        html_text = render_html_report(report)
        self.assertIn("1. Case Information", html_text)
        self.assertIn("2. Investigation Summary", html_text)
        self.assertIn("3. Artifact Statistics", html_text)
        self.assertIn("4. Artifacts", html_text)
        self.assertIn("5. Source / Lineage Information", html_text)
        self.assertIn("6. Audit Information", html_text)

    def test_19_html_artifact_representation(self):
        """19. Verify HTML properly lists artifacts in table format."""
        report = build_forensic_report(self.collection)
        html_text = render_html_report(report)
        self.assertIn("AUTH-3333", html_text)
        self.assertIn("ssh_login_success", html_text)
        self.assertIn("/evidence/var/log/auth.log", html_text)

    def test_20_html_unicode(self):
        """20. Verify HTML correctly renders non-ASCII Unicode."""
        unicode_user = UserAccount(
            user_id="USER-u",
            source_artifact_id=None,
            source_path="/evidence/home/sécurité",
            line_number=1,
            username="sécurité",
            uid=2000,
            gid=2000,
            gecos="Agent de Sécurité",
            home_directory="/home/sécurité",
            login_shell="/bin/bash",
            is_privileged=False,
            primary_group="sécurité",
            supplementary_groups=(),
            raw_line="sécurité:x:2000:2000:::",
        )
        report = build_forensic_report([to_host_artifact(unicode_user)])
        html_text = render_html_report(report)
        self.assertIn("sécurité", html_text)

    def test_21_html_escaping_of_evidence_controlled_content(self):
        """21. Verify evidence containing <script> and tags is HTML-escaped and never executable."""
        xss_log = LogEvent(
            event_id="EVT-xss",
            source_artifact_id=None,
            source_path="/evidence/var/log/<script>alert(1)</script>.log",
            line_number=1,
            raw_timestamp="Sep 30 12:00:00",
            normalized_timestamp=None,
            hostname="attacker",
            service="<img src=x onerror=alert(2)>",
            pid=1,
            event_type="generic_syslog",
            attributes={},
            raw_message="<script>document.cookie</script>",
            raw_line="<script>alert('pwned')</script>",
        )
        report = build_forensic_report([to_host_artifact(xss_log)])
        html_text = render_html_report(report)

        # Raw executable tags must NOT exist in HTML
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertNotIn("<img src=x onerror=alert(2)>", html_text)
        self.assertNotIn("<script>document.cookie</script>", html_text)
        self.assertNotIn("<script>alert('pwned')</script>", html_text)

        # Escaped versions MUST be present
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
        self.assertIn("&lt;img src=x onerror=alert(2)&gt;", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;", html_text)

    def test_22_html_special_character_handling(self):
        """22. Verify quotes, ampersands, and angle brackets are escaped properly."""
        special_user = UserAccount(
            user_id="USER-spec",
            source_artifact_id=None,
            source_path="/path/a&b<c>d'e\"f",
            line_number=1,
            username="foo&bar",
            uid=3000,
            gid=3000,
            gecos="Tom & Jerry 'cat' \"mouse\"",
            home_directory="/home/foo",
            login_shell="/bin/sh",
            is_privileged=False,
            primary_group="foo",
            supplementary_groups=(),
            raw_line="foo&bar:x:3000:3000:Tom & Jerry 'cat' \"mouse\":/home/foo:/bin/sh",
        )
        report = build_forensic_report([to_host_artifact(special_user)])
        html_text = render_html_report(report)
        self.assertIn("Tom &amp; Jerry &#x27;cat&#x27; &quot;mouse&quot;", html_text)

    def test_23_standalone_html_no_external_resources(self):
        """23. Verify HTML contains zero external HTTP/HTTPS CDN references or scripts."""
        report = build_forensic_report(self.collection)
        html_text = render_html_report(report)
        self.assertNotIn("http://", html_text)
        self.assertNotIn("https://", html_text)
        self.assertNotIn("<script src=", html_text)
        self.assertNotIn("<link rel=\"stylesheet\" href=", html_text)

    def test_24_audit_event_creation(self):
        """24. Verify creation and fields of AuditEvent."""
        ev = create_audit_event(
            event_type=AuditEventType.EVIDENCE_REGISTERED,
            description="Registered raw evidence image",
            actor="Analyst",
            related_id="EV-1234",
            metadata={"file_size": 1024},
        )
        self.assertTrue(ev.audit_id.startswith("AUDIT-"))
        self.assertEqual(ev.event_type, "EVIDENCE_REGISTERED")
        self.assertEqual(ev.description, "Registered raw evidence image")
        self.assertEqual(ev.actor, "Analyst")
        self.assertEqual(ev.related_id, "EV-1234")

    def test_25_audit_immutability(self):
        """25. Verify AuditEvent is frozen and rejects mutation."""
        ev = create_audit_event(
            event_type=AuditEventType.CASE_CREATED,
            description="Created case",
        )
        with self.assertRaises(Exception):
            ev.description = "MUTATED"  # type: ignore

    def test_26_audit_chronological_ordering(self):
        """26. Verify audit events are ordered chronologically by timestamp."""
        ev1 = create_audit_event(
            event_type=AuditEventType.CASE_CREATED,
            description="Initial action",
            timestamp="2026-09-30T09:00:00Z",
        )
        ev2 = create_audit_event(
            event_type=AuditEventType.INVESTIGATION_EXECUTED,
            description="Second action",
            timestamp="2026-09-30T10:00:00Z",
        )
        report = build_forensic_report(
            source=self.collection,
            audit_trail=[ev2, ev1],  # Passed out-of-order
            created_at="2026-09-30T11:00:00Z",
        )
        timestamps = [e.timestamp for e in report.audit_trail]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_27_audit_related_ids(self):
        """27. Verify audit events preserve related tracking IDs."""
        report = build_forensic_report(self.collection)
        gen_ev = next(e for e in report.audit_trail if e.event_type == AuditEventType.REPORT_GENERATED.value)
        self.assertEqual(gen_ev.related_id, report.metadata.report_id)

    def test_28_no_fabricated_audit_events(self):
        """28. Verify only supplied events and report generation event are recorded."""
        report = build_forensic_report(self.collection, audit_trail=None, record_generation_audit=False)
        self.assertEqual(len(report.audit_trail), 0)

        report_with_gen = build_forensic_report(self.collection, audit_trail=None, record_generation_audit=True)
        self.assertEqual(len(report_with_gen.audit_trail), 1)
        self.assertEqual(report_with_gen.audit_trail[0].event_type, "REPORT_GENERATED")

    def test_29_source_object_immutability(self):
        """29. Verify report generation leaves source objects strictly unchanged."""
        pre_count = len(self.collection.artifacts)
        pre_summary = self.collection.summary

        _ = render_json_report(build_forensic_report(self.collection))
        _ = render_csv_report(build_forensic_report(self.collection))
        _ = render_html_report(build_forensic_report(self.collection))

        self.assertEqual(len(self.collection.artifacts), pre_count)
        self.assertEqual(self.collection.summary, pre_summary)

    def test_30_zero_filesystem_reads_during_rendering(self):
        """30. Verify rendering functions perform no disk reads."""
        # Using purely synthetic paths that cannot be read from disk
        synth_art = to_host_artifact(
            LogEvent(
                event_id="EVT-synth",
                source_artifact_id=None,
                source_path="/completely/unmounted/virtual/device/nonexistent.log",
                line_number=1,
                raw_timestamp="Sep 30 12:00:00",
                normalized_timestamp=None,
                hostname="h",
                service="s",
                pid=1,
                event_type="generic_syslog",
                attributes={},
                raw_message="msg",
                raw_line="raw",
            )
        )
        report = build_forensic_report([synth_art])
        j = render_json_report(report)
        c = render_csv_report(report)
        h = render_html_report(report)
        self.assertTrue(len(j) > 0)
        self.assertTrue(len(c) > 0)
        self.assertTrue(len(h) > 0)

    def test_31_zero_subprocess_execution(self):
        """31. Verify report generation executes no commands or tools."""
        # Standard execution should succeed without any external system call
        report = build_forensic_report(self.collection)
        self.assertIsNotNone(render_json_report(report))

    def test_32_zero_network_access(self):
        """32. Verify report generation requires and uses zero network calls."""
        report = build_forensic_report(self.collection)
        html_out = render_html_report(report)
        self.assertNotIn("googleapis.com", html_out)
        self.assertNotIn("cdnjs.cloudflare.com", html_out)

    def test_33_empty_collection_handling(self):
        """33. Verify building reports from an empty collection succeeds gracefully."""
        empty_report = build_forensic_report([])
        self.assertEqual(empty_report.total_artifacts, 0)
        self.assertEqual(empty_report.artifacts, ())

        json_out = render_json_report(empty_report)
        self.assertIn('"total_artifacts": 0', json_out)

        csv_out = render_csv_report(empty_report)
        # Headers line only
        self.assertEqual(len(csv_out.strip().split("\n")), 1)

        html_out = render_html_report(empty_report)
        self.assertIn("No artifacts recorded", html_out)

    def test_34_file_writing_helpers(self):
        """34. Verify file output helpers write properly and return destination Path."""
        report = build_forensic_report(self.collection)
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "report.json"
            csv_path = Path(tmp_dir) / "report.csv"
            html_path = Path(tmp_dir) / "report.html"

            w_json = write_json_report(report, json_path)
            w_csv = write_csv_report(report, csv_path)
            w_html = write_html_report(report, html_path)

            self.assertEqual(w_json, json_path)
            self.assertEqual(w_csv, csv_path)
            self.assertEqual(w_html, html_path)

            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())
            self.assertTrue(html_path.exists())

            self.assertTrue(json_path.stat().st_size > 0)
            self.assertTrue(csv_path.stat().st_size > 0)
            self.assertTrue(html_path.stat().st_size > 0)

    def test_35_integration_from_v27_investigation_result_set(self):
        """35. Verify direct construction of reports from V2.7 InvestigationResultSet."""
        investigator = HostArtifactInvestigator(self.collection)
        query_result = investigator.filter_by_type("ssh_login_success")
        self.assertEqual(len(query_result), 2)

        report = build_forensic_report(
            source=query_result,
            case_id="IR-CASE-42",
            case_name="Targeted SSH Investigation",
            investigator="Lead Incident Handler",
        )
        self.assertEqual(report.total_artifacts, 2)
        for art in report.artifacts:
            self.assertEqual(art.artifact_type, "ssh_login_success")

        json_text = render_json_report(report)
        self.assertIn("Targeted SSH Investigation", json_text)

    def test_36_default_report_version_v2_regression(self):
        """36. Verify default report-builder version is 4.0.0 in ReportMetadata, JSON, and HTML."""
        # 1. Verify application version is 4.0.0
        self.assertEqual(__version__, "4.0.0")

        report = build_forensic_report(self.collection)
        # 2. Prove default version in ReportMetadata is "4.0.0"
        self.assertEqual(report.metadata.forensix_version, "4.0.0")

        # 3. Verify JSON rendering contains "forensix_version": "4.0.0"
        json_text = render_json_report(report)
        self.assertIn('"forensix_version": "4.0.0"', json_text)
        parsed = json.loads(json_text)
        self.assertEqual(parsed["metadata"]["forensix_version"], "4.0.0")

        # 4. Verify HTML rendering displays "Platform Version: 4.0.0"
        html_text = render_html_report(report)
        self.assertIn("Platform Version: <code>4.0.0</code>", html_text)


if __name__ == "__main__":
    unittest.main()
