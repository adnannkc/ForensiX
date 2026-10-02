"""
Comprehensive Test Suite for ForensiX V3.6 Timeline Reporting.

Covers:
- JSON report rendering and structure
- HTML report rendering and structure
- Provenance preservation (paths, lines, artifact IDs, event IDs, raw data, attributes)
- Timestamp fidelity (aware -> Z, naive -> no tz, missing -> None, raw timestamp preserved)
- HTML security escaping (prevention of XSS / script injection)
- ReconstructedTimeline and TimelineQueryResult compatibility
- Preserved event ordering (matches canonical timeline)
- Empty timeline handling (event_count=0)
- Falsy value preservation (0, False, empty string, empty dict)
- Deterministic output generation
- Deep immutability of inputs
- Safe file-writing utilities
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_query import (
    TimelineQuery,
    TimelineQueryResult,
    query_timeline,
)
from forensix.timeline_reconstruction import (
    ReconstructedTimeline,
    reconstruct_timeline,
)
from forensix.timeline_reporting import (
    TimelineReport,
    generate_timeline_report,
    render_timeline_html,
    render_timeline_json,
    serialize_timeline_event,
    write_timeline_html_report,
    write_timeline_json_report,
)


class TestTimelineReporting(unittest.TestCase):
    def setUp(self) -> None:
        self.dt_aware_1 = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        self.dt_aware_2 = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
        self.dt_naive = datetime(2023, 1, 1, 12, 0, 0)

        self.ev_aware_1 = create_timeline_event(
            timestamp=self.dt_aware_1,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login",
            description="Accepted publickey for user alice",
            source_path="/var/log/auth.log",
            source_line=105,
            source_artifact_id="ART-101",
            source_event_id="EVT-201",
            raw_timestamp="2023-01-01T10:00:00Z",
            raw_data="Jan  1 10:00:00 server sshd[123]: Accepted publickey for alice",
            attributes={"user": "alice", "port": 22, "success": True, "attempts": 0},
        )

        self.ev_aware_2 = create_timeline_event(
            timestamp=self.dt_aware_2,
            category=TimelineCategory.FILESYSTEM,
            event_type="file_creation",
            description="File created: /etc/sudoers.d/custom",
            source_path="/etc/sudoers.d/custom",
            source_line=1,
            source_artifact_id="ART-102",
            source_event_id="EVT-202",
            raw_timestamp="2023-01-01T11:00:00Z",
            raw_data="metadata: create 2023-01-01T11:00:00Z",
            attributes={"path": "/etc/sudoers.d/custom", "mode": 440, "is_link": False},
        )

        self.ev_naive = create_timeline_event(
            timestamp=self.dt_naive,
            category=TimelineCategory.LOG,
            event_type="cron_job",
            description="Cron job executed",
            source_path="/var/log/syslog",
            source_line=50,
            source_artifact_id="ART-103",
            source_event_id="EVT-203",
            raw_timestamp="2023-01-01 12:00:00",
            raw_data="CRON[500]: (root) CMD (/usr/bin/backup)",
            attributes={"job": "backup"},
        )

        self.ev_missing = create_timeline_event(
            timestamp=None,
            raw_timestamp="Jan 1 09:30:00",
            category=TimelineCategory.LOG,
            event_type="syslog_message",
            description="Kernel ring buffer boot message",
            source_path="/var/log/kern.log",
            source_line=1,
            source_artifact_id="ART-104",
            source_event_id="EVT-204",
            raw_data="Linux version 5.15.0",
            attributes={},
        )

        self.timeline = reconstruct_timeline(
            [self.ev_aware_2, self.ev_missing, self.ev_aware_1, self.ev_naive]
        )

    # 1. Report Model & Generation Tests
    def test_01_generate_report_from_reconstructed_timeline(self) -> None:
        """Verify report generation from ReconstructedTimeline."""
        report = generate_timeline_report(
            self.timeline,
            case_id="CASE-2026-001",
            case_name="Incident Alpha",
            investigator="Det. Forensix",
            generated_at="2026-10-02T10:00:00Z",
        )
        self.assertIsInstance(report, TimelineReport)
        self.assertEqual(report.event_count, 4)
        self.assertEqual(len(report), 4)
        self.assertEqual(report.case_id, "CASE-2026-001")
        self.assertEqual(report.case_name, "Incident Alpha")
        self.assertEqual(report.investigator, "Det. Forensix")
        self.assertEqual(report.generated_at, "2026-10-02T10:00:00Z")
        self.assertIsNone(report.query_summary)

    def test_02_generate_report_from_query_result(self) -> None:
        """Verify report generation from TimelineQueryResult reports filtered count only."""
        q = TimelineQuery(category=TimelineCategory.AUTHENTICATION)
        q_res = query_timeline(self.timeline, q)
        self.assertEqual(q_res.total_events, 1)

        report = generate_timeline_report(q_res)
        self.assertEqual(report.event_count, 1)
        self.assertEqual(len(report.events), 1)
        self.assertEqual(report.events[0].event_type, "ssh_login")
        self.assertIsNotNone(report.query_summary)
        self.assertEqual(report.query_summary["category"], "authentication")

    def test_03_generate_report_from_raw_event_sequence(self) -> None:
        """Verify report generation from a raw sequence of TimelineEvents."""
        report = generate_timeline_report([self.ev_aware_1, self.ev_aware_2])
        self.assertEqual(report.event_count, 2)
        self.assertEqual(report.categories, {"authentication": 1, "filesystem": 1})

    def test_04_generate_report_empty_timeline(self) -> None:
        """Verify generating report on empty timeline produces event_count=0 without error."""
        empty_tl = reconstruct_timeline([])
        report = generate_timeline_report(empty_tl)
        self.assertEqual(report.event_count, 0)
        self.assertEqual(report.categories, {})
        self.assertEqual(report.event_types, {})
        self.assertEqual(report.timestamp_coverage["total_events"], 0)
        self.assertEqual(report.timestamp_coverage["timestamped_events"], 0)
        self.assertEqual(report.timestamp_coverage["missing_timestamp_events"], 0)
        self.assertEqual(len(report.events), 0)

    def test_05_input_validation(self) -> None:
        """Verify invalid timeline input raises ValueError or TypeError."""
        with self.assertRaises(ValueError):
            generate_timeline_report(None)  # type: ignore

        with self.assertRaises(TypeError):
            generate_timeline_report(["invalid", "string"])  # type: ignore

    # 2. JSON Serialization & Structure Tests
    def test_06_render_timeline_json_valid_and_structured(self) -> None:
        """Verify rendered JSON parses cleanly and contains all required sections."""
        json_str = render_timeline_json(self.timeline, indent=2)
        data = json.loads(json_str)

        self.assertEqual(data["report_type"], "timeline")
        self.assertEqual(data["report_version"], "3.6")
        self.assertEqual(data["event_count"], 4)
        self.assertIn("categories", data)
        self.assertIn("event_types", data)
        self.assertIn("timestamp_coverage", data)
        self.assertIn("events", data)
        self.assertEqual(len(data["events"]), 4)

    def test_07_json_category_and_event_type_summaries(self) -> None:
        """Verify category and event-type counts are accurate and sorted."""
        report = generate_timeline_report(self.timeline)
        self.assertEqual(
            report.categories,
            {"authentication": 1, "filesystem": 1, "log": 2},
        )
        self.assertEqual(
            report.event_types,
            {"cron_job": 1, "file_creation": 1, "ssh_login": 1, "syslog_message": 1},
        )

    def test_08_json_timestamp_coverage(self) -> None:
        """Verify timestamp coverage metrics distinguish aware, naive, and missing timestamps."""
        report = generate_timeline_report(self.timeline)
        tc = report.timestamp_coverage
        self.assertEqual(tc["total_events"], 4)
        self.assertEqual(tc["timestamped_events"], 3)
        self.assertEqual(tc["missing_timestamp_events"], 1)
        self.assertEqual(tc["aware_timestamps"], 2)
        self.assertEqual(tc["naive_timestamps"], 1)

    def test_09_json_timestamp_serialization_fidelity(self) -> None:
        """Verify aware timestamps format with 'Z', naive stay naive, missing are null."""
        data = json.loads(render_timeline_json(self.timeline))
        events = data["events"]

        # 1. Aware event 1
        ev1 = next(e for e in events if e["event_type"] == "ssh_login")
        self.assertEqual(ev1["timestamp"], "2023-01-01T10:00:00Z")
        self.assertEqual(ev1["raw_timestamp"], "2023-01-01T10:00:00Z")

        # 2. Naive event
        ev_naive = next(e for e in events if e["event_type"] == "cron_job")
        self.assertEqual(ev_naive["timestamp"], "2023-01-01T12:00:00")
        self.assertNotIn("Z", ev_naive["timestamp"])
        self.assertNotIn("+", ev_naive["timestamp"])

        # 3. Missing timestamp event
        ev_miss = next(e for e in events if e["event_type"] == "syslog_message")
        self.assertIsNone(ev_miss["timestamp"])
        self.assertEqual(ev_miss["raw_timestamp"], "Jan 1 09:30:00")

    def test_10_json_provenance_preservation(self) -> None:
        """Verify provenance fields are preserved verbatim in JSON output."""
        data = json.loads(render_timeline_json(self.timeline))
        ev = next(e for e in data["events"] if e["event_type"] == "ssh_login")
        self.assertEqual(ev["source_path"], "/var/log/auth.log")
        self.assertEqual(ev["source_line"], 105)
        self.assertEqual(ev["source_artifact_id"], "ART-101")
        self.assertEqual(ev["source_event_id"], "EVT-201")
        self.assertIn("Accepted publickey", ev["raw_data"])

    def test_11_json_falsy_values_preservation(self) -> None:
        """Verify falsy attribute values (0, False, empty dict, empty string) are preserved."""
        data = json.loads(render_timeline_json(self.timeline))
        ev_auth = next(e for e in data["events"] if e["event_type"] == "ssh_login")
        attrs = ev_auth["attributes"]
        self.assertEqual(attrs["attempts"], 0)
        self.assertIs(attrs["success"], True)

        ev_fs = next(e for e in data["events"] if e["event_type"] == "file_creation")
        self.assertIs(ev_fs["attributes"]["is_link"], False)

        ev_miss = next(e for e in data["events"] if e["event_type"] == "syslog_message")
        self.assertEqual(ev_miss["attributes"], {})

    # 3. HTML Rendering & Safety Tests
    def test_12_render_timeline_html_valid_structure(self) -> None:
        """Verify rendered HTML is self-contained and contains required sections."""
        html_str = render_timeline_html(
            self.timeline,
            case_id="CASE-88",
            case_name="Operation Watchtower",
            investigator="Agent 42",
        )
        self.assertTrue(html_str.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>ForensiX Timeline Report</title>", html_str)
        self.assertIn("<style>", html_str)
        self.assertIn("CASE-88", html_str)
        self.assertIn("Operation Watchtower", html_str)
        self.assertIn("Agent 42", html_str)
        self.assertIn("Category Breakdown", html_str)
        self.assertIn("Event Type Breakdown", html_str)
        self.assertIn("Chronological Timeline Events (4)", html_str)
        self.assertIn("Accepted publickey for user alice", html_str)
        self.assertIn("</html>", html_str)

    def test_13_html_escaping_prevents_xss(self) -> None:
        """Verify malicious strings in events are strictly escaped and never rendered as executable tags."""
        malicious_ev = create_timeline_event(
            timestamp=self.dt_aware_1,
            category=TimelineCategory.LOG,
            event_type="<script>alert('xss')</script>",
            description='Test "quotes" & <tags> \'single\'',
            source_path="/path/<inject>/test.log",
            source_line=1,
            source_artifact_id="<script>art</script>",
            source_event_id="<img src=x onerror=alert(1)>",
            raw_timestamp="<raw_ts>",
            raw_data="<script>document.cookie</script>",
            attributes={"payload": "<script>evil()</script>"},
        )
        html_str = render_timeline_html([malicious_ev])

        # Raw executable script tags must NOT exist in the body
        self.assertNotIn("<script>alert('xss')</script>", html_str)
        self.assertNotIn("<img src=x onerror=alert(1)>", html_str)
        self.assertNotIn("<script>document.cookie</script>", html_str)

        # Escaped representations MUST exist
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_str)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_str)
        self.assertIn("&lt;script&gt;document.cookie&lt;/script&gt;", html_str)
        self.assertIn("Test &quot;quotes&quot; &amp; &lt;tags&gt; &#x27;single&#x27;", html_str)

    def test_14_html_empty_timeline(self) -> None:
        """Verify HTML renders cleanly when timeline contains 0 events."""
        empty_tl = reconstruct_timeline([])
        html_str = render_timeline_html(empty_tl)
        self.assertIn("No timeline events recorded.", html_str)
        self.assertIn("Chronological Timeline Events (0)", html_str)

    def test_15_html_details_and_provenance(self) -> None:
        """Verify provenance details block renders in HTML."""
        html_str = render_timeline_html(self.timeline)
        self.assertIn("<details><summary>Provenance &amp; Data</summary>", html_str)
        self.assertIn("Source Event ID:", html_str)
        self.assertIn("EVT-201", html_str)
        self.assertIn("Raw Data:", html_str)
        self.assertIn("Attributes:", html_str)

    def test_16_html_query_summary_display(self) -> None:
        """Verify query filters are displayed in HTML when given a TimelineQueryResult."""
        q = TimelineQuery(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_creation",
            source_path="/etc/sudoers.d/custom",
        )
        q_res = query_timeline(self.timeline, q)
        html_str = render_timeline_html(q_res)
        self.assertIn("Applied Query Filters", html_str)
        self.assertIn("<code>category</code>", html_str)
        self.assertIn("filesystem", html_str)
        self.assertIn("<code>event_type</code>", html_str)
        self.assertIn("file_creation", html_str)

    # 4. Ordering Preservation Tests
    def test_17_report_preserves_canonical_v34_order(self) -> None:
        """Verify report events preserve exact V3.4 canonical chronological order."""
        report = generate_timeline_report(self.timeline)
        canonical_ids = [e.event_id for e in self.timeline.events]
        report_ids = [e.event_id for e in report.events]
        self.assertEqual(report_ids, canonical_ids)

        # In JSON
        data = json.loads(render_timeline_json(self.timeline))
        json_ids = [e["event_id"] for e in data["events"]]
        self.assertEqual(json_ids, canonical_ids)

    # 5. Determinism & Immutability Tests
    def test_18_determinism_json(self) -> None:
        """Verify render_timeline_json produces bit-for-bit identical output on repeated runs."""
        json1 = render_timeline_json(self.timeline)
        json2 = render_timeline_json(self.timeline)
        self.assertEqual(json1, json2)

    def test_19_determinism_html(self) -> None:
        """Verify render_timeline_html produces bit-for-bit identical output on repeated runs."""
        html1 = render_timeline_html(self.timeline)
        html2 = render_timeline_html(self.timeline)
        self.assertEqual(html1, html2)

    def test_20_input_immutability(self) -> None:
        """Verify report generation leaves source timeline and events completely unmodified."""
        orig_events = [e.to_dict() for e in self.timeline.events]
        orig_summary = dict(self.timeline.summary)

        # Generate both JSON and HTML
        _ = render_timeline_json(self.timeline)
        _ = render_timeline_html(self.timeline)

        new_events = [e.to_dict() for e in self.timeline.events]
        new_summary = dict(self.timeline.summary)

        self.assertEqual(orig_events, new_events)
        self.assertEqual(orig_summary, new_summary)

    # 6. File Writing Utility Tests
    def test_21_write_json_report_to_disk(self) -> None:
        """Verify write_timeline_json_report writes valid JSON to specified output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "sub" / "report.json"
            written = write_timeline_json_report(self.timeline, out_path, indent=2)
            self.assertEqual(written, out_path)
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["event_count"], 4)

    def test_22_write_html_report_to_disk(self) -> None:
        """Verify write_timeline_html_report writes valid HTML to specified output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "sub" / "report.html"
            written = write_timeline_html_report(self.timeline, out_path)
            self.assertEqual(written, out_path)
            self.assertTrue(out_path.exists())
            content = out_path.read_text(encoding="utf-8")
            self.assertIn("ForensiX Timeline Report", content)

    # 7. Edge & Corner Cases
    def test_23_unicode_and_special_characters(self) -> None:
        """Verify Unicode characters in filenames, descriptions, and attributes are preserved."""
        unicode_ev = create_timeline_event(
            timestamp=self.dt_aware_1,
            category=TimelineCategory.FILESYSTEM,
            event_type="file_touch",
            description="Created file: résumé_ñ_日本語.txt",
            source_path="/home/user/résumé_ñ_日本語.txt",
            attributes={"unicode_note": "✓ Success: 100% verified 🛡️"},
        )
        report = generate_timeline_report([unicode_ev])
        json_data = json.loads(render_timeline_json(report))
        ev_dict = json_data["events"][0]
        self.assertEqual(ev_dict["description"], "Created file: résumé_ñ_日本語.txt")
        self.assertEqual(ev_dict["source_path"], "/home/user/résumé_ñ_日本語.txt")
        self.assertEqual(ev_dict["attributes"]["unicode_note"], "✓ Success: 100% verified 🛡️")

    def test_24_generated_at_formatting(self) -> None:
        """Verify generated_at formats properly when given a datetime object."""
        now_dt = datetime(2026, 10, 2, 10, 30, 0, tzinfo=timezone.utc)
        report = generate_timeline_report(self.timeline, generated_at=now_dt)
        self.assertEqual(report.generated_at, "2026-10-02T10:30:00Z")
        self.assertIn("2026-10-02T10:30:00Z", render_timeline_json(report))
        self.assertIn("2026-10-02T10:30:00Z", render_timeline_html(report))

    def test_25_serialize_timeline_event_standalone(self) -> None:
        """Verify standalone serialize_timeline_event utility."""
        serialized = serialize_timeline_event(self.ev_aware_1)
        self.assertEqual(serialized["timestamp"], "2023-01-01T10:00:00Z")
        self.assertEqual(serialized["category"], "authentication")
        self.assertEqual(serialized["event_type"], "ssh_login")
        self.assertEqual(serialized["source_path"], "/var/log/auth.log")



if __name__ == "__main__":
    unittest.main()
