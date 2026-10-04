"""
Comprehensive Unit Test Suite for ForensiX V4.6 — Correlation & Detection Reporting.

Mandatory Test Scenarios:
 1. correlation JSON serialization
 2. correlation field preservation
 3. correlation deterministic ordering
 4. detection JSON serialization
 5. detection field preservation
 6. detection deterministic ordering
 7. provenance preservation
 8. correlation-to-event references
 9. detection-to-correlation references
10. detection-to-event references
11. empty correlation collection
12. empty detection collection
13. multiple correlations
14. multiple detections
15. mixed correlation types
16. matched and unmatched results
17. deterministic repeated serialization
18. input immutability
19. malformed input handling
20. speculative-language protection
21. V3 reporting regression
22. V4.1 regression
23. V4.2 regression
24. V4.3 regression
25. V4.4 regression
26. V4.5 regression
27. HTML generation
28. expected sections
29. IDs appear
30. rule names appear
31. provenance appears
32. no speculative verdicts
33. deterministic output structure
34. mandatory synthetic investigation tracing chain
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from forensix.artifacts import ArtifactCategory, ArtifactRecord, ArtifactType
from forensix.correlation_engine import (
    CorrelationConfig,
    CorrelationEngine,
    correlate_events,
)
from forensix.correlation_models import (
    DISALLOWED_SPECULATIVE_TERMS,
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
    create_correlation,
)
from forensix.correlation_reporting import (
    CorrelationReport,
    generate_correlation_report,
    render_correlation_html,
    render_correlation_json,
    serialize_correlation,
    write_correlation_html_report,
    write_correlation_json_report,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    compute_deterministic_detection_id,
    evaluate_rule,
    evaluate_rules,
)
from forensix.detection_reporting import (
    CorrelationDetectionReport,
    DetectionReport,
    InvestigationReport,
    generate_correlation_detection_report,
    generate_detection_report,
    generate_investigation_report,
    render_correlation_detection_html,
    render_correlation_detection_json,
    render_detection_html,
    render_detection_json,
    serialize_detection,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
    write_detection_html_report,
    write_detection_json_report,
)
from forensix.initial_rules import (
    RULE_NAME_SSH_AUTH_SUDO,
    RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
    RULE_NAME_ACCOUNT_PRIVILEGE,
    RULE_NAME_PERSISTENCE_FOLLOWUP,
    create_initial_rules,
    create_ssh_auth_sudo_rule,
)
from forensix.rule_models import ConditionOperator, DetectionRule, RuleCollection, RuleCondition, create_rule
from forensix.timeline_models import TimelineCategory, TimelineEvent, create_timeline_event
from forensix.timeline_reconstruction import ReconstructedTimeline, reconstruct_timeline
from forensix.timeline_reporting import generate_timeline_report, render_timeline_json


class TestCorrelationReporting(unittest.TestCase):
    """Tests for correlation reporting functionality (JSON, HTML, ordering, immutability)."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        self.t1 = datetime(2026, 10, 3, 10, 2, 0, tzinfo=timezone.utc)
        self.ev_id_1 = "TIMELINE-11111111-1111-4111-8111-111111111111"
        self.ev_id_2 = "TIMELINE-22222222-2222-4222-8222-222222222222"
        self.ev_id_3 = "TIMELINE-33333333-3333-4333-8333-333333333333"
        self.ev_id_4 = "TIMELINE-44444444-4444-4444-8444-444444444444"

        self.corr1 = create_correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.ev_id_1, self.ev_id_2],
            description="Observed SSH authentication followed by sudo invocation within 120.0s.",
            source_event_ids=["log-101", "log-102"],
            source_artifact_ids=["art-auth-log", "art-auth-log"],
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )
        self.corr2 = create_correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.ev_id_3, self.ev_id_4],
            description="Observed temporal proximity within 120.0s.",
            source_event_ids=["fs-1", "fs-2"],
            source_artifact_ids=["art-fs", "art-fs"],
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            attributes={"path": "/etc/shadow"},
        )

    def test_01_correlation_json_serialization(self) -> None:
        """Scenario 1: correlation JSON serialization produces valid dictionary and JSON."""
        d = serialize_correlation(self.corr1)
        self.assertEqual(d["correlation_id"], self.corr1.correlation_id)
        self.assertEqual(d["relationship_type"], "AUTHENTICATION_PRIVILEGE")
        self.assertEqual(d["event_ids"], [self.ev_id_1, self.ev_id_2])
        self.assertEqual(d["start_timestamp"], "2026-10-03T10:00:00Z")
        self.assertEqual(d["end_timestamp"], "2026-10-03T10:02:00Z")
        self.assertEqual(d["time_delta_seconds"], 120.0)

        # Ensure valid JSON string serialization
        json_str = render_correlation_json(self.corr1)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["summary"]["total_correlations"], 1)
        self.assertEqual(parsed["correlations"][0]["correlation_id"], self.corr1.correlation_id)

    def test_02_correlation_field_preservation(self) -> None:
        """Scenario 2: correlation field preservation (provenance, attributes, delta)."""
        d = serialize_correlation(self.corr1)
        self.assertEqual(d["source_event_ids"], ["log-101", "log-102"])
        self.assertEqual(d["source_artifact_ids"], ["art-auth-log"])
        self.assertEqual(d["attributes"], {"identity_user": "alice", "source_ip": "10.0.0.10"})
        self.assertEqual(d["description"], "Observed SSH authentication followed by sudo invocation within 120.0s.")

    def test_03_correlation_deterministic_ordering(self) -> None:
        """Scenario 3: correlation deterministic ordering regardless of input sequence."""
        report1 = generate_correlation_report([self.corr2, self.corr1])
        report2 = generate_correlation_report([self.corr1, self.corr2])
        self.assertEqual(report1.to_dict(), report2.to_dict())
        self.assertEqual(render_correlation_json(report1), render_correlation_json(report2))

    def test_11_empty_correlation_collection(self) -> None:
        """Scenario 11: empty correlation collection handles cleanly."""
        report = generate_correlation_report([])
        d = report.to_dict()
        self.assertEqual(d["summary"]["total_correlations"], 0)
        self.assertEqual(d["correlations"], [])
        json_str = render_correlation_json(report)
        self.assertIn('"total_correlations": 0', json_str)
        html_str = render_correlation_html(report)
        self.assertIn("No correlations identified", html_str)

    def test_13_multiple_correlations(self) -> None:
        """Scenario 13: multiple correlations rendered correctly."""
        report = generate_correlation_report([self.corr1, self.corr2])
        self.assertEqual(report.total_correlations, 2)
        d = report.to_dict()
        self.assertEqual(len(d["correlations"]), 2)
        self.assertEqual(d["summary"]["relationship_counts"]["AUTHENTICATION_PRIVILEGE"], 1)
        self.assertEqual(d["summary"]["relationship_counts"]["TEMPORAL"], 1)

    def test_15_mixed_correlation_types(self) -> None:
        """Scenario 15: mixed correlation types in a single collection."""
        corr3 = create_correlation(
            relationship_type=CorrelationType.SAME_USER,
            event_ids=[self.ev_id_1, self.ev_id_3],
            description="Same user activity.",
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            attributes={"identity_user": "alice"},
        )
        report = generate_correlation_report([self.corr1, self.corr2, corr3])
        self.assertEqual(report.total_correlations, 3)
        self.assertEqual(set(report.relationship_counts.keys()), {"AUTHENTICATION_PRIVILEGE", "TEMPORAL", "SAME_USER"})

    def test_17_deterministic_repeated_serialization(self) -> None:
        """Scenario 17: deterministic repeated serialization yields byte-for-byte identical output."""
        report = generate_correlation_report([self.corr1, self.corr2])
        json1 = render_correlation_json(report)
        json2 = render_correlation_json(report)
        self.assertEqual(json1, json2)
        html1 = render_correlation_html(report)
        html2 = render_correlation_html(report)
        self.assertEqual(html1, html2)

    def test_18_input_immutability(self) -> None:
        """Scenario 18: reporting does not mutate input Correlation instances."""
        orig_id = self.corr1.correlation_id
        orig_attrs = dict(self.corr1.attributes)
        report = generate_correlation_report([self.corr1])
        _ = report.to_dict()
        _ = render_correlation_json(report)
        _ = render_correlation_html(report)

        self.assertEqual(self.corr1.correlation_id, orig_id)
        self.assertEqual(dict(self.corr1.attributes), orig_attrs)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            self.corr1.description = "Mutated"  # type: ignore

    def test_19_malformed_input_handling(self) -> None:
        """Scenario 19: malformed input handling raises TypeError."""
        with self.assertRaises(ValueError):
            generate_correlation_report(None)  # type: ignore
        with self.assertRaises(TypeError):
            generate_correlation_report(["invalid-string"])  # type: ignore


class TestDetectionReporting(unittest.TestCase):
    """Tests for detection reporting functionality (JSON, HTML, ordering, immutability)."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        self.t1 = datetime(2026, 10, 3, 10, 2, 0, tzinfo=timezone.utc)
        self.rule = create_ssh_auth_sudo_rule()
        self.ev_id_1 = "TIMELINE-11111111-1111-4111-8111-111111111111"
        self.ev_id_2 = "TIMELINE-22222222-2222-4222-8222-222222222222"
        self.corr_id_1 = "CORR-55555555-5555-5555-8555-555555555555"

        self.ev_id_3 = "TIMELINE-33333333-3333-4333-8333-333333333333"
        self.ev_id_4 = "TIMELINE-44444444-4444-4444-8444-444444444444"

        self.det_match = DetectionResult(
            rule_id=self.rule.rule_id,
            rule_name=self.rule.name,
            matched_event_ids=[self.ev_id_1, self.ev_id_2],
            matched=True,
            matched_source_event_ids=["log-101", "log-102"],
            matched_source_artifact_ids=["art-auth-log"],
            matched_correlation_ids=[self.corr_id_1],
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            explanation="Observed SSH authentication followed by sudo invocation within 120.0s.",
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )
        self.det_nomatch = DetectionResult(
            rule_id=self.rule.rule_id,
            rule_name=self.rule.name,
            matched_event_ids=[self.ev_id_3, self.ev_id_4],
            matched=False,
            matched_source_event_ids=[],
            matched_source_artifact_ids=[],
            matched_correlation_ids=[],
            start_timestamp=None,
            end_timestamp=None,
            time_delta_seconds=None,
            explanation="No matching activity observed.",
            attributes={},
        )

    def test_04_detection_json_serialization(self) -> None:
        """Scenario 4: detection JSON serialization produces valid dictionary and JSON."""
        d = serialize_detection(self.det_match)
        self.assertEqual(d["detection_id"], self.det_match.detection_id)
        self.assertEqual(d["rule_id"], self.rule.rule_id)
        self.assertEqual(d["rule_name"], self.rule.name)
        self.assertTrue(d["matched"])
        self.assertEqual(d["matched_event_ids"], [self.ev_id_1, self.ev_id_2])
        self.assertEqual(d["start_timestamp"], "2026-10-03T10:00:00Z")
        self.assertEqual(d["end_timestamp"], "2026-10-03T10:02:00Z")
        self.assertEqual(d["time_delta_seconds"], 120.0)

        json_str = render_detection_json(self.det_match)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["summary"]["total_detections"], 1)
        self.assertEqual(parsed["detections"][0]["detection_id"], self.det_match.detection_id)

    def test_05_detection_field_preservation(self) -> None:
        """Scenario 5: detection field preservation (provenance, attributes, explanation)."""
        d = serialize_detection(self.det_match)
        self.assertEqual(d["matched_source_event_ids"], ["log-101", "log-102"])
        self.assertEqual(d["matched_source_artifact_ids"], ["art-auth-log"])
        self.assertEqual(d["matched_correlation_ids"], [self.corr_id_1])
        self.assertEqual(d["explanation"], "Observed SSH authentication followed by sudo invocation within 120.0s.")
        self.assertEqual(d["attributes"], {"identity_user": "alice", "source_ip": "10.0.0.10"})

    def test_06_detection_deterministic_ordering(self) -> None:
        """Scenario 6: detection deterministic ordering via detection_sort_key."""
        report1 = generate_detection_report([self.det_nomatch, self.det_match])
        report2 = generate_detection_report([self.det_match, self.det_nomatch])
        self.assertEqual(report1.to_dict(), report2.to_dict())
        self.assertEqual(render_detection_json(report1), render_detection_json(report2))

    def test_12_empty_detection_collection(self) -> None:
        """Scenario 12: empty detection collection handles cleanly."""
        report = generate_detection_report([])
        d = report.to_dict()
        self.assertEqual(d["summary"]["total_detections"], 0)
        self.assertEqual(d["summary"]["matched_detections"], 0)
        self.assertEqual(d["detections"], [])
        html_str = render_detection_html(report)
        self.assertIn("No detections identified", html_str)

    def test_14_multiple_detections(self) -> None:
        """Scenario 14: multiple detections handled and counted properly."""
        report = generate_detection_report([self.det_match, self.det_nomatch])
        self.assertEqual(report.total_detections, 2)
        self.assertEqual(report.matched_detections, 1)

    def test_16_matched_and_unmatched_results(self) -> None:
        """Scenario 16: matched and unmatched results filtering and serialization."""
        all_rep = generate_detection_report([self.det_match, self.det_nomatch], matched_only=False)
        self.assertEqual(all_rep.total_detections, 2)

        matched_rep = generate_detection_report([self.det_match, self.det_nomatch], matched_only=True)
        self.assertEqual(matched_rep.total_detections, 1)
        self.assertEqual(matched_rep.detections[0].detection_id, self.det_match.detection_id)

    def test_18_detection_input_immutability(self) -> None:
        """Scenario 18: reporting does not mutate input DetectionResult instances."""
        orig_id = self.det_match.detection_id
        report = generate_detection_report([self.det_match])
        _ = report.to_dict()
        _ = render_detection_json(report)
        _ = render_detection_html(report)

        self.assertEqual(self.det_match.detection_id, orig_id)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            self.det_match.matched = False  # type: ignore

    def test_20_speculative_language_protection(self) -> None:
        """Scenario 20: ensure no speculative language appears in default explanations or generated reports."""
        report = generate_detection_report([self.det_match])
        json_out = render_detection_json(report)
        html_out = render_detection_html(report)

        for term in DISALLOWED_SPECULATIVE_TERMS:
            self.assertNotIn(term.lower(), json_out.lower(), f"Disallowed term '{term}' found in JSON report")
            self.assertNotIn(term.lower(), html_out.lower(), f"Disallowed term '{term}' found in HTML report")


class TestInvestigationTraceabilityAndReports(unittest.TestCase):
    """Tests for integrated Investigation reporting (traceability, HTML generation, files)."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        self.t1 = datetime(2026, 10, 3, 10, 2, 0, tzinfo=timezone.utc)
        self.evt_ssh = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="auth_ssh_success",
            description="Accepted publickey for alice from 10.0.0.10 port 45122 ssh2",
            timestamp=self.t0,
            source_path="/var/log/auth.log",
            source_line=105,
            source_artifact_id="art-auth-log",
            source_event_id="log-auth-105",
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )
        self.evt_sudo = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="auth_sudo_command",
            description="alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
            timestamp=self.t1,
            source_path="/var/log/auth.log",
            source_line=142,
            source_artifact_id="art-auth-log",
            source_event_id="log-auth-142",
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )
        self.corr_auth_sudo = create_correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.evt_ssh.event_id, self.evt_sudo.event_id],
            description="Observed SSH authentication followed by sudo invocation within 120.0s.",
            source_event_ids=[self.evt_ssh.source_event_id, self.evt_sudo.source_event_id],
            source_artifact_ids=[self.evt_ssh.source_artifact_id, self.evt_sudo.source_artifact_id],
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )
        self.rule = create_ssh_auth_sudo_rule()
        self.det = DetectionResult(
            detection_id=compute_deterministic_detection_id(
                rule_id=self.rule.rule_id,
                matched_event_ids=[self.evt_ssh.event_id, self.evt_sudo.event_id],
                matched_correlation_ids=[self.corr_auth_sudo.correlation_id],
            ),
            rule_id=self.rule.rule_id,
            rule_name=self.rule.name,
            matched=True,
            matched_event_ids=(self.evt_ssh.event_id, self.evt_sudo.event_id),
            matched_source_event_ids=(self.evt_ssh.source_event_id, self.evt_sudo.source_event_id),
            matched_source_artifact_ids=(self.evt_ssh.source_artifact_id, self.evt_sudo.source_artifact_id),
            matched_correlation_ids=(self.corr_auth_sudo.correlation_id,),
            start_timestamp=self.t0,
            end_timestamp=self.t1,
            time_delta_seconds=120.0,
            explanation="Observed a successful SSH authentication followed by privileged sudo execution for the same identity within 300 seconds.",
            attributes={"identity_user": "alice", "source_ip": "10.0.0.10"},
        )

    def test_07_provenance_preservation(self) -> None:
        """Scenario 7: Full provenance chain is preserved in investigation report."""
        inv_rep = generate_correlation_detection_report(
            detections=[self.det],
            correlations=[self.corr_auth_sudo],
            timeline=[self.evt_ssh, self.evt_sudo],
        )
        d = inv_rep.to_dict()
        det_entry = d["detections"][0]
        self.assertEqual(det_entry["matched_correlation_ids"], [self.corr_auth_sudo.correlation_id])
        self.assertEqual(det_entry["matched_event_ids"], [self.evt_ssh.event_id, self.evt_sudo.event_id])
        self.assertEqual(det_entry["matched_source_artifact_ids"], ["art-auth-log"])
        self.assertEqual(det_entry["matched_source_event_ids"], ["log-auth-105", "log-auth-142"])

        # Check resolved supporting events
        supporting = det_entry["supporting_events"]
        self.assertEqual(len(supporting), 2)
        self.assertEqual(supporting[0]["source_path"], "/var/log/auth.log")
        self.assertEqual(supporting[0]["source_line"], 105)
        self.assertEqual(supporting[1]["source_path"], "/var/log/auth.log")
        self.assertEqual(supporting[1]["source_line"], 142)

    def test_08_correlation_to_event_references(self) -> None:
        """Scenario 8: correlation-to-event references are correctly linked."""
        inv_rep = generate_correlation_detection_report(
            detections=[],
            correlations=[self.corr_auth_sudo],
            timeline=[self.evt_ssh, self.evt_sudo],
        )
        corr_entry = inv_rep.to_dict()["correlations"][0]
        self.assertEqual(corr_entry["event_ids"], [self.evt_ssh.event_id, self.evt_sudo.event_id])

    def test_09_detection_to_correlation_references(self) -> None:
        """Scenario 9: detection-to-correlation references are properly resolved."""
        inv_rep = generate_correlation_detection_report(
            detections=[self.det],
            correlations=[self.corr_auth_sudo],
        )
        det_entry = inv_rep.to_dict()["detections"][0]
        resolved_corrs = det_entry["correlations"]
        self.assertEqual(len(resolved_corrs), 1)
        self.assertEqual(resolved_corrs[0]["correlation_id"], self.corr_auth_sudo.correlation_id)
        self.assertEqual(resolved_corrs[0]["relationship_type"], "AUTHENTICATION_PRIVILEGE")

    def test_10_detection_to_event_references(self) -> None:
        """Scenario 10: detection-to-event references are properly resolved."""
        inv_rep = generate_correlation_detection_report(
            detections=[self.det],
            timeline=[self.evt_ssh, self.evt_sudo],
        )
        det_entry = inv_rep.to_dict()["detections"][0]
        resolved_evts = det_entry["supporting_events"]
        self.assertEqual(len(resolved_evts), 2)
        self.assertEqual(resolved_evts[0]["event_id"], self.evt_ssh.event_id)
        self.assertEqual(resolved_evts[1]["event_id"], self.evt_sudo.event_id)

    def test_27_to_33_html_reporting_features(self) -> None:
        """Scenarios 27-33: HTML generation, sections, IDs, rules, provenance, no verdicts, determinism."""
        inv_rep = generate_correlation_detection_report(
            detections=[self.det],
            correlations=[self.corr_auth_sudo],
            timeline=[self.evt_ssh, self.evt_sudo],
            case_id="CASE-2026-001",
            investigator="Forensic Examiner Alice",
        )
        html_out = render_correlation_detection_html(inv_rep)

        # 27. HTML generation
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("<html", html_out)

        # 28. Expected sections
        self.assertIn("Investigation Summary", html_out)
        self.assertIn("Detection Results", html_out)
        self.assertIn("Correlations", html_out)
        self.assertIn("Timeline Events", html_out)

        # 29. IDs appear
        self.assertIn(self.det.detection_id, html_out)
        self.assertIn(self.corr_auth_sudo.correlation_id, html_out)
        self.assertIn(self.evt_ssh.event_id, html_out)
        self.assertIn(self.evt_sudo.event_id, html_out)

        # 30. Rule names appear
        self.assertIn(self.rule.name, html_out)

        # 31. Provenance appears
        self.assertIn("/var/log/auth.log", html_out)
        self.assertIn("Line: 105", html_out)
        self.assertIn("Line: 142", html_out)
        self.assertIn("art-auth-log", html_out)

        # 32. No speculative verdicts
        for term in DISALLOWED_SPECULATIVE_TERMS:
            self.assertNotIn(term.lower(), html_out.lower())

        # 33. Deterministic output structure
        html_out2 = render_correlation_detection_html(inv_rep)
        self.assertEqual(html_out, html_out2)

    def test_file_writing_utilities(self) -> None:
        """Verify write_* utilities create files with exact content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "report.json"
            html_path = Path(tmpdir) / "report.html"

            inv_rep = generate_correlation_detection_report(
                detections=[self.det],
                correlations=[self.corr_auth_sudo],
                timeline=[self.evt_ssh, self.evt_sudo],
            )
            ret_json = write_correlation_detection_json_report(inv_rep, json_path)
            ret_html = write_correlation_detection_html_report(inv_rep, html_path)

            self.assertEqual(ret_json, json_path)
            self.assertEqual(ret_html, html_path)
            self.assertTrue(json_path.exists())
            self.assertTrue(html_path.exists())

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(data["summary"]["detection_count"], 1)

            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn(self.det.detection_id, content)


class TestMandatorySyntheticInvestigation(unittest.TestCase):
    """
    Mandatory Synthetic Investigation Scenario:
    Timeline:
    10:00: Successful SSH authentication (user = alice, source = 10.0.0.10)
    10:02: Sudo command (user = alice, source = 10.0.0.10)
    10:03: Persistence modification (persistence path)
    10:10: Unrelated event (user = bob)

    Using:
    - V3 timeline objects
    - V4.2 correlation engine
    - V4.5 initial rules
    - V4.4 detection engine
    - V4.6 reporting layer
    """

    def test_synthetic_investigation_traceability(self) -> None:
        t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 10, 3, 10, 2, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 10, 3, 10, 3, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 10, 3, 10, 10, 0, tzinfo=timezone.utc)

        # 1. Timeline Events
        evt1_ssh = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for alice from 10.0.0.10 port 52244 ssh2",
            timestamp=t0,
            source_path="/var/log/auth.log",
            source_line=210,
            source_artifact_id="art-auth-log",
            source_event_id="log-auth-210",
            attributes={"username": "alice", "source_ip": "10.0.0.10", "session_id": "sess-alice"},
        )

        evt2_sudo = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/crontab -e",
            timestamp=t1,
            source_path="/var/log/auth.log",
            source_line=245,
            source_artifact_id="art-auth-log",
            source_event_id="log-auth-245",
            attributes={
                "username": "alice",
                "source_ip": "10.0.0.10",
                "session_id": "sess-alice",
                "command": "/usr/bin/crontab -e",
            },
        )

        evt3_persist = create_timeline_event(
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="File modified: /var/spool/cron/crontabs/alice",
            timestamp=t2,
            source_path="/var/spool/cron/crontabs/alice",
            source_line=1,
            source_artifact_id="art-cron-alice",
            source_event_id="fs-cron-1",
            attributes={
                "username": "alice",
                "path": "/var/spool/cron/crontabs/alice",
                "command": "/opt/backup.sh",
            },
        )

        evt4_unrelated = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for bob from 192.168.1.50 port 41233 ssh2",
            timestamp=t3,
            source_path="/var/log/auth.log",
            source_line=300,
            source_artifact_id="art-auth-log",
            source_event_id="log-auth-300",
            attributes={"username": "bob", "source_ip": "192.168.1.50"},
        )

        events = [evt1_ssh, evt2_sudo, evt3_persist, evt4_unrelated]

        # 2. Correlate with V4.2 Engine
        corr_engine = CorrelationEngine()
        corr_collection = corr_engine.correlate(events)

        # Verify expected correlations were produced
        self.assertGreaterEqual(len(corr_collection), 2)
        corr_types = {c.relationship_type for c in corr_collection}
        self.assertIn(CorrelationType.AUTHENTICATION_PRIVILEGE, corr_types)

        # 3. Detect with V4.5 Rules and V4.4 Engine
        rules = create_initial_rules()
        det_engine = DetectionEngine(rules=rules)
        det_results = det_engine.evaluate(
            timeline=events,
            correlations=corr_collection,
        )

        # Verify Rule 1 (SSH auth followed by sudo) matched
        rule1_matches = [d for d in det_results if d.rule_name == RULE_NAME_SSH_AUTH_SUDO and d.matched]
        self.assertEqual(len(rule1_matches), 1)
        det_rule1 = rule1_matches[0]

        # 4. Generate V4.6 Investigation Report
        report = generate_correlation_detection_report(
            detections=det_results,
            correlations=corr_collection,
            timeline=events,
            case_id="SYNTHETIC-INVESTIGATION-01",
            investigator="ForensiX Verification Agent",
        )

        # 5. Verify Investigator Traceability Chain in serialized report:
        # Detection -> Matched Correlation -> SSH event -> Sudo event -> Source Provenance
        rep_dict = report.to_dict()
        det_entries = [d for d in rep_dict["detections"] if d["detection_id"] == det_rule1.detection_id]
        self.assertEqual(len(det_entries), 1)
        det_entry = det_entries[0]

        # Step A: Detection -> Matched Correlation
        self.assertTrue(len(det_entry["matched_correlation_ids"]) > 0)
        matched_corr_id = det_entry["matched_correlation_ids"][0]
        self.assertTrue(any(c["correlation_id"] == matched_corr_id for c in det_entry["correlations"]))
        corr_obj = [c for c in det_entry["correlations"] if c["correlation_id"] == matched_corr_id][0]
        self.assertEqual(corr_obj["relationship_type"], "AUTHENTICATION_PRIVILEGE")

        # Step B: Correlation -> Supporting Events
        self.assertIn(evt1_ssh.event_id, corr_obj["event_ids"])
        self.assertIn(evt2_sudo.event_id, corr_obj["event_ids"])

        # Step C: Supporting Events -> Source Provenance
        supporting_map = {e["event_id"]: e for e in det_entry["supporting_events"]}
        self.assertIn(evt1_ssh.event_id, supporting_map)
        self.assertIn(evt2_sudo.event_id, supporting_map)

        ssh_serialized = supporting_map[evt1_ssh.event_id]
        self.assertEqual(ssh_serialized["source_path"], "/var/log/auth.log")
        self.assertEqual(ssh_serialized["source_line"], 210)
        self.assertEqual(ssh_serialized["source_artifact_id"], "art-auth-log")
        self.assertEqual(ssh_serialized["source_event_id"], "log-auth-210")

        sudo_serialized = supporting_map[evt2_sudo.event_id]
        self.assertEqual(sudo_serialized["source_path"], "/var/log/auth.log")
        self.assertEqual(sudo_serialized["source_line"], 245)
        self.assertEqual(sudo_serialized["source_artifact_id"], "art-auth-log")
        self.assertEqual(sudo_serialized["source_event_id"], "log-auth-245")

        # 6. Verify HTML Rendering Contains Traceable Elements
        html_out = render_correlation_detection_html(report)
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, html_out)
        self.assertIn("AUTHENTICATION_PRIVILEGE", html_out)
        self.assertIn("/var/log/auth.log", html_out)
        self.assertIn("Line: 210", html_out)
        self.assertIn("Line: 245", html_out)
        self.assertIn("SYNTHETIC-INVESTIGATION-01", html_out)


class TestRegressionsV1ThroughV45(unittest.TestCase):
    """Verify regressions across earlier milestones V1-V3, V4.1-V4.5."""

    def test_21_v3_reporting_regression(self) -> None:
        """Scenario 21: V3 timeline reporting continues to work without disruption."""
        t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        evt = create_timeline_event(
            timestamp=t0,
            category=TimelineCategory.AUTHENTICATION,
            event_type="auth_ssh_success",
            source_path="/var/log/auth.log",
            source_line=1,
            description="Test V3 event",
        )
        timeline = reconstruct_timeline([evt])
        v3_report = generate_timeline_report(timeline)
        v3_json = render_timeline_json(v3_report)
        self.assertIn(evt.event_id, v3_json)

    def test_22_v41_regression(self) -> None:
        """Scenario 22: V4.1 correlation models remain fully functional."""
        t0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        ev_id_1 = "TIMELINE-11111111-1111-4111-8111-111111111111"
        ev_id_2 = "TIMELINE-22222222-2222-4222-8222-222222222222"
        corr = create_correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[ev_id_1, ev_id_2],
            description="Sequence correlation",
            start_timestamp=t0,
            end_timestamp=t0,
            time_delta_seconds=0.0,
        )
        self.assertEqual(corr.relationship_type, CorrelationType.TEMPORAL)
        col = CorrelationCollection([corr])
        self.assertEqual(len(col), 1)

    def test_23_v42_regression(self) -> None:
        """Scenario 23: V4.2 correlation engine works identically."""
        engine = CorrelationEngine()
        res = engine.correlate([])
        self.assertEqual(len(res), 0)

    def test_24_v43_regression(self) -> None:
        """Scenario 24: V4.3 rule models work identically."""
        cond = RuleCondition(field="username", operator=ConditionOperator.EQUALS, value="alice")
        rule = create_rule(
            name="Test Rule",
            description="Observes test condition.",
            detection_description="Observed test condition.",
            required_categories=[TimelineCategory.AUTHENTICATION],
            conditions=[cond],
        )
        self.assertTrue(rule.rule_id.startswith("RULE-"))

    def test_25_v44_regression(self) -> None:
        """Scenario 25: V4.4 detection engine works identically."""
        det_engine = DetectionEngine(rules=[])
        results = det_engine.evaluate(timeline=[])
        self.assertEqual(len(results), 0)

    def test_26_v45_regression(self) -> None:
        """Scenario 26: V4.5 initial rules create exactly 4 canonical rules."""
        rules = create_initial_rules()
        self.assertEqual(len(rules), 4)
        rule_names = {r.name for r in rules}
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, rule_names)
        self.assertIn(RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS, rule_names)
        self.assertIn(RULE_NAME_ACCOUNT_PRIVILEGE, rule_names)
        self.assertIn(RULE_NAME_PERSISTENCE_FOLLOWUP, rule_names)


if __name__ == "__main__":
    unittest.main()
