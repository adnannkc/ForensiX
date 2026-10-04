"""
ForensiX V3.8 — Final Verification, Hardening & Release Readiness Test Suite.

Provides exhaustive verification for:
1.  Full Pipeline Orchestration & End-to-End Integration (Evidence -> Adapters -> Reconstruction -> Query -> Report -> CLI)
2.  Full Timeline CLI Execution (JSON and HTML reporting)
3.  Multi-Criteria Filtering & Strict AND Semantics
4.  Empty Query Handling (Exit code 0, event_count 0, report generated)
5.  Error Handling & Non-Traceback Graceful Exits (Invalid category, timestamp, format, missing paths)
6.  Evidence Immutability & Cryptographic Hash Preservation (SHA-256 before == after)
7.  Determinism & Reconstruction Idempotency (reconstruct(reconstruct(x)) == reconstruct(x))
8.  Source Provenance Chain Integrity (Raw evidence -> Artifact -> Event -> Report)
9.  Timestamp Normalization Fidelity (Aware UTC conversion, naive preservation, missing preservation)
10. Deep Immutability across all 5 Core V3 Dataclasses
11. Security & HTML Injection / XSS Sanitization
12. Offline Safety & Zero External Invocations (No subprocess, no socket)
13. V1 & V2 Regression Compatibility
14. Package Metadata & Version Consistency ("2.0.1")
15. V3 Scope Audit & Rejection of Speculative/Investigative Conclusions
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import types
from typing import Dict, List, Optional
import unittest
from unittest.mock import patch

from forensix import __version__
from forensix.analyzer import analyze_evidence
from forensix.artifact_adapters import (
    AuthenticationAdapter,
    FilesystemAdapter,
    LogAdapter,
    adapt_artifacts,
)
from forensix.artifacts import ArtifactCategory, ArtifactRecord, ArtifactType
from forensix.auth_models import AuthenticationRecord, AuthEventType, AuthStatus
from forensix.hasher import compute_hashes
from forensix.log_models import LogEvent, LogEventType
from forensix.main import main
from forensix.timeline_cli import (
    build_timeline_parser,
    execute_timeline_cli,
    timeline_main,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
    generate_timeline_id,
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
    REPORT_TYPE,
    REPORT_VERSION,
    TimelineReport,
    generate_timeline_report,
    render_timeline_html,
    render_timeline_json,
    write_timeline_html_report,
    write_timeline_json_report,
)
from forensix.timestamp_normalizer import (
    NormalizedTimestamp,
    normalize_timestamp,
    parse_timestamp,
)
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


def compute_evidence_hashes(directory: Path) -> Dict[str, str]:
    """Calculate SHA-256 for all regular files in a directory."""
    hashes = {}
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(directory))
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            hashes[rel] = h.hexdigest()
    return hashes


class TestTimelineV3Hardening(unittest.TestCase):
    """Exhaustive V3.8 hardening, regression, and safety test suite."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_dir = Path(self.temp_dir.name) / "evidence"
        self.evidence_dir.mkdir(parents=True)
        self.output_dir = Path(self.temp_dir.name) / "reports"
        self.output_dir.mkdir(parents=True)

        # Create structured synthetic evidence fixture
        self._populate_synthetic_evidence()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _populate_synthetic_evidence(self) -> None:
        """Create safe, deterministic, synthetic Linux log & artifact evidence."""
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True)
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True)

        # 1. /var/log/syslog (with ISO-8601 aware timestamps)
        syslog_content = (
            "2026-09-30T10:00:00.123456+00:00 host1 systemd[1]: Starting OpenSSH server...\n"
            "2026-09-30T10:00:01.000000+00:00 host1 sshd[1234]: Server listening on 0.0.0.0 port 22.\n"
            "2026-09-30T10:15:30.500000+00:00 host1 cron[567]: (root) CMD (/usr/bin/backup.sh)\n"
        )
        (log_dir / "syslog").write_text(syslog_content, encoding="utf-8")

        # 2. /var/log/auth.log (with standard syslog timestamp)
        auth_content = (
            "Sep 30 10:05:00 host1 sshd[2001]: Accepted publickey for alice from 192.168.1.10 port 45678 ssh2\n"
            "Sep 30 10:06:00 host1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
            "Sep 30 10:10:00 host1 sshd[2005]: Failed password for invalid user bob from 10.0.0.99 port 55555 ssh2\n"
        )
        (log_dir / "auth.log").write_text(auth_content, encoding="utf-8")

        # 3. /etc/passwd and /etc/shadow
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1000:1000:Alice Admin:/home/alice:/bin/bash\n"
            "bob:x:1001:1001:Bob Test:/home/bob:/bin/sh\n"
        )
        (etc_dir / "passwd").write_text(passwd_content, encoding="utf-8")

        shadow_content = (
            "root:$6$salt$hash:19000:0:99999:7:::\n"
            "alice:$6$salt$hash2:19000:0:99999:7:::\n"
            "bob:!:19000:0:99999:7:::\n"
        )
        (etc_dir / "shadow").write_text(shadow_content, encoding="utf-8")

    # =========================================================================
    # 1. Pipeline Orchestration & End-to-End Integration
    # =========================================================================
    def test_01_full_pipeline_orchestration(self):
        """Verify seamless execution: Evidence -> Triage -> Adapters -> Reconstruction -> Query -> Report."""
        # Step A: Triage analysis
        triage_config = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            collect_audit=False,
        )
        orchestrator = TriageOrchestrator(triage_config)
        triage_result = orchestrator.run()
        self.assertIsNotNone(triage_result)
        self.assertIsNotNone(triage_result.artifacts)
        self.assertGreater(len(triage_result.artifacts.artifacts), 0)

        # Step B: Adapt artifacts into TimelineEvents
        events = adapt_artifacts(triage_result.artifacts.artifacts, ignore_unsupported=True)
        self.assertGreater(len(events), 0)
        self.assertTrue(all(isinstance(e, TimelineEvent) for e in events))

        # Step C: Reconstruct timeline
        reconstructed = reconstruct_timeline(events)
        self.assertIsInstance(reconstructed, ReconstructedTimeline)
        self.assertGreater(reconstructed.total_events, 0)

        # Step D: Query timeline (filter category AUTHENTICATION)
        query = TimelineQuery(category=TimelineCategory.AUTHENTICATION)
        filtered = query_timeline(reconstructed, query)
        self.assertIsInstance(filtered, TimelineQueryResult)
        for e in filtered.events:
            self.assertEqual(e.category, TimelineCategory.AUTHENTICATION)

        # Step E: Generate report
        report = generate_timeline_report(
            filtered,
            case_id="CASE-V3-HARDENING",
            case_name="Hardening Integration",
            investigator="Lead Analyst",
        )
        self.assertIsInstance(report, TimelineReport)
        self.assertEqual(report.case_id, "CASE-V3-HARDENING")
        self.assertEqual(report.event_count, filtered.total_events)

        # Step F: Render JSON and HTML
        json_output = render_timeline_json(report)
        html_output = render_timeline_html(report)
        self.assertTrue(json_output.startswith("{"))
        self.assertIn("<!DOCTYPE html>", html_output)

    # =========================================================================
    # 2. Full Timeline CLI Execution (JSON & HTML)
    # =========================================================================
    def test_02_cli_full_timeline_json_and_html(self):
        """Verify CLI produces valid JSON and HTML reports with exit code 0."""
        # Run JSON
        json_target = self.output_dir / "timeline.json"
        exit_code_json, report_json = execute_timeline_cli([
            str(self.evidence_dir),
            "--format", "json",
            "--output", str(json_target),
            "--case-id", "CASE-CLI-JSON",
            "--investigator", "Investigator A",
        ])
        self.assertEqual(exit_code_json, 0)
        self.assertIsNotNone(report_json)
        self.assertTrue(json_target.exists())
        with open(json_target, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["report_type"], REPORT_TYPE)
        self.assertEqual(data["report_version"], REPORT_VERSION)
        self.assertEqual(data["forensix_version"], __version__)
        self.assertEqual(data["metadata"]["case_id"], "CASE-CLI-JSON")
        self.assertGreater(len(data["events"]), 0)

        # Run HTML
        html_target = self.output_dir / "timeline.html"
        exit_code_html, report_html = execute_timeline_cli([
            str(self.evidence_dir),
            "--format", "html",
            "--output", str(html_target),
            "--case-id", "CASE-CLI-HTML",
        ])
        self.assertEqual(exit_code_html, 0)
        self.assertIsNotNone(report_html)
        self.assertTrue(html_target.exists())
        content = html_target.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("CASE-CLI-HTML", content)

    # =========================================================================
    # 3. Multi-Criteria Filtering & AND Semantics
    # =========================================================================
    def test_03_multi_criteria_filtering_and_semantics(self):
        """Verify single and combined query filters adhere strictly to logical AND semantics."""
        # 1. Category filter
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--output", str(self.output_dir / "auth_filter.json"),
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        for e in report.events:
            self.assertEqual(e.category, TimelineCategory.AUTHENTICATION)

        # 2. Text filter (case-sensitive and case-insensitive)
        exit_code_ci, report_ci = execute_timeline_cli([
            str(self.evidence_dir),
            "--text", "ALICE",
            "--output", str(self.output_dir / "text_ci.json"),
        ])
        self.assertEqual(exit_code_ci, 0)
        self.assertGreater(report_ci.event_count, 0)

        exit_code_cs, report_cs = execute_timeline_cli([
            str(self.evidence_dir),
            "--text", "ALICE",
            "--case-sensitive",
            "--output", str(self.output_dir / "text_cs.json"),
        ])
        self.assertEqual(exit_code_cs, 0)
        self.assertEqual(report_cs.event_count, 0)  # "alice" was lowercase in auth.log

        # 3. Combined AND filter (Category + Text + Source Path)
        auth_file = str(self.evidence_dir / "var" / "log" / "auth.log")
        exit_code_comb, report_comb = execute_timeline_cli([
            str(self.evidence_dir),
            "--category", "AUTHENTICATION",
            "--text", "publickey",
            "--source-path", auth_file,
            "--output", str(self.output_dir / "combined.json"),
        ])
        self.assertEqual(exit_code_comb, 0)
        self.assertEqual(report_comb.event_count, 1)
        self.assertIn("Accepted publickey", report_comb.events[0].description)

    # =========================================================================
    # 4. Empty Query Handling
    # =========================================================================
    def test_04_empty_query_result(self):
        """Verify queries matching zero events complete cleanly with exit code 0."""
        empty_out = self.output_dir / "empty.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--text", "NON_EXISTENT_STRING_XYZ_9999",
            "--output", str(empty_out),
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 0)
        self.assertTrue(empty_out.exists())

        with open(empty_out, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["summary"]["event_count"], 0)
        self.assertEqual(data["events"], [])

    # =========================================================================
    # 5. Error Handling & Non-Traceback Graceful Exits
    # =========================================================================
    def test_05_error_handling_graceful_exits(self):
        """Verify invalid user inputs exit with non-zero code and clean error messages without tracebacks."""
        stderr_capture = io.StringIO()

        # 1. Invalid category
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--category", "MALWARE_DETECTION",
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Invalid category", stderr_capture.getvalue())

        # 2. Invalid timestamp format
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--start", "not-a-timestamp",
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Invalid timeline filter", stderr_capture.getvalue())

        # 3. Invalid output format
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--format", "pdf",
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Unsupported timeline format", stderr_capture.getvalue())

        # 4. Non-existent evidence directory
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir / "does_not_exist"),
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Evidence directory does not exist", stderr_capture.getvalue())

        # 5. File passed where directory expected
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir / "var" / "log" / "syslog"),
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Evidence path is not a directory", stderr_capture.getvalue())

        # 6. Output path inside evidence directory
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            code, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--output", str(self.evidence_dir / "nested_report.html"),
            ])
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Error: Output report path cannot be within", stderr_capture.getvalue())

    # =========================================================================
    # 6. Evidence Immutability & Cryptographic Hash Preservation
    # =========================================================================
    def test_06_evidence_immutability_preservation(self):
        """Verify evidence files are untouched; before SHA-256 == after SHA-256."""
        hashes_before = compute_evidence_hashes(self.evidence_dir)
        self.assertGreater(len(hashes_before), 0)

        # Run multiple operations over the evidence
        execute_timeline_cli([str(self.evidence_dir), "--format", "json", "-o", str(self.output_dir / "run1.json")])
        execute_timeline_cli([str(self.evidence_dir), "--format", "html", "-o", str(self.output_dir / "run2.html")])
        execute_timeline_cli([str(self.evidence_dir), "--category", "AUTHENTICATION", "-o", str(self.output_dir / "run3.json")])

        hashes_after = compute_evidence_hashes(self.evidence_dir)

        # Verify exact set of files and hashes match
        self.assertEqual(hashes_before.keys(), hashes_after.keys())
        for rel_path, sha_before in hashes_before.items():
            self.assertEqual(sha_before, hashes_after[rel_path], f"Evidence file modified: {rel_path}")

    # =========================================================================
    # 7. Determinism & Idempotency
    # =========================================================================
    def test_07_determinism_and_reconstruction_idempotency(self):
        """Verify timeline reconstruction idempotency and deterministic report content."""
        # Step A: Test reconstruct_timeline(reconstruct_timeline(events)) == reconstruct_timeline(events)
        dt1 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 9, 30, 10, 5, 0, tzinfo=timezone.utc)

        e1 = create_timeline_event(
            timestamp=dt2,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login",
            description="Login from alice",
            source_path="/var/log/auth.log",
            source_line=1,
        )
        e2 = create_timeline_event(
            timestamp=dt1,
            category=TimelineCategory.LOG,
            event_type="service_start",
            description="Service started",
            source_path="/var/log/syslog",
            source_line=1,
        )

        r1 = reconstruct_timeline([e1, e2])
        r2 = reconstruct_timeline(r1.events)

        self.assertEqual(r1.total_events, r2.total_events)
        self.assertEqual(len(r1.events), len(r2.events))
        for ev1, ev2 in zip(r1.events, r2.events):
            self.assertEqual(ev1.timestamp, ev2.timestamp)
            self.assertEqual(ev1.category, ev2.category)
            self.assertEqual(ev1.event_type, ev2.event_type)
            self.assertEqual(ev1.description, ev2.description)
            self.assertEqual(ev1.source_path, ev2.source_path)
            self.assertEqual(ev1.source_line, ev2.source_line)

        # Step B: Repeated report rendering with fixed generated_at produces 100% byte-for-byte identical output
        fixed_time = "2026-10-02T12:00:00Z"
        report_a = generate_timeline_report(r1, case_id="FIXED-CASE", generated_at=fixed_time)
        report_b = generate_timeline_report(r1, case_id="FIXED-CASE", generated_at=fixed_time)

        json_a = render_timeline_json(report_a)
        json_b = render_timeline_json(report_b)
        self.assertEqual(json_a, json_b)

        html_a = render_timeline_html(report_a)
        html_b = render_timeline_html(report_b)
        self.assertEqual(html_a, html_b)

    # =========================================================================
    # 8. Source Provenance Chain Integrity
    # =========================================================================
    def test_08_provenance_chain_integrity(self):
        """Verify provenance fields remain fully intact from source log event through report."""
        # Run CLI with JSON output
        out_json = self.output_dir / "provenance.json"
        exit_code, _ = execute_timeline_cli([
            str(self.evidence_dir),
            "--format", "json",
            "-o", str(out_json),
        ])
        self.assertEqual(exit_code, 0)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        events = data["events"]
        # Find auth event for alice
        alice_event = next(
            (e for e in events if "alice" in e["description"].lower() and e["category"] == "authentication"),
            None,
        )
        self.assertIsNotNone(alice_event)
        self.assertTrue(alice_event["source_path"].endswith("auth.log"))
        self.assertEqual(alice_event["source_line"], 1)
        self.assertTrue(alice_event["source_artifact_id"].startswith("ART-"))
        self.assertTrue(alice_event["source_event_id"].startswith("AUTH-"))
        self.assertIsNotNone(alice_event["raw_data"])
        self.assertIn("Accepted publickey for alice", alice_event["raw_data"])
        self.assertEqual(alice_event["attributes"].get("username"), "alice")

    # =========================================================================
    # 9. Timestamp Normalization Fidelity
    # =========================================================================
    def test_09_timestamp_fidelity_and_ordering(self):
        """Verify aware timestamps normalize to UTC, naive remain naive, missing remain None."""
        # 1. Aware normalization
        aware_str = "2026-09-30T15:30:00+05:30"
        dt_aware = normalize_timestamp(aware_str)
        self.assertEqual(dt_aware.tzinfo, timezone.utc)
        self.assertEqual(dt_aware.hour, 10)
        self.assertEqual(dt_aware.minute, 0)

        nt_aware = parse_timestamp(aware_str)
        self.assertTrue(nt_aware.is_timezone_aware)
        self.assertEqual(nt_aware.original_tz_offset, "+05:30")

        # 2. Naive preservation
        naive_str = "2026-09-30T10:00:00"
        dt_naive = normalize_timestamp(naive_str)
        self.assertIsNone(dt_naive.tzinfo)

        nt_naive = parse_timestamp(naive_str)
        self.assertFalse(nt_naive.is_timezone_aware)
        self.assertIsNone(nt_naive.original_tz_offset)

        # 3. Missing preservation in TimelineEvent
        ev = create_timeline_event(
            timestamp=None,
            category=TimelineCategory.FILESYSTEM,
            event_type="file_unknown",
            description="Undated file",
            source_path="/test",
            source_line=1,
        )
        self.assertIsNone(ev.timestamp)
        self.assertIsNone(ev.raw_timestamp)

    # =========================================================================
    # 10. Deep Immutability across Core V3 Dataclasses
    # =========================================================================
    def test_10_deep_immutability_all_v3_models(self):
        """Verify all 5 V3 dataclasses are strictly frozen and nested dicts are immutable."""
        dt = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
        input_attrs = {"key": "val", "nested": {"sub": 123}}
        ev = create_timeline_event(
            timestamp=dt,
            category=TimelineCategory.AUTHENTICATION,
            event_type="test_event",
            description="Test event",
            source_path="/test",
            source_line=1,
            attributes=input_attrs,
            raw_data="raw log line content",
        )

        # TimelineEvent immutability
        with self.assertRaises(FrozenInstanceError):
            ev.description = "modified"  # type: ignore

        # Attributes immutability: mutating original input does not leak
        input_attrs["key"] = "mutated"
        self.assertEqual(ev.to_dict()["attributes"]["key"], "val")

        # Attributes tuple cannot be assigned to
        with self.assertRaises(TypeError):
            ev.attributes[0] = ("hacked", "value")  # type: ignore

        # ReconstructedTimeline immutability
        timeline = reconstruct_timeline([ev])
        with self.assertRaises(FrozenInstanceError):
            timeline.total_events = 99  # type: ignore

        # TimelineQuery immutability
        query = TimelineQuery(category=TimelineCategory.AUTHENTICATION)
        with self.assertRaises(FrozenInstanceError):
            query.text = "modified"  # type: ignore

        # TimelineQueryResult immutability
        q_result = query_timeline(timeline, query)
        with self.assertRaises(FrozenInstanceError):
            q_result.total_events = 0  # type: ignore

        # TimelineReport immutability
        report = generate_timeline_report(timeline, case_id="CASE-1")
        with self.assertRaises(FrozenInstanceError):
            report.case_id = "CASE-MUTATED"  # type: ignore

    # =========================================================================
    # 11. Security & HTML Injection / XSS Sanitization
    # =========================================================================
    def test_11_html_injection_and_xss_sanitization(self):
        """Verify all evidence fields in HTML report are securely escaped against XSS."""
        malicious_str = '<script>alert("XSS")</script>'
        img_injection = '<img src=x onerror=alert(1)>'
        attr_injection = '"><script>alert(2)</script>'

        ev = create_timeline_event(
            timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.AUTHENTICATION,
            event_type="login",
            description=malicious_str,
            source_path=img_injection,
            source_line=42,
            attributes={"xss": attr_injection},
            raw_data="<test>&foo='bar'\"baz\"</test>",
        )

        report = generate_timeline_report([ev], case_id="<case>&")
        html = render_timeline_html(report)

        # Must NOT contain raw unescaped HTML tags
        self.assertNotIn('<script>alert("XSS")</script>', html)
        self.assertNotIn('<img src=x onerror=alert(1)>', html)
        self.assertNotIn('"><script>alert(2)</script>', html)

        # Must contain properly escaped entities
        self.assertIn('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertIn('&lt;case&gt;&amp;', html)

    # =========================================================================
    # 12. Offline Safety & Zero External Invocations
    # =========================================================================
    def test_12_zero_subprocess_zero_network_safety(self):
        """Verify timeline analysis and reporting execute with zero subprocesses and zero network."""
        with patch("subprocess.Popen", side_effect=RuntimeError("Subprocess forbidden")), \
             patch("subprocess.run", side_effect=RuntimeError("Subprocess forbidden")), \
             patch("socket.socket", side_effect=RuntimeError("Network forbidden")):

            # Run full pipeline with mocks active
            out_file = self.output_dir / "safe_report.html"
            exit_code, report = execute_timeline_cli([
                str(self.evidence_dir),
                "--output", str(out_file),
            ])
            self.assertEqual(exit_code, 0)
            self.assertIsNotNone(report)
            self.assertTrue(out_file.exists())

    # =========================================================================
    # 13. V1 & V2 Regression Compatibility
    # =========================================================================
    def test_13_v1_and_v2_regression_compatibility(self):
        """Verify existing V1 single-file analysis and V2 triage CLI work unimpeded."""
        # V1: analyze single file
        target_file = self.evidence_dir / "etc" / "passwd"
        v1_result = analyze_evidence(target_file)
        self.assertIsNotNone(v1_result)
        self.assertTrue(v1_result.evidence.evidence_id.startswith("EV-"))
        self.assertGreater(v1_result.file.size, 0)
        self.assertIsNotNone(v1_result.hashes.sha256)

        # V2: triage command execution via main
        v2_out = self.output_dir / "v2_triage"
        v2_code = main(["triage", str(self.evidence_dir), "-o", str(v2_out), "--format", "json"])
        self.assertEqual(v2_code, 0)
        self.assertTrue((v2_out / "forensix_report_triage.json").exists())

    # =========================================================================
    # 14. Package Metadata & Version Consistency
    # =========================================================================
    def test_14_package_version_consistency(self):
        """Verify package version is consistently '4.0.0'."""
        self.assertEqual(__version__, "4.0.0")

        # Check pyproject.toml
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        self.assertTrue(pyproject_path.exists())
        pyproject_text = pyproject_path.read_text(encoding="utf-8")
        self.assertIn('version = "4.0.0"', pyproject_text)

    # =========================================================================
    # 15. V3 Scope Audit: Rejection of Speculative Conclusions
    # =========================================================================
    def test_15_rejection_of_speculative_conclusions(self):
        """Verify V3 strictly rejects speculative/interpretive conclusion event types."""
        speculative_types = [
            "attack_detected",
            "compromise_confirmed",
            "malware_executed",
            "threat_detected",
            "incident_confirmed",
            "anomaly_detected",
        ]
        for spec_type in speculative_types:
            with self.subTest(spec_type=spec_type):
                with self.assertRaises(ValueError) as ctx:
                    create_timeline_event(
                        category=TimelineCategory.AUTHENTICATION,
                        event_type=spec_type,
                        description="Speculative statement",
                        source_path="/test",
                        source_line=1,
                    )
                self.assertIn("disallowed in V3.1", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
