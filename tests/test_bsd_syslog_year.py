"""
Unit and Integration Tests for ForensiX BSD Syslog Year Context.

Validates the patch for BSD/RFC 3164 syslog timestamp normalization:
- Scenario A: BSD timestamp + no year -> normalized_timestamp is None, TimelineEvent.timestamp is None.
- Scenario B: BSD timestamp + year 2026 -> correct naive datetime 2026-09-30 10:00:00.
- Scenario C: Raw timestamp preserved across LogEvent, AuthenticationRecord, and TimelineEvent.
- Scenario D: Invalid date/year handled safely (e.g. Feb 29 on non-leap year -> None, no crash).
- Scenario E: ISO/RFC 5424 timestamps remain unchanged even when year context is supplied.
- Scenario F: End-to-end BSD auth.log produces usable TimelineEvent timestamps with --log-year 2026.
- Scenario G: V4 Rule 1 (SSH Auth followed by Sudo) produces detection within 300s window.
- Scenario H: V4 Rule 2 (Failed -> Failed -> Successful SSH) produces expected detections.
- Scenario I: Out-of-window events (>300s) and yearless runs produce zero matched detections.
"""

from datetime import datetime
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from forensix.artifact_adapters import (
    AuthenticationAdapter,
    LogAdapter,
    adapt_artifacts,
)
from forensix.auth_analyzer import (
    extract_authentication_activity,
    stream_authentication_activity,
)
from forensix.auth_models import AuthenticationRecord
from forensix.initial_rules import (
    RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
    RULE_NAME_SSH_AUTH_SUDO,
)
from forensix.log_models import LogEvent
from forensix.log_parser import (
    parse_log_file,
    parse_log_line,
    parse_syslog_header,
    stream_log_events,
)
from forensix.timeline_models import TimelineCategory
from forensix.timestamp_normalizer import (
    normalize_bsd_timestamp,
    normalize_timestamp,
)
from forensix.triage_cli import execute_investigation_cli
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


class TestBsdSyslogYearContext(unittest.TestCase):
    """Test suite verifying BSD syslog year context handling and V4 rule detection."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="forensix_bsd_test_"))
        self.evidence_dir = self.temp_dir / "evidence"
        self.log_dir = self.evidence_dir / "var" / "log"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = self.temp_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Scenario A: Existing behavior without year context
    # -------------------------------------------------------------------------
    def test_scenario_a_bsd_timestamp_no_year(self):
        """Verify BSD timestamp with no year produces None for normalized timestamp."""
        raw = "Sep 30 10:00:00"

        # 1. normalize_bsd_timestamp without year returns None
        self.assertIsNone(normalize_bsd_timestamp(raw, log_timestamp_year=None))

        # 2. General normalize_timestamp continues to reject yearless strings
        with self.assertRaises(ValueError):
            normalize_timestamp(raw)

        # 3. parse_syslog_header without year returns None for normalized_ts
        line = "Sep 30 10:00:00 lab sshd[1001]: Failed password for adnan from 10.10.10.50 port 40001"
        header = parse_syslog_header(line)
        self.assertIsNotNone(header)
        raw_ts, norm_ts, hostname, service, pid, msg = header
        self.assertEqual(raw_ts, "Sep 30 10:00:00")
        self.assertIsNone(norm_ts)

        # 4. parse_log_line without year produces LogEvent with normalized_timestamp=None
        evt = parse_log_line(line, line_number=1, source_path="/var/log/auth.log")
        self.assertEqual(evt.raw_timestamp, "Sep 30 10:00:00")
        self.assertIsNone(evt.normalized_timestamp)

        # 5. LogAdapter without year produces TimelineEvent with timestamp=None
        adapter = LogAdapter()
        tl_events = adapter._adapt_log_event(evt)
        self.assertEqual(len(tl_events), 1)
        self.assertIsNone(tl_events[0].timestamp)
        self.assertEqual(tl_events[0].raw_timestamp, "Sep 30 10:00:00")

    # -------------------------------------------------------------------------
    # Scenario B: Explicit year context
    # -------------------------------------------------------------------------
    def test_scenario_b_explicit_year_normalization(self):
        """Verify BSD timestamp with explicit year 2026 produces naive datetime 2026-09-30 10:00:00."""
        raw = "Sep 30 10:00:00"

        # 1. normalize_bsd_timestamp returns canonical naive datetime
        dt = normalize_bsd_timestamp(raw, log_timestamp_year=2026)
        self.assertIsNotNone(dt)
        self.assertEqual(dt, datetime(2026, 9, 30, 10, 0, 0))
        self.assertIsNone(dt.tzinfo)

        # 2. Single-digit day parsing
        dt_single = normalize_bsd_timestamp("Sep  5 09:12:33", log_timestamp_year=2026)
        self.assertIsNotNone(dt_single)
        self.assertEqual(dt_single, datetime(2026, 9, 5, 9, 12, 33))

        # 3. parse_syslog_header with year returns ISO string
        line = "Sep 30 10:00:00 lab sshd[1001]: Failed password for adnan from 10.10.10.50 port 40001"
        header = parse_syslog_header(line, log_timestamp_year=2026)
        self.assertIsNotNone(header)
        raw_ts, norm_ts, hostname, service, pid, msg = header
        self.assertEqual(raw_ts, "Sep 30 10:00:00")
        self.assertEqual(norm_ts, "2026-09-30T10:00:00")

        # 4. parse_log_line with year produces LogEvent with normalized_timestamp
        evt = parse_log_line(line, line_number=1, source_path="/var/log/auth.log", log_timestamp_year=2026)
        self.assertEqual(evt.normalized_timestamp, "2026-09-30T10:00:00")

        # 5. LogAdapter with year produces TimelineEvent with valid datetime
        adapter = LogAdapter(log_timestamp_year=2026)
        tl_events = adapter._adapt_log_event(evt)
        self.assertEqual(len(tl_events), 1)
        self.assertEqual(tl_events[0].timestamp, datetime(2026, 9, 30, 10, 0, 0))

    # -------------------------------------------------------------------------
    # Scenario C: Raw timestamp preserved
    # -------------------------------------------------------------------------
    def test_scenario_c_raw_timestamp_preserved(self):
        """Verify raw_timestamp is strictly preserved across LogEvent, AuthenticationRecord, and TimelineEvent."""
        raw_literal = "Sep 30 10:02:00"
        line = f"{raw_literal} lab sshd[1003]: Accepted password for adnan from 10.10.10.50 port 40003"

        evt = parse_log_line(line, line_number=3, source_path="/var/log/auth.log", log_timestamp_year=2026)
        self.assertEqual(evt.raw_timestamp, raw_literal)

        auth_records = list(extract_authentication_activity([evt]).records)
        self.assertEqual(len(auth_records), 1)
        self.assertEqual(auth_records[0].raw_timestamp, raw_literal)
        self.assertEqual(auth_records[0].normalized_timestamp, "2026-09-30T10:02:00")

        tl_events = adapt_artifacts([auth_records[0]], log_timestamp_year=2026)
        self.assertEqual(len(tl_events), 1)
        self.assertEqual(tl_events[0].raw_timestamp, raw_literal)
        self.assertEqual(tl_events[0].timestamp, datetime(2026, 9, 30, 10, 2, 0))

    # -------------------------------------------------------------------------
    # Scenario D: Invalid supplied date/year handled safely
    # -------------------------------------------------------------------------
    def test_scenario_d_invalid_date_year_safety(self):
        """Verify invalid date/year combinations return None safely without fabricating dates or crashing."""
        # Non-leap year Feb 29 fails safely
        self.assertIsNone(normalize_bsd_timestamp("Feb 29 10:00:00", log_timestamp_year=2026))

        # Leap year Feb 29 succeeds
        dt_leap = normalize_bsd_timestamp("Feb 29 10:00:00", log_timestamp_year=2024)
        self.assertEqual(dt_leap, datetime(2024, 2, 29, 10, 0, 0))

        # 31st of 30-day month fails safely
        self.assertIsNone(normalize_bsd_timestamp("Sep 31 10:00:00", log_timestamp_year=2026))

        # Out-of-range years fail safely
        self.assertIsNone(normalize_bsd_timestamp("Sep 30 10:00:00", log_timestamp_year=-1))
        self.assertIsNone(normalize_bsd_timestamp("Sep 30 10:00:00", log_timestamp_year=0))
        self.assertIsNone(normalize_bsd_timestamp("Sep 30 10:00:00", log_timestamp_year=10000))

        # Non-int year fails safely
        self.assertIsNone(normalize_bsd_timestamp("Sep 30 10:00:00", log_timestamp_year="invalid"))  # type: ignore

        # Malformed timestamp string fails safely
        self.assertIsNone(normalize_bsd_timestamp("Not a date", log_timestamp_year=2026))
        self.assertIsNone(normalize_bsd_timestamp("", log_timestamp_year=2026))

        # Line parsing on invalid date safely keeps normalized_timestamp as None
        bad_line = "Feb 29 10:00:00 lab sshd[1001]: Failed password for root from 1.2.3.4 port 22"
        h = parse_syslog_header(bad_line, log_timestamp_year=2026)
        self.assertIsNotNone(h)
        self.assertIsNone(h[1])  # norm_ts is None

    # -------------------------------------------------------------------------
    # Scenario E: ISO/RFC 5424 timestamps remain unchanged
    # -------------------------------------------------------------------------
    def test_scenario_e_rfc5424_timestamps_remain_unchanged(self):
        """Verify RFC 5424 / ISO 8601 timestamps are not overwritten by log_timestamp_year."""
        iso_line = "2024-05-15T12:00:00+00:00 lab sshd[1001]: Accepted password for adnan from 10.10.10.50 port 40003"
        header = parse_syslog_header(iso_line, log_timestamp_year=2026)
        self.assertIsNotNone(header)
        raw_ts, norm_ts, hostname, service, pid, msg = header
        self.assertEqual(raw_ts, "2024-05-15T12:00:00+00:00")
        self.assertEqual(norm_ts, "2024-05-15T12:00:00+00:00")

        evt = parse_log_line(iso_line, line_number=1, source_path="/var/log/auth.log", log_timestamp_year=2026)
        self.assertEqual(evt.normalized_timestamp, "2024-05-15T12:00:00+00:00")

    # -------------------------------------------------------------------------
    # Scenario F, G, H: End-to-end BSD auth.log investigation with Rules 1 & 2
    # -------------------------------------------------------------------------
    def test_scenarios_f_g_h_end_to_end_bsd_investigation(self):
        """Verify full CLI investigation pipeline with --log-year 2026 detects Rules 1 and 2."""
        auth_log = self.log_dir / "auth.log"
        auth_log.write_text(
            "Sep 30 10:00:00 lab sshd[1001]: Failed password for adnan from 10.10.10.50 port 40001\n"
            "Sep 30 10:01:00 lab sshd[1002]: Failed password for adnan from 10.10.10.50 port 40002\n"
            "Sep 30 10:02:00 lab sshd[1003]: Accepted password for adnan from 10.10.10.50 port 40003\n"
            "Sep 30 10:03:00 lab sudo[1004]: adnan : TTY=pts/0 ; PWD=/home/adnan ; USER=root ; COMMAND=/usr/bin/id\n",
            encoding="utf-8",
        )

        out_report = self.reports_dir / "inv_report.json"
        code, report = execute_investigation_cli([
            str(self.evidence_dir),
            "--log-year", "2026",
            "--json",
            "-o", str(out_report),
        ])

        self.assertEqual(code, 0)
        self.assertIsNotNone(report)
        self.assertTrue(out_report.exists())

        # Verify timeline events have valid datetimes
        log_and_auth_events = [
            ev for ev in report.timeline_events
            if ev.category in (TimelineCategory.LOG, TimelineCategory.AUTHENTICATION)
        ]
        self.assertEqual(len(log_and_auth_events), 8)
        for ev in log_and_auth_events:
            self.assertIsNotNone(ev.timestamp, f"Event {ev.event_id} missing timestamp")
            self.assertEqual(ev.timestamp.year, 2026)
            self.assertEqual(ev.timestamp.month, 9)
            self.assertEqual(ev.timestamp.day, 30)

        # Check matched detections
        matched_rules = {d.rule_name for d in report.detections if d.matched}

        # Scenario G: Rule 1 matches (SSH auth at 10:02 followed by sudo at 10:03, delta=60s <= 300s)
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, matched_rules)

        # Scenario H: Rule 2 matches (Failed SSH at 10:00, 10:01 followed by success at 10:02)
        self.assertIn(RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS, matched_rules)

    # -------------------------------------------------------------------------
    # Scenario I: Negative and out-of-window tests
    # -------------------------------------------------------------------------
    def test_scenario_i_out_of_window_and_yearless_negative_controls(self):
        """Verify out-of-window events and yearless evidence do not match temporal rules."""
        # 1. Yearless run produces 0 matched detections because timestamps remain None
        auth_log = self.log_dir / "auth.log"
        auth_log.write_text(
            "Sep 30 10:00:00 lab sshd[1001]: Failed password for adnan from 10.10.10.50 port 40001\n"
            "Sep 30 10:01:00 lab sshd[1002]: Failed password for adnan from 10.10.10.50 port 40002\n"
            "Sep 30 10:02:00 lab sshd[1003]: Accepted password for adnan from 10.10.10.50 port 40003\n"
            "Sep 30 10:03:00 lab sudo[1004]: adnan : TTY=pts/0 ; PWD=/home/adnan ; USER=root ; COMMAND=/usr/bin/id\n",
            encoding="utf-8",
        )

        code_noyear, rep_noyear = execute_investigation_cli([
            str(self.evidence_dir),
            "--json",
            "-o", str(self.reports_dir / "noyear.json"),
        ])
        self.assertEqual(code_noyear, 0)
        self.assertEqual(rep_noyear.matched_detections, 0)

        # 2. Out-of-window run: SSH login and sudo separated by 600 seconds (> 300s window)
        out_of_window_dir = self.temp_dir / "oow_evidence"
        oow_log_dir = out_of_window_dir / "var" / "log"
        oow_log_dir.mkdir(parents=True, exist_ok=True)
        (oow_log_dir / "auth.log").write_text(
            "Sep 30 10:00:00 lab sshd[1003]: Accepted password for adnan from 10.10.10.50 port 40003\n"
            "Sep 30 10:10:00 lab sudo[1004]: adnan : TTY=pts/0 ; PWD=/home/adnan ; USER=root ; COMMAND=/usr/bin/id\n",
            encoding="utf-8",
        )

        code_oow, rep_oow = execute_investigation_cli([
            str(out_of_window_dir),
            "--log-year", "2026",
            "--json",
            "-o", str(self.reports_dir / "oow.json"),
        ])
        self.assertEqual(code_oow, 0)
        # Sudo at 10:10 is 600s after SSH login at 10:00, which exceeds the 300s window
        matched_oow = {d.rule_name for d in rep_oow.detections if d.matched}
        self.assertNotIn(RULE_NAME_SSH_AUTH_SUDO, matched_oow)


if __name__ == "__main__":
    unittest.main()
