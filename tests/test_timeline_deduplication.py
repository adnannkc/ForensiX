"""
Unit and integration tests for ForensiX timeline event deduplication.

Verifies:
1. Timeline reconstruction deduplicates generic log events when an authentication
   event exists for the same source log line.
2. The synthetic sample evidence timeline contains exactly 19 events (10 filesystem, 9 authentication).
3. Plain log events without corresponding authentication records are preserved.
4. Multiple distinct lines in the same second are both preserved.
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List
import unittest

from forensix.artifact_adapters import adapt_artifacts
from forensix.timeline_models import TimelineCategory, TimelineEvent, create_timeline_event
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


class TestTimelineDeduplication(unittest.TestCase):
    """Test suite ensuring one timeline event per source log line (authentication over generic log)."""

    def setUp(self) -> None:
        self.evidence_dir = Path(__file__).resolve().parent.parent / "examples" / "case-synthetic" / "evidence_host"

    def _extract_sample_timeline_events(self) -> List[TimelineEvent]:
        config = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            collect_audit=False,
        )
        orchestrator = TriageOrchestrator(config)
        res = orchestrator.run()
        raw_events = adapt_artifacts(res.artifacts.artifacts, ignore_unsupported=True)
        reconstructed = reconstruct_timeline(raw_events)
        return list(reconstructed.events)

    def test_sample_timeline_has_no_duplicate_line_events(self) -> None:
        """No two events share the same (source_path, source_line, timestamp, event_type)."""
        events = self._extract_sample_timeline_events()
        self.assertGreater(len(events), 0)

        seen = set()
        duplicates = []
        for e in events:
            if e.source_line is not None and e.source_path is not None:
                key = (e.source_path, e.source_line, e.timestamp, e.event_type)
                if key in seen:
                    duplicates.append(key)
                seen.add(key)

        self.assertEqual(
            duplicates,
            [],
            f"Found duplicate (source_path, source_line, timestamp, event_type) events: {duplicates}",
        )

    def test_sample_timeline_event_count_is_19(self) -> None:
        """The timeline for examples/case-synthetic/evidence_host has exactly 19 events (10 filesystem and 9 authentication)."""
        events = self._extract_sample_timeline_events()
        self.assertEqual(len(events), 19, f"Expected 19 events, got {len(events)}")

        counts = Counter(e.category for e in events)
        self.assertEqual(counts[TimelineCategory.FILESYSTEM], 10, "Expected 10 filesystem events")
        self.assertEqual(counts[TimelineCategory.AUTHENTICATION], 9, "Expected 9 authentication events")
        self.assertEqual(counts.get(TimelineCategory.LOG, 0), 0, "Expected 0 generic log events")

    def test_authentication_event_kept_over_generic_log_event(self) -> None:
        """For a line that produces both a generic log event and an authentication event, keep authentication."""
        ts = datetime(2026, 10, 21, 7, 12, 0, 100000, tzinfo=timezone.utc)
        path = "/var/log/auth.log"
        line = 1

        log_event = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="ssh_invalid_user",
            description="sshd: Failed password for invalid user admin",
            timestamp=ts,
            source_path=path,
            source_line=line,
            source_artifact_id="ART-LOG-1",
            source_event_id="EVT-1",
        )

        auth_event = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_invalid_user",
            description="Failed password for invalid user admin from 198.51.100.45",
            timestamp=ts,
            source_path=path,
            source_line=line,
            source_artifact_id="ART-LOG-1",
            source_event_id="AUTH-1",
            attributes={"username": "admin", "status": "failure"},
        )

        timeline = reconstruct_timeline([log_event, auth_event])
        self.assertEqual(len(timeline), 1, "Expected exactly 1 surviving event")
        self.assertEqual(timeline[0].category, TimelineCategory.AUTHENTICATION)
        self.assertEqual(timeline[0].source_event_id, "AUTH-1")

    def test_distinct_lines_same_second_are_kept(self) -> None:
        """Two different auth lines with the same timestamp and event_type are both kept."""
        ts = datetime(2026, 10, 21, 7, 12, 0, tzinfo=timezone.utc)
        path = "/var/log/auth.log"

        auth1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_failure",
            description="Failed password for user1",
            timestamp=ts,
            source_path=path,
            source_line=10,
            source_artifact_id="ART-LOG-1",
            source_event_id="AUTH-10",
        )

        auth2 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_failure",
            description="Failed password for user2",
            timestamp=ts,
            source_path=path,
            source_line=11,
            source_artifact_id="ART-LOG-1",
            source_event_id="AUTH-11",
        )

        timeline = reconstruct_timeline([auth1, auth2])
        self.assertEqual(len(timeline), 2, "Both distinct lines must be kept")
        lines = [e.source_line for e in timeline]
        self.assertEqual(sorted(lines), [10, 11])

    def test_non_auth_log_lines_still_produce_log_events(self) -> None:
        """A plain syslog line that the authentication adapter ignores still produces its LOG event."""
        ts = datetime(2026, 10, 21, 7, 30, 0, tzinfo=timezone.utc)
        path = "/var/log/syslog"

        log_event = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="cron_job",
            description="cron[1234]: (root) CMD (/usr/local/bin/backup.sh)",
            timestamp=ts,
            source_path=path,
            source_line=42,
            source_artifact_id="ART-SYSLOG-1",
            source_event_id="EVT-42",
        )

        timeline = reconstruct_timeline([log_event])
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0].category, TimelineCategory.LOG)
        self.assertEqual(timeline[0].source_line, 42)
