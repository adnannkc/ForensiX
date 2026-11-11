"""
Unit and integration tests for ForensiX timeline path privacy.

Verifies:
1. Timeline events do not leak analyst home directory paths in source_path or description.
2. Filesystem event descriptions use evidence-relative paths when relative_path is set.
3. source_path uses relative_path when available on evidence artifact records.
4. Records without relative_path preserve their source_path unchanged (backward compatibility).
"""

import os
from pathlib import Path
from typing import Any, List
import unittest

from forensix.artifact_adapters import FilesystemAdapter
from forensix.artifacts import ArtifactRecord
from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator
from forensix.artifact_adapters import adapt_artifacts
from forensix.timeline_reconstruction import reconstruct_timeline


class TestTimelinePathPrivacy(unittest.TestCase):
    """Test suite ensuring personal analyst paths do not leak into timeline events."""

    def setUp(self) -> None:
        self.home_dir = str(Path.home().resolve())
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

    def test_sample_case_timeline_has_no_analyst_home_paths(self) -> None:
        """Run timeline on sample case evidence and assert no event contains analyst home path."""
        events = [e for e in self._extract_sample_timeline_events() if e.category == TimelineCategory.FILESYSTEM]
        self.assertGreater(len(events), 0)

        for event in events:
            if event.source_path:
                self.assertNotIn(
                    self.home_dir,
                    event.source_path,
                    f"Event {event.event_id} leaks home path in source_path: {event.source_path}",
                )
            if event.description:
                self.assertNotIn(
                    self.home_dir,
                    event.description,
                    f"Event {event.event_id} leaks home path in description: {event.description}",
                )

    def test_filesystem_descriptions_use_relative_paths(self) -> None:
        """A 'File modified:' description for etc/passwd must contain 'etc/passwd' and not absolute prefix."""
        abs_passwd = str(self.evidence_dir / "etc" / "passwd")
        rec = ArtifactRecord(
            artifact_id="ART-TEST-PASSWD",
            relative_path="etc/passwd",
            source_path=abs_passwd,
            category="filesystem",
            artifact_type="passwd",
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-10-01T12:00:00Z",
            accessed=None,
            created=None,
            md5=None,
            sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            status="SUCCESS",
        )

        adapter = FilesystemAdapter()
        events = adapter.adapt(rec)
        mod_events = [e for e in events if e.event_type == "file_modified"]
        self.assertEqual(len(mod_events), 1)
        mod_event = mod_events[0]

        self.assertIn("etc/passwd", mod_event.description)
        self.assertNotIn(str(self.evidence_dir), mod_event.description)
        self.assertNotIn(self.home_dir, mod_event.description)

    def test_source_path_is_relative_for_evidence_files(self) -> None:
        """For every filesystem event with a relative_path, source_path must be relative to evidence root."""
        abs_passwd = str(self.evidence_dir / "etc" / "passwd")
        rec = ArtifactRecord(
            artifact_id="ART-TEST-REL",
            relative_path="etc/passwd",
            source_path=abs_passwd,
            category="filesystem",
            artifact_type="passwd",
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-10-01T12:00:00Z",
            accessed="2026-10-01T12:01:00Z",
            created="2026-10-01T11:00:00Z",
            md5=None,
            sha256=None,
            status="SUCCESS",
        )

        adapter = FilesystemAdapter()
        events = adapter.adapt(rec)
        self.assertGreater(len(events), 0)

        for e in events:
            self.assertEqual(e.source_path, "etc/passwd")
            self.assertFalse(
                os.path.isabs(e.source_path),
                f"source_path should be relative, got: {e.source_path}",
            )

    def test_mock_absolute_paths_still_honoured(self) -> None:
        """A record whose relative_path is None keeps its source_path unchanged (backward compatibility)."""
        rec = ArtifactRecord(
            artifact_id="ART-TEST-MOCK",
            relative_path=None,
            source_path="/evidence/target/etc/passwd",
            category="filesystem",
            artifact_type="passwd",
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-10-01T12:00:00Z",
            accessed=None,
            created=None,
            md5=None,
            sha256=None,
            status="SUCCESS",
        )

        adapter = FilesystemAdapter()
        events = adapter.adapt(rec)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_path, "/evidence/target/etc/passwd")
        self.assertEqual(events[0].description, "File modified: /evidence/target/etc/passwd")

    def test_auth_and_log_timeline_events_use_relative_source_path_and_dedup(self) -> None:
        from pathlib import Path

        from forensix.artifact_adapters import adapt_artifacts
        from forensix.timeline_models import TimelineCategory
        from forensix.timeline_reconstruction import reconstruct_timeline
        from forensix.triage_orchestrator import TriageOrchestrator

        evidence_dir = (
            Path(__file__).resolve().parent.parent
            / "examples"
            / "case-synthetic"
            / "evidence_host"
        )
        res = TriageOrchestrator(evidence_path=str(evidence_dir), skip_reports=True).run()
        raw_events = adapt_artifacts(res.artifacts.artifacts, ignore_unsupported=True)

        auth_raw = [
            ev for ev in raw_events
            if ev.category == TimelineCategory.AUTHENTICATION.value
        ]
        log_raw = [
            ev for ev in raw_events
            if ev.category == TimelineCategory.LOG.value
            and "auth.log" in (ev.source_path or "").replace("\\", "/")
        ]
        self.assertGreater(len(auth_raw), 0)
        self.assertGreater(len(log_raw), 0)

        for ev in auth_raw + log_raw:
            self.assertIs(type(ev.source_path), str)
            self.assertEqual(ev.source_path, "var/log/auth.log")
            self.assertFalse(ev.source_path.startswith("/"))
            self.assertNotIn("/home/", ev.source_path)

        recon = reconstruct_timeline(raw_events)
        self.assertEqual(len(recon.events), 19)
        line_pairs = [
            (ev.source_path, ev.source_line)
            for ev in recon.events
            if ev.source_line is not None
        ]
        self.assertEqual(len(line_pairs), len(set(line_pairs)))
        for ev in recon.events:
            if ev.category == TimelineCategory.AUTHENTICATION.value or (
                ev.category == TimelineCategory.LOG.value
                and "auth.log" in (ev.source_path or "").replace("\\", "/")
            ):
                self.assertIs(type(ev.source_path), str)
                self.assertEqual(ev.source_path, "var/log/auth.log")

    def test_adapt_artifacts_falls_back_to_evidence_root_when_relative_path_absent(self) -> None:
        import dataclasses

        from forensix.artifact_adapters import adapt_artifacts
        from forensix.artifacts import ArtifactRecord
        from forensix.auth_models import AuthEventType, AuthStatus, AuthenticationRecord
        from forensix.log_models import LogEvent
        from forensix.timeline_models import TimelineCategory

        rec_no_rel = ArtifactRecord(
            artifact_id="ART-11111111-1111-4111-8111-111111111111",
            relative_path="",
            source_path="/evidence/host/var/log/auth.log",
            category="log",
            artifact_type="auth_log",
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-10-21T07:00:00Z",
            accessed=None,
            created=None,
            md5=None,
            sha256=None,
            status="collected",
        )
        log_evt = LogEvent(
            event_id="EVT-11111111-1111-4111-8111-222222222222",
            source_artifact_id="ART-11111111-1111-4111-8111-111111111111",
            source_path="/evidence/host/var/log/auth.log",
            line_number=5,
            raw_timestamp="2026-10-21T07:12:15Z",
            normalized_timestamp="2026-10-21T07:12:15Z",
            hostname="host1",
            service="sshd",
            pid=1234,
            event_type="ssh_accepted",
            attributes={"username": "alice"},
            raw_message="Accepted publickey for alice",
            raw_line="Oct 21 07:12:15 host1 sshd[1234]: Accepted publickey for alice",
        )
        auth_rec = AuthenticationRecord(
            auth_id="AUTH-11111111-1111-4111-8111-333333333333",
            event_id="EVT-11111111-1111-4111-8111-222222222222",
            source_artifact_id="ART-11111111-1111-4111-8111-111111111111",
            source_path="/evidence/host/var/log/auth.log",
            line_number=5,
            raw_timestamp="2026-10-21T07:12:15Z",
            normalized_timestamp="2026-10-21T07:12:15Z",
            hostname="host1",
            service="sshd",
            event_type=AuthEventType.SSH_LOGIN_SUCCESS.value,
            status=AuthStatus.SUCCESS.value,
            username="alice",
            source_ip="192.0.2.10",
            source_port=51234,
            authentication_method="publickey",
            attributes={},
            raw_message="Accepted publickey for alice",
            raw_line="Oct 21 07:12:15 host1 sshd[1234]: Accepted publickey for alice",
        )

        for parent_rec, expected_path in (
            (rec_no_rel, "var/log/auth.log"),
            (dataclasses.replace(rec_no_rel, relative_path="custom/auth.log"), "custom/auth.log"),
        ):
            events = adapt_artifacts(
                [parent_rec, log_evt, auth_rec],
                evidence_root="/evidence/host",
            )
            log_or_auth = [
                ev for ev in events
                if ev.category in (TimelineCategory.LOG.value, TimelineCategory.AUTHENTICATION.value)
            ]
            self.assertEqual(len(log_or_auth), 2)
            for ev in log_or_auth:
                self.assertIs(type(ev.source_path), str)
                self.assertEqual(ev.source_path, expected_path)


if __name__ == "__main__":
    unittest.main()
