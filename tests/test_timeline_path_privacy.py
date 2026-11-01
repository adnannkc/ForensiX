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


if __name__ == "__main__":
    unittest.main()
