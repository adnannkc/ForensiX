"""
Tests for ForensiX timeline --user filter.

Validates that --user queries filter TimelineEvent records based on exact match
against structured user/username attributes.
"""

from pathlib import Path
import tempfile
import unittest

from forensix.timeline_cli import execute_timeline_cli
from forensix.timeline_models import TimelineCategory


class TestTimelineUserFilter(unittest.TestCase):
    """Test suite for timeline --user filter functionality."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.evidence_dir = cls.repo_root / "examples" / "case-synthetic" / "evidence_host"
        assert cls.evidence_dir.is_dir(), f"Evidence dir missing: {cls.evidence_dir}"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_user_filter_returns_only_that_user(self) -> None:
        """--user user_1002 returns only events for user_1002, matching GATE 2 count."""
        out_file = self.output_dir / "user_1002.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--user", "user_1002",
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        # Expected count from Gate 2 for user_1002
        self.assertEqual(report.event_count, 4)
        for event in report.events:
            event_users = [
                v for k, v in event.attributes if k in ("user", "username")
            ]
            self.assertIn("user_1002", event_users)

    def test_user_filter_unknown_user_returns_zero(self) -> None:
        """--user nobody returns 0 events and exit code 0."""
        out_file = self.output_dir / "user_nobody.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--user", "nobody",
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 0)

    def test_user_filter_combines_with_category(self) -> None:
        """--user user_1002 --category AUTHENTICATION returns the same count as --user user_1002 alone."""
        out_file = self.output_dir / "user_auth_comb.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--user", "user_1002",
            "--category", "AUTHENTICATION",
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 4)
        for event in report.events:
            self.assertEqual(event.category, TimelineCategory.AUTHENTICATION)
            event_users = [
                v for k, v in event.attributes if k in ("user", "username")
            ]
            self.assertIn("user_1002", event_users)

    def test_user_filter_is_exact_match(self) -> None:
        """--user USER_1002 returns 0 (exact, case-sensitive matching)."""
        out_file = self.output_dir / "user_case.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "--user", "USER_1002",
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 0)

    def test_user_filter_absent_flag_changes_nothing(self) -> None:
        """The timeline without --user has the same event count (19) as before the change."""
        out_file = self.output_dir / "no_user_filter.json"
        exit_code, report = execute_timeline_cli([
            str(self.evidence_dir),
            "-o", str(out_file),
            "--format", "json",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.event_count, 19)


if __name__ == "__main__":
    unittest.main()

