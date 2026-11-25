"""
Integration tests for browser history analysis in the ForensiX triage and case pipelines.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from forensix.case_config import CaseConfig
from forensix.dashboard_service import DashboardReportRegistry
from forensix.pipeline_engine import EXIT_SUCCESS, run_pipeline
from forensix.timeline_cli import execute_timeline_cli
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator
from forensix.unified_models import HostArtifactCategory


UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _micros_since(epoch: datetime, dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _create_firefox_db(db_path: Path, url: str, title: str, visit_dt: datetime, visit_id: int = 1) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE moz_places ("
        "id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, "
        "visit_count INTEGER DEFAULT 0, last_visit_date INTEGER)"
    )
    conn.execute(
        "CREATE TABLE moz_historyvisits ("
        "id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, visit_date INTEGER NOT NULL)"
    )
    ts_us = _micros_since(UNIX_EPOCH, visit_dt)
    conn.execute(
        "INSERT INTO moz_places (id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
        (1, url, title, 2, ts_us),
    )
    conn.execute(
        "INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (?, ?, ?)",
        (visit_id, 1, ts_us),
    )
    conn.commit()
    conn.close()


def _create_chromium_db(db_path: Path, url: str, title: str, visit_dt: datetime, visit_id: int = 1) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE urls ("
        "id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, "
        "visit_count INTEGER DEFAULT 0, last_visit_time INTEGER)"
    )
    conn.execute(
        "CREATE TABLE visits ("
        "id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL)"
    )
    ts_us = _micros_since(CHROMIUM_EPOCH, visit_dt)
    conn.execute(
        "INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
        (1, url, title, 3, ts_us),
    )
    conn.execute(
        "INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)",
        (visit_id, 1, ts_us),
    )
    conn.commit()
    conn.close()


class TestBrowserPipelineIntegration(unittest.TestCase):
    """Verify browser history reaches triage, timeline, case reports, and dashboard."""

    def test_case_pipeline_includes_firefox_and_chromium_in_timeline_report_and_dashboard(self) -> None:
        dt_ff = datetime(2026, 10, 21, 14, 15, 0, tzinfo=timezone.utc)
        dt_ch = datetime(2026, 10, 21, 14, 20, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ev_dir = root / "evidence"
            out_dir = root / "reports"

            _create_firefox_db(
                ev_dir / "home" / "alice" / ".mozilla" / "firefox" / "p1.default" / "places.sqlite",
                url="https://docs.python.org/3/",
                title="Python 3 Docs",
                visit_dt=dt_ff,
                visit_id=10,
            )
            _create_chromium_db(
                ev_dir / "home" / "alice" / ".config" / "chromium" / "Default" / "History",
                url="https://example.org/portal",
                title="Portal Login",
                visit_dt=dt_ch,
                visit_id=20,
            )

            # 1. Timeline CLI includes browser_history_visit events
            tl_path = root / "timeline.json"
            ret, _ = execute_timeline_cli([str(ev_dir), "--format", "json", "-o", str(tl_path)])
            self.assertEqual(ret, 0)
            tl_data = json.loads(tl_path.read_text(encoding="utf-8"))
            browser_tl = [ev for ev in tl_data["events"] if ev["event_type"] == "browser_history_visit"]
            self.assertEqual(len(browser_tl), 2)
            urls = {ev["attributes"]["url"] for ev in browser_tl}
            self.assertEqual(urls, {"https://docs.python.org/3/", "https://example.org/portal"})
            self.assertTrue(all(ev["category"] == "log" for ev in browser_tl))

            # 2. Full V9 Case Pipeline includes browser history in host artifacts, timeline count, and Schema 8.0 reports
            cfg = CaseConfig(
                case_id="CASE-BROWSER-01",
                case_name="Browser Integration Test",
                investigator="Analyst",
                evidence_host_dir=ev_dir,
                output_dir=out_dir,
                overwrite=True,
            )
            res = run_pipeline(cfg)
            self.assertEqual(res.exit_code, EXIT_SUCCESS)
            self.assertIsNotNone(res.report)
            assert res.report is not None

            # At least 2 filesystem DB artifacts + 2 browser history events
            self.assertGreaterEqual(res.report.findings_summary.total_host_artifacts, 4)
            self.assertGreaterEqual(res.report.findings_summary.total_timeline_events, 2)

            report_json_path = out_dir / "report_CASE-BROWSER-01.json"
            report_html_path = out_dir / "report_CASE-BROWSER-01.html"
            self.assertTrue(report_json_path.exists())
            self.assertTrue(report_html_path.exists())

            report_json = json.loads(report_json_path.read_text(encoding="utf-8"))
            details = report_json.get("details", {})
            self.assertEqual(details.get("browser_history_count"), 2)
            bh_events = details.get("browser_history_events", [])
            self.assertEqual(len(bh_events), 2)
            self.assertEqual({e["url"] for e in bh_events}, {"https://docs.python.org/3/", "https://example.org/portal"})

            html_text = report_html_path.read_text(encoding="utf-8")
            self.assertIn("https://docs.python.org/3/", html_text)
            self.assertIn("https://example.org/portal", html_text)

            # 3. Dashboard report registry ingests the Schema 8.0 report with browser details and counts
            registry = DashboardReportRegistry()
            rep_id = registry.register_file(report_json_path)
            overview_list = registry.list_reports()
            self.assertEqual(len(overview_list), 1)
            self.assertEqual(overview_list[0]["counts"]["artifact_count"], res.report.findings_summary.total_host_artifacts)
            self.assertEqual(overview_list[0]["counts"]["event_count"], res.report.findings_summary.total_timeline_events)

            reg_details = registry.get_report_details(rep_id)
            self.assertIsNotNone(reg_details)
            assert reg_details is not None
            raw_details = reg_details["raw_data"]["details"]
            self.assertEqual(raw_details["browser_history_count"], 2)
            self.assertEqual(len(raw_details["browser_history_events"]), 2)

    def test_triage_orchestrator_preserves_9_stages_and_handles_corrupt_browser_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_dir = Path(tmpdir) / "evidence"
            corrupt_db = ev_dir / "home" / "alice" / ".mozilla" / "firefox" / "bad.default" / "places.sqlite"
            corrupt_db.parent.mkdir(parents=True, exist_ok=True)
            corrupt_db.write_bytes(b"corrupt sqlite bytes")

            cfg = TriageConfig(evidence_path=str(ev_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertEqual(len(res.stage_results), 9)
            self.assertTrue(res.summary.is_success)
            fs_stage = next(s for s in res.stage_results if s.stage_id == "filesystem_collection")
            self.assertTrue(any("Browser history warning" in w for w in fs_stage.warnings))

            # Verify valid browser profile yields HostArtifactCategory.BROWSER in HostArtifactCollection
            _create_firefox_db(
                ev_dir / "root" / ".mozilla" / "firefox" / "root.default" / "places.sqlite",
                url="https://root.example/",
                title="Root Visit",
                visit_dt=datetime(2026, 10, 21, 15, 0, 0, tzinfo=timezone.utc),
            )
            res2 = TriageOrchestrator(cfg).run()
            browser_arts = [
                a for a in res2.artifacts.artifacts
                if a.category == HostArtifactCategory.BROWSER.value
            ]
            self.assertEqual(len(browser_arts), 1)
            self.assertEqual(browser_arts[0].artifact_type, "firefox_history")
            self.assertEqual(browser_arts[0].raw_data, "https://root.example/")


if __name__ == "__main__":
    unittest.main()

