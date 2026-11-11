"""
Tests for ForensiX read-only browser history parsing (Firefox & Chromium).

All synthetic SQLite fixtures are built inside temporary directories so the
repository and examples tree remain untouched. Tests verify UTC timestamp
conversion, WAL and rollback integrity, evidence-relative paths, and error
handling on corrupt or schema-incomplete files.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from typing import Dict, Tuple


UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _to_unix_microseconds(dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - UNIX_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _to_chromium_microseconds(dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - CHROMIUM_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _snapshot_tree(root: Path) -> Dict[str, str]:
    """Return {relative_posix_path: sha256_hex} for every file under root."""
    manifest: Dict[str, str] = {}
    for current_dir, dir_names, file_names in os.walk(root):
        dir_names.sort()
        file_names.sort()
        for fname in file_names:
            fpath = Path(current_dir) / fname
            rel = fpath.relative_to(root).as_posix()
            manifest[rel] = hashlib.sha256(fpath.read_bytes()).hexdigest()
    return manifest


def _create_firefox_places(
    db_path: Path,
    rows: Tuple[Tuple[int, str, str, int, datetime], ...],
    *,
    wal_mode: bool = False,
) -> sqlite3.Connection | None:
    """Create a synthetic Firefox places.sqlite database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    if wal_mode:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute(
        """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_date INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER NOT NULL,
            visit_date INTEGER NOT NULL
        )
        """
    )
    if wal_mode:
        # Checkpoint base schema so subsequent inserts sit uncheckpointed in -wal.
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    for place_id, (visit_id, url, title, visit_count, visit_dt) in enumerate(rows, start=1):
        ts_us = _to_unix_microseconds(visit_dt)
        conn.execute(
            "INSERT INTO moz_places (id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
            (place_id, url, title, visit_count, ts_us),
        )
        conn.execute(
            "INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (?, ?, ?)",
            (visit_id, place_id, ts_us),
        )
    conn.commit()
    if wal_mode:
        return conn
    conn.close()
    return None


def _create_chromium_history(
    db_path: Path,
    rows: Tuple[Tuple[int, str, str, int, datetime], ...],
    *,
    wal_mode: bool = False,
) -> sqlite3.Connection | None:
    """Create a synthetic Chromium History SQLite database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    if wal_mode:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_time INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL
        )
        """
    )
    if wal_mode:
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    for url_id, (visit_id, url, title, visit_count, visit_dt) in enumerate(rows, start=1):
        ts_us = _to_chromium_microseconds(visit_dt)
        conn.execute(
            "INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
            (url_id, url, title, visit_count, ts_us),
        )
        conn.execute(
            "INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)",
            (visit_id, url_id, ts_us),
        )
    conn.commit()
    if wal_mode:
        return conn
    conn.close()
    return None


class TestBrowserHistoryAnalyzer(unittest.TestCase):
    """Gate 1 specification tests for standalone browser history parsing."""

    def test_a_firefox_timestamps_convert_to_utc(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        dt1 = datetime(2026, 10, 21, 7, 12, 15, 400000, tzinfo=timezone.utc)
        dt2 = datetime(2026, 10, 21, 7, 15, 22, 100000, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            db_path = root / "home" / "alice" / ".mozilla" / "firefox" / "p1.default" / "places.sqlite"
            _create_firefox_places(
                db_path,
                (
                    (101, "https://docs.python.org/3/", "Python Docs", 3, dt1),
                    (102, "https://sqlite.org/uri.html", "SQLite URIs", 1, dt2),
                ),
            )

            result = analyze_browser_history(root)
            self.assertEqual(len(result.errors), 0)
            self.assertEqual(len(result.events), 2)

            by_id = {ev.row_id: ev for ev in result.events}
            self.assertEqual(by_id[101].browser, "firefox")
            self.assertEqual(by_id[101].url, "https://docs.python.org/3/")
            self.assertEqual(by_id[101].title, "Python Docs")
            self.assertEqual(by_id[101].visit_time, dt1)
            self.assertEqual(by_id[101].visit_time.tzinfo, timezone.utc)

            self.assertEqual(by_id[102].visit_time, dt2)
            self.assertEqual(by_id[102].visit_time.tzinfo, timezone.utc)

    def test_b_chromium_timestamps_convert_from_1601_epoch(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        dt1 = datetime(2026, 10, 21, 8, 0, 5, 250000, tzinfo=timezone.utc)
        dt2 = datetime(2026, 10, 21, 8, 5, 42, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            db_path = root / "home" / "alice" / ".config" / "chromium" / "Default" / "History"
            _create_chromium_history(
                db_path,
                (
                    (201, "https://example.org/login", "Portal", 2, dt1),
                    (202, "https://example.org/status", "Status", 5, dt2),
                ),
            )

            result = analyze_browser_history(root)
            self.assertEqual(len(result.errors), 0)
            self.assertEqual(len(result.events), 2)

            by_id = {ev.row_id: ev for ev in result.events}
            self.assertEqual(by_id[201].browser, "chromium")
            self.assertEqual(by_id[201].url, "https://example.org/login")
            self.assertEqual(by_id[201].title, "Portal")
            self.assertEqual(by_id[201].visit_time, dt1)
            self.assertEqual(by_id[201].visit_time.tzinfo, timezone.utc)
            self.assertEqual(by_id[202].visit_time, dt2)

    def test_c_database_bytes_and_directory_listing_unchanged_standard_and_wal(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        dt1 = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 10, 21, 9, 1, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ff_db = root / "home" / "alice" / ".mozilla" / "firefox" / "p1.default" / "places.sqlite"
            ch_db = root / "home" / "alice" / ".config" / "chromium" / "Default" / "History"
            _create_firefox_places(ff_db, ((1, "https://a.example/", "A", 1, dt1),))
            wal_conn = _create_chromium_history(
                ch_db,
                ((2, "https://b.example/", "B", 1, dt2),),
                wal_mode=True,
            )
            try:
                before_listing_ff = sorted(p.name for p in ff_db.parent.iterdir())
                before_listing_ch = sorted(p.name for p in ch_db.parent.iterdir())
                before_manifest = _snapshot_tree(root)

                result = analyze_browser_history(root)
                self.assertEqual(len(result.errors), 0)
                self.assertEqual(len(result.events), 2)

                after_listing_ff = sorted(p.name for p in ff_db.parent.iterdir())
                after_listing_ch = sorted(p.name for p in ch_db.parent.iterdir())
                after_manifest = _snapshot_tree(root)

                self.assertEqual(after_listing_ff, ["places.sqlite"])
                self.assertEqual(after_listing_ch, before_listing_ch)
                self.assertEqual(after_manifest, before_manifest)
            finally:
                if wal_conn is not None:
                    wal_conn.close()

    def test_d_missing_table_and_corrupt_file_return_clear_errors(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Valid SQLite database missing moz_historyvisits table
            missing_tbl = root / "home" / "alice" / ".mozilla" / "firefox" / "broken.default" / "places.sqlite"
            missing_tbl.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(missing_tbl))
            conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
            conn.commit()
            conn.close()

            # Corrupt Chromium History file
            corrupt_db = root / "home" / "alice" / ".config" / "google-chrome" / "Default" / "History"
            corrupt_db.parent.mkdir(parents=True, exist_ok=True)
            corrupt_db.write_bytes(b"not a valid sqlite database payload\x00\xff")

            result = analyze_browser_history(root)
            self.assertEqual(len(result.events), 0)
            self.assertEqual(len(result.errors), 2)

            err_by_path = {err.source_path: err.error for err in result.errors}
            ff_rel = "home/alice/.mozilla/firefox/broken.default/places.sqlite"
            ch_rel = "home/alice/.config/google-chrome/Default/History"
            self.assertIn(ff_rel, err_by_path)
            self.assertIn(ch_rel, err_by_path)
            self.assertTrue(err_by_path[ff_rel])
            self.assertTrue(err_by_path[ch_rel])

    def test_e_events_record_evidence_relative_source_path(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        dt1 = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 10, 21, 10, 5, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ff_rel = "home/bob/.mozilla/firefox/work.default/places.sqlite"
            ch_rel = "home/bob/.config/google-chrome/Profile 1/History"
            _create_firefox_places(root / ff_rel, ((11, "https://one.example/", "One", 1, dt1),))
            _create_chromium_history(root / ch_rel, ((22, "https://two.example/", "Two", 1, dt2),))

            result = analyze_browser_history(root)
            self.assertEqual(len(result.errors), 0)
            self.assertEqual(len(result.events), 2)

            for ev in result.events:
                self.assertIs(type(ev.source_path), str)
                self.assertFalse(ev.source_path.startswith("/"))
                self.assertNotIn(str(root), ev.source_path)

            paths = {ev.browser: ev.source_path for ev in result.events}
            self.assertEqual(paths["firefox"], ff_rel)
            self.assertEqual(paths["chromium"], ch_rel)

    def test_f_wal_mode_returns_uncheckpointed_visits_without_gaining_sidecars(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        dt_uncheckpointed = datetime(2026, 10, 21, 11, 30, 45, 500000, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir, tempfile.TemporaryDirectory() as snap_dir:
            live_root = Path(tmpdir)
            live_db = live_root / "home" / "alice" / ".mozilla" / "firefox" / "wal.default" / "places.sqlite"
            wal_conn = _create_firefox_places(
                live_db,
                ((77, "https://uncheckpointed.example/page", "WAL Page", 1, dt_uncheckpointed),),
                wal_mode=True,
            )
            try:
                wal_sidecar = Path(f"{live_db}-wal")
                self.assertTrue(wal_sidecar.exists())
                self.assertGreater(wal_sidecar.stat().st_size, 0)

                # Snapshot only places.sqlite and places.sqlite-wal (no -shm present)
                snap_root = Path(snap_dir)
                snap_db = snap_root / "home" / "alice" / ".mozilla" / "firefox" / "wal.default" / "places.sqlite"
                snap_db.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(live_db, snap_db)
                shutil.copy2(wal_sidecar, Path(f"{snap_db}-wal"))
            finally:
                if wal_conn is not None:
                    wal_conn.close()

            before_listing = sorted(p.name for p in snap_db.parent.iterdir())
            self.assertEqual(before_listing, ["places.sqlite", "places.sqlite-wal"])
            before_manifest = _snapshot_tree(snap_root)

            result = analyze_browser_history(snap_root)
            self.assertEqual(len(result.errors), 0)
            self.assertEqual(len(result.events), 1)
            ev = result.events[0]
            self.assertEqual(ev.browser, "firefox")
            self.assertEqual(ev.url, "https://uncheckpointed.example/page")
            self.assertEqual(ev.title, "WAL Page")
            self.assertEqual(ev.visit_time, dt_uncheckpointed)
            self.assertEqual(ev.row_id, 77)
            self.assertEqual(ev.source_path, "home/alice/.mozilla/firefox/wal.default/places.sqlite")

            after_listing = sorted(p.name for p in snap_db.parent.iterdir())
            after_manifest = _snapshot_tree(snap_root)
            self.assertEqual(after_listing, before_listing)
            self.assertEqual(after_manifest, before_manifest)


if __name__ == "__main__":
    unittest.main()
