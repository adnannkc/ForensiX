"""
Gate 1 tests for strict browser history discovery rules in ForensiX.

All synthetic databases and sidecar files are created inside temporary
directories via `tempfile.TemporaryDirectory` so the repository and examples
tree remain untouched.
"""

from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest


UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SAMPLE_DT = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)


def _microseconds_since(epoch: datetime, dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _create_firefox_db(
    db_path: Path,
    url: str = "https://example.org/firefox",
    title: str = "Firefox Visit",
    visit_id: int = 1,
    *,
    wal_mode: bool = False,
) -> sqlite3.Connection | None:
    """Create a synthetic Firefox places.sqlite database at `db_path`."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    if wal_mode:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute(
        "CREATE TABLE moz_places ("
        "id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, "
        "visit_count INTEGER DEFAULT 0, last_visit_date INTEGER)"
    )
    conn.execute(
        "CREATE TABLE moz_historyvisits ("
        "id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, visit_date INTEGER NOT NULL)"
    )
    if wal_mode:
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    ts_us = _microseconds_since(UNIX_EPOCH, SAMPLE_DT)
    conn.execute(
        "INSERT INTO moz_places (id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
        (1, url, title, 1, ts_us),
    )
    conn.execute(
        "INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (?, ?, ?)",
        (visit_id, 1, ts_us),
    )
    conn.commit()
    if wal_mode:
        return conn
    conn.close()
    return None


def _create_chromium_db(
    db_path: Path,
    url: str = "https://example.org/chromium",
    title: str = "Chromium Visit",
    visit_id: int = 1,
) -> None:
    """Create a synthetic Chromium History database at `db_path`."""
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
    ts_us = _microseconds_since(CHROMIUM_EPOCH, SAMPLE_DT)
    conn.execute(
        "INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
        (1, url, title, 1, ts_us),
    )
    conn.execute(
        "INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)",
        (visit_id, 1, ts_us),
    )
    conn.commit()
    conn.close()


class TestBrowserDiscovery(unittest.TestCase):
    """Verify exact discovery patterns and sidecar handling for browser history."""

    def _assert_discovered(self, rel_path: str, browser_kind: str) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            db_path = root / rel_path
            if browser_kind == "firefox":
                _create_firefox_db(db_path)
            else:
                _create_chromium_db(db_path)

            result = analyze_browser_history(root)
            self.assertEqual(result.errors, ())
            self.assertEqual(result.files_inspected, (rel_path,))
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.events[0].source_path, rel_path)

    def _assert_not_discovered(self, rel_path: str, browser_kind: str) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            db_path = root / rel_path
            if browser_kind == "firefox":
                _create_firefox_db(db_path)
            else:
                _create_chromium_db(db_path)

            result = analyze_browser_history(root)
            self.assertEqual(result.files_inspected, ())
            self.assertEqual(result.events, ())
            self.assertEqual(result.errors, ())

    def _assert_lone_sidecar_ignored(self, rel_path: str) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sidecar_path = root / rel_path
            sidecar_path.parent.mkdir(parents=True, exist_ok=True)
            sidecar_path.write_bytes(b"sqlite sidecar bytes")

            result = analyze_browser_history(root)
            self.assertEqual(result.files_inspected, ())
            self.assertEqual(result.events, ())
            self.assertEqual(result.errors, ())

    # (a) Allowed discovery patterns (exact segment counts)

    def test_a1_discovers_home_firefox(self) -> None:
        self._assert_discovered(
            "home/alice/.mozilla/firefox/p1.default/places.sqlite",
            "firefox",
        )

    def test_a2_discovers_root_firefox(self) -> None:
        self._assert_discovered(
            "root/.mozilla/firefox/default.release/places.sqlite",
            "firefox",
        )

    def test_a3_discovers_home_chromium(self) -> None:
        self._assert_discovered(
            "home/alice/.config/chromium/Default/History",
            "chromium",
        )

    def test_a4_discovers_home_google_chrome(self) -> None:
        self._assert_discovered(
            "home/alice/.config/google-chrome/Profile 1/History",
            "chromium",
        )

    def test_a5_discovers_root_chromium(self) -> None:
        self._assert_discovered(
            "root/.config/chromium/Default/History",
            "chromium",
        )

    def test_a6_discovers_root_google_chrome(self) -> None:
        self._assert_discovered(
            "root/.config/google-chrome/Default/History",
            "chromium",
        )

    def test_a7_discovers_home_brave_browser(self) -> None:
        self._assert_discovered(
            "home/alice/.config/brave-browser/Default/History",
            "chromium",
        )

    def test_a8_discovers_root_brave_browser(self) -> None:
        self._assert_discovered(
            "root/.config/brave-browser/Profile 1/History",
            "chromium",
        )

    def test_a9_discovers_home_microsoft_edge(self) -> None:
        self._assert_discovered(
            "home/alice/.config/microsoft-edge/Default/History",
            "chromium",
        )

    def test_a10_discovers_root_microsoft_edge(self) -> None:
        self._assert_discovered(
            "root/.config/microsoft-edge/Profile 2/History",
            "chromium",
        )

    def test_a11_discovers_windows_chrome(self) -> None:
        self._assert_discovered(
            "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            "chromium",
        )

    def test_a12_discovers_windows_edge(self) -> None:
        self._assert_discovered(
            "Users/alice/AppData/Local/Microsoft/Edge/User Data/Profile 1/History",
            "chromium",
        )

    def test_a13_discovers_windows_brave(self) -> None:
        self._assert_discovered(
            "Users/alice/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
            "chromium",
        )

    def test_a14_discovers_windows_firefox(self) -> None:
        self._assert_discovered(
            "Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd1234.default-release/places.sqlite",
            "firefox",
        )

    def test_a15_discovers_macos_chrome(self) -> None:
        self._assert_discovered(
            "Users/alice/Library/Application Support/Google/Chrome/Default/History",
            "chromium",
        )

    def test_a16_discovers_macos_edge(self) -> None:
        self._assert_discovered(
            "Users/alice/Library/Application Support/Microsoft Edge/Profile 1/History",
            "chromium",
        )

    def test_a17_discovers_macos_brave(self) -> None:
        self._assert_discovered(
            "Users/alice/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
            "chromium",
        )

    def test_a18_discovers_macos_firefox(self) -> None:
        self._assert_discovered(
            "Users/alice/Library/Application Support/Firefox/Profiles/efgh5678.default-release/places.sqlite",
            "firefox",
        )

    # (b) Negative cases: each in its own isolated fixture

    def test_b1_rejects_home_user_places_sqlite(self) -> None:
        self._assert_not_discovered("home/alice/places.sqlite", "firefox")

    def test_b2_rejects_users_firefox_places_sqlite(self) -> None:
        self._assert_not_discovered(
            "Users/x/.mozilla/firefox/p/places.sqlite",
            "firefox",
        )

    def test_b3_rejects_users_history(self) -> None:
        self._assert_not_discovered("Users/x/History", "chromium")

    def test_b4_rejects_evidence_root_history(self) -> None:
        self._assert_not_discovered("History", "chromium")

    def test_b5_rejects_firefox_missing_profile_segment(self) -> None:
        self._assert_not_discovered(
            "home/alice/.mozilla/firefox/places.sqlite",
            "firefox",
        )

    def test_b6_rejects_firefox_too_deep(self) -> None:
        self._assert_not_discovered(
            "home/alice/.mozilla/firefox/p/extra/places.sqlite",
            "firefox",
        )

    # (c) Lone SQLite sidecars without a parent database produce no discovery result

    def test_c1_ignores_lone_wal_sidecar(self) -> None:
        self._assert_lone_sidecar_ignored(
            "home/alice/.mozilla/firefox/p1.default/places.sqlite-wal"
        )

    def test_c2_ignores_lone_shm_sidecar(self) -> None:
        self._assert_lone_sidecar_ignored(
            "home/alice/.mozilla/firefox/p1.default/places.sqlite-shm"
        )

    def test_c3_ignores_lone_journal_sidecar(self) -> None:
        self._assert_lone_sidecar_ignored(
            "home/alice/.mozilla/firefox/p1.default/places.sqlite-journal"
        )

    # (d) A -wal sidecar alongside a discovered places.sqlite is still read

    def test_d_wal_sidecar_next_to_discovered_places_sqlite_is_still_read(self) -> None:
        from forensix.browser_analyzer import analyze_browser_history

        with tempfile.TemporaryDirectory() as live_dir, tempfile.TemporaryDirectory() as snap_dir:
            rel_path = "home/alice/.mozilla/firefox/wal.default/places.sqlite"
            live_db = Path(live_dir) / rel_path
            wal_conn = _create_firefox_db(
                live_db,
                url="https://wal.example.org/uncheckpointed",
                title="WAL Discovery Page",
                visit_id=88,
                wal_mode=True,
            )
            try:
                wal_sidecar = Path(f"{live_db}-wal")
                self.assertTrue(wal_sidecar.exists())
                self.assertGreater(wal_sidecar.stat().st_size, 0)

                snap_root = Path(snap_dir)
                snap_db = snap_root / rel_path
                snap_db.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(live_db, snap_db)
                shutil.copy2(wal_sidecar, Path(f"{snap_db}-wal"))
            finally:
                if wal_conn is not None:
                    wal_conn.close()

            before_listing = sorted(p.name for p in snap_db.parent.iterdir())
            self.assertEqual(before_listing, ["places.sqlite", "places.sqlite-wal"])

            result = analyze_browser_history(snap_root)
            self.assertEqual(result.errors, ())
            self.assertEqual(result.files_inspected, (rel_path,))
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.events[0].url, "https://wal.example.org/uncheckpointed")
            self.assertEqual(result.events[0].row_id, 88)
            self.assertEqual(sorted(p.name for p in snap_db.parent.iterdir()), before_listing)


if __name__ == "__main__":
    unittest.main()

