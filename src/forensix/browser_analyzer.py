"""
Read-only Forensic Browser History Analyzer for ForensiX.

Parses browsing history observations from Firefox (`places.sqlite`) and
Chromium-based (`History`) SQLite databases without modifying the evidence
tree or leaving `-wal`, `-shm`, or `-journal` sidecars behind. Each target
database and any `-wal` sidecar are copied to a temporary directory outside
the evidence root, opened via `sqlite3` in read-only URI mode (`mode=ro`),
and cleaned up immediately after reading.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from forensix.identifier import normalize_relative_path


UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_BROWSER_EVENT_NAMESPACE = uuid.UUID("7f4f45d4-3c6e-4b3e-9a4e-64c6b1c8a910")


@dataclass(frozen=True)
class _BrowserSchemaSpec:
    browser: str
    epoch: datetime
    required_tables: Tuple[str, ...]
    query: str


_FIREFOX_SPEC = _BrowserSchemaSpec(
    browser="firefox",
    epoch=UNIX_EPOCH,
    required_tables=("moz_places", "moz_historyvisits"),
    query=(
        "SELECT v.id, p.url, p.title, p.visit_count, v.visit_date "
        "FROM moz_historyvisits AS v "
        "JOIN moz_places AS p ON v.place_id = p.id "
        "ORDER BY v.visit_date ASC, v.id ASC"
    ),
)

_CHROMIUM_SPEC = _BrowserSchemaSpec(
    browser="chromium",
    epoch=CHROMIUM_EPOCH,
    required_tables=("urls", "visits"),
    query=(
        "SELECT v.id, u.url, u.title, u.visit_count, v.visit_time "
        "FROM visits AS v "
        "JOIN urls AS u ON v.url = u.id "
        "ORDER BY v.visit_time ASC, v.id ASC"
    ),
)


@dataclass(frozen=True)
class BrowserHistoryEvent:
    """
    Immutable observation of a recorded browser history visit.

    Attributes:
        event_id: Deterministic unique tracking identifier.
        browser: Browser family string (`firefox` or `chromium`).
        url: Visited URL recorded in the database.
        title: Recorded page title, or None if unset.
        visit_time: Timezone-aware UTC datetime of the visit observation.
        source_path: Evidence-relative POSIX path to the source database file.
        row_id: Source visit row identifier (`moz_historyvisits.id` or `visits.id`).
        visit_count: Recorded aggregate visit count on the URL entry, if present.
    """

    event_id: str
    browser: str
    url: str
    title: Optional[str]
    visit_time: datetime
    source_path: str
    row_id: int
    visit_count: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert browser history event to a JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "browser": self.browser,
            "url": self.url,
            "title": self.title,
            "visit_time": self.visit_time.isoformat(),
            "source_path": self.source_path,
            "row_id": self.row_id,
            "visit_count": self.visit_count,
        }


@dataclass(frozen=True)
class BrowserFileError:
    """
    Immutable record of an unreadable, corrupt, or schema-incomplete browser database.
    """

    source_path: str
    browser: str
    error: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert error record to a JSON-serializable dictionary."""
        return {
            "source_path": self.source_path,
            "browser": self.browser,
            "error": self.error,
        }


@dataclass(frozen=True)
class BrowserHistoryResult:
    """
    Immutable aggregate result from read-only browser history parsing.
    """

    evidence_root: str
    events: Tuple[BrowserHistoryEvent, ...]
    errors: Tuple[BrowserFileError, ...]
    files_inspected: Tuple[str, ...]
    total_events: int
    total_errors: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert browser history collection result to a JSON-serializable dictionary."""
        return {
            "evidence_root": self.evidence_root,
            "events": [ev.to_dict() for ev in self.events],
            "errors": [err.to_dict() for err in self.errors],
            "files_inspected": list(self.files_inspected),
            "total_events": self.total_events,
            "total_errors": self.total_errors,
        }


def _is_within_directory(base_dir: Path, target_path: Path) -> bool:
    """Verify that target_path resolves inside base_dir without symlink escape."""
    try:
        target_path.resolve().relative_to(base_dir.resolve())
        return True
    except (ValueError, RuntimeError):
        return False


def _relative_source_path(file_path: Path, evidence_root: Optional[Path]) -> str:
    """Return a normalized evidence-relative POSIX path when rooted, else basename."""
    if evidence_root is not None:
        try:
            rel = file_path.resolve().relative_to(evidence_root.resolve())
            normalized = normalize_relative_path(rel)
            if normalized:
                return normalized
        except (ValueError, RuntimeError):
            pass
    return normalize_relative_path(file_path.name)


def _convert_microseconds_to_utc(raw_timestamp: Any, epoch: datetime) -> Optional[datetime]:
    """Convert integer microseconds since `epoch` to an aware UTC datetime."""
    if raw_timestamp is None:
        return None
    try:
        micros = int(raw_timestamp)
        if micros <= 0:
            return None
        return epoch + timedelta(microseconds=micros)
    except (ValueError, TypeError, OverflowError):
        return None


def _open_readonly_uri(db_file: Path) -> sqlite3.Connection:
    """Open a SQLite database strictly in read-only URI mode."""
    safe_path = str(db_file).replace("?", "%3F").replace("#", "%23")
    return sqlite3.connect(f"file:{safe_path}?mode=ro", uri=True)


def _parse_database_file(
    db_path: Path,
    spec: _BrowserSchemaSpec,
    evidence_root: Optional[Path] = None,
) -> Tuple[List[BrowserHistoryEvent], Optional[BrowserFileError]]:
    """
    Copy db_path and any -wal sidecar to a temporary directory, open read-only,
    extract visit rows, and remove the temporary directory on exit.
    """
    rel_path = _relative_source_path(db_path, evidence_root)

    if not db_path.exists():
        return [], BrowserFileError(
            source_path=rel_path,
            browser=spec.browser,
            error=f"Database file does not exist: '{rel_path}'",
        )
    if db_path.is_symlink() and evidence_root is not None and not _is_within_directory(evidence_root, db_path):
        return [], BrowserFileError(
            source_path=rel_path,
            browser=spec.browser,
            error=f"Symbolic link points outside evidence root: '{rel_path}'",
        )
    if not db_path.is_file():
        return [], BrowserFileError(
            source_path=rel_path,
            browser=spec.browser,
            error=f"Target path is not a regular file: '{rel_path}'",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="forensix_browser_") as tmpdir:
            copy_db = Path(tmpdir) / db_path.name
            shutil.copyfile(db_path, copy_db)

            wal_sidecar = Path(f"{db_path}-wal")
            if wal_sidecar.exists() and wal_sidecar.is_file():
                if evidence_root is None or _is_within_directory(evidence_root, wal_sidecar):
                    shutil.copyfile(wal_sidecar, Path(f"{copy_db}-wal"))

            conn: Optional[sqlite3.Connection] = None
            try:
                conn = _open_readonly_uri(copy_db)
                table_rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
                existing_tables = {row[0] for row in table_rows}
                missing = [tbl for tbl in spec.required_tables if tbl not in existing_tables]
                if missing:
                    return [], BrowserFileError(
                        source_path=rel_path,
                        browser=spec.browser,
                        error=f"Missing required SQLite table(s): {', '.join(missing)}",
                    )

                rows = conn.execute(spec.query).fetchall()
            finally:
                if conn is not None:
                    conn.close()
    except (sqlite3.Error, OSError) as exc:
        return [], BrowserFileError(
            source_path=rel_path,
            browser=spec.browser,
            error=f"Unable to read {spec.browser} SQLite database '{rel_path}': {exc}",
        )

    events: List[BrowserHistoryEvent] = []
    for row_id_raw, url_raw, title_raw, count_raw, ts_raw in rows:
        visit_dt = _convert_microseconds_to_utc(ts_raw, spec.epoch)
        if visit_dt is None or url_raw is None:
            continue
        row_id = int(row_id_raw)
        url_str = str(url_raw)
        title_str = str(title_raw) if title_raw is not None else None
        visit_count = int(count_raw) if count_raw is not None else None
        det_seed = f"{spec.browser}|{rel_path}|{row_id}|{url_str}|{visit_dt.isoformat()}"
        event_id = f"BROWSER-{uuid.uuid5(_BROWSER_EVENT_NAMESPACE, det_seed)}"
        events.append(
            BrowserHistoryEvent(
                event_id=event_id,
                browser=spec.browser,
                url=url_str,
                title=title_str,
                visit_time=visit_dt,
                source_path=rel_path,
                row_id=row_id,
                visit_count=visit_count,
            )
        )

    return events, None


def _parse_single(
    db_path: Union[str, Path],
    spec: _BrowserSchemaSpec,
    evidence_root: Optional[Union[str, Path]] = None,
) -> BrowserHistoryResult:
    target = Path(db_path)
    root_path = Path(evidence_root).resolve() if evidence_root is not None else None
    rel_path = _relative_source_path(target, root_path)
    events, err = _parse_database_file(target, spec, evidence_root=root_path)
    errors = (err,) if err is not None else ()
    return BrowserHistoryResult(
        evidence_root=str(root_path) if root_path is not None else "",
        events=tuple(events),
        errors=errors,
        files_inspected=(rel_path,),
        total_events=len(events),
        total_errors=len(errors),
    )


def parse_firefox_history(
    db_path: Union[str, Path],
    evidence_root: Optional[Union[str, Path]] = None,
) -> BrowserHistoryResult:
    """Parse a single Firefox `places.sqlite` database in strict read-only mode."""
    return _parse_single(db_path, _FIREFOX_SPEC, evidence_root=evidence_root)


def parse_chromium_history(
    db_path: Union[str, Path],
    evidence_root: Optional[Union[str, Path]] = None,
) -> BrowserHistoryResult:
    """Parse a single Chromium `History` SQLite database in strict read-only mode."""
    return _parse_single(db_path, _CHROMIUM_SPEC, evidence_root=evidence_root)


_DISCOVERY_PATTERNS: Tuple[Tuple[str, bool, Tuple[str, ...], str, _BrowserSchemaSpec], ...] = (
    # Linux Firefox
    ("home", True, (".mozilla", "firefox"), "places.sqlite", _FIREFOX_SPEC),
    ("root", False, (".mozilla", "firefox"), "places.sqlite", _FIREFOX_SPEC),
    # Linux Chromium
    ("home", True, (".config", "chromium"), "History", _CHROMIUM_SPEC),
    ("home", True, (".config", "google-chrome"), "History", _CHROMIUM_SPEC),
    ("home", True, (".config", "brave-browser"), "History", _CHROMIUM_SPEC),
    ("home", True, (".config", "microsoft-edge"), "History", _CHROMIUM_SPEC),
    ("root", False, (".config", "chromium"), "History", _CHROMIUM_SPEC),
    ("root", False, (".config", "google-chrome"), "History", _CHROMIUM_SPEC),
    ("root", False, (".config", "brave-browser"), "History", _CHROMIUM_SPEC),
    ("root", False, (".config", "microsoft-edge"), "History", _CHROMIUM_SPEC),
    # Windows Chromium
    ("Users", True, ("AppData", "Local", "Google", "Chrome", "User Data"), "History", _CHROMIUM_SPEC),
    ("Users", True, ("AppData", "Local", "Microsoft", "Edge", "User Data"), "History", _CHROMIUM_SPEC),
    ("Users", True, ("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"), "History", _CHROMIUM_SPEC),
    # Windows Firefox
    ("Users", True, ("AppData", "Roaming", "Mozilla", "Firefox", "Profiles"), "places.sqlite", _FIREFOX_SPEC),
    # macOS Chromium
    ("Users", True, ("Library", "Application Support", "Google", "Chrome"), "History", _CHROMIUM_SPEC),
    ("Users", True, ("Library", "Application Support", "Microsoft Edge"), "History", _CHROMIUM_SPEC),
    ("Users", True, ("Library", "Application Support", "BraveSoftware", "Brave-Browser"), "History", _CHROMIUM_SPEC),
    # macOS Firefox
    ("Users", True, ("Library", "Application Support", "Firefox", "Profiles"), "places.sqlite", _FIREFOX_SPEC),
)


def _match_browser_spec(rel_parts: Tuple[str, ...]) -> Optional[_BrowserSchemaSpec]:
    """Identify whether a relative file path strictly matches an allowed browser profile layout."""
    if not rel_parts:
        return None
    for root_dir, has_user, middle_parts, filename, spec in _DISCOVERY_PATTERNS:
        mid_start = 2 if has_user else 1
        expected_len = mid_start + len(middle_parts) + 2
        if len(rel_parts) != expected_len:
            continue
        if rel_parts[0] != root_dir or rel_parts[-1] != filename:
            continue
        if has_user and not rel_parts[1]:
            continue
        if not rel_parts[-2]:
            continue
        if rel_parts[mid_start : mid_start + len(middle_parts)] == middle_parts:
            return spec
    return None


def analyze_browser_history(
    evidence_root: Union[str, Path],
) -> BrowserHistoryResult:
    """
    Discover and parse Firefox and Chromium history databases inside `evidence_root`.

    Never mutates files inside `evidence_root` and blocks out-of-bounds symlinks.
    """
    root = Path(evidence_root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Evidence directory does not exist: '{root}'")
    if not root.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: '{root}'")

    discovered: List[Tuple[str, Path, _BrowserSchemaSpec]] = []
    for current_dir, dir_names, file_names in os.walk(root, followlinks=False):
        dir_names.sort()
        file_names.sort()
        current_path = Path(current_dir)
        for fname in file_names:
            candidate = current_path / fname
            if candidate.is_symlink() and not _is_within_directory(root, candidate):
                continue
            rel = candidate.relative_to(root)
            spec = _match_browser_spec(rel.parts)
            if spec is not None:
                discovered.append((normalize_relative_path(rel), candidate, spec))

    all_events: List[BrowserHistoryEvent] = []
    all_errors: List[BrowserFileError] = []
    inspected: List[str] = []

    for rel_path, candidate, spec in sorted(discovered, key=lambda item: item[0]):
        inspected.append(rel_path)
        events, err = _parse_database_file(candidate, spec, evidence_root=root)
        all_events.extend(events)
        if err is not None:
            all_errors.append(err)

    all_events.sort(key=lambda ev: (ev.visit_time, ev.source_path, ev.row_id))

    return BrowserHistoryResult(
        evidence_root=str(root),
        events=tuple(all_events),
        errors=tuple(all_errors),
        files_inspected=tuple(inspected),
        total_events=len(all_events),
        total_errors=len(all_errors),
    )
