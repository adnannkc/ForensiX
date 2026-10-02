"""
Forensic Timestamp Normalization Engine for ForensiX (V3.2 Timeline Reconstruction).

Provides deterministic, forensically sound normalization of valid timestamp representations
into canonical datetime objects and standardized ISO 8601 strings, building on the foundational
V3.1 TimelineEvent model.

Core Principles:
1. Never fabricate timestamps: Ambiguous, incomplete, or invalid input is rejected rather than guessed.
2. Preserve original timestamps: Raw timestamp representations are retained for audit provenance.
3. Deterministic behavior: Identical inputs produce byte-identical normalized outputs regardless of host locale or system timezone.
4. Explicit timezone handling: Timezone-aware inputs are deterministically converted to UTC; timezone-naive inputs remain naive without synthetic timezones.
5. High-precision preservation: Microsecond and millisecond fractional precision is preserved without truncation.
6. Date-only rejection: Date-only strings without time components are rejected to prevent fabricating midnight.
7. No forensic interpretation: Normalization performs purely chronological parsing; no risk scoring, event classification, or threat detection.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re
from typing import Any, Dict, Optional, Union


def is_timezone_aware(val: Union[datetime, str]) -> bool:
    """
    Determine whether a datetime object or timestamp string contains explicit timezone information.

    Args:
        val: A datetime instance or a timestamp string.

    Returns:
        bool: True if timezone information is explicitly present, False if naive.

    Raises:
        TypeError: If val is not a str or datetime.
        ValueError: If val is an invalid timestamp string.
    """
    if isinstance(val, datetime):
        return val.tzinfo is not None and val.tzinfo.utcoffset(val) is not None
    if isinstance(val, str):
        dt = normalize_timestamp(val, to_utc=False)
        return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None
    raise TypeError(f"is_timezone_aware requires str or datetime, got {type(val).__name__}")


def format_iso_timestamp(dt: datetime, use_z: bool = True) -> str:
    """
    Format a datetime object into a deterministic ISO 8601 string.

    Args:
        dt: The datetime instance to format.
        use_z: If True and the datetime is in UTC, suffix with 'Z' instead of '+00:00'.

    Returns:
        str: Deterministic ISO 8601 formatted timestamp string.

    Raises:
        TypeError: If dt is not a datetime instance.
    """
    if not isinstance(dt, datetime):
        raise TypeError(f"format_iso_timestamp requires datetime, got {type(dt).__name__}")
    if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
        if dt.utcoffset() == timedelta(0):
            if use_z:
                return dt.isoformat().replace("+00:00", "Z")
            return dt.isoformat()
        return dt.isoformat()
    # Timezone-naive datetime
    return dt.isoformat()


def _extract_offset_str(clean_str: str) -> Optional[str]:
    """Extract the literal timezone offset string from a clean timestamp string if present."""
    if clean_str.endswith(" UTC") or clean_str.endswith(" utc"):
        return "UTC"
    if clean_str.endswith("Z") or clean_str.endswith("z"):
        return "Z"
    match = re.search(r"([+-]\d{2}:?\d{2})$", clean_str)
    if match:
        return match.group(1)
    return None


@dataclass(frozen=True)
class NormalizedTimestamp:
    """
    Immutable structured result of timestamp normalization with forensic provenance.

    Attributes:
        normalized_datetime: Canonical normalized datetime (converted to UTC if aware, naive if naive).
        raw_timestamp: The exact original input string or representation prior to normalization.
        is_timezone_aware: Boolean indicating if the original input contained timezone information.
        original_tz_offset: Original timezone offset string (e.g. '+05:30', 'UTC', 'Z'), or None if naive.
    """

    normalized_datetime: datetime
    raw_timestamp: str
    is_timezone_aware: bool
    original_tz_offset: Optional[str] = None

    @property
    def iso_format(self) -> str:
        """Deterministic ISO 8601 string representation."""
        return format_iso_timestamp(self.normalized_datetime)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a deterministic JSON-serializable dictionary representation."""
        return {
            "normalized_datetime": self.normalized_datetime.isoformat(),
            "raw_timestamp": self.raw_timestamp,
            "is_timezone_aware": self.is_timezone_aware,
            "original_tz_offset": self.original_tz_offset,
        }


def normalize_timestamp(
    val: Union[datetime, str],
    to_utc: bool = True,
) -> datetime:
    """
    Normalize a forensic timestamp representation into a canonical Python datetime.

    Supported inputs:
    - ISO 8601 strings (e.g. '2026-09-30T14:30:00Z', '2026-09-30T14:30:00+05:30', '2026-09-30T14:30:00-04:00')
    - Common space-separated representations (e.g. '2026-09-30 14:30:00', '2026-09-30 14:30:00+05:30', '2026-09-30 14:30:00 UTC')
    - Slash-separated dates with time (e.g. '2026/09/30 14:30:00')
    - High-precision timestamps with milliseconds or microseconds (e.g. '...14:30:00.123456+05:30')
    - Python datetime objects (both aware and naive)

    Forensic guarantees:
    - Timezone-aware timestamps: Converted explicitly to UTC if to_utc=True (default); offset preserved if False.
    - Timezone-naive timestamps: Preserved as naive (tzinfo=None); NEVER converted to UTC or local machine timezone.
    - Precision: Microsecond and millisecond fractional seconds are preserved exactly.
    - Date-only strings: Rejected (e.g. '2026-09-30') because midnight cannot be forensically assumed.
    - Incomplete/ambiguous strings: Rejected (e.g. yearless syslog 'Oct 1 12:00:00').

    Args:
        val: The timestamp string or datetime object to normalize.
        to_utc: If True (default), convert timezone-aware timestamps to UTC.

    Returns:
        datetime: The normalized canonical datetime object.

    Raises:
        TypeError: If val is not a str or datetime instance.
        ValueError: If val is empty, whitespace, date-only, ambiguous, or malformed.
    """
    if val is None:
        raise ValueError("Timestamp cannot be None")

    if isinstance(val, datetime):
        if val.tzinfo is not None and val.tzinfo.utcoffset(val) is not None:
            return val.astimezone(timezone.utc) if to_utc else val
        return val

    if not isinstance(val, str):
        raise TypeError(f"Expected str or datetime, got {type(val).__name__}")

    clean = val.strip()
    if not clean:
        raise ValueError("Timestamp string cannot be empty or whitespace")

    # Reject date-only strings lacking time component to prevent fabricating midnight
    if ":" not in clean:
        raise ValueError(
            f"Date-only timestamp '{val}' lacks a time component. "
            "Forensic timestamps require an explicit time component to prevent fabricating midnight."
        )

    # Standardize common variations before parsing
    norm_str = clean
    if norm_str.endswith(" UTC") or norm_str.endswith(" utc"):
        norm_str = norm_str[:-4] + "Z"
    elif norm_str.endswith("z"):
        norm_str = norm_str[:-1] + "Z"

    # Support slash-delimited date prefix (YYYY/MM/DD)
    if len(norm_str) >= 10 and norm_str[4] == "/" and norm_str[7] == "/":
        norm_str = norm_str[:4] + "-" + norm_str[5:7] + "-" + norm_str[8:]

    try:
        parsed = datetime.fromisoformat(norm_str)
    except Exception as err:
        raise ValueError(
            f"Failed to parse forensic timestamp '{val}': invalid or unrecognized format ({err})"
        ) from err

    # Apply UTC normalization if timezone-aware
    if parsed.tzinfo is not None and parsed.tzinfo.utcoffset(parsed) is not None:
        return parsed.astimezone(timezone.utc) if to_utc else parsed

    # Return naive datetime without fabricating a timezone
    return parsed


def parse_timestamp(
    val: Union[datetime, str],
    to_utc: bool = True,
) -> NormalizedTimestamp:
    """
    Parse and normalize a forensic timestamp into a structured NormalizedTimestamp record.

    Preserves both the normalized canonical datetime and the original raw input representation
    along with provenance metadata (awareness flag and original timezone offset string).

    Args:
        val: The timestamp string or datetime object to parse.
        to_utc: If True (default), normalize timezone-aware timestamps to UTC.

    Returns:
        NormalizedTimestamp: Immutable record containing normalized datetime and provenance.

    Raises:
        TypeError: If val is not a str or datetime.
        ValueError: If val cannot be parsed as a valid timestamp.
    """
    raw_str = val.isoformat() if isinstance(val, datetime) else str(val)
    offset_str: Optional[str] = None

    if isinstance(val, str):
        offset_str = _extract_offset_str(val.strip())
    elif isinstance(val, datetime):
        if val.tzinfo is not None and val.tzinfo.utcoffset(val) is not None:
            offset_delta = val.utcoffset()
            if offset_delta == timedelta(0):
                offset_str = "Z"
            else:
                total_seconds = int(offset_delta.total_seconds())  # type: ignore
                sign = "+" if total_seconds >= 0 else "-"
                total_seconds = abs(total_seconds)
                hours, remainder = divmod(total_seconds, 3600)
                minutes = remainder // 60
                offset_str = f"{sign}{hours:02d}:{minutes:02d}"

    normalized_dt = normalize_timestamp(val, to_utc=to_utc)
    aware = normalized_dt.tzinfo is not None and normalized_dt.tzinfo.utcoffset(normalized_dt) is not None

    return NormalizedTimestamp(
        normalized_datetime=normalized_dt,
        raw_timestamp=raw_str,
        is_timezone_aware=aware,
        original_tz_offset=offset_str,
    )
