"""
Forensic Linux Log Parser for ForensiX (V2.2 Linux Log Analysis).

Responsible for streaming, parsing, and structuring Linux text-based logs
(auth.log, secure, syslog, messages, and rotated/compressed versions) into
strongly typed LogEvent records while preserving evidence immutability.
"""

from collections import Counter
import gzip
from pathlib import Path
import re
from typing import Any, Dict, Iterator, Optional, Tuple, Union

from forensix.log_models import (
    LogEvent,
    LogEventType,
    LogParseResult,
    generate_event_id,
)
from forensix.timestamp_normalizer import normalize_bsd_timestamp

# Traditional RFC 3164 BSD syslog header (e.g., 'Sep 30 14:25:31 hostname sshd[1234]: message')
# Note: BSD syslog does NOT contain a year.
RE_BSD_SYSLOG = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$"
)

# RFC 5424 / ISO 8601 timestamp syslog header (e.g., '2026-09-30T14:25:31.123456+00:00 hostname sshd[1234]: message')
RE_ISO_SYSLOG = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+([^\s:]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$"
)

# SSH Event Patterns
RE_SSH_ACCEPTED = re.compile(
    r"^Accepted\s+(password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
RE_SSH_FAILED_INVALID = re.compile(
    r"^Failed\s+(password|publickey)\s+for\s+invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
RE_SSH_FAILED = re.compile(
    r"^Failed\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
RE_SSH_INVALID_USER = re.compile(
    r"^Invalid\s+user\s+(\S+)\s+from\s+(\S+)(?:\s+port\s+(\d+))?"
)
RE_SESSION_OPEN = re.compile(
    r"session opened for user\s+(\S+)(?:\s+by\s+\(uid=\d+\))?"
)
RE_SESSION_CLOSE = re.compile(
    r"session closed for user\s+(\S+)"
)

# Sudo Event Patterns
RE_SUDO_COMMAND = re.compile(
    r"^\s*(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)$"
)
RE_SUDO_SESSION_OPEN = re.compile(
    r"pam_unix\(sudo:session\):\s*session opened for user\s+(\S+)"
)
RE_SUDO_SESSION_CLOSE = re.compile(
    r"pam_unix\(sudo:session\):\s*session closed for user\s+(\S+)"
)


def iter_log_lines(file_path: Union[str, Path]) -> Iterator[Tuple[int, str]]:
    """
    Safely stream lines from a text or gzip-compressed log file.

    Forensic Safety:
    - Opens target strictly in read-only text mode ('rt').
    - Streams line-by-line using bounded memory (no full-file slurping).
    - Uses errors='replace' to safely handle invalid UTF-8 without raising errors.
    - Transparently streams gzip files without creating temporary files on disk.

    Args:
        file_path: Path to the target log file.

    Yields:
        Tuple of (1-indexed line number, stripped line content).

    Raises:
        FileNotFoundError: If the target does not exist.
        IsADirectoryError: If the target is a directory.
    """
    target = Path(file_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Log evidence file does not exist: '{target}'")
    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a log file: '{target}'")

    is_gz = target.name.endswith(".gz")

    if is_gz:
        with gzip.open(target, mode="rt", encoding="utf-8", errors="replace") as stream:
            for line_idx, line in enumerate(stream, start=1):
                yield line_idx, line.rstrip("\r\n")
    else:
        with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
            for line_idx, line in enumerate(stream, start=1):
                yield line_idx, line.rstrip("\r\n")


def parse_syslog_header(
    line: str,
    log_timestamp_year: Optional[int] = None,
) -> Optional[Tuple[str, Optional[str], str, str, Optional[int], str]]:
    """
    Attempt to extract standard syslog header fields from a raw line.

    Returns:
        Optional tuple of:
        (raw_timestamp, normalized_timestamp, hostname, service, pid, raw_message)
        where normalized_timestamp is None for BSD syslog (lacking year) unless
        an explicit log_timestamp_year is provided, or the ISO string if explicitly
        present in RFC 5424 logs.
    """
    # 1. Try ISO 8601 / RFC 5424 (contains year)
    iso_match = RE_ISO_SYSLOG.match(line)
    if iso_match:
        raw_ts = iso_match.group(1)
        hostname = iso_match.group(2)
        service = iso_match.group(3)
        pid = int(iso_match.group(4)) if iso_match.group(4) else None
        msg = iso_match.group(5)
        return raw_ts, raw_ts, hostname, service, pid, msg

    # 2. Try BSD / RFC 3164 (lacks year; normalized_timestamp remains None unless explicit year provided)
    bsd_match = RE_BSD_SYSLOG.match(line)
    if bsd_match:
        raw_ts = bsd_match.group(1)
        hostname = bsd_match.group(2)
        service = bsd_match.group(3)
        pid = int(bsd_match.group(4)) if bsd_match.group(4) else None
        msg = bsd_match.group(5)
        norm_ts: Optional[str] = None
        if log_timestamp_year is not None:
            dt = normalize_bsd_timestamp(raw_ts, log_timestamp_year=log_timestamp_year)
            if dt is not None:
                norm_ts = dt.isoformat()
        return raw_ts, norm_ts, hostname, service, pid, msg

    return None


def classify_log_message(service: Optional[str], message: str) -> Tuple[str, Dict[str, Any]]:
    """
    Classify a syslog message and extract structured attributes.

    Returns:
        Tuple of (LogEventType value, attributes dict).
    """
    # Normalize service name
    svc_lower = (service or "").lower()

    # SSH Events
    if "sshd" in svc_lower:
        m_acc = RE_SSH_ACCEPTED.search(message)
        if m_acc:
            return LogEventType.SSH_LOGIN_SUCCESS.value, {
                "auth_method": m_acc.group(1),
                "user": m_acc.group(2),
                "src_ip": m_acc.group(3),
                "src_port": int(m_acc.group(4)),
            }

        m_fail_inv = RE_SSH_FAILED_INVALID.search(message)
        if m_fail_inv:
            return LogEventType.SSH_INVALID_USER.value, {
                "auth_method": m_fail_inv.group(1),
                "user": m_fail_inv.group(2),
                "src_ip": m_fail_inv.group(3),
                "src_port": int(m_fail_inv.group(4)),
                "is_invalid_user": True,
            }

        m_fail = RE_SSH_FAILED.search(message)
        if m_fail:
            return LogEventType.SSH_LOGIN_FAILURE.value, {
                "auth_method": m_fail.group(1),
                "user": m_fail.group(2),
                "src_ip": m_fail.group(3),
                "src_port": int(m_fail.group(4)),
            }

        m_inv = RE_SSH_INVALID_USER.search(message)
        if m_inv:
            return LogEventType.SSH_INVALID_USER.value, {
                "user": m_inv.group(1),
                "src_ip": m_inv.group(2),
                "src_port": int(m_inv.group(3)) if m_inv.group(3) else None,
                "is_invalid_user": True,
            }

    # Sudo Events
    if "sudo" in svc_lower:
        m_sudo_cmd = RE_SUDO_COMMAND.search(message)
        if m_sudo_cmd:
            return LogEventType.SUDO_COMMAND.value, {
                "sudo_user": m_sudo_cmd.group(1),
                "tty": m_sudo_cmd.group(2),
                "pwd": m_sudo_cmd.group(3),
                "target_user": m_sudo_cmd.group(4),
                "command": m_sudo_cmd.group(5).strip(),
            }

        m_sopen = RE_SUDO_SESSION_OPEN.search(message)
        if m_sopen:
            return LogEventType.SESSION_OPEN.value, {
                "user": m_sopen.group(1),
                "service": "sudo",
            }

        m_sclose = RE_SUDO_SESSION_CLOSE.search(message)
        if m_sclose:
            return LogEventType.SESSION_CLOSE.value, {
                "user": m_sclose.group(1),
                "service": "sudo",
            }

    # General Session Management (PAM / systemd / login)
    m_open = RE_SESSION_OPEN.search(message)
    if m_open:
        return LogEventType.SESSION_OPEN.value, {
            "user": m_open.group(1),
            "service": service or "unknown",
        }

    m_close = RE_SESSION_CLOSE.search(message)
    if m_close:
        return LogEventType.SESSION_CLOSE.value, {
            "user": m_close.group(1),
            "service": service or "unknown",
        }

    # Default recognized syslog
    return LogEventType.GENERIC_SYSLOG.value, {}


def parse_log_line(
    line: str,
    line_number: int,
    source_path: str,
    source_artifact_id: Optional[str] = None,
    log_timestamp_year: Optional[int] = None,
) -> LogEvent:
    """
    Parse a single raw log line into an immutable LogEvent.

    Gracefully falls back to UNKNOWN_FORMAT if line structure is non-standard.
    """
    event_id = generate_event_id()

    # Empty / blank line handling
    if not line.strip():
        return LogEvent(
            event_id=event_id,
            source_artifact_id=source_artifact_id,
            source_path=source_path,
            line_number=line_number,
            raw_timestamp=None,
            normalized_timestamp=None,
            hostname=None,
            service=None,
            pid=None,
            event_type=LogEventType.UNKNOWN_FORMAT.value,
            attributes={},
            raw_message=line,
            raw_line=line,
        )

    header = parse_syslog_header(line, log_timestamp_year=log_timestamp_year)
    if header is None:
        # Unrecognized syslog structure: safely preserve the entire line
        return LogEvent(
            event_id=event_id,
            source_artifact_id=source_artifact_id,
            source_path=source_path,
            line_number=line_number,
            raw_timestamp=None,
            normalized_timestamp=None,
            hostname=None,
            service=None,
            pid=None,
            event_type=LogEventType.UNKNOWN_FORMAT.value,
            attributes={},
            raw_message=line,
            raw_line=line,
        )

    raw_ts, norm_ts, hostname, service, pid, msg = header
    event_type, attributes = classify_log_message(service, msg)

    return LogEvent(
        event_id=event_id,
        source_artifact_id=source_artifact_id,
        source_path=source_path,
        line_number=line_number,
        raw_timestamp=raw_ts,
        normalized_timestamp=norm_ts,
        hostname=hostname,
        service=service,
        pid=pid,
        event_type=event_type,
        attributes=attributes,
        raw_message=msg,
        raw_line=line,
    )


def stream_log_events(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
    log_timestamp_year: Optional[int] = None,
) -> Iterator[LogEvent]:
    """
    Stream structured LogEvent records line-by-line from a log file.

    Memory bounded: suitable for gigabyte-scale logs.
    """
    target = Path(file_path).resolve()
    canonical_path = str(target)

    for line_idx, line in iter_log_lines(target):
        try:
            yield parse_log_line(
                line=line,
                line_number=line_idx,
                source_path=canonical_path,
                source_artifact_id=artifact_id,
                log_timestamp_year=log_timestamp_year,
            )
        except Exception:
            # Defensive catch-all to guarantee a malformed line never halts the stream
            yield LogEvent(
                event_id=generate_event_id(),
                source_artifact_id=artifact_id,
                source_path=canonical_path,
                line_number=line_idx,
                raw_timestamp=None,
                normalized_timestamp=None,
                hostname=None,
                service=None,
                pid=None,
                event_type=LogEventType.UNKNOWN_FORMAT.value,
                attributes={"parser_error": True},
                raw_message=line,
                raw_line=line,
            )


def parse_log_file(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
    log_timestamp_year: Optional[int] = None,
) -> LogParseResult:
    """
    Parse an entire log evidence file and produce an aggregate LogParseResult.

    Args:
        file_path: Path to target log file.
        artifact_id: Optional artifact ID to link with collection results.
        log_timestamp_year: Optional explicit year context for BSD syslog timestamps.

    Returns:
        LogParseResult: Immutable aggregate result containing all parsed events.
    """
    target = Path(file_path).resolve()
    events = list(stream_log_events(target, artifact_id=artifact_id, log_timestamp_year=log_timestamp_year))

    total_lines = len(events)
    unrecognized = sum(
        1 for e in events if e.event_type == LogEventType.UNKNOWN_FORMAT.value
    )
    error_lines = sum(
        1 for e in events if e.attributes.get("parser_error") is True
    )
    parsed_events = total_lines - unrecognized

    counts = Counter(e.event_type for e in events)

    return LogParseResult(
        source_path=str(target),
        artifact_id=artifact_id,
        total_lines=total_lines,
        parsed_events=parsed_events,
        unrecognized_lines=unrecognized,
        error_lines=error_lines,
        events=tuple(events),
        event_counts=dict(counts),
    )
