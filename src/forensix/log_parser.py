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

# Account Lifecycle & SSH Key Patterns
RE_USERADD_NEW_USER = re.compile(
    r"^new\s+user:\s*name=([^,\s]+)(?:,\s*UID=(\d+))?(?:,\s*GID=(\d+))?(?:,\s*home=([^,\s]+))?(?:,\s*shell=([^,\s]+))?",
    re.IGNORECASE,
)
RE_ADDUSER_ADDING = re.compile(
    r"^Adding\s+(?:new\s+)?user\s+[`'\"]?([^\s`'\"]+)[`'\"]?(?:\s+\((\d+)\))?(?:.*group\s+[`'\"]?([^\s`'\"]+)[`'\"]?)?",
    re.IGNORECASE,
)
RE_USERMOD_ADD_GROUP = re.compile(
    r"^add\s+['\"]([^'\"]+)['\"]\s+to\s+(?:shadow\s+)?group\s+['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
RE_USERMOD_CHANGE_ATTR = re.compile(
    r"^change\s+user\s+['\"]([^'\"]+)['\"]\s+(shell|home|UID|GID)\s+from\s+['\"]([^'\"]*)['\"]\s+to\s+['\"]([^'\"]*)['\"]",
    re.IGNORECASE,
)
RE_USERMOD_USER_ACTION = re.compile(
    r"^(change|lock|unlock)\s+user\s+['\"]([^'\"]+)['\"](?:\s+(.*))?$",
    re.IGNORECASE,
)
RE_PASSWD_PAM_CHANGED = re.compile(
    r"(?:pam_unix\([^)]*:chauthtok\):\s*)?password\s+changed\s+for\s+(\S+)",
    re.IGNORECASE,
)
RE_PASSWD_CHANGED_BY = re.compile(
    r"^password\s+for\s+['\"]([^'\"]+)['\"]\s+changed\s+by\s+['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
RE_AUTHORIZED_KEYS = re.compile(r"authorized_keys", re.IGNORECASE)
RE_SSH_KEY_CHANGE_VERB = re.compile(
    r"\b(?:add(?:ed|ing)?|append(?:ed|ing)?|writ(?:e|es|ten|ing)|wrote|modif(?:y|ies|ied|ying)|remov(?:e|es|ed|ing)|delet(?:e|es|ed|ing)|replac(?:e|es|ed|ing)|updat(?:e|es|ed|ing)|creat(?:e|es|ed|ing)|chang(?:e|es|ed|ing)|install(?:ed|ing)?)\b",
    re.IGNORECASE,
)
RE_AUTH_KEYS_PATH_USER = re.compile(
    r"(?:/(?P<root>root)|/home/(?P<home_user>[^/\s'\"]+))/\.ssh/authorized_keys"
)


def _extract_authorized_keys_attrs(text: str) -> Dict[str, Any]:
    """Extract key_action and optional user from an authorized_keys log message or command."""
    key_action = "modified" if RE_SSH_KEY_CHANGE_VERB.search(text) else "referenced"
    attrs: Dict[str, Any] = {
        "references_authorized_keys": True,
        "key_action": key_action,
        "action": key_action,
    }
    m_path = RE_AUTH_KEYS_PATH_USER.search(text)
    if m_path:
        attrs["user"] = "root" if m_path.group("root") else m_path.group("home_user")
    return attrs


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
            cmd_str = m_sudo_cmd.group(5).strip()
            sudo_attrs: Dict[str, Any] = {
                "sudo_user": m_sudo_cmd.group(1),
                "tty": m_sudo_cmd.group(2),
                "pwd": m_sudo_cmd.group(3),
                "target_user": m_sudo_cmd.group(4),
                "command": cmd_str,
            }
            if RE_AUTHORIZED_KEYS.search(cmd_str):
                sudo_attrs.update(_extract_authorized_keys_attrs(cmd_str))
            return LogEventType.SUDO_COMMAND.value, sudo_attrs

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

    # Account creation (useradd / adduser)
    if "useradd" in svc_lower or "adduser" in svc_lower:
        m_new_user = RE_USERADD_NEW_USER.search(message)
        if m_new_user:
            attrs: Dict[str, Any] = {"user": m_new_user.group(1), "action": "create_user"}
            if m_new_user.group(2):
                attrs["uid"] = int(m_new_user.group(2))
            if m_new_user.group(3):
                attrs["gid"] = int(m_new_user.group(3))
            if m_new_user.group(4):
                attrs["home"] = m_new_user.group(4)
            if m_new_user.group(5):
                attrs["shell"] = m_new_user.group(5)
            return LogEventType.USER_ADDED.value, attrs

        m_adduser = RE_ADDUSER_ADDING.search(message)
        if m_adduser:
            attrs = {"user": m_adduser.group(1), "action": "create_user"}
            if m_adduser.group(2):
                attrs["uid"] = int(m_adduser.group(2))
            if m_adduser.group(3):
                attrs["group"] = m_adduser.group(3)
            return LogEventType.USER_ADDED.value, attrs

    # Account modification (usermod)
    if "usermod" in svc_lower:
        m_mod_grp = RE_USERMOD_ADD_GROUP.search(message)
        if m_mod_grp:
            return LogEventType.USER_MODIFIED.value, {
                "user": m_mod_grp.group(1),
                "group": m_mod_grp.group(2),
                "action": "add_to_group",
            }

        m_mod_attr = RE_USERMOD_CHANGE_ATTR.search(message)
        if m_mod_attr:
            field = m_mod_attr.group(2).lower()
            new_val = m_mod_attr.group(4)
            attrs = {"user": m_mod_attr.group(1), "action": f"change_{field}"}
            attrs[field] = int(new_val) if field in ("uid", "gid") and new_val.isdigit() else new_val
            return LogEventType.USER_MODIFIED.value, attrs

        m_mod_act = RE_USERMOD_USER_ACTION.search(message)
        if m_mod_act:
            verb = m_mod_act.group(1).lower()
            suffix = (m_mod_act.group(3) or "").lower()
            action = f"{verb}_password" if "password" in suffix else verb
            return LogEventType.USER_MODIFIED.value, {
                "user": m_mod_act.group(2),
                "action": action,
            }

    # Password changes (passwd / chpasswd / pam_unix chauthtok)
    if "passwd" in svc_lower or "chpasswd" in svc_lower or "chauthtok" in message.lower():
        m_pw_by = RE_PASSWD_CHANGED_BY.search(message)
        if m_pw_by:
            return LogEventType.PASSWORD_CHANGED.value, {
                "user": m_pw_by.group(1),
                "changed_by": m_pw_by.group(2),
                "action": "password_changed",
            }

        m_pw_pam = RE_PASSWD_PAM_CHANGED.search(message)
        if m_pw_pam:
            return LogEventType.PASSWORD_CHANGED.value, {
                "user": m_pw_pam.group(1),
                "action": "password_changed",
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

    # Other syslog lines mentioning authorized_keys
    if RE_AUTHORIZED_KEYS.search(message):
        return LogEventType.SSH_KEY_MODIFIED.value, _extract_authorized_keys_attrs(message)

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
    if event_type in (
        LogEventType.USER_ADDED.value,
        LogEventType.USER_MODIFIED.value,
        LogEventType.PASSWORD_CHANGED.value,
        LogEventType.SSH_KEY_MODIFIED.value,
    ) or attributes.get("references_authorized_keys"):
        attributes = dict(attributes)
        attributes["line_number"] = line_number

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
