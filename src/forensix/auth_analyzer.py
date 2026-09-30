"""
Forensic Authentication Activity Analyzer for ForensiX (V2.3).

Responsible for extracting, normalizing, and structuring authentication-related
activity from Linux log evidence and parsed V2.2 log events while maintaining
source traceability and evidence immutability.
"""

from collections import Counter
from pathlib import Path
import re
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple, Union

from forensix.auth_models import (
    AuthEventType,
    AuthStatus,
    AuthenticationActivityResult,
    AuthenticationRecord,
    generate_auth_id,
)
from forensix.log_models import LogEvent, LogEventType
from forensix.log_parser import stream_log_events

# Pattern for PAM authentication failure lines across sudo, su, login, sshd
RE_PAM_AUTH_FAIL = re.compile(
    r"authentication failure;.*?(?:user=(\S+)|ruser=(\S+))"
)
RE_PAM_AUTH_FAIL_DETAILED = re.compile(
    r"authentication failure;\s*(?:logname=(\S*))?\s*(?:uid=(\S*))?\s*(?:euid=(\S*))?\s*(?:tty=(\S*))?\s*(?:ruser=(\S*))?\s*(?:rhost=(\S*))?\s*(?:user=(\S*))?"
)

AUTH_SERVICES = {"sshd", "sudo", "su", "login", "pam", "pam_unix", "polkit"}


def is_auth_log_source(source_path: str) -> bool:
    """Check if the source path filename corresponds to standard Linux auth logs."""
    name = Path(source_path).name.lower()
    return "auth.log" in name or "secure" in name


def log_event_to_auth_record(log_event: LogEvent) -> Optional[AuthenticationRecord]:
    """
    Transform a parsed LogEvent into a structured AuthenticationRecord.

    Returns None if the log event does not represent authentication-related activity.
    """
    aid = generate_auth_id()
    svc_lower = (log_event.service or "").lower()
    msg = log_event.raw_message
    event_type = log_event.event_type

    # 1. SSH Events
    if event_type == LogEventType.SSH_LOGIN_SUCCESS.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SSH_LOGIN_SUCCESS.value,
            status=AuthStatus.SUCCESS.value,
            username=log_event.attributes.get("user"),
            source_ip=log_event.attributes.get("src_ip"),
            source_port=log_event.attributes.get("src_port"),
            authentication_method=log_event.attributes.get("auth_method"),
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    if event_type == LogEventType.SSH_LOGIN_FAILURE.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SSH_LOGIN_FAILURE.value,
            status=AuthStatus.FAILURE.value,
            username=log_event.attributes.get("user"),
            source_ip=log_event.attributes.get("src_ip"),
            source_port=log_event.attributes.get("src_port"),
            authentication_method=log_event.attributes.get("auth_method"),
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    if event_type == LogEventType.SSH_INVALID_USER.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SSH_INVALID_USER.value,
            status=AuthStatus.FAILURE.value,
            username=log_event.attributes.get("user"),
            source_ip=log_event.attributes.get("src_ip"),
            source_port=log_event.attributes.get("src_port"),
            authentication_method=log_event.attributes.get("auth_method"),
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    # 2. Sudo Activity
    if event_type == LogEventType.SUDO_COMMAND.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SUDO_COMMAND.value,
            status=AuthStatus.INFO.value,
            username=log_event.attributes.get("sudo_user"),
            source_ip=None,
            source_port=None,
            authentication_method=None,
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    # 3. Session Open / Close
    if event_type == LogEventType.SESSION_OPEN.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SESSION_OPEN.value,
            status=AuthStatus.SUCCESS.value,
            username=log_event.attributes.get("user"),
            source_ip=None,
            source_port=None,
            authentication_method=None,
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    if event_type == LogEventType.SESSION_CLOSE.value:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.SESSION_CLOSE.value,
            status=AuthStatus.INFO.value,
            username=log_event.attributes.get("user"),
            source_ip=None,
            source_port=None,
            authentication_method=None,
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    # 4. PAM Authentication Failures
    if "authentication failure" in msg:
        m_fail = RE_PAM_AUTH_FAIL_DETAILED.search(msg)
        user = None
        rhost = None
        attrs: Dict[str, Any] = {}
        if m_fail:
            user = m_fail.group(7) or m_fail.group(5) or None
            rhost = m_fail.group(6) or None
            attrs = {
                "logname": m_fail.group(1),
                "uid": m_fail.group(2),
                "euid": m_fail.group(3),
                "tty": m_fail.group(4),
                "ruser": m_fail.group(5),
                "rhost": rhost,
                "user": user,
            }
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.AUTHENTICATION_FAILURE.value,
            status=AuthStatus.FAILURE.value,
            username=user,
            source_ip=rhost,
            source_port=None,
            authentication_method=None,
            attributes=attrs,
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    # 5. Unclassified events from authentication logs or authentication services
    is_auth_src = is_auth_log_source(log_event.source_path)
    is_auth_svc = any(s in svc_lower for s in AUTH_SERVICES)

    if is_auth_src or is_auth_svc:
        return AuthenticationRecord(
            auth_id=aid,
            event_id=log_event.event_id,
            source_artifact_id=log_event.source_artifact_id,
            source_path=log_event.source_path,
            line_number=log_event.line_number,
            raw_timestamp=log_event.raw_timestamp,
            normalized_timestamp=log_event.normalized_timestamp,
            hostname=log_event.hostname,
            service=log_event.service,
            event_type=AuthEventType.UNKNOWN_AUTH_EVENT.value,
            status=AuthStatus.UNKNOWN.value,
            username=None,
            source_ip=None,
            source_port=None,
            authentication_method=None,
            attributes=dict(log_event.attributes),
            raw_message=log_event.raw_message,
            raw_line=log_event.raw_line,
        )

    # Not an authentication-related event (e.g. cron daemon, general system log)
    return None


def stream_authentication_activity(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
) -> Iterator[AuthenticationRecord]:
    """
    Stream structured AuthenticationRecord instances line-by-line from a log file.

    Memory bounded: Suitable for gigabyte-scale logs without full memory loading.
    """
    target = Path(file_path).resolve()
    for log_event in stream_log_events(target, artifact_id=artifact_id):
        auth_record = log_event_to_auth_record(log_event)
        if auth_record is not None:
            yield auth_record


def extract_authentication_activity(
    source: Union[str, Path, Iterable[LogEvent]],
    artifact_id: Optional[str] = None,
) -> AuthenticationActivityResult:
    """
    Extract authentication activity from a log file or an existing iterable of LogEvents.

    Args:
        source: File path (str or Path) or an iterable of LogEvent records.
        artifact_id: Optional tracking identifier for the source artifact.

    Returns:
        AuthenticationActivityResult: Complete immutable collection of authentication activity.

    Raises:
        FileNotFoundError: If the evidence path does not exist.
        IsADirectoryError: If the path points to a directory.
    """
    if isinstance(source, (str, Path)):
        target = Path(source).resolve()
        source_path = str(target)
        records = list(stream_authentication_activity(target, artifact_id=artifact_id))
    elif isinstance(source, Iterable):
        source_path = "iterable"
        records_list = []
        for evt in source:
            if isinstance(evt, LogEvent):
                source_path = evt.source_path
                rec = log_event_to_auth_record(evt)
                if rec is not None:
                    records_list.append(rec)
        records = records_list
    else:
        raise TypeError(f"Expected file path or iterable of LogEvents, got {type(source).__name__}")

    total_records = len(records)
    success_count = sum(1 for r in records if r.status == AuthStatus.SUCCESS.value)
    failure_count = sum(1 for r in records if r.status == AuthStatus.FAILURE.value)
    unknown_count = sum(1 for r in records if r.status == AuthStatus.UNKNOWN.value)
    counts = Counter(r.event_type for r in records)

    return AuthenticationActivityResult(
        source_path=source_path,
        artifact_id=artifact_id,
        total_records=total_records,
        success_count=success_count,
        failure_count=failure_count,
        unknown_count=unknown_count,
        records=tuple(records),
        event_counts=dict(counts),
    )
