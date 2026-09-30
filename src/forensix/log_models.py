"""
Forensic Log Data Models for ForensiX (V2.2 Linux Log Analysis).

Provides strongly typed, immutable dataclasses representing individual parsed log events
and aggregate log parse results, maintaining strict separation between observed facts
and parser-derived attributes.
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple
import uuid


class LogEventType(str, Enum):
    """Categorization of recognized Linux log events."""

    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_LOGIN_FAILURE = "ssh_login_failure"
    SSH_INVALID_USER = "ssh_invalid_user"
    SUDO_COMMAND = "sudo_command"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    GENERIC_SYSLOG = "generic_syslog"
    UNKNOWN_FORMAT = "unknown_format"


def generate_event_id() -> str:
    """Generate a unique tracking identifier for a forensic log event."""
    return f"EVT-{uuid.uuid4()}"


@dataclass(frozen=True)
class LogEvent:
    """
    Immutable representation of an individual parsed log line.

    Attributes:
        event_id: Unique identifier for the event (e.g. 'EVT-<UUID>').
        source_artifact_id: Optional tracking ID of the parent artifact.
        source_path: Canonical path to the source log file.
        line_number: 1-indexed line number in the source file.
        raw_timestamp: Observed raw timestamp string exactly as written.
        normalized_timestamp: ISO 8601 timestamp string if explicit in log;
            remains None for traditional BSD syslog lines lacking year.
        hostname: Observed system hostname, or None.
        service: Observed service/daemon/program name (e.g. 'sshd', 'sudo'), or None.
        pid: Process ID if present, or None.
        event_type: Classification string from LogEventType.
        attributes: Extracted key-value attributes (e.g., user, src_ip, command).
        raw_message: Message payload following the syslog header.
        raw_line: Complete unparsed raw line preserving original evidence.
    """

    event_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    raw_timestamp: Optional[str]
    normalized_timestamp: Optional[str]
    hostname: Optional[str]
    service: Optional[str]
    pid: Optional[int]
    event_type: str
    attributes: Dict[str, Any]
    raw_message: str
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert log event to a JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "raw_timestamp": self.raw_timestamp,
            "normalized_timestamp": self.normalized_timestamp,
            "hostname": self.hostname,
            "service": self.service,
            "pid": self.pid,
            "event_type": self.event_type,
            "attributes": dict(self.attributes),
            "raw_message": self.raw_message,
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class LogParseResult:
    """
    Immutable representation of aggregate log parsing outcome for a file.
    """

    source_path: str
    artifact_id: Optional[str]
    total_lines: int
    parsed_events: int
    unrecognized_lines: int
    error_lines: int
    events: Tuple[LogEvent, ...]
    event_counts: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        """Convert parse result to a JSON-serializable dictionary."""
        return {
            "source_path": self.source_path,
            "artifact_id": self.artifact_id,
            "summary": {
                "total_lines": self.total_lines,
                "parsed_events": self.parsed_events,
                "unrecognized_lines": self.unrecognized_lines,
                "error_lines": self.error_lines,
                "event_counts": dict(self.event_counts),
            },
            "events": [evt.to_dict() for evt in self.events],
        }
