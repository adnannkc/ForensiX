"""
Forensic Authentication Activity Models for ForensiX (V2.3 Authentication Activity).

Provides strongly typed, immutable dataclasses representing individual observed
authentication activities and aggregate authentication activity results.
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple
import uuid


class AuthEventType(str, Enum):
    """Forensic classification of observed authentication activity events."""

    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_LOGIN_FAILURE = "ssh_login_failure"
    SSH_INVALID_USER = "ssh_invalid_user"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    SUDO_COMMAND = "sudo_command"
    AUTHENTICATION_FAILURE = "authentication_failure"
    UNKNOWN_AUTH_EVENT = "unknown_auth_event"


class AuthStatus(str, Enum):
    """High-level outcome category of an observed authentication event."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


def generate_auth_id() -> str:
    """Generate a unique tracking identifier formatted as AUTH-<UUIDv4>."""
    return f"AUTH-{uuid.uuid4()}"


@dataclass(frozen=True)
class AuthenticationRecord:
    """
    Immutable representation of an observed authentication activity record.

    Forensic notes on raw_line:
        raw_line is the decoded line as read by V2.2. Valid UTF-8 preserves
        the original text; invalid UTF-8 bytes may be represented by Unicode
        replacement characters according to the V2.2 decoding policy.

    Attributes:
        auth_id: Unique tracking identifier formatted as AUTH-<UUIDv4>.
        event_id: Traceable reference to the underlying LogEvent.event_id.
        source_artifact_id: Optional tracking ID of the parent artifact.
        source_path: Canonical filesystem path to the source evidence file.
        line_number: 1-indexed line number where the event was recorded.
        raw_timestamp: Observed raw timestamp string exactly as written.
        normalized_timestamp: Explicit ISO 8601 timestamp string if present;
            remains None for traditional BSD syslog lines lacking year.
        hostname: Hostname where the activity was recorded, or None.
        service: Service/daemon responsible (e.g. 'sshd', 'sudo', 'login'), or None.
        event_type: Classification string from AuthEventType.
        status: Outcome classification string from AuthStatus.
        username: Extracted username or None.
        source_ip: Extracted remote IP address or None.
        source_port: Extracted remote port number or None.
        authentication_method: Explicit method (e.g. 'password', 'publickey') or None.
        attributes: Extracted contextual key-value pairs (e.g. sudo command, tty, pwd).
        raw_message: Message payload following the syslog header.
        raw_line: Decoded line as read by V2.2.
    """

    auth_id: str
    event_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    raw_timestamp: Optional[str]
    normalized_timestamp: Optional[str]
    hostname: Optional[str]
    service: Optional[str]
    event_type: str
    status: str
    username: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[int]
    authentication_method: Optional[str]
    attributes: Dict[str, Any]
    raw_message: str
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert authentication record to a JSON-serializable dictionary."""
        return {
            "auth_id": self.auth_id,
            "event_id": self.event_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "raw_timestamp": self.raw_timestamp,
            "normalized_timestamp": self.normalized_timestamp,
            "hostname": self.hostname,
            "service": self.service,
            "event_type": self.event_type,
            "status": self.status,
            "username": self.username,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "authentication_method": self.authentication_method,
            "attributes": dict(self.attributes),
            "raw_message": self.raw_message,
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class AuthenticationActivityResult:
    """
    Immutable representation of aggregate authentication activity extracted from evidence.
    """

    source_path: str
    artifact_id: Optional[str]
    total_records: int
    success_count: int
    failure_count: int
    unknown_count: int
    records: Tuple[AuthenticationRecord, ...]
    event_counts: Dict[str, int]

    @property
    def summary(self) -> Dict[str, Any]:
        """Convenience property returning high-level metric counts."""
        return {
            "total_records": self.total_records,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "unknown_count": self.unknown_count,
            "event_counts": dict(self.event_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregate authentication result to a JSON-serializable dictionary."""
        return {
            "source_path": self.source_path,
            "artifact_id": self.artifact_id,
            "summary": self.summary,
            "records": [rec.to_dict() for rec in self.records],
        }
