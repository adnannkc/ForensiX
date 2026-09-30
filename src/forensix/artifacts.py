"""
Forensic Artifact Data Models for ForensiX (V2 Host & System Artifacts).

Provides strongly typed, immutable dataclasses representing individual discovered
host artifacts and aggregate collection results from an evidence directory.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid


class ArtifactCategory(str, Enum):
    """High-level forensic classification of host artifacts."""

    ACCOUNT = "account"
    LOG = "log"
    HOST_CONFIG = "host_config"
    SSH = "ssh"
    USER_FS = "user_fs"
    GENERIC = "generic"


class ArtifactType(str, Enum):
    """Specific artifact classification type."""

    # Account artifacts
    PASSWD = "passwd"
    GROUP = "group"
    SHADOW = "shadow"

    # Host configuration artifacts
    HOSTS = "hosts"
    HOSTNAME = "hostname"
    RESOLV_CONF = "resolv_conf"
    OS_RELEASE = "os_release"
    ISSUE = "issue"

    # Log artifacts
    AUTH_LOG = "auth_log"
    SYSLOG = "syslog"
    MESSAGES = "messages"

    # SSH artifacts
    SSH_CONFIG = "ssh_config"
    SSH_KEY = "ssh_key"
    SSH_KNOWN_HOSTS = "ssh_known_hosts"
    SSH_AUTHORIZED_KEYS = "ssh_authorized_keys"

    # User filesystem artifacts
    USER_FILE = "user_file"

    # Generic filesystem fallback
    GENERIC_FILE = "generic_file"


class ArtifactStatus(str, Enum):
    """Collection and analysis state of an artifact."""

    COLLECTED = "collected"
    UNREADABLE = "unreadable"
    PERMISSION_DENIED = "permission_denied"
    BROKEN_SYMLINK = "broken_symlink"
    OUT_OF_BOUNDS_SYMLINK = "out_of_bounds_symlink"


def generate_artifact_id() -> str:
    """Generate a unique tracking identifier for a forensic artifact."""
    return f"ART-{uuid.uuid4()}"


@dataclass(frozen=True)
class ArtifactRecord:
    """
    Immutable representation of an individual forensic artifact.

    Distinguishes observed facts (raw bytes, filesystem stat, hashes)
    from derived information (classification, normalized category).
    """

    artifact_id: str
    relative_path: str
    source_path: str
    category: str
    artifact_type: str
    is_known: bool
    size: int
    permissions: Optional[str]
    modified: Optional[str]
    accessed: Optional[str]
    created: Optional[str]
    md5: Optional[str]
    sha256: Optional[str]
    status: str
    mime_type: Optional[str] = None
    error: Optional[str] = None
    forensic_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the artifact record to a JSON-serializable dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "relative_path": self.relative_path,
            "source_path": self.source_path,
            "category": self.category,
            "artifact_type": self.artifact_type,
            "is_known": self.is_known,
            "size": self.size,
            "permissions": self.permissions,
            "timestamps": {
                "modified": self.modified,
                "accessed": self.accessed,
                "created": self.created,
            },
            "hashes": {
                "md5": self.md5,
                "sha256": self.sha256,
            }
            if self.md5 or self.sha256
            else None,
            "status": self.status,
            "mime_type": self.mime_type,
            "error": self.error,
            "forensic_notes": self.forensic_notes,
        }


@dataclass(frozen=True)
class ArtifactCollectionResult:
    """
    Immutable representation of the collection result for an evidence directory.
    """

    evidence_id: str
    evidence_root: str
    collected_at: str
    artifacts: Tuple[ArtifactRecord, ...]
    total_artifacts: int
    known_artifacts: int
    generic_artifacts: int
    unreadable_artifacts: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert collection result to a nested JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_root": self.evidence_root,
            "collected_at": self.collected_at,
            "summary": {
                "total_artifacts": self.total_artifacts,
                "known_artifacts": self.known_artifacts,
                "generic_artifacts": self.generic_artifacts,
                "unreadable_artifacts": self.unreadable_artifacts,
            },
            "artifacts": [art.to_dict() for art in self.artifacts],
        }
