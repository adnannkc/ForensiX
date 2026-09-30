"""
Unified Forensic Host Artifact Models for ForensiX (V2.6).

Provides strongly typed, deeply immutable dataclasses representing unified host artifacts
and aggregate host collections across all specialized V2 subsystems (filesystem, logs,
authentication, accounts, privileges, persistence) while preserving detailed specialized payloads
and complete forensic chain-of-custody references.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union
import uuid

from forensix.account_models import (
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.artifacts import ArtifactRecord
from forensix.auth_models import AuthenticationRecord
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord

SpecializedPayload = Union[
    ArtifactRecord,
    LogEvent,
    AuthenticationRecord,
    UserAccount,
    GroupRecord,
    ShadowRecord,
    SudoRule,
    SshKeyInfo,
    PersistenceRecord,
]

SUPPORTED_PAYLOAD_TYPES = (
    ArtifactRecord,
    LogEvent,
    AuthenticationRecord,
    UserAccount,
    GroupRecord,
    ShadowRecord,
    SudoRule,
    SshKeyInfo,
    PersistenceRecord,
)


class HostArtifactCategory(str, Enum):
    """Categorization of unified forensic host artifacts."""

    FILESYSTEM = "filesystem"
    LOG = "log"
    AUTHENTICATION = "authentication"
    ACCOUNT = "account"
    GROUP = "group"
    CREDENTIAL_METADATA = "credential_metadata"
    PRIVILEGE = "privilege"
    SSH_KEY = "ssh_key"
    PERSISTENCE = "persistence"


def generate_host_artifact_id() -> str:
    """Generate a unique tracking identifier for a unified host artifact (HOSTART-<UUIDv4>)."""
    return f"HOSTART-{uuid.uuid4()}"


def freeze_value(val: Any) -> Any:
    """
    Recursively freeze mutable structures (dict, list, set) into immutable tuples.
    """
    if isinstance(val, dict):
        return tuple((k, freeze_value(v)) for k, v in sorted(val.items()))
    elif isinstance(val, (list, set)):
        return tuple(freeze_value(item) for item in val)
    elif isinstance(val, tuple):
        return tuple(freeze_value(item) for item in val)
    return val


@dataclass(frozen=True)
class HostArtifact:
    """
    Immutable unified forensic representation of an observed host artifact or event.

    Attributes:
        unified_id: Unique identifier conforming to HOSTART-<UUIDv4>.
        source_id: Original tracking ID from the specialized model
                   (e.g. ART-..., EVT-..., AUTH-..., USER-..., GRP-..., SHAD-..., SUDO-..., SSHKEY-..., PERSIST-...).
        source_event_id: Reference to underlying log event ID (EVT-...) if applicable.
        source_artifact_id: Reference to parent evidence file artifact ID (ART-...) if applicable.
        category: High-level classification from HostArtifactCategory.
        artifact_type: Specialized artifact/event classification string.
        source_path: Exact source path preserved from the source model.
        line_number: Line number where applicable, or None for file-level artifacts.
        raw_data: Decoded raw line or textual configuration when available.
        specialized_payload: Strictly typed original immutable source model.
        status: Analyzer/parser status ('PARSED', 'UNPARSED', 'MALFORMED', 'COLLECTED', etc.).
        warnings: Immutable tuple of warning or limitation messages.
    """

    unified_id: str
    source_id: str
    source_event_id: Optional[str]
    source_artifact_id: Optional[str]
    category: str
    artifact_type: str
    source_path: str
    line_number: Optional[int]
    raw_data: Optional[str]
    specialized_payload: SpecializedPayload
    status: str
    warnings: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Enforce strict type validation and deep immutability."""
        if not isinstance(self.specialized_payload, SUPPORTED_PAYLOAD_TYPES):
            raise TypeError(
                f"Unsupported specialized payload type: {type(self.specialized_payload).__name__}. "
                f"Must be one of: {tuple(t.__name__ for t in SUPPORTED_PAYLOAD_TYPES)}"
            )
        # Deeply freeze warnings
        if not isinstance(self.warnings, tuple):
            object.__setattr__(self, "warnings", tuple(self.warnings))

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a JSON-serializable dictionary.

        Serializes common indexable fields, delegates payload serialization to its to_dict(),
        and guarantees output contains only standard JSON-serializable types.
        """
        payload_dict = (
            self.specialized_payload.to_dict()
            if hasattr(self.specialized_payload, "to_dict")
            else None
        )
        return {
            "unified_id": self.unified_id,
            "source_id": self.source_id,
            "source_event_id": self.source_event_id,
            "source_artifact_id": self.source_artifact_id,
            "category": str(self.category),
            "artifact_type": str(self.artifact_type),
            "source_path": self.source_path,
            "line_number": self.line_number,
            "raw_data": self.raw_data,
            "status": str(self.status),
            "warnings": list(self.warnings),
            "specialized_payload": payload_dict,
        }


@dataclass(frozen=True)
class HostArtifactCollection:
    """
    Immutable aggregate collection of unified host artifacts for an evidence target.

    Attributes:
        evidence_root: Root path of the analyzed evidence target.
        collected_at: ISO 8601 UTC timestamp string.
        artifacts: Immutable tuple of HostArtifact instances.
        total_artifacts: Total number of host artifacts.
        category_counts: Immutable tuple of (category, count) pairs.
        status_counts: Immutable tuple of (status, count) pairs.
    """

    evidence_root: str
    collected_at: str
    artifacts: Tuple[HostArtifact, ...]
    total_artifacts: int
    category_counts: Tuple[Tuple[str, int], ...]
    status_counts: Tuple[Tuple[str, int], ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on collections and metrics."""
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.category_counts, tuple):
            object.__setattr__(self, "category_counts", freeze_value(self.category_counts))
        if not isinstance(self.status_counts, tuple):
            object.__setattr__(self, "status_counts", freeze_value(self.status_counts))

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics with category and status counts in stable key order."""
        return {
            "total_artifacts": self.total_artifacts,
            "category_counts": dict(self.category_counts),
            "status_counts": dict(self.status_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregate collection to a fully JSON-serializable dictionary."""
        return {
            "evidence_root": self.evidence_root,
            "collected_at": self.collected_at,
            "summary": self.summary,
            "artifacts": [art.to_dict() for art in self.artifacts],
        }
