"""
Forensic Audit & Provenance Trail Models for ForensiX (V2.8).

Provides strongly typed, deeply immutable audit event models tracking processing
provenance across forensic artifact collection, investigation, and report generation.

Strict boundaries:
- Factual software processing / provenance audit trail only
- Not a replacement for a legal evidence chain-of-custody affidavit
- Deeply immutable
- No fabricated history: only records events explicitly supplied or generated
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Tuple
import uuid

from forensix.unified_models import freeze_value


class AuditEventType(str, Enum):
    """Categorization of factual software processing and triage audit events."""

    # V2.8
    CASE_CREATED = "CASE_CREATED"
    EVIDENCE_REGISTERED = "EVIDENCE_REGISTERED"
    HASH_CALCULATED = "HASH_CALCULATED"
    ARTIFACT_COLLECTION_STARTED = "ARTIFACT_COLLECTION_STARTED"
    ARTIFACT_COLLECTION_COMPLETED = "ARTIFACT_COLLECTION_COMPLETED"
    INVESTIGATION_EXECUTED = "INVESTIGATION_EXECUTED"
    REPORT_GENERATED = "REPORT_GENERATED"

    # V2.9.3 Triage Orchestration Lifecycle
    TRIAGE_STARTED = "TRIAGE_STARTED"
    TRIAGE_COMPLETED = "TRIAGE_COMPLETED"
    STAGE_STARTED = "STAGE_STARTED"
    STAGE_COMPLETED = "STAGE_COMPLETED"
    STAGE_PARTIAL = "STAGE_PARTIAL"
    STAGE_FAILED = "STAGE_FAILED"
    STAGE_SKIPPED = "STAGE_SKIPPED"


def generate_audit_id() -> str:
    """Generate a unique tracking identifier for an audit event (AUDIT-<UUIDv4>)."""
    return f"AUDIT-{uuid.uuid4()}"


@dataclass(frozen=True)
class AuditEvent:
    """
    Immutable representation of an individual factual processing provenance event.

    Attributes:
        audit_id: Unique identifier conforming to AUDIT-<UUIDv4>.
        event_type: Classification string from AuditEventType.
        timestamp: ISO 8601 UTC timestamp string when the event occurred.
        description: Factual textual description of the action taken.
        actor: Optional name or identifier of investigator or system process.
        related_id: Optional tracking identifier related to this event (e.g. EV-..., REPORT-...).
        metadata: Immutable tuple of (key, value) pairs for extra provenance context.
    """

    audit_id: str
    event_type: str
    timestamp: str
    description: str
    actor: Optional[str] = None
    related_id: Optional[str] = None
    metadata: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Enforce strict types and deep immutability."""
        if not isinstance(self.audit_id, str) or not self.audit_id.strip():
            raise ValueError("audit_id must be a non-empty string")
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(self.timestamp, str) or not self.timestamp.strip():
            raise ValueError("timestamp must be a non-empty string")
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")
        if self.actor is not None and not isinstance(self.actor, str):
            raise TypeError("actor must be a string or None")
        if self.related_id is not None and not isinstance(self.related_id, str):
            raise TypeError("related_id must be a string or None")
        if not isinstance(self.metadata, tuple):
            object.__setattr__(self, "metadata", freeze_value(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a fully JSON-serializable dictionary."""
        return {
            "audit_id": self.audit_id,
            "event_type": str(self.event_type),
            "timestamp": self.timestamp,
            "description": self.description,
            "actor": self.actor,
            "related_id": self.related_id,
            "metadata": dict(self.metadata),
        }


def create_audit_event(
    event_type: Union[AuditEventType, str],
    description: str,
    actor: Optional[str] = None,
    related_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Helper function to create a validated, immutable AuditEvent with UTC timestamp."""
    ev_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
    ts = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()
    meta_tuple: Tuple[Tuple[str, Any], ...] = ()
    if metadata:
        meta_tuple = tuple(sorted(freeze_value(metadata)))

    return AuditEvent(
        audit_id=generate_audit_id(),
        event_type=ev_type,
        timestamp=ts,
        description=str(description),
        actor=actor,
        related_id=related_id,
        metadata=meta_tuple,
    )
