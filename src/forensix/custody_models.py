"""
Forensic Chain-of-Custody Models for ForensiX (V8.1).

Provides strongly typed, deeply immutable dataclasses representing custody actions,
actor declarations, hash-linked custody events, canonical JSON serialization,
and explicit evidentiary limitation disclaimers.

Strict Evidentiary Principles & Honest Boundaries:
- A cryptographic hash detects unauthorized modification of historical records if compared
  against an independently secured reference digest. It does NOT independently prove who
  possessed the evidence, establish legal chain of custody, or prevent undetectable history
  rewriting if no external anchor is preserved.
- An actor identity is a declared value, not a cryptographically verified biometric or PKI token.
- Timestamps represent host system clocks unless explicitly designated otherwise; they are
  not RFC 3161 trusted third-party timestamps.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import uuid

from forensix.timestamp_normalizer import normalize_timestamp

# Standard evidentiary disclaimer documenting boundary limitations
CUSTODY_LIMITATIONS_DISCLAIMER: str = (
    "NOTICE: Cryptographic hash chaining detects modifications to recorded event data "
    "when verified against an independently preserved reference digest. Hash chaining alone "
    "does NOT authenticate human actor identity, establish legal chain of custody, provide "
    "trusted timestamps, or prevent undetectable history rewriting if no external anchor exists."
)

GENESIS_PREV_HASH: str = "0" * 64

_RE_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RE_MD5_HEX = re.compile(r"^[0-9a-f]{32}$")


class CustodyActionType(str, Enum):
    """Categorization of defensible forensic chain-of-custody actions."""

    EVIDENCE_RECEIVED = "EVIDENCE_RECEIVED"
    EVIDENCE_REGISTERED = "EVIDENCE_REGISTERED"
    EVIDENCE_COPIED = "EVIDENCE_COPIED"
    CUSTODY_TRANSFERRED = "CUSTODY_TRANSFERRED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_MISMATCH_DETECTED = "INTEGRITY_MISMATCH_DETECTED"
    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    REPORT_GENERATED = "REPORT_GENERATED"
    DISPOSITION_RECORDED = "DISPOSITION_RECORDED"


class TimestampSource(str, Enum):
    """Explicit declaration of timestamp origin semantics."""

    HOST_SYSTEM_CLOCK = "HOST_SYSTEM_CLOCK"
    MANUAL_ENTRY = "MANUAL_ENTRY"
    EXTERNAL_UNAUTHENTICATED = "EXTERNAL_UNAUTHENTICATED"


def generate_custody_event_id() -> str:
    """
    Generate a canonical tracking identifier for a custody event (COCEVT-<UUIDv4>).

    Returns:
        str: Unique identifier string conforming to COCEVT-<UUIDv4>.
    """
    return f"COCEVT-{uuid.uuid4()}"


def is_valid_custody_event_id(event_id: Any) -> bool:
    """
    Validate that an identifier strictly conforms to COCEVT-<UUIDv4>.

    Args:
        event_id: Candidate identifier string.

    Returns:
        bool: True if valid COCEVT-<UUIDv4>, False otherwise.
    """
    if not isinstance(event_id, str):
        return False
    if not event_id.startswith("COCEVT-"):
        return False
    raw_uuid = event_id[7:]
    try:
        val = uuid.UUID(raw_uuid)
        return val.version == 4 and str(val) == raw_uuid
    except (ValueError, AttributeError, TypeError):
        return False


def _freeze_hash_pairs(
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]],
) -> Tuple[Tuple[str, str], ...]:
    """
    Validate and freeze hash pairs into a sorted, immutable tuple of (algorithm, digest).

    Supported algorithms:
    - 'sha256': exactly 64 lowercase hex characters
    - 'md5': exactly 32 lowercase hex characters

    Args:
        hashes: Mapping or sequence of (algorithm, digest) pairs.

    Returns:
        Tuple[Tuple[str, str], ...]: Deterministically sorted tuple of valid hash pairs.

    Raises:
        TypeError: If hashes is not a mapping or sequence of pairs.
        ValueError: If algorithm is unsupported or digest is malformed.
    """
    items: List[Tuple[str, str]] = []
    if isinstance(hashes, Mapping):
        for k, v in hashes.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Hash algorithm and digest must both be strings")
            items.append((k.strip().lower(), v.strip().lower()))
    elif isinstance(hashes, (list, tuple)):
        for pair in hashes:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise TypeError(f"Expected (algorithm, digest) 2-tuple, got {pair!r}")
            k, v = pair
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Hash algorithm and digest must both be strings")
            items.append((k.strip().lower(), v.strip().lower()))
    else:
        raise TypeError(f"hashes must be a Mapping or Sequence of pairs, got {type(hashes).__name__}")

    validated: List[Tuple[str, str]] = []
    for algo, digest in items:
        if algo == "sha256":
            if not _RE_SHA256_HEX.match(digest):
                raise ValueError(
                    f"Invalid SHA-256 digest '{digest}': must be exactly 64 lowercase hex characters"
                )
        elif algo == "md5":
            if not _RE_MD5_HEX.match(digest):
                raise ValueError(
                    f"Invalid MD5 digest '{digest}': must be exactly 32 lowercase hex characters"
                )
        else:
            raise ValueError(f"Unsupported hash algorithm '{algo}': supported are 'sha256', 'md5'")
        validated.append((algo, digest))

    # Return deterministically sorted by algorithm name
    return tuple(sorted(validated, key=lambda x: x[0]))


@dataclass(frozen=True)
class CustodyActor:
    """
    Immutable representation of an actor or custodian declared in a custody event.

    Attributes:
        declared_identity: Full name or designated ID of examiner/custodian.
        role: Functional role (e.g. 'Lead Forensic Examiner', 'Evidence Custodian').
        organization: Organization or unit (e.g. 'Cyber Incident Response Team').
        contact_info: Optional contact detail (email, badge number, phone).
    """

    declared_identity: str
    role: Optional[str] = None
    organization: Optional[str] = None
    contact_info: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate actor fields defensively."""
        if not isinstance(self.declared_identity, str):
            raise TypeError("declared_identity must be a string")
        cleaned = self.declared_identity.strip()
        if not cleaned:
            raise ValueError("declared_identity cannot be empty or whitespace")
        object.__setattr__(self, "declared_identity", cleaned)

        for field_name in ("role", "organization", "contact_info"):
            val = getattr(self, field_name)
            if val is not None:
                if not isinstance(val, str):
                    raise TypeError(f"{field_name} must be a string or None")
                cleaned_val = val.strip()
                object.__setattr__(self, field_name, cleaned_val if cleaned_val else None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert actor representation to a pure, JSON-serializable dictionary."""
        return {
            "declared_identity": self.declared_identity,
            "role": self.role,
            "organization": self.organization,
            "contact_info": self.contact_info,
        }


@dataclass(frozen=True)
class CustodyEvent:
    """
    Immutable, hash-linked representation of an evidentiary chain-of-custody event.

    Attributes:
        event_id: Unique event tracking ID conforming to COCEVT-<UUIDv4>.
        sequence_number: 0-indexed integer position in the custody chain.
        timestamp: ISO 8601 UTC timestamp string of event occurrence.
        timestamp_source: Classification from TimestampSource.
        action_type: Classification from CustodyActionType.
        evidence_id: ForensiX evidence tracking identifier (e.g. EV-...).
        actor: CustodyActor record of the declaring examiner or custodian.
        source_location: Originating custody path, device, or storage locker.
        destination_location: Destination custody path, device, or storage locker.
        hashes: Immutable tuple of verified cryptographic digest pairs.
        verification_method: Factual method used to verify integrity (e.g. 'SINGLE_PASS_SHA256').
        notes: Factual notes, reasons, or observations.
        prev_event_hash: 64-char hex SHA-256 digest of previous event in chain (or 64 zeros for genesis).
        record_hash: 64-char hex SHA-256 digest computed across canonical payload.
    """

    event_id: str
    sequence_number: int
    timestamp: str
    timestamp_source: Union[TimestampSource, str]
    action_type: Union[CustodyActionType, str]
    evidence_id: str
    actor: CustodyActor
    source_location: Optional[str] = None
    destination_location: Optional[str] = None
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]] = ()
    verification_method: Optional[str] = None
    notes: Optional[str] = None
    prev_event_hash: str = GENESIS_PREV_HASH
    record_hash: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce strict field validation and compute/verify cryptographic record hash."""
        # 1. Event ID
        if not is_valid_custody_event_id(self.event_id):
            raise ValueError(
                f"Invalid event_id '{self.event_id}': must conform to canonical COCEVT-<UUIDv4>"
            )

        # 2. Sequence Number: reject booleans explicitly since bool is a subclass of int
        if type(self.sequence_number) is not int or isinstance(self.sequence_number, bool):
            raise TypeError("sequence_number must be an integer, not a boolean or other type")
        if self.sequence_number < 0:
            raise ValueError(f"sequence_number must be non-negative, got {self.sequence_number}")

        # 3. Timestamp: strictly validate ISO-8601 formatting, preserve supplied value
        if not isinstance(self.timestamp, str):
            raise TypeError("timestamp must be a string")
        clean_ts = self.timestamp.strip()
        if not clean_ts:
            raise ValueError("timestamp cannot be empty or whitespace")
        # Validate parseability via ForensiX timestamp normalizer
        normalize_timestamp(clean_ts, to_utc=False)
        object.__setattr__(self, "timestamp", clean_ts)

        # 4. Timestamp Source Enum
        ts_src = self.timestamp_source.value if isinstance(self.timestamp_source, TimestampSource) else str(self.timestamp_source)
        valid_ts_sources = {e.value for e in TimestampSource}
        if ts_src not in valid_ts_sources:
            raise ValueError(
                f"Invalid timestamp_source '{self.timestamp_source}': must be one of {sorted(valid_ts_sources)}"
            )
        object.__setattr__(self, "timestamp_source", ts_src)

        # 5. Action Type Enum
        act_type = self.action_type.value if isinstance(self.action_type, CustodyActionType) else str(self.action_type)
        valid_actions = {e.value for e in CustodyActionType}
        if act_type not in valid_actions:
            raise ValueError(
                f"Invalid action_type '{self.action_type}': must be one of {sorted(valid_actions)}"
            )
        object.__setattr__(self, "action_type", act_type)

        # 6. Evidence ID
        if not isinstance(self.evidence_id, str):
            raise TypeError("evidence_id must be a string")
        clean_eid = self.evidence_id.strip()
        if not clean_eid:
            raise ValueError("evidence_id cannot be empty or whitespace")
        object.__setattr__(self, "evidence_id", clean_eid)

        # 7. Actor
        if not isinstance(self.actor, CustodyActor):
            raise TypeError(f"actor must be an instance of CustodyActor, got {type(self.actor).__name__}")

        # 8. String and Optional String attributes
        for field_name in ("source_location", "destination_location", "verification_method", "notes"):
            val = getattr(self, field_name)
            if val is not None:
                if not isinstance(val, str):
                    raise TypeError(f"{field_name} must be a string or None")
                cleaned = val.strip()
                object.__setattr__(self, field_name, cleaned if cleaned else None)

        # 9. Hashes: defensively validate and freeze into sorted tuple of pairs
        frozen_hashes = _freeze_hash_pairs(self.hashes)
        object.__setattr__(self, "hashes", frozen_hashes)

        # 10. Previous Event Hash validation
        if not isinstance(self.prev_event_hash, str):
            raise TypeError("prev_event_hash must be a string")
        clean_prev = self.prev_event_hash.strip().lower()
        if not _RE_SHA256_HEX.match(clean_prev):
            raise ValueError(
                f"prev_event_hash '{self.prev_event_hash}' must be exactly 64 lowercase hexadecimal characters"
            )

        if self.sequence_number == 0:
            if clean_prev != GENESIS_PREV_HASH:
                raise ValueError(
                    f"Genesis event (sequence_number=0) must have prev_event_hash='{'0'*64}', got '{clean_prev}'"
                )
        else:
            if clean_prev == GENESIS_PREV_HASH:
                raise ValueError(
                    f"Non-genesis event (sequence_number={self.sequence_number}) cannot have an all-zero prev_event_hash"
                )
        object.__setattr__(self, "prev_event_hash", clean_prev)

        # 11. Record Hash computation and validation
        computed_hash = compute_event_record_hash(self)
        if self.record_hash is not None:
            if not isinstance(self.record_hash, str):
                raise TypeError("record_hash must be a string or None")
            clean_rec = self.record_hash.strip().lower()
            if clean_rec != computed_hash:
                raise ValueError(
                    f"Supplied record_hash '{clean_rec}' does not match computed canonical SHA-256 digest '{computed_hash}'"
                )
            object.__setattr__(self, "record_hash", clean_rec)
        else:
            object.__setattr__(self, "record_hash", computed_hash)

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete event to a deterministic, pure JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "timestamp_source": self.timestamp_source,
            "action_type": self.action_type,
            "evidence_id": self.evidence_id,
            "actor": self.actor.to_dict(),
            "source_location": self.source_location,
            "destination_location": self.destination_location,
            "hashes": dict(self.hashes),
            "verification_method": self.verification_method,
            "notes": self.notes,
            "prev_event_hash": self.prev_event_hash,
            "record_hash": self.record_hash,
        }


def compute_canonical_event_payload(event: CustodyEvent) -> Dict[str, Any]:
    """
    Extract the canonical dictionary representation of an event excluding record_hash.

    Args:
        event: CustodyEvent instance.

    Returns:
        Dict[str, Any]: Canonical dictionary representation for hashing.
    """
    return {
        "action_type": str(event.action_type),
        "actor": event.actor.to_dict(),
        "destination_location": event.destination_location,
        "evidence_id": event.evidence_id,
        "event_id": event.event_id,
        "hashes": dict(sorted(event.hashes)),
        "notes": event.notes,
        "prev_event_hash": event.prev_event_hash,
        "sequence_number": event.sequence_number,
        "source_location": event.source_location,
        "timestamp": event.timestamp,
        "timestamp_source": str(event.timestamp_source),
        "verification_method": event.verification_method,
    }


def compute_canonical_event_json(event: CustodyEvent) -> str:
    """
    Produce byte-deterministic canonical JSON string for a CustodyEvent.

    Uses UTF-8, sorted keys, and compact separators (',', ':') to guarantee
    byte-for-byte reproducibility regardless of Python dictionary ordering.

    Args:
        event: CustodyEvent instance.

    Returns:
        str: Deterministic canonical JSON string.
    """
    payload = compute_canonical_event_payload(event)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_event_record_hash(event: CustodyEvent) -> str:
    """
    Calculate the canonical SHA-256 cryptographic digest of a CustodyEvent record.

    Args:
        event: CustodyEvent instance.

    Returns:
        str: 64-character lowercase hex SHA-256 digest.
    """
    canonical_json = compute_canonical_event_json(event)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
