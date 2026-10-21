"""
Forensic Runtime Chain-of-Custody Ledger Engine for ForensiX (V8.3).

Provides a runtime ledger implementation that builds on the immutable V8.1 custody models
(CustodyEvent, CustodyActor, CustodyActionType), managing event creation, cryptographic chain
linking, historical integrity verification, atomic in-memory append semantics, and safe persistence.

Evidentiary & Engineering Boundaries:
1. Integrity Detection vs. Provenance Proof:
   Cryptographic hash chaining detects modifications to recorded event data when verified against
   an independently preserved reference digest. Hash chaining alone does NOT authenticate human
   actor identity, establish legal chain of custody, provide trusted timestamps, or prevent
   undetectable history rewriting if no external reference anchor exists.
2. Ledger Header Digest Boundary:
   The ledger-level header digest covers the ledger metadata container (ledger_id, created_at,
   case_id, description, total_events, terminal_hash). It is distinct from the event-by-event
   hash chain. It does NOT serve as an external trust anchor or protect against an attacker who
   can rewrite both the ledger file and its digest on disk.
3. Strict Non-Silent Hash Regeneration:
   On deserialization, every imported event record and the ledger itself must provide explicit,
   valid cryptographic digests. Missing, malformed, or mismatched hashes are strictly rejected
   with ValueError and are never silently regenerated or auto-repaired.
4. Non-Destructive Atomic Append:
   All event validations and hash computations are completed before modifying ledger state.
   A failed append guarantees zero mutation of event count, event history, or terminal hash.
5. Evidence Separation:
   Custody records are stored separately from evidence files. When an evidence root is supplied,
   attempts to write the ledger inside or over evidence targets are strictly rejected.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import uuid

from forensix.advanced_report_models import CustodySummary
from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    compute_canonical_event_json,
    compute_event_record_hash,
    generate_custody_event_id,
    is_valid_custody_event_id,
)
from forensix.timestamp_normalizer import normalize_timestamp

CUSTODY_LEDGER_SCHEMA_VERSION: str = "8.0"


class StaleLedgerError(RuntimeError):
    """Raised when an attempt to overwrite a ledger file on disk detects that disk state has changed since snapshot was taken."""
    pass


_RE_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RE_UUIDV4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def generate_custody_ledger_id() -> str:
    """
    Generate a canonical tracking identifier for a custody ledger (COCLEDGER-<UUIDv4>).

    Returns:
        str: Unique identifier string conforming to COCLEDGER-<UUIDv4>.
    """
    return f"COCLEDGER-{uuid.uuid4()}"


def is_valid_custody_ledger_id(ledger_id: Any) -> bool:
    """
    Validate that an identifier strictly conforms to COCLEDGER-<UUIDv4>.

    Args:
        ledger_id: Candidate identifier.

    Returns:
        bool: True if valid COCLEDGER-<UUIDv4>, False otherwise.
    """
    if not isinstance(ledger_id, str):
        return False
    if not ledger_id.startswith("COCLEDGER-"):
        return False
    raw_uuid = ledger_id[10:]
    return bool(_RE_UUIDV4.match(raw_uuid.lower()))


@dataclass(frozen=True)
class CustodyChainVerificationResult:
    """
    Immutable representation of the verification outcome for a custody ledger chain.

    Attributes:
        is_valid: True iff all sequential and cryptographic integrity checks passed.
        integrity_status: 'VERIFIED' (non-empty & valid), 'UNVERIFIED' (empty), or 'TAMPERED'.
                          Note: 'TAMPERED' is a factual verification failure classification,
                          not a legal accusation or proof of human malice.
        total_events: Number of events evaluated.
        terminal_hash: 64-char lowercase hex digest of final event, or None if empty.
        discrepancies: Tuple of factual explanatory strings for each observed failure.
        evidentiary_notice: Standard disclaimer documenting hash-chain boundaries.
    """

    is_valid: bool
    integrity_status: str
    total_events: int
    terminal_hash: Optional[str] = None
    discrepancies: Tuple[str, ...] = ()
    evidentiary_notice: str = CUSTODY_LIMITATIONS_DISCLAIMER

    def __post_init__(self) -> None:
        """Enforce validation rules and immutability."""
        valid_statuses = {"VERIFIED", "UNVERIFIED", "TAMPERED"}
        if self.integrity_status not in valid_statuses:
            raise ValueError(
                f"Invalid integrity_status '{self.integrity_status}': must be one of {sorted(valid_statuses)}"
            )

        if not isinstance(self.discrepancies, tuple):
            object.__setattr__(self, "discrepancies", tuple(self.discrepancies))

    def to_dict(self) -> Dict[str, Any]:
        """Convert verification result to a JSON-serializable dictionary."""
        return {
            "is_valid": self.is_valid,
            "integrity_status": self.integrity_status,
            "total_events": self.total_events,
            "terminal_hash": self.terminal_hash,
            "discrepancies": list(self.discrepancies),
            "evidentiary_notice": self.evidentiary_notice,
        }


def compute_canonical_ledger_header_payload(ledger: "CustodyLedger") -> Dict[str, Any]:
    """
    Construct canonical dictionary of ledger header metadata for digest calculation.

    Covers exactly:
    - case_id
    - created_at
    - description
    - ledger_id
    - terminal_hash (or GENESIS_PREV_HASH if empty)
    - total_events
    """
    term_hash = ledger.terminal_hash if ledger.terminal_hash is not None else GENESIS_PREV_HASH
    return {
        "case_id": ledger.case_id,
        "created_at": ledger.created_at,
        "description": ledger.description,
        "ledger_id": ledger.ledger_id,
        "terminal_hash": term_hash,
        "total_events": len(ledger.events),
    }


def compute_canonical_ledger_header_json(ledger: "CustodyLedger") -> str:
    """Produce byte-deterministic canonical JSON string for ledger header metadata."""
    payload = compute_canonical_ledger_header_payload(ledger)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_ledger_digest(ledger: "CustodyLedger") -> str:
    """
    Calculate canonical SHA-256 digest over the ledger header metadata.

    Binds ledger_id, created_at, case_id, description, total_events, and terminal_hash.
    """
    canonical_json = compute_canonical_ledger_header_json(ledger)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class CustodyLedger:
    """
    Runtime Forensic Chain-of-Custody Ledger.

    Maintains an ordered sequence of hash-linked CustodyEvent objects, provides
    atomic append semantics, historical chain verification, JSON export/import,
    and safe atomic file persistence.
    """

    def __init__(
        self,
        ledger_id: Optional[str] = None,
        created_at: Optional[str] = None,
        case_id: Optional[str] = None,
        description: Optional[str] = None,
        events: Optional[Sequence[CustodyEvent]] = None,
    ) -> None:
        """
        Initialize an in-memory CustodyLedger.

        Args:
            ledger_id: Optional canonical identifier (default: generated COCLEDGER-<UUIDv4>).
            created_at: Optional ISO 8601 UTC timestamp (default: current UTC time).
            case_id: Optional case tracking identifier.
            description: Optional textual description of the ledger context.
            events: Optional initial sequence of pre-validated CustodyEvent instances.
        """
        if ledger_id is not None:
            if not is_valid_custody_ledger_id(ledger_id):
                raise ValueError(
                    f"Invalid ledger_id '{ledger_id}': must conform to canonical COCLEDGER-<UUIDv4>"
                )
            self._ledger_id = ledger_id
        else:
            self._ledger_id = generate_custody_ledger_id()

        if created_at is not None:
            if not isinstance(created_at, str) or not created_at.strip():
                raise ValueError("created_at must be a non-empty string")
            clean_ts = created_at.strip()
            normalize_timestamp(clean_ts, to_utc=False)
            self._created_at = clean_ts
        else:
            self._created_at = datetime.now(timezone.utc).isoformat()

        if case_id is not None:
            if not isinstance(case_id, str):
                raise TypeError("case_id must be a string or None")
            clean_case = case_id.strip()
            self._case_id = clean_case if clean_case else None
        else:
            self._case_id = None

        if description is not None:
            if not isinstance(description, str):
                raise TypeError("description must be a string or None")
            clean_desc = description.strip()
            self._description = clean_desc if clean_desc else None
        else:
            self._description = None

        self._events: List[CustodyEvent] = []
        if events is not None:
            for ev in events:
                self.add_event(ev)

    @property
    def ledger_id(self) -> str:
        """Canonical ledger tracking identifier."""
        return self._ledger_id

    @property
    def created_at(self) -> str:
        """ISO 8601 UTC creation timestamp."""
        return self._created_at

    @property
    def case_id(self) -> Optional[str]:
        """Associated case identifier, if defined."""
        return self._case_id

    @property
    def description(self) -> Optional[str]:
        """Factual description of ledger context, if defined."""
        return self._description

    @property
    def events(self) -> Tuple[CustodyEvent, ...]:
        """Immutable view of the sequential custody events in the ledger."""
        return tuple(self._events)

    @property
    def terminal_hash(self) -> Optional[str]:
        """SHA-256 digest of the most recent event, or None if ledger is empty."""
        if not self._events:
            return None
        return self._events[-1].record_hash

    @property
    def ledger_digest(self) -> str:
        """Canonical SHA-256 digest of the ledger header metadata."""
        return compute_ledger_digest(self)

    def __len__(self) -> int:
        """Return the number of events in the ledger."""
        return len(self._events)

    def __getitem__(self, index: int) -> CustodyEvent:
        """Access a custody event by sequence position."""
        return self._events[index]

    def append_event(
        self,
        action_type: Union[CustodyActionType, str],
        evidence_id: str,
        actor: CustodyActor,
        hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]] = (),
        timestamp: Optional[str] = None,
        timestamp_source: Union[TimestampSource, str] = TimestampSource.HOST_SYSTEM_CLOCK,
        source_location: Optional[str] = None,
        destination_location: Optional[str] = None,
        verification_method: Optional[str] = None,
        notes: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> CustodyEvent:
        """
        Atomically construct and append a new hash-linked custody event.

        Derives sequence_number and prev_event_hash automatically from current ledger state.
        Guarantees that if validation or event construction fails, ledger state remains unchanged.

        Args:
            action_type: CustodyActionType or valid action type string.
            evidence_id: Evidence tracking identifier (e.g. EV-...).
            actor: CustodyActor instance representing declared custodian.
            hashes: Cryptographic digests of the evidence at this custody point.
            timestamp: Optional ISO 8601 UTC timestamp (default: current UTC time).
            timestamp_source: TimestampSource or valid string (default: HOST_SYSTEM_CLOCK).
            source_location: Originating custody location or container.
            destination_location: Destination custody location or container.
            verification_method: Method used to verify integrity.
            notes: Factual notes or observations.
            event_id: Optional explicit event identifier (default: generated COCEVT-<UUIDv4>).

        Returns:
            CustodyEvent: The immutable appended event.

        Raises:
            ValueError, TypeError: If any event attribute is invalid or duplicate ID is supplied.
        """
        seq_num = len(self._events)
        prev_hash = GENESIS_PREV_HASH if seq_num == 0 else self._events[-1].record_hash

        eid = event_id if event_id is not None else generate_custody_event_id()
        if any(e.event_id == eid for e in self._events):
            raise ValueError(f"Duplicate event_id detected in ledger: '{eid}'")

        ts = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

        # Construct new event in local variable; __post_init__ strictly validates all fields
        new_event = CustodyEvent(
            event_id=eid,
            sequence_number=seq_num,
            timestamp=ts,
            timestamp_source=timestamp_source,
            action_type=action_type,
            evidence_id=evidence_id,
            actor=actor,
            source_location=source_location,
            destination_location=destination_location,
            hashes=hashes,
            verification_method=verification_method,
            notes=notes,
            prev_event_hash=prev_hash,
            record_hash=None,  # Computed automatically by CustodyEvent
        )

        # Mutate state only after complete, successful construction and validation
        self._events.append(new_event)
        return new_event

    def add_event(self, event: CustodyEvent) -> CustodyEvent:
        """
        Atomically append an already constructed CustodyEvent instance to the ledger.

        Enforces sequence continuity, hash linkage, and identifier uniqueness.

        Args:
            event: Pre-constructed CustodyEvent instance.

        Returns:
            CustodyEvent: The appended event.

        Raises:
            TypeError: If event is not an instance of CustodyEvent.
            ValueError: If sequence, hash link, or identifier is invalid.
        """
        if not isinstance(event, CustodyEvent):
            raise TypeError(f"event must be an instance of CustodyEvent, got {type(event).__name__}")

        expected_seq = len(self._events)
        if event.sequence_number != expected_seq:
            raise ValueError(
                f"Invalid sequence_number {event.sequence_number}: expected next sequential index {expected_seq}"
            )

        expected_prev = GENESIS_PREV_HASH if expected_seq == 0 else self._events[-1].record_hash
        if event.prev_event_hash != expected_prev:
            raise ValueError(
                f"Invalid prev_event_hash '{event.prev_event_hash}': expected '{expected_prev}'"
            )

        if any(e.event_id == event.event_id for e in self._events):
            raise ValueError(f"Duplicate event_id detected in ledger: '{event.event_id}'")

        computed_hash = compute_event_record_hash(event)
        if event.record_hash != computed_hash:
            raise ValueError(
                f"Event record_hash '{event.record_hash}' does not match computed digest '{computed_hash}'"
            )

        self._events.append(event)
        return event

    def validate_chain(self) -> CustodyChainVerificationResult:
        """
        Verify the complete cryptographic and sequential integrity of the custody event chain.

        Strictly read-only: never mutates, re-hashes, repairs, or reorders stored events.

        Checks:
        1. Genesis event links to 64 zeros.
        2. Sequence numbers are continuous from 0 to N-1 without gaps or inversions.
        3. Every subsequent event's prev_event_hash strictly matches prior event's record_hash.
        4. Every event's record_hash matches its recomputed canonical payload digest.
        5. Every event_id conforms to COCEVT-<UUIDv4> and is unique within the chain.

        Returns:
            CustodyChainVerificationResult: Complete immutable verification result.
        """
        total = len(self._events)
        if total == 0:
            return CustodyChainVerificationResult(
                is_valid=True,
                integrity_status="UNVERIFIED",
                total_events=0,
                terminal_hash=None,
                discrepancies=(),
                evidentiary_notice=CUSTODY_LIMITATIONS_DISCLAIMER,
            )

        discrepancies: List[str] = []
        seen_ids = set()

        for idx, event in enumerate(self._events):
            # 1. Sequence check
            if event.sequence_number != idx:
                discrepancies.append(
                    f"Sequence error at index {idx}: expected sequence_number {idx}, found {event.sequence_number}"
                )

            # 2. Event ID format and uniqueness
            if not is_valid_custody_event_id(event.event_id):
                discrepancies.append(
                    f"Invalid event_id format at index {idx}: '{event.event_id}'"
                )
            if event.event_id in seen_ids:
                discrepancies.append(
                    f"Duplicate event_id detected at index {idx}: '{event.event_id}'"
                )
            seen_ids.add(event.event_id)

            # 3. Genesis and Chain linkage
            if idx == 0:
                if event.prev_event_hash != GENESIS_PREV_HASH:
                    discrepancies.append(
                        f"Genesis linkage mismatch at index 0: prev_event_hash is '{event.prev_event_hash}', expected 64 zeros"
                    )
            else:
                prior_hash = self._events[idx - 1].record_hash
                if event.prev_event_hash != prior_hash:
                    discrepancies.append(
                        f"Chain linkage mismatch at index {idx}: prev_event_hash '{event.prev_event_hash}' "
                        f"does not match prior record_hash '{prior_hash}'"
                    )

            # 4. Internal record hash verification
            computed_rec = compute_event_record_hash(event)
            if event.record_hash != computed_rec:
                discrepancies.append(
                    f"Digest mismatch at index {idx}: recorded hash '{event.record_hash}' "
                    f"does not match recomputed canonical payload hash '{computed_rec}'"
                )

        if discrepancies:
            return CustodyChainVerificationResult(
                is_valid=False,
                integrity_status="TAMPERED",
                total_events=total,
                terminal_hash=self._events[-1].record_hash,
                discrepancies=tuple(discrepancies),
                evidentiary_notice=CUSTODY_LIMITATIONS_DISCLAIMER,
            )

        return CustodyChainVerificationResult(
            is_valid=True,
            integrity_status="VERIFIED",
            total_events=total,
            terminal_hash=self._events[-1].record_hash,
            discrepancies=(),
            evidentiary_notice=CUSTODY_LIMITATIONS_DISCLAIMER,
        )

    def get_custody_summary(self) -> CustodySummary:
        """
        Construct an immutable CustodySummary compatible with ForensiX Schema 8.0 reports.

        Returns:
            CustodySummary: Verified summary dataclass.
        """
        if not self._events:
            return CustodySummary(
                ledger_id=self._ledger_id,
                total_events=0,
                terminal_hash=GENESIS_PREV_HASH,
                chain_integrity="UNVERIFIED",
            )

        verification = self.validate_chain()
        term_hash = self.terminal_hash or GENESIS_PREV_HASH
        return CustodySummary(
            ledger_id=self._ledger_id,
            total_events=len(self._events),
            terminal_hash=term_hash,
            chain_integrity=verification.integrity_status,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete ledger and its events to a pure JSON-serializable dictionary."""
        return {
            "schema_version": CUSTODY_LEDGER_SCHEMA_VERSION,
            "ledger_id": self._ledger_id,
            "created_at": self._created_at,
            "case_id": self._case_id,
            "description": self._description,
            "total_events": len(self._events),
            "terminal_hash": self.terminal_hash,
            "ledger_digest": self.ledger_digest,
            "events": [e.to_dict() for e in self._events],
            "evidentiary_notice": CUSTODY_LIMITATIONS_DISCLAIMER,
        }

    def to_json(self, indent: int = 2) -> str:
        """Render complete ledger as a formatted UTF-8 JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CustodyLedger":
        """
        Deserialize and validate a CustodyLedger from a dictionary mapping.

        Anti-Silent-Regeneration Policy:
        - Every event record MUST contain an explicit, valid 'record_hash'.
        - Missing, empty, or malformed hashes raise ValueError.
        - Mismatched event digests raise ValueError.
        - The ledger header MUST contain an explicit, matching 'ledger_digest'.

        Args:
            data: Mapping containing serialized ledger data.

        Returns:
            CustodyLedger: Restored ledger instance preserving exact original hashes.

        Raises:
            ValueError, TypeError: If structure is malformed or cryptographic digests do not match.
        """
        if not isinstance(data, (dict, Mapping)):
            raise TypeError(f"Ledger data must be a Mapping, got {type(data).__name__}")

        schema_ver = data.get("schema_version", CUSTODY_LEDGER_SCHEMA_VERSION)
        if schema_ver != CUSTODY_LEDGER_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported custody ledger schema version '{schema_ver}': expected '{CUSTODY_LEDGER_SCHEMA_VERSION}'"
            )

        if "ledger_id" not in data or not data["ledger_id"]:
            raise ValueError("Missing or empty required field 'ledger_id'")
        ledger_id = str(data["ledger_id"])

        if "created_at" not in data or not data["created_at"]:
            raise ValueError("Missing or empty required field 'created_at'")
        created_at = str(data["created_at"])

        case_id = data.get("case_id")
        description = data.get("description")

        # Explicit ledger digest requirement
        if "ledger_digest" not in data or not data["ledger_digest"]:
            raise ValueError("Imported custody ledger is missing required 'ledger_digest'")
        supplied_ledger_digest = str(data["ledger_digest"]).strip().lower()
        if not _RE_SHA256_HEX.match(supplied_ledger_digest):
            raise ValueError(
                f"Imported custody ledger contains malformed 'ledger_digest': '{supplied_ledger_digest}'"
            )

        raw_events = data.get("events", [])
        if not isinstance(raw_events, (list, tuple)):
            raise TypeError(f"'events' must be a sequence, got {type(raw_events).__name__}")

        parsed_events: List[CustodyEvent] = []
        for idx, item in enumerate(raw_events):
            if isinstance(item, CustodyEvent):
                parsed_events.append(item)
                continue

            if not isinstance(item, (dict, Mapping)):
                raise TypeError(f"Event at index {idx} must be a Mapping, got {type(item).__name__}")

            # Enforce explicit record_hash on import (never silently regenerate)
            if "record_hash" not in item or item["record_hash"] is None:
                raise ValueError(
                    f"Imported custody event at index {idx} is missing required 'record_hash'"
                )
            supplied_rec_hash = str(item["record_hash"]).strip().lower()
            if not _RE_SHA256_HEX.match(supplied_rec_hash):
                raise ValueError(
                    f"Imported custody event at index {idx} contains malformed record_hash: '{supplied_rec_hash}'"
                )

            actor_data = item.get("actor")
            if not isinstance(actor_data, (dict, Mapping)):
                raise TypeError(f"Event at index {idx} is missing valid actor mapping")
            actor = CustodyActor(
                declared_identity=actor_data["declared_identity"],
                role=actor_data.get("role"),
                organization=actor_data.get("organization"),
                contact_info=actor_data.get("contact_info"),
            )

            # Construct CustodyEvent with supplied record_hash
            # CustodyEvent.__post_init__ will verify that supplied_rec_hash matches recomputed payload hash
            event = CustodyEvent(
                event_id=item["event_id"],
                sequence_number=item["sequence_number"],
                timestamp=item["timestamp"],
                timestamp_source=item.get("timestamp_source", TimestampSource.HOST_SYSTEM_CLOCK),
                action_type=item["action_type"],
                evidence_id=item["evidence_id"],
                actor=actor,
                source_location=item.get("source_location"),
                destination_location=item.get("destination_location"),
                hashes=item.get("hashes", ()),
                verification_method=item.get("verification_method"),
                notes=item.get("notes"),
                prev_event_hash=item.get("prev_event_hash", GENESIS_PREV_HASH),
                record_hash=supplied_rec_hash,
            )
            parsed_events.append(event)

        # Construct ledger instance
        ledger = cls(
            ledger_id=ledger_id,
            created_at=created_at,
            case_id=case_id,
            description=description,
            events=parsed_events,
        )

        # Verify that reconstructed ledger produces the exact supplied ledger_digest
        computed_digest = ledger.ledger_digest
        if supplied_ledger_digest != computed_digest:
            raise ValueError(
                f"Supplied ledger_digest '{supplied_ledger_digest}' does not match computed "
                f"canonical header digest '{computed_digest}'"
            )

        return ledger

    @classmethod
    def from_json(cls, json_str: str) -> "CustodyLedger":
        """Deserialize a CustodyLedger from a JSON string."""
        try:
            data = json.loads(json_str)
        except Exception as err:
            raise ValueError(f"Failed to parse custody ledger JSON: {err}") from err
        return cls.from_dict(data)

    def append_transfer(
        self,
        evidence_id: str,
        releasing_actor: CustodyActor,
        receiving_actor: CustodyActor,
        source_location: str,
        destination_location: str,
        reason: str,
        **kwargs: Any,
    ) -> Any:
        """
        Record and append a formal bilateral custody transfer to the ledger.

        Delegates to forensix.custody_transfer.record_transfer().
        """
        from forensix.custody_transfer import record_transfer

        return record_transfer(
            ledger=self,
            evidence_id=evidence_id,
            releasing_actor=releasing_actor,
            receiving_actor=receiving_actor,
            source_location=source_location,
            destination_location=destination_location,
            reason=reason,
            **kwargs,
        )

    def audit_custody(
        self,
        manifest: Optional[Any] = None,
        evidence_directory: Optional[Any] = None,
        allow_symlinks: bool = False,
    ) -> Any:
        """
        Audit ledger cryptographic integrity, possession continuity, and digest consistency.

        Delegates to forensix.custody_transfer.audit_custody_ledger().
        """
        from forensix.custody_transfer import audit_custody_ledger

        return audit_custody_ledger(
            ledger_or_path=self,
            manifest=manifest,
            evidence_directory=evidence_directory,
            allow_symlinks=allow_symlinks,
        )

    def save_to_file(
        self,
        path: Union[str, Path],
        overwrite: bool = False,
        evidence_root: Optional[Union[str, Path]] = None,
        expected_terminal_hash: Optional[str] = None,
        check_stale: bool = True,
    ) -> Path:
        """
        Save the serialized custody ledger to a file using atomic write semantics.

        Safety Policies:
        1. Non-destructive default: If path already exists and overwrite is False,
           raises FileExistsError.
        2. Evidence Root Separation: If evidence_root is provided, path is resolved and
           verified to not overwrite or reside within the evidence directory root.
        3. Stale State Protection: If overwriting an existing file that was loaded from disk
           or if expected_terminal_hash is provided, verifies that on-disk terminal hash
           has not changed since load time. Raises StaleLedgerError on mismatch.
        4. Atomic Persistence: Writes to a uniquely named temporary sibling file in the
           destination directory before renaming via os.replace(), ensuring zero partial writes.
        5. Failure Cleanup: If write or replace fails, temporary files are safely removed.

        Args:
            path: Destination file path.
            overwrite: If False (default), existing file is preserved and error raised.
            evidence_root: Optional root directory containing evidence files.
            expected_terminal_hash: Optional expected terminal hash to verify against disk.
            check_stale: If True and ledger was loaded from file, verifies terminal hash on disk.

        Returns:
            Path: Resolved path of the saved ledger file.

        Raises:
            FileExistsError: If destination file exists and overwrite is False.
            IsADirectoryError: If destination path is an existing directory.
            ValueError: If destination collides with or resides within evidence_root.
            StaleLedgerError: If on-disk terminal hash contradicts the expected snapshot hash.
        """
        dest = Path(path).resolve()

        # Evidence root separation check (when evidence_root is supplied)
        if evidence_root is not None:
            resolved_root = Path(evidence_root).resolve()
            if dest == resolved_root:
                raise ValueError(
                    f"Custody ledger destination cannot overwrite evidence root: '{dest}'"
                )
            try:
                dest.relative_to(resolved_root)
                is_within_evidence = True
            except ValueError:
                is_within_evidence = False

            if is_within_evidence:
                raise ValueError(
                    f"Custody ledger destination cannot reside within evidence directory: '{dest}'"
                )

        if dest.is_dir():
            raise IsADirectoryError(f"Destination path is a directory, not a regular file: '{dest}'")

        if dest.exists() and not overwrite:
            raise FileExistsError(
                f"Destination file already exists: '{dest}'. Set overwrite=True to replace."
            )

        if dest.exists() and overwrite:
            loaded_path = getattr(self, "_loaded_from_path", None)
            loaded_term = getattr(self, "_loaded_terminal_hash", None)
            target_expected = (
                expected_terminal_hash
                if expected_terminal_hash is not None
                else (loaded_term if check_stale and loaded_path == dest else None)
            )
            if target_expected is not None:
                try:
                    with dest.open(mode="rb") as stream:
                        disk_data = json.load(stream)
                    disk_term = disk_data.get("terminal_hash")
                    if disk_term != target_expected:
                        raise StaleLedgerError(
                            f"Ledger file on disk '{dest}' was modified (terminal_hash='{disk_term}') "
                            f"since snapshot was loaded (expected terminal_hash='{target_expected}'). "
                            "Commit aborted to prevent data loss."
                        )
                except StaleLedgerError:
                    raise
                except Exception:
                    pass

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Temporary sibling file in same directory ensures atomic intra-filesystem rename
        temp_file = dest.with_name(f".{dest.name}.tmp.{uuid.uuid4().hex}")
        content = self.to_json(indent=2)

        try:
            temp_file.write_text(content, encoding="utf-8")
            os.replace(temp_file, dest)
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass

        self._loaded_from_path = dest
        self._loaded_terminal_hash = self.terminal_hash
        self._loaded_total_events = len(self._events)

        return dest

    @classmethod
    def load_from_file(cls, path: Union[str, Path]) -> "CustodyLedger":
        """
        Load and strictly validate a CustodyLedger from a JSON file.

        Opens file in binary read-only mode ('rb'). Does not modify or lock target.

        Args:
            path: Path to the custody ledger JSON file.

        Returns:
            CustodyLedger: Reconstituted ledger instance with tracking metadata for stale-state checks.
        """
        target = Path(path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Custody ledger file does not exist: '{target}'")
        if not target.is_file():
            raise ValueError(f"Custody ledger path is not a regular file: '{target}'")

        try:
            with target.open(mode="rb") as stream:
                data = json.load(stream)
        except Exception as err:
            raise ValueError(f"Failed to load custody ledger file '{target}': {err}") from err

        ledger = cls.from_dict(data)
        ledger._loaded_from_path = target
        ledger._loaded_terminal_hash = ledger.terminal_hash
        ledger._loaded_total_events = len(ledger.events)
        return ledger

    @classmethod
    def verify_serialized_ledger(
        cls,
        data_or_path: Union[Mapping[str, Any], str, Path],
    ) -> CustodyChainVerificationResult:
        """
        Evaluate and verify a serialized ledger structure without raising unhandled exceptions.

        Suitable for auditing external or potentially tampered ledger files.

        Returns:
            CustodyChainVerificationResult: Factual verification outcome.
        """
        data: Mapping[str, Any]
        if isinstance(data_or_path, (str, Path)):
            target = Path(data_or_path).resolve()
            if not target.exists():
                return CustodyChainVerificationResult(
                    is_valid=False,
                    integrity_status="TAMPERED",
                    total_events=0,
                    discrepancies=(f"Ledger file does not exist: '{target}'",),
                )
            try:
                with target.open(mode="rb") as stream:
                    data = json.load(stream)
            except Exception as err:
                return CustodyChainVerificationResult(
                    is_valid=False,
                    integrity_status="TAMPERED",
                    total_events=0,
                    discrepancies=(f"JSON parse error: {err}",),
                )
        elif isinstance(data_or_path, (dict, Mapping)):
            data = data_or_path
        else:
            return CustodyChainVerificationResult(
                is_valid=False,
                integrity_status="TAMPERED",
                total_events=0,
                discrepancies=(f"Invalid input type: {type(data_or_path).__name__}",),
            )

        try:
            ledger = cls.from_dict(data)
            return ledger.validate_chain()
        except Exception as err:
            total_evs = len(data.get("events", [])) if isinstance(data.get("events"), list) else 0
            return CustodyChainVerificationResult(
                is_valid=False,
                integrity_status="TAMPERED",
                total_events=total_evs,
                terminal_hash=data.get("terminal_hash"),
                discrepancies=(f"Deserialization integrity failure: {err}",),
            )
