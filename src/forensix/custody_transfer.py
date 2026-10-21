"""
Forensic Custody Transfer Workflow & Audit-Trail Integrity Engine for ForensiX (V8.7).

Provides strongly typed, deeply immutable models and validation engines for:
1. Bilateral custody transfer records (releasing and receiving custodians).
2. Schema 8.0 backward-compatible event bridging.
3. Possession continuity tracking and legacy ledger auditing.
4. Evidence digest baseline provenance and comparison.
5. Deterministic precedence-based audit results (TAMPERED > DISCREPANCY > INCOMPLETE > VERIFIED).
6. Deterministic custody transfer receipts with post-commit failure safety.

Evidentiary Disclaimers:
- Cryptographic hash chaining detects modifications to recorded event data.
- Declared actor identities and location entries reflect recorded administrative statements.
- Hash chaining alone does NOT authenticate biological actor identity, provide trusted
  third-party timestamps, or prevent history rewriting if no external reference anchor exists.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union
import uuid

from forensix.custody_ledger import (
    CUSTODY_LEDGER_SCHEMA_VERSION,
    CustodyChainVerificationResult,
    CustodyLedger,
    StaleLedgerError,
)
from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    _freeze_hash_pairs,
    compute_event_record_hash,
    generate_custody_event_id,
    is_valid_custody_event_id,
)
from forensix.manifest_models import ManifestRecord
from forensix.manifest_verifier import (
    ManifestVerificationResult,
    verify_manifest,
)
from forensix.timestamp_normalizer import (
    is_timezone_aware,
    normalize_timestamp,
)

_RE_UUIDV4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_RE_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def generate_custody_transfer_id() -> str:
    """Generate a canonical tracking identifier for a custody transfer (COCTRAN-<UUIDv4>)."""
    return f"COCTRAN-{uuid.uuid4()}"


def is_valid_custody_transfer_id(transfer_id: Any) -> bool:
    """Validate that an identifier strictly conforms to COCTRAN-<UUIDv4>."""
    if not isinstance(transfer_id, str):
        return False
    if not transfer_id.startswith("COCTRAN-"):
        return False
    raw_uuid = transfer_id[8:]
    return bool(_RE_UUIDV4.match(raw_uuid.lower()))


def generate_custody_receipt_id() -> str:
    """Generate a canonical tracking identifier for a custody transfer receipt (COCRECP-<UUIDv4>)."""
    return f"COCRECP-{uuid.uuid4()}"


def is_valid_custody_receipt_id(receipt_id: Any) -> bool:
    """Validate that an identifier strictly conforms to COCRECP-<UUIDv4>."""
    if not isinstance(receipt_id, str):
        return False
    if not receipt_id.startswith("COCRECP-"):
        return False
    raw_uuid = receipt_id[8:]
    return bool(_RE_UUIDV4.match(raw_uuid.lower()))


class CustodyTransferStatus(str, Enum):
    """Categorization of custody transfer execution outcomes."""

    COMPLETED = "COMPLETED"
    VERIFIED_HANDOVER = "VERIFIED_HANDOVER"
    REJECTED_MISMATCH = "REJECTED_MISMATCH"
    PENDING = "PENDING"


@dataclass(frozen=True)
class CustodyTransferRecord:
    """
    Immutable representation of a formal bilateral custody transfer.

    Attributes:
        transfer_id: Canonical tracking ID (COCTRAN-<UUIDv4>).
        evidence_id: ForensiX evidence tracking identifier (e.g. EV-...).
        releasing_actor: CustodyActor relinquishing custodial responsibility.
        receiving_actor: CustodyActor accepting custodial responsibility.
        source_location: Originating custody container, locker, or facility.
        destination_location: Destination custody container, locker, or facility.
        transfer_timestamp: ISO 8601 UTC timestamp of transfer.
        reason: Factual purpose for transfer.
        timestamp_source: Classification from TimestampSource.
        authorization_ref: Optional legal or administrative reference (warrant, intake slip).
        condition_notes: Factual packaging or physical condition notes.
        hashes: Cryptographic digest pairs recorded at transfer.
        verification_method: Method used to verify integrity.
        transfer_status: Status classification from CustodyTransferStatus.
        event_id: Linked CustodyEvent identifier recorded in the custody ledger.
    """

    transfer_id: str
    evidence_id: str
    releasing_actor: CustodyActor
    receiving_actor: CustodyActor
    source_location: str
    destination_location: str
    transfer_timestamp: str
    reason: str
    timestamp_source: Union[TimestampSource, str] = TimestampSource.HOST_SYSTEM_CLOCK
    authorization_ref: Optional[str] = None
    condition_notes: Optional[str] = None
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]] = ()
    verification_method: Optional[str] = None
    transfer_status: Union[CustodyTransferStatus, str] = CustodyTransferStatus.COMPLETED
    event_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate all transfer fields strictly."""
        # 1. Transfer ID
        if not is_valid_custody_transfer_id(self.transfer_id):
            raise ValueError(
                f"Invalid transfer_id '{self.transfer_id}': must conform to canonical COCTRAN-<UUIDv4>"
            )

        # 2. Evidence ID
        if not isinstance(self.evidence_id, str):
            raise TypeError("evidence_id must be a string")
        clean_eid = self.evidence_id.strip()
        if not clean_eid:
            raise ValueError("evidence_id cannot be empty or whitespace")
        object.__setattr__(self, "evidence_id", clean_eid)

        # 3. Actors
        if not isinstance(self.releasing_actor, CustodyActor):
            raise TypeError(
                f"releasing_actor must be CustodyActor, got {type(self.releasing_actor).__name__}"
            )
        if not isinstance(self.receiving_actor, CustodyActor):
            raise TypeError(
                f"receiving_actor must be CustodyActor, got {type(self.receiving_actor).__name__}"
            )

        # 4. Locations
        for loc_field in ("source_location", "destination_location"):
            val = getattr(self, loc_field)
            if not isinstance(val, str):
                raise TypeError(f"{loc_field} must be a string")
            clean_loc = val.strip()
            if not clean_loc:
                raise ValueError(f"{loc_field} cannot be empty or whitespace")
            object.__setattr__(self, loc_field, clean_loc)

        # 5. Timestamp
        if not isinstance(self.transfer_timestamp, str):
            raise TypeError("transfer_timestamp must be a string")
        clean_ts = self.transfer_timestamp.strip()
        if not clean_ts:
            raise ValueError("transfer_timestamp cannot be empty or whitespace")
        normalize_timestamp(clean_ts, to_utc=False)
        object.__setattr__(self, "transfer_timestamp", clean_ts)

        # 6. Timestamp Source
        ts_src = (
            self.timestamp_source.value
            if isinstance(self.timestamp_source, TimestampSource)
            else str(self.timestamp_source)
        )
        valid_ts_sources = {e.value for e in TimestampSource}
        if ts_src not in valid_ts_sources:
            raise ValueError(
                f"Invalid timestamp_source '{self.timestamp_source}': must be one of {sorted(valid_ts_sources)}"
            )
        object.__setattr__(self, "timestamp_source", ts_src)

        # 7. Reason
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")
        clean_reason = self.reason.strip()
        if not clean_reason:
            raise ValueError("reason cannot be empty or whitespace")
        object.__setattr__(self, "reason", clean_reason)

        # 8. Optionals
        for opt_field in ("authorization_ref", "condition_notes", "verification_method"):
            val = getattr(self, opt_field)
            if val is not None:
                if not isinstance(val, str):
                    raise TypeError(f"{opt_field} must be a string or None")
                cleaned = val.strip()
                object.__setattr__(self, opt_field, cleaned if cleaned else None)

        # 9. Hashes
        frozen_hashes = _freeze_hash_pairs(self.hashes)
        object.__setattr__(self, "hashes", frozen_hashes)

        # 10. Transfer Status
        status_val = (
            self.transfer_status.value
            if isinstance(self.transfer_status, CustodyTransferStatus)
            else str(self.transfer_status)
        )
        valid_statuses = {e.value for e in CustodyTransferStatus}
        if status_val not in valid_statuses:
            raise ValueError(
                f"Invalid transfer_status '{self.transfer_status}': must be one of {sorted(valid_statuses)}"
            )
        object.__setattr__(self, "transfer_status", status_val)

        # 11. Event ID
        if self.event_id is not None:
            if not is_valid_custody_event_id(self.event_id):
                raise ValueError(
                    f"Invalid event_id '{self.event_id}': must conform to canonical COCEVT-<UUIDv4>"
                )

    @property
    def is_relocation(self) -> bool:
        """True iff this transfer represents physical relocation under the same custodian."""
        return self.releasing_actor.declared_identity == self.receiving_actor.declared_identity

    def to_dict(self) -> Dict[str, Any]:
        """Convert transfer record to a pure JSON-serializable dictionary."""
        return {
            "transfer_id": self.transfer_id,
            "evidence_id": self.evidence_id,
            "releasing_actor": self.releasing_actor.to_dict(),
            "receiving_actor": self.receiving_actor.to_dict(),
            "source_location": self.source_location,
            "destination_location": self.destination_location,
            "transfer_timestamp": self.transfer_timestamp,
            "timestamp_source": self.timestamp_source,
            "reason": self.reason,
            "authorization_ref": self.authorization_ref,
            "condition_notes": self.condition_notes,
            "hashes": dict(self.hashes),
            "verification_method": self.verification_method,
            "transfer_status": self.transfer_status,
            "event_id": self.event_id,
            "is_relocation": self.is_relocation,
        }


@dataclass(frozen=True)
class CustodyTransferReceipt:
    """
    Immutable representation of a custody transfer verification receipt.

    Binds transfer parameters, the ledger state immediately prior to the transfer,
    and the terminal digest of the committed ledger event.
    """

    receipt_id: str
    transfer_id: str
    ledger_id: str
    evidence_id: str
    releasing_actor: CustodyActor
    receiving_actor: CustodyActor
    source_location: str
    destination_location: str
    transfer_timestamp: str
    timestamp_source: str
    reason: str
    terminal_hash_before: str
    terminal_hash_after: str
    case_id: Optional[str] = None
    authorization_ref: Optional[str] = None
    condition_notes: Optional[str] = None
    hashes: Tuple[Tuple[str, str], ...] = ()
    receipt_digest: Optional[str] = None
    evidentiary_notice: str = (
        "NOTICE: Declared actor identities and location entries reflect recorded administrative statements. "
        "Hash chaining verifies record integrity, not biological identity or external physical acceptance."
    )

    def __post_init__(self) -> None:
        """Validate receipt fields and compute deterministic receipt digest."""
        if not is_valid_custody_receipt_id(self.receipt_id):
            raise ValueError(
                f"Invalid receipt_id '{self.receipt_id}': must conform to canonical COCRECP-<UUIDv4>"
            )

        if not isinstance(self.hashes, tuple):
            object.__setattr__(self, "hashes", tuple(self.hashes))

        computed_digest = self.compute_digest()
        if self.receipt_digest is not None:
            clean_digest = self.receipt_digest.strip().lower()
            if clean_digest != computed_digest:
                raise ValueError(
                    f"Supplied receipt_digest '{clean_digest}' does not match computed digest '{computed_digest}'"
                )
            object.__setattr__(self, "receipt_digest", clean_digest)
        else:
            object.__setattr__(self, "receipt_digest", computed_digest)

    def compute_canonical_payload(self) -> Dict[str, Any]:
        """Extract deterministic payload mapping covering all receipt parameters."""
        return {
            "authorization_ref": self.authorization_ref,
            "case_id": self.case_id,
            "condition_notes": self.condition_notes,
            "destination_location": self.destination_location,
            "evidence_id": self.evidence_id,
            "hashes": dict(sorted(self.hashes)),
            "ledger_id": self.ledger_id,
            "reason": self.reason,
            "receipt_id": self.receipt_id,
            "receiving_actor": self.receiving_actor.to_dict(),
            "releasing_actor": self.releasing_actor.to_dict(),
            "source_location": self.source_location,
            "terminal_hash_after": self.terminal_hash_after,
            "terminal_hash_before": self.terminal_hash_before,
            "timestamp_source": self.timestamp_source,
            "transfer_id": self.transfer_id,
            "transfer_timestamp": self.transfer_timestamp,
        }

    def compute_digest(self) -> str:
        """Compute canonical SHA-256 digest over sorted, compact JSON payload."""
        payload = self.compute_canonical_payload()
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert receipt to clean dictionary."""
        d = self.compute_canonical_payload()
        d["receipt_digest"] = self.receipt_digest
        d["evidentiary_notice"] = self.evidentiary_notice
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize receipt to deterministic JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)

    def render_text(self) -> str:
        """Render human-readable, air-gapped ASCII custody transfer certificate."""
        hashes_str = (
            ", ".join(f"{algo.upper()}:{digest}" for algo, digest in self.hashes)
            if self.hashes
            else "None recorded"
        )
        lines = [
            "================================================================================",
            "                 FORENSIX FORMAL CUSTODY TRANSFER RECEIPT                       ",
            "================================================================================",
            f"Receipt Identifier:      {self.receipt_id}",
            f"Transfer Identifier:     {self.transfer_id}",
            f"Ledger Tracking ID:      {self.ledger_id}",
            f"Case Reference:          {self.case_id or 'None'}",
            f"Evidence Item ID:        {self.evidence_id}",
            "--------------------------------------------------------------------------------",
            "TRANSFER PARTICIPANTS & LOCATIONS",
            f"  Releasing Custodian:   {self.releasing_actor.declared_identity}",
            f"    Role / Org:          {self.releasing_actor.role or 'N/A'} | {self.releasing_actor.organization or 'N/A'}",
            f"    Source Location:     {self.source_location}",
            f"  Receiving Custodian:   {self.receiving_actor.declared_identity}",
            f"    Role / Org:          {self.receiving_actor.role or 'N/A'} | {self.receiving_actor.organization or 'N/A'}",
            f"    Destination:         {self.destination_location}",
            "--------------------------------------------------------------------------------",
            "TRANSFER DETAILS & EVIDENTIARY CONTEXT",
            f"  Handover Timestamp:    {self.transfer_timestamp} ({self.timestamp_source})",
            f"  Transfer Purpose:      {self.reason}",
            f"  Authorization Ref:     {self.authorization_ref or 'None'}",
            f"  Packaging/Condition:   {self.condition_notes or 'Intact / Standard'}",
            f"  Handover Hashes:       {hashes_str}",
            "--------------------------------------------------------------------------------",
            "CRYPTOGRAPHIC LEDGER BINDING",
            f"  Prior Terminal Hash:   {self.terminal_hash_before}",
            f"  Committed Event Hash:  {self.terminal_hash_after}",
            f"  Receipt SHA-256:       {self.receipt_digest}",
            "--------------------------------------------------------------------------------",
            self.evidentiary_notice,
            "================================================================================",
        ]
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class AuditFinding:
    """
    Immutable structured finding produced by a custody ledger audit.

    Attributes:
        finding_type: Standard classification string.
        severity: Severity level: 'TAMPERED', 'DISCREPANCY', 'INCOMPLETE', or 'INFO'.
        message: Factual explanatory description.
        evidence_id: Associated evidence tracking identifier, if applicable.
        event_id: Associated custody event tracking identifier, if applicable.
        sequence_number: Associated ledger sequence index, if applicable.
        details: Granular dictionary of context values.
    """

    finding_type: str
    severity: str
    message: str
    evidence_id: Optional[str] = None
    event_id: Optional[str] = None
    sequence_number: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to pure dictionary."""
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "message": self.message,
            "evidence_id": self.evidence_id,
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class CustodyAuditResult:
    """
    Immutable comprehensive result of a custody ledger audit.

    Attributes:
        ledger_id: Tracking identifier of the audited custody ledger.
        is_valid: True iff audit_status == 'VERIFIED'.
        audit_status: Precedence classification: 'TAMPERED', 'DISCREPANCY_DETECTED',
                      'INCOMPLETE_HISTORY', or 'VERIFIED'.
        total_events: Count of events evaluated in ledger.
        evidence_ids_tracked: Distinct evidence identifiers found in ledger.
        current_custodians: Tuple of (evidence_id, CustodyActor dict) pairs.
        current_locations: Tuple of (evidence_id, location str) pairs.
        findings: Tuple of all AuditFinding instances accumulated during audit.
        evidentiary_notice: Standard boundary disclaimer.
    """

    ledger_id: str
    is_valid: bool
    audit_status: str
    total_events: int
    evidence_ids_tracked: Tuple[str, ...]
    current_custodians: Tuple[Tuple[str, Dict[str, Any]], ...]
    current_locations: Tuple[Tuple[str, Optional[str]], ...]
    findings: Tuple[AuditFinding, ...]
    evidentiary_notice: str = CUSTODY_LIMITATIONS_DISCLAIMER

    def __post_init__(self) -> None:
        """Enforce validation rules on audit results."""
        valid_statuses = {"VERIFIED", "INCOMPLETE_HISTORY", "DISCREPANCY_DETECTED", "TAMPERED"}
        if self.audit_status not in valid_statuses:
            raise ValueError(
                f"Invalid audit_status '{self.audit_status}': must be one of {sorted(valid_statuses)}"
            )

        if not isinstance(self.findings, tuple):
            object.__setattr__(self, "findings", tuple(self.findings))

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit result to dictionary."""
        return {
            "ledger_id": self.ledger_id,
            "is_valid": self.is_valid,
            "audit_status": self.audit_status,
            "total_events": self.total_events,
            "evidence_ids_tracked": list(self.evidence_ids_tracked),
            "current_custodians": dict(self.current_custodians),
            "current_locations": dict(self.current_locations),
            "findings": [f.to_dict() for f in self.findings],
            "evidentiary_notice": self.evidentiary_notice,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize audit result to deterministic JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)

    def render_summary(self) -> str:
        """Render a clean, human-readable terminal summary of the audit."""
        lines = [
            "================================================================================",
            "                   FORENSIX CUSTODY AUDIT SUMMARY REPORT                        ",
            "================================================================================",
            f"Ledger Tracking ID:      {self.ledger_id}",
            f"Audit Outcome:           {self.audit_status}",
            f"Overall Valid:           {'YES' if self.is_valid else 'NO'}",
            f"Total Events Audited:    {self.total_events}",
            f"Evidence Items Tracked:  {len(self.evidence_ids_tracked)}",
            "--------------------------------------------------------------------------------",
            "CURRENT CUSTODIAL POSSESSION & LOCATIONS",
        ]
        cust_map = dict(self.current_custodians)
        loc_map = dict(self.current_locations)
        if not self.evidence_ids_tracked:
            lines.append("  (No evidence items tracked in ledger)")
        else:
            for eid in self.evidence_ids_tracked:
                actor_d = cust_map.get(eid)
                actor_name = actor_d.get("declared_identity", "UNKNOWN") if actor_d else "UNRECORDED"
                loc = loc_map.get(eid) or "UNRECORDED"
                lines.append(f"  Item [{eid}]:")
                lines.append(f"    Current Custodian:   {actor_name}")
                lines.append(f"    Current Location:    {loc}")

        lines.append("--------------------------------------------------------------------------------")
        lines.append(f"AUDIT FINDINGS & DISCREPANCIES ({len(self.findings)} total)")
        if not self.findings:
            lines.append("  Zero discrepancies or gaps detected. Chain and possession are verified.")
        else:
            for idx, f in enumerate(self.findings, 1):
                loc_info = f" [seq={f.sequence_number}]" if f.sequence_number is not None else ""
                lines.append(f"  {idx}. [{f.severity}] {f.finding_type}{loc_info}: {f.message}")

        lines.append("================================================================================")
        return "\n".join(lines) + "\n"


def _format_transfer_event_notes(transfer: CustodyTransferRecord) -> str:
    """Format structured transfer metadata as deterministic JSON for CustodyEvent.notes."""
    payload = {
        "authorization_ref": transfer.authorization_ref,
        "condition_notes": transfer.condition_notes,
        "destination_location": transfer.destination_location,
        "is_relocation": transfer.is_relocation,
        "reason": transfer.reason,
        "receiving_actor": transfer.receiving_actor.to_dict(),
        "releasing_actor": transfer.releasing_actor.to_dict(),
        "source_location": transfer.source_location,
        "transfer_id": transfer.transfer_id,
        "transfer_status": transfer.transfer_status,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_transfer_from_event(event: CustodyEvent) -> Optional[CustodyTransferRecord]:
    """
    Safely reconstruct a CustodyTransferRecord from a CustodyEvent if structured notes exist.

    Returns:
        Optional[CustodyTransferRecord]: Reconstructed record or None if legacy/unstructured.
    """
    if event.action_type != CustodyActionType.CUSTODY_TRANSFERRED:
        return None
    if not event.notes:
        return None

    try:
        data = json.loads(event.notes)
    except Exception:
        return None

    if not isinstance(data, dict) or not data.get("transfer_id"):
        return None

    tid = data["transfer_id"]
    if not is_valid_custody_transfer_id(tid):
        return None

    try:
        rel_actor_d = data.get("releasing_actor", {})
        rec_actor_d = data.get("receiving_actor", {})
        releasing_actor = CustodyActor(
            declared_identity=rel_actor_d["declared_identity"],
            role=rel_actor_d.get("role"),
            organization=rel_actor_d.get("organization"),
            contact_info=rel_actor_d.get("contact_info"),
        )
        receiving_actor = CustodyActor(
            declared_identity=rec_actor_d["declared_identity"],
            role=rec_actor_d.get("role"),
            organization=rec_actor_d.get("organization"),
            contact_info=rec_actor_d.get("contact_info"),
        )
        return CustodyTransferRecord(
            transfer_id=tid,
            evidence_id=event.evidence_id,
            releasing_actor=releasing_actor,
            receiving_actor=receiving_actor,
            source_location=data.get("source_location") or event.source_location or "UNKNOWN",
            destination_location=data.get("destination_location") or event.destination_location or "UNKNOWN",
            transfer_timestamp=event.timestamp,
            reason=data.get("reason", "Custody transfer"),
            timestamp_source=event.timestamp_source,
            authorization_ref=data.get("authorization_ref"),
            condition_notes=data.get("condition_notes"),
            hashes=event.hashes,
            verification_method=event.verification_method,
            transfer_status=data.get("transfer_status", CustodyTransferStatus.COMPLETED),
            event_id=event.event_id,
        )
    except Exception:
        return None


def record_transfer(
    ledger: CustodyLedger,
    evidence_id: str,
    releasing_actor: CustodyActor,
    receiving_actor: CustodyActor,
    source_location: str,
    destination_location: str,
    reason: str,
    timestamp: Optional[str] = None,
    timestamp_source: Union[TimestampSource, str] = TimestampSource.HOST_SYSTEM_CLOCK,
    authorization_ref: Optional[str] = None,
    condition_notes: Optional[str] = None,
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]] = (),
    verification_method: Optional[str] = None,
    transfer_status: Union[CustodyTransferStatus, str] = CustodyTransferStatus.COMPLETED,
    transfer_id: Optional[str] = None,
) -> Tuple[CustodyEvent, CustodyTransferRecord]:
    """
    Construct a validated CustodyTransferRecord, bridge it to a canonical Schema 8.0 CustodyEvent,
    and atomically append it to the in-memory CustodyLedger.

    Args:
        ledger: CustodyLedger instance to append to.
        evidence_id: ForensiX evidence tracking identifier.
        releasing_actor: CustodyActor relinquishing responsibility.
        receiving_actor: CustodyActor accepting responsibility.
        source_location: Source container or location.
        destination_location: Destination container or location.
        reason: Factual purpose for transfer.
        timestamp: Optional ISO 8601 UTC timestamp string (default: current UTC time).
        timestamp_source: TimestampSource classification.
        authorization_ref: Optional legal or administrative reference.
        condition_notes: Optional packaging or physical condition notes.
        hashes: Cryptographic digest pairs recorded at handover.
        verification_method: Integrity verification method name.
        transfer_status: Classification from CustodyTransferStatus.
        transfer_id: Optional explicit COCTRAN-<UUIDv4> identifier.

    Returns:
        Tuple[CustodyEvent, CustodyTransferRecord]: The appended event and transfer record.

    Raises:
        ValueError, TypeError: If any transfer argument is invalid or incompatible.
    """
    tid = transfer_id if transfer_id is not None else generate_custody_transfer_id()
    ts = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

    # Pre-construct transfer record to defensively validate all fields
    raw_transfer = CustodyTransferRecord(
        transfer_id=tid,
        evidence_id=evidence_id,
        releasing_actor=releasing_actor,
        receiving_actor=receiving_actor,
        source_location=source_location,
        destination_location=destination_location,
        transfer_timestamp=ts,
        reason=reason,
        timestamp_source=timestamp_source,
        authorization_ref=authorization_ref,
        condition_notes=condition_notes,
        hashes=hashes,
        verification_method=verification_method,
        transfer_status=transfer_status,
        event_id=None,
    )

    notes_json = _format_transfer_event_notes(raw_transfer)

    # Bridge to Schema 8.0 CustodyEvent:
    # Actor represents the receiving custodian accepting active custody
    appended_event = ledger.append_event(
        action_type=CustodyActionType.CUSTODY_TRANSFERRED,
        evidence_id=raw_transfer.evidence_id,
        actor=raw_transfer.receiving_actor,
        hashes=raw_transfer.hashes,
        timestamp=raw_transfer.transfer_timestamp,
        timestamp_source=raw_transfer.timestamp_source,
        source_location=raw_transfer.source_location,
        destination_location=raw_transfer.destination_location,
        verification_method=raw_transfer.verification_method,
        notes=notes_json,
    )

    final_transfer = CustodyTransferRecord(
        transfer_id=raw_transfer.transfer_id,
        evidence_id=raw_transfer.evidence_id,
        releasing_actor=raw_transfer.releasing_actor,
        receiving_actor=raw_transfer.receiving_actor,
        source_location=raw_transfer.source_location,
        destination_location=raw_transfer.destination_location,
        transfer_timestamp=raw_transfer.transfer_timestamp,
        reason=raw_transfer.reason,
        timestamp_source=raw_transfer.timestamp_source,
        authorization_ref=raw_transfer.authorization_ref,
        condition_notes=raw_transfer.condition_notes,
        hashes=raw_transfer.hashes,
        verification_method=raw_transfer.verification_method,
        transfer_status=raw_transfer.transfer_status,
        event_id=appended_event.event_id,
    )

    return appended_event, final_transfer


def generate_transfer_receipt(
    transfer: CustodyTransferRecord,
    ledger: CustodyLedger,
    receipt_id: Optional[str] = None,
) -> CustodyTransferReceipt:
    """
    Construct an immutable CustodyTransferReceipt binding the transfer record and
    the committed terminal ledger digest.

    Args:
        transfer: Committed CustodyTransferRecord with linked event_id.
        ledger: CustodyLedger containing the committed transfer event.
        receipt_id: Optional canonical COCRECP-<UUIDv4> tracking identifier.

    Returns:
        CustodyTransferReceipt: Fully validated and digest-bound receipt.

    Raises:
        ValueError: If transfer has no linked event or is not found in ledger.
    """
    if not isinstance(transfer, CustodyTransferRecord):
        raise TypeError(f"transfer must be CustodyTransferRecord, got {type(transfer).__name__}")
    if not isinstance(ledger, CustodyLedger):
        raise TypeError(f"ledger must be CustodyLedger, got {type(ledger).__name__}")

    if not transfer.event_id:
        raise ValueError("Cannot generate receipt for uncommitted transfer (event_id is None)")

    # Find the matching event in ledger
    event_idx = None
    for idx, ev in enumerate(ledger.events):
        if ev.event_id == transfer.event_id:
            event_idx = idx
            break

    if event_idx is None:
        raise ValueError(
            f"Transfer event_id '{transfer.event_id}' was not found in the provided ledger"
        )

    committed_event = ledger.events[event_idx]
    terminal_hash_after = committed_event.record_hash
    terminal_hash_before = (
        GENESIS_PREV_HASH if event_idx == 0 else ledger.events[event_idx - 1].record_hash
    )

    rec_id = receipt_id if receipt_id is not None else generate_custody_receipt_id()

    return CustodyTransferReceipt(
        receipt_id=rec_id,
        transfer_id=transfer.transfer_id,
        ledger_id=ledger.ledger_id,
        case_id=ledger.case_id,
        evidence_id=transfer.evidence_id,
        releasing_actor=transfer.releasing_actor,
        receiving_actor=transfer.receiving_actor,
        source_location=transfer.source_location,
        destination_location=transfer.destination_location,
        transfer_timestamp=transfer.transfer_timestamp,
        timestamp_source=transfer.timestamp_source,
        reason=transfer.reason,
        authorization_ref=transfer.authorization_ref,
        condition_notes=transfer.condition_notes,
        hashes=transfer.hashes,
        terminal_hash_before=terminal_hash_before,
        terminal_hash_after=terminal_hash_after,
    )


def audit_custody_ledger(
    ledger_or_path: Union[CustodyLedger, str, Path],
    manifest: Optional[Union[ManifestRecord, ManifestVerificationResult, str, Path]] = None,
    evidence_directory: Optional[Union[str, Path]] = None,
    allow_symlinks: bool = False,
) -> CustodyAuditResult:
    """
    Perform a comprehensive cryptographic, possession-continuity, chronology, and digest audit.

    Evaluation Dimensions:
    1. Cryptographic chain integrity (delegates to validate_chain()).
    2. Declared possession continuity per evidence item.
    3. Chronological progression per evidence item.
    4. Evidence digest comparison against trusted baselines.

    Precedence Hierarchy:
    TAMPERED > DISCREPANCY_DETECTED > INCOMPLETE_HISTORY > VERIFIED

    Args:
        ledger_or_path: CustodyLedger instance or path to JSON ledger.
        manifest: Optional ManifestRecord, ManifestVerificationResult, or manifest file path.
        evidence_directory: Optional evidence root directory (needed if manifest file requires verification).
        allow_symlinks: Symlink policy if on-demand manifest verification is required.

    Returns:
        CustodyAuditResult: Complete audit result preserving all granular findings.
    """
    findings: List[AuditFinding] = []

    # 1. Resolve and Load Ledger
    ledger: CustodyLedger
    if isinstance(ledger_or_path, (str, Path)):
        p = Path(ledger_or_path).resolve()
        if not p.exists():
            return CustodyAuditResult(
                ledger_id="UNKNOWN",
                is_valid=False,
                audit_status="TAMPERED",
                total_events=0,
                evidence_ids_tracked=(),
                current_custodians=(),
                current_locations=(),
                findings=(
                    AuditFinding(
                        finding_type="LEDGER_FILE_NOT_FOUND",
                        severity="TAMPERED",
                        message=f"Custody ledger file does not exist: '{p}'",
                    ),
                ),
            )
        try:
            ledger = CustodyLedger.load_from_file(p)
        except Exception as err:
            return CustodyAuditResult(
                ledger_id="UNKNOWN",
                is_valid=False,
                audit_status="TAMPERED",
                total_events=0,
                evidence_ids_tracked=(),
                current_custodians=(),
                current_locations=(),
                findings=(
                    AuditFinding(
                        finding_type="LEDGER_DESERIALIZATION_FAILURE",
                        severity="TAMPERED",
                        message=f"Failed to load or validate custody ledger JSON: {err}",
                    ),
                ),
            )
    elif isinstance(ledger_or_path, CustodyLedger):
        ledger = ledger_or_path
    else:
        raise TypeError(f"ledger_or_path must be CustodyLedger or path, got {type(ledger_or_path).__name__}")

    # 2. Cryptographic Chain Validation
    chain_verif = ledger.validate_chain()
    is_chain_tampered = not chain_verif.is_valid or chain_verif.integrity_status == "TAMPERED"
    if is_chain_tampered:
        for disc in chain_verif.discrepancies:
            findings.append(
                AuditFinding(
                    finding_type="CRYPTOGRAPHIC_CHAIN_FAILURE",
                    severity="TAMPERED",
                    message=disc,
                )
            )

    # Empty Ledger Handling
    if len(ledger.events) == 0:
        findings.append(
            AuditFinding(
                finding_type="EMPTY_LEDGER",
                severity="INCOMPLETE",
                message="Custody ledger is empty; no events are recorded.",
            )
        )
        return CustodyAuditResult(
            ledger_id=ledger.ledger_id,
            is_valid=False,
            audit_status="TAMPERED" if is_chain_tampered else "INCOMPLETE_HISTORY",
            total_events=0,
            evidence_ids_tracked=(),
            current_custodians=(),
            current_locations=(),
            findings=tuple(findings),
        )

    # 3. Resolve Trusted Manifest Baseline (if provided)
    trusted_baselines: Dict[str, Dict[str, str]] = {}  # evidence_id or relative_path -> {algo: digest}
    if manifest is not None:
        if isinstance(manifest, ManifestVerificationResult):
            if manifest.overall_status:
                for ev in manifest.entry_results:
                    if ev.is_verified:
                        trusted_baselines[ev.relative_path] = dict(ev.expected_hashes)
            else:
                findings.append(
                    AuditFinding(
                        finding_type="MANIFEST_BASELINE_FAILED_VERIFICATION",
                        severity="DISCREPANCY",
                        message=(
                            f"Supplied manifest verification result has failures ({manifest.mismatch_count} mismatch, "
                            f"{manifest.missing_count} missing); cannot serve as a trusted baseline."
                        ),
                    )
                )
        elif isinstance(manifest, ManifestRecord):
            if evidence_directory is not None:
                ev_dir_path = Path(evidence_directory).resolve()
                v_res = verify_manifest(manifest=manifest, base_dir=ev_dir_path, allow_symlinks=allow_symlinks)
                if v_res.overall_status:
                    for ev in v_res.entry_results:
                        if ev.is_verified:
                            trusted_baselines[ev.relative_path] = dict(ev.expected_hashes)
                else:
                    findings.append(
                        AuditFinding(
                            finding_type="MANIFEST_BASELINE_FAILED_VERIFICATION",
                            severity="DISCREPANCY",
                            message="On-demand manifest verification failed against evidence directory.",
                        )
                    )
            else:
                findings.append(
                    AuditFinding(
                        finding_type="MANIFEST_UNVERIFIED_WITHOUT_EVIDENCE_DIR",
                        severity="INCOMPLETE",
                        message=(
                            "ManifestRecord provided without evidence_directory; "
                            "unverified manifest entries cannot serve as trusted baseline."
                        ),
                    )
                )
        elif isinstance(manifest, (str, Path)):
            man_path = Path(manifest).resolve()
            if not man_path.exists():
                findings.append(
                    AuditFinding(
                        finding_type="MANIFEST_FILE_NOT_FOUND",
                        severity="DISCREPANCY",
                        message=f"Manifest file path does not exist: '{man_path}'",
                    )
                )
            elif evidence_directory is not None:
                ev_dir_path = Path(evidence_directory).resolve()
                try:
                    v_res = verify_manifest(manifest=man_path, base_dir=ev_dir_path, allow_symlinks=allow_symlinks)
                    if v_res.overall_status:
                        for ev in v_res.entry_results:
                            if ev.is_verified:
                                trusted_baselines[ev.relative_path] = dict(ev.expected_hashes)
                    else:
                        findings.append(
                            AuditFinding(
                                finding_type="MANIFEST_BASELINE_FAILED_VERIFICATION",
                                severity="DISCREPANCY",
                                message=f"Verification of manifest '{man_path.name}' failed against evidence directory.",
                            )
                        )
                except Exception as err:
                    findings.append(
                        AuditFinding(
                            finding_type="MANIFEST_VERIFICATION_ERROR",
                            severity="DISCREPANCY",
                            message=f"Failed to verify manifest file: {err}",
                        )
                    )
            else:
                findings.append(
                    AuditFinding(
                        finding_type="MANIFEST_UNVERIFIED_WITHOUT_EVIDENCE_DIR",
                        severity="INCOMPLETE",
                        message="Manifest file provided without evidence_directory; unverified manifest cannot serve as trusted baseline.",
                    )
                )

    # 4. Group Events by Evidence ID
    events_by_evidence: Dict[str, List[CustodyEvent]] = {}
    for ev in ledger.events:
        events_by_evidence.setdefault(ev.evidence_id, []).append(ev)

    current_custodians_map: Dict[str, Dict[str, Any]] = {}
    current_locations_map: Dict[str, Optional[str]] = {}

    for eid, ev_list in events_by_evidence.items():
        active_custodian: Optional[CustodyActor] = None
        active_location: Optional[str] = None
        intake_established: bool = False
        prior_dt: Optional[datetime] = None
        prior_dt_is_aware: Optional[bool] = None

        first_event = ev_list[0]

        # 4A. Intake Check
        if first_event.action_type in (
            CustodyActionType.EVIDENCE_RECEIVED,
            CustodyActionType.EVIDENCE_REGISTERED,
        ):
            intake_established = True
            active_custodian = first_event.actor
            active_location = first_event.destination_location or first_event.source_location
        else:
            findings.append(
                AuditFinding(
                    finding_type="MISSING_INTAKE_EVENT",
                    severity="INCOMPLETE",
                    evidence_id=eid,
                    event_id=first_event.event_id,
                    sequence_number=first_event.sequence_number,
                    message=(
                        f"Evidence item '{eid}' has no recorded EVIDENCE_RECEIVED or "
                        f"EVIDENCE_REGISTERED intake event; initial custody is unverified."
                    ),
                )
            )

        # 4B. Evaluate Event Sequence for this Evidence ID
        for ev in ev_list:
            # Chronology Evaluation
            try:
                # Compare timestamps safely
                curr_is_aware = is_timezone_aware(ev.timestamp)
                curr_dt = normalize_timestamp(ev.timestamp, to_utc=True if curr_is_aware else False)

                if prior_dt is not None:
                    if prior_dt_is_aware != curr_is_aware:
                        findings.append(
                            AuditFinding(
                                finding_type="TIMESTAMP_TIMEZONE_AMBIGUITY",
                                severity="DISCREPANCY",
                                evidence_id=eid,
                                event_id=ev.event_id,
                                sequence_number=ev.sequence_number,
                                message=(
                                    f"Consecutive events for evidence '{eid}' mix timezone-aware "
                                    f"and timezone-naive timestamps ({prior_dt} vs {curr_dt})."
                                ),
                            )
                        )
                    else:
                        # Consistent awareness: check chronological progression
                        if curr_dt < prior_dt:
                            finding_type = (
                                "CHRONOLOGICAL_INVERSION_MANUAL_ENTRY"
                                if ev.timestamp_source == TimestampSource.MANUAL_ENTRY
                                else "CHRONOLOGICAL_INVERSION_HOST_CLOCK_SKEW"
                            )
                            findings.append(
                                AuditFinding(
                                    finding_type=finding_type,
                                    severity="DISCREPANCY",
                                    evidence_id=eid,
                                    event_id=ev.event_id,
                                    sequence_number=ev.sequence_number,
                                    message=(
                                        f"Chronological inversion on evidence '{eid}': timestamp '{ev.timestamp}' "
                                        f"is earlier than preceding event timestamp (source: {ev.timestamp_source})."
                                    ),
                                    details={"preceding_timestamp": prior_dt.isoformat(), "current_timestamp": curr_dt.isoformat()},
                                )
                            )

                prior_dt = curr_dt
                prior_dt_is_aware = curr_is_aware
            except Exception as ts_err:
                findings.append(
                    AuditFinding(
                        finding_type="MALFORMED_EVENT_TIMESTAMP",
                        severity="DISCREPANCY",
                        evidence_id=eid,
                        event_id=ev.event_id,
                        sequence_number=ev.sequence_number,
                        message=f"Failed to parse event timestamp '{ev.timestamp}': {ts_err}",
                    )
                )

            # Possession Continuity & Transfer Evaluation
            if ev.action_type == CustodyActionType.CUSTODY_TRANSFERRED:
                structured_transfer = parse_transfer_from_event(ev)
                if structured_transfer is not None:
                    # Modern V8.7 structured transfer
                    if structured_transfer.is_relocation:
                        # Relocation under same custodian
                        active_location = structured_transfer.destination_location
                    else:
                        # Inter-custodian handover
                        if active_custodian is not None:
                            if structured_transfer.releasing_actor.declared_identity != active_custodian.declared_identity:
                                findings.append(
                                    AuditFinding(
                                        finding_type="POSSESSION_CONTINUITY_BREAK",
                                        severity="DISCREPANCY",
                                        evidence_id=eid,
                                        event_id=ev.event_id,
                                        sequence_number=ev.sequence_number,
                                        message=(
                                            f"Possession continuity break for evidence '{eid}' at event '{ev.event_id}': "
                                            f"releasing actor '{structured_transfer.releasing_actor.declared_identity}' does not "
                                            f"match registered active custodian '{active_custodian.declared_identity}'."
                                        ),
                                        details={
                                            "declared_releasing": structured_transfer.releasing_actor.to_dict(),
                                            "active_custodian": active_custodian.to_dict(),
                                        },
                                    )
                                )
                        else:
                            findings.append(
                                AuditFinding(
                                    finding_type="UNVERIFIED_INITIAL_CUSTODIAN",
                                    severity="INCOMPLETE",
                                    evidence_id=eid,
                                    event_id=ev.event_id,
                                    sequence_number=ev.sequence_number,
                                    message=(
                                        f"Transfer on evidence '{eid}' occurred without prior verified custodian; "
                                        f"releasing actor '{structured_transfer.releasing_actor.declared_identity}' cannot be authenticated."
                                    ),
                                )
                            )
                        active_custodian = structured_transfer.receiving_actor
                        active_location = structured_transfer.destination_location
                else:
                    # Legacy Schema 8.0 transfer (single actor)
                    findings.append(
                        AuditFinding(
                            finding_type="UNVERIFIABLE_LEGACY_TRANSFER",
                            severity="INCOMPLETE",
                            evidence_id=eid,
                            event_id=ev.event_id,
                            sequence_number=ev.sequence_number,
                            message=(
                                f"Legacy transfer event '{ev.event_id}' lacks structured releasing/receiving metadata; "
                                f"possession continuity cannot be fully certified."
                            ),
                        )
                    )
                    active_custodian = ev.actor
                    active_location = ev.destination_location or ev.source_location
            elif ev.action_type in (
                CustodyActionType.EVIDENCE_RECEIVED,
                CustodyActionType.EVIDENCE_REGISTERED,
            ):
                active_custodian = ev.actor
                active_location = ev.destination_location or ev.source_location

            # Digest Comparison against Trusted Baseline
            if ev.hashes:
                ev_hashes_dict = dict(ev.hashes)
                # Look up trusted baseline by evidence_id or relative path
                baseline_hashes = trusted_baselines.get(eid)
                if baseline_hashes is not None:
                    # Compare shared algorithms
                    for algo, digest in ev_hashes_dict.items():
                        if algo in baseline_hashes:
                            base_digest = baseline_hashes[algo]
                            if digest.lower() != base_digest.lower():
                                findings.append(
                                    AuditFinding(
                                        finding_type="DIGEST_MISMATCH",
                                        severity="DISCREPANCY",
                                        evidence_id=eid,
                                        event_id=ev.event_id,
                                        sequence_number=ev.sequence_number,
                                        message=(
                                            f"Evidence digest mismatch on item '{eid}' ({algo}): "
                                            f"event digest '{digest}' differs from trusted baseline '{base_digest}'."
                                        ),
                                        details={"algorithm": algo, "event_digest": digest, "baseline_digest": base_digest},
                                    )
                                )
                            else:
                                findings.append(
                                    AuditFinding(
                                        finding_type="DIGEST_MATCH",
                                        severity="INFO",
                                        evidence_id=eid,
                                        event_id=ev.event_id,
                                        sequence_number=ev.sequence_number,
                                        message=f"Evidence digest on item '{eid}' ({algo}) matches trusted baseline.",
                                    )
                                )
                else:
                    findings.append(
                        AuditFinding(
                            finding_type="DIGEST_UNTRUSTED_OBSERVATION",
                            severity="INFO",
                            evidence_id=eid,
                            event_id=ev.event_id,
                            sequence_number=ev.sequence_number,
                            message=f"Event records digest for item '{eid}', but no trusted baseline anchor was supplied.",
                            details={"hashes": ev_hashes_dict},
                        )
                    )

        if active_custodian is not None:
            current_custodians_map[eid] = active_custodian.to_dict()
        current_locations_map[eid] = active_location

    # 5. Determine Overall Precedence Status
    # Precedence: TAMPERED > DISCREPANCY_DETECTED > INCOMPLETE_HISTORY > VERIFIED
    has_tampered = any(f.severity == "TAMPERED" for f in findings) or is_chain_tampered
    has_discrepancy = any(f.severity == "DISCREPANCY" for f in findings)
    has_incomplete = any(f.severity == "INCOMPLETE" for f in findings)

    overall_status: str
    if has_tampered:
        overall_status = "TAMPERED"
    elif has_discrepancy:
        overall_status = "DISCREPANCY_DETECTED"
    elif has_incomplete:
        overall_status = "INCOMPLETE_HISTORY"
    else:
        overall_status = "VERIFIED"

    is_overall_valid = overall_status == "VERIFIED"

    return CustodyAuditResult(
        ledger_id=ledger.ledger_id,
        is_valid=is_overall_valid,
        audit_status=overall_status,
        total_events=len(ledger.events),
        evidence_ids_tracked=tuple(sorted(events_by_evidence.keys())),
        current_custodians=tuple(sorted(current_custodians_map.items())),
        current_locations=tuple(sorted(current_locations_map.items())),
        findings=tuple(findings),
    )
