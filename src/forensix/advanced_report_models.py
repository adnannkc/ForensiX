"""
Advanced Forensic Report Models for ForensiX (V8.1).

Provides strongly typed, deeply immutable dataclasses representing the unified
ForensiX Schema 8.0 advanced investigation report, binding case metadata, evidence
inventory, analytical findings summaries, chain-of-custody status, and explicit
analytical limitations into a single verifiable forensic artifact.

Strict Engineering & Forensic Principles:
- Preserves missing, ambiguous, or incomplete data as None (never fabricates metadata).
- Rejects booleans for integer counters.
- Defensively freezes nested collections and mappings to enforce deep immutability.
- Separates observed facts, derived correlations, and analytical limitations explicitly.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import uuid

from forensix.manifest_models import validate_relative_entry_path
from forensix.report_reader import freeze_payload, unfreeze_payload
from forensix.timestamp_normalizer import normalize_timestamp

ADVANCED_REPORT_SCHEMA_VERSION: str = "8.0"

DEFAULT_ANALYTICAL_DISCLAIMER: str = (
    "Detections, correlations, and forensic artifacts represent automated observations and rule evaluations. "
    "They do not constitute conclusive proof of compromise, attribution, or legal culpability."
)

_RE_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RE_MD5_HEX = re.compile(r"^[0-9a-f]{32}$")

VALID_CHAIN_INTEGRITY_STATUSES = {"VERIFIED", "UNVERIFIED", "TAMPERED"}


def generate_advanced_report_id() -> str:
    """
    Generate a canonical tracking identifier for an advanced forensic report (REP8-<UUIDv4>).

    Returns:
        str: Unique identifier string conforming to REP8-<UUIDv4>.
    """
    return f"REP8-{uuid.uuid4()}"


def is_valid_advanced_report_id(report_id: Any) -> bool:
    """
    Validate that an identifier strictly conforms to REP8-<UUIDv4>.

    Args:
        report_id: Candidate identifier string.

    Returns:
        bool: True if valid REP8-<UUIDv4>, False otherwise.
    """
    if not isinstance(report_id, str):
        return False
    if not report_id.startswith("REP8-"):
        return False
    raw_uuid = report_id[5:]
    try:
        val = uuid.UUID(raw_uuid)
        return val.version == 4 and str(val) == raw_uuid
    except (ValueError, AttributeError, TypeError):
        return False


def _validate_hashes(
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]],
) -> Tuple[Tuple[str, str], ...]:
    """Validate and freeze hash pairs into a sorted tuple."""
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

    if not items:
        raise ValueError("EvidenceInventoryItem must contain at least one valid cryptographic hash")

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

    return tuple(sorted(validated, key=lambda x: x[0]))


@dataclass(frozen=True)
class EvidenceInventoryItem:
    """
    Immutable representation of an evidence item analyzed in the investigation.

    Attributes:
        evidence_id: ForensiX evidence tracking identifier (e.g. EV-...).
        relative_path: Validated relative POSIX path from evidence root.
        size_bytes: Non-negative file size in bytes.
        hashes: Cryptographic baseline digests (MD5, SHA-256).
        registration_timestamp: ISO 8601 UTC timestamp string of registration.
        verification_status: Optional post-analysis verification status (e.g. 'MATCH', 'MISMATCH').
    """

    evidence_id: str
    relative_path: str
    size_bytes: int
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]]
    registration_timestamp: str
    verification_status: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate evidence inventory fields."""
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("evidence_id must be a non-empty string")
        object.__setattr__(self, "evidence_id", self.evidence_id.strip())

        valid_path = validate_relative_entry_path(self.relative_path)
        object.__setattr__(self, "relative_path", valid_path)

        if type(self.size_bytes) is not int or isinstance(self.size_bytes, bool):
            raise TypeError(f"size_bytes must be an integer, got {type(self.size_bytes).__name__}")
        if self.size_bytes < 0:
            raise ValueError(f"size_bytes must be non-negative, got {self.size_bytes}")

        frozen_hashes = _validate_hashes(self.hashes)
        object.__setattr__(self, "hashes", frozen_hashes)

        if not isinstance(self.registration_timestamp, str) or not self.registration_timestamp.strip():
            raise ValueError("registration_timestamp must be a non-empty ISO 8601 string")
        clean_ts = self.registration_timestamp.strip()
        normalize_timestamp(clean_ts, to_utc=False)
        object.__setattr__(self, "registration_timestamp", clean_ts)

        if self.verification_status is not None:
            if not isinstance(self.verification_status, str):
                raise TypeError("verification_status must be a string or None")
            clean_status = self.verification_status.strip().upper()
            object.__setattr__(self, "verification_status", clean_status if clean_status else None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert inventory item to a clean JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
            "hashes": dict(self.hashes),
            "registration_timestamp": self.registration_timestamp,
            "verification_status": self.verification_status,
        }


@dataclass(frozen=True)
class FindingsSummary:
    """
    Immutable aggregate metrics summarizing verified analytical findings.

    Attributes:
        total_host_artifacts: Count of host artifacts extracted.
        total_timeline_events: Count of chronological timeline events reconstructed.
        total_correlations: Count of cross-artifact correlations identified.
        total_rule_evaluations: Count of declarative detection rules evaluated.
        matched_detections: Count of detection rules that produced a match.
    """

    total_host_artifacts: int = 0
    total_timeline_events: int = 0
    total_correlations: int = 0
    total_rule_evaluations: int = 0
    matched_detections: int = 0

    def __post_init__(self) -> None:
        """Validate that all counters are non-negative integers (reject booleans)."""
        for field_name in (
            "total_host_artifacts",
            "total_timeline_events",
            "total_correlations",
            "total_rule_evaluations",
            "matched_detections",
        ):
            val = getattr(self, field_name)
            if type(val) is not int or isinstance(val, bool):
                raise TypeError(f"{field_name} must be an integer, got {type(val).__name__}")
            if val < 0:
                raise ValueError(f"{field_name} must be non-negative, got {val}")

    def to_dict(self) -> Dict[str, int]:
        """Convert summary counters to dictionary."""
        return {
            "total_host_artifacts": self.total_host_artifacts,
            "total_timeline_events": self.total_timeline_events,
            "total_correlations": self.total_correlations,
            "total_rule_evaluations": self.total_rule_evaluations,
            "matched_detections": self.matched_detections,
        }


@dataclass(frozen=True)
class CustodySummary:
    """
    Immutable representation of chain-of-custody status within an advanced report.

    Attributes:
        ledger_id: Tracking identifier of the custody ledger.
        total_events: Number of custody events recorded.
        terminal_hash: 64-character lowercase hex SHA-256 of the terminal event.
        chain_integrity: Status string: 'VERIFIED', 'UNVERIFIED', or 'TAMPERED'.
    """

    ledger_id: str
    total_events: int
    terminal_hash: str
    chain_integrity: str = "UNVERIFIED"

    def __post_init__(self) -> None:
        """Validate custody summary attributes."""
        if not isinstance(self.ledger_id, str) or not self.ledger_id.strip():
            raise ValueError("ledger_id must be a non-empty string")
        object.__setattr__(self, "ledger_id", self.ledger_id.strip())

        if type(self.total_events) is not int or isinstance(self.total_events, bool):
            raise TypeError(f"total_events must be an integer, got {type(self.total_events).__name__}")
        if self.total_events < 0:
            raise ValueError(f"total_events must be non-negative, got {self.total_events}")

        if not isinstance(self.terminal_hash, str):
            raise TypeError("terminal_hash must be a string")
        clean_hash = self.terminal_hash.strip().lower()
        if not _RE_SHA256_HEX.match(clean_hash):
            raise ValueError(
                f"terminal_hash '{self.terminal_hash}' must be exactly 64 lowercase hex characters"
            )
        object.__setattr__(self, "terminal_hash", clean_hash)

        if not isinstance(self.chain_integrity, str):
            raise TypeError("chain_integrity must be a string")
        clean_status = self.chain_integrity.strip().upper()
        if clean_status not in VALID_CHAIN_INTEGRITY_STATUSES:
            raise ValueError(
                f"chain_integrity '{self.chain_integrity}' must be one of {sorted(VALID_CHAIN_INTEGRITY_STATUSES)}"
            )
        object.__setattr__(self, "chain_integrity", clean_status)

    def to_dict(self) -> Dict[str, Any]:
        """Convert custody summary to dictionary."""
        return {
            "ledger_id": self.ledger_id,
            "total_events": self.total_events,
            "terminal_hash": self.terminal_hash,
            "chain_integrity": self.chain_integrity,
        }


@dataclass(frozen=True)
class AnalyticalLimitations:
    """
    Immutable representation of explicitly stated omissions, warnings, and disclaimers.

    Attributes:
        warnings: Immutable tuple of warning strings (e.g. unreadable files).
        omissions: Immutable tuple of unsupported features or intentionally excluded scopes.
        evidentiary_disclaimer: Factual standard disclaimer text.
    """

    warnings: Sequence[str] = ()
    omissions: Sequence[str] = ()
    evidentiary_disclaimer: str = DEFAULT_ANALYTICAL_DISCLAIMER

    def __post_init__(self) -> None:
        """Freeze warning and omission sequences into tuples of strings."""
        frozen_warnings = tuple(str(w).strip() for w in self.warnings if str(w).strip())
        object.__setattr__(self, "warnings", frozen_warnings)

        frozen_omissions = tuple(str(o).strip() for o in self.omissions if str(o).strip())
        object.__setattr__(self, "omissions", frozen_omissions)

        if not isinstance(self.evidentiary_disclaimer, str) or not self.evidentiary_disclaimer.strip():
            raise ValueError("evidentiary_disclaimer must be a non-empty string")
        object.__setattr__(self, "evidentiary_disclaimer", self.evidentiary_disclaimer.strip())

    def to_dict(self) -> Dict[str, Any]:
        """Convert limitations to dictionary."""
        return {
            "warnings": list(self.warnings),
            "omissions": list(self.omissions),
            "evidentiary_disclaimer": self.evidentiary_disclaimer,
        }


@dataclass(frozen=True)
class AdvancedReport:
    """
    Immutable representation of a ForensiX Schema 8.0 Advanced Forensic Report.

    Attributes:
        report_schema: Schema version string, fixed to '8.0'.
        report_id: Canonical report identifier conforming to REP8-<UUIDv4>.
        created_at: ISO 8601 UTC timestamp string of report generation.
        forensix_version: Software release version generating the report.
        case_metadata: Case administrative parameters (case_id, case_name, investigator, evidence_root).
        evidence_inventory: Immutable tuple of EvidenceInventoryItem instances.
        findings_summary: FindingsSummary metrics.
        custody_summary: Optional CustodySummary record.
        limitations: AnalyticalLimitations record.
        details: Optional deeply frozen dictionary of granular findings (artifacts, events, detections).
    """

    report_schema: str
    report_id: str
    created_at: str
    forensix_version: str
    case_metadata: Mapping[str, Any]
    evidence_inventory: Sequence[EvidenceInventoryItem]
    findings_summary: FindingsSummary
    limitations: AnalyticalLimitations
    custody_summary: Optional[CustodySummary] = None
    details: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate and defensively freeze report components."""
        # 1. Report schema
        if not isinstance(self.report_schema, str) or self.report_schema.strip() != ADVANCED_REPORT_SCHEMA_VERSION:
            raise ValueError(
                f"report_schema must be '{ADVANCED_REPORT_SCHEMA_VERSION}', got '{self.report_schema}'"
            )
        object.__setattr__(self, "report_schema", ADVANCED_REPORT_SCHEMA_VERSION)

        # 2. Report ID
        if not is_valid_advanced_report_id(self.report_id):
            raise ValueError(
                f"Invalid report_id '{self.report_id}': must conform to canonical REP8-<UUIDv4>"
            )

        # 3. Created At
        if not isinstance(self.created_at, str) or not self.created_at.strip():
            raise ValueError("created_at must be a non-empty ISO 8601 string")
        clean_ts = self.created_at.strip()
        normalize_timestamp(clean_ts, to_utc=False)
        object.__setattr__(self, "created_at", clean_ts)

        # 4. ForensiX Version
        if not isinstance(self.forensix_version, str) or not self.forensix_version.strip():
            raise ValueError("forensix_version must be a non-empty string")
        object.__setattr__(self, "forensix_version", self.forensix_version.strip())

        # 5. Case Metadata (deeply frozen)
        if not isinstance(self.case_metadata, (dict, Mapping)):
            raise TypeError(f"case_metadata must be a Mapping, got {type(self.case_metadata).__name__}")
        object.__setattr__(self, "case_metadata", freeze_payload(self.case_metadata))

        # 6. Evidence Inventory
        if not isinstance(self.evidence_inventory, (list, tuple)):
            raise TypeError("evidence_inventory must be a Sequence of EvidenceInventoryItem instances")
        for idx, item in enumerate(self.evidence_inventory):
            if not isinstance(item, EvidenceInventoryItem):
                raise TypeError(
                    f"Item at index {idx} of evidence_inventory is {type(item).__name__}, expected EvidenceInventoryItem"
                )
        object.__setattr__(self, "evidence_inventory", tuple(self.evidence_inventory))

        # 7. Findings Summary
        if not isinstance(self.findings_summary, FindingsSummary):
            raise TypeError(f"findings_summary must be FindingsSummary, got {type(self.findings_summary).__name__}")

        # 8. Limitations
        if not isinstance(self.limitations, AnalyticalLimitations):
            raise TypeError(f"limitations must be AnalyticalLimitations, got {type(self.limitations).__name__}")

        # 9. Custody Summary
        if self.custody_summary is not None and not isinstance(self.custody_summary, CustodySummary):
            raise TypeError(f"custody_summary must be CustodySummary or None, got {type(self.custody_summary).__name__}")

        # 10. Granular Details (deeply frozen if provided)
        if self.details is not None:
            if not isinstance(self.details, (dict, Mapping)):
                raise TypeError(f"details must be a Mapping or None, got {type(self.details).__name__}")
            object.__setattr__(self, "details", freeze_payload(self.details))

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete advanced report to a pure, JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "report_schema": self.report_schema,
            "report_id": self.report_id,
            "created_at": self.created_at,
            "forensix_version": self.forensix_version,
            "case_metadata": unfreeze_payload(self.case_metadata),
            "evidence_inventory": [item.to_dict() for item in self.evidence_inventory],
            "findings_summary": self.findings_summary.to_dict(),
            "limitations": self.limitations.to_dict(),
        }
        if self.custody_summary is not None:
            d["custody_summary"] = self.custody_summary.to_dict()
        if self.details is not None:
            d["details"] = unfreeze_payload(self.details)
        return d
