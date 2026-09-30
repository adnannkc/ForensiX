"""
Forensic Report Models for ForensiX (V2.8).

Provides strongly typed, deeply immutable models representing structured forensic reports,
their metadata, artifact summaries, and provenance audit trails.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union
import uuid

from forensix.audit import AuditEvent
from forensix.unified_models import HostArtifact, freeze_value


class ReportFormat(str, Enum):
    """Supported output presentation formats for ForensiX reports."""

    JSON = "json"
    CSV = "csv"
    HTML = "html"


def generate_report_id() -> str:
    """Generate a unique tracking identifier for a forensic report (REPORT-<UUIDv4>)."""
    return f"REPORT-{uuid.uuid4()}"


@dataclass(frozen=True)
class ReportMetadata:
    """
    Immutable representation of forensic report administrative context and provenance.

    Attributes:
        report_id: Unique identifier conforming to REPORT-<UUIDv4>.
        case_id: Case identifier if available, or None (never fabricated).
        case_name: Case name if available, or None.
        investigator: Name or ID of investigator if available, or None.
        created_at: ISO 8601 UTC timestamp string when the report was generated.
        forensix_version: Software release version generating the report.
        evidence_root: Root path of analyzed evidence if applicable, or None.
        report_format: Format string ('json', 'csv', 'html').
    """

    report_id: str
    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    created_at: str
    forensix_version: str
    evidence_root: Optional[str]
    report_format: str
    triage_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate metadata fields strictly."""
        if not isinstance(self.report_id, str) or not self.report_id.strip():
            raise ValueError("report_id must be a non-empty string")
        if not isinstance(self.created_at, str) or not self.created_at.strip():
            raise ValueError("created_at must be a non-empty string")
        if not isinstance(self.forensix_version, str) or not self.forensix_version.strip():
            raise ValueError("forensix_version must be a non-empty string")
        if not isinstance(self.report_format, str) or not self.report_format.strip():
            raise ValueError("report_format must be a non-empty string")
        if self.triage_id is not None:
            if not isinstance(self.triage_id, str) or not self.triage_id.strip():
                raise ValueError("triage_id must be a non-empty string when provided")

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a fully JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "report_id": self.report_id,
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "created_at": self.created_at,
            "forensix_version": self.forensix_version,
            "evidence_root": self.evidence_root,
            "report_format": self.report_format,
        }
        if self.triage_id is not None:
            d["triage_id"] = self.triage_id
        return d


@dataclass(frozen=True)
class ForensicReport:
    """
    Immutable, deterministically structured representation of a complete forensic report.

    Attributes:
        metadata: ReportMetadata describing the case and generation parameters.
        artifacts: Tuple of HostArtifact instances, deterministically sorted.
        total_artifacts: Total count of artifacts in the report.
        category_breakdown: Tuple of (category, count) pairs sorted alphabetically.
        status_breakdown: Tuple of (status, count) pairs sorted alphabetically.
        audit_trail: Tuple of AuditEvent instances in chronological order.
        stage_results: Optional tuple of pipeline stage results for triage runs.
        trace_records: Optional tuple of provenance trace records for triage runs.
        investigation_summary: Optional dictionary summary of investigation query results.
    """

    metadata: ReportMetadata
    artifacts: Tuple[HostArtifact, ...]
    total_artifacts: int
    category_breakdown: Tuple[Tuple[str, int], ...]
    status_breakdown: Tuple[Tuple[str, int], ...]
    audit_trail: Tuple[AuditEvent, ...]
    stage_results: Tuple[Any, ...] = ()
    trace_records: Tuple[Any, ...] = ()
    investigation_summary: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Enforce deep immutability on report contents."""
        if not isinstance(self.metadata, ReportMetadata):
            raise TypeError(f"metadata must be ReportMetadata, got {type(self.metadata).__name__}")
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.category_breakdown, tuple):
            object.__setattr__(self, "category_breakdown", freeze_value(self.category_breakdown))
        if not isinstance(self.status_breakdown, tuple):
            object.__setattr__(self, "status_breakdown", freeze_value(self.status_breakdown))
        if not isinstance(self.audit_trail, tuple):
            object.__setattr__(self, "audit_trail", tuple(self.audit_trail))
        if not isinstance(self.stage_results, tuple):
            object.__setattr__(self, "stage_results", tuple(self.stage_results))
        if not isinstance(self.trace_records, tuple):
            object.__setattr__(self, "trace_records", tuple(self.trace_records))
        if self.investigation_summary is not None and not isinstance(self.investigation_summary, dict):
            object.__setattr__(self, "investigation_summary", freeze_value(self.investigation_summary))

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics with category and status counts in stable key order."""
        res: Dict[str, Any] = {
            "total_artifacts": self.total_artifacts,
            "category_breakdown": dict(self.category_breakdown),
            "status_breakdown": dict(self.status_breakdown),
            "audit_events_count": len(self.audit_trail),
        }
        if self.stage_results:
            res["stages_count"] = len(self.stage_results)
        if self.trace_records:
            res["trace_records_count"] = len(self.trace_records)
        if self.investigation_summary is not None:
            res["investigation_summary"] = dict(self.investigation_summary)
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete report to a fully JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "metadata": self.metadata.to_dict(),
            "summary": self.summary,
            "artifacts": [art.to_dict() for art in self.artifacts],
            "audit_trail": [evt.to_dict() for evt in self.audit_trail],
        }
        if self.stage_results:
            d["stage_results"] = [
                s.to_dict() if hasattr(s, "to_dict") else dict(s) for s in self.stage_results
            ]
        if self.trace_records:
            d["trace_records"] = [
                t.to_dict() if hasattr(t, "to_dict") else dict(t) for t in self.trace_records
            ]
        if self.investigation_summary is not None:
            d["investigation_summary"] = (
                self.investigation_summary
                if isinstance(self.investigation_summary, dict)
                else dict(self.investigation_summary)
            )
        return d
