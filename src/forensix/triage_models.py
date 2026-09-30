"""
Forensic Triage & Orchestration Models for ForensiX (V2.9.1).

Provides strongly typed, deeply immutable models representing triage pipeline configuration,
stage lifecycles, structured execution errors, stage results, and aggregate triage outcomes.

Strict boundaries:
- Orchestration and automation models only
- Factual software execution states (NOT forensic/threat conclusions)
- Deeply immutable (frozen dataclasses, tuple collections)
- Deterministic, JSON-serializable output structures
- Canonical models (HostArtifact, InvestigationResultSet, ForensicReport) remain authoritative
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.audit import AuditEvent
from forensix.investigation import HostArtifactInvestigator, InvestigationResultSet
from forensix.report_models import ForensicReport, ReportFormat
from forensix.unified_models import HostArtifactCollection, freeze_value


class TriageStage(str, Enum):
    """Enumeration of standard stages in the ForensiX V2 triage pipeline."""

    EVIDENCE_VALIDATION = "evidence_validation"
    FILESYSTEM_COLLECTION = "filesystem_collection"
    LOG_PARSING = "log_parsing"
    AUTHENTICATION_ANALYSIS = "authentication_analysis"
    ACCOUNT_ANALYSIS = "account_analysis"
    PERSISTENCE_ANALYSIS = "persistence_analysis"
    UNIFIED_HOST_MODEL = "unified_host_model"
    INVESTIGATION = "investigation"
    REPORTING = "reporting"


ALL_TRIAGE_STAGES: Tuple[str, ...] = tuple(s.value for s in TriageStage)


class TriageStageStatus(str, Enum):
    """
    Execution lifecycle status of an individual pipeline stage.

    Describes software execution state only. Does NOT indicate forensic threat or compromise findings.
    """

    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


ALL_STAGE_STATUSES: Tuple[str, ...] = tuple(s.value for s in TriageStageStatus)


def generate_triage_id() -> str:
    """Generate a unique tracking identifier for an end-to-end triage run (TRIAGE-<UUIDv4>)."""
    return f"TRIAGE-{uuid.uuid4()}"


@dataclass(frozen=True)
class TriageConfig:
    """
    Immutable configuration specification for an end-to-end host triage run.

    Attributes:
        evidence_path: Target evidence directory path string.
        case_id: Incident case tracking identifier if available.
        case_name: Human-readable incident title if available.
        investigator: Handling investigator name or ID if available.
        output_dir: Destination directory for generated reports if applicable.
        enabled_stages: Immutable tuple of TriageStage values to execute.
        report_formats: Immutable tuple of ReportFormat strings ('json', 'csv', 'html').
        skip_reports: If True, skips generating file reports.
        collect_audit: If True, records software provenance audit events.
    """

    evidence_path: str
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    output_dir: Optional[str] = None
    enabled_stages: Tuple[str, ...] = ALL_TRIAGE_STAGES
    report_formats: Tuple[str, ...] = (ReportFormat.JSON.value, ReportFormat.CSV.value, ReportFormat.HTML.value)
    skip_reports: bool = False
    collect_audit: bool = True

    def __post_init__(self) -> None:
        """Validate configuration parameters strictly."""
        if not isinstance(self.evidence_path, (str, Path)):
            raise TypeError(f"evidence_path must be str or Path, got {type(self.evidence_path).__name__}")
        str_path = str(self.evidence_path).strip()
        if not str_path:
            raise ValueError("evidence_path cannot be empty or whitespace")
        object.__setattr__(self, "evidence_path", str_path)

        if self.case_id is not None:
            if not isinstance(self.case_id, str):
                raise TypeError(f"case_id must be str or None, got {type(self.case_id).__name__}")
            object.__setattr__(self, "case_id", self.case_id.strip() or None)

        if self.case_name is not None:
            if not isinstance(self.case_name, str):
                raise TypeError(f"case_name must be str or None, got {type(self.case_name).__name__}")
            object.__setattr__(self, "case_name", self.case_name.strip() or None)

        if self.investigator is not None:
            if not isinstance(self.investigator, str):
                raise TypeError(f"investigator must be str or None, got {type(self.investigator).__name__}")
            object.__setattr__(self, "investigator", self.investigator.strip() or None)

        if self.output_dir is not None:
            if not isinstance(self.output_dir, (str, Path)):
                raise TypeError(f"output_dir must be str, Path, or None, got {type(self.output_dir).__name__}")
            out_str = str(self.output_dir).strip()
            if out_str:
                ev_res = Path(str_path).resolve()
                out_res = Path(out_str).resolve()
                if out_res == ev_res or ev_res in out_res.parents:
                    raise ValueError(
                        f"output_dir cannot be within or identical to evidence_path: {out_str!r}"
                    )
            object.__setattr__(self, "output_dir", out_str or None)

        # Enforce immutable tuple for enabled_stages and validate members
        if isinstance(self.enabled_stages, (list, tuple)):
            norm_stages: List[str] = []
            for s in self.enabled_stages:
                val = s.value if isinstance(s, TriageStage) else str(s)
                if val not in ALL_TRIAGE_STAGES:
                    raise ValueError(f"Invalid stage in enabled_stages: {val!r}. Must be one of {ALL_TRIAGE_STAGES}")
                norm_stages.append(val)
            object.__setattr__(self, "enabled_stages", tuple(norm_stages))
        else:
            raise TypeError("enabled_stages must be a sequence of TriageStage or stage name strings")

        # Enforce immutable tuple for report_formats and validate members
        valid_formats = {f.value for f in ReportFormat}
        if isinstance(self.report_formats, (list, tuple)):
            norm_formats: List[str] = []
            for f in self.report_formats:
                val = f.value if isinstance(f, ReportFormat) else str(f)
                if val not in valid_formats:
                    raise ValueError(f"Invalid report format: {val!r}. Must be one of {sorted(valid_formats)}")
                norm_formats.append(val)
            object.__setattr__(self, "report_formats", tuple(norm_formats))
        else:
            raise TypeError("report_formats must be a sequence of ReportFormat or format name strings")

        if not isinstance(self.skip_reports, bool):
            raise TypeError(f"skip_reports must be bool, got {type(self.skip_reports).__name__}")
        if not isinstance(self.collect_audit, bool):
            raise TypeError(f"collect_audit must be bool, got {type(self.collect_audit).__name__}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a fully JSON-serializable dictionary."""
        return {
            "evidence_path": self.evidence_path,
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "output_dir": self.output_dir,
            "enabled_stages": list(self.enabled_stages),
            "report_formats": list(self.report_formats),
            "skip_reports": self.skip_reports,
            "collect_audit": self.collect_audit,
        }


@dataclass(frozen=True)
class TriageStageError:
    """
    Structured, factual representation of an execution error encountered during a stage.

    Describes execution failure facts without speculating on threat intent or compromise.
    """

    stage_id: str
    error_type: str
    error_message: str
    details: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate error fields and freeze details."""
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise ValueError("stage_id must be a non-empty string")
        if not isinstance(self.error_type, str) or not self.error_type.strip():
            raise ValueError("error_type must be a non-empty string")
        if not isinstance(self.error_message, str):
            raise TypeError("error_message must be a string")
        if not isinstance(self.details, tuple):
            object.__setattr__(self, "details", freeze_value(self.details))

    def to_dict(self) -> Dict[str, Any]:
        """Convert error representation to a JSON-serializable dictionary."""
        return {
            "stage_id": self.stage_id,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class TriageStageResult:
    """
    Immutable representation of an individual triage stage execution outcome.

    Attributes:
        stage_id: Identifier matching a TriageStage value.
        stage_name: Human-readable stage title.
        status: Execution status string from TriageStageStatus.
        started_at: ISO 8601 UTC timestamp string when stage started, or None.
        completed_at: ISO 8601 UTC timestamp string when stage finished, or None.
        duration_seconds: Execution elapsed time in seconds, or None.
        records_produced: Count of discrete records or artifacts output by this stage.
        errors: Immutable tuple of TriageStageError objects.
        warnings: Immutable tuple of warning message strings.
        metadata: Immutable tuple of (key, value) pairs for stage-specific metrics.
    """

    stage_id: str
    stage_name: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    records_produced: int = 0
    errors: Tuple[TriageStageError, ...] = ()
    warnings: Tuple[str, ...] = ()
    metadata: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Enforce types, value constraints, and deep immutability."""
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise ValueError("stage_id must be a non-empty string")
        if not isinstance(self.stage_name, str) or not self.stage_name.strip():
            raise ValueError("stage_name must be a non-empty string")

        st_val = self.status.value if isinstance(self.status, TriageStageStatus) else str(self.status)
        if st_val not in ALL_STAGE_STATUSES:
            raise ValueError(f"Invalid stage status: {st_val!r}. Must be one of {ALL_STAGE_STATUSES}")
        object.__setattr__(self, "status", st_val)

        if not isinstance(self.records_produced, int) or isinstance(self.records_produced, bool):
            raise TypeError("records_produced must be an integer")
        if self.records_produced < 0:
            raise ValueError("records_produced cannot be negative")

        if not isinstance(self.errors, tuple):
            object.__setattr__(self, "errors", tuple(self.errors))
        for err in self.errors:
            if not isinstance(err, TriageStageError):
                raise TypeError(f"errors elements must be TriageStageError, got {type(err).__name__}")

        if not isinstance(self.warnings, tuple):
            object.__setattr__(self, "warnings", tuple(str(w) for w in self.warnings))

        if not isinstance(self.metadata, tuple):
            object.__setattr__(self, "metadata", freeze_value(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        """Convert stage result to a fully JSON-serializable dictionary."""
        return {
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "records_produced": self.records_produced,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class TriageSummary:
    """
    Immutable overview of the end-to-end triage execution.
    """

    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    evidence_root: str
    started_at: Optional[str]
    completed_at: Optional[str]
    total_duration_seconds: Optional[float]
    total_artifacts: int
    stages_completed: int
    stages_partial: int
    stages_failed: int
    stages_skipped: int
    is_success: bool

    def __post_init__(self) -> None:
        """Validate summary metrics."""
        if not isinstance(self.evidence_root, str) or not self.evidence_root.strip():
            raise ValueError("evidence_root must be a non-empty string")
        if not isinstance(self.is_success, bool):
            raise TypeError("is_success must be a bool")

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to a JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "evidence_root": self.evidence_root,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_seconds": self.total_duration_seconds,
            "total_artifacts": self.total_artifacts,
            "stages_completed": self.stages_completed,
            "stages_partial": self.stages_partial,
            "stages_failed": self.stages_failed,
            "stages_skipped": self.stages_skipped,
            "is_success": self.is_success,
        }


@dataclass(frozen=True)
class TriageTraceRecord:
    """
    Immutable representation of factual provenance and processing lineage for an individual triage stage.

    Preserves exact references, identifiers, and source relationships across V2 components
    without duplicating entire forensic payload objects.
    """

    triage_id: str
    stage_id: str
    stage_status: str
    input_identifiers: Tuple[str, ...] = ()
    output_identifiers: Tuple[str, ...] = ()
    source_artifact_ids: Tuple[str, ...] = ()
    source_event_ids: Tuple[str, ...] = ()
    source_paths: Tuple[str, ...] = ()
    unified_artifact_ids: Tuple[str, ...] = ()
    timestamp: str = ""

    def __post_init__(self) -> None:
        """Validate fields and enforce deep immutability."""
        if not isinstance(self.triage_id, str) or not self.triage_id.strip():
            raise ValueError("triage_id must be a non-empty string")
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise ValueError("stage_id must be a non-empty string")
        if not isinstance(self.stage_status, str) or not self.stage_status.strip():
            raise ValueError("stage_status must be a non-empty string")

        if not self.timestamp:
            object.__setattr__(self, "timestamp", datetime.now(timezone.utc).isoformat())

        for field_name in (
            "input_identifiers",
            "output_identifiers",
            "source_artifact_ids",
            "source_event_ids",
            "source_paths",
            "unified_artifact_ids",
        ):
            val = getattr(self, field_name)
            if not isinstance(val, tuple):
                object.__setattr__(self, field_name, tuple(val))
            for item in getattr(self, field_name):
                if not isinstance(item, str):
                    raise TypeError(f"Items in {field_name} must be strings, got {type(item).__name__}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert trace record to a JSON-serializable dictionary."""
        return {
            "triage_id": self.triage_id,
            "stage_id": self.stage_id,
            "stage_status": self.stage_status,
            "input_identifiers": list(self.input_identifiers),
            "output_identifiers": list(self.output_identifiers),
            "source_artifact_ids": list(self.source_artifact_ids),
            "source_event_ids": list(self.source_event_ids),
            "source_paths": list(self.source_paths),
            "unified_artifact_ids": list(self.unified_artifact_ids),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class TriageResult:
    """
    Immutable aggregate representation of the complete end-to-end triage execution.

    Contains configuration, summary statistics, ordered stage results, and references
    to canonical models (HostArtifactCollection, HostArtifactInvestigator, ForensicReport).
    """

    triage_id: str
    config: TriageConfig
    summary: TriageSummary
    stage_results: Tuple[TriageStageResult, ...]
    artifacts: Optional[HostArtifactCollection] = None
    investigator: Optional[HostArtifactInvestigator] = None
    report: Optional[ForensicReport] = None
    report_files: Tuple[Tuple[str, str], ...] = ()
    audit_trail: Tuple[AuditEvent, ...] = ()
    investigation_result: Optional[InvestigationResultSet] = None
    trace_records: Tuple[TriageTraceRecord, ...] = ()

    def __post_init__(self) -> None:
        """Enforce types and deep immutability."""
        if not isinstance(self.triage_id, str) or not self.triage_id.strip():
            raise ValueError("triage_id must be a non-empty string")
        if not isinstance(self.config, TriageConfig):
            raise TypeError(f"config must be TriageConfig, got {type(self.config).__name__}")
        if not isinstance(self.summary, TriageSummary):
            raise TypeError(f"summary must be TriageSummary, got {type(self.summary).__name__}")

        if not isinstance(self.stage_results, tuple):
            object.__setattr__(self, "stage_results", tuple(self.stage_results))
        for res in self.stage_results:
            if not isinstance(res, TriageStageResult):
                raise TypeError(f"stage_results elements must be TriageStageResult, got {type(res).__name__}")

        if self.artifacts is not None and not isinstance(self.artifacts, HostArtifactCollection):
            raise TypeError(f"artifacts must be HostArtifactCollection, got {type(self.artifacts).__name__}")
        if self.investigator is not None and not isinstance(self.investigator, HostArtifactInvestigator):
            raise TypeError(f"investigator must be HostArtifactInvestigator, got {type(self.investigator).__name__}")
        if self.report is not None and not isinstance(self.report, ForensicReport):
            raise TypeError(f"report must be ForensicReport, got {type(self.report).__name__}")
        if self.investigation_result is not None and not isinstance(self.investigation_result, InvestigationResultSet):
            raise TypeError(f"investigation_result must be InvestigationResultSet, got {type(self.investigation_result).__name__}")

        if not isinstance(self.report_files, tuple):
            object.__setattr__(self, "report_files", freeze_value(self.report_files))
        if not isinstance(self.audit_trail, tuple):
            object.__setattr__(self, "audit_trail", tuple(self.audit_trail))

        if not isinstance(self.trace_records, tuple):
            object.__setattr__(self, "trace_records", tuple(self.trace_records))
        for tr in self.trace_records:
            if not isinstance(tr, TriageTraceRecord):
                raise TypeError(f"trace_records elements must be TriageTraceRecord, got {type(tr).__name__}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert triage result to a fully JSON-serializable dictionary."""
        return {
            "triage_id": self.triage_id,
            "config": self.config.to_dict(),
            "summary": self.summary.to_dict(),
            "stage_results": [st.to_dict() for st in self.stage_results],
            "artifacts_summary": self.artifacts.summary if self.artifacts else None,
            "investigation_summary": self.investigation_result.summary if self.investigation_result else None,
            "report_summary": self.report.summary if self.report else None,
            "report_files": dict(self.report_files),
            "audit_trail": [ev.to_dict() for ev in self.audit_trail],
            "trace_records": [tr.to_dict() for tr in self.trace_records],
        }
