"""
Forensic Report Builder for ForensiX (V2.8).

Constructs immutable, deterministically sorted ForensicReport objects from
HostArtifactCollection, InvestigationResultSet, or sequences of HostArtifact instances.

Strict boundaries:
- In-memory only; zero filesystem I/O during model construction
- Zero command execution, subprocesses, or network access
- Zero mutation of source artifacts or source collections
- Exact preservation of artifact fields, IDs, and lineage
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from forensix.audit import AuditEvent, AuditEventType, create_audit_event
from forensix.investigation import InvestigationResultSet, artifact_sort_key
from forensix.report_models import (
    ForensicReport,
    ReportFormat,
    ReportMetadata,
    generate_report_id,
)
from forensix.unified_models import HostArtifact, HostArtifactCollection


def build_forensic_report(
    source: Union[HostArtifactCollection, InvestigationResultSet, Sequence[HostArtifact]],
    report_format: Union[ReportFormat, str] = ReportFormat.JSON,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    evidence_root: Optional[str] = None,
    forensix_version: str = "1.0.0",
    created_at: Optional[str] = None,
    audit_trail: Optional[Sequence[AuditEvent]] = None,
    record_generation_audit: bool = True,
    triage_id: Optional[str] = None,
    stage_results: Optional[Sequence[Any]] = None,
    trace_records: Optional[Sequence[Any]] = None,
    investigation_summary: Optional[Dict[str, Any]] = None,
) -> ForensicReport:
    """
    Construct a validated, deeply immutable ForensicReport from in-memory forensic objects.

    Does not modify source artifacts or input collections.
    """
    # 1. Extract artifacts and infer evidence_root if available
    extracted_artifacts: List[HostArtifact] = []
    inferred_root = evidence_root
    inferred_inv_summary = investigation_summary

    if isinstance(source, HostArtifactCollection):
        extracted_artifacts = list(source.artifacts)
        if inferred_root is None:
            inferred_root = source.evidence_root
    elif isinstance(source, InvestigationResultSet):
        extracted_artifacts = list(source.artifacts)
        if inferred_inv_summary is None:
            inferred_inv_summary = source.summary
    elif isinstance(source, (list, tuple)):
        for idx, item in enumerate(source):
            if not isinstance(item, HostArtifact):
                raise TypeError(
                    f"Item at index {idx} is {type(item).__name__}, expected HostArtifact"
                )
            extracted_artifacts.append(item)
    else:
        raise TypeError(
            f"source must be HostArtifactCollection, InvestigationResultSet, or Sequence[HostArtifact], "
            f"got {type(source).__name__}"
        )

    # 2. Deterministic sorting of artifacts
    sorted_artifacts = sorted(extracted_artifacts, key=artifact_sort_key)

    # 3. Categorization and status breakdown
    cat_counts = tuple(
        sorted(Counter(a.category for a in sorted_artifacts).items(), key=lambda x: x[0])
    )
    stat_counts = tuple(
        sorted(Counter(a.status for a in sorted_artifacts).items(), key=lambda x: x[0])
    )

    # 4. Timestamps and Report ID
    now_utc = created_at if created_at is not None else datetime.now(timezone.utc).isoformat()
    rep_id = generate_report_id()
    fmt_str = report_format.value if isinstance(report_format, ReportFormat) else str(report_format)

    # 5. Metadata
    metadata = ReportMetadata(
        report_id=rep_id,
        case_id=str(case_id) if case_id is not None else None,
        case_name=str(case_name) if case_name is not None else None,
        investigator=str(investigator) if investigator is not None else None,
        created_at=now_utc,
        forensix_version=str(forensix_version),
        evidence_root=str(inferred_root) if inferred_root is not None else None,
        report_format=fmt_str,
        triage_id=str(triage_id) if triage_id is not None else None,
    )

    # 6. Audit Trail assembly
    events: List[AuditEvent] = []
    if audit_trail:
        for idx, ev in enumerate(audit_trail):
            if not isinstance(ev, AuditEvent):
                raise TypeError(f"Audit event at index {idx} is {type(ev).__name__}, expected AuditEvent")
            events.append(ev)

    if record_generation_audit:
        gen_event = create_audit_event(
            event_type=AuditEventType.REPORT_GENERATED,
            description=f"Generated {fmt_str.upper()} forensic report with {len(sorted_artifacts)} artifacts.",
            actor=investigator,
            related_id=rep_id,
            timestamp=now_utc,
            metadata={
                "report_format": fmt_str,
                "total_artifacts": len(sorted_artifacts),
                "case_id": case_id,
            },
        )
        events.append(gen_event)

    # Sort audit events chronologically, then by audit_id
    sorted_audit = tuple(sorted(events, key=lambda ev: (ev.timestamp, ev.audit_id)))

    return ForensicReport(
        metadata=metadata,
        artifacts=tuple(sorted_artifacts),
        total_artifacts=len(sorted_artifacts),
        category_breakdown=cat_counts,
        status_breakdown=stat_counts,
        audit_trail=sorted_audit,
        stage_results=tuple(stage_results) if stage_results is not None else (),
        trace_records=tuple(trace_records) if trace_records is not None else (),
        investigation_summary=inferred_inv_summary,
    )
