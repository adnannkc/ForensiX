"""
Forensic Triage Orchestrator for ForensiX (V2.9.2).

Responsible for coordinating end-to-end incident triage execution across
ForensiX V2 capabilities (V2.1 filesystem, V2.2 logs, V2.3 auth, V2.4 accounts,
V2.5 persistence, V2.6 unified host model, V2.7 investigation, V2.8 reporting)
while maintaining:
- Strict stage ordering and dependency enforcement
- Graceful failure containment and partial result handling
- In-memory output propagation across stages
- Forensic read-only safety and zero evidence mutation
- Zero subprocess execution and zero network access
- Deterministic execution state and structured error reporting
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from forensix.account_analyzer import analyze_account_artifacts
from forensix.account_models import AccountCollectionResult
from forensix.artifacts import ArtifactCategory, ArtifactCollectionResult, ArtifactRecord
from forensix.audit import AuditEvent, AuditEventType, create_audit_event
from forensix.auth_analyzer import extract_authentication_activity
from forensix.auth_models import AuthenticationActivityResult, AuthenticationRecord
from forensix.investigation import HostArtifactInvestigator, InvestigationResultSet
from forensix.log_models import LogEvent, LogParseResult
from forensix.log_parser import parse_log_file
from forensix.persistence_analyzer import analyze_persistence_artifacts
from forensix.persistence_models import PersistenceCollectionResult, PersistenceRecord
from forensix.report_builder import build_forensic_report
from forensix.report_csv import write_csv_report
from forensix.report_html import write_html_report
from forensix.report_json import write_json_report
from forensix.report_models import ForensicReport
from forensix.scanner import scan_evidence_directory
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageSummary,
    TriageTraceRecord,
    generate_triage_id,
)
from forensix.unified_adapter import build_host_artifact_collection
from forensix.unified_models import HostArtifactCollection, SpecializedPayload

STAGE_NAMES: Dict[str, str] = {
    TriageStage.EVIDENCE_VALIDATION.value: "Evidence Validation",
    TriageStage.FILESYSTEM_COLLECTION.value: "Filesystem Artifact Collection",
    TriageStage.LOG_PARSING.value: "Linux Log Parsing",
    TriageStage.AUTHENTICATION_ANALYSIS.value: "Authentication Activity Analysis",
    TriageStage.ACCOUNT_ANALYSIS.value: "User Account & Privilege Analysis",
    TriageStage.PERSISTENCE_ANALYSIS.value: "Persistence Artifacts Analysis",
    TriageStage.UNIFIED_HOST_MODEL.value: "Unified Host Artifact Model",
    TriageStage.INVESTIGATION.value: "Investigation Query Interface",
    TriageStage.REPORTING.value: "Forensic Reporting",
}

STAGE_DEPENDENCIES: Dict[str, Tuple[str, ...]] = {
    TriageStage.EVIDENCE_VALIDATION.value: (),
    TriageStage.FILESYSTEM_COLLECTION.value: (TriageStage.EVIDENCE_VALIDATION.value,),
    TriageStage.LOG_PARSING.value: (TriageStage.EVIDENCE_VALIDATION.value,),
    TriageStage.AUTHENTICATION_ANALYSIS.value: (TriageStage.LOG_PARSING.value,),
    TriageStage.ACCOUNT_ANALYSIS.value: (TriageStage.EVIDENCE_VALIDATION.value,),
    TriageStage.PERSISTENCE_ANALYSIS.value: (TriageStage.EVIDENCE_VALIDATION.value,),
    TriageStage.UNIFIED_HOST_MODEL.value: (),  # Evaluated dynamically based on available specialized outputs
    TriageStage.INVESTIGATION.value: (TriageStage.UNIFIED_HOST_MODEL.value,),
    TriageStage.REPORTING.value: (TriageStage.UNIFIED_HOST_MODEL.value,),
}

SPECIALIZED_ANALYSIS_STAGES: Tuple[str, ...] = (
    TriageStage.FILESYSTEM_COLLECTION.value,
    TriageStage.LOG_PARSING.value,
    TriageStage.AUTHENTICATION_ANALYSIS.value,
    TriageStage.ACCOUNT_ANALYSIS.value,
    TriageStage.PERSISTENCE_ANALYSIS.value,
)

EVENT_LIFECYCLE_ORDER: Dict[str, int] = {
    AuditEventType.TRIAGE_STARTED.value: 10,
    AuditEventType.CASE_CREATED.value: 15,
    AuditEventType.EVIDENCE_REGISTERED.value: 20,
    AuditEventType.STAGE_STARTED.value: 30,
    AuditEventType.HASH_CALCULATED.value: 40,
    AuditEventType.ARTIFACT_COLLECTION_STARTED.value: 45,
    AuditEventType.ARTIFACT_COLLECTION_COMPLETED.value: 50,
    AuditEventType.STAGE_COMPLETED.value: 60,
    AuditEventType.STAGE_PARTIAL.value: 60,
    AuditEventType.STAGE_FAILED.value: 60,
    AuditEventType.STAGE_SKIPPED.value: 60,
    AuditEventType.INVESTIGATION_EXECUTED.value: 70,
    AuditEventType.REPORT_GENERATED.value: 80,
    AuditEventType.TRIAGE_COMPLETED.value: 90,
}


def sort_audit_events(events: Sequence[AuditEvent]) -> Tuple[AuditEvent, ...]:
    """
    Sort audit events chronologically with deterministic lifecycle tie-breaking.

    Preserves logical event order when timestamps tie:
    TRIAGE_STARTED -> EVIDENCE_REGISTERED -> STAGE_STARTED -> ... -> STAGE_COMPLETED -> TRIAGE_COMPLETED
    """
    indexed = list(enumerate(events))
    sorted_pairs = sorted(
        indexed,
        key=lambda pair: (
            pair[1].timestamp,
            EVENT_LIFECYCLE_ORDER.get(pair[1].event_type, 50),
            pair[0],
            pair[1].audit_id,
        ),
    )
    return tuple(pair[1] for pair in sorted_pairs)


@dataclass
class StageExecutionContext:
    """Internal mutable container holding intermediate stage outputs during an orchestration run."""

    config: TriageConfig
    triage_id: Optional[str] = None
    evidence_path: Optional[Path] = None
    filesystem_result: Optional[ArtifactCollectionResult] = None
    log_events: List[LogEvent] = field(default_factory=list)
    log_results: List[LogParseResult] = field(default_factory=list)
    auth_result: Optional[AuthenticationActivityResult] = None
    account_result: Optional[AccountCollectionResult] = None
    persistence_result: Optional[PersistenceCollectionResult] = None
    host_collection: Optional[HostArtifactCollection] = None
    investigator: Optional[HostArtifactInvestigator] = None
    investigation_result: Optional[InvestigationResultSet] = None
    report: Optional[ForensicReport] = None
    report_files: List[Tuple[str, str]] = field(default_factory=list)
    audit_trail: List[AuditEvent] = field(default_factory=list)
    trace_records: List[TriageTraceRecord] = field(default_factory=list)
    stage_results: Dict[str, TriageStageResult] = field(default_factory=dict)


class TriageOrchestrator:
    """
    Core orchestration engine executing registered ForensiX triage pipeline stages.
    """

    def __init__(
        self,
        config: Optional[TriageConfig] = None,
        custom_handlers: Optional[Dict[str, Callable[[StageExecutionContext], TriageStageResult]]] = None,
        **config_kwargs: Any,
    ) -> None:
        """Initialize the triage orchestrator with configuration and stage handlers."""
        if config is None:
            self.config = TriageConfig(**config_kwargs)
        elif isinstance(config, TriageConfig):
            if config_kwargs:
                raise ValueError("Cannot pass both a TriageConfig instance and config keyword arguments")
            self.config = config
        else:
            raise TypeError(f"config must be TriageConfig, got {type(config).__name__}")

        # Register default stage handlers
        self._handlers: Dict[str, Callable[[StageExecutionContext], TriageStageResult]] = {
            TriageStage.EVIDENCE_VALIDATION.value: self._execute_evidence_validation,
            TriageStage.FILESYSTEM_COLLECTION.value: self._execute_filesystem_collection,
            TriageStage.LOG_PARSING.value: self._execute_log_parsing,
            TriageStage.AUTHENTICATION_ANALYSIS.value: self._execute_authentication_analysis,
            TriageStage.ACCOUNT_ANALYSIS.value: self._execute_account_analysis,
            TriageStage.PERSISTENCE_ANALYSIS.value: self._execute_persistence_analysis,
            TriageStage.UNIFIED_HOST_MODEL.value: self._execute_unified_host_model,
            TriageStage.INVESTIGATION.value: self._execute_investigation,
            TriageStage.REPORTING.value: self._execute_reporting,
        }

        # Override with custom handlers if provided (useful for testing/simulation)
        if custom_handlers:
            for stage_id, handler in custom_handlers.items():
                if stage_id not in ALL_TRIAGE_STAGES:
                    raise ValueError(f"Unknown stage identifier for custom handler: {stage_id}")
                self._handlers[stage_id] = handler

    def register_stage_handler(
        self,
        stage_id: Union[str, TriageStage],
        handler: Callable[[StageExecutionContext], TriageStageResult],
    ) -> None:
        """Register or override a handler for a specific triage stage."""
        key = stage_id.value if isinstance(stage_id, TriageStage) else stage_id
        if key not in ALL_TRIAGE_STAGES:
            raise ValueError(f"Unknown stage identifier: {key}")
        if not callable(handler):
            raise TypeError(f"Handler must be callable, got {type(handler).__name__}")
        self._handlers[key] = handler

    def run(self) -> TriageResult:
        """
        Execute the configured triage pipeline in strict dependency order with audit & trace provenance.

        Returns:
            TriageResult: Complete immutable execution container.
        """
        triage_id = generate_triage_id()
        pipeline_started_at = datetime.now(timezone.utc).isoformat()
        start_mono = time.perf_counter()

        ctx = StageExecutionContext(config=self.config, triage_id=triage_id)

        # 1. Emit TRIAGE_STARTED audit event
        if self.config.collect_audit:
            ctx.audit_trail.append(
                create_audit_event(
                    event_type=AuditEventType.TRIAGE_STARTED.value,
                    description=f"Triage execution started for case {self.config.case_id or 'unspecified'}",
                    actor=self.config.investigator,
                    related_id=triage_id,
                    timestamp=pipeline_started_at,
                    metadata={
                        "triage_id": triage_id,
                        "case_id": self.config.case_id,
                        "case_name": self.config.case_name,
                        "investigator": self.config.investigator,
                        "started_at": pipeline_started_at,
                    },
                )
            )

        for stage_id in ALL_TRIAGE_STAGES:
            stage_name = STAGE_NAMES.get(stage_id, stage_id)

            # 2. Check if stage is enabled
            if stage_id not in self.config.enabled_stages:
                skip_res = TriageStageResult(
                    stage_id=stage_id,
                    stage_name=stage_name,
                    status=TriageStageStatus.SKIPPED,
                    warnings=("Stage disabled by configuration",),
                )
                ctx.stage_results[stage_id] = skip_res
                if self.config.collect_audit:
                    ctx.audit_trail.append(
                        create_audit_event(
                            event_type=AuditEventType.STAGE_SKIPPED.value,
                            description=f"Stage {stage_id} skipped: Stage disabled by configuration",
                            actor=self.config.investigator,
                            related_id=triage_id,
                            metadata={
                                "triage_id": triage_id,
                                "stage_id": stage_id,
                                "reason": "Stage disabled by configuration",
                            },
                        )
                    )
                ctx.trace_records.append(
                    self._build_stage_trace(triage_id, stage_id, skip_res, ctx)
                )
                continue

            # 3. Check dependencies
            dep_failure = self._check_dependencies(stage_id, ctx)
            if dep_failure:
                skip_res = TriageStageResult(
                    stage_id=stage_id,
                    stage_name=stage_name,
                    status=TriageStageStatus.SKIPPED,
                    warnings=(dep_failure,),
                )
                ctx.stage_results[stage_id] = skip_res
                if self.config.collect_audit:
                    ctx.audit_trail.append(
                        create_audit_event(
                            event_type=AuditEventType.STAGE_SKIPPED.value,
                            description=f"Stage {stage_id} skipped: {dep_failure}",
                            actor=self.config.investigator,
                            related_id=triage_id,
                            metadata={
                                "triage_id": triage_id,
                                "stage_id": stage_id,
                                "reason": dep_failure,
                            },
                        )
                    )
                ctx.trace_records.append(
                    self._build_stage_trace(triage_id, stage_id, skip_res, ctx)
                )
                continue

            # 4. Execute stage handler with failure containment
            stage_started_at = datetime.now(timezone.utc).isoformat()
            stage_mono_start = time.perf_counter()

            if self.config.collect_audit:
                ctx.audit_trail.append(
                    create_audit_event(
                        event_type=AuditEventType.STAGE_STARTED.value,
                        description=f"Stage {stage_id} execution started",
                        actor=self.config.investigator,
                        related_id=triage_id,
                        timestamp=stage_started_at,
                        metadata={
                            "triage_id": triage_id,
                            "stage_id": stage_id,
                            "status": TriageStageStatus.RUNNING.value,
                        },
                    )
                )

            try:
                handler = self._handlers[stage_id]
                stage_res = handler(ctx)
                if not isinstance(stage_res, TriageStageResult):
                    raise TypeError(
                        f"Stage handler for '{stage_id}' returned {type(stage_res).__name__}, expected TriageStageResult"
                    )

                # Ensure timestamps and durations are populated if omitted by handler
                if stage_res.started_at is None:
                    duration = round(time.perf_counter() - stage_mono_start, 4)
                    completed_at = datetime.now(timezone.utc).isoformat()
                    stage_res = TriageStageResult(
                        stage_id=stage_res.stage_id,
                        stage_name=stage_res.stage_name,
                        status=stage_res.status,
                        started_at=stage_started_at,
                        completed_at=completed_at,
                        duration_seconds=duration,
                        records_produced=stage_res.records_produced,
                        errors=stage_res.errors,
                        warnings=stage_res.warnings,
                        metadata=stage_res.metadata,
                    )

                ctx.stage_results[stage_id] = stage_res

                if self.config.collect_audit:
                    if stage_res.status == TriageStageStatus.PARTIAL.value:
                        warn_desc = "; ".join(stage_res.warnings) if stage_res.warnings else "Non-fatal warnings encountered"
                        ctx.audit_trail.append(
                            create_audit_event(
                                event_type=AuditEventType.STAGE_PARTIAL.value,
                                description=f"Stage {stage_id} completed with partial results: {warn_desc}",
                                actor=self.config.investigator,
                                related_id=triage_id,
                                timestamp=stage_res.completed_at,
                                metadata={
                                    "triage_id": triage_id,
                                    "stage_id": stage_id,
                                    "status": "PARTIAL",
                                    "records_produced": stage_res.records_produced,
                                    "warnings": list(stage_res.warnings),
                                    "duration_seconds": stage_res.duration_seconds,
                                },
                            )
                        )
                    elif stage_res.status == TriageStageStatus.FAILED.value:
                        err_msg = stage_res.errors[0].error_message if stage_res.errors else "Stage execution failed"
                        ctx.audit_trail.append(
                            create_audit_event(
                                event_type=AuditEventType.STAGE_FAILED.value,
                                description=f"Stage {stage_id} failed: {err_msg}",
                                actor=self.config.investigator,
                                related_id=triage_id,
                                timestamp=stage_res.completed_at,
                                metadata={
                                    "triage_id": triage_id,
                                    "stage_id": stage_id,
                                    "status": "FAILED",
                                    "error_type": stage_res.errors[0].error_type if stage_res.errors else "StageError",
                                    "error_message": err_msg,
                                    "duration_seconds": stage_res.duration_seconds,
                                },
                            )
                        )
                    else:
                        ctx.audit_trail.append(
                            create_audit_event(
                                event_type=AuditEventType.STAGE_COMPLETED.value,
                                description=f"Stage {stage_id} completed with {stage_res.records_produced} records",
                                actor=self.config.investigator,
                                related_id=triage_id,
                                timestamp=stage_res.completed_at,
                                metadata={
                                    "triage_id": triage_id,
                                    "stage_id": stage_id,
                                    "status": "COMPLETED",
                                    "records_produced": stage_res.records_produced,
                                    "duration_seconds": stage_res.duration_seconds,
                                },
                            )
                        )

            except Exception as exc:
                duration = round(time.perf_counter() - stage_mono_start, 4)
                completed_at = datetime.now(timezone.utc).isoformat()
                err = TriageStageError(
                    stage_id=stage_id,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    details=(("exception_class", type(exc).__name__),),
                )
                failed_res = TriageStageResult(
                    stage_id=stage_id,
                    stage_name=stage_name,
                    status=TriageStageStatus.FAILED,
                    started_at=stage_started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    records_produced=0,
                    errors=(err,),
                )
                ctx.stage_results[stage_id] = failed_res

                if self.config.collect_audit:
                    ctx.audit_trail.append(
                        create_audit_event(
                            event_type=AuditEventType.STAGE_FAILED.value,
                            description=f"Stage {stage_id} failed: {type(exc).__name__}: {str(exc)}",
                            actor=self.config.investigator,
                            related_id=triage_id,
                            timestamp=completed_at,
                            metadata={
                                "triage_id": triage_id,
                                "stage_id": stage_id,
                                "status": "FAILED",
                                "error_type": type(exc).__name__,
                                "error_message": str(exc),
                            },
                        )
                    )

            # Record factual stage trace
            ctx.trace_records.append(
                self._build_stage_trace(triage_id, stage_id, ctx.stage_results[stage_id], ctx)
            )

        pipeline_completed_at = datetime.now(timezone.utc).isoformat()
        total_duration = round(time.perf_counter() - start_mono, 4)

        # Build summary metrics
        stages_completed = sum(
            1 for r in ctx.stage_results.values() if r.status == TriageStageStatus.COMPLETED.value
        )
        stages_partial = sum(
            1 for r in ctx.stage_results.values() if r.status == TriageStageStatus.PARTIAL.value
        )
        stages_failed = sum(
            1 for r in ctx.stage_results.values() if r.status == TriageStageStatus.FAILED.value
        )
        stages_skipped = sum(
            1 for r in ctx.stage_results.values() if r.status == TriageStageStatus.SKIPPED.value
        )
        total_artifacts = ctx.host_collection.total_artifacts if ctx.host_collection else 0
        is_success = (stages_failed == 0)

        # Emit TRIAGE_COMPLETED audit event
        if self.config.collect_audit:
            ctx.audit_trail.append(
                create_audit_event(
                    event_type=AuditEventType.TRIAGE_COMPLETED.value,
                    description=f"Triage execution completed: {stages_completed} completed, {stages_partial} partial, {stages_failed} failed, {stages_skipped} skipped",
                    actor=self.config.investigator,
                    related_id=triage_id,
                    timestamp=pipeline_completed_at,
                    metadata={
                        "triage_id": triage_id,
                        "completed_at": pipeline_completed_at,
                        "total_duration_seconds": total_duration,
                        "stages_completed": stages_completed,
                        "stages_partial": stages_partial,
                        "stages_failed": stages_failed,
                        "stages_skipped": stages_skipped,
                        "is_success": is_success,
                    },
                )
            )

        summary = TriageSummary(
            case_id=self.config.case_id,
            case_name=self.config.case_name,
            investigator=self.config.investigator,
            evidence_root=str(ctx.evidence_path or self.config.evidence_path),
            started_at=pipeline_started_at,
            completed_at=pipeline_completed_at,
            total_duration_seconds=total_duration,
            total_artifacts=total_artifacts,
            stages_completed=stages_completed,
            stages_partial=stages_partial,
            stages_failed=stages_failed,
            stages_skipped=stages_skipped,
            is_success=is_success,
        )

        ordered_results = tuple(ctx.stage_results[s] for s in ALL_TRIAGE_STAGES)
        sorted_audit_trail = sort_audit_events(ctx.audit_trail)

        return TriageResult(
            triage_id=triage_id,
            config=self.config,
            summary=summary,
            stage_results=ordered_results,
            artifacts=ctx.host_collection,
            investigator=ctx.investigator,
            report=ctx.report,
            report_files=tuple(ctx.report_files),
            audit_trail=sorted_audit_trail,
            investigation_result=ctx.investigation_result,
            trace_records=tuple(ctx.trace_records),
        )

    def _build_stage_trace(
        self,
        triage_id: str,
        stage_id: str,
        stage_res: TriageStageResult,
        ctx: StageExecutionContext,
    ) -> TriageTraceRecord:
        """
        Construct a factual provenance trace record preserving source lineage and component relationships.
        """
        ts = stage_res.completed_at or stage_res.started_at or datetime.now(timezone.utc).isoformat()

        if stage_res.status == TriageStageStatus.SKIPPED.value:
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=(),
                output_identifiers=(),
                source_artifact_ids=(),
                source_event_ids=(),
                source_paths=(),
                unified_artifact_ids=(),
                timestamp=ts,
            )

        if stage_res.status == TriageStageStatus.FAILED.value:
            input_ids: Tuple[str, ...] = (str(ctx.evidence_path or ctx.config.evidence_path),)
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=(),
                source_artifact_ids=(),
                source_event_ids=(),
                source_paths=(),
                unified_artifact_ids=(),
                timestamp=ts,
            )

        if stage_id == TriageStage.EVIDENCE_VALIDATION.value:
            ev_path = str(ctx.evidence_path or ctx.config.evidence_path)
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=(str(ctx.config.evidence_path),),
                output_identifiers=(ev_path,),
                source_artifact_ids=(),
                source_event_ids=(),
                source_paths=(ev_path,),
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.FILESYSTEM_COLLECTION.value:
            input_ids = (str(ctx.evidence_path or ctx.config.evidence_path),)
            if ctx.filesystem_result:
                out_ids = tuple(art.artifact_id for art in ctx.filesystem_result.artifacts)
                src_paths = tuple(sorted(set(art.source_path for art in ctx.filesystem_result.artifacts if art.source_path)))
            else:
                out_ids = ()
                src_paths = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=out_ids,
                source_event_ids=(),
                source_paths=src_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.LOG_PARSING.value:
            if ctx.log_results:
                input_ids = tuple(sorted(set(str(res.source_path) for res in ctx.log_results)))
            else:
                input_ids = (str(ctx.evidence_path or ctx.config.evidence_path),)
            out_ids = tuple(evt.event_id for evt in ctx.log_events)
            src_art_ids = tuple(sorted(set(evt.source_artifact_id for evt in ctx.log_events if evt.source_artifact_id)))
            src_paths = tuple(sorted(set(evt.source_path for evt in ctx.log_events if evt.source_path)))
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=out_ids,
                source_paths=src_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.AUTHENTICATION_ANALYSIS.value:
            input_ids = tuple(evt.event_id for evt in ctx.log_events)
            if ctx.auth_result:
                out_ids = tuple(rec.auth_id for rec in ctx.auth_result.records)
                src_art_ids = tuple(sorted(set(rec.source_artifact_id for rec in ctx.auth_result.records if rec.source_artifact_id)))
                src_evt_ids = tuple(sorted(set(rec.event_id for rec in ctx.auth_result.records if rec.event_id)))
                src_paths = tuple(sorted(set(rec.source_path for rec in ctx.auth_result.records if rec.source_path)))
            else:
                out_ids = ()
                src_art_ids = ()
                src_evt_ids = ()
                src_paths = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=src_evt_ids,
                source_paths=src_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.ACCOUNT_ANALYSIS.value:
            input_ids = (str(ctx.evidence_path or ctx.config.evidence_path),)
            if ctx.account_result:
                all_account_items = (
                    list(ctx.account_result.users)
                    + list(ctx.account_result.groups)
                    + list(ctx.account_result.shadow_records)
                    + list(ctx.account_result.sudo_rules)
                    + list(ctx.account_result.ssh_keys)
                )
                out_ids = tuple(
                    getattr(item, "user_id", None)
                    or getattr(item, "group_id", None)
                    or getattr(item, "shadow_id", None)
                    or getattr(item, "rule_id", None)
                    or getattr(item, "key_id", None)
                    or ""
                    for item in all_account_items
                )
                src_art_ids = tuple(
                    sorted(set(getattr(item, "source_artifact_id", "") for item in all_account_items if getattr(item, "source_artifact_id", None)))
                )
                src_paths = tuple(
                    sorted(set(getattr(item, "source_path", "") for item in all_account_items if getattr(item, "source_path", None)))
                )
            else:
                out_ids = ()
                src_art_ids = ()
                src_paths = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=(),
                source_paths=src_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.PERSISTENCE_ANALYSIS.value:
            input_ids = (str(ctx.evidence_path or ctx.config.evidence_path),)
            if ctx.persistence_result:
                out_ids = tuple(r.persistence_id for r in ctx.persistence_result.records)
                src_art_ids = tuple(sorted(set(r.source_artifact_id for r in ctx.persistence_result.records if r.source_artifact_id)))
                src_paths = tuple(sorted(set(r.source_path for r in ctx.persistence_result.records if r.source_path)))
            else:
                out_ids = ()
                src_art_ids = ()
                src_paths = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=(),
                source_paths=src_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        elif stage_id == TriageStage.UNIFIED_HOST_MODEL.value:
            if ctx.host_collection:
                out_ids = tuple(art.unified_id for art in ctx.host_collection.artifacts)
                src_art_ids = tuple(sorted(set(art.source_artifact_id for art in ctx.host_collection.artifacts if art.source_artifact_id)))
                src_evt_ids = tuple(sorted(set(art.source_event_id for art in ctx.host_collection.artifacts if art.source_event_id)))
                src_paths = tuple(sorted(set(art.source_path for art in ctx.host_collection.artifacts if art.source_path)))
                input_ids = tuple(art.source_id for art in ctx.host_collection.artifacts)
            else:
                out_ids = ()
                src_art_ids = ()
                src_evt_ids = ()
                src_paths = ()
                input_ids = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=src_evt_ids,
                source_paths=src_paths,
                unified_artifact_ids=out_ids,
                timestamp=ts,
            )

        elif stage_id == TriageStage.INVESTIGATION.value:
            if ctx.host_collection:
                input_ids = tuple(art.unified_id for art in ctx.host_collection.artifacts)
            else:
                input_ids = ()
            if ctx.investigation_result:
                out_ids = tuple(art.unified_id for art in ctx.investigation_result.artifacts)
                src_art_ids = tuple(sorted(set(art.source_artifact_id for art in ctx.investigation_result.artifacts if art.source_artifact_id)))
                src_evt_ids = tuple(sorted(set(art.source_event_id for art in ctx.investigation_result.artifacts if art.source_event_id)))
                src_paths = tuple(sorted(set(art.source_path for art in ctx.investigation_result.artifacts if art.source_path)))
            else:
                out_ids = ()
                src_art_ids = ()
                src_evt_ids = ()
                src_paths = ()
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=src_art_ids,
                source_event_ids=src_evt_ids,
                source_paths=src_paths,
                unified_artifact_ids=out_ids,
                timestamp=ts,
            )

        elif stage_id == TriageStage.REPORTING.value:
            if ctx.investigation_result:
                input_ids = tuple(art.unified_id for art in ctx.investigation_result.artifacts)
            elif ctx.host_collection:
                input_ids = tuple(art.unified_id for art in ctx.host_collection.artifacts)
            else:
                input_ids = ()
            report_id = (ctx.report.metadata.report_id,) if ctx.report else ()
            file_paths = tuple(p for _, p in ctx.report_files)
            out_ids = report_id + file_paths
            return TriageTraceRecord(
                triage_id=triage_id,
                stage_id=stage_id,
                stage_status=stage_res.status,
                input_identifiers=input_ids,
                output_identifiers=out_ids,
                source_artifact_ids=(),
                source_event_ids=(),
                source_paths=file_paths,
                unified_artifact_ids=(),
                timestamp=ts,
            )

        return TriageTraceRecord(
            triage_id=triage_id,
            stage_id=stage_id,
            stage_status=stage_res.status,
            input_identifiers=(),
            output_identifiers=(),
            source_artifact_ids=(),
            source_event_ids=(),
            source_paths=(),
            unified_artifact_ids=(),
            timestamp=ts,
        )

    def _check_dependencies(self, stage_id: str, ctx: StageExecutionContext) -> Optional[str]:
        """
        Evaluate stage prerequisites. Returns a failure explanation if unfulfilled, or None if ready.
        """
        # 1. Unified Host Model dependency rule:
        # Requires at least one specialized stage to have completed or produced partial results.
        if stage_id == TriageStage.UNIFIED_HOST_MODEL.value:
            any_specialized_success = any(
                ctx.stage_results.get(st) is not None
                and ctx.stage_results[st].status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value)
                for st in SPECIALIZED_ANALYSIS_STAGES
            )
            if not any_specialized_success:
                return "Skipped because no specialized analysis stages completed successfully"
            return None

        # 2. Standard explicit predecessors
        required_deps = STAGE_DEPENDENCIES.get(stage_id, ())
        for dep in required_deps:
            dep_res = ctx.stage_results.get(dep)
            if dep_res is None:
                return f"Skipped because required predecessor '{dep}' has not executed"
            if dep_res.status not in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                return f"Skipped because required predecessor '{dep}' did not complete successfully (status: {dep_res.status})"

        return None

    # -------------------------------------------------------------------------
    # Default Stage Handlers
    # -------------------------------------------------------------------------

    def _execute_evidence_validation(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 1: Evidence Validation."""
        target = Path(ctx.config.evidence_path)
        if not target.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {target}")
        if not target.is_dir():
            raise NotADirectoryError(f"Evidence path is not a directory: {target}")

        ctx.evidence_path = target.resolve()

        if ctx.config.collect_audit:
            ctx.audit_trail.append(
                create_audit_event(
                    event_type=AuditEventType.EVIDENCE_REGISTERED,
                    description=f"Evidence root validated at {ctx.evidence_path}",
                    related_id=ctx.triage_id,
                )
            )

        return TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name=STAGE_NAMES[TriageStage.EVIDENCE_VALIDATION.value],
            status=TriageStageStatus.COMPLETED,
            records_produced=1,
            metadata=(("evidence_root", str(ctx.evidence_path)),),
        )

    def _execute_filesystem_collection(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 2: Filesystem Artifact Collection."""
        assert ctx.evidence_path is not None
        collection_result = scan_evidence_directory(
            evidence_dir=ctx.evidence_path,
            evidence_id=ctx.config.case_id,
        )
        ctx.filesystem_result = collection_result

        status = (
            TriageStageStatus.PARTIAL
            if collection_result.unreadable_artifacts > 0
            else TriageStageStatus.COMPLETED
        )

        warnings: Tuple[str, ...] = ()
        if collection_result.unreadable_artifacts > 0:
            warnings = (f"{collection_result.unreadable_artifacts} unreadable artifacts detected during filesystem scan",)

        return TriageStageResult(
            stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
            stage_name=STAGE_NAMES[TriageStage.FILESYSTEM_COLLECTION.value],
            status=status,
            records_produced=collection_result.total_artifacts,
            warnings=warnings,
            metadata=(
                ("total_artifacts", collection_result.total_artifacts),
                ("known_artifacts", collection_result.known_artifacts),
                ("generic_artifacts", collection_result.generic_artifacts),
                ("unreadable_artifacts", collection_result.unreadable_artifacts),
            ),
        )

    def _execute_log_parsing(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 3: Linux Log Parsing."""
        assert ctx.evidence_path is not None
        discovered_log_paths: List[Path] = []

        art_id_by_path: Dict[str, str] = {}
        # Strategy A: Use filesystem collection artifacts if available
        if ctx.filesystem_result is not None:
            for art in ctx.filesystem_result.artifacts:
                if art.category == ArtifactCategory.LOG.value or art.category == "log":
                    p = Path(art.source_path)
                    if p.exists() and p.is_file():
                        discovered_log_paths.append(p)
                        art_id_by_path[str(p.resolve())] = art.artifact_id
                        art_id_by_path[str(p)] = art.artifact_id

        # Strategy B: Fallback / directory inspection under var/log
        if not discovered_log_paths:
            log_dir = ctx.evidence_path / "var" / "log"
            if log_dir.exists() and log_dir.is_dir():
                for item in sorted(log_dir.iterdir()):
                    if item.is_file() and not item.name.startswith("."):
                        name_lower = item.name.lower()
                        if any(k in name_lower for k in ("auth", "secure", "syslog", "messages")):
                            discovered_log_paths.append(item)

        had_parser_errors = False
        parsed_events: List[LogEvent] = []

        for log_path in discovered_log_paths:
            art_id = art_id_by_path.get(str(log_path.resolve())) or art_id_by_path.get(str(log_path))
            parse_res = parse_log_file(log_path, artifact_id=art_id)
            ctx.log_results.append(parse_res)
            parsed_events.extend(parse_res.events)
            if parse_res.error_lines > 0:
                had_parser_errors = True

        ctx.log_events = parsed_events

        warnings: Tuple[str, ...] = ()
        if not discovered_log_paths:
            warnings = ("No log files discovered in evidence directory",)

        status = TriageStageStatus.PARTIAL if had_parser_errors else TriageStageStatus.COMPLETED

        return TriageStageResult(
            stage_id=TriageStage.LOG_PARSING.value,
            stage_name=STAGE_NAMES[TriageStage.LOG_PARSING.value],
            status=status,
            records_produced=len(parsed_events),
            warnings=warnings,
            metadata=(("log_files_count", len(discovered_log_paths)),),
        )

    def _execute_authentication_analysis(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 4: Authentication Activity Analysis."""
        auth_result = extract_authentication_activity(ctx.log_events)
        ctx.auth_result = auth_result

        return TriageStageResult(
            stage_id=TriageStage.AUTHENTICATION_ANALYSIS.value,
            stage_name=STAGE_NAMES[TriageStage.AUTHENTICATION_ANALYSIS.value],
            status=TriageStageStatus.COMPLETED,
            records_produced=auth_result.total_records,
            metadata=(
                ("success_count", auth_result.success_count),
                ("failure_count", auth_result.failure_count),
                ("unknown_count", auth_result.unknown_count),
            ),
        )

    def _execute_account_analysis(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 5: User Account & Privilege Analysis."""
        assert ctx.evidence_path is not None
        account_res = analyze_account_artifacts(ctx.evidence_path)
        ctx.account_result = account_res

        total_records = (
            account_res.total_users
            + account_res.total_groups
            + account_res.total_shadow_records
            + account_res.total_sudo_rules
            + account_res.total_ssh_keys
        )

        return TriageStageResult(
            stage_id=TriageStage.ACCOUNT_ANALYSIS.value,
            stage_name=STAGE_NAMES[TriageStage.ACCOUNT_ANALYSIS.value],
            status=TriageStageStatus.COMPLETED,
            records_produced=total_records,
            metadata=(
                ("users_count", account_res.total_users),
                ("groups_count", account_res.total_groups),
                ("shadow_count", account_res.total_shadow_records),
                ("sudo_rules_count", account_res.total_sudo_rules),
                ("ssh_keys_count", account_res.total_ssh_keys),
            ),
        )

    def _execute_persistence_analysis(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 6: Persistence Artifacts Analysis."""
        assert ctx.evidence_path is not None
        persistence_res = analyze_persistence_artifacts(ctx.evidence_path)
        ctx.persistence_result = persistence_res

        return TriageStageResult(
            stage_id=TriageStage.PERSISTENCE_ANALYSIS.value,
            stage_name=STAGE_NAMES[TriageStage.PERSISTENCE_ANALYSIS.value],
            status=TriageStageStatus.COMPLETED,
            records_produced=persistence_res.total_records,
            metadata=(("persistence_records_count", persistence_res.total_records),),
        )

    def _execute_unified_host_model(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 7: Unified Host Artifact Model Construction."""
        assert ctx.evidence_path is not None
        all_records: List[SpecializedPayload] = []
        missing_or_failed_stages: List[str] = []

        # Gather filesystem records
        if TriageStage.FILESYSTEM_COLLECTION.value in ctx.config.enabled_stages:
            st = ctx.stage_results.get(TriageStage.FILESYSTEM_COLLECTION.value)
            if st is not None and st.status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                if ctx.filesystem_result:
                    all_records.extend(ctx.filesystem_result.artifacts)
            else:
                missing_or_failed_stages.append(TriageStage.FILESYSTEM_COLLECTION.value)

        # Gather log events
        if TriageStage.LOG_PARSING.value in ctx.config.enabled_stages:
            st = ctx.stage_results.get(TriageStage.LOG_PARSING.value)
            if st is not None and st.status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                all_records.extend(ctx.log_events)
            else:
                missing_or_failed_stages.append(TriageStage.LOG_PARSING.value)

        # Gather authentication records
        if TriageStage.AUTHENTICATION_ANALYSIS.value in ctx.config.enabled_stages:
            st = ctx.stage_results.get(TriageStage.AUTHENTICATION_ANALYSIS.value)
            if st is not None and st.status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                if ctx.auth_result:
                    all_records.extend(ctx.auth_result.records)
            else:
                missing_or_failed_stages.append(TriageStage.AUTHENTICATION_ANALYSIS.value)

        # Gather account records
        if TriageStage.ACCOUNT_ANALYSIS.value in ctx.config.enabled_stages:
            st = ctx.stage_results.get(TriageStage.ACCOUNT_ANALYSIS.value)
            if st is not None and st.status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                if ctx.account_result:
                    all_records.extend(ctx.account_result.users)
                    all_records.extend(ctx.account_result.groups)
                    all_records.extend(ctx.account_result.shadow_records)
                    all_records.extend(ctx.account_result.sudo_rules)
                    all_records.extend(ctx.account_result.ssh_keys)
            else:
                missing_or_failed_stages.append(TriageStage.ACCOUNT_ANALYSIS.value)

        # Gather persistence records
        if TriageStage.PERSISTENCE_ANALYSIS.value in ctx.config.enabled_stages:
            st = ctx.stage_results.get(TriageStage.PERSISTENCE_ANALYSIS.value)
            if st is not None and st.status in (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value):
                if ctx.persistence_result:
                    all_records.extend(ctx.persistence_result.records)
            else:
                missing_or_failed_stages.append(TriageStage.PERSISTENCE_ANALYSIS.value)

        collection = build_host_artifact_collection(
            evidence_root=str(ctx.evidence_path),
            records=all_records,
        )
        ctx.host_collection = collection

        warnings: Tuple[str, ...] = ()
        if missing_or_failed_stages:
            warnings = (
                f"Unified host model built with partial inputs; specialized stages {missing_or_failed_stages} did not complete successfully",
            )
            status = TriageStageStatus.PARTIAL
        else:
            status = TriageStageStatus.COMPLETED

        return TriageStageResult(
            stage_id=TriageStage.UNIFIED_HOST_MODEL.value,
            stage_name=STAGE_NAMES[TriageStage.UNIFIED_HOST_MODEL.value],
            status=status,
            records_produced=collection.total_artifacts,
            warnings=warnings,
            metadata=(("total_unified_artifacts", collection.total_artifacts),),
        )

    def _execute_investigation(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 8: Investigation Query Interface."""
        if ctx.host_collection is None:
            raise RuntimeError("HostArtifactCollection unavailable for investigation")

        investigator = HostArtifactInvestigator(ctx.host_collection)
        ctx.investigator = investigator

        # Baseline investigation query: all artifacts indexed with full summary breakdown
        investigation_result = investigator.query()
        ctx.investigation_result = investigation_result

        return TriageStageResult(
            stage_id=TriageStage.INVESTIGATION.value,
            stage_name=STAGE_NAMES[TriageStage.INVESTIGATION.value],
            status=TriageStageStatus.COMPLETED,
            records_produced=investigation_result.total_matches,
            metadata=(
                ("total_matches", investigation_result.total_matches),
                ("category_breakdown_count", len(investigation_result.category_breakdown)),
            ),
        )

    def _execute_reporting(self, ctx: StageExecutionContext) -> TriageStageResult:
        """Stage 9: Forensic Reporting."""
        if ctx.config.skip_reports:
            return TriageStageResult(
                stage_id=TriageStage.REPORTING.value,
                stage_name=STAGE_NAMES[TriageStage.REPORTING.value],
                status=TriageStageStatus.SKIPPED,
                warnings=("Reporting skipped by configuration",),
            )

        source = ctx.investigation_result if ctx.investigation_result else ctx.host_collection
        if source is None:
            source = ()

        report = build_forensic_report(
            source=source,
            report_format=ctx.config.report_formats[0] if ctx.config.report_formats else ReportFormat.JSON,
            case_id=ctx.config.case_id,
            case_name=ctx.config.case_name,
            investigator=ctx.config.investigator,
            evidence_root=str(ctx.evidence_path or ctx.config.evidence_path),
            audit_trail=tuple(ctx.audit_trail),
            triage_id=ctx.triage_id,
            stage_results=tuple(ctx.stage_results.values()),
            trace_records=tuple(ctx.trace_records),
            investigation_summary=ctx.investigation_result.summary if ctx.investigation_result else None,
        )
        ctx.report = report

        # Write reports to output directory if configured
        written_files: List[Tuple[str, str]] = []
        errors: List[TriageStageError] = []
        warnings: List[str] = []

        if ctx.config.output_dir:
            out_dir = Path(ctx.config.output_dir).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            case_slug = ctx.config.case_id or "triage"

            for fmt in ctx.config.report_formats:
                fmt_lower = fmt.lower().strip()
                try:
                    if fmt_lower == "json":
                        p = out_dir / f"forensix_report_{case_slug}.json"
                        write_json_report(report, p)
                        written_files.append(("json", str(p)))
                    elif fmt_lower == "csv":
                        p = out_dir / f"forensix_report_{case_slug}.csv"
                        write_csv_report(report, p)
                        written_files.append(("csv", str(p)))
                    elif fmt_lower == "html":
                        p = out_dir / f"forensix_report_{case_slug}.html"
                        write_html_report(report, p)
                        written_files.append(("html", str(p)))
                    else:
                        warnings.append(f"Unsupported report format: {fmt}")
                except Exception as e:
                    err = TriageStageError(
                        stage_id=TriageStage.REPORTING.value,
                        error_type=type(e).__name__,
                        error_message=f"Failed to generate {fmt_lower.upper()} report: {str(e)}",
                    )
                    errors.append(err)
                    warnings.append(f"{fmt_lower.upper()} generation failed: {str(e)}")

        ctx.report_files.extend(written_files)

        if errors and not written_files:
            return TriageStageResult(
                stage_id=TriageStage.REPORTING.value,
                stage_name=STAGE_NAMES[TriageStage.REPORTING.value],
                status=TriageStageStatus.FAILED,
                records_produced=0,
                errors=tuple(errors),
                warnings=tuple(warnings),
                metadata=(
                    ("formats_requested", tuple(ctx.config.report_formats)),
                    ("files_written_count", 0),
                ),
            )
        elif errors and written_files:
            return TriageStageResult(
                stage_id=TriageStage.REPORTING.value,
                stage_name=STAGE_NAMES[TriageStage.REPORTING.value],
                status=TriageStageStatus.PARTIAL,
                records_produced=len(written_files),
                errors=tuple(errors),
                warnings=tuple(warnings),
                metadata=(
                    ("formats_requested", tuple(ctx.config.report_formats)),
                    ("files_written_count", len(written_files)),
                ),
            )
        else:
            return TriageStageResult(
                stage_id=TriageStage.REPORTING.value,
                stage_name=STAGE_NAMES[TriageStage.REPORTING.value],
                status=TriageStageStatus.COMPLETED,
                records_produced=len(written_files) if written_files else 1,
                warnings=tuple(warnings),
                metadata=(
                    ("formats_generated", tuple(ctx.config.report_formats)),
                    ("files_written_count", len(written_files)),
                ),
            )
