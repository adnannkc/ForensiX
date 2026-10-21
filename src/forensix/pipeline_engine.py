"""
ForensiX V9 - Controlled Investigation Pipeline Engine.

Orchestrates multi-domain digital forensics analysis across Host, Network, and Memory evidence:
1. Validates configuration and executes preflight integrity checks without modifying original evidence.
2. Initializes or resumes a cryptographically linked Schema 8.0 chain-of-custody ledger.
3. Sequentially executes enabled domain engines (Host, Network, Memory) under strict fault containment.
4. Synthesizes a unified chronological timeline and evaluates cross-domain correlations and detection rules.
5. Produces a Schema 8.0 Advanced Forensic Report and commits the finalized custody ledger.
6. Emits a deterministic, machine-readable pipeline_manifest.json recording output SHA-256 digests.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from forensix import __version__
from forensix.advanced_report_builder import (
    build_advanced_report,
    write_advanced_report_html,
    write_advanced_report_json,
)
from forensix.advanced_report_models import (
    AdvancedReport,
    CustodySummary,
    EvidenceInventoryItem,
    FindingsSummary,
)
from forensix.artifact_adapters import adapt_artifacts
from forensix.case_config import CaseConfig, validate_case_config
from forensix.correlation_engine import correlate_events
from forensix.correlation_models import CorrelationCollection
from forensix.custody_ledger import (
    CustodyChainVerificationResult,
    CustodyLedger,
    StaleLedgerError,
)
from forensix.custody_models import (
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
)
from forensix.detection_engine import DetectionEngine, DetectionResultCollection
from forensix.hasher import compute_hashes
from forensix.initial_rules import get_initial_rules
from forensix.manifest_models import ManifestEntry, ManifestRecord
from forensix.manifest_verifier import (
    ManifestVerificationResult,
    verify_manifest,
)
from forensix.memory_cli import load_memory_artifacts
from forensix.memory_rules import create_canonical_memory_rules
from forensix.memory_timeline import MemoryTimelineEvent
from forensix.memory_triage import MemoryTriageConfig, MemoryTriageResult, run_memory_triage
from forensix.network_correlation import (
    HostNetworkCorrelationConfig,
    correlate_host_network_events,
)
from forensix.network_events import NetworkEvent, extract_network_event
from forensix.network_metadata import (
    NetworkApplicationMetadata,
    extract_metadata_from_packet,
)
from forensix.network_models import NetworkEvidenceRecord
from forensix.network_pcap_parser import PcapParser
from forensix.network_rules import create_canonical_network_rules
from forensix.network_timeline import adapt_network_artifact
from forensix.pipeline_models import (
    ALL_PIPELINE_STAGES,
    GeneratedFileRecord,
    PipelineRunManifest,
    PipelineRunStatus,
    PipelineStageId,
    StageRecord,
    StageStatus,
    generate_run_id,
)
from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.timeline_reconstruction import ReconstructedTimeline, reconstruct_timeline
from forensix.triage_models import TriageConfig, TriageResult
from forensix.triage_orchestrator import TriageOrchestrator
from forensix.unified_models import HostArtifact, HostArtifactCollection

# Standard exit code contract for ForensiX V9
EXIT_SUCCESS = 0
EXIT_CONFIG_ERROR = 1
EXIT_VERIFICATION_OR_PARTIAL = 2
EXIT_CUSTODY_FAILURE = 3
EXIT_FILESYSTEM_IO_ERROR = 4


@dataclass(frozen=True)
class PipelineExecutionResult:
    """
    Immutable outcome container for an InvestigationPipeline execution.
    """

    run_manifest: PipelineRunManifest
    report: Optional[AdvancedReport] = None
    custody_ledger: Optional[CustodyLedger] = None
    exit_code: int = EXIT_SUCCESS
    output_files: Tuple[Path, ...] = ()


def _clean_source_location(p: Optional[Path]) -> Optional[str]:
    """Return a relative, portable string representation of an evidence path."""
    if p is None:
        return None
    try:
        return str(p.resolve().relative_to(Path.cwd().resolve()))
    except (ValueError, RuntimeError):
        return p.name


class InvestigationPipeline:
    """
    Controlled investigation pipeline orchestrator executing multi-domain forensics.
    """

    def __init__(self, config: CaseConfig) -> None:
        if not isinstance(config, CaseConfig):
            raise TypeError(f"config must be CaseConfig, got {type(config).__name__}")
        self.config = config

    def execute(self) -> PipelineExecutionResult:
        """
        Execute the 12-stage investigation pipeline in strict dependency order.
        """
        run_id = generate_run_id()
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()

        stage_records: List[StageRecord] = []
        evidence_digests: Dict[str, str] = {}
        written_file_records: List[GeneratedFileRecord] = []
        written_paths: List[Path] = []

        overall_status = PipelineRunStatus.SUCCESS
        exit_code = EXIT_SUCCESS

        # Context containers
        manifest_verif: Optional[ManifestVerificationResult] = None
        manifest_record: Optional[ManifestRecord] = None
        ledger: Optional[CustodyLedger] = None
        actor = CustodyActor(
            declared_identity=self.config.investigator or "ForensiX Automated Pipeline",
            role=self.config.actor_role,
            organization=self.config.actor_org,
        )

        host_collection: Optional[HostArtifactCollection] = None
        host_timeline_events: List[TimelineEvent] = []
        net_records: List[NetworkEvidenceRecord] = []
        net_timeline_events: List[TimelineEvent] = []
        mem_artifacts: List[Any] = []
        mem_timeline_events: List[TimelineEvent] = []

        all_timeline_events: List[TimelineEvent] = []
        correlations: Optional[CorrelationCollection] = None
        detections: Optional[DetectionResultCollection] = None
        report: Optional[AdvancedReport] = None

        clean_case_name = re.sub(r"[^\w\-.]", "_", str(self.config.case_id).strip()) if self.config.case_id else "case"

        # ---------------------------------------------------------------------
        # STAGE 1: CONFIG_VALIDATION
        # ---------------------------------------------------------------------
        st1_start = datetime.now(timezone.utc).isoformat()
        st1_t0 = time.perf_counter()
        try:
            validate_case_config(self.config)
            st1_dur = time.perf_counter() - st1_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CONFIG_VALIDATION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st1_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st1_dur,
                    records_produced=len(self.config.all_evidence_paths),
                )
            )
        except Exception as exc:
            st1_dur = time.perf_counter() - st1_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CONFIG_VALIDATION.value,
                    status=StageStatus.FAILED.value,
                    started_at=st1_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st1_dur,
                    errors=(str(exc),),
                )
            )
            # Critical halt
            total_dur = time.perf_counter() - t0
            run_manifest = PipelineRunManifest(
                run_id=run_id,
                forensix_version=__version__,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                total_duration_seconds=total_dur,
                run_status=PipelineRunStatus.FAILURE.value,
                case_id=self.config.case_id,
                case_name=self.config.case_name,
                investigator=self.config.investigator,
                stages=tuple(stage_records),
            )
            return PipelineExecutionResult(
                run_manifest=run_manifest,
                exit_code=EXIT_CONFIG_ERROR,
            )

        # ---------------------------------------------------------------------
        # STAGE 2: PREFLIGHT_VERIFICATION
        # ---------------------------------------------------------------------
        st2_start = datetime.now(timezone.utc).isoformat()
        st2_t0 = time.perf_counter()
        st2_errors: List[str] = []
        st2_warnings: List[str] = []
        preflight_failed = False
        manifest_discrepancy_detected = False

        try:
            # 1. Output directory creation and pre-flight no-clobber check
            out_dir = self.config.output_dir.resolve()
            out_dir.mkdir(parents=True, exist_ok=True)

            target_files = [
                out_dir / f"report_{clean_case_name}.json",
                out_dir / f"report_{clean_case_name}.html",
                out_dir / f"ledger_{clean_case_name}.json",
                out_dir / "pipeline_manifest.json",
            ]
            if not self.config.overwrite:
                existing = [f.name for f in target_files if f.exists()]
                if existing:
                    raise FileExistsError(
                        f"Output files already exist in '{out_dir}' and overwrite is False: {', '.join(existing)}"
                    )

            # 2. Record baseline hashes of discrete evidence files
            for pcap_path in self.config.evidence_pcap_files:
                h = compute_hashes(pcap_path)
                evidence_digests[pcap_path.name] = h["sha256"]

            for mem_path in self.config.evidence_mem_files:
                if mem_path.is_file():
                    h = compute_hashes(mem_path)
                    evidence_digests[mem_path.name] = h["sha256"]

            # 3. Optional manifest verification
            if self.config.manifest_path is not None:
                manifest_verif = verify_manifest(
                    manifest=self.config.manifest_path,
                    base_dir=self.config.evidence_host_dir,
                    allow_symlinks=self.config.allow_symlinks,
                )
                if not manifest_verif.overall_status:
                    manifest_discrepancy_detected = True
                    st2_warnings.append(
                        f"Manifest verification discrepancy: {manifest_verif.mismatch_count} mismatch(es), "
                        f"{manifest_verif.missing_count} missing file(s)"
                    )
                # Parse ManifestRecord for report builder
                with open(self.config.manifest_path, "r", encoding="utf-8") as f:
                    raw_man = json.load(f)
                parsed_entries = [
                    ManifestEntry(
                        relative_path=e["relative_path"],
                        size_bytes=e["size_bytes"],
                        hashes=e["hashes"],
                        artifact_type=e.get("artifact_type", "evidence"),
                        evidence_id=e.get("evidence_id"),
                        metadata=e.get("metadata", ()),
                    )
                    for e in raw_man.get("entries", [])
                ]
                manifest_record = ManifestRecord(
                    manifest_id=raw_man["manifest_id"],
                    manifest_version=raw_man.get("manifest_version", "8.0"),
                    created_at=raw_man["created_at"],
                    forensix_version=raw_man["forensix_version"],
                    case_id=raw_man.get("case_id"),
                    investigator=raw_man.get("investigator"),
                    entries=parsed_entries,
                )

        except FileExistsError as exc:
            preflight_failed = True
            st2_errors.append(str(exc))
            exit_code = EXIT_FILESYSTEM_IO_ERROR
        except Exception as exc:
            preflight_failed = True
            st2_errors.append(str(exc))
            exit_code = EXIT_CONFIG_ERROR

        st2_dur = time.perf_counter() - st2_t0
        if preflight_failed:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.PREFLIGHT_VERIFICATION.value,
                    status=StageStatus.FAILED.value,
                    started_at=st2_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st2_dur,
                    errors=tuple(st2_errors),
                )
            )
            total_dur = time.perf_counter() - t0
            run_manifest = PipelineRunManifest(
                run_id=run_id,
                forensix_version=__version__,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                total_duration_seconds=total_dur,
                run_status=PipelineRunStatus.FAILURE.value,
                case_id=self.config.case_id,
                case_name=self.config.case_name,
                investigator=self.config.investigator,
                stages=tuple(stage_records),
            )
            return PipelineExecutionResult(run_manifest=run_manifest, exit_code=exit_code)

        stage_records.append(
            StageRecord(
                stage_id=PipelineStageId.PREFLIGHT_VERIFICATION.value,
                status=StageStatus.COMPLETED.value,
                started_at=st2_start,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=st2_dur,
                warnings=tuple(st2_warnings),
                records_produced=len(evidence_digests) + (len(manifest_record.entries) if manifest_record else 0),
            )
        )

        if manifest_discrepancy_detected:
            overall_status = PipelineRunStatus.PARTIAL_SUCCESS
            exit_code = EXIT_VERIFICATION_OR_PARTIAL

        # ---------------------------------------------------------------------
        # STAGE 3: CUSTODY_INITIALIZATION
        # ---------------------------------------------------------------------
        st3_start = datetime.now(timezone.utc).isoformat()
        st3_t0 = time.perf_counter()
        st3_errors: List[str] = []
        try:
            if self.config.custody_ledger_path is not None:
                ledger = CustodyLedger.load_from_file(self.config.custody_ledger_path)
                chain_verif = ledger.validate_chain()
                if not chain_verif.is_valid:
                    raise ValueError(
                        f"Custody ledger chain integrity failure on resume: {'; '.join(chain_verif.discrepancies)}"
                    )
            else:
                ledger = CustodyLedger(case_id=self.config.case_id, description=self.config.case_name)

            # Record intake for each evidence root/file
            if self.config.evidence_host_dir:
                ledger.append_event(
                    action_type=CustodyActionType.EVIDENCE_RECEIVED,
                    evidence_id=self.config.evidence_host_dir.name,
                    actor=actor,
                    source_location=_clean_source_location(self.config.evidence_host_dir),
                    notes=f"Host evidence directory '{self.config.evidence_host_dir.name}' ingested into pipeline",
                )
            for pcap in self.config.evidence_pcap_files:
                ledger.append_event(
                    action_type=CustodyActionType.EVIDENCE_RECEIVED,
                    evidence_id=pcap.name,
                    actor=actor,
                    source_location=_clean_source_location(pcap),
                    notes=f"Network capture '{pcap.name}' ingested into pipeline",
                    hashes=(("sha256", evidence_digests.get(pcap.name, "")),),
                )
            for mem in self.config.evidence_mem_files:
                ledger.append_event(
                    action_type=CustodyActionType.EVIDENCE_RECEIVED,
                    evidence_id=mem.name,
                    actor=actor,
                    source_location=_clean_source_location(mem),
                    notes=f"Memory artifact file '{mem.name}' ingested into pipeline",
                    hashes=(("sha256", evidence_digests.get(mem.name, "")),) if mem.is_file() else (),
                )

            # Manifest verification custody recording
            if manifest_verif is not None:
                if manifest_verif.overall_status:
                    ledger.append_event(
                        action_type=CustodyActionType.INTEGRITY_VERIFIED,
                        evidence_id=manifest_verif.manifest_id,
                        actor=actor,
                        notes=f"Manifest baseline verified: {manifest_verif.verified_count}/{manifest_verif.total_entries} matched",
                    )
                else:
                    ledger.append_event(
                        action_type=CustodyActionType.INTEGRITY_MISMATCH_DETECTED,
                        evidence_id=manifest_verif.manifest_id,
                        actor=actor,
                        notes=(
                            f"Manifest verification discrepancy: {manifest_verif.mismatch_count} mismatch(es), "
                            f"{manifest_verif.missing_count} missing file(s)"
                        ),
                    )

            st3_dur = time.perf_counter() - st3_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CUSTODY_INITIALIZATION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st3_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st3_dur,
                    records_produced=len(ledger),
                )
            )

        except Exception as exc:
            st3_dur = time.perf_counter() - st3_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CUSTODY_INITIALIZATION.value,
                    status=StageStatus.FAILED.value,
                    started_at=st3_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st3_dur,
                    errors=(str(exc),),
                )
            )
            total_dur = time.perf_counter() - t0
            run_manifest = PipelineRunManifest(
                run_id=run_id,
                forensix_version=__version__,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                total_duration_seconds=total_dur,
                run_status=PipelineRunStatus.FAILURE.value,
                case_id=self.config.case_id,
                case_name=self.config.case_name,
                investigator=self.config.investigator,
                stages=tuple(stage_records),
            )
            return PipelineExecutionResult(run_manifest=run_manifest, exit_code=EXIT_CUSTODY_FAILURE)

        # ---------------------------------------------------------------------
        # STAGE 4: HOST_ANALYSIS
        # ---------------------------------------------------------------------
        st4_start = datetime.now(timezone.utc).isoformat()
        st4_t0 = time.perf_counter()
        if self.config.evidence_host_dir and "host" in self.config.enabled_domains:
            try:
                triage_cfg = TriageConfig(
                    evidence_path=str(self.config.evidence_host_dir),
                    case_id=self.config.case_id,
                    case_name=self.config.case_name,
                    investigator=self.config.investigator,
                    skip_reports=True,
                    collect_audit=True,
                    log_timestamp_year=self.config.log_year,
                )
                triage_orch = TriageOrchestrator(triage_cfg)
                triage_res = triage_orch.run()
                host_collection = triage_res.artifacts
                if host_collection and host_collection.artifacts:
                    host_timeline_events = list(
                        adapt_artifacts(
                            host_collection.artifacts,
                            ignore_unsupported=True,
                            log_timestamp_year=self.config.log_year,
                        )
                    )

                st4_dur = time.perf_counter() - st4_t0
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.HOST_ANALYSIS.value,
                        status=StageStatus.COMPLETED.value,
                        started_at=st4_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st4_dur,
                        records_produced=len(host_collection.artifacts) if (host_collection and host_collection.artifacts) else 0,
                    )
                )
            except Exception as exc:
                st4_dur = time.perf_counter() - st4_t0
                overall_status = PipelineRunStatus.PARTIAL_SUCCESS
                exit_code = EXIT_VERIFICATION_OR_PARTIAL
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.HOST_ANALYSIS.value,
                        status=StageStatus.FAILED.value,
                        started_at=st4_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st4_dur,
                        errors=(str(exc),),
                    )
                )
                if self.config.fail_fast:
                    return self._abort_run(
                        run_id, started_at, t0, stage_records, evidence_digests, exit_code
                    )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.HOST_ANALYSIS.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st4_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st4_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 5: NETWORK_ANALYSIS
        # ---------------------------------------------------------------------
        st5_start = datetime.now(timezone.utc).isoformat()
        st5_t0 = time.perf_counter()
        if self.config.evidence_pcap_files and "network" in self.config.enabled_domains:
            st5_errors: List[str] = []
            st5_count = 0
            for pcap_file in self.config.evidence_pcap_files:
                try:
                    parser = PcapParser(pcap_file, pcap_name=pcap_file.name)
                    link_type = parser.global_header.network
                    for rec, pkt_bytes in parser.read_raw_records():
                        st5_count += 1
                        net_records.append(rec)
                        # Pipeline wrapper source tagging
                        meta = extract_metadata_from_packet(rec, pkt_bytes, link_type)
                        tl_evs = adapt_network_artifact(meta if meta is not None else rec)
                        if tl_evs:
                            net_timeline_events.extend(tl_evs)

                except Exception as exc:
                    st5_errors.append(f"Error analyzing '{pcap_file.name}': {exc}")

            st5_dur = time.perf_counter() - st5_t0
            if st5_errors:
                overall_status = PipelineRunStatus.PARTIAL_SUCCESS
                exit_code = EXIT_VERIFICATION_OR_PARTIAL
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.NETWORK_ANALYSIS.value,
                        status=StageStatus.FAILED.value if st5_count == 0 else StageStatus.PARTIAL.value,
                        started_at=st5_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st5_dur,
                        records_produced=st5_count,
                        errors=tuple(st5_errors),
                    )
                )
                if self.config.fail_fast:
                    return self._abort_run(
                        run_id, started_at, t0, stage_records, evidence_digests, exit_code
                    )
            else:
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.NETWORK_ANALYSIS.value,
                        status=StageStatus.COMPLETED.value,
                        started_at=st5_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st5_dur,
                        records_produced=st5_count,
                    )
                )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.NETWORK_ANALYSIS.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st5_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st5_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 6: MEMORY_ANALYSIS
        # ---------------------------------------------------------------------
        st6_start = datetime.now(timezone.utc).isoformat()
        st6_t0 = time.perf_counter()
        if self.config.evidence_mem_files and "memory" in self.config.enabled_domains:
            st6_errors: List[str] = []
            st6_count = 0
            for mem_path in self.config.evidence_mem_files:
                try:
                    artifacts, err = load_memory_artifacts(mem_path)
                    if err:
                        st6_errors.append(err)
                        continue
                    mem_artifacts.extend(artifacts)
                    st6_count += len(artifacts)
                except Exception as exc:
                    st6_errors.append(f"Failed loading memory artifacts from '{mem_path.name}': {exc}")

            if mem_artifacts:
                try:
                    mem_triage_res: MemoryTriageResult = run_memory_triage(
                        mem_artifacts,
                        config=MemoryTriageConfig(
                            case_id=self.config.case_id,
                            case_name=self.config.case_name,
                            investigator=self.config.investigator,
                        ),
                    )
                    if mem_triage_res.timeline_events:
                        mem_timeline_events.extend(mem_triage_res.timeline_events)
                except Exception as exc:
                    st6_errors.append(f"Memory triage evaluation failed: {exc}")

            st6_dur = time.perf_counter() - st6_t0
            if st6_errors:
                overall_status = PipelineRunStatus.PARTIAL_SUCCESS
                exit_code = EXIT_VERIFICATION_OR_PARTIAL
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.MEMORY_ANALYSIS.value,
                        status=StageStatus.FAILED.value if st6_count == 0 else StageStatus.PARTIAL.value,
                        started_at=st6_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st6_dur,
                        records_produced=st6_count,
                        errors=tuple(st6_errors),
                    )
                )
                if self.config.fail_fast:
                    return self._abort_run(
                        run_id, started_at, t0, stage_records, evidence_digests, exit_code
                    )
            else:
                stage_records.append(
                    StageRecord(
                        stage_id=PipelineStageId.MEMORY_ANALYSIS.value,
                        status=StageStatus.COMPLETED.value,
                        started_at=st6_start,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=st6_dur,
                        records_produced=st6_count,
                    )
                )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.MEMORY_ANALYSIS.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st6_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st6_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 7: TIMELINE_RECONSTRUCTION
        # ---------------------------------------------------------------------
        st7_start = datetime.now(timezone.utc).isoformat()
        st7_t0 = time.perf_counter()
        if "timeline" in self.config.enabled_domains:
            all_raw_events = host_timeline_events + net_timeline_events + mem_timeline_events
            recon: ReconstructedTimeline = reconstruct_timeline(all_raw_events)
            all_timeline_events = list(recon.events)
            st7_dur = time.perf_counter() - st7_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.TIMELINE_RECONSTRUCTION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st7_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st7_dur,
                    records_produced=len(all_timeline_events),
                )
            )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.TIMELINE_RECONSTRUCTION.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st7_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st7_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 8: CORRELATION
        # ---------------------------------------------------------------------
        st8_start = datetime.now(timezone.utc).isoformat()
        st8_t0 = time.perf_counter()
        if "correlation" in self.config.enabled_domains and all_timeline_events:
            combined_correlations: List[Any] = []
            # 1. Temporal and identity correlation across unified timeline
            c1 = correlate_events(all_timeline_events)
            combined_correlations.extend(c1.correlations)

            # 2. Host-to-network IP correlation if both present
            if host_timeline_events and net_timeline_events:
                corr_host_net = correlate_host_network_events(all_timeline_events)
                combined_correlations.extend(corr_host_net.correlations)

            # Deduplicate by correlation_id
            seen_cids: Set[str] = set()
            unique_correlations = []
            for corr in combined_correlations:
                if corr.correlation_id not in seen_cids:
                    seen_cids.add(corr.correlation_id)
                    unique_correlations.append(corr)

            correlations = CorrelationCollection(correlations=tuple(unique_correlations))
            st8_dur = time.perf_counter() - st8_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CORRELATION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st8_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st8_dur,
                    records_produced=len(correlations),
                )
            )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CORRELATION.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st8_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st8_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 9: DETECTION
        # ---------------------------------------------------------------------
        st9_start = datetime.now(timezone.utc).isoformat()
        st9_t0 = time.perf_counter()
        if "detection" in self.config.enabled_domains and all_timeline_events:
            # Combine canonical rules across all domains
            combined_rules = list(get_initial_rules()) + list(create_canonical_network_rules()) + list(create_canonical_memory_rules())
            detect_engine = DetectionEngine(combined_rules)
            detections = detect_engine.evaluate(all_timeline_events, correlations=correlations)
            st9_dur = time.perf_counter() - st9_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.DETECTION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st9_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st9_dur,
                    records_produced=len(detections),
                    metadata=(("matched_detections", sum(1 for d in detections if d.matched)),),
                )
            )
        else:
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.DETECTION.value,
                    status=StageStatus.SKIPPED.value,
                    started_at=st9_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=time.perf_counter() - st9_t0,
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 10: REPORT_SYNTHESIS
        # ---------------------------------------------------------------------
        st10_start = datetime.now(timezone.utc).isoformat()
        st10_t0 = time.perf_counter()
        try:
            total_host_arts = (
                len(host_collection.artifacts)
                if (host_collection and host_collection.artifacts)
                else 0
            )
            total_net_pkts = len(net_records)
            total_mem_procs = sum(1 for m in mem_artifacts if getattr(m, "pid", None) is not None)

            findings_summary = FindingsSummary(
                total_host_artifacts=total_host_arts,
                total_timeline_events=len(all_timeline_events),
                total_correlations=len(correlations) if correlations else 0,
                total_rule_evaluations=len(detections) if detections else 0,
                matched_detections=sum(1 for d in detections if d.matched) if detections else 0,
            )

            # Details dictionary for HTML & JSON report views
            report_details: Dict[str, Any] = {
                "pipeline_run_id": run_id,
                "total_timeline_events": len(all_timeline_events),
                "total_correlations": len(correlations) if correlations else 0,
                "total_detections": len(detections) if detections else 0,
                "network_packets_analyzed": total_net_pkts,
                "memory_artifacts_analyzed": len(mem_artifacts),
            }
            if detections:
                report_details["detections"] = [
                    d.to_dict() for d in detections if d.matched
                ]

            case_meta = {
                "case_id": self.config.case_id,
                "case_name": self.config.case_name,
                "investigator": self.config.investigator,
            }

            report = build_advanced_report(
                case_metadata=case_meta,
                manifest=manifest_record,
                manifest_verification=manifest_verif,
                custody_ledger=ledger,
                investigation_results=host_collection,
                findings_summary=findings_summary,
                details=report_details,
            )

            # Write JSON & HTML reports
            if "json" in self.config.report_formats:
                json_path = out_dir / f"report_{clean_case_name}.json"
                write_advanced_report_json(
                    report=report,
                    output_path=json_path,
                    overwrite=self.config.overwrite,
                    evidence_root=self.config.evidence_host_dir,
                )
                h_json = compute_hashes(json_path)
                written_file_records.append(
                    GeneratedFileRecord(
                        relative_path=json_path.name,
                        sha256=h_json["sha256"],
                        size_bytes=json_path.stat().st_size,
                        file_type="advanced_report_json",
                    )
                )
                written_paths.append(json_path)

            if "html" in self.config.report_formats:
                html_path = out_dir / f"report_{clean_case_name}.html"
                write_advanced_report_html(
                    report=report,
                    output_path=html_path,
                    overwrite=self.config.overwrite,
                    evidence_root=self.config.evidence_host_dir,
                )
                h_html = compute_hashes(html_path)
                written_file_records.append(
                    GeneratedFileRecord(
                        relative_path=html_path.name,
                        sha256=h_html["sha256"],
                        size_bytes=html_path.stat().st_size,
                        file_type="advanced_report_html",
                    )
                )
                written_paths.append(html_path)

            st10_dur = time.perf_counter() - st10_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.REPORT_SYNTHESIS.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st10_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st10_dur,
                    records_produced=len(written_file_records),
                )
            )

        except Exception as exc:
            st10_dur = time.perf_counter() - st10_t0
            overall_status = PipelineRunStatus.FAILURE
            exit_code = EXIT_FILESYSTEM_IO_ERROR
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.REPORT_SYNTHESIS.value,
                    status=StageStatus.FAILED.value,
                    started_at=st10_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st10_dur,
                    errors=(str(exc),),
                )
            )
            return self._abort_run(run_id, started_at, t0, stage_records, evidence_digests, exit_code)

        # ---------------------------------------------------------------------
        # STAGE 11: CUSTODY_FINALIZATION
        # ---------------------------------------------------------------------
        st11_start = datetime.now(timezone.utc).isoformat()
        st11_t0 = time.perf_counter()
        try:
            if ledger is not None and report is not None:
                ledger.append_event(
                    action_type=CustodyActionType.REPORT_GENERATED,
                    evidence_id=report.report_id,
                    actor=actor,
                    notes=(
                        f"Generated Schema 8.0 Advanced Forensic Report '{report.report_id}' "
                        f"covering multi-domain pipeline execution (run_id: {run_id})"
                    ),
                )
                final_chain = ledger.validate_chain()
                if not final_chain.is_valid:
                    raise ValueError(f"Final custody chain validation failed: {'; '.join(final_chain.discrepancies)}")

                ledger_path = out_dir / f"ledger_{clean_case_name}.json"
                ledger.save_to_file(
                    path=ledger_path,
                    overwrite=self.config.overwrite,
                    evidence_root=self.config.evidence_host_dir,
                )
                h_led = compute_hashes(ledger_path)
                written_file_records.append(
                    GeneratedFileRecord(
                        relative_path=ledger_path.name,
                        sha256=h_led["sha256"],
                        size_bytes=ledger_path.stat().st_size,
                        file_type="custody_ledger_json",
                    )
                )
                written_paths.append(ledger_path)

            st11_dur = time.perf_counter() - st11_t0
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CUSTODY_FINALIZATION.value,
                    status=StageStatus.COMPLETED.value,
                    started_at=st11_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st11_dur,
                    records_produced=len(ledger) if ledger else 0,
                )
            )
        except Exception as exc:
            st11_dur = time.perf_counter() - st11_t0
            overall_status = PipelineRunStatus.PARTIAL_SUCCESS
            exit_code = EXIT_CUSTODY_FAILURE
            stage_records.append(
                StageRecord(
                    stage_id=PipelineStageId.CUSTODY_FINALIZATION.value,
                    status=StageStatus.FAILED.value,
                    started_at=st11_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=st11_dur,
                    errors=(str(exc),),
                )
            )

        # ---------------------------------------------------------------------
        # STAGE 12: RUN_MANIFEST
        # ---------------------------------------------------------------------
        st12_start = datetime.now(timezone.utc).isoformat()
        st12_t0 = time.perf_counter()

        # Temporary stage record for manifest completion
        stage_records.append(
            StageRecord(
                stage_id=PipelineStageId.RUN_MANIFEST.value,
                status=StageStatus.COMPLETED.value,
                started_at=st12_start,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=time.perf_counter() - st12_t0,
                records_produced=len(written_file_records),
            )
        )

        total_dur = time.perf_counter() - t0
        run_manifest = PipelineRunManifest(
            run_id=run_id,
            forensix_version=__version__,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_duration_seconds=total_dur,
            run_status=overall_status.value,
            case_id=self.config.case_id,
            case_name=self.config.case_name,
            investigator=self.config.investigator,
            stages=tuple(stage_records),
            generated_files=tuple(written_file_records),
            evidence_digests=tuple((str(k), v) for k, v in sorted(evidence_digests.items())),
        )

        # Write pipeline_manifest.json (Condition 4: exactly pipeline_manifest.json)
        manifest_file = out_dir / "pipeline_manifest.json"
        manifest_file.write_text(run_manifest.to_json(indent=2), encoding="utf-8")
        written_paths.append(manifest_file)

        return PipelineExecutionResult(
            run_manifest=run_manifest,
            report=report,
            custody_ledger=ledger,
            exit_code=exit_code,
            output_files=tuple(written_paths),
        )

    def _abort_run(
        self,
        run_id: str,
        started_at: str,
        t0: float,
        stage_records: List[StageRecord],
        evidence_digests: Dict[str, str],
        exit_code: int,
    ) -> PipelineExecutionResult:
        """Helper to cleanly terminate a failed run."""
        total_dur = time.perf_counter() - t0
        run_manifest = PipelineRunManifest(
            run_id=run_id,
            forensix_version=__version__,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_duration_seconds=total_dur,
            run_status=PipelineRunStatus.FAILURE.value,
            case_id=self.config.case_id,
            case_name=self.config.case_name,
            investigator=self.config.investigator,
            stages=tuple(stage_records),
            evidence_digests=tuple((str(k), v) for k, v in sorted(evidence_digests.items())),
        )
        return PipelineExecutionResult(
            run_manifest=run_manifest,
            exit_code=exit_code,
        )


def run_pipeline(config: CaseConfig) -> PipelineExecutionResult:
    """
    Convenience wrapper to execute an InvestigationPipeline for a given CaseConfig.
    """
    pipeline = InvestigationPipeline(config)
    return pipeline.execute()
