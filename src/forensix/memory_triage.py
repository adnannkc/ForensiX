"""
Forensic Memory Triage & Investigation Layer for ForensiX (V6.7).

Provides strongly typed, deterministic memory triage orchestration, artifact
lifecycle management, timeline integration, correlation evaluation, rule-based
detection evaluation, and reporting.

Core Principles:
1. Evidence-Image Isolation:
   - Processes, modules, and network sockets are scoped strictly to their source
     memory evidence ID (MEM-<UUID>).
   - Identical PIDs or sockets across differing evidence images are never equated
     or cross-correlated.
2. Non-Destructive & Read-Only:
   - Memory triage does not modify, execute, acquire, or dump evidence.
   - Operates on strongly typed extracted artifacts or structured extraction results.
3. Provenance Chain & Factual Integrity:
   - Retains source artifact IDs (MEMPROC-, MEMMOD-, MEMNET-), source event IDs,
     Volatility execution IDs, and memory correlation identifiers throughout detection.
   - Evaluates factual observations only; does not emit speculative claims of compromise.
4. Determinism & Immutability:
   - Stable output ordering and deterministic RFC 4122 UUIDv5 triage identifiers.
   - Reuses existing V4 DetectionEngine and CorrelationDetectionReport models directly.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid

from forensix import __version__
from forensix.correlation_models import Correlation, CorrelationCollection
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    detection_sort_key,
)
from forensix.detection_reporting import (
    CorrelationDetectionReport,
    generate_correlation_detection_report,
    render_correlation_detection_html,
    render_correlation_detection_json,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
)
from forensix.memory_correlation import (
    MemoryCorrelation,
    MemoryCorrelationCollection,
    MemoryCorrelationConfig,
    correlate_memory_artifacts,
    memory_correlation_sort_key,
)
from forensix.memory_models import (
    FORENSIX_V6_MEMORY_NAMESPACE,
    MemoryEvidenceRecord,
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    ModuleExtractionResult,
    NetworkExtractionResult,
    ProcessExtractionResult,
    _validate_memory_id,
)
from forensix.memory_rules import create_canonical_memory_rules
from forensix.memory_timeline import (
    MemoryTimelineEvent,
    ReconstructedMemoryTimeline,
    adapt_module_artifact,
    adapt_network_artifact,
    adapt_process_artifact,
    memory_timeline_sort_key,
    reconstruct_memory_timeline,
)
from forensix.rule_models import DetectionRule, RuleCollection
from forensix.timeline_models import TimelineEvent
from forensix.timeline_reconstruction import timeline_sort_key


@dataclass(frozen=True)
class MemoryTriageConfig:
    """
    Immutable configuration options for memory triage execution.

    Attributes:
        case_id: Incident case tracking identifier.
        case_name: Human-readable incident title.
        investigator: Handling forensic investigator name or ID.
        correlation_config: Configuration for memory relationship correlation.
        rules: Optional override of DetectionRules to evaluate.
        matched_only: If True, reports only matched detection findings.
        report_formats: Tuple of report formats to generate ('json', 'html').
        output_dir: Destination path for generated reports.
    """

    case_id: Optional[str] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    correlation_config: Optional[MemoryCorrelationConfig] = None
    rules: Optional[Tuple[DetectionRule, ...]] = None
    matched_only: bool = False
    report_formats: Tuple[str, ...] = ("json", "html")
    output_dir: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate configuration parameters strictly."""
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

        if self.rules is not None:
            if isinstance(self.rules, RuleCollection):
                object.__setattr__(self, "rules", self.rules.rules)
            elif isinstance(self.rules, (list, tuple)):
                for idx, r in enumerate(self.rules):
                    if not isinstance(r, DetectionRule):
                        raise TypeError(f"Item {idx} in rules is not DetectionRule, got {type(r).__name__}")
                object.__setattr__(self, "rules", tuple(self.rules))
            else:
                raise TypeError(f"rules must be RuleCollection or sequence of DetectionRules, got {type(self.rules).__name__}")

        if not isinstance(self.matched_only, bool):
            raise TypeError(f"matched_only must be bool, got {type(self.matched_only).__name__}")

        if isinstance(self.report_formats, (list, tuple)):
            norm_fmts: List[str] = []
            for f in self.report_formats:
                val = str(f).strip().lower()
                if val not in ("json", "html"):
                    raise ValueError(f"Invalid report format: '{val}'. Supported formats: 'json', 'html'")
                norm_fmts.append(val)
            object.__setattr__(self, "report_formats", tuple(norm_fmts))
        else:
            raise TypeError("report_formats must be a sequence of format strings ('json', 'html')")

        if self.output_dir is not None:
            if not isinstance(self.output_dir, (str, Path)):
                raise TypeError(f"output_dir must be str, Path, or None, got {type(self.output_dir).__name__}")
            object.__setattr__(self, "output_dir", str(self.output_dir).strip() or None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a deterministic JSON-safe dictionary."""
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "matched_only": self.matched_only,
            "report_formats": list(self.report_formats),
            "output_dir": self.output_dir,
            "rule_count": len(self.rules) if self.rules else None,
        }


def compute_deterministic_triage_id(
    evidence_ids: Sequence[str],
    artifact_count: int,
    detection_count: int,
) -> str:
    """
    Generate a deterministic RFC 4122 UUIDv5 tracking identifier for a memory triage execution.

    Stable inputs:
    - Sorted unique evidence IDs
    - Total discrete artifact count
    - Total detection finding count
    """
    sorted_eids = sorted(set(str(eid).strip() for eid in evidence_ids if str(eid).strip()))
    canonical_key = f"eids:{','.join(sorted_eids)}|arts:{artifact_count}|dets:{detection_count}"
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMTRIAGE-{det_uuid}"


@dataclass(frozen=True)
class MemoryTriageResult:
    """
    Immutable representation of an end-to-end memory triage execution outcome.

    Preserves strict separation between:
    - Raw memory timeline observations (MemoryTimelineEvent)
    - Canonical timeline events (TimelineEvent)
    - Raw memory correlations (MemoryCorrelation)
    - Canonical correlations (Correlation)
    - Deterministic detection results (DetectionResultCollection)
    """

    triage_id: str
    evidence_ids: Tuple[str, ...]
    total_artifacts: int
    timeline_events: Tuple[TimelineEvent, ...]
    memory_timeline_events: Tuple[MemoryTimelineEvent, ...]
    correlations: Tuple[Correlation, ...]
    memory_correlations: Tuple[MemoryCorrelation, ...]
    detections: DetectionResultCollection
    summary: Tuple[Tuple[str, Any], ...]
    is_success: bool = True
    errors: Tuple[str, ...] = ()
    config: Optional[MemoryTriageConfig] = None

    def __post_init__(self) -> None:
        """Validate and freeze collections."""
        if not isinstance(self.triage_id, str) or not self.triage_id.startswith("MEMTRIAGE-"):
            raise ValueError(f"triage_id must start with 'MEMTRIAGE-', got '{self.triage_id}'")

        if not isinstance(self.evidence_ids, tuple):
            object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))

        if not isinstance(self.timeline_events, tuple):
            object.__setattr__(self, "timeline_events", tuple(self.timeline_events))

        if not isinstance(self.memory_timeline_events, tuple):
            object.__setattr__(self, "memory_timeline_events", tuple(self.memory_timeline_events))

        if not isinstance(self.correlations, tuple):
            object.__setattr__(self, "correlations", tuple(self.correlations))

        if not isinstance(self.memory_correlations, tuple):
            object.__setattr__(self, "memory_correlations", tuple(self.memory_correlations))

        if not isinstance(self.detections, DetectionResultCollection):
            raise TypeError(f"detections must be DetectionResultCollection, got {type(self.detections).__name__}")

        if not isinstance(self.summary, tuple):
            if isinstance(self.summary, dict):
                frozen = tuple((str(k), v) for k, v in sorted(self.summary.items()))
                object.__setattr__(self, "summary", frozen)
            else:
                object.__setattr__(self, "summary", tuple(self.summary))

        if not isinstance(self.errors, tuple):
            object.__setattr__(self, "errors", tuple(str(e) for e in self.errors))

    @property
    def summary_dict(self) -> Dict[str, Any]:
        """Return summary metrics as a dictionary."""
        return dict(self.summary)

    def to_dict(self) -> Dict[str, Any]:
        """Convert memory triage result to a deterministic JSON-safe dictionary."""
        return {
            "triage_id": self.triage_id,
            "evidence_ids": list(self.evidence_ids),
            "total_artifacts": self.total_artifacts,
            "total_timeline_events": len(self.timeline_events),
            "total_correlations": len(self.correlations),
            "total_detections": len(self.detections),
            "matched_detections": sum(1 for d in self.detections if d.matched),
            "is_success": self.is_success,
            "errors": list(self.errors),
            "summary": dict(self.summary),
            "detections": self.detections.to_dict(),
            "config": self.config.to_dict() if self.config else None,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize triage result to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def generate_report(self, matched_only: Optional[bool] = None) -> CorrelationDetectionReport:
        """
        Generate an integrated CorrelationDetectionReport from this triage result.

        Directly leverages existing V4.6 reporting layer without duplicate renderers.
        """
        is_matched = matched_only if matched_only is not None else (self.config.matched_only if self.config else False)
        case_id = self.config.case_id if self.config else None
        case_name = self.config.case_name if self.config else None
        investigator = self.config.investigator if self.config else None

        return generate_correlation_detection_report(
            detections=self.detections,
            correlations=self.correlations,
            timeline=self.timeline_events,
            case_id=case_id,
            case_name=case_name,
            investigator=investigator,
            matched_only=is_matched,
            errors=self.errors if self.errors else None,
            limitations=[
                "Memory detections reflect in-memory artifact observations at acquisition time.",
                "Detection rule matches do not constitute proof of compromise or attacker intent.",
            ],
        )

    def render_report(self, format: str = "json", matched_only: Optional[bool] = None) -> str:
        """Render report as a formatted string ('json' or 'html')."""
        clean_fmt = str(format).strip().lower()
        report = self.generate_report(matched_only=matched_only)
        if clean_fmt == "json":
            return render_correlation_detection_json(report)
        elif clean_fmt == "html":
            return render_correlation_detection_html(report)
        else:
            raise ValueError(f"Unsupported report format: '{format}'. Supported formats: 'json', 'html'")

    def write_report(
        self,
        output_path: Union[str, Path],
        format: str = "json",
        matched_only: Optional[bool] = None,
    ) -> Path:
        """Write formatted report to destination file path."""
        clean_fmt = str(format).strip().lower()
        report = self.generate_report(matched_only=matched_only)
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        if clean_fmt == "json":
            return write_correlation_detection_json_report(report, target)
        elif clean_fmt == "html":
            return write_correlation_detection_html_report(report, target)
        else:
            raise ValueError(f"Unsupported report format: '{format}'. Supported formats: 'json', 'html'")


def run_memory_triage(
    artifacts: Sequence[Any],
    rules: Optional[Union[RuleCollection, Sequence[DetectionRule]]] = None,
    config: Optional[MemoryTriageConfig] = None,
) -> MemoryTriageResult:
    """
    Execute end-to-end memory triage and detection evaluation over forensic artifacts.

    Forensic Scope & Boundaries:
    - Accepts already-extracted memory artifacts:
      * MemoryProcessArtifact / ProcessExtractionResult
      * MemoryModuleArtifact / ModuleExtractionResult
      * MemoryNetworkArtifact / NetworkExtractionResult
      * MemoryTimelineEvent / ReconstructedMemoryTimeline
    - Does NOT execute live Volatility processes or perform raw image acquisition.
    - Strictly enforces Evidence Isolation: groups artifacts by evidence_id, evaluates
      correlations and detection rules strictly within each evidence image, and merges
      findings in deterministic order.
    - Uses existing DetectionEngine, DetectionResult, and Correlation models directly.

    Args:
        artifacts: Sequence of memory artifacts or structured extraction results.
        rules: Optional custom detection rules. Defaults to create_canonical_memory_rules().
        config: Optional MemoryTriageConfig specifying case metadata and options.

    Returns:
        Immutable, deterministic MemoryTriageResult containing events, correlations,
        detections, and summary metrics.
    """
    cfg = config or MemoryTriageConfig()

    # Determine active rules
    if rules is not None:
        if isinstance(rules, RuleCollection):
            active_rules: Tuple[DetectionRule, ...] = rules.rules
        elif isinstance(rules, (list, tuple)):
            for r in rules:
                if not isinstance(r, DetectionRule):
                    raise TypeError(f"Item in rules is not DetectionRule, got {type(r).__name__}")
            active_rules = tuple(rules)
        else:
            raise TypeError(f"rules must be RuleCollection or sequence of DetectionRules, got {type(rules).__name__}")
    elif cfg.rules is not None:
        active_rules = cfg.rules
    else:
        active_rules = create_canonical_memory_rules().rules

    if not isinstance(artifacts, (list, tuple, set)):
        raise TypeError(f"artifacts must be a sequence of memory artifacts, got {type(artifacts).__name__}")

    # 1. Unpack items and group strictly by evidence_id
    evidence_groups: Dict[str, Dict[str, List[Any]]] = {}
    discrete_artifact_count = 0

    def get_group(eid: str) -> Dict[str, List[Any]]:
        _validate_memory_id(eid)
        if eid not in evidence_groups:
            evidence_groups[eid] = {
                "raw_artifacts": [],
                "memory_events": [],
            }
        return evidence_groups[eid]

    for item in artifacts:
        if isinstance(item, MemoryProcessArtifact):
            grp = get_group(item.evidence_id)
            grp["raw_artifacts"].append(item)
            grp["memory_events"].extend(adapt_process_artifact(item))
            discrete_artifact_count += 1
        elif isinstance(item, ProcessExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["raw_artifacts"].append(art)
                grp["memory_events"].extend(adapt_process_artifact(art))
                discrete_artifact_count += 1
        elif isinstance(item, MemoryModuleArtifact):
            grp = get_group(item.evidence_id)
            grp["raw_artifacts"].append(item)
            grp["memory_events"].extend(adapt_module_artifact(item))
            discrete_artifact_count += 1
        elif isinstance(item, ModuleExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["raw_artifacts"].append(art)
                grp["memory_events"].extend(adapt_module_artifact(art))
                discrete_artifact_count += 1
        elif isinstance(item, MemoryNetworkArtifact):
            grp = get_group(item.evidence_id)
            grp["raw_artifacts"].append(item)
            grp["memory_events"].extend(adapt_network_artifact(item))
            discrete_artifact_count += 1
        elif isinstance(item, NetworkExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["raw_artifacts"].append(art)
                grp["memory_events"].extend(adapt_network_artifact(art))
                discrete_artifact_count += 1
        elif isinstance(item, MemoryTimelineEvent):
            grp = get_group(item.evidence_id)
            grp["raw_artifacts"].append(item)
            grp["memory_events"].append(item)
            discrete_artifact_count += 1
        elif isinstance(item, ReconstructedMemoryTimeline):
            for ev in item.events:
                grp = get_group(ev.evidence_id)
                grp["raw_artifacts"].append(ev)
                grp["memory_events"].append(ev)
                discrete_artifact_count += 1
        else:
            raise TypeError(f"Unsupported artifact type for memory triage: {type(item).__name__}")

    all_canonical_timeline_events: List[TimelineEvent] = []
    all_memory_timeline_events: List[MemoryTimelineEvent] = []
    all_canonical_correlations: List[Correlation] = []
    all_memory_correlations: List[MemoryCorrelation] = []
    all_detections: List[DetectionResult] = []

    detection_engine = DetectionEngine(rules=active_rules)

    # 2. Process each evidence image with STRICT evidence isolation
    for eid in sorted(evidence_groups.keys()):
        grp = evidence_groups[eid]
        raw_arts = grp["raw_artifacts"]
        mem_evts = grp["memory_events"]

        # Reconstruct memory timeline for this evidence image
        recon_timeline = reconstruct_memory_timeline(mem_evts, deduplicate=True)
        evidence_mem_events = list(recon_timeline.events)
        evidence_canonical_events = [e.to_timeline_event() for e in evidence_mem_events]

        # Correlate memory artifacts strictly within this evidence image
        mem_corr_col = correlate_memory_artifacts(raw_arts, config=cfg.correlation_config)
        evidence_mem_corrs = list(mem_corr_col.correlations)
        evidence_canonical_corrs = [c.to_correlation() for c in evidence_mem_corrs]

        # Evaluate detection rules strictly on this evidence image's events and correlations
        det_result_col = detection_engine.evaluate(
            timeline=evidence_canonical_events,
            correlations=evidence_canonical_corrs,
        )

        all_memory_timeline_events.extend(evidence_mem_events)
        all_canonical_timeline_events.extend(evidence_canonical_events)
        all_memory_correlations.extend(evidence_mem_corrs)
        all_canonical_correlations.extend(evidence_canonical_corrs)
        all_detections.extend(det_result_col.results)

    # 3. Sort collections deterministically
    sorted_canonical_events = tuple(sorted(all_canonical_timeline_events, key=timeline_sort_key))
    sorted_memory_events = tuple(sorted(all_memory_timeline_events, key=memory_timeline_sort_key))
    sorted_memory_corrs = tuple(sorted(all_memory_correlations, key=memory_correlation_sort_key))
    sorted_canonical_corrs = tuple(sorted(all_canonical_correlations, key=lambda c: (c.relationship_type.value, c.correlation_id)))
    sorted_detections = tuple(sorted(all_detections, key=detection_sort_key))

    # Apply matched_only filter if configured
    if cfg.matched_only:
        final_detections = tuple(d for d in sorted_detections if d.matched)
    else:
        final_detections = sorted_detections

    final_det_col = DetectionResultCollection(final_detections)

    sorted_eids = tuple(sorted(evidence_groups.keys()))
    triage_id = compute_deterministic_triage_id(
        evidence_ids=sorted_eids,
        artifact_count=discrete_artifact_count,
        detection_count=len(final_det_col),
    )

    # Calculate summary metrics
    matched_count = sum(1 for d in final_det_col if d.matched)
    summary_dict = {
        "evidence_count": len(sorted_eids),
        "total_artifacts": discrete_artifact_count,
        "timeline_events_count": len(sorted_canonical_events),
        "correlations_count": len(sorted_canonical_corrs),
        "detections_evaluated": len(final_det_col),
        "detections_matched": matched_count,
        "active_rules_count": len(active_rules),
    }

    return MemoryTriageResult(
        triage_id=triage_id,
        evidence_ids=sorted_eids,
        total_artifacts=discrete_artifact_count,
        timeline_events=sorted_canonical_events,
        memory_timeline_events=sorted_memory_events,
        correlations=sorted_canonical_corrs,
        memory_correlations=sorted_memory_corrs,
        detections=final_det_col,
        summary=tuple(sorted(summary_dict.items())),
        is_success=True,
        errors=(),
        config=cfg,
    )
