"""
Forensic Memory Correlation Engine for ForensiX (V6.6).

Provides an evidence-backed, deterministic, explainable correlation layer connecting
memory process artifacts (V6.2), kernel module/driver artifacts (V6.3), network socket
artifacts (V6.4), and memory timeline events (V6.5).

Core Architectural Principles:
1. Factual Observation Representation Only:
   - Correlation establishes defensible, evidence-backed relationships.
   - Does NOT infer compromise, persistence, active malicious traffic, or attack execution.
   - Does NOT produce risk or maliciousness scores.
2. Evidence Isolation & Cross-Evidence Boundaries:
   - Scopes PID-based and host-internal relationships strictly to the same evidence image (MEM-<UUID>).
   - Matching PIDs across different memory images are strictly isolated and never equated.
   - Recognizes potential PID reuse when process names diverge at the same PID.
3. No Speculative Linkage:
   - Sockets and processes are correlated ONLY when explicit PID (or source field) supports the link;
     never inferred from temporal proximity alone.
   - Modules and processes are correlated ONLY when defensible path or memory bindings exist;
     never inferred from name similarity alone.
4. Determinism, Immutability & Reproducibility:
   - Every correlation receives a deterministic RFC 4122 UUIDv5 identifier (MEMCORR-<UUIDv5>).
   - Independent of source input order.
   - Completely immutable models with deterministic JSON serialization.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)
import uuid

from forensix.correlation_engine import compute_timestamp_delta
from forensix.correlation_models import (
    Correlation,
    CorrelationType,
)
from forensix.memory_models import (
    FORENSIX_V6_MEMORY_NAMESPACE,
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    ModuleExtractionResult,
    NetworkExtractionResult,
    ProcessExtractionResult,
    _validate_memory_id,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
    ReconstructedMemoryTimeline,
    classify_memory_event_timestamp,
    compute_deterministic_v4_timeline_id,
)
from forensix.timeline_models import (
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)
from forensix.timeline_reconstruction import TimestampClass


class MemoryCorrelationType(str, Enum):
    """Evidence-backed relationship types between memory forensics artifacts."""

    PROCESS_PID_MATCH = "PROCESS_PID_MATCH"
    PARENT_CHILD_PROCESS = "PARENT_CHILD_PROCESS"
    PROCESS_NETWORK_SOCKET = "PROCESS_NETWORK_SOCKET"
    PROCESS_MODULE = "PROCESS_MODULE"
    SHARED_EXECUTION_PROVENANCE = "SHARED_EXECUTION_PROVENANCE"
    SHARED_PLUGIN = "SHARED_PLUGIN"
    SAME_EVIDENCE = "SAME_EVIDENCE"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"


class MemoryCorrelationConfidence(str, Enum):
    """Categorical strength of forensic memory relationships."""

    DIRECT = "DIRECT"
    CONTEXTUAL = "CONTEXTUAL"


def compute_deterministic_memory_correlation_id(
    evidence_id: str,
    relationship_type: Union[MemoryCorrelationType, str],
    artifact_ids: Iterable[str],
    discriminator: Optional[str] = None,
) -> str:
    """
    Generate a deterministic RFC 4122 UUIDv5 correlation identifier (MEMCORR-<UUIDv5>).

    Canonical Inputs:
    - evidence_id: Memory evidence image ID (MEM-<UUID>).
    - relationship_type: Relationship type enum or string.
    - artifact_ids: Iterable of participating artifact IDs, sorted lexicographically.
    - discriminator: Optional secondary discriminator for multiple distinct links between same artifacts.

    Guarantees:
    - Absolute determinism across independent runs.
    - Order independence: artifact_ids are sorted before hashing.
    - Distinct relationships receive distinct IDs.
    """
    clean_eid = str(evidence_id).strip().lower()
    if isinstance(relationship_type, MemoryCorrelationType):
        rel_str = relationship_type.value
    elif isinstance(relationship_type, str):
        rel_str = relationship_type.strip().upper()
    else:
        raise TypeError(f"relationship_type must be MemoryCorrelationType or str, got {type(relationship_type).__name__}")

    clean_ids: List[str] = []
    for aid in artifact_ids:
        s = str(aid).strip()
        if s:
            clean_ids.append(s)

    if not clean_ids:
        raise ValueError("Cannot compute deterministic correlation ID without artifact IDs")

    sorted_ids = sorted(clean_ids)
    key_parts = [
        f"evidence:{clean_eid}",
        f"type:{rel_str}",
        f"artifacts:{','.join(sorted_ids)}",
    ]
    if discriminator is not None and str(discriminator).strip():
        key_parts.append(f"disc:{str(discriminator).strip()}")

    canonical_key = "|".join(key_parts)
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMCORR-{det_uuid}"


def _validate_correlation_id(val: str) -> str:
    """Validate that a string conforms to the ForensiX MEMCORR-<UUID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"correlation_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id.startswith("MEMCORR-"):
        raise ValueError(f"correlation_id must start with 'MEMCORR-', got '{val}'")
    suffix = clean_id[len("MEMCORR-"):].strip()
    try:
        parsed = uuid.UUID(suffix)
        if parsed.version != 5:
            raise ValueError(f"correlation_id UUID must be version 5, got version {parsed.version}")
    except (ValueError, AttributeError) as err:
        raise ValueError(f"correlation_id must contain a valid UUIDv5 suffix, got '{val}'") from err
    return clean_id


@dataclass(frozen=True)
class MemoryCorrelation:
    """
    Immutable representation of an evidence-backed relationship between memory artifacts.

    Fields:
        correlation_id: Deterministic correlation identifier (MEMCORR-<UUIDv5>).
        relationship_type: Specific MemoryCorrelationType enum value.
        evidence_id: Source memory evidence ID (MEM-<UUID>).
        artifact_ids: Canonical sorted tuple of participating artifact/event IDs.
        artifact_categories: Tuple of (artifact_id, category_string) pairs.
        confidence: "DIRECT" (concrete field match) or "CONTEXTUAL" (environmental/proximity link).
        explanation: Concise, non-speculative factual statement explaining the relationship.
        supporting_fields: Deeply frozen tuple of (field_name, observed_value) pairs.
        source_plugins: Tuple of participating Volatility plugins.
        execution_ids: Tuple of participating Volatility execution IDs.
        time_delta_seconds: Absolute time delta in seconds between artifacts, or None.
        temporal_basis: Description of temporal calculation basis, or None.
        temporal_limitations: Explicit explanation of timestamp limitations, or None.
        attributes: Deeply frozen tuple of arbitrary metadata (key, value) pairs.
    """

    correlation_id: str
    relationship_type: MemoryCorrelationType
    evidence_id: str
    artifact_ids: Tuple[str, ...]
    artifact_categories: Tuple[Tuple[str, str], ...] = ()
    confidence: str = "DIRECT"
    explanation: str = ""
    supporting_fields: Tuple[Tuple[str, Any], ...] = ()
    source_plugins: Tuple[str, ...] = ()
    execution_ids: Tuple[str, ...] = ()
    time_delta_seconds: Optional[float] = None
    temporal_basis: Optional[str] = None
    temporal_limitations: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate and deeply freeze all fields upon initialization."""
        # 1. Validate correlation_id
        validated_corr_id = _validate_correlation_id(self.correlation_id)
        object.__setattr__(self, "correlation_id", validated_corr_id)

        # 2. Validate evidence_id
        _validate_memory_id(self.evidence_id)

        # 3. Validate relationship_type
        if isinstance(self.relationship_type, MemoryCorrelationType):
            validated_rel = self.relationship_type
        elif isinstance(self.relationship_type, str):
            try:
                validated_rel = MemoryCorrelationType(self.relationship_type.strip().upper())
            except ValueError as err:
                valid_types = sorted([t.value for t in MemoryCorrelationType])
                raise ValueError(
                    f"Invalid relationship_type: '{self.relationship_type}'. Must be one of: {valid_types}"
                ) from err
        else:
            raise TypeError(
                f"relationship_type must be MemoryCorrelationType or str, got {type(self.relationship_type).__name__}"
            )
        object.__setattr__(self, "relationship_type", validated_rel)

        # 4. Validate artifact_ids
        if not isinstance(self.artifact_ids, (list, tuple)):
            raise TypeError(f"artifact_ids must be a sequence of strings, got {type(self.artifact_ids).__name__}")
        clean_aids = tuple(str(a).strip() for a in self.artifact_ids if str(a).strip())
        if len(clean_aids) < 2:
            raise ValueError(f"artifact_ids must contain at least 2 distinct artifacts, got {clean_aids}")
        # Ensure canonical sorting
        sorted_aids = tuple(sorted(clean_aids))
        object.__setattr__(self, "artifact_ids", sorted_aids)

        # 5. Validate confidence
        if isinstance(self.confidence, MemoryCorrelationConfidence):
            validated_conf = self.confidence.value
        elif isinstance(self.confidence, str):
            clean_conf = self.confidence.strip().upper()
            if clean_conf not in ("DIRECT", "CONTEXTUAL"):
                raise ValueError(f"confidence must be 'DIRECT' or 'CONTEXTUAL', got '{self.confidence}'")
            validated_conf = clean_conf
        else:
            raise TypeError(f"confidence must be str or MemoryCorrelationConfidence, got {type(self.confidence).__name__}")
        object.__setattr__(self, "confidence", validated_conf)

        # 6. Validate explanation
        if not isinstance(self.explanation, str) or not self.explanation.strip():
            raise ValueError("explanation must be a non-empty string")

        # 7. Freeze artifact_categories
        if isinstance(self.artifact_categories, (list, tuple)):
            cats = tuple(
                (str(item[0]).strip(), str(item[1]).strip())
                for item in self.artifact_categories
                if isinstance(item, (list, tuple)) and len(item) == 2
            )
            object.__setattr__(self, "artifact_categories", cats)
        else:
            object.__setattr__(self, "artifact_categories", ())

        # 8. Freeze supporting_fields
        if isinstance(self.supporting_fields, dict):
            frozen_supp = tuple((str(k), freeze_attributes(v)) for k, v in sorted(self.supporting_fields.items()))
            object.__setattr__(self, "supporting_fields", frozen_supp)
        elif isinstance(self.supporting_fields, (list, tuple)):
            clean_supp = []
            for item in self.supporting_fields:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_supp.append((str(item[0]), freeze_attributes(item[1])))
                else:
                    raise TypeError("supporting_fields items must be (key, value) pairs")
            object.__setattr__(self, "supporting_fields", tuple(clean_supp))
        else:
            raise TypeError("supporting_fields must be a sequence of (key, value) pairs or dict")

        # 9. Freeze source_plugins and execution_ids
        if isinstance(self.source_plugins, (list, tuple, set)):
            object.__setattr__(self, "source_plugins", tuple(sorted(set(str(p).strip() for p in self.source_plugins if str(p).strip()))))
        if isinstance(self.execution_ids, (list, tuple, set)):
            object.__setattr__(self, "execution_ids", tuple(sorted(set(str(e).strip() for e in self.execution_ids if str(e).strip()))))

        # 10. Freeze attributes
        if isinstance(self.attributes, dict):
            frozen_attrs = tuple((str(k), freeze_attributes(v)) for k, v in sorted(self.attributes.items()))
            object.__setattr__(self, "attributes", frozen_attrs)
        elif isinstance(self.attributes, (list, tuple)):
            clean_attrs = []
            for item in self.attributes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_attrs.append((str(item[0]), freeze_attributes(item[1])))
                else:
                    raise TypeError("attributes items must be (key, value) pairs")
            object.__setattr__(self, "attributes", tuple(clean_attrs))
        else:
            raise TypeError("attributes must be a sequence of (key, value) pairs or dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert memory correlation to a deterministic JSON-serializable dictionary."""
        return {
            "correlation_id": self.correlation_id,
            "relationship_type": self.relationship_type.value if hasattr(self.relationship_type, "value") else str(self.relationship_type),
            "evidence_id": self.evidence_id,
            "artifact_ids": list(self.artifact_ids),
            "artifact_categories": [list(c) for c in self.artifact_categories],
            "confidence": self.confidence,
            "explanation": self.explanation,
            "supporting_fields": unfreeze_to_dict(self.supporting_fields),
            "source_plugins": list(self.source_plugins),
            "execution_ids": list(self.execution_ids),
            "time_delta_seconds": self.time_delta_seconds,
            "temporal_basis": self.temporal_basis,
            "temporal_limitations": self.temporal_limitations,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize memory correlation to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_correlation(self) -> Correlation:
        """
        Adapt this MemoryCorrelation directly into a canonical V4.1 Timeline Correlation.

        Bridges memory correlation into the timeline correlation reporting layer.
        """
        # Map MemoryCorrelationType to closest canonical CorrelationType
        if self.relationship_type == MemoryCorrelationType.TEMPORAL_PROXIMITY:
            canonical_rel = CorrelationType.TEMPORAL
        elif self.relationship_type in (
            MemoryCorrelationType.PROCESS_PID_MATCH,
            MemoryCorrelationType.PARENT_CHILD_PROCESS,
            MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            MemoryCorrelationType.PROCESS_MODULE,
        ):
            canonical_rel = CorrelationType.HOST_NETWORK if self.relationship_type == MemoryCorrelationType.PROCESS_NETWORK_SOCKET else CorrelationType.SAME_SOURCE
        else:
            canonical_rel = CorrelationType.SAME_SOURCE

        # Compute deterministic V4 CORR-<UUIDv4/v5> identifier
        det_v4_uuid = compute_deterministic_v4_timeline_id(self.correlation_id)
        v4_corr_id = f"CORR-{det_v4_uuid}"

        merged_attrs: Dict[str, Any] = dict(unfreeze_to_dict(self.attributes))
        merged_attrs["evidence_id"] = self.evidence_id
        merged_attrs["memory_correlation_id"] = self.correlation_id
        merged_attrs["memory_relationship_type"] = self.relationship_type.value if hasattr(self.relationship_type, "value") else str(self.relationship_type)
        merged_attrs["confidence"] = self.confidence
        merged_attrs["supporting_fields"] = unfreeze_to_dict(self.supporting_fields)
        if self.source_plugins:
            merged_attrs["source_plugins"] = list(self.source_plugins)
        if self.execution_ids:
            merged_attrs["execution_ids"] = list(self.execution_ids)
        if self.temporal_basis:
            merged_attrs["temporal_basis"] = self.temporal_basis
        if self.temporal_limitations:
            merged_attrs["temporal_limitations"] = self.temporal_limitations

        canonical_event_ids = tuple(
            f"TIMELINE-{compute_deterministic_v4_timeline_id(aid)}"
            for aid in self.artifact_ids
        )

        return Correlation(
            correlation_id=v4_corr_id,
            relationship_type=canonical_rel,
            event_ids=canonical_event_ids,
            description=self.explanation,
            source_artifact_ids=self.artifact_ids,
            time_delta_seconds=self.time_delta_seconds,
            attributes=merged_attrs,
            explanation=self.explanation,
        )


@dataclass(frozen=True)
class MemoryCorrelationCollection:
    """
    Immutable collection of ordered, deduplicated memory correlations.

    Attributes:
        correlations: Immutable tuple of MemoryCorrelation instances.
        total_correlations: Count of correlations in collection.
        relationship_counts: Tuple of (relationship_type, count) pairs.
        evidence_counts: Tuple of (evidence_id, count) pairs.
        direct_count: Count of DIRECT confidence relationships.
        contextual_count: Count of CONTEXTUAL confidence relationships.
    """

    correlations: Tuple[MemoryCorrelation, ...]
    total_correlations: int
    relationship_counts: Tuple[Tuple[str, int], ...]
    evidence_counts: Tuple[Tuple[str, int], ...]
    direct_count: int
    contextual_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.correlations, tuple):
            object.__setattr__(self, "correlations", tuple(self.correlations))
        if not isinstance(self.relationship_counts, tuple):
            object.__setattr__(self, "relationship_counts", tuple(self.relationship_counts))
        if not isinstance(self.evidence_counts, tuple):
            object.__setattr__(self, "evidence_counts", tuple(self.evidence_counts))

    def __len__(self) -> int:
        return len(self.correlations)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.correlations[idx]

    def __iter__(self) -> Iterator[MemoryCorrelation]:
        return iter(self.correlations)

    @property
    def summary(self) -> Dict[str, Any]:
        """Summary metrics in stable dictionary order."""
        return {
            "total_correlations": self.total_correlations,
            "direct_relationships": self.direct_count,
            "contextual_relationships": self.contextual_count,
            "relationship_counts": dict(self.relationship_counts),
            "evidence_counts": dict(self.evidence_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert collection to a JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "correlations": [corr.to_dict() for corr in self.correlations],
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize collection to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def filter(
        self,
        relationship_type: Optional[Union[MemoryCorrelationType, str]] = None,
        confidence: Optional[Union[MemoryCorrelationConfidence, str]] = None,
        evidence_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
    ) -> "MemoryCorrelationCollection":
        """Filter correlations deterministically by criteria."""
        filtered: List[MemoryCorrelation] = []

        target_rel = None
        if relationship_type is not None:
            target_rel = relationship_type.value if hasattr(relationship_type, "value") else str(relationship_type).strip().upper()

        target_conf = None
        if confidence is not None:
            target_conf = confidence.value if hasattr(confidence, "value") else str(confidence).strip().upper()

        target_eid = evidence_id.strip() if evidence_id else None
        target_aid = artifact_id.strip() if artifact_id else None

        for corr in self.correlations:
            if target_rel:
                corr_rel = corr.relationship_type.value if hasattr(corr.relationship_type, "value") else str(corr.relationship_type)
                if corr_rel != target_rel:
                    continue
            if target_conf and corr.confidence != target_conf:
                continue
            if target_eid and corr.evidence_id != target_eid:
                continue
            if target_aid and target_aid not in corr.artifact_ids:
                continue
            filtered.append(corr)

        return _build_correlation_collection(filtered)


def _build_correlation_collection(correlations: Sequence[MemoryCorrelation]) -> MemoryCorrelationCollection:
    """Helper to construct an immutable MemoryCorrelationCollection with computed metrics."""
    rel_counts: Counter = Counter()
    eid_counts: Counter = Counter()
    direct_n = 0
    contextual_n = 0

    for corr in correlations:
        rel_str = corr.relationship_type.value if hasattr(corr.relationship_type, "value") else str(corr.relationship_type)
        rel_counts[rel_str] += 1
        eid_counts[corr.evidence_id] += 1
        if corr.confidence == "DIRECT":
            direct_n += 1
        else:
            contextual_n += 1

    sorted_rels = tuple(sorted(rel_counts.items()))
    sorted_eids = tuple(sorted(eid_counts.items()))

    return MemoryCorrelationCollection(
        correlations=tuple(correlations),
        total_correlations=len(correlations),
        relationship_counts=sorted_rels,
        evidence_counts=sorted_eids,
        direct_count=direct_n,
        contextual_count=contextual_n,
    )


@dataclass(frozen=True)
class MemoryCorrelationConfig:
    """
    Configuration options for memory artifact correlation.

    Attributes:
        include_pid_matches: Correlate processes sharing the same PID in same evidence image.
        include_parent_child: Correlate parent and child processes via ppid.
        include_network_sockets: Correlate network sockets to processes via socket.pid.
        include_module_associations: Correlate modules to processes via verified driver_path or memory offset.
        include_execution_provenance: Correlate artifacts sharing the same Volatility execution_id.
        include_shared_plugin: Correlate artifacts extracted via the same plugin in same evidence image.
        include_same_evidence: Correlate cross-category artifacts sharing same evidence image.
        include_temporal_proximity: Correlate timestamps within time window.
        temporal_window_seconds: Maximum delta in seconds for temporal relationships.
        allowed_relationship_types: Optional explicit set of enabled relationship types.
    """

    include_pid_matches: bool = True
    include_parent_child: bool = True
    include_network_sockets: bool = True
    include_module_associations: bool = True
    include_execution_provenance: bool = True
    include_shared_plugin: bool = False
    include_same_evidence: bool = False
    include_temporal_proximity: bool = False
    temporal_window_seconds: float = 300.0
    allowed_relationship_types: Optional[Tuple[MemoryCorrelationType, ...]] = None


def memory_correlation_sort_key(corr: MemoryCorrelation) -> Tuple[Any, ...]:
    """
    Construct a deterministic, type-safe comparison key for a MemoryCorrelation.

    Ordering Hierarchy:
    1. Evidence ID (lexicographical)
    2. Relationship Type (lexicographical)
    3. Confidence ("DIRECT" precedes "CONTEXTUAL")
    4. Joined artifact IDs (lexicographical)
    5. Correlation ID (lexicographical)
    """
    conf_rank = 0 if corr.confidence == "DIRECT" else 1
    rel_name = corr.relationship_type.value if hasattr(corr.relationship_type, "value") else str(corr.relationship_type)
    return (
        corr.evidence_id,
        rel_name,
        conf_rank,
        ",".join(corr.artifact_ids),
        corr.correlation_id,
    )


def _parse_artifact_timestamp(art: Any) -> Optional[datetime]:
    """Extract a typed datetime from an artifact if available."""
    if isinstance(art, MemoryTimelineEvent):
        return art.timestamp
    if isinstance(art, (MemoryProcessArtifact, MemoryNetworkArtifact)):
        ts_str = getattr(art, "created_at", None)
        if ts_str and isinstance(ts_str, str):
            clean = ts_str.strip()
            if clean and clean.lower() not in ("none", "null", "n/a", "-"):
                try:
                    return datetime.fromisoformat(clean)
                except (ValueError, TypeError):
                    return None
    return None


def _get_raw_attribute(artifact: Any, key: str) -> Any:
    """Safely extract an attribute from raw_attributes whether it is a dict, tuple, or _FrozenDict."""
    raw = getattr(artifact, "raw_attributes", None)
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw.get(key)
    if isinstance(raw, (tuple, list)):
        for item in raw:
            if isinstance(item, (tuple, list)) and len(item) == 2 and item[0] == key:
                return item[1]
    return None


def correlate_memory_artifacts(
    items: Sequence[Any],
    config: Optional[MemoryCorrelationConfig] = None,
) -> MemoryCorrelationCollection:
    """
    Discover, correlate, and index evidence-backed relationships across memory artifacts.

    Accepts sequences containing:
    - MemoryProcessArtifact / ProcessExtractionResult
    - MemoryModuleArtifact / ModuleExtractionResult
    - MemoryNetworkArtifact / NetworkExtractionResult
    - MemoryTimelineEvent / ReconstructedMemoryTimeline

    Guarantees:
    - Evidence Isolation: PID, socket, and module linkages are strictly isolated per evidence image.
    - Determinism: Canonical edge representation and stable sorting produce identical output
      regardless of input sequence ordering.
    - Duplicate Suppression: Identical relationship edges between the same artifacts are consolidated.
    - Zero Speculation: Does not infer socket connections or module ownership without explicit field evidence.
    """
    cfg = config or MemoryCorrelationConfig()

    # 1. Unpack items into structured collections per evidence_id
    evidence_groups: Dict[str, Dict[str, List[Any]]] = {}

    def get_group(eid: str) -> Dict[str, List[Any]]:
        if eid not in evidence_groups:
            evidence_groups[eid] = {
                "processes": [],
                "modules": [],
                "networks": [],
                "timeline_events": [],
                "all_artifacts": [],
            }
        return evidence_groups[eid]

    for item in items:
        if isinstance(item, MemoryProcessArtifact):
            grp = get_group(item.evidence_id)
            grp["processes"].append(item)
            grp["all_artifacts"].append(item)
        elif isinstance(item, ProcessExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["processes"].append(art)
                grp["all_artifacts"].append(art)
        elif isinstance(item, MemoryModuleArtifact):
            grp = get_group(item.evidence_id)
            grp["modules"].append(item)
            grp["all_artifacts"].append(item)
        elif isinstance(item, ModuleExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["modules"].append(art)
                grp["all_artifacts"].append(art)
        elif isinstance(item, MemoryNetworkArtifact):
            grp = get_group(item.evidence_id)
            grp["networks"].append(item)
            grp["all_artifacts"].append(item)
        elif isinstance(item, NetworkExtractionResult):
            for art in item.artifacts:
                grp = get_group(art.evidence_id)
                grp["networks"].append(art)
                grp["all_artifacts"].append(art)
        elif isinstance(item, MemoryTimelineEvent):
            grp = get_group(item.evidence_id)
            grp["timeline_events"].append(item)
            grp["all_artifacts"].append(item)
        elif isinstance(item, ReconstructedMemoryTimeline):
            for evt in item.events:
                grp = get_group(evt.evidence_id)
                grp["timeline_events"].append(evt)
                grp["all_artifacts"].append(evt)
        else:
            raise TypeError(f"Unsupported item type for memory correlation: {type(item).__name__}")

    # Deduplicate edges: key = (evidence_id, relationship_type, canonical_artifact_ids_tuple)
    discovered_edges: Dict[Tuple[str, MemoryCorrelationType, Tuple[str, ...]], MemoryCorrelation] = {}

    def is_type_allowed(rel_type: MemoryCorrelationType) -> bool:
        if cfg.allowed_relationship_types is not None:
            return rel_type in cfg.allowed_relationship_types
        return True

    # 2. Iterate each evidence image independently (Strict Evidence Isolation)
    for eid, grp in sorted(evidence_groups.items()):
        processes: List[MemoryProcessArtifact] = grp["processes"]
        modules: List[MemoryModuleArtifact] = grp["modules"]
        networks: List[MemoryNetworkArtifact] = grp["networks"]
        all_arts: List[Any] = grp["all_artifacts"]

        # Deduplicate artifacts by artifact_id or event_id within group to prevent self-pairing
        proc_by_id: Dict[str, MemoryProcessArtifact] = {}
        for p in processes:
            proc_by_id[p.artifact_id] = p
        unique_procs = sorted(proc_by_id.values(), key=lambda x: x.artifact_id)

        mod_by_id: Dict[str, MemoryModuleArtifact] = {}
        for m in modules:
            mod_by_id[m.artifact_id] = m
        unique_mods = sorted(mod_by_id.values(), key=lambda x: x.artifact_id)

        net_by_id: Dict[str, MemoryNetworkArtifact] = {}
        for n in networks:
            net_by_id[n.artifact_id] = n
        unique_nets = sorted(net_by_id.values(), key=lambda x: x.artifact_id)

        # Index processes by PID
        procs_by_pid: Dict[int, List[MemoryProcessArtifact]] = {}
        for p in unique_procs:
            if p.pid is not None:
                procs_by_pid.setdefault(p.pid, []).append(p)

        # RULE 1: PROCESS_PID_MATCH (Processes sharing same PID across plugins in same image)
        if cfg.include_pid_matches and is_type_allowed(MemoryCorrelationType.PROCESS_PID_MATCH):
            for pid, p_list in sorted(procs_by_pid.items()):
                if len(p_list) > 1:
                    # Pairwise combinations of processes with same PID
                    for i in range(len(p_list)):
                        for j in range(i + 1, len(p_list)):
                            p1, p2 = p_list[i], p_list[j]
                            aids = tuple(sorted([p1.artifact_id, p2.artifact_id]))
                            edge_key = (eid, MemoryCorrelationType.PROCESS_PID_MATCH, aids)
                            if edge_key not in discovered_edges:
                                # Check name concordance to detect PID reuse
                                name_concordant = p1.process_name.lower() == p2.process_name.lower()
                                pid_reuse = not name_concordant

                                supp = [
                                    ("pid", pid),
                                    ("process_name_1", p1.process_name),
                                    ("process_name_2", p2.process_name),
                                    ("name_concordant", name_concordant),
                                ]
                                if pid_reuse:
                                    supp.append(("pid_reuse_suspected", True))
                                    expl = (
                                        f"Process artifacts share PID {pid} within evidence {eid} "
                                        f"with divergent names ('{p1.process_name}' vs '{p2.process_name}'); potential PID reuse"
                                    )
                                else:
                                    expl = (
                                        f"Process artifacts concordantly observe PID {pid} ('{p1.process_name}') "
                                        f"within evidence {eid} (plugins: {p1.source_plugin}, {p2.source_plugin})"
                                    )

                                corr_id = compute_deterministic_memory_correlation_id(
                                    evidence_id=eid,
                                    relationship_type=MemoryCorrelationType.PROCESS_PID_MATCH,
                                    artifact_ids=aids,
                                )
                                cats = ((p1.artifact_id, "process"), (p2.artifact_id, "process"))
                                plugins = tuple(sorted(set([p1.source_plugin, p2.source_plugin])))
                                exec_ids = tuple(sorted(set([e for e in (p1.execution_id, p2.execution_id) if e])))

                                discovered_edges[edge_key] = MemoryCorrelation(
                                    correlation_id=corr_id,
                                    relationship_type=MemoryCorrelationType.PROCESS_PID_MATCH,
                                    evidence_id=eid,
                                    artifact_ids=aids,
                                    artifact_categories=cats,
                                    confidence="DIRECT",
                                    explanation=expl,
                                    supporting_fields=tuple(supp),
                                    source_plugins=plugins,
                                    execution_ids=exec_ids,
                                )

        # RULE 2: PARENT_CHILD_PROCESS (Child references parent via ppid)
        if cfg.include_parent_child and is_type_allowed(MemoryCorrelationType.PARENT_CHILD_PROCESS):
            for child in unique_procs:
                if child.ppid is not None and child.ppid > 0:
                    parent_candidates = procs_by_pid.get(child.ppid, [])
                    for parent in parent_candidates:
                        if parent.artifact_id != child.artifact_id:
                            aids = tuple(sorted([parent.artifact_id, child.artifact_id]))
                            edge_key = (eid, MemoryCorrelationType.PARENT_CHILD_PROCESS, aids)
                            if edge_key not in discovered_edges:
                                supp = [
                                    ("parent_pid", parent.pid),
                                    ("child_pid", child.pid),
                                    ("parent_name", parent.process_name),
                                    ("child_name", child.process_name),
                                    ("child_ppid", child.ppid),
                                ]
                                expl = (
                                    f"Process '{child.process_name}' (PID {child.pid}) references "
                                    f"parent PID {child.ppid} corresponding to '{parent.process_name}' (PID {parent.pid})"
                                )
                                corr_id = compute_deterministic_memory_correlation_id(
                                    evidence_id=eid,
                                    relationship_type=MemoryCorrelationType.PARENT_CHILD_PROCESS,
                                    artifact_ids=aids,
                                )
                                cats = ((parent.artifact_id, "process"), (child.artifact_id, "process"))
                                plugins = tuple(sorted(set([parent.source_plugin, child.source_plugin])))
                                exec_ids = tuple(sorted(set([e for e in (parent.execution_id, child.execution_id) if e])))

                                discovered_edges[edge_key] = MemoryCorrelation(
                                    correlation_id=corr_id,
                                    relationship_type=MemoryCorrelationType.PARENT_CHILD_PROCESS,
                                    evidence_id=eid,
                                    artifact_ids=aids,
                                    artifact_categories=cats,
                                    confidence="DIRECT",
                                    explanation=expl,
                                    supporting_fields=tuple(supp),
                                    source_plugins=plugins,
                                    execution_ids=exec_ids,
                                )

        # RULE 3: PROCESS_NETWORK_SOCKET (Socket references process PID)
        if cfg.include_network_sockets and is_type_allowed(MemoryCorrelationType.PROCESS_NETWORK_SOCKET):
            for sock in unique_nets:
                if sock.pid is not None and sock.pid > 0:
                    matching_procs = procs_by_pid.get(sock.pid, [])
                    for proc in matching_procs:
                        aids = tuple(sorted([proc.artifact_id, sock.artifact_id]))
                        edge_key = (eid, MemoryCorrelationType.PROCESS_NETWORK_SOCKET, aids)
                        if edge_key not in discovered_edges:
                            name_concordant = None
                            if sock.process_name:
                                name_concordant = sock.process_name.lower() == proc.process_name.lower()

                            supp = [
                                ("pid", proc.pid),
                                ("protocol", sock.protocol),
                                ("process_name", proc.process_name),
                            ]
                            if sock.local_address or sock.local_port is not None:
                                supp.append(("local_endpoint", f"{sock.local_address or '*'}:{sock.local_port if sock.local_port is not None else '*'}"))
                            if sock.remote_address or sock.remote_port is not None:
                                supp.append(("remote_endpoint", f"{sock.remote_address or '*'}:{sock.remote_port if sock.remote_port is not None else '*'}"))
                            if sock.state:
                                supp.append(("state", sock.state))
                            if name_concordant is not None:
                                supp.append(("name_concordant", name_concordant))

                            expl = (
                                f"Network socket {sock.protocol} (PID {sock.pid}) explicitly bound to "
                                f"process '{proc.process_name}' (PID {proc.pid}) in evidence {eid}"
                            )
                            corr_id = compute_deterministic_memory_correlation_id(
                                evidence_id=eid,
                                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                                artifact_ids=aids,
                            )
                            cats = ((proc.artifact_id, "process"), (sock.artifact_id, "network_socket"))
                            plugins = tuple(sorted(set([proc.source_plugin, sock.source_plugin])))
                            exec_ids = tuple(sorted(set([e for e in (proc.execution_id, sock.execution_id) if e])))

                            discovered_edges[edge_key] = MemoryCorrelation(
                                correlation_id=corr_id,
                                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                                evidence_id=eid,
                                artifact_ids=aids,
                                artifact_categories=cats,
                                confidence="DIRECT",
                                explanation=expl,
                                supporting_fields=tuple(supp),
                                source_plugins=plugins,
                                execution_ids=exec_ids,
                            )

        # RULE 4: PROCESS_MODULE (Defensible path/address binding; never name similarity alone)
        if cfg.include_module_associations and is_type_allowed(MemoryCorrelationType.PROCESS_MODULE):
            for proc in unique_procs:
                proc_image = str(_get_raw_attribute(proc, "ImagePath") or "").strip().lower()
                for mod in unique_mods:
                    mod_path = str(mod.driver_path or "").strip().lower()
                    binding_found = False
                    binding_field = ""
                    binding_val = ""

                    # 1. Driver path match against process image path
                    if mod_path and proc_image and (mod_path == proc_image or mod_path.endswith(proc_image) or proc_image.endswith(mod_path)):
                        binding_found = True
                        binding_field = "path_binding"
                        binding_val = mod.driver_path or ""
                    # 2. Base address memory binding
                    else:
                        mem_regions = str(_get_raw_attribute(proc, "MemoryRegions") or "")
                        if mod.base_address and mod.base_address in mem_regions:
                            binding_found = True
                            binding_field = "base_address_binding"
                            binding_val = str(mod.base_address)

                    if binding_found:
                        aids = tuple(sorted([proc.artifact_id, mod.artifact_id]))
                        edge_key = (eid, MemoryCorrelationType.PROCESS_MODULE, aids)
                        if edge_key not in discovered_edges:
                            supp = [
                                ("process_name", proc.process_name),
                                ("module_name", mod.module_name),
                                ("binding_field", binding_field),
                                ("binding_value", binding_val),
                            ]
                            expl = (
                                f"Kernel module '{mod.module_name}' associated with process '{proc.process_name}' "
                                f"via explicit {binding_field} in evidence {eid}"
                            )
                            corr_id = compute_deterministic_memory_correlation_id(
                                evidence_id=eid,
                                relationship_type=MemoryCorrelationType.PROCESS_MODULE,
                                artifact_ids=aids,
                            )
                            cats = ((proc.artifact_id, "process"), (mod.artifact_id, "kernel_module"))
                            plugins = tuple(sorted(set([proc.source_plugin, mod.source_plugin])))
                            exec_ids = tuple(sorted(set([e for e in (proc.execution_id, mod.execution_id) if e])))

                            discovered_edges[edge_key] = MemoryCorrelation(
                                correlation_id=corr_id,
                                relationship_type=MemoryCorrelationType.PROCESS_MODULE,
                                evidence_id=eid,
                                artifact_ids=aids,
                                artifact_categories=cats,
                                confidence="DIRECT",
                                explanation=expl,
                                supporting_fields=tuple(supp),
                                source_plugins=plugins,
                                execution_ids=exec_ids,
                            )

        # RULE 5: SHARED_EXECUTION_PROVENANCE (Artifacts sharing same execution_id)
        if cfg.include_execution_provenance and is_type_allowed(MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE):
            exec_groups: Dict[str, List[Any]] = {}
            for item in all_arts:
                xid = getattr(item, "execution_id", None)
                if xid and str(xid).strip():
                    exec_groups.setdefault(str(xid).strip(), []).append(item)

            for xid, x_arts in sorted(exec_groups.items()):
                # Group by artifact_id to avoid redundant pairs from same artifact
                unique_x_arts = {}
                for a in x_arts:
                    aid = getattr(a, "artifact_id", getattr(a, "event_id", None))
                    if aid:
                        unique_x_arts[aid] = a
                sorted_x_list = sorted(unique_x_arts.values(), key=lambda a: getattr(a, "artifact_id", getattr(a, "event_id", "")))

                for i in range(len(sorted_x_list)):
                    for j in range(i + 1, len(sorted_x_list)):
                        a1, a2 = sorted_x_list[i], sorted_x_list[j]
                        id1 = getattr(a1, "artifact_id", getattr(a1, "event_id", ""))
                        id2 = getattr(a2, "artifact_id", getattr(a2, "event_id", ""))
                        if id1 != id2:
                            aids = tuple(sorted([id1, id2]))
                            edge_key = (eid, MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE, aids)
                            if edge_key not in discovered_edges:
                                supp = [("execution_id", xid)]
                                expl = f"Artifacts share Volatility execution provenance '{xid}' in evidence {eid}"
                                corr_id = compute_deterministic_memory_correlation_id(
                                    evidence_id=eid,
                                    relationship_type=MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE,
                                    artifact_ids=aids,
                                )
                                plugins = tuple(sorted(set([getattr(a1, "source_plugin", ""), getattr(a2, "source_plugin", "")])))
                                discovered_edges[edge_key] = MemoryCorrelation(
                                    correlation_id=corr_id,
                                    relationship_type=MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE,
                                    evidence_id=eid,
                                    artifact_ids=aids,
                                    confidence="CONTEXTUAL",
                                    explanation=expl,
                                    supporting_fields=tuple(supp),
                                    source_plugins=tuple(p for p in plugins if p),
                                    execution_ids=(xid,),
                                )

        # RULE 6: SHARED_PLUGIN (Artifacts extracted via same plugin in same evidence image)
        if cfg.include_shared_plugin and is_type_allowed(MemoryCorrelationType.SHARED_PLUGIN):
            plugin_groups: Dict[str, List[Any]] = {}
            for item in all_arts:
                plug = getattr(item, "source_plugin", None)
                if plug and str(plug).strip():
                    plugin_groups.setdefault(str(plug).strip(), []).append(item)

            for plug, p_arts in sorted(plugin_groups.items()):
                unique_p_arts = {}
                for a in p_arts:
                    aid = getattr(a, "artifact_id", getattr(a, "event_id", None))
                    if aid and str(aid).strip():
                        unique_p_arts[str(aid).strip()] = a
                sorted_p_list = sorted(unique_p_arts.values(), key=lambda a: getattr(a, "artifact_id", getattr(a, "event_id", "")))

                for i in range(len(sorted_p_list)):
                    for j in range(i + 1, len(sorted_p_list)):
                        a1, a2 = sorted_p_list[i], sorted_p_list[j]
                        id1 = getattr(a1, "artifact_id", getattr(a1, "event_id", ""))
                        id2 = getattr(a2, "artifact_id", getattr(a2, "event_id", ""))
                        if id1 != id2:
                            aids = tuple(sorted([id1, id2]))
                            edge_key = (eid, MemoryCorrelationType.SHARED_PLUGIN, aids)
                            if edge_key not in discovered_edges:
                                supp = [("source_plugin", plug)]
                                expl = f"Artifacts share Volatility plugin provenance '{plug}' in evidence {eid}"
                                corr_id = compute_deterministic_memory_correlation_id(
                                    evidence_id=eid,
                                    relationship_type=MemoryCorrelationType.SHARED_PLUGIN,
                                    artifact_ids=aids,
                                )
                                exec_ids = tuple(sorted(set([e for e in (getattr(a1, "execution_id", None), getattr(a2, "execution_id", None)) if e])))
                                discovered_edges[edge_key] = MemoryCorrelation(
                                    correlation_id=corr_id,
                                    relationship_type=MemoryCorrelationType.SHARED_PLUGIN,
                                    evidence_id=eid,
                                    artifact_ids=aids,
                                    confidence="CONTEXTUAL",
                                    explanation=expl,
                                    supporting_fields=tuple(supp),
                                    source_plugins=(plug,),
                                    execution_ids=exec_ids,
                                )

        # RULE 7: TEMPORAL_PROXIMITY (Comparable timestamps within configured time window)
        if cfg.include_temporal_proximity and is_type_allowed(MemoryCorrelationType.TEMPORAL_PROXIMITY):
            # Collect items with timestamps
            timed_arts: List[Tuple[str, datetime, Any]] = []
            for a in all_arts:
                aid = getattr(a, "artifact_id", getattr(a, "event_id", None))
                if aid:
                    dt = _parse_artifact_timestamp(a)
                    if dt is not None:
                        timed_arts.append((aid, dt, a))

            # Deduplicate by artifact_id
            unique_timed = {}
            for aid, dt, a in timed_arts:
                if aid not in unique_timed:
                    unique_timed[aid] = (dt, a)

            sorted_timed = sorted(unique_timed.items(), key=lambda x: x[0])
            for i in range(len(sorted_timed)):
                aid1, (dt1, a1) = sorted_timed[i]
                for j in range(i + 1, len(sorted_timed)):
                    aid2, (dt2, a2) = sorted_timed[j]
                    delta = compute_timestamp_delta(dt1, dt2)
                    if delta is not None and delta <= cfg.temporal_window_seconds:
                        aids = tuple(sorted([aid1, aid2]))
                        edge_key = (eid, MemoryCorrelationType.TEMPORAL_PROXIMITY, aids)
                        if edge_key not in discovered_edges:
                            supp = [
                                ("time_delta_seconds", round(delta, 3)),
                                ("timestamp_1", dt1.isoformat()),
                                ("timestamp_2", dt2.isoformat()),
                            ]
                            expl = f"Observations occurred within {delta:.2f}s (window: {cfg.temporal_window_seconds}s) in evidence {eid}"
                            corr_id = compute_deterministic_memory_correlation_id(
                                evidence_id=eid,
                                relationship_type=MemoryCorrelationType.TEMPORAL_PROXIMITY,
                                artifact_ids=aids,
                            )
                            plugins = tuple(sorted(set([getattr(a1, "source_plugin", ""), getattr(a2, "source_plugin", "")])))
                            exec_ids = tuple(sorted(set([e for e in (getattr(a1, "execution_id", None), getattr(a2, "execution_id", None)) if e])))
                            discovered_edges[edge_key] = MemoryCorrelation(
                                correlation_id=corr_id,
                                relationship_type=MemoryCorrelationType.TEMPORAL_PROXIMITY,
                                evidence_id=eid,
                                artifact_ids=aids,
                                confidence="CONTEXTUAL",
                                explanation=expl,
                                supporting_fields=tuple(supp),
                                source_plugins=tuple(p for p in plugins if p),
                                execution_ids=exec_ids,
                                time_delta_seconds=delta,
                                temporal_basis=f"Comparable timestamps delta {delta:.2f}s <= {cfg.temporal_window_seconds}s",
                            )

        # RULE 8: SAME_EVIDENCE (Contextual link across distinct artifact categories)
        if cfg.include_same_evidence and is_type_allowed(MemoryCorrelationType.SAME_EVIDENCE):
            # Pair cross-category artifacts within same evidence
            for p in unique_procs:
                for m in unique_mods:
                    aids = tuple(sorted([p.artifact_id, m.artifact_id]))
                    edge_key = (eid, MemoryCorrelationType.SAME_EVIDENCE, aids)
                    if edge_key not in discovered_edges:
                        corr_id = compute_deterministic_memory_correlation_id(
                            evidence_id=eid,
                            relationship_type=MemoryCorrelationType.SAME_EVIDENCE,
                            artifact_ids=aids,
                        )
                        discovered_edges[edge_key] = MemoryCorrelation(
                            correlation_id=corr_id,
                            relationship_type=MemoryCorrelationType.SAME_EVIDENCE,
                            evidence_id=eid,
                            artifact_ids=aids,
                            confidence="CONTEXTUAL",
                            explanation=f"Process and kernel module co-located in memory evidence image {eid}",
                            source_plugins=tuple(sorted(set([p.source_plugin, m.source_plugin]))),
                        )

    # 3. Sort correlations deterministically
    sorted_correlations = sorted(discovered_edges.values(), key=memory_correlation_sort_key)
    return _build_correlation_collection(sorted_correlations)
