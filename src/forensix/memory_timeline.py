"""
Forensic Memory Timeline Integration Layer for ForensiX (V6.5).

Integrates extracted memory evidence artifacts (V6.2 process observations, V6.3 kernel modules
and drivers, and V6.4 network sockets and connections) into a deterministic, chronological
forensic timeline while strictly preserving provenance, temporal accuracy, and the boundary
between observed facts and derived relationships.

Core Architectural Principles:
1. Factual Observation vs Speculation:
   - Events represent memory structures observed at acquisition time.
   - Does NOT infer compromise, persistence, active malicious traffic, or attack execution.
2. Temporal Accuracy & Non-Fabrication:
   - Does NOT invent timestamps when memory artifacts lack reliable timestamps.
   - Does NOT substitute memory acquisition time for artifact creation time.
   - Preserves timezone offsets when present; preserves naive timestamps without synthetic offsets;
     records unanchored events (timestamp=None) explicitly with documented limitations.
3. Complete Provenance Traceability:
   - Retains evidence ID (MEM-<UUID>), artifact ID (MEMPROC-, MEMMOD-, MEMNET-), Volatility execution ID
     (VOLEXEC-), source plugin, and original source-row indices.
4. Deterministic Identity & Conservative Deduplication:
   - Every event receives a reproducible MEMEVT-<UUIDv5> identifier derived from canonical facts.
   - Interoperable with canonical V3.1 TimelineEvent structures via deterministic TIMELINE-<UUIDv4>.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union
import uuid

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
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)
from forensix.timeline_reconstruction import (
    TimestampClass,
)
from forensix.timestamp_normalizer import (
    format_iso_timestamp,
    normalize_timestamp,
)


class MemoryTimelineCategory(str, Enum):
    """Factual forensic categorization of memory timeline observations."""

    PROCESS = "process"
    KERNEL_MODULE = "kernel_module"
    NETWORK_SOCKET = "network_socket"


def compute_deterministic_memory_event_id(
    evidence_id: str,
    artifact_id: str,
    event_type: str,
    timestamp_origin: str = "none",
) -> str:
    """
    Generate a deterministic RFC 4122 UUIDv5 identifier for a memory timeline event (MEMEVT-<UUIDv5>).

    Inputs:
    - evidence_id: Source memory evidence ID (e.g. 'MEM-<UUID>').
    - artifact_id: Source memory artifact ID (e.g. 'MEMPROC-...', 'MEMMOD-...', 'MEMNET-...').
    - event_type: Factual event type classification string.
    - timestamp_origin: Origin of event timestamp ('source_created_at', 'source_exit_time', 'none').

    Guarantees:
    - Absolute determinism across independent runs.
    - Distinct events generated from the same artifact (e.g. creation vs exit) receive distinct IDs.
    """
    clean_eid = str(evidence_id).strip().lower()
    clean_aid = str(artifact_id).strip()
    clean_type = str(event_type).strip().lower()
    clean_origin = str(timestamp_origin).strip().lower()

    canonical_key = (
        f"evidence:{clean_eid}|artifact:{clean_aid}|type:{clean_type}|origin:{clean_origin}"
    )
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMEVT-{det_uuid}"


def compute_deterministic_v4_timeline_id(canonical_key: str) -> str:
    """
    Compute a deterministic UUIDv4 tracking identifier compatible with V3.1 TimelineEvent validation.

    Constructs an RFC 4122 version 4 UUID deterministically from a SHA-256 hash digest
    by enforcing version 4 (0100) and variant 1 (10) bit patterns.
    """
    h = hashlib.sha256(canonical_key.encode("utf-8")).digest()[:16]
    b = bytearray(h)
    b[6] = (b[6] & 0x0F) | 0x40  # RFC 4122 version 4
    b[8] = (b[8] & 0x3F) | 0x80  # RFC 4122 variant 1
    return str(uuid.UUID(bytes=bytes(b)))


@dataclass(frozen=True)
class MemoryTimelineEvent:
    """
    Immutable representation of an individual chronological observation derived from memory evidence.

    Factual forensic fields:
        event_id: Deterministic event tracking identifier (MEMEVT-<UUIDv5>).
        timestamp: Typed datetime instant if genuinely present in source, or None.
        artifact_category: MemoryTimelineCategory enum or string ('process', 'kernel_module', 'network_socket').
        event_type: Specific factual event classification.
        description: Non-speculative forensic description.
        evidence_id: Source memory evidence ID (MEM-<UUID>).
        artifact_id: Source memory artifact ID (MEMPROC-, MEMMOD-, MEMNET-).
        source_plugin: Name of the Volatility plugin generating the observation.
        execution_id: Optional Volatility execution ID (VOLEXEC-<UUID>).
        source_row_indices: Tuple of original source output row indices.
        raw_timestamp: Original raw timestamp string or None.
        timestamp_origin: Factual source of the timestamp ('source_created_at', 'source_exit_time', 'none').
        timestamp_limitation: Explicit documentation of timestamp absence or limitations.
        attributes: Deeply frozen tuple of (key, value) pairs.
    """

    event_id: str
    timestamp: Optional[datetime]
    artifact_category: MemoryTimelineCategory
    event_type: str
    description: str
    evidence_id: str
    artifact_id: str
    source_plugin: str
    execution_id: Optional[str] = None
    source_row_indices: Tuple[int, ...] = ()
    raw_timestamp: Optional[str] = None
    timestamp_origin: str = "none"
    timestamp_limitation: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate fields strictly upon initialization."""
        # 1. Validate event_id
        if not isinstance(self.event_id, str) or not self.event_id.startswith("MEMEVT-"):
            raise ValueError(f"event_id must start with 'MEMEVT-', got '{self.event_id}'")
        suffix = self.event_id[len("MEMEVT-"):]
        try:
            uuid.UUID(suffix)
        except (ValueError, AttributeError) as err:
            raise ValueError(f"event_id must contain a valid UUID suffix, got '{self.event_id}'") from err

        # 2. Validate evidence_id
        _validate_memory_id(self.evidence_id)

        # 3. Validate artifact_id
        if not isinstance(self.artifact_id, str) or not self.artifact_id.strip():
            raise ValueError("artifact_id must be a non-empty string")

        # 4. Validate artifact_category
        if isinstance(self.artifact_category, MemoryTimelineCategory):
            validated_category = self.artifact_category
        elif isinstance(self.artifact_category, str):
            try:
                validated_category = MemoryTimelineCategory(self.artifact_category.strip().lower())
            except ValueError as err:
                valid_cats = sorted([c.value for c in MemoryTimelineCategory])
                raise ValueError(f"Invalid artifact_category: '{self.artifact_category}'. Must be one of: {valid_cats}") from err
        else:
            raise TypeError(f"artifact_category must be a MemoryTimelineCategory or str, got {type(self.artifact_category).__name__}")
        object.__setattr__(self, "artifact_category", validated_category)

        # 5. Validate event_type & description
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("description must be a non-empty string")

        # 6. Validate source_plugin
        if not isinstance(self.source_plugin, str) or not self.source_plugin.strip():
            raise ValueError("source_plugin must be a non-empty string")

        # 7. Validate timestamp
        if self.timestamp is not None and not isinstance(self.timestamp, datetime):
            raise TypeError(f"timestamp must be a datetime or None, got {type(self.timestamp).__name__}")

        # 8. Freeze source_row_indices
        if isinstance(self.source_row_indices, (list, tuple)):
            clean_indices = tuple(int(i) for i in self.source_row_indices if isinstance(i, int) and i >= 0)
            object.__setattr__(self, "source_row_indices", clean_indices)
        else:
            raise TypeError("source_row_indices must be a tuple or list of non-negative integers")

        # 9. Freeze attributes
        if isinstance(self.attributes, dict):
            frozen = tuple((str(k), freeze_attributes(v)) for k, v in sorted(self.attributes.items()))
            object.__setattr__(self, "attributes", frozen)
        elif isinstance(self.attributes, (list, tuple)):
            clean_attrs = []
            for item in self.attributes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_attrs.append((str(item[0]), freeze_attributes(item[1])))
                else:
                    raise TypeError("attributes items must be (key, value) pairs")
            object.__setattr__(self, "attributes", tuple(clean_attrs))
        else:
            raise TypeError("attributes must be a sequence of (key, value) pairs or a dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert memory timeline event to a deterministic JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp is not None else None,
            "artifact_category": self.artifact_category.value if hasattr(self.artifact_category, "value") else str(self.artifact_category),
            "event_type": self.event_type,
            "description": self.description,
            "evidence_id": self.evidence_id,
            "artifact_id": self.artifact_id,
            "execution_id": self.execution_id,
            "source_plugin": self.source_plugin,
            "source_row_indices": list(self.source_row_indices),
            "raw_timestamp": self.raw_timestamp,
            "timestamp_origin": self.timestamp_origin,
            "timestamp_limitation": self.timestamp_limitation,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize memory timeline event to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_timeline_event(self, category: Optional[TimelineCategory] = None) -> TimelineEvent:
        """
        Adapt this MemoryTimelineEvent directly into a canonical V3.1 TimelineEvent.

        Guarantees:
        - Category: Maps network sockets to TimelineCategory.NETWORK, or uses specified V3 category.
        - Event ID: Computes a valid, deterministic TIMELINE-<UUIDv4> identifier from the event_id.
        - Provenance: Preserves evidence_id, artifact_id, memory_event_id, and source_line.
        - Backward Compatibility: Fully compatible with TimelineReconstructor and V3 reporting.
        """
        if category is None:
            if self.artifact_category == MemoryTimelineCategory.NETWORK_SOCKET:
                chosen_category = TimelineCategory.NETWORK
            else:
                # Default to LOG for process/kernel observations when bridging to V3 categories
                chosen_category = TimelineCategory.LOG
        else:
            chosen_category = category

        det_v4_uuid = compute_deterministic_v4_timeline_id(self.event_id)
        first_line = (self.source_row_indices[0] + 1) if self.source_row_indices else 1

        attrs_dict = dict(self.attributes)
        attrs_dict["evidence_id"] = self.evidence_id
        attrs_dict["memory_artifact_id"] = self.artifact_id
        attrs_dict["memory_event_id"] = self.event_id
        attrs_dict["source_plugin"] = self.source_plugin
        attrs_dict["timestamp_origin"] = self.timestamp_origin
        if self.timestamp_limitation:
            attrs_dict["timestamp_limitation"] = self.timestamp_limitation
        if self.execution_id:
            attrs_dict["execution_id"] = self.execution_id

        return TimelineEvent(
            event_id=f"TIMELINE-{det_v4_uuid}",
            timestamp=self.timestamp,
            category=chosen_category,
            event_type=self.event_type,
            description=self.description,
            source_path=f"memory:{self.evidence_id}",
            source_line=first_line,
            source_artifact_id=self.artifact_id,
            source_event_id=self.event_id,
            raw_timestamp=self.raw_timestamp,
            attributes=attrs_dict,
        )


def _parse_iso_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse a normalized ISO timestamp string into a datetime object without synthetic offsets."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    clean = ts_str.strip()
    if not clean or clean.lower() in ("n/a", "none", "null", "-"):
        return None
    try:
        return datetime.fromisoformat(clean)
    except (ValueError, TypeError):
        try:
            return normalize_timestamp(clean)
        except (ValueError, TypeError):
            return None


def adapt_process_artifact(artifact: MemoryProcessArtifact) -> List[MemoryTimelineEvent]:
    """
    Extract chronological memory timeline events from a MemoryProcessArtifact.

    Temporal Mapping:
    - If created_at is present: emits a 'memory_process_created' event.
    - If exit_time is present: emits a 'memory_process_exited' event.
    - If neither timestamp is present: emits a single 'memory_process_observed' event with
      timestamp=None and explicit timestamp_limitation documentation.
    """
    if not isinstance(artifact, MemoryProcessArtifact):
        raise TypeError(f"adapt_process_artifact expects MemoryProcessArtifact, got {type(artifact).__name__}")

    events: List[MemoryTimelineEvent] = []
    base_attrs = {
        "pid": artifact.pid,
        "ppid": artifact.ppid,
        "process_name": artifact.process_name,
        "offset": artifact.offset,
        "raw_attributes": dict(artifact.raw_attributes),
    }

    created_dt = _parse_iso_datetime(artifact.created_at)
    exit_dt = _parse_iso_datetime(artifact.exit_time)

    # 1. Process Created Event
    if created_dt is not None:
        evt_id = compute_deterministic_memory_event_id(
            evidence_id=artifact.evidence_id,
            artifact_id=artifact.artifact_id,
            event_type="memory_process_created",
            timestamp_origin="source_created_at",
        )
        desc = f"Memory process created: {artifact.process_name} (PID {artifact.pid})"
        events.append(
            MemoryTimelineEvent(
                event_id=evt_id,
                timestamp=created_dt,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="memory_process_created",
                description=desc,
                evidence_id=artifact.evidence_id,
                artifact_id=artifact.artifact_id,
                source_plugin=artifact.source_plugin,
                execution_id=artifact.execution_id,
                source_row_indices=artifact.source_row_indices,
                raw_timestamp=artifact.created_at,
                timestamp_origin="source_created_at",
                timestamp_limitation="Timestamp observed in memory process structure",
                attributes=base_attrs,
            )
        )

    # 2. Process Exited Event
    if exit_dt is not None:
        evt_id = compute_deterministic_memory_event_id(
            evidence_id=artifact.evidence_id,
            artifact_id=artifact.artifact_id,
            event_type="memory_process_exited",
            timestamp_origin="source_exit_time",
        )
        desc = f"Memory process exited: {artifact.process_name} (PID {artifact.pid})"
        events.append(
            MemoryTimelineEvent(
                event_id=evt_id,
                timestamp=exit_dt,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="memory_process_exited",
                description=desc,
                evidence_id=artifact.evidence_id,
                artifact_id=artifact.artifact_id,
                source_plugin=artifact.source_plugin,
                execution_id=artifact.execution_id,
                source_row_indices=artifact.source_row_indices,
                raw_timestamp=artifact.exit_time,
                timestamp_origin="source_exit_time",
                timestamp_limitation="Exit timestamp observed in memory process structure",
                attributes=base_attrs,
            )
        )

    # 3. Unanchored Process Observed Event (when no timestamps exist)
    if not events:
        evt_id = compute_deterministic_memory_event_id(
            evidence_id=artifact.evidence_id,
            artifact_id=artifact.artifact_id,
            event_type="memory_process_observed",
            timestamp_origin="none",
        )
        desc = f"Memory process observed: {artifact.process_name} (PID {artifact.pid})"
        events.append(
            MemoryTimelineEvent(
                event_id=evt_id,
                timestamp=None,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="memory_process_observed",
                description=desc,
                evidence_id=artifact.evidence_id,
                artifact_id=artifact.artifact_id,
                source_plugin=artifact.source_plugin,
                execution_id=artifact.execution_id,
                source_row_indices=artifact.source_row_indices,
                raw_timestamp=None,
                timestamp_origin="none",
                timestamp_limitation="No reliable timestamp present in memory process artifact",
                attributes=base_attrs,
            )
        )

    return events


def adapt_module_artifact(artifact: MemoryModuleArtifact) -> List[MemoryTimelineEvent]:
    """
    Extract chronological memory timeline events from a MemoryModuleArtifact.

    Temporal Mapping:
    - Kernel modules and drivers do not record reliable creation timestamps in standard memory structures.
    - Emits a 'memory_module_observed' event with timestamp=None and explicit limitation documentation.
    """
    if not isinstance(artifact, MemoryModuleArtifact):
        raise TypeError(f"adapt_module_artifact expects MemoryModuleArtifact, got {type(artifact).__name__}")

    evt_id = compute_deterministic_memory_event_id(
        evidence_id=artifact.evidence_id,
        artifact_id=artifact.artifact_id,
        event_type="memory_module_observed",
        timestamp_origin="none",
    )
    base_part = f", Base: {artifact.base_address}" if artifact.base_address else ""
    size_part = f", Size: {artifact.size_bytes}" if artifact.size_bytes is not None else ""
    desc = f"Memory kernel module observed: {artifact.module_name}{base_part}{size_part}"

    attrs = {
        "module_name": artifact.module_name,
        "base_address": artifact.base_address,
        "size_bytes": artifact.size_bytes,
        "offset": artifact.offset,
        "driver_path": artifact.driver_path,
        "raw_attributes": dict(artifact.raw_attributes),
    }

    event = MemoryTimelineEvent(
        event_id=evt_id,
        timestamp=None,
        artifact_category=MemoryTimelineCategory.KERNEL_MODULE,
        event_type="memory_module_observed",
        description=desc,
        evidence_id=artifact.evidence_id,
        artifact_id=artifact.artifact_id,
        source_plugin=artifact.source_plugin,
        execution_id=artifact.execution_id,
        source_row_indices=artifact.source_row_indices,
        raw_timestamp=None,
        timestamp_origin="none",
        timestamp_limitation="Kernel modules do not contain reliable creation timestamps in memory",
        attributes=attrs,
    )
    return [event]


def adapt_network_artifact(artifact: MemoryNetworkArtifact) -> List[MemoryTimelineEvent]:
    """
    Extract chronological memory timeline events from a MemoryNetworkArtifact.

    Temporal Mapping:
    - If created_at is present (e.g. from windows.netscan pool scan): emits a 'memory_network_socket_created' event.
    - If created_at is absent (e.g. linux.sockstat, windows.netstat): emits a 'memory_network_socket_observed' event
      with timestamp=None and explicit limitation documentation.
    """
    if not isinstance(artifact, MemoryNetworkArtifact):
        raise TypeError(f"adapt_network_artifact expects MemoryNetworkArtifact, got {type(artifact).__name__}")

    created_dt = _parse_iso_datetime(artifact.created_at)
    event_type = "memory_network_socket_created" if created_dt is not None else "memory_network_socket_observed"
    ts_origin = "source_created_at" if created_dt is not None else "none"
    limitation = "Timestamp observed in network pool allocation" if created_dt is not None else "Socket structures do not record reliable creation timestamps"

    evt_id = compute_deterministic_memory_event_id(
        evidence_id=artifact.evidence_id,
        artifact_id=artifact.artifact_id,
        event_type=event_type,
        timestamp_origin=ts_origin,
    )

    l_ep = f"{artifact.local_address or '*'}:{artifact.local_port if artifact.local_port is not None else '*'}"
    r_ep = f"{artifact.remote_address or '*'}:{artifact.remote_port if artifact.remote_port is not None else '*'}"
    state_part = f" (State: {artifact.state})" if artifact.state else ""
    pid_part = f" (PID: {artifact.pid})" if artifact.pid is not None else ""
    desc = f"Memory network socket observed: {artifact.protocol} {l_ep} -> {r_ep}{state_part}{pid_part}"

    attrs = {
        "protocol": artifact.protocol,
        "local_address": artifact.local_address,
        "local_port": artifact.local_port,
        "remote_address": artifact.remote_address,
        "remote_port": artifact.remote_port,
        "state": artifact.state,
        "pid": artifact.pid,
        "process_name": artifact.process_name,
        "offset": artifact.offset,
        "raw_attributes": dict(artifact.raw_attributes),
    }

    event = MemoryTimelineEvent(
        event_id=evt_id,
        timestamp=created_dt,
        artifact_category=MemoryTimelineCategory.NETWORK_SOCKET,
        event_type=event_type,
        description=desc,
        evidence_id=artifact.evidence_id,
        artifact_id=artifact.artifact_id,
        source_plugin=artifact.source_plugin,
        execution_id=artifact.execution_id,
        source_row_indices=artifact.source_row_indices,
        raw_timestamp=artifact.created_at,
        timestamp_origin=ts_origin,
        timestamp_limitation=limitation,
        attributes=attrs,
    )
    return [event]


def adapt_process_extraction_result(result: ProcessExtractionResult) -> List[MemoryTimelineEvent]:
    """Adapt all artifacts in a ProcessExtractionResult into timeline events."""
    if not isinstance(result, ProcessExtractionResult):
        raise TypeError(f"adapt_process_extraction_result expects ProcessExtractionResult, got {type(result).__name__}")
    events: List[MemoryTimelineEvent] = []
    for art in result.artifacts:
        events.extend(adapt_process_artifact(art))
    return events


def adapt_module_extraction_result(result: ModuleExtractionResult) -> List[MemoryTimelineEvent]:
    """Adapt all artifacts in a ModuleExtractionResult into timeline events."""
    if not isinstance(result, ModuleExtractionResult):
        raise TypeError(f"adapt_module_extraction_result expects ModuleExtractionResult, got {type(result).__name__}")
    events: List[MemoryTimelineEvent] = []
    for art in result.artifacts:
        events.extend(adapt_module_artifact(art))
    return events


def adapt_network_extraction_result(result: NetworkExtractionResult) -> List[MemoryTimelineEvent]:
    """Adapt all artifacts in a NetworkExtractionResult into timeline events."""
    if not isinstance(result, NetworkExtractionResult):
        raise TypeError(f"adapt_network_extraction_result expects NetworkExtractionResult, got {type(result).__name__}")
    events: List[MemoryTimelineEvent] = []
    for art in result.artifacts:
        events.extend(adapt_network_artifact(art))
    return events


def classify_memory_event_timestamp(event: MemoryTimelineEvent) -> TimestampClass:
    """Classify the timestamp of a MemoryTimelineEvent into AWARE (0), NAIVE (1), or MISSING (2)."""
    if event.timestamp is None:
        return TimestampClass.MISSING
    if event.timestamp.tzinfo is not None and event.timestamp.tzinfo.utcoffset(event.timestamp) is not None:
        return TimestampClass.AWARE
    return TimestampClass.NAIVE


def memory_timeline_sort_key(event: MemoryTimelineEvent) -> Tuple[Any, ...]:
    """
    Construct a deterministic, type-safe comparison key for a MemoryTimelineEvent.

    Ordering Hierarchy:
    1. TimestampClass: AWARE (0) -> NAIVE (1) -> MISSING (2)
    2. Normalized Instant:
       - AWARE: Exact UTC instant
       - NAIVE: Naive datetime
       - MISSING: Integer 0 (all unanchored events tie)
    3. Evidence ID (lexicographical)
    4. Artifact ID (lexicographical)
    5. First source row index (integer)
    6. Event Type (lexicographical)
    7. Description (lexicographical)
    8. Event ID (lexicographical)
    """
    ts_class = classify_memory_event_timestamp(event)
    if ts_class == TimestampClass.AWARE:
        assert event.timestamp is not None
        ts_val: Any = event.timestamp.astimezone(timezone.utc)
    elif ts_class == TimestampClass.NAIVE:
        assert event.timestamp is not None
        ts_val = event.timestamp
    else:
        ts_val = 0

    first_line = event.source_row_indices[0] if event.source_row_indices else 0

    return (
        ts_class.value,
        ts_val,
        event.evidence_id,
        event.artifact_id,
        first_line,
        event.event_type,
        event.description,
        event.event_id,
    )


def compute_memory_event_fingerprint(event: MemoryTimelineEvent) -> Tuple[Any, ...]:
    """Compute factual deduplication fingerprint for MemoryTimelineEvent."""
    ts_key: Optional[Tuple[int, Optional[datetime]]] = None
    if event.timestamp is not None:
        if event.timestamp.tzinfo is not None and event.timestamp.tzinfo.utcoffset(event.timestamp) is not None:
            ts_key = (0, event.timestamp.astimezone(timezone.utc))
        else:
            ts_key = (1, event.timestamp)
    else:
        ts_key = (2, None)

    cat_str = event.artifact_category.value if hasattr(event.artifact_category, "value") else str(event.artifact_category)

    return (
        ts_key,
        event.raw_timestamp,
        cat_str,
        event.event_type,
        event.description,
        event.evidence_id,
        event.artifact_id,
        event.timestamp_origin,
        event.attributes,
    )


@dataclass(frozen=True)
class ReconstructedMemoryTimeline:
    """
    Immutable representation of an ordered, deduplicated memory forensic timeline.

    Attributes:
        events: Immutable tuple of ordered MemoryTimelineEvent instances.
        total_events: Count of surviving events in the timeline.
        duplicates_removed: Count of duplicate events filtered during reconstruction.
        timestamp_class_counts: Immutable tuple of (timestamp_class_name, count) pairs.
        category_counts: Immutable tuple of (category_name, count) pairs.
        unanchored_event_count: Count of events with missing timestamps (TimestampClass.MISSING).
    """

    events: Tuple[MemoryTimelineEvent, ...]
    total_events: int
    duplicates_removed: int
    timestamp_class_counts: Tuple[Tuple[str, int], ...]
    category_counts: Tuple[Tuple[str, int], ...]
    unanchored_event_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))
        if not isinstance(self.timestamp_class_counts, tuple):
            object.__setattr__(self, "timestamp_class_counts", tuple(self.timestamp_class_counts))
        if not isinstance(self.category_counts, tuple):
            object.__setattr__(self, "category_counts", tuple(self.category_counts))

    def __len__(self) -> int:
        return len(self.events)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.events[idx]

    def __iter__(self) -> Iterator[MemoryTimelineEvent]:
        return iter(self.events)

    @property
    def summary(self) -> Dict[str, Any]:
        """Summary metrics in stable dictionary order."""
        return {
            "total_events": self.total_events,
            "duplicates_removed": self.duplicates_removed,
            "unanchored_events": self.unanchored_event_count,
            "timestamp_class_counts": dict(self.timestamp_class_counts),
            "category_counts": dict(self.category_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert reconstructed memory timeline to a JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "events": [event.to_dict() for event in self.events],
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize reconstructed memory timeline to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def reconstruct_memory_timeline(
    items: Sequence[Any],
    deduplicate: bool = True,
) -> ReconstructedMemoryTimeline:
    """
    Reconstruct, order, and conservatively deduplicate memory timeline events from raw items or events.

    Accepts sequences containing:
    - MemoryTimelineEvent
    - MemoryProcessArtifact / ProcessExtractionResult
    - MemoryModuleArtifact / ModuleExtractionResult
    - MemoryNetworkArtifact / NetworkExtractionResult

    Guarantees:
    - Input immutability: Original items are never mutated.
    - Idempotence: reconstruct_memory_timeline(timeline.events) == timeline.
    - Temporal fidelity: Partitioned by TimestampClass without comparing aware to naive datetimes.
    """
    all_events: List[MemoryTimelineEvent] = []

    for item in items:
        if isinstance(item, MemoryTimelineEvent):
            all_events.append(item)
        elif isinstance(item, MemoryProcessArtifact):
            all_events.extend(adapt_process_artifact(item))
        elif isinstance(item, ProcessExtractionResult):
            all_events.extend(adapt_process_extraction_result(item))
        elif isinstance(item, MemoryModuleArtifact):
            all_events.extend(adapt_module_artifact(item))
        elif isinstance(item, ModuleExtractionResult):
            all_events.extend(adapt_module_extraction_result(item))
        elif isinstance(item, MemoryNetworkArtifact):
            all_events.extend(adapt_network_artifact(item))
        elif isinstance(item, NetworkExtractionResult):
            all_events.extend(adapt_network_extraction_result(item))
        else:
            raise TypeError(f"Unsupported item type for memory timeline reconstruction: {type(item).__name__}")

    # Deduplicate conservatively
    duplicates_removed = 0
    if deduplicate:
        seen_fingerprints: Set[Tuple[Any, ...]] = set()
        deduped_events: List[MemoryTimelineEvent] = []
        for event in all_events:
            fp = compute_memory_event_fingerprint(event)
            if fp in seen_fingerprints:
                duplicates_removed += 1
            else:
                seen_fingerprints.add(fp)
                deduped_events.append(event)
        surviving_events = deduped_events
    else:
        surviving_events = list(all_events)

    # Sort deterministically
    surviving_events.sort(key=memory_timeline_sort_key)

    # Compute metrics
    ts_counts: Counter = Counter()
    cat_counts: Counter = Counter()
    unanchored = 0

    for ev in surviving_events:
        ts_cls = classify_memory_event_timestamp(ev)
        ts_counts[ts_cls.name] += 1
        cat_name = ev.artifact_category.value if hasattr(ev.artifact_category, "value") else str(ev.artifact_category)
        cat_counts[cat_name] += 1
        if ts_cls == TimestampClass.MISSING:
            unanchored += 1

    sorted_ts_counts = tuple(sorted(ts_counts.items()))
    sorted_cat_counts = tuple(sorted(cat_counts.items()))

    return ReconstructedMemoryTimeline(
        events=tuple(surviving_events),
        total_events=len(surviving_events),
        duplicates_removed=duplicates_removed,
        timestamp_class_counts=sorted_ts_counts,
        category_counts=sorted_cat_counts,
        unanchored_event_count=unanchored,
    )
