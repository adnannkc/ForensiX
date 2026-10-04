"""
Forensic Correlation Models for ForensiX (V4.1 Event Correlation).

Provides strongly typed, deeply immutable dataclasses representing deterministic
relationships between V3 forensic timeline events.

Core Principles:
- Factual observation representation only.
- Correlation is NOT proof of compromise.
- No speculative labels or attack-chain conclusions.
- Preserves full forensic provenance (event IDs, source artifact IDs, source event IDs).
- Deterministic, reproducible representation and identity generation.
- Deeply immutable and JSON-serializable.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union
import uuid

from forensix.timeline_models import (
    TimelineEvent,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)


class CorrelationType(str, Enum):
    """
    Forensic relationship types connecting timeline events.

    Initial supported types per V4.1 specification:
    - TEMPORAL: Events occurring within a defined temporal window.
    - SAME_USER: Events sharing the same user/account identity.
    - SAME_SOURCE: Events originating from the same source (IP, host, service).
    - SAME_PATH: Events referencing the same filesystem path or resource.
    - SAME_SESSION: Events occurring within the same logon/terminal session.
    - AUTHENTICATION_PRIVILEGE: Authentication activity associated with privilege activity.
    """

    TEMPORAL = "TEMPORAL"
    SAME_USER = "SAME_USER"
    SAME_SOURCE = "SAME_SOURCE"
    SAME_PATH = "SAME_PATH"
    SAME_SESSION = "SAME_SESSION"
    AUTHENTICATION_PRIVILEGE = "AUTHENTICATION_PRIVILEGE"


# Convenience alias for relationship type
RelationshipType = CorrelationType

# Canonical RFC 4122 UUID namespace for ForensiX V4 deterministic correlation identities
FORENSIX_V4_CORRELATION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v4/correlation"
)

# Forensic terms prohibited in correlation descriptions to prevent speculative conclusions
DISALLOWED_SPECULATIVE_TERMS: Tuple[str, ...] = (
    "confirmed attack",
    "attacker confirmed",
    "system compromised",
    "malware confirmed",
    "intrusion confirmed",
    "attack confirmed",
    "compromised system",
)


def generate_correlation_id() -> str:
    """Generate a unique tracking identifier for a correlation (CORR-<UUIDv4>)."""
    return f"CORR-{uuid.uuid4()}"


def compute_deterministic_correlation_id(
    relationship_type: Union[CorrelationType, str],
    event_ids: Iterable[Union[str, TimelineEvent]],
    discriminator: Optional[str] = None,
) -> str:
    """
    Compute a deterministic RFC 4122 UUIDv5 correlation identifier.

    Guarantees:
    - Same relationship type + same sorted event IDs (+ same discriminator)
      always produces the exact same correlation ID across runs and platforms.
    - Preserves existing event IDs without modifying them.
    - Format: CORR-<UUIDv5>.

    Raises:
        ValueError: If event_ids is empty or relationship_type is invalid.
    """
    if isinstance(relationship_type, CorrelationType):
        rel_str = relationship_type.value
    elif isinstance(relationship_type, str):
        rel_str = relationship_type.strip().upper()
    else:
        raise TypeError(
            f"relationship_type must be CorrelationType or str, got {type(relationship_type).__name__}"
        )

    clean_ids: List[str] = []
    for item in event_ids:
        if isinstance(item, TimelineEvent):
            clean_ids.append(item.event_id)
        elif isinstance(item, str):
            s = item.strip()
            if s:
                clean_ids.append(s)
        else:
            raise TypeError(
                f"event_ids must contain TimelineEvent or str instances, got {type(item).__name__}"
            )

    if not clean_ids:
        raise ValueError("Cannot compute deterministic correlation ID without event IDs")

    sorted_ids = sorted(clean_ids)
    key_parts = [rel_str, ",".join(sorted_ids)]
    if discriminator is not None and str(discriminator).strip():
        key_parts.append(str(discriminator).strip())

    canonical_key = ":".join(key_parts)
    det_uuid = uuid.uuid5(FORENSIX_V4_CORRELATION_NAMESPACE, canonical_key)
    return f"CORR-{det_uuid}"


def _validate_timeline_event_id(val: str) -> str:
    """Validate that a string conforms to the V3 TimelineEvent ID specification."""
    if not isinstance(val, str):
        raise TypeError(f"timeline event ID must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id:
        raise ValueError("timeline event ID must not be empty")
    if not clean_id.startswith("TIMELINE-"):
        raise ValueError(f"timeline event ID must start with 'TIMELINE-', got '{val}'")
    uuid_part = clean_id[len("TIMELINE-"):]
    try:
        parsed = uuid.UUID(uuid_part)
        if parsed.version not in (4, 5):
            raise ValueError(
                f"timeline event ID UUID must be version 4 or 5, got version {parsed.version}"
            )
    except (ValueError, AttributeError) as err:
        raise ValueError(f"timeline event ID must contain a valid UUID, got '{val}'") from err
    return clean_id


def _validate_correlation_id(val: str) -> str:
    """Validate that a string conforms to the ForensiX CORR-<UUID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"correlation_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id:
        raise ValueError("correlation_id must not be empty")
    if not clean_id.startswith("CORR-"):
        raise ValueError(f"correlation_id must start with 'CORR-', got '{val}'")
    uuid_part = clean_id[len("CORR-"):]
    try:
        parsed = uuid.UUID(uuid_part)
        if parsed.version not in (4, 5):
            raise ValueError(
                f"correlation_id UUID must be version 4 or 5, got version {parsed.version}"
            )
    except (ValueError, AttributeError) as err:
        raise ValueError(f"correlation_id must contain a valid UUID, got '{val}'") from err
    return clean_id


@dataclass(frozen=True)
class Correlation:
    """
    Immutable forensic representation of a relationship between timeline events.

    Forensic Guarantees:
    - Traceable to involved timeline events, source artifacts, and source events.
    - Deeply immutable after creation.
    - Deterministic ID generation based on RFC 4122 UUIDv5.
    - Rejection of speculative or interpretive conclusions.
    - Deterministic JSON-safe serialization.
    """

    correlation_id: str
    relationship_type: CorrelationType
    event_ids: Tuple[str, ...]
    source_event_ids: Tuple[str, ...] = ()
    source_artifact_ids: Tuple[str, ...] = ()
    start_timestamp: Optional[datetime] = None
    end_timestamp: Optional[datetime] = None
    time_delta_seconds: Optional[float] = None
    description: str = ""
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        *args: Any,
        correlation_id: Optional[str] = None,
        relationship_type: Optional[Union[CorrelationType, str]] = None,
        event_ids: Optional[Sequence[Union[str, TimelineEvent]]] = None,
        description: Optional[str] = None,
        source_event_ids: Optional[Union[str, Sequence[str]]] = None,
        source_artifact_ids: Optional[Union[str, Sequence[str]]] = None,
        start_timestamp: Optional[Union[datetime, str]] = None,
        end_timestamp: Optional[Union[datetime, str]] = None,
        time_delta_seconds: Optional[Union[float, int]] = None,
        attributes: Any = None,
        explanation: Optional[str] = None,
    ) -> None:
        """
        Construct an immutable Correlation instance with comprehensive validation.

        Positional arguments support either:
        - (relationship_type, event_ids, description, ...)
        - (correlation_id, relationship_type, event_ids, description, ...)
        """
        # Resolve positional arguments if provided
        pos_corr_id = correlation_id
        pos_rel_type = relationship_type
        pos_event_ids = event_ids
        pos_desc = description

        if args:
            if len(args) >= 1:
                first = args[0]
                if isinstance(first, str) and first.startswith("CORR-"):
                    pos_corr_id = first
                    if len(args) >= 2:
                        pos_rel_type = args[1]
                    if len(args) >= 3:
                        pos_event_ids = args[2]
                    if len(args) >= 4:
                        pos_desc = args[3]
                else:
                    pos_rel_type = first
                    if len(args) >= 2:
                        pos_event_ids = args[1]
                    if len(args) >= 3:
                        pos_desc = args[2]

        # 1. Validate relationship_type
        if pos_rel_type is None:
            raise TypeError("Correlation missing required argument: 'relationship_type'")
        if isinstance(pos_rel_type, CorrelationType):
            validated_rel_type = pos_rel_type
        elif isinstance(pos_rel_type, str):
            clean_rel = pos_rel_type.strip().upper()
            try:
                validated_rel_type = CorrelationType(clean_rel)
            except ValueError:
                valid_types = sorted([t.value for t in CorrelationType])
                raise ValueError(
                    f"Invalid relationship type: '{pos_rel_type}'. Must be one of: {valid_types}"
                )
        else:
            raise TypeError(
                f"relationship_type must be CorrelationType or str, got {type(pos_rel_type).__name__}"
            )

        # 2. Validate event_ids
        if pos_event_ids is None:
            raise TypeError("Correlation missing required argument: 'event_ids'")
        if isinstance(pos_event_ids, (str, bytes, dict)) or not hasattr(pos_event_ids, "__iter__"):
            raise TypeError(
                f"event_ids must be a sequence of timeline event references, got {type(pos_event_ids).__name__}"
            )

        raw_event_items = list(pos_event_ids)
        if len(raw_event_items) < 2:
            raise ValueError(
                f"Correlation requires at least 2 timeline events, got {len(raw_event_items)}"
            )

        validated_event_ids_list: List[str] = []
        extracted_source_events: List[str] = []
        extracted_source_artifacts: List[str] = []
        extracted_timestamps: List[datetime] = []

        for item in raw_event_items:
            if isinstance(item, TimelineEvent):
                validated_event_ids_list.append(item.event_id)
                if item.source_event_id:
                    extracted_source_events.append(item.source_event_id)
                if item.source_artifact_id:
                    extracted_source_artifacts.append(item.source_artifact_id)
                if item.timestamp is not None:
                    extracted_timestamps.append(item.timestamp)
            elif isinstance(item, str):
                validated_event_ids_list.append(_validate_timeline_event_id(item))
            else:
                raise TypeError(
                    f"event_ids item must be TimelineEvent or str, got {type(item).__name__}"
                )

        # Check for duplicate event IDs (cannot correlate an event with itself)
        if len(validated_event_ids_list) != len(set(validated_event_ids_list)):
            raise ValueError(
                "Correlated event_ids must be distinct; cannot correlate an event with itself"
            )

        validated_event_ids: Tuple[str, ...] = tuple(validated_event_ids_list)

        # 3. Validate description / explanation
        chosen_desc = pos_desc if pos_desc is not None else explanation
        if chosen_desc is None:
            raise TypeError("Correlation missing required argument: 'description'")
        if not isinstance(chosen_desc, str):
            raise TypeError(f"description must be a string, got {type(chosen_desc).__name__}")
        clean_desc = chosen_desc.strip()
        if not clean_desc:
            raise ValueError("description must be a non-empty string")

        # Prohibit speculative labels per forensic principles
        desc_lower = clean_desc.lower()
        for term in DISALLOWED_SPECULATIVE_TERMS:
            if term in desc_lower:
                raise ValueError(
                    f"Speculative or interpretive phrase '{term}' is disallowed in forensic correlation. "
                    "Correlations must use factual, explainable language."
                )

        # 4. Validate / Compute correlation_id
        if pos_corr_id is None:
            validated_corr_id = compute_deterministic_correlation_id(
                validated_rel_type, validated_event_ids
            )
        else:
            validated_corr_id = _validate_correlation_id(pos_corr_id)

        # 5. Validate source_event_ids
        if source_event_ids is not None:
            if isinstance(source_event_ids, str):
                s = source_event_ids.strip()
                if not s:
                    raise ValueError("source_event_ids string must not be empty")
                validated_source_events = (s,)
            elif isinstance(source_event_ids, (list, tuple, set)):
                items = []
                for it in source_event_ids:
                    if not isinstance(it, str):
                        raise TypeError(f"source_event_ids item must be a str, got {type(it).__name__}")
                    s = it.strip()
                    if not s:
                        raise ValueError("source_event_ids item must not be empty")
                    items.append(s)
                # Deduplicate preserving order
                validated_source_events = tuple(dict.fromkeys(items))
            else:
                raise TypeError(
                    f"source_event_ids must be a str, sequence of str, or None, got {type(source_event_ids).__name__}"
                )
        else:
            # Use extracted from TimelineEvent objects if available
            validated_source_events = tuple(dict.fromkeys(extracted_source_events))

        # 6. Validate source_artifact_ids
        if source_artifact_ids is not None:
            if isinstance(source_artifact_ids, str):
                s = source_artifact_ids.strip()
                if not s:
                    raise ValueError("source_artifact_ids string must not be empty")
                validated_source_artifacts = (s,)
            elif isinstance(source_artifact_ids, (list, tuple, set)):
                items = []
                for it in source_artifact_ids:
                    if not isinstance(it, str):
                        raise TypeError(f"source_artifact_ids item must be a str, got {type(it).__name__}")
                    s = it.strip()
                    if not s:
                        raise ValueError("source_artifact_ids item must not be empty")
                    items.append(s)
                # Deduplicate preserving order
                validated_source_artifacts = tuple(dict.fromkeys(items))
            else:
                raise TypeError(
                    f"source_artifact_ids must be a str, sequence of str, or None, got {type(source_artifact_ids).__name__}"
                )
        else:
            # Use extracted from TimelineEvent objects if available
            validated_source_artifacts = tuple(dict.fromkeys(extracted_source_artifacts))

        # 7. Validate temporal information (start_timestamp, end_timestamp, time_delta_seconds)
        validated_start_ts: Optional[datetime] = None
        if start_timestamp is not None:
            if isinstance(start_timestamp, datetime):
                validated_start_ts = start_timestamp
            elif isinstance(start_timestamp, str):
                try:
                    validated_start_ts = datetime.fromisoformat(start_timestamp)
                except Exception as err:
                    raise ValueError(
                        f"Invalid ISO timestamp string for start_timestamp: '{start_timestamp}'"
                    ) from err
            else:
                raise TypeError(
                    f"start_timestamp must be datetime, ISO string, or None, got {type(start_timestamp).__name__}"
                )

        validated_end_ts: Optional[datetime] = None
        if end_timestamp is not None:
            if isinstance(end_timestamp, datetime):
                validated_end_ts = end_timestamp
            elif isinstance(end_timestamp, str):
                try:
                    validated_end_ts = datetime.fromisoformat(end_timestamp)
                except Exception as err:
                    raise ValueError(
                        f"Invalid ISO timestamp string for end_timestamp: '{end_timestamp}'"
                    ) from err
            else:
                raise TypeError(
                    f"end_timestamp must be datetime, ISO string, or None, got {type(end_timestamp).__name__}"
                )

        # Auto-infer timestamps from TimelineEvent objects if not explicitly supplied
        if validated_start_ts is None and validated_end_ts is None and extracted_timestamps:
            # Check awareness consistency across extracted timestamps
            aware_count = sum(
                1 for ts in extracted_timestamps if ts.tzinfo is not None and ts.tzinfo.utcoffset(ts) is not None
            )
            if aware_count == len(extracted_timestamps) or aware_count == 0:
                # All aware or all naive -> safe to compare
                sorted_ts = sorted(extracted_timestamps)
                validated_start_ts = sorted_ts[0]
                validated_end_ts = sorted_ts[-1]
            # If mixed awareness, leave as None (awareness mismatch)

        # Validate timestamp ordering if both are present and awareness-compatible
        if validated_start_ts is not None and validated_end_ts is not None:
            start_aware = validated_start_ts.tzinfo is not None and validated_start_ts.tzinfo.utcoffset(validated_start_ts) is not None
            end_aware = validated_end_ts.tzinfo is not None and validated_end_ts.tzinfo.utcoffset(validated_end_ts) is not None
            if start_aware == end_aware:
                if validated_start_ts > validated_end_ts:
                    raise ValueError(
                        f"start_timestamp ({validated_start_ts}) cannot be after end_timestamp ({validated_end_ts})"
                    )

        # 8. Validate time_delta_seconds
        validated_delta: Optional[float] = None
        if time_delta_seconds is not None:
            if isinstance(time_delta_seconds, bool) or not isinstance(time_delta_seconds, (int, float)):
                raise TypeError(
                    f"time_delta_seconds must be a float or int, got {type(time_delta_seconds).__name__}"
                )
            if time_delta_seconds < 0:
                raise ValueError(
                    f"time_delta_seconds must be non-negative, got {time_delta_seconds}"
                )
            validated_delta = float(time_delta_seconds)
        elif validated_start_ts is not None and validated_end_ts is not None:
            start_aware = validated_start_ts.tzinfo is not None and validated_start_ts.tzinfo.utcoffset(validated_start_ts) is not None
            end_aware = validated_end_ts.tzinfo is not None and validated_end_ts.tzinfo.utcoffset(validated_end_ts) is not None
            if start_aware == end_aware:
                # Same awareness -> compute exact delta
                diff = (validated_end_ts - validated_start_ts).total_seconds()
                validated_delta = abs(float(diff))

        # 9. Validate / freeze attributes
        if attributes is None or (isinstance(attributes, (dict, tuple, list)) and len(attributes) == 0):
            frozen_attributes: Tuple[Tuple[str, Any], ...] = _FrozenDict()
        elif isinstance(attributes, (dict, tuple, list)):
            frozen_attributes = freeze_attributes(attributes)
        else:
            raise TypeError(
                f"attributes must be a dict, sequence of pairs, or None, got {type(attributes).__name__}"
            )

        # Assign frozen fields
        object.__setattr__(self, "correlation_id", validated_corr_id)
        object.__setattr__(self, "relationship_type", validated_rel_type)
        object.__setattr__(self, "event_ids", validated_event_ids)
        object.__setattr__(self, "source_event_ids", validated_source_events)
        object.__setattr__(self, "source_artifact_ids", validated_source_artifacts)
        object.__setattr__(self, "start_timestamp", validated_start_ts)
        object.__setattr__(self, "end_timestamp", validated_end_ts)
        object.__setattr__(self, "time_delta_seconds", validated_delta)
        object.__setattr__(self, "description", clean_desc)
        object.__setattr__(self, "attributes", frozen_attributes)

    @property
    def timeline_event_ids(self) -> Tuple[str, ...]:
        """Alias for event_ids for explicit clarity."""
        return self.event_ids

    @property
    def explanation(self) -> str:
        """Alias for description for investigative clarity."""
        return self.description

    @property
    def delta_seconds(self) -> Optional[float]:
        """Alias for time_delta_seconds."""
        return self.time_delta_seconds

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a deterministic JSON-serializable dictionary.

        Guarantees:
        - Stable key order
        - Explicit serialization of None and falsy values (0, 0.0, False)
        - Only standard JSON-safe types (str, int, float, bool, list, dict, None)
        """
        return {
            "correlation_id": self.correlation_id,
            "relationship_type": self.relationship_type.value,
            "event_ids": list(self.event_ids),
            "source_event_ids": list(self.source_event_ids),
            "source_artifact_ids": list(self.source_artifact_ids),
            "start_timestamp": self.start_timestamp.isoformat() if self.start_timestamp is not None else None,
            "end_timestamp": self.end_timestamp.isoformat() if self.end_timestamp is not None else None,
            "time_delta_seconds": self.time_delta_seconds,
            "description": self.description,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Correlation":
        """Reconstruct a Correlation instance from a dictionary representation."""
        if not isinstance(data, dict):
            raise TypeError(f"data must be a dict, got {type(data).__name__}")
        return cls(
            correlation_id=data.get("correlation_id"),
            relationship_type=data["relationship_type"],
            event_ids=data["event_ids"],
            description=data["description"],
            source_event_ids=data.get("source_event_ids", ()),
            source_artifact_ids=data.get("source_artifact_ids", ()),
            start_timestamp=data.get("start_timestamp"),
            end_timestamp=data.get("end_timestamp"),
            time_delta_seconds=data.get("time_delta_seconds"),
            attributes=data.get("attributes", {}),
        )


def create_correlation(
    relationship_type: Union[CorrelationType, str],
    event_ids: Sequence[Union[str, TimelineEvent]],
    description: str,
    *,
    correlation_id: Optional[str] = None,
    source_event_ids: Optional[Union[str, Sequence[str]]] = None,
    source_artifact_ids: Optional[Union[str, Sequence[str]]] = None,
    start_timestamp: Optional[Union[datetime, str]] = None,
    end_timestamp: Optional[Union[datetime, str]] = None,
    time_delta_seconds: Optional[Union[float, int]] = None,
    attributes: Any = None,
    explanation: Optional[str] = None,
) -> Correlation:
    """
    Convenience factory to construct an immutable Correlation.
    """
    return Correlation(
        relationship_type=relationship_type,
        event_ids=event_ids,
        description=description,
        correlation_id=correlation_id,
        source_event_ids=source_event_ids,
        source_artifact_ids=source_artifact_ids,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        time_delta_seconds=time_delta_seconds,
        attributes=attributes,
        explanation=explanation,
    )


@dataclass(frozen=True)
class CorrelationCollection:
    """
    Immutable aggregate collection of forensic correlations.

    Attributes:
        correlations: Immutable tuple of Correlation instances.
        total_correlations: Count of correlations in this collection.
        relationship_counts: Immutable tuple of (relationship_type, count) pairs.
    """

    correlations: Tuple[Correlation, ...]
    total_correlations: int
    relationship_counts: Tuple[Tuple[str, int], ...]

    def __init__(self, correlations: Sequence[Correlation] = ()) -> None:
        """Construct an immutable CorrelationCollection from a sequence of Correlation objects."""
        if correlations is None:
            correlations_seq: Sequence[Correlation] = ()
        elif isinstance(correlations, (list, tuple, set)):
            correlations_seq = list(correlations)
        else:
            raise TypeError(
                f"correlations must be a sequence of Correlation objects, got {type(correlations).__name__}"
            )

        validated: List[Correlation] = []
        counts: Dict[str, int] = {}
        for item in correlations_seq:
            if not isinstance(item, Correlation):
                raise TypeError(
                    f"Item in correlations must be Correlation, got {type(item).__name__}"
                )
            validated.append(item)
            rel_str = item.relationship_type.value
            counts[rel_str] = counts.get(rel_str, 0) + 1

        object.__setattr__(self, "correlations", tuple(validated))
        object.__setattr__(self, "total_correlations", len(validated))
        object.__setattr__(self, "relationship_counts", tuple(sorted(counts.items())))

    def __len__(self) -> int:
        return self.total_correlations

    def __iter__(self) -> Iterator[Correlation]:
        return iter(self.correlations)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.correlations[idx]

    def __contains__(self, item: Any) -> bool:
        return item in self.correlations

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics with counts in stable key order."""
        return {
            "total_correlations": self.total_correlations,
            "relationship_counts": dict(self.relationship_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert correlation collection to a deterministic JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "correlations": [c.to_dict() for c in self.correlations],
        }
