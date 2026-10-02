"""
Timeline Reconstruction, Ordering & Deduplication Engine for ForensiX (V3.4).

Provides a deterministic, forensically sound reconstruction layer that takes factual
TimelineEvent objects (typically produced by V3.3 Artifact Adapters), validates them,
orders them chronologically with stable secondary tie-breaking, and conservatively
deduplicates identical observations without mutating events or inferring conclusions.

Core Architectural Flow:
    Forensic Artifacts
           ↓
    V3.3 Artifact Adapters
           ↓
    TimelineEvent objects
           ↓
    V3.4 Timeline Reconstruction
           ↓
    Deterministic Ordering (TimestampClass partitioning + secondary tie-breaking)
           ↓
    Conservative Deduplication (Factual fingerprint matching)
           ↓
    ReconstructedTimeline (Immutable chronological sequence)

Strict Forensic Boundaries:
1. Purely structural reconstruction: No threat detection, anomaly scoring, compromise assessment,
   or incident determination.
2. No causality or correlation: Does not infer attack chains, relationships, or attacker intent.
3. No fabricated timestamps: Preserves timestamps exactly as emitted; missing timestamps remain None.
4. Timezone fidelity: Timezone-aware timestamps compare by exact UTC instant; timezone-naive timestamps
   remain naive without synthetic offsets; mixed sets are partitioned deterministically.
5. Deep immutability: Input TimelineEvent instances are never mutated.
6. Absolute determinism: Identical inputs produce byte-identical ordered outputs and duplicate decisions.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)


class TimestampClass(int, Enum):
    """
    Explicit classification of timeline timestamps for deterministic partitioning.

    Prevents invalid comparisons between timezone-aware and timezone-naive datetimes
    and avoids fabricating synthetic timezones or assumptions for naive or missing timestamps.
    """

    AWARE = 0    # Explicit timezone offset present; normalized to UTC instant
    NAIVE = 1    # No timezone offset; calendar date and time preserved strictly as naive
    MISSING = 2  # No normalized timestamp available (e.g. yearless syslog lines)


def classify_timestamp(event: TimelineEvent) -> TimestampClass:
    """
    Determine the TimestampClass of a TimelineEvent.

    Args:
        event: TimelineEvent instance to inspect.

    Returns:
        TimestampClass: AWARE (0), NAIVE (1), or MISSING (2).
    """
    if event.timestamp is None:
        return TimestampClass.MISSING
    if event.timestamp.tzinfo is not None and event.timestamp.tzinfo.utcoffset(event.timestamp) is not None:
        return TimestampClass.AWARE
    return TimestampClass.NAIVE


def timeline_sort_key(event: TimelineEvent) -> Tuple[Any, ...]:
    """
    Construct a deterministic, type-safe comparison key for a TimelineEvent.

    Ordering Rules:
    1. TimestampClass:
       - Class 0 (AWARE): Sorted chronologically by exact UTC instant.
       - Class 1 (NAIVE): Sorted chronologically by naive datetime (year, month, day, time).
       - Class 2 (MISSING): No timestamp; grouped together.
    2. Normalized Instant:
       - Within AWARE: UTC datetime (`event.timestamp.astimezone(timezone.utc)`).
       - Within NAIVE: Naive datetime (`event.timestamp`).
       - Within MISSING: Integer 0 (all tie on instant, moving to provenance).
    3. Source Path: Lexicographical order (`event.source_path or ""`).
    4. Source Line: Integer line number (`event.source_line or -1`).
    5. Source Artifact ID: Lexicographical order (`event.source_artifact_id or ""`).
    6. Source Event ID: Lexicographical order (`event.source_event_id or ""`).
    7. Event Type: Lexicographical order (`event.event_type`).
    8. Description: Lexicographical order (`event.description`).
    9. Event ID: Lexicographical order (`event.event_id`).

    Guarantees:
    - Never compares aware and naive datetimes directly (avoids Python TypeError).
    - Preserves timezone uncertainty without guessing UTC or local timezone for naive timestamps.
    - 100% deterministic tie-breaking based solely on immutable event data.
    """
    ts_class = classify_timestamp(event)

    if ts_class == TimestampClass.AWARE:
        # Guarantee UTC instant comparison
        assert event.timestamp is not None
        ts_val: Any = event.timestamp.astimezone(timezone.utc)
    elif ts_class == TimestampClass.NAIVE:
        # Guarantee naive comparison
        assert event.timestamp is not None
        ts_val = event.timestamp
    else:
        # Fixed integer for missing timestamps so all missing events tie on instant
        ts_val = 0

    return (
        ts_class.value,
        ts_val,
        event.source_path or "",
        event.source_line if event.source_line is not None else -1,
        event.source_artifact_id or "",
        event.source_event_id or "",
        event.event_type,
        event.description,
        event.event_id,
    )


def compute_event_fingerprint(event: TimelineEvent) -> Tuple[Any, ...]:
    """
    Compute a deterministic, hashable factual fingerprint for duplicate detection.

    Two events are considered true duplicates if and only if they share identical:
    - Normalized timestamp instant (UTC for aware, naive datetime for naive, None for missing)
    - Raw timestamp string
    - Category
    - Event type
    - Description
    - Source path
    - Source line
    - Source artifact ID
    - Source event ID
    - Raw data
    - Attributes (deeply frozen attributes tuple)

    Note: `event_id` is intentionally excluded from the fingerprint because multiple adapter runs
    or evidence scans may generate distinct UUIDs for the exact same underlying forensic observation.
    """
    # Normalize timestamp representation for instant equivalence
    ts_key: Optional[Tuple[int, Optional[datetime]]] = None
    if event.timestamp is not None:
        if event.timestamp.tzinfo is not None and event.timestamp.tzinfo.utcoffset(event.timestamp) is not None:
            ts_key = (0, event.timestamp.astimezone(timezone.utc))
        else:
            ts_key = (1, event.timestamp)
    else:
        ts_key = (2, None)

    cat_str = event.category.value if hasattr(event.category, "value") else str(event.category)

    return (
        ts_key,
        event.raw_timestamp,
        cat_str,
        event.event_type,
        event.description,
        event.source_path,
        event.source_line,
        event.source_artifact_id,
        event.source_event_id,
        event.raw_data,
        event.attributes,
    )


@dataclass(frozen=True)
class ReconstructedTimeline:
    """
    Immutable representation of an ordered, deduplicated forensic timeline.

    Attributes:
        events: Immutable tuple of ordered TimelineEvent instances.
        total_events: Count of surviving events in the timeline.
        duplicates_removed: Count of duplicate events filtered during reconstruction.
        timestamp_class_counts: Immutable tuple of (timestamp_class_name, count) pairs.
        category_counts: Immutable tuple of (category_name, count) pairs.
    """

    events: Tuple[TimelineEvent, ...]
    total_events: int
    duplicates_removed: int
    timestamp_class_counts: Tuple[Tuple[str, int], ...]
    category_counts: Tuple[Tuple[str, int], ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on collections."""
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

    def __iter__(self) -> Iterator[TimelineEvent]:
        return iter(self.events)

    def __contains__(self, item: Any) -> bool:
        return item in self.events

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics with counts in stable key order."""
        return {
            "total_events": self.total_events,
            "duplicates_removed": self.duplicates_removed,
            "timestamp_class_counts": dict(self.timestamp_class_counts),
            "category_counts": dict(self.category_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert reconstructed timeline to a deterministic JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "events": [event.to_dict() for event in self.events],
        }


class TimelineReconstructor:
    """
    Engine for deterministic timeline reconstruction, ordering, and deduplication.

    Guarantees:
    - Input immutability: Source events are never modified.
    - Idempotence: reconstruct(reconstruct(events)) == reconstruct(events).
    - Conservative deduplication: Removes only exact factual duplicates.
    """

    def __init__(self, deduplicate: bool = True) -> None:
        self.deduplicate = deduplicate

    def reconstruct(
        self,
        events: Union[Sequence[TimelineEvent], ReconstructedTimeline],
    ) -> ReconstructedTimeline:
        """
        Reconstruct a collection of TimelineEvents into an ordered, deduplicated ReconstructedTimeline.

        Args:
            events: Sequence of TimelineEvent instances or an existing ReconstructedTimeline.

        Returns:
            ReconstructedTimeline: Immutable ordered and deduplicated timeline container.

        Raises:
            ValueError: If events is None.
            TypeError: If any element in events is not a TimelineEvent.
        """
        if events is None:
            raise ValueError("Events sequence cannot be None")

        if isinstance(events, ReconstructedTimeline):
            if self.deduplicate:
                return events
            event_list: Sequence[TimelineEvent] = events.events
        else:
            event_list = events

        # Validate input types
        for i, item in enumerate(event_list):
            if not isinstance(item, TimelineEvent):
                raise TypeError(
                    f"Item at index {i} is not a TimelineEvent (got {type(item).__name__}). "
                    "Timeline reconstruction requires valid TimelineEvent instances."
                )

        if not event_list:
            return ReconstructedTimeline(
                events=(),
                total_events=0,
                duplicates_removed=0,
                timestamp_class_counts=(("aware", 0), ("naive", 0), ("missing", 0)),
                category_counts=(),
            )

        # 1. Deterministic chronological sort with tie-breaking
        sorted_events = sorted(event_list, key=timeline_sort_key)

        # 2. Conservative deduplication
        final_events: List[TimelineEvent] = []
        duplicates_removed = 0

        if self.deduplicate:
            seen_fingerprints: Set[Tuple[Any, ...]] = set()
            for event in sorted_events:
                fp = compute_event_fingerprint(event)
                if fp in seen_fingerprints:
                    duplicates_removed += 1
                    continue
                seen_fingerprints.add(fp)
                final_events.append(event)
        else:
            final_events = list(sorted_events)

        # 3. Calculate deterministic summary counts
        ts_counter = Counter(classify_timestamp(e).name.lower() for e in final_events)
        cat_counter = Counter(
            (e.category.value if hasattr(e.category, "value") else str(e.category))
            for e in final_events
        )

        sorted_ts_counts = tuple(
            sorted(
                [
                    ("aware", ts_counter.get("aware", 0)),
                    ("naive", ts_counter.get("naive", 0)),
                    ("missing", ts_counter.get("missing", 0)),
                ],
                key=lambda x: x[0],
            )
        )
        sorted_cat_counts = tuple(sorted(cat_counter.items(), key=lambda x: x[0]))

        return ReconstructedTimeline(
            events=tuple(final_events),
            total_events=len(final_events),
            duplicates_removed=duplicates_removed,
            timestamp_class_counts=sorted_ts_counts,
            category_counts=sorted_cat_counts,
        )

    def order_and_deduplicate(
        self,
        events: Union[Sequence[TimelineEvent], ReconstructedTimeline],
    ) -> Tuple[TimelineEvent, ...]:
        """Convenience method returning the tuple of ordered, deduplicated TimelineEvents."""
        return self.reconstruct(events).events


# Default singleton reconstructors
_DEFAULT_RECONSTRUCTOR_DEDUP = TimelineReconstructor(deduplicate=True)
_DEFAULT_RECONSTRUCTOR_NO_DEDUP = TimelineReconstructor(deduplicate=False)


def reconstruct_timeline(
    events: Union[Sequence[TimelineEvent], ReconstructedTimeline],
    deduplicate: bool = True,
) -> ReconstructedTimeline:
    """
    Reconstruct a collection of TimelineEvents into a deterministic, chronological ReconstructedTimeline.

    Args:
        events: Sequence of TimelineEvent instances or existing ReconstructedTimeline.
        deduplicate: If True (default), remove exact factual duplicate observations.

    Returns:
        ReconstructedTimeline: Immutable, ordered, deduplicated timeline.

    Raises:
        ValueError: If events is None.
        TypeError: If an element is not a TimelineEvent.
    """
    reconstructor = _DEFAULT_RECONSTRUCTOR_DEDUP if deduplicate else _DEFAULT_RECONSTRUCTOR_NO_DEDUP
    return reconstructor.reconstruct(events)


def order_timeline_events(
    events: Union[Sequence[TimelineEvent], ReconstructedTimeline],
    deduplicate: bool = True,
) -> Tuple[TimelineEvent, ...]:
    """
    Order and optionally deduplicate a sequence of TimelineEvents, returning an immutable tuple.

    Args:
        events: Sequence of TimelineEvent instances or existing ReconstructedTimeline.
        deduplicate: If True (default), filter exact duplicate observations.

    Returns:
        Tuple[TimelineEvent, ...]: Ordered, deduplicated sequence of events.
    """
    reconstructor = _DEFAULT_RECONSTRUCTOR_DEDUP if deduplicate else _DEFAULT_RECONSTRUCTOR_NO_DEDUP
    return reconstructor.order_and_deduplicate(events)
