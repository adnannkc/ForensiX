"""
Forensic Timeline Querying and Filtering Engine for ForensiX (V3.5).

Provides a safe, deterministic, and immutable querying layer over already reconstructed
timelines (ReconstructedTimeline or TimelineEvent sequences) without modifying events,
reordering results, or introducing speculative investigative conclusions.

Core Principles:
1. Pure factual filtering: Filters events based on observed properties (timestamps, categories,
   event types, source paths, artifact/event IDs, and raw text). No detection, correlation,
   or risk scoring.
2. Strict ordering preservation: Query results retain the canonical chronological order
   established by V3.4 Timeline Reconstruction.
3. Timezone fidelity:
   - Aware query matches aware events by UTC instant.
   - Naive query matches naive events directly.
   - Incompatible timezone awareness (aware query + naive event, or naive query + aware event)
     is treated as non-matching without guessing or fabricating timezones.
   - Events with missing timestamps (timestamp=None) never match timestamp ranges but match
     non-time filters.
4. Deep immutability: Source events and timelines are never mutated.
5. Deterministic output: Identical queries against identical timelines produce identical results.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.timeline_reconstruction import ReconstructedTimeline
from forensix.timestamp_normalizer import is_timezone_aware, normalize_timestamp


VALID_CATEGORIES = frozenset(c.value for c in TimelineCategory)


def _validate_and_normalize_query_timestamp(
    val: Optional[Union[datetime, str]],
    field_name: str,
) -> Optional[datetime]:
    """
    Validate and convert query timestamp inputs into datetime instances.

    Uses V3.2 normalize_timestamp to ensure sound parsing and date-only rejection.
    Preserves timezone awareness as-is (aware stays aware, naive stays naive).
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        clean = val.strip()
        if not clean:
            raise ValueError(f"{field_name} timestamp cannot be empty or whitespace")
        # to_utc=False preserves original timezone awareness/offset
        return normalize_timestamp(clean, to_utc=False)
    raise TypeError(
        f"{field_name} must be datetime, ISO timestamp string, or None, got {type(val).__name__}"
    )


@dataclass(frozen=True)
class TimelineQuery:
    """
    Immutable specification of factual filter criteria for querying a timeline.

    Filters are combined using logical AND: only events matching all supplied non-None
    filters are returned.

    Attributes:
        start: Earliest event timestamp (inclusive).
        end: Latest event timestamp (inclusive).
        category: High-level TimelineCategory or valid category string.
        event_type: Specific factual event classification string (exact match).
        source_path: Evidence file path (exact match).
        source_artifact_id: Parent artifact tracking ID (exact match).
        source_event_id: Specialized record tracking ID (exact match).
        text: Substring to search across description, raw_data, and string attributes.
        case_sensitive: Whether text search is case-sensitive (default: False).
    """

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    category: Optional[TimelineCategory] = None
    event_type: Optional[str] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    source_event_id: Optional[str] = None
    text: Optional[str] = None
    case_sensitive: bool = False

    def __init__(
        self,
        *,
        start: Optional[Union[datetime, str]] = None,
        end: Optional[Union[datetime, str]] = None,
        category: Optional[Union[TimelineCategory, str]] = None,
        event_type: Optional[str] = None,
        source_path: Optional[Union[str, Path]] = None,
        source_artifact_id: Optional[str] = None,
        source_event_id: Optional[str] = None,
        text: Optional[str] = None,
        case_sensitive: bool = False,
    ) -> None:
        norm_start = _validate_and_normalize_query_timestamp(start, "start")
        norm_end = _validate_and_normalize_query_timestamp(end, "end")

        # Validate range compatibility and order
        if norm_start is not None and norm_end is not None:
            start_aware = is_timezone_aware(norm_start)
            end_aware = is_timezone_aware(norm_end)
            if start_aware != end_aware:
                raise ValueError(
                    "start and end timestamps must have matching timezone awareness "
                    f"(start aware={start_aware}, end aware={end_aware}). "
                    "Do not mix timezone-aware and timezone-naive boundary parameters."
                )
            if start_aware:
                if norm_start.astimezone(timezone.utc) > norm_end.astimezone(timezone.utc):
                    raise ValueError(
                        f"start timestamp ({norm_start.isoformat()}) cannot be greater than "
                        f"end timestamp ({norm_end.isoformat()})"
                    )
            else:
                if norm_start > norm_end:
                    raise ValueError(
                        f"start timestamp ({norm_start.isoformat()}) cannot be greater than "
                        f"end timestamp ({norm_end.isoformat()})"
                    )

        # Validate category
        norm_cat: Optional[TimelineCategory] = None
        if category is not None:
            if isinstance(category, TimelineCategory):
                norm_cat = category
            elif isinstance(category, str):
                cat_clean = category.strip().lower()
                if cat_clean not in VALID_CATEGORIES:
                    raise ValueError(
                        f"Invalid category '{category}'. Must be one of: {sorted(VALID_CATEGORIES)}"
                    )
                norm_cat = TimelineCategory(cat_clean)
            else:
                raise TypeError(
                    f"category must be TimelineCategory, str, or None, got {type(category).__name__}"
                )

        # Validate event_type
        norm_event_type: Optional[str] = None
        if event_type is not None:
            if not isinstance(event_type, str):
                raise TypeError(f"event_type must be str, got {type(event_type).__name__}")
            clean_et = event_type.strip()
            if not clean_et:
                raise ValueError("event_type cannot be empty or whitespace")
            norm_event_type = clean_et

        # Validate source_path
        norm_source_path: Optional[str] = None
        if source_path is not None:
            if isinstance(source_path, (str, Path)):
                clean_sp = str(source_path).strip()
                if not clean_sp:
                    raise ValueError("source_path cannot be empty or whitespace")
                norm_source_path = clean_sp
            else:
                raise TypeError(f"source_path must be str, Path, or None, got {type(source_path).__name__}")

        # Validate source_artifact_id
        norm_art_id: Optional[str] = None
        if source_artifact_id is not None:
            if not isinstance(source_artifact_id, str):
                raise TypeError(f"source_artifact_id must be str, got {type(source_artifact_id).__name__}")
            clean_aid = source_artifact_id.strip()
            if not clean_aid:
                raise ValueError("source_artifact_id cannot be empty or whitespace")
            norm_art_id = clean_aid

        # Validate source_event_id
        norm_eid: Optional[str] = None
        if source_event_id is not None:
            if not isinstance(source_event_id, str):
                raise TypeError(f"source_event_id must be str, got {type(source_event_id).__name__}")
            clean_eid = source_event_id.strip()
            if not clean_eid:
                raise ValueError("source_event_id cannot be empty or whitespace")
            norm_eid = clean_eid

        # Validate text
        norm_text: Optional[str] = None
        if text is not None:
            if not isinstance(text, str):
                raise TypeError(f"text must be str, got {type(text).__name__}")
            clean_txt = text.strip()
            if not clean_txt:
                raise ValueError("text cannot be empty or whitespace")
            norm_text = clean_txt if case_sensitive else clean_txt.lower()

        if not isinstance(case_sensitive, bool):
            raise TypeError(f"case_sensitive must be bool, got {type(case_sensitive).__name__}")

        object.__setattr__(self, "start", norm_start)
        object.__setattr__(self, "end", norm_end)
        object.__setattr__(self, "category", norm_cat)
        object.__setattr__(self, "event_type", norm_event_type)
        object.__setattr__(self, "source_path", norm_source_path)
        object.__setattr__(self, "source_artifact_id", norm_art_id)
        object.__setattr__(self, "source_event_id", norm_eid)
        object.__setattr__(self, "text", norm_text)
        object.__setattr__(self, "case_sensitive", case_sensitive)

    def matches(self, event: TimelineEvent) -> bool:
        """
        Evaluate whether an individual TimelineEvent matches all query criteria (logical AND).

        Args:
            event: TimelineEvent instance to evaluate.

        Returns:
            bool: True if event satisfies all query filters, False otherwise.
        """
        # 1. Category filter
        if self.category is not None and event.category != self.category:
            return False

        # 2. Event type filter (exact match)
        if self.event_type is not None and event.event_type != self.event_type:
            return False

        # 3. Source path filter (exact match)
        if self.source_path is not None and event.source_path != self.source_path:
            return False

        # 4. Source artifact ID filter (exact match)
        if self.source_artifact_id is not None and event.source_artifact_id != self.source_artifact_id:
            return False

        # 5. Source event ID filter (exact match)
        if self.source_event_id is not None and event.source_event_id != self.source_event_id:
            return False

        # 6. Timestamp range filtering
        if self.start is not None or self.end is not None:
            # Events without timestamps never match time-range queries
            if event.timestamp is None:
                return False

            event_is_aware = is_timezone_aware(event.timestamp)

            if self.start is not None:
                query_start_aware = is_timezone_aware(self.start)
                if query_start_aware != event_is_aware:
                    # Incompatible timezone awareness is treated as non-matching
                    return False
                if query_start_aware:
                    if event.timestamp.astimezone(timezone.utc) < self.start.astimezone(timezone.utc):
                        return False
                else:
                    if event.timestamp < self.start:
                        return False

            if self.end is not None:
                query_end_aware = is_timezone_aware(self.end)
                if query_end_aware != event_is_aware:
                    return False
                if query_end_aware:
                    if event.timestamp.astimezone(timezone.utc) > self.end.astimezone(timezone.utc):
                        return False
                else:
                    if event.timestamp > self.end:
                        return False

        # 7. Text search filter
        if self.text is not None:
            search_corpus = [event.description]
            if event.raw_data:
                search_corpus.append(event.raw_data)
            search_corpus.append(event.event_type)

            # Extract string attributes recursively
            def _extract_strings(attr_tuple: Any) -> None:
                if isinstance(attr_tuple, (tuple, list)):
                    for item in attr_tuple:
                        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                            search_corpus.append(item[0])
                            if isinstance(item[1], str):
                                search_corpus.append(item[1])
                            else:
                                _extract_strings(item[1])
                        elif isinstance(item, str):
                            search_corpus.append(item)
                        else:
                            _extract_strings(item)

            _extract_strings(event.attributes)

            matched = False
            for text_chunk in search_corpus:
                target = text_chunk if self.case_sensitive else text_chunk.lower()
                if self.text in target:
                    matched = True
                    break
            if not matched:
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert query parameters to a deterministic JSON-serializable dictionary."""
        return {
            "start": self.start.isoformat() if self.start is not None else None,
            "end": self.end.isoformat() if self.end is not None else None,
            "category": self.category.value if self.category is not None else None,
            "event_type": self.event_type,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "source_event_id": self.source_event_id,
            "text": self.text,
            "case_sensitive": self.case_sensitive,
        }


@dataclass(frozen=True)
class TimelineQueryResult:
    """
    Immutable representation of timeline query results preserving canonical timeline ordering.

    Attributes:
        events: Immutable tuple of matching TimelineEvent records.
        total_events: Count of matching events.
        query: The TimelineQuery specification used to produce this result.
    """

    events: Tuple[TimelineEvent, ...]
    total_events: int
    query: TimelineQuery

    def __post_init__(self) -> None:
        """Enforce deep immutability on the events collection."""
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))

    def __len__(self) -> int:
        return len(self.events)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.events[idx]

    def __iter__(self) -> Iterator[TimelineEvent]:
        return iter(self.events)

    def __contains__(self, item: Any) -> bool:
        return item in self.events

    def to_dict(self) -> Dict[str, Any]:
        """Convert query result to a deterministic JSON-serializable dictionary."""
        return {
            "summary": {
                "total_events": self.total_events,
                "query": self.query.to_dict(),
            },
            "events": [event.to_dict() for event in self.events],
        }


def query_timeline(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    query: Optional[TimelineQuery] = None,
    **kwargs: Any,
) -> TimelineQueryResult:
    """
    Execute a factual query against an already reconstructed timeline or TimelineEvent sequence.

    Preserves the canonical ordering established by V3.4 Timeline Reconstruction.
    Does not mutate events or timeline containers.

    Args:
        timeline: ReconstructedTimeline instance or sequence of TimelineEvents.
        query: Optional pre-constructed TimelineQuery.
        **kwargs: Filter arguments passed to TimelineQuery if query is not provided.

    Returns:
        TimelineQueryResult: Immutable query result container with matching events.

    Raises:
        ValueError: If timeline is None, or if both query and kwargs are supplied conflictingly.
        TypeError: If timeline elements are not TimelineEvents.
    """
    if timeline is None:
        raise ValueError("Timeline cannot be None")

    if query is not None and kwargs:
        raise ValueError(
            "Cannot specify both a TimelineQuery object and keyword arguments to query_timeline"
        )

    active_query = query if query is not None else TimelineQuery(**kwargs)

    # Extract event sequence
    if isinstance(timeline, ReconstructedTimeline):
        event_seq: Sequence[TimelineEvent] = timeline.events
    elif isinstance(timeline, TimelineQueryResult):
        event_seq = timeline.events
    elif isinstance(timeline, (tuple, list)):
        event_seq = timeline
    else:
        # Generic sequence fallback
        try:
            event_seq = tuple(timeline)
        except Exception as err:
            raise TypeError(f"Unsupported timeline container type: {type(timeline).__name__}") from err

    # Validate elements and filter while preserving exact input ordering
    matching_events: List[TimelineEvent] = []
    for i, item in enumerate(event_seq):
        if not isinstance(item, TimelineEvent):
            raise TypeError(
                f"Element at index {i} is not a TimelineEvent (got {type(item).__name__}). "
                "Timeline querying requires valid TimelineEvent instances."
            )
        if active_query.matches(item):
            matching_events.append(item)

    return TimelineQueryResult(
        events=tuple(matching_events),
        total_events=len(matching_events),
        query=active_query,
    )
