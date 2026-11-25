"""
Forensic Correlation Engine for ForensiX (V4.2 Event Correlation).

Discovers deterministic, explainable relationships between V3 TimelineEvents
without modifying evidence, altering timeline events, or generating speculative
compromise conclusions.

Supported Relationship Types:
1. TEMPORAL: Events occurring within a configured time window.
2. SAME_USER: Events explicitly sharing the same user/account identity.
3. SAME_SOURCE: Events explicitly originating from the same source (IP, host).
4. SAME_PATH: Events explicitly referencing the same normalized path/resource.
5. SAME_SESSION: Events explicitly sharing the same session identifier.
6. AUTHENTICATION_PRIVILEGE: Successful authentication followed by privilege-related activity.

Core Principles:
- Factual observation representation only: Correlation is NOT proof of compromise.
- Deterministic execution: Identical inputs produce identical correlation outputs and order.
- Respect V3 timestamp semantics: Never fabricate timestamps or assume timezones.
- Complete provenance: Preserves timeline event IDs, source event IDs, and source artifact IDs.
- Deep immutability: Input events are untouched; output is an immutable CorrelationCollection.
"""

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    create_correlation,
)
from forensix.identifier import normalize_relative_path
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)
from forensix.timeline_reconstruction import ReconstructedTimeline


# Default correlation window: 300.0 seconds (5 minutes)
DEFAULT_TIME_WINDOW_SECONDS: float = 300.0

# Default per-run cap on materialized Correlation links
DEFAULT_MAX_CORRELATIONS: int = 50000

_UNSET = object()

# Supported relationship types set for fast validation
ALL_RELATIONSHIP_TYPES: Tuple[CorrelationType, ...] = (
    CorrelationType.TEMPORAL,
    CorrelationType.SAME_USER,
    CorrelationType.SAME_SOURCE,
    CorrelationType.SAME_PATH,
    CorrelationType.SAME_SESSION,
    CorrelationType.AUTHENTICATION_PRIVILEGE,
    CorrelationType.HOST_NETWORK,
)

# Known event types and substrings indicating privilege activity
PRIVILEGE_EVENT_TYPES: Set[str] = {
    "sudo_command",
    "sudo_rule",
    "su_session",
    "privilege_escalation",
    "group_modified",
    "shadow_modified",
    "account_privilege_granted",
}

# Known event types indicating successful authentication
AUTH_SUCCESS_EVENT_TYPES: Set[str] = {
    "ssh_login_success",
    "session_open",
    "authentication_success",
    "login_success",
}


def compute_timestamp_delta(
    ts1: Optional[datetime],
    ts2: Optional[datetime],
) -> Optional[float]:
    """
    Compute absolute time difference in seconds between two timestamps.

    Follows V3 timestamp semantics:
    - Aware + Aware: Compares UTC instants.
    - Naive + Naive: Compares naive datetime values directly.
    - Aware + Naive: Returns None (awareness mismatch; never assumes a timezone).
    - Missing (None): Returns None (never fabricates a timestamp).
    """
    if ts1 is None or ts2 is None:
        return None

    aware1 = ts1.tzinfo is not None and ts1.tzinfo.utcoffset(ts1) is not None
    aware2 = ts2.tzinfo is not None and ts2.tzinfo.utcoffset(ts2) is not None

    if aware1 != aware2:
        return None

    if aware1:
        utc1 = ts1.astimezone(timezone.utc)
        utc2 = ts2.astimezone(timezone.utc)
        return abs((utc2 - utc1).total_seconds())

    return abs((ts2 - ts1).total_seconds())


def is_chronologically_ordered(
    ts1: Optional[datetime],
    ts2: Optional[datetime],
) -> Optional[bool]:
    """
    Check if ts1 <= ts2 in chronological time.

    Returns:
        True: If ts1 <= ts2.
        False: If ts1 > ts2.
        None: If either timestamp is missing or there is an awareness mismatch.
    """
    if ts1 is None or ts2 is None:
        return None

    aware1 = ts1.tzinfo is not None and ts1.tzinfo.utcoffset(ts1) is not None
    aware2 = ts2.tzinfo is not None and ts2.tzinfo.utcoffset(ts2) is not None

    if aware1 != aware2:
        return None

    if aware1:
        return ts1.astimezone(timezone.utc) <= ts2.astimezone(timezone.utc)

    return ts1 <= ts2


def _extract_attribute(event: TimelineEvent, key: str) -> Optional[Any]:
    """Extract a named attribute from a TimelineEvent's frozen attributes tuple."""
    if not event.attributes:
        return None
    for k, v in event.attributes:
        if k == key:
            return v
    return None


def extract_user_identity(event: TimelineEvent) -> Optional[str]:
    """
    Extract an explicit, non-empty user identity from a TimelineEvent.

    Only checks explicit user/username attributes. Does not infer identity from unrelated fields.
    """
    val = _extract_attribute(event, "username")
    if val is None:
        val = _extract_attribute(event, "user")
    if val is None:
        val = _extract_attribute(event, "account")

    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned:
            return cleaned
    return None


def extract_source_identity(event: TimelineEvent) -> Optional[str]:
    """
    Extract an explicit, non-empty source identity (IP, hostname, host) from a TimelineEvent.

    Does not infer source identity from unrelated fields.
    """
    val = _extract_attribute(event, "source_ip")
    if val is None:
        val = _extract_attribute(event, "src_ip")
    if val is None:
        val = _extract_attribute(event, "hostname")
    if val is None:
        val = _extract_attribute(event, "source_host")

    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned:
            return cleaned
    return None


def extract_path_identity(event: TimelineEvent) -> Optional[str]:
    """
    Extract and normalize an explicit path reference from a TimelineEvent.

    Checks explicit path attributes or event.source_path, and normalizes
    per project conventions via normalize_relative_path.
    """
    val = _extract_attribute(event, "path")
    if val is None:
        val = _extract_attribute(event, "target_path")
    if val is None:
        val = _extract_attribute(event, "file_path")
    if val is None and event.source_path:
        val = event.source_path

    if isinstance(val, (str, Path, PurePosixPath)):
        raw_str = str(val).strip()
        if raw_str:
            norm = normalize_relative_path(raw_str)
            if norm:
                return norm
    return None


def extract_session_identity(event: TimelineEvent) -> Optional[str]:
    """
    Extract an explicit, non-empty session identifier from a TimelineEvent.

    Does not infer sessions from unrelated fields.
    """
    val = _extract_attribute(event, "session_id")
    if val is None:
        val = _extract_attribute(event, "session")

    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned:
            return cleaned
    elif isinstance(val, int) and not isinstance(val, bool):
        return str(val)
    return None


def is_authentication_event(event: TimelineEvent) -> bool:
    """
    Determine if a TimelineEvent represents an authentication event.
    """
    cat_str = event.category.value if hasattr(event.category, "value") else str(event.category)
    if cat_str.lower() == "authentication":
        status = _extract_attribute(event, "status")
        # Exclude failed authentication for initial authentication_privilege matching
        if isinstance(status, str) and status.upper() in ("FAILURE", "FAILED"):
            return False
        return True

    return event.event_type.lower() in AUTH_SUCCESS_EVENT_TYPES


def is_privilege_event(event: TimelineEvent) -> bool:
    """
    Determine if a TimelineEvent represents privilege-related activity.
    """
    ev_type_lower = event.event_type.lower()
    if ev_type_lower in PRIVILEGE_EVENT_TYPES:
        return True
    if "sudo" in ev_type_lower or "privilege" in ev_type_lower:
        return True

    cmd = _extract_attribute(event, "command")
    if cmd and "sudo" in str(cmd).lower():
        return True

    return False


@dataclass(frozen=True)
class CorrelationConfig:
    """
    Configuration for the ForensiX V4.2 Correlation Engine.

    Attributes:
        time_window_seconds: Maximum delta in seconds for temporal relationships (inclusive).
        relationship_types: Explicit tuple of relationship types to evaluate.
        max_correlations: Optional maximum number of correlations to discover (default: 50000).
    """

    time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS
    relationship_types: Tuple[CorrelationType, ...] = ALL_RELATIONSHIP_TYPES
    max_correlations: Optional[int] = DEFAULT_MAX_CORRELATIONS

    def __init__(
        self,
        *,
        time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
        relationship_types: Optional[Sequence[Union[CorrelationType, str]]] = None,
        max_correlations: Any = _UNSET,
    ) -> None:
        if isinstance(time_window_seconds, bool) or not isinstance(time_window_seconds, (int, float)):
            raise TypeError(
                f"time_window_seconds must be a float or int, got {type(time_window_seconds).__name__}"
            )
        if time_window_seconds < 0:
            raise ValueError(f"time_window_seconds must be non-negative, got {time_window_seconds}")

        if relationship_types is None:
            validated_types = ALL_RELATIONSHIP_TYPES
        elif isinstance(relationship_types, (list, tuple, set)):
            v_list: List[CorrelationType] = []
            for t in relationship_types:
                if isinstance(t, CorrelationType):
                    v_list.append(t)
                elif isinstance(t, str):
                    clean = t.strip().upper()
                    try:
                        v_list.append(CorrelationType(clean))
                    except ValueError:
                        valid_vals = sorted([rt.value for rt in ALL_RELATIONSHIP_TYPES])
                        raise ValueError(
                            f"Invalid relationship type: '{t}'. Must be one of: {valid_vals}"
                        )
                else:
                    raise TypeError(
                        f"relationship_types item must be CorrelationType or str, got {type(t).__name__}"
                    )
            validated_types = tuple(dict.fromkeys(v_list))
        else:
            raise TypeError(
                f"relationship_types must be a sequence of CorrelationType or str, got {type(relationship_types).__name__}"
            )

        resolved_max = DEFAULT_MAX_CORRELATIONS if max_correlations is _UNSET else max_correlations
        if resolved_max is not None:
            if isinstance(resolved_max, bool) or not isinstance(resolved_max, int):
                raise TypeError(
                    f"max_correlations must be an integer, got {type(resolved_max).__name__}"
                )
            if resolved_max < 1:
                raise ValueError(f"max_correlations must be >= 1, got {resolved_max}")

        object.__setattr__(self, "time_window_seconds", float(time_window_seconds))
        object.__setattr__(self, "relationship_types", validated_types)
        object.__setattr__(self, "max_correlations", resolved_max)


def correlation_sort_key(corr: Correlation) -> Tuple[Any, ...]:
    """
    Construct a deterministic comparison key for sorting Correlation objects.

    Ordering guarantees:
    1. Aware start timestamps first (sorted by UTC instant).
    2. Naive start timestamps second (sorted by naive datetime).
    3. Missing start timestamps third.
    4. Relationship type value (lexicographical).
    5. Inverted/canonical event IDs (lexicographical).
    6. Correlation ID (lexicographical).
    """
    ts = corr.start_timestamp
    if ts is None:
        ts_class = 2
        ts_val: Any = 0
    elif ts.tzinfo is not None and ts.tzinfo.utcoffset(ts) is not None:
        ts_class = 0
        ts_val = ts.astimezone(timezone.utc)
    else:
        ts_class = 1
        ts_val = ts

    eid1 = corr.event_ids[0] if corr.event_ids else ""
    eid2 = corr.event_ids[1] if len(corr.event_ids) > 1 else ""

    return (
        ts_class,
        ts_val,
        corr.relationship_type.value,
        eid1,
        eid2,
        corr.correlation_id,
    )


@dataclass(frozen=True)
class _PreparedEvent:
    """Pre-extracted event fields for O(1) per-candidate correlation checks."""

    index: int
    event: TimelineEvent
    user: Optional[str]
    source: Optional[str]
    path: Optional[str]
    session: Optional[str]
    is_auth: bool
    is_priv: bool
    ts_kind: str  # "aware", "naive", or "none"
    ts_cmp: Optional[datetime]


def _prepare_event(index: int, event: TimelineEvent) -> _PreparedEvent:
    """Extract all correlation identities, flags, and normalized timestamp once per event."""
    attr_map: Dict[str, Any] = dict(event.attributes) if event.attributes else {}

    # User identity
    user_val = attr_map.get("username")
    if user_val is None:
        user_val = attr_map.get("user")
    if user_val is None:
        user_val = attr_map.get("account")
    user = user_val.strip() if isinstance(user_val, str) and user_val.strip() else None

    # Source identity
    src_val = attr_map.get("source_ip")
    if src_val is None:
        src_val = attr_map.get("src_ip")
    if src_val is None:
        src_val = attr_map.get("hostname")
    if src_val is None:
        src_val = attr_map.get("source_host")
    source = src_val.strip() if isinstance(src_val, str) and src_val.strip() else None

    # Normalized path identity
    path_val = attr_map.get("path")
    if path_val is None:
        path_val = attr_map.get("target_path")
    if path_val is None:
        path_val = attr_map.get("file_path")
    if path_val is None and event.source_path:
        path_val = event.source_path
    norm_path: Optional[str] = None
    if isinstance(path_val, (str, Path, PurePosixPath)):
        raw_str = str(path_val).strip()
        if raw_str:
            norm = normalize_relative_path(raw_str)
            if norm:
                norm_path = norm

    # Session identity
    sess_val = attr_map.get("session_id")
    if sess_val is None:
        sess_val = attr_map.get("session")
    session: Optional[str] = None
    if isinstance(sess_val, str):
        cleaned_sess = sess_val.strip()
        if cleaned_sess:
            session = cleaned_sess
    elif isinstance(sess_val, int) and not isinstance(sess_val, bool):
        session = str(sess_val)

    # Auth / privilege flags
    cat_str = event.category.value if hasattr(event.category, "value") else str(event.category)
    ev_type_lower = event.event_type.lower()
    if cat_str.lower() == "authentication":
        status = attr_map.get("status")
        is_auth = not (isinstance(status, str) and status.upper() in ("FAILURE", "FAILED"))
    else:
        is_auth = ev_type_lower in AUTH_SUCCESS_EVENT_TYPES

    cmd = attr_map.get("command")
    is_priv = (
        ev_type_lower in PRIVILEGE_EVENT_TYPES
        or "sudo" in ev_type_lower
        or "privilege" in ev_type_lower
        or bool(cmd and "sudo" in str(cmd).lower())
    )

    # Timestamp classification
    ts = event.timestamp
    if ts is None:
        ts_kind = "none"
        ts_cmp = None
    elif ts.tzinfo is not None and ts.tzinfo.utcoffset(ts) is not None:
        ts_kind = "aware"
        ts_cmp = ts.astimezone(timezone.utc)
    else:
        ts_kind = "naive"
        ts_cmp = ts

    return _PreparedEvent(
        index=index,
        event=event,
        user=user,
        source=source,
        path=norm_path,
        session=session,
        is_auth=is_auth,
        is_priv=is_priv,
        ts_kind=ts_kind,
        ts_cmp=ts_cmp,
    )


def _pair_delta(p1: _PreparedEvent, p2: _PreparedEvent) -> Optional[float]:
    """Compute exact absolute delta in seconds using pre-classified timestamps."""
    if p1.ts_cmp is None or p2.ts_cmp is None or p1.ts_kind != p2.ts_kind:
        return None
    return abs((p2.ts_cmp - p1.ts_cmp).total_seconds())


class CorrelationEngine:
    """
    Deterministic correlation discovery engine for ForensiX timeline events.

    Receives V3 timeline events and evaluates explicit, factual correlation conditions
    without modifying evidence or speculating about security compromises.
    """

    def __init__(
        self,
        config: Optional[CorrelationConfig] = None,
        *,
        time_window_seconds: Optional[float] = None,
        relationship_types: Optional[Sequence[Union[CorrelationType, str]]] = None,
        max_correlations: Any = _UNSET,
    ) -> None:
        if config is not None:
            if not isinstance(config, CorrelationConfig):
                raise TypeError(f"config must be CorrelationConfig, got {type(config).__name__}")
            self.config = config
        else:
            kwargs: Dict[str, Any] = {}
            if time_window_seconds is not None:
                kwargs["time_window_seconds"] = time_window_seconds
            if relationship_types is not None:
                kwargs["relationship_types"] = relationship_types
            if max_correlations is not _UNSET:
                kwargs["max_correlations"] = max_correlations
            self.config = CorrelationConfig(**kwargs)

    def correlate(
        self,
        timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    ) -> CorrelationCollection:
        """
        Evaluate timeline events and discover all factual relationships matching configuration.

        Args:
            timeline: A ReconstructedTimeline instance or sequence of TimelineEvent objects.

        Returns:
            CorrelationCollection containing discovered Correlation instances in deterministic order.

        Raises:
            TypeError: If timeline is not a ReconstructedTimeline or sequence of TimelineEvents.
        """
        if isinstance(timeline, ReconstructedTimeline):
            events = timeline.events
        elif isinstance(timeline, (list, tuple)):
            for idx, item in enumerate(timeline):
                if not isinstance(item, TimelineEvent):
                    raise TypeError(
                        f"Item at index {idx} in timeline is not a TimelineEvent, got {type(item).__name__}"
                    )
            events = tuple(timeline)
        else:
            raise TypeError(
                f"timeline must be a ReconstructedTimeline or sequence of TimelineEvents, got {type(timeline).__name__}"
            )

        num_events = len(events)
        if num_events < 2:
            return CorrelationCollection(())

        active_types = set(self.config.relationship_types)
        window = self.config.time_window_seconds
        window_td = timedelta(seconds=window)
        limit = self.config.max_correlations

        prepared = [_prepare_event(idx, ev) for idx, ev in enumerate(events)]

        discovered: List[Correlation] = []
        seen_pairs: Set[Tuple[str, Tuple[str, str]]] = set()
        truncated = False
        skipped_candidates = 0

        def _pair_key(e1: TimelineEvent, e2: TimelineEvent) -> Tuple[str, str]:
            id1 = e1.event_id
            id2 = e2.event_id
            return (id1, id2) if id1 <= id2 else (id2, id1)

        def _try_emit(
            rel_type: CorrelationType,
            e1: TimelineEvent,
            e2: TimelineEvent,
            description: str,
            delta: Optional[float],
            attributes: Dict[str, Any],
        ) -> bool:
            """Emit correlation if unseen and under cap. Returns False if cap blocked emission."""
            nonlocal truncated, skipped_candidates
            dedup_key = (rel_type.value, _pair_key(e1, e2))
            if dedup_key in seen_pairs:
                return True
            if limit is not None and len(discovered) >= limit:
                truncated = True
                skipped_candidates += 1
                return False
            corr = create_correlation(
                relationship_type=rel_type,
                event_ids=[e1, e2],
                description=description,
                time_delta_seconds=delta,
                attributes=attributes,
            )
            discovered.append(corr)
            seen_pairs.add(dedup_key)
            return True

        def _process_windowed_seq(
            seq: List[int],
            rel_type: CorrelationType,
            make_desc_and_attrs: Any,
        ) -> None:
            nonlocal truncated, skipped_candidates
            m = len(seq)
            if m < 2:
                return
            hi = 0
            for pos1 in range(m):
                i = seq[pos1]
                p1 = prepared[i]
                t1 = p1.ts_cmp
                assert t1 is not None
                if hi <= pos1:
                    hi = pos1 + 1
                limit_ts = t1 + window_td
                while hi < m and prepared[seq[hi]].ts_cmp <= limit_ts:  # type: ignore[operator]
                    hi += 1

                if limit is not None and len(discovered) >= limit:
                    truncated = True
                    skipped_candidates += hi - pos1 - 1
                    continue

                for pos2 in range(pos1 + 1, hi):
                    j = seq[pos2]
                    p2 = prepared[j]
                    if p1.event.event_id == p2.event.event_id:
                        continue
                    if limit is not None and len(discovered) >= limit:
                        truncated = True
                        skipped_candidates += hi - pos2
                        break
                    delta = abs((p2.ts_cmp - t1).total_seconds())  # type: ignore[operator]
                    desc, attrs = make_desc_and_attrs(p1, p2, delta)
                    ordered = (p1.event, p2.event) if p1.index < p2.index else (p2.event, p1.event)
                    _try_emit(rel_type, ordered[0], ordered[1], desc, delta, attrs)

        def _process_cross_lists(
            list_a: List[int],
            list_b: List[int],
            rel_type: CorrelationType,
            make_desc_and_attrs: Any,
        ) -> None:
            nonlocal truncated, skipped_candidates
            if not list_a or not list_b:
                return
            if limit is not None and len(discovered) >= limit:
                truncated = True
                skipped_candidates += len(list_a) * len(list_b)
                return
            total_b = len(list_b)
            for idx_a, i in enumerate(list_a):
                p1 = prepared[i]
                if limit is not None and len(discovered) >= limit:
                    truncated = True
                    skipped_candidates += (len(list_a) - idx_a) * total_b
                    return
                for idx_b, j in enumerate(list_b):
                    p2 = prepared[j]
                    if p1.event.event_id == p2.event.event_id:
                        continue
                    if limit is not None and len(discovered) >= limit:
                        truncated = True
                        skipped_candidates += (total_b - idx_b) + (len(list_a) - idx_a - 1) * total_b
                        return
                    desc, attrs = make_desc_and_attrs(p1, p2, None)
                    ordered = (p1.event, p2.event) if p1.index < p2.index else (p2.event, p1.event)
                    _try_emit(rel_type, ordered[0], ordered[1], desc, None, attrs)

        def _process_unordered_list(
            seq: List[int],
            rel_type: CorrelationType,
            make_desc_and_attrs: Any,
        ) -> None:
            nonlocal truncated, skipped_candidates
            m = len(seq)
            if m < 2:
                return
            if limit is not None and len(discovered) >= limit:
                truncated = True
                skipped_candidates += m * (m - 1) // 2
                return
            for pos1 in range(m):
                p1 = prepared[seq[pos1]]
                if limit is not None and len(discovered) >= limit:
                    truncated = True
                    rem = m - pos1
                    skipped_candidates += rem * (rem - 1) // 2
                    return
                for pos2 in range(pos1 + 1, m):
                    p2 = prepared[seq[pos2]]
                    if p1.event.event_id == p2.event.event_id:
                        continue
                    if limit is not None and len(discovered) >= limit:
                        truncated = True
                        rem_tail = m - pos2
                        rem_after = m - pos1 - 1
                        skipped_candidates += rem_tail + (rem_after * (rem_after - 1) // 2)
                        return
                    desc, attrs = make_desc_and_attrs(p1, p2, None)
                    ordered = (p1.event, p2.event) if p1.index < p2.index else (p2.event, p1.event)
                    _try_emit(rel_type, ordered[0], ordered[1], desc, None, attrs)

        aware_sorted = sorted(
            (p.index for p in prepared if p.ts_kind == "aware"),
            key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
        )
        naive_sorted = sorted(
            (p.index for p in prepared if p.ts_kind == "naive"),
            key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
        )

        # 1. TEMPORAL relationship (sliding time window)
        if CorrelationType.TEMPORAL in active_types:
            def _temporal_payload(p1: _PreparedEvent, p2: _PreparedEvent, delta: Optional[float]) -> Tuple[str, Dict[str, Any]]:
                assert delta is not None
                return (
                    f"Events occurred within {delta:.1f}s (configured window: {window:.1f}s)",
                    {"delta_seconds": delta, "window_seconds": window},
                )

            _process_windowed_seq(aware_sorted, CorrelationType.TEMPORAL, _temporal_payload)
            _process_windowed_seq(naive_sorted, CorrelationType.TEMPORAL, _temporal_payload)

        # 2-5. Bucketed attribute relationships
        def _run_bucketed_relationship(
            rel_type: CorrelationType,
            key_getter: Any,
            make_desc_and_attrs: Any,
        ) -> None:
            buckets: Dict[str, List[int]] = {}
            for p in prepared:
                key_val = key_getter(p)
                if key_val:
                    buckets.setdefault(key_val, []).append(p.index)

            for key_val in sorted(buckets.keys()):
                idxs = buckets[key_val]
                if len(idxs) < 2:
                    continue
                b_aware = sorted(
                    (idx for idx in idxs if prepared[idx].ts_kind == "aware"),
                    key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
                )
                b_naive = sorted(
                    (idx for idx in idxs if prepared[idx].ts_kind == "naive"),
                    key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
                )
                b_none = [idx for idx in idxs if prepared[idx].ts_kind == "none"]

                _process_windowed_seq(b_aware, rel_type, make_desc_and_attrs)
                _process_windowed_seq(b_naive, rel_type, make_desc_and_attrs)
                _process_cross_lists(b_aware, b_naive, rel_type, make_desc_and_attrs)
                _process_cross_lists(b_aware, b_none, rel_type, make_desc_and_attrs)
                _process_cross_lists(b_naive, b_none, rel_type, make_desc_and_attrs)
                _process_unordered_list(b_none, rel_type, make_desc_and_attrs)

        if CorrelationType.SAME_USER in active_types:
            _run_bucketed_relationship(
                CorrelationType.SAME_USER,
                lambda p: p.user,
                lambda p1, p2, delta: (
                    f"Events share the same user identity: '{p1.user}'",
                    {"user": p1.user, "delta_seconds": delta},
                ),
            )

        if CorrelationType.SAME_SOURCE in active_types:
            _run_bucketed_relationship(
                CorrelationType.SAME_SOURCE,
                lambda p: p.source,
                lambda p1, p2, delta: (
                    f"Events share the same source identity: '{p1.source}'",
                    {"source": p1.source, "delta_seconds": delta},
                ),
            )

        if CorrelationType.SAME_PATH in active_types:
            _run_bucketed_relationship(
                CorrelationType.SAME_PATH,
                lambda p: p.path,
                lambda p1, p2, delta: (
                    f"Events reference the same normalized path: '{p1.path}'",
                    {"path": p1.path, "delta_seconds": delta},
                ),
            )

        if CorrelationType.SAME_SESSION in active_types:
            _run_bucketed_relationship(
                CorrelationType.SAME_SESSION,
                lambda p: p.session,
                lambda p1, p2, delta: (
                    f"Events share the same session identifier: '{p1.session}'",
                    {"session_id": p1.session, "delta_seconds": delta},
                ),
            )

        # 6. AUTHENTICATION_PRIVILEGE relationship
        if CorrelationType.AUTHENTICATION_PRIVILEGE in active_types:
            auth_indices = [p.index for p in prepared if p.is_auth]
            priv_indices = [p.index for p in prepared if p.is_priv]

            if auth_indices and priv_indices:
                priv_aware = sorted(
                    (idx for idx in priv_indices if prepared[idx].ts_kind == "aware"),
                    key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
                )
                priv_naive = sorted(
                    (idx for idx in priv_indices if prepared[idx].ts_kind == "naive"),
                    key=lambda idx: (prepared[idx].ts_cmp, idx),  # type: ignore[arg-type]
                )
                priv_none = [idx for idx in priv_indices if prepared[idx].ts_kind == "none"]
                priv_aware_ts = [prepared[idx].ts_cmp for idx in priv_aware]
                priv_naive_ts = [prepared[idx].ts_cmp for idx in priv_naive]

                for i_auth in auth_indices:
                    pa = prepared[i_auth]
                    candidates: List[int] = []
                    if pa.ts_kind == "aware":
                        assert pa.ts_cmp is not None
                        lo = bisect_left(priv_aware_ts, pa.ts_cmp)  # type: ignore[type-var]
                        hi = bisect_right(priv_aware_ts, pa.ts_cmp + window_td)  # type: ignore[type-var]
                        candidates.extend(priv_aware[lo:hi])
                        candidates.extend(idx for idx in priv_none if i_auth < idx)
                    elif pa.ts_kind == "naive":
                        assert pa.ts_cmp is not None
                        lo = bisect_left(priv_naive_ts, pa.ts_cmp)  # type: ignore[type-var]
                        hi = bisect_right(priv_naive_ts, pa.ts_cmp + window_td)  # type: ignore[type-var]
                        candidates.extend(priv_naive[lo:hi])
                        candidates.extend(idx for idx in priv_none if i_auth < idx)
                    else:
                        candidates.extend(idx for idx in priv_indices if i_auth < idx)

                    for i_priv in candidates:
                        if i_priv == i_auth:
                            continue
                        pp = prepared[i_priv]
                        if pa.event.event_id == pp.event.event_id:
                            continue
                        if pa.user is not None and pp.user is not None and pa.user != pp.user:
                            continue
                        delta = _pair_delta(pa, pp)
                        if delta is not None and delta > window:
                            continue
                        target_user = pa.user or pp.user or "unknown"
                        desc = (
                            f"Observed authentication activity ('{pa.event.event_type}') "
                            f"followed by privilege-related activity ('{pp.event.event_type}') "
                            f"for user '{target_user}'"
                        )
                        _try_emit(
                            CorrelationType.AUTHENTICATION_PRIVILEGE,
                            pa.event,
                            pp.event,
                            desc,
                            delta,
                            {
                                "user": target_user,
                                "auth_event_type": pa.event.event_type,
                                "privilege_event_type": pp.event.event_type,
                                "delta_seconds": delta,
                            },
                        )

        # 7. HOST_NETWORK relationship (V5.6)
        if CorrelationType.HOST_NETWORK in active_types:
            if limit is None or len(discovered) < limit:
                from forensix.network_correlation import correlate_host_network_events

                remaining = (limit - len(discovered)) if limit is not None else None
                probe_limit = (remaining + 1) if remaining is not None else None
                host_net_corrs = correlate_host_network_events(
                    events,
                    time_window_seconds=window,
                    max_correlations=probe_limit,
                )
                for idx_hn, corr in enumerate(host_net_corrs):
                    pair_key = _pair_key_from_ids(corr.event_ids)
                    dedup_key = (CorrelationType.HOST_NETWORK.value, pair_key)
                    if dedup_key in seen_pairs:
                        continue
                    if limit is not None and len(discovered) >= limit:
                        truncated = True
                        skipped_candidates += len(host_net_corrs) - idx_hn
                        break
                    discovered.append(corr)
                    seen_pairs.add(dedup_key)

        # Sort discovered correlations in stable, deterministic order
        discovered.sort(key=correlation_sort_key)

        if limit is not None and len(discovered) > limit:
            skipped_candidates += len(discovered) - limit
            discovered = discovered[:limit]
            truncated = True

        return CorrelationCollection(
            discovered,
            truncated=truncated,
            skipped_candidates=skipped_candidates,
        )


def _pair_key_from_ids(event_ids: Tuple[str, ...]) -> Tuple[str, str]:
    if len(event_ids) == 2:
        id1, id2 = event_ids[0], event_ids[1]
        return (id1, id2) if id1 <= id2 else (id2, id1)
    sorted_ids = sorted(event_ids)
    return (sorted_ids[0], sorted_ids[1]) if len(sorted_ids) >= 2 else ("", "")


def correlate_events(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    config: Optional[CorrelationConfig] = None,
    *,
    time_window_seconds: Optional[float] = None,
    relationship_types: Optional[Sequence[Union[CorrelationType, str]]] = None,
    max_correlations: Any = _UNSET,
) -> CorrelationCollection:
    """
    Convenience functional interface to discover correlations from timeline events.

    Args:
        timeline: ReconstructedTimeline or sequence of TimelineEvent instances.
        config: Optional pre-configured CorrelationConfig instance.
        time_window_seconds: Configurable maximum time window delta (seconds).
        relationship_types: Optional subset of relationship types to evaluate.
        max_correlations: Optional cap on returned correlations.

    Returns:
        Immutable CorrelationCollection containing discovered relationships.
    """
    engine = CorrelationEngine(
        config=config,
        time_window_seconds=time_window_seconds,
        relationship_types=relationship_types,
        max_correlations=max_correlations,
    )
    return engine.correlate(timeline)
