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

from dataclasses import dataclass
from datetime import datetime, timezone
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

# Supported relationship types set for fast validation
ALL_RELATIONSHIP_TYPES: Tuple[CorrelationType, ...] = (
    CorrelationType.TEMPORAL,
    CorrelationType.SAME_USER,
    CorrelationType.SAME_SOURCE,
    CorrelationType.SAME_PATH,
    CorrelationType.SAME_SESSION,
    CorrelationType.AUTHENTICATION_PRIVILEGE,
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
        max_correlations: Optional maximum number of correlations to discover.
    """

    time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS
    relationship_types: Tuple[CorrelationType, ...] = ALL_RELATIONSHIP_TYPES
    max_correlations: Optional[int] = None

    def __init__(
        self,
        *,
        time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
        relationship_types: Optional[Sequence[Union[CorrelationType, str]]] = None,
        max_correlations: Optional[int] = None,
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

        if max_correlations is not None:
            if isinstance(max_correlations, bool) or not isinstance(max_correlations, int):
                raise TypeError(
                    f"max_correlations must be an integer, got {type(max_correlations).__name__}"
                )
            if max_correlations < 1:
                raise ValueError(f"max_correlations must be >= 1, got {max_correlations}")

        object.__setattr__(self, "time_window_seconds", float(time_window_seconds))
        object.__setattr__(self, "relationship_types", validated_types)
        object.__setattr__(self, "max_correlations", max_correlations)


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
        max_correlations: Optional[int] = None,
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
            if max_correlations is not None:
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
        discovered: List[Correlation] = []
        seen_pairs: Set[Tuple[str, Tuple[str, ...]]] = set()

        for i in range(num_events):
            e1 = events[i]
            for j in range(i + 1, num_events):
                e2 = events[j]

                # Pair identity (order-independent event pair for duplicate prevention)
                pair_key = tuple(sorted([e1.event_id, e2.event_id]))

                # Compute temporal delta between e1 and e2 if both have timestamps
                delta = compute_timestamp_delta(e1.timestamp, e2.timestamp)

                # 1. TEMPORAL relationship
                if CorrelationType.TEMPORAL in active_types:
                    dedup_key = (CorrelationType.TEMPORAL.value, pair_key)
                    if dedup_key not in seen_pairs:
                        if delta is not None and delta <= window:
                            corr = create_correlation(
                                relationship_type=CorrelationType.TEMPORAL,
                                event_ids=[e1, e2],
                                description=f"Events occurred within {delta:.1f}s (configured window: {window:.1f}s)",
                                time_delta_seconds=delta,
                                attributes={"delta_seconds": delta, "window_seconds": window},
                            )
                            discovered.append(corr)
                            seen_pairs.add(dedup_key)

                # 2. SAME_USER relationship
                if CorrelationType.SAME_USER in active_types:
                    dedup_key = (CorrelationType.SAME_USER.value, pair_key)
                    if dedup_key not in seen_pairs:
                        u1 = extract_user_identity(e1)
                        u2 = extract_user_identity(e2)
                        if u1 and u2 and u1 == u2:
                            # If events have timestamps and a time window is set, enforce the window
                            if delta is None or delta <= window:
                                corr = create_correlation(
                                    relationship_type=CorrelationType.SAME_USER,
                                    event_ids=[e1, e2],
                                    description=f"Events share the same user identity: '{u1}'",
                                    time_delta_seconds=delta,
                                    attributes={"user": u1, "delta_seconds": delta},
                                )
                                discovered.append(corr)
                                seen_pairs.add(dedup_key)

                # 3. SAME_SOURCE relationship
                if CorrelationType.SAME_SOURCE in active_types:
                    dedup_key = (CorrelationType.SAME_SOURCE.value, pair_key)
                    if dedup_key not in seen_pairs:
                        s1 = extract_source_identity(e1)
                        s2 = extract_source_identity(e2)
                        if s1 and s2 and s1 == s2:
                            if delta is None or delta <= window:
                                corr = create_correlation(
                                    relationship_type=CorrelationType.SAME_SOURCE,
                                    event_ids=[e1, e2],
                                    description=f"Events share the same source identity: '{s1}'",
                                    time_delta_seconds=delta,
                                    attributes={"source": s1, "delta_seconds": delta},
                                )
                                discovered.append(corr)
                                seen_pairs.add(dedup_key)

                # 4. SAME_PATH relationship
                if CorrelationType.SAME_PATH in active_types:
                    dedup_key = (CorrelationType.SAME_PATH.value, pair_key)
                    if dedup_key not in seen_pairs:
                        p1 = extract_path_identity(e1)
                        p2 = extract_path_identity(e2)
                        if p1 and p2 and p1 == p2:
                            if delta is None or delta <= window:
                                corr = create_correlation(
                                    relationship_type=CorrelationType.SAME_PATH,
                                    event_ids=[e1, e2],
                                    description=f"Events reference the same normalized path: '{p1}'",
                                    time_delta_seconds=delta,
                                    attributes={"path": p1, "delta_seconds": delta},
                                )
                                discovered.append(corr)
                                seen_pairs.add(dedup_key)

                # 5. SAME_SESSION relationship
                if CorrelationType.SAME_SESSION in active_types:
                    dedup_key = (CorrelationType.SAME_SESSION.value, pair_key)
                    if dedup_key not in seen_pairs:
                        sess1 = extract_session_identity(e1)
                        sess2 = extract_session_identity(e2)
                        if sess1 and sess2 and sess1 == sess2:
                            if delta is None or delta <= window:
                                corr = create_correlation(
                                    relationship_type=CorrelationType.SAME_SESSION,
                                    event_ids=[e1, e2],
                                    description=f"Events share the same session identifier: '{sess1}'",
                                    time_delta_seconds=delta,
                                    attributes={"session_id": sess1, "delta_seconds": delta},
                                )
                                discovered.append(corr)
                                seen_pairs.add(dedup_key)

                # 6. AUTHENTICATION_PRIVILEGE relationship
                if CorrelationType.AUTHENTICATION_PRIVILEGE in active_types:
                    dedup_key = (CorrelationType.AUTHENTICATION_PRIVILEGE.value, pair_key)
                    if dedup_key not in seen_pairs:
                        # Must have one auth event and one privilege event
                        auth_first = is_authentication_event(e1) and is_privilege_event(e2)
                        auth_second = is_authentication_event(e2) and is_privilege_event(e1)

                        if auth_first or auth_second:
                            e_auth = e1 if auth_first else e2
                            e_priv = e2 if auth_first else e1

                            # Order requirement: e_auth must occur before or at the same time as e_priv
                            order_ok = False
                            if e_auth.timestamp is not None and e_priv.timestamp is not None:
                                is_ordered = is_chronologically_ordered(e_auth.timestamp, e_priv.timestamp)
                                if is_ordered is True:
                                    order_ok = True
                            elif auth_first:
                                # When timestamps are missing, preserve reconstructed timeline sequence order
                                order_ok = True

                            if order_ok:
                                # Check user identity compatibility if present on both
                                u_auth = extract_user_identity(e_auth)
                                u_priv = extract_user_identity(e_priv)
                                user_compatible = (u_auth is None or u_priv is None or u_auth == u_priv)

                                if user_compatible:
                                    if delta is None or delta <= window:
                                        target_user = u_auth or u_priv or "unknown"
                                        desc = (
                                            f"Observed authentication activity ('{e_auth.event_type}') "
                                            f"followed by privilege-related activity ('{e_priv.event_type}') "
                                            f"for user '{target_user}'"
                                        )
                                        corr = create_correlation(
                                            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
                                            event_ids=[e_auth, e_priv],
                                            description=desc,
                                            time_delta_seconds=delta,
                                            attributes={
                                                "user": target_user,
                                                "auth_event_type": e_auth.event_type,
                                                "privilege_event_type": e_priv.event_type,
                                                "delta_seconds": delta,
                                            },
                                        )
                                        discovered.append(corr)
                                        seen_pairs.add(dedup_key)

                # Stop early if max_correlations limit reached
                if (
                    self.config.max_correlations is not None
                    and len(discovered) >= self.config.max_correlations
                ):
                    break
            if (
                self.config.max_correlations is not None
                and len(discovered) >= self.config.max_correlations
            ):
                break

        # Sort discovered correlations in stable, deterministic order
        discovered.sort(key=correlation_sort_key)

        if self.config.max_correlations is not None:
            discovered = discovered[: self.config.max_correlations]

        return CorrelationCollection(discovered)


def correlate_events(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    config: Optional[CorrelationConfig] = None,
    *,
    time_window_seconds: Optional[float] = None,
    relationship_types: Optional[Sequence[Union[CorrelationType, str]]] = None,
    max_correlations: Optional[int] = None,
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
