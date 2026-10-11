"""
Forensic Host-to-Network Correlation for ForensiX (V5.6 Host-to-Network Correlation).

Provides a focused, defensible correlation layer linking host-level observations
(logs, authentication records, filesystem events) and network-level observations
(packets, transport frames, application metadata) within the unified ForensiX V3/V4
architecture.

Core Principles:
- Factual observation representation only: Correlation is NOT proof of compromise.
- No speculative attack labels, malicious attribution, or hypothetical risk scores.
- Strict provenance preservation: Preserves timeline event IDs, source artifact IDs,
  packet frame numbers, line numbers, and source event IDs.
- Explicit ambiguity handling: Rejects assumption that an IP uniquely identifies
  a single machine (acknowledges NAT, proxies, DHCP reassignment, shared addresses).
- Deep immutability and determinism: Output is an immutable CorrelationCollection
  with stable RFC 4122 UUIDv5 identities and reproducible sorting.
- Scalable indexing: Avoids unbounded O(N^2) pairwise comparisons via IP and identity
  indexing across the host-network partition boundary.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import (
    Any,
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

from forensix.correlation_engine import (
    DEFAULT_TIME_WINDOW_SECONDS,
    compute_timestamp_delta,
    correlation_sort_key,
    extract_session_identity,
    extract_user_identity,
)
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    compute_deterministic_correlation_id,
    create_correlation,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)
from forensix.timeline_reconstruction import ReconstructedTimeline


def normalize_ip_address(ip_val: Optional[Any]) -> Optional[str]:
    """
    Validate, clean, and normalize an IP address string.

    Returns the canonical string representation (e.g. '192.168.1.50' or '2001:db8::1'),
    or None if invalid or empty.
    """
    if ip_val is None:
        return None
    raw_str = str(ip_val).strip()
    if not raw_str:
        return None
    try:
        addr = ipaddress.ip_address(raw_str)
        return str(addr)
    except ValueError:
        return None


_SHARED_NETWORKS: Tuple[Any, ...] = (
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 Shared Address Space (CGNAT)
)


def is_private_or_shared_ip(ip_val: Optional[Any]) -> bool:
    """
    Determine if an IP address belongs to a private, loopback, link-local,
    multicast, or reserved/shared network range (e.g. RFC 1918, RFC 6598 CGNAT).
    """
    if ip_val is None:
        return False
    raw_str = str(ip_val).strip()
    if not raw_str:
        return False
    try:
        addr = ipaddress.ip_address(raw_str)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return True
        for net in _SHARED_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


def is_host_event(event: TimelineEvent) -> bool:
    """Return True if the timeline event is a host observation (non-network category)."""
    if not isinstance(event, TimelineEvent):
        return False
    cat = event.category
    cat_val = cat.value if hasattr(cat, "value") else str(cat)
    return cat_val.lower() != "network"


def is_network_event(event: TimelineEvent) -> bool:
    """Return True if the timeline event is a network observation."""
    if not isinstance(event, TimelineEvent):
        return False
    cat = event.category
    cat_val = cat.value if hasattr(cat, "value") else str(cat)
    return cat_val.lower() == "network"


def _extract_attribute_val(event: TimelineEvent, key: str) -> Optional[Any]:
    """Extract a named attribute value from a TimelineEvent's frozen attributes tuple."""
    if not event.attributes:
        return None
    for k, v in event.attributes:
        if k == key:
            return v
    return None


def extract_host_observed_ips(event: TimelineEvent) -> Set[str]:
    """
    Extract all explicit, normalized IP addresses observed in a host timeline event.

    Inspects standard host attribute keys: 'source_ip', 'src_ip', 'client_ip',
    'remote_ip', 'target_ip', 'destination_ip', 'dst_ip', 'ip_address'.
    Does not guess or fabricate addresses.
    """
    observed: Set[str] = set()
    candidate_keys = (
        "source_ip",
        "src_ip",
        "client_ip",
        "remote_ip",
        "target_ip",
        "destination_ip",
        "dst_ip",
        "ip_address",
        "host_ip",
    )
    for k in candidate_keys:
        val = _extract_attribute_val(event, k)
        norm = normalize_ip_address(val)
        if norm:
            observed.add(norm)
    return observed


def extract_network_ips(event: TimelineEvent) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract normalized (src_ip, dst_ip) from a network timeline event.
    """
    src = normalize_ip_address(_extract_attribute_val(event, "src_ip"))
    dst = normalize_ip_address(_extract_attribute_val(event, "dst_ip"))
    return src, dst


def extract_host_ports(event: TimelineEvent) -> Set[int]:
    """
    Extract explicit transport port integers from a host timeline event.

    Inspects 'source_port', 'src_port', 'port', 'target_port', 'dst_port'.
    """
    ports: Set[int] = set()
    candidate_keys = ("source_port", "src_port", "port", "target_port", "dst_port")
    for k in candidate_keys:
        val = _extract_attribute_val(event, k)
        if isinstance(val, int) and not isinstance(val, bool) and 1 <= val <= 65535:
            ports.add(val)
        elif isinstance(val, str) and val.isdigit():
            i_val = int(val)
            if 1 <= i_val <= 65535:
                ports.add(i_val)
    return ports


def extract_network_ports(event: TimelineEvent) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract (src_port, dst_port) integers from a network timeline event.
    """
    p_src = _extract_attribute_val(event, "src_port")
    p_dst = _extract_attribute_val(event, "dst_port")
    src_int = p_src if isinstance(p_src, int) and not isinstance(p_src, bool) and 1 <= p_src <= 65535 else None
    dst_int = p_dst if isinstance(p_dst, int) and not isinstance(p_dst, bool) and 1 <= p_dst <= 65535 else None
    return src_int, dst_int


@dataclass(frozen=True)
class HostNetworkCorrelationConfig:
    """
    Configuration options for host-to-network timeline correlation.

    Attributes:
        time_window_seconds: Maximum allowed time difference between host and network observations.
        match_ip: Whether to correlate host-observed IPs with network endpoints.
        match_user: Whether to require/check user identity equality when both present.
        match_session: Whether to require/check session identity equality when both present.
        match_port: Whether to check port alignment when ports are present on both events.
        known_host_ips: Optional set of IP addresses explicitly identified as belonging to the host.
        require_timestamps: If True, events lacking timestamps are not correlated.
        max_correlations: Maximum number of correlations to discover before stopping.
    """

    time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS
    match_ip: bool = True
    match_user: bool = True
    match_session: bool = True
    match_port: bool = True
    known_host_ips: Tuple[str, ...] = ()
    require_timestamps: bool = True
    max_correlations: Optional[int] = None

    def __init__(
        self,
        *,
        time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
        match_ip: bool = True,
        match_user: bool = True,
        match_session: bool = True,
        match_port: bool = True,
        known_host_ips: Optional[Iterable[str]] = None,
        require_timestamps: bool = True,
        max_correlations: Optional[int] = None,
    ) -> None:
        if isinstance(time_window_seconds, bool) or not isinstance(time_window_seconds, (int, float)):
            raise TypeError(
                f"time_window_seconds must be a float or int, got {type(time_window_seconds).__name__}"
            )
        if time_window_seconds < 0:
            raise ValueError(f"time_window_seconds must be non-negative, got {time_window_seconds}")

        if max_correlations is not None:
            if isinstance(max_correlations, bool) or not isinstance(max_correlations, int):
                raise TypeError(
                    f"max_correlations must be an integer, got {type(max_correlations).__name__}"
                )
            if max_correlations < 1:
                raise ValueError(f"max_correlations must be >= 1, got {max_correlations}")

        clean_host_ips: List[str] = []
        if known_host_ips is not None:
            for item in known_host_ips:
                norm = normalize_ip_address(item)
                if norm:
                    clean_host_ips.append(norm)

        object.__setattr__(self, "time_window_seconds", float(time_window_seconds))
        object.__setattr__(self, "match_ip", bool(match_ip))
        object.__setattr__(self, "match_user", bool(match_user))
        object.__setattr__(self, "match_session", bool(match_session))
        object.__setattr__(self, "match_port", bool(match_port))
        object.__setattr__(self, "known_host_ips", tuple(sorted(dict.fromkeys(clean_host_ips))))
        object.__setattr__(self, "require_timestamps", bool(require_timestamps))
        object.__setattr__(self, "max_correlations", max_correlations)


class HostNetworkCorrelator:
    """
    Deterministic, scalable host-to-network forensic correlator.

    Indexes network events by observed IP and identity attributes to achieve
    scalable O(N_host * k_candidates) evaluation without unbounded pairwise loops.
    """

    def __init__(
        self,
        config: Optional[HostNetworkCorrelationConfig] = None,
        *,
        time_window_seconds: Optional[float] = None,
        match_ip: Optional[bool] = None,
        match_user: Optional[bool] = None,
        match_session: Optional[bool] = None,
        match_port: Optional[bool] = None,
        known_host_ips: Optional[Iterable[str]] = None,
        require_timestamps: Optional[bool] = None,
        max_correlations: Optional[int] = None,
    ) -> None:
        if config is not None:
            if not isinstance(config, HostNetworkCorrelationConfig):
                raise TypeError(
                    f"config must be HostNetworkCorrelationConfig, got {type(config).__name__}"
                )
            self.config = config
        else:
            kwargs: Dict[str, Any] = {}
            if time_window_seconds is not None:
                kwargs["time_window_seconds"] = time_window_seconds
            if match_ip is not None:
                kwargs["match_ip"] = match_ip
            if match_user is not None:
                kwargs["match_user"] = match_user
            if match_session is not None:
                kwargs["match_session"] = match_session
            if match_port is not None:
                kwargs["match_port"] = match_port
            if known_host_ips is not None:
                kwargs["known_host_ips"] = known_host_ips
            if require_timestamps is not None:
                kwargs["require_timestamps"] = require_timestamps
            if max_correlations is not None:
                kwargs["max_correlations"] = max_correlations
            self.config = HostNetworkCorrelationConfig(**kwargs)

    def correlate(
        self,
        timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    ) -> CorrelationCollection:
        """
        Correlate host events and network events from the provided timeline.

        Returns:
            CorrelationCollection containing deterministic Correlation instances.
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

        if len(events) < 2:
            return CorrelationCollection(())

        # 1. Partition into host events and network events
        host_events: List[TimelineEvent] = []
        network_events: List[TimelineEvent] = []
        for e in events:
            if is_network_event(e):
                network_events.append(e)
            elif is_host_event(e):
                host_events.append(e)

        if not host_events or not network_events:
            return CorrelationCollection(())

        # 2. Build index structures over network events to avoid O(N^2) pairwise comparisons
        net_by_ip: Dict[str, List[TimelineEvent]] = {}
        net_by_user: Dict[str, List[TimelineEvent]] = {}
        net_by_session: Dict[str, List[TimelineEvent]] = {}

        for net_ev in network_events:
            src_ip, dst_ip = extract_network_ips(net_ev)
            if src_ip:
                net_by_ip.setdefault(src_ip, []).append(net_ev)
            if dst_ip:
                net_by_ip.setdefault(dst_ip, []).append(net_ev)

            u_net = extract_user_identity(net_ev)
            if u_net:
                net_by_user.setdefault(u_net.lower(), []).append(net_ev)

            sess_net = extract_session_identity(net_ev)
            if sess_net:
                net_by_session.setdefault(sess_net, []).append(net_ev)

        # 3. Discover correlations by matching host observations against network index
        discovered: List[Correlation] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        window = self.config.time_window_seconds
        known_host_ips_set = set(self.config.known_host_ips)

        for host_ev in host_events:
            # Determine candidate network events for this host observation
            candidates: Dict[str, Tuple[TimelineEvent, str, str]] = {}  # net_id -> (net_ev, match_dimension, matched_val)

            # A. Match on host-observed IPs
            if self.config.match_ip:
                host_ips = extract_host_observed_ips(host_ev)
                for h_ip in host_ips:
                    matching_nets = net_by_ip.get(h_ip, [])
                    for net_ev in matching_nets:
                        candidates[net_ev.event_id] = (net_ev, "ip_match", h_ip)

                # B. Match on known host IPs
                if known_host_ips_set:
                    for kh_ip in known_host_ips_set:
                        matching_nets = net_by_ip.get(kh_ip, [])
                        for net_ev in matching_nets:
                            if net_ev.event_id not in candidates:
                                candidates[net_ev.event_id] = (net_ev, "host_endpoint_ip_match", kh_ip)

            # C. Match on user identity if both have explicit identity
            if self.config.match_user:
                u_host = extract_user_identity(host_ev)
                if u_host:
                    matching_nets = net_by_user.get(u_host.lower(), [])
                    for net_ev in matching_nets:
                        if net_ev.event_id not in candidates:
                            candidates[net_ev.event_id] = (net_ev, "user_match", u_host)

            # D. Match on session identifier if both have explicit session
            if self.config.match_session:
                sess_host = extract_session_identity(host_ev)
                if sess_host:
                    matching_nets = net_by_session.get(sess_host, [])
                    for net_ev in matching_nets:
                        if net_ev.event_id not in candidates:
                            candidates[net_ev.event_id] = (net_ev, "session_match", sess_host)

            if not candidates:
                continue

            # Evaluate each candidate against temporal window and constraint checks
            for net_id, (net_ev, match_dimension, matched_val) in candidates.items():
                pair_key = tuple(sorted([host_ev.event_id, net_ev.event_id]))
                if pair_key in seen_pairs:
                    continue

                # Temporal check
                delta = compute_timestamp_delta(host_ev.timestamp, net_ev.timestamp)
                if delta is None:
                    if self.config.require_timestamps:
                        # Missing timestamps reject correlation when temporal window is mandated
                        continue
                else:
                    if delta > window:
                        # Outside configured time window
                        continue

                # User mismatch check (if both specify user and they differ, reject match)
                u_host = extract_user_identity(host_ev)
                u_net = extract_user_identity(net_ev)
                if u_host is not None and u_net is not None:
                    if u_host.lower() != u_net.lower():
                        # Explicit conflicting user identity
                        continue

                # Session mismatch check (if both specify session and they differ, reject match)
                sess_host = extract_session_identity(host_ev)
                sess_net = extract_session_identity(net_ev)
                if sess_host is not None and sess_net is not None:
                    if sess_host != sess_net:
                        # Explicit conflicting session identifier
                        continue

                # Port alignment check
                host_ports = extract_host_ports(host_ev)
                net_src_port, net_dst_port = extract_network_ports(net_ev)
                net_ports = {p for p in (net_src_port, net_dst_port) if p is not None}
                port_matched = False
                if host_ports and net_ports:
                    if host_ports.intersection(net_ports):
                        port_matched = True

                # Determine directionality of IP match
                src_ip, dst_ip = extract_network_ips(net_ev)
                matched_direction = "unspecified"
                if match_dimension in ("ip_match", "host_endpoint_ip_match"):
                    if matched_val == src_ip:
                        matched_direction = "network_source"
                    elif matched_val == dst_ip:
                        matched_direction = "network_destination"

                # Assess ambiguity
                is_private = is_private_or_shared_ip(matched_val) if match_dimension in ("ip_match", "host_endpoint_ip_match") else False
                ambiguity_notes: List[str] = []
                if match_dimension in ("ip_match", "host_endpoint_ip_match"):
                    if is_private:
                        ambiguity_notes.append(
                            "Matched address is within a private, loopback, or reserved range; "
                            "attribution may be ambiguous due to potential NAT, DHCP reassignment, or network overlapping."
                        )
                    else:
                        ambiguity_notes.append(
                            "IP match reflects observed addressing; does not guarantee unique machine identity "
                            "if proxies, NAT gateways, or dynamic allocation are present."
                        )

                if not port_matched and host_ports:
                    ambiguity_notes.append("Host event recorded port(s) that did not align with network packet ports.")

                # User alignment check
                user_matched = False
                if u_host is not None and u_net is not None and u_host.lower() == u_net.lower():
                    user_matched = True

                # Construct factual explanation
                desc_parts: List[str] = [
                    f"Host observation ({host_ev.event_type}) linked to network observation ({net_ev.event_type})",
                    f"via {match_dimension}='{matched_val}'",
                ]
                if user_matched:
                    desc_parts.append(f"user='{u_host}'")
                if port_matched:
                    desc_parts.append("(ports aligned)")
                if delta is not None:
                    desc_parts.append(f"within {delta:.1f}s (window: {window:.1f}s)")
                else:
                    desc_parts.append("(missing timestamp)")

                factual_desc = " ".join(desc_parts)

                # Construct correlation attributes
                attrs: Dict[str, Any] = {
                    "correlation_layer": "host_to_network",
                    "match_dimension": match_dimension,
                    "matched_dimension": match_dimension,
                    "matched_value": matched_val,
                    "matched_direction": matched_direction,
                    "host_event_id": host_ev.event_id,
                    "network_event_id": net_ev.event_id,
                    "host_category": host_ev.category.value if hasattr(host_ev.category, "value") else str(host_ev.category),
                    "host_event_type": host_ev.event_type,
                    "network_event_type": net_ev.event_type,
                    "is_private_or_shared_ip": is_private,
                    "port_aligned": port_matched,
                    "user_aligned": user_matched,
                    "delta_seconds": delta,
                    "window_seconds": window,
                }
                if user_matched:
                    attrs["matched_user"] = u_host
                if ambiguity_notes:
                    attrs["ambiguity_notes"] = tuple(ambiguity_notes)

                corr = create_correlation(
                    relationship_type=CorrelationType.HOST_NETWORK,
                    event_ids=[host_ev, net_ev],
                    description=factual_desc,
                    time_delta_seconds=delta,
                    attributes=attrs,
                )
                discovered.append(corr)
                seen_pairs.add(pair_key)

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

        # Sort discovered correlations into canonical deterministic order
        discovered.sort(key=correlation_sort_key)

        if self.config.max_correlations is not None:
            discovered = discovered[: self.config.max_correlations]

        return CorrelationCollection(discovered)


def correlate_host_network_events(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    config: Optional[HostNetworkCorrelationConfig] = None,
    *,
    time_window_seconds: Optional[float] = None,
    match_ip: Optional[bool] = None,
    match_user: Optional[bool] = None,
    match_session: Optional[bool] = None,
    match_port: Optional[bool] = None,
    known_host_ips: Optional[Iterable[str]] = None,
    require_timestamps: Optional[bool] = None,
    max_correlations: Optional[int] = None,
) -> CorrelationCollection:
    """
    Convenience function to correlate host and network events from a timeline.
    """
    correlator = HostNetworkCorrelator(
        config=config,
        time_window_seconds=time_window_seconds,
        match_ip=match_ip,
        match_user=match_user,
        match_session=match_session,
        match_port=match_port,
        known_host_ips=known_host_ips,
        require_timestamps=require_timestamps,
        max_correlations=max_correlations,
    )
    return correlator.correlate(timeline)
