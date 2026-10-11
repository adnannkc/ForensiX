"""
Forensic Network Detection Rules for ForensiX (V5.7 Network Detection Rules).

Provides strongly typed, declarative detection rule factories, builders, and
canonical network detection rules integrating network evidence observations
into the existing V4 declarative detection architecture.

Core Principles:
- Purely declarative specification: Rules describe WHAT conditions must match,
  never HOW detection is executed.
- Zero executable code: Prohibits callables, dynamic expressions, eval/exec,
  shell commands, and arbitrary scripts.
- Factual and neutral: Rejects unsupported speculative claims of compromise,
  maliciousness, or attacker intent. A rule match represents an observed factual
  condition, not proof of malicious activity.
- Deeply immutable: Rules and nested conditions cannot be mutated after creation.
- Deterministic identity: Stable RFC 4122 UUIDv5 rule IDs based on rule facts.
- Full compatibility: Reuses V4 DetectionRule, RuleCondition, and DetectionEngine.
"""

from typing import Any, Dict, List, Optional, Sequence, Union

from forensix.correlation_models import CorrelationType
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    create_rule,
)
from forensix.timeline_models import TimelineCategory

# Standard default time window: 300.0 seconds (5 minutes)
DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS: float = 300.0

# Canonical rule name constants
RULE_NAME_DNS_QUERY_PATTERN: str = "DNS Query Domain Observation"
RULE_NAME_HTTP_REQUEST_PATTERN: str = "HTTP Request Observation"
RULE_NAME_TLS_SNI_PATTERN: str = "TLS Server Name Indication Observation"
RULE_NAME_PROTOCOL_PORT_PATTERN: str = "Network Protocol and Port Observation"
RULE_NAME_HOST_NETWORK_CORRELATION: str = "Host Event Correlated With Network Observation"


# ==============================================================================
# Declarative Factory Functions
# ==============================================================================

def create_dns_query_rule(
    domain_pattern: str,
    *,
    operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    query_type: Optional[str] = None,
    answer_data: Optional[str] = None,
    answer_operator: Union[ConditionOperator, str] = ConditionOperator.CONTAINS,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching DNS query or response metadata.

    Args:
        domain_pattern: Domain name or pattern to match against query_name.
        operator: Comparison operator (e.g. EQUALS, CONTAINS, ENDS_WITH, STARTS_WITH).
        query_type: Optional DNS resource record query type filter (e.g. "A", "TXT", "AAAA").
        answer_data: Optional answer payload string or IP address to match in observed answers.
        answer_operator: Comparison operator for answer data (default CONTAINS).
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional custom factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    if not isinstance(domain_pattern, str) or not domain_pattern.strip():
        raise ValueError("domain_pattern must be a non-empty string")

    clean_domain = domain_pattern.strip()
    conds: List[RuleCondition] = [
        RuleCondition(field="query_name", operator=operator, value=clean_domain)
    ]

    if query_type is not None:
        if not isinstance(query_type, str) or not query_type.strip():
            raise ValueError("query_type must be a non-empty string if provided")
        conds.append(
            RuleCondition(
                field="query_type",
                operator=ConditionOperator.EQUALS,
                value=query_type.strip().upper(),
            )
        )

    if answer_data is not None:
        if not isinstance(answer_data, str) or not answer_data.strip():
            raise ValueError("answer_data must be a non-empty string if provided")
        conds.append(
            RuleCondition(
                field="answers_data",
                operator=answer_operator,
                value=answer_data.strip(),
            )
        )

    name = rule_name or f"{RULE_NAME_DNS_QUERY_PATTERN} ({clean_domain})"
    desc = (
        description
        or f"Identifies observed DNS query activity matching domain pattern '{clean_domain}'."
    )
    det_desc = (
        detection_description
        or f"Observed DNS query activity matching domain pattern '{clean_domain}'."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "network_detection",
        "protocol": "DNS",
        "domain_pattern": clean_domain,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=["network_dns_metadata"],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_http_request_rule(
    *,
    host: Optional[str] = None,
    host_operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    target: Optional[str] = None,
    target_operator: Union[ConditionOperator, str] = ConditionOperator.STARTS_WITH,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching cleartext HTTP request metadata.

    At least one condition parameter (host, target, method, status_code) must be specified.

    Args:
        host: Host header value or pattern.
        host_operator: Comparison operator for host.
        target: Request URI path or pattern.
        target_operator: Comparison operator for target path.
        method: HTTP method (e.g. "GET", "POST").
        status_code: Response status code (e.g. 200, 404).
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    conds: List[RuleCondition] = []
    summary_parts: List[str] = []

    if host is not None:
        if not isinstance(host, str) or not host.strip():
            raise ValueError("host must be a non-empty string if provided")
        clean_host = host.strip()
        conds.append(RuleCondition(field="host", operator=host_operator, value=clean_host))
        summary_parts.append(f"Host: {clean_host}")

    if target is not None:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string if provided")
        clean_target = target.strip()
        conds.append(
            RuleCondition(field="target", operator=target_operator, value=clean_target)
        )
        summary_parts.append(f"Path: {clean_target}")

    if method is not None:
        if not isinstance(method, str) or not method.strip():
            raise ValueError("method must be a non-empty string if provided")
        clean_method = method.strip().upper()
        conds.append(
            RuleCondition(field="method", operator=ConditionOperator.EQUALS, value=clean_method)
        )
        summary_parts.append(f"Method: {clean_method}")

    if status_code is not None:
        if not isinstance(status_code, int):
            raise TypeError(f"status_code must be an integer, got {type(status_code).__name__}")
        conds.append(
            RuleCondition(
                field="status_code",
                operator=ConditionOperator.EQUALS,
                value=status_code,
            )
        )
        summary_parts.append(f"Status: {status_code}")

    if not conds:
        raise ValueError(
            "At least one condition (host, target, method, status_code) must be specified for create_http_request_rule"
        )

    summary_str = ", ".join(summary_parts)
    name = rule_name or f"{RULE_NAME_HTTP_REQUEST_PATTERN} ({summary_str})"
    desc = (
        description
        or f"Identifies observed HTTP communication matching configured criteria: {summary_str}."
    )
    det_desc = (
        detection_description
        or f"Observed HTTP communication matching configured criteria: {summary_str}."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "network_detection",
        "protocol": "HTTP",
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=["network_http_metadata"],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_tls_sni_rule(
    server_name: str,
    *,
    operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    alpn_protocol: Optional[str] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching TLS ClientHello SNI metadata.

    Args:
        server_name: Server Name Indication hostname pattern to match.
        operator: Comparison operator for server_name.
        alpn_protocol: Optional Application Layer Protocol Negotiation string (e.g. "h2").
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    if not isinstance(server_name, str) or not server_name.strip():
        raise ValueError("server_name must be a non-empty string")

    clean_sni = server_name.strip()
    conds: List[RuleCondition] = [
        RuleCondition(field="server_name", operator=operator, value=clean_sni)
    ]

    if alpn_protocol is not None:
        if not isinstance(alpn_protocol, str) or not alpn_protocol.strip():
            raise ValueError("alpn_protocol must be a non-empty string if provided")
        conds.append(
            RuleCondition(
                field="alpn_protocols",
                operator=ConditionOperator.CONTAINS,
                value=alpn_protocol.strip(),
            )
        )

    name = rule_name or f"{RULE_NAME_TLS_SNI_PATTERN} ({clean_sni})"
    desc = (
        description
        or f"Identifies observed TLS handshake activity with Server Name Indication matching '{clean_sni}'."
    )
    det_desc = (
        detection_description
        or f"Observed TLS handshake activity with Server Name Indication matching '{clean_sni}'."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "network_detection",
        "protocol": "TLS",
        "sni_pattern": clean_sni,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=["network_tls_metadata"],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_network_protocol_port_rule(
    protocol: str,
    port: int,
    *,
    is_destination: bool = True,
    ip_address: Optional[str] = None,
    event_type: Optional[str] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching network protocol and port observations.

    Args:
        protocol: Transport protocol string (e.g. "TCP", "UDP").
        port: Integer port number (0-65535).
        is_destination: If True, matches destination port (and destination IP). If False, source port.
        ip_address: Optional IP address filter.
        event_type: Optional specific network event type (e.g. "tcp_packet", "udp_packet").
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("protocol must be a non-empty string")
    clean_proto = protocol.strip().upper()

    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError(f"port must be an integer, got {type(port).__name__}")
    if not (0 <= port <= 65535):
        raise ValueError(f"port must be between 0 and 65535, got {port}")

    port_field = "dst_port" if is_destination else "src_port"
    conds: List[RuleCondition] = [
        RuleCondition(
            field="transport_protocol",
            operator=ConditionOperator.EQUALS,
            value=clean_proto,
        ),
        RuleCondition(
            field=port_field,
            operator=ConditionOperator.EQUALS,
            value=port,
        ),
    ]

    port_label = f"dst_port={port}" if is_destination else f"src_port={port}"

    if ip_address is not None:
        if not isinstance(ip_address, str) or not ip_address.strip():
            raise ValueError("ip_address must be a non-empty string if provided")
        clean_ip = ip_address.strip()
        ip_field = "dst_ip" if is_destination else "src_ip"
        conds.append(
            RuleCondition(
                field=ip_field,
                operator=ConditionOperator.EQUALS,
                value=clean_ip,
            )
        )
        port_label += f" and {'dst_ip' if is_destination else 'src_ip'}={clean_ip}"

    name = rule_name or f"{RULE_NAME_PROTOCOL_PORT_PATTERN} ({clean_proto}/{port_label})"
    desc = (
        description
        or f"Identifies observed network traffic matching {clean_proto} on {port_label}."
    )
    det_desc = (
        detection_description
        or f"Observed network traffic matching {clean_proto} on {port_label}."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "network_detection",
        "transport_protocol": clean_proto,
        "port": port,
        "is_destination": is_destination,
    }
    if attributes:
        attrs.update(attributes)

    required_types = [event_type] if event_type else None

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=required_types,
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_host_network_correlation_rule(
    *,
    host_event_type: Optional[str] = None,
    network_event_type: Optional[str] = None,
    conditions: Optional[Sequence[Union[RuleCondition, Dict[str, Any]]]] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: float = DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching V5.6 host-to-network correlations.

    Args:
        host_event_type: Optional required host event type (e.g. "ssh_login_success").
        network_event_type: Optional required network event type (e.g. "tcp_packet").
        conditions: Optional additional declarative conditions to evaluate on the correlation.
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Maximum allowable time delta in seconds between host and network observations.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    req_types: List[str] = []
    if host_event_type is not None:
        if not isinstance(host_event_type, str) or not host_event_type.strip():
            raise ValueError("host_event_type must be a non-empty string if provided")
        req_types.append(host_event_type.strip())
    if network_event_type is not None:
        if not isinstance(network_event_type, str) or not network_event_type.strip():
            raise ValueError("network_event_type must be a non-empty string if provided")
        req_types.append(network_event_type.strip())

    name = rule_name or RULE_NAME_HOST_NETWORK_CORRELATION
    desc = (
        description
        or f"Identifies correlated host activity associated with network traffic observations within {int(time_window_seconds)}s."
    )
    det_desc = (
        detection_description
        or f"Observed host activity correlated with network traffic observation within {int(time_window_seconds)} seconds."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "network_correlation_detection",
        "correlation_type": CorrelationType.HOST_NETWORK.value,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=req_types if req_types else None,
        required_relationships=[CorrelationType.HOST_NETWORK],
        conditions=conditions,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


# ==============================================================================
# Declarative Network Rule Builder
# ==============================================================================

class NetworkRuleBuilder:
    """
    Fluent declarative builder for constructing strongly-typed, explainable
    forensic network detection rules.
    """

    def __init__(self, name: str, description: Optional[str] = None) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")
        self._name: str = name.strip()
        self._description: str = (
            description.strip()
            if (description and isinstance(description, str))
            else f"Network detection rule for {self._name}."
        )
        self._detection_description: Optional[str] = None
        self._required_categories: List[TimelineCategory] = [TimelineCategory.NETWORK]
        self._required_event_types: List[str] = []
        self._required_relationships: List[CorrelationType] = []
        self._conditions: List[RuleCondition] = []
        self._time_window_seconds: Optional[float] = None
        self._rule_id: Optional[str] = None
        self._attributes: Dict[str, Any] = {"rule_type": "network_detection"}

    def set_description(self, description: str) -> "NetworkRuleBuilder":
        """Set the rule description."""
        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must be a non-empty string")
        self._description = description.strip()
        return self

    def set_detection_description(self, desc: str) -> "NetworkRuleBuilder":
        """Set the factual explanation emitted upon detection match."""
        if not isinstance(desc, str) or not desc.strip():
            raise ValueError("detection_description must be a non-empty string")
        self._detection_description = desc.strip()
        return self

    def match_category(self, category: Union[TimelineCategory, str]) -> "NetworkRuleBuilder":
        """Add a required timeline category."""
        if isinstance(category, TimelineCategory):
            cat = category
        elif isinstance(category, str):
            cat = TimelineCategory(category.strip().upper())
        else:
            raise TypeError(f"category must be TimelineCategory or str, got {type(category).__name__}")
        if cat not in self._required_categories:
            self._required_categories.append(cat)
        return self

    def match_event_type(self, event_type: str) -> "NetworkRuleBuilder":
        """Add a required timeline event type."""
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        clean_et = event_type.strip()
        if clean_et not in self._required_event_types:
            self._required_event_types.append(clean_et)
        return self

    def match_relationship(self, relationship: Union[CorrelationType, str]) -> "NetworkRuleBuilder":
        """Add a required correlation relationship."""
        if isinstance(relationship, CorrelationType):
            rel = relationship
        elif isinstance(relationship, str):
            rel = CorrelationType(relationship.strip().upper())
        else:
            raise TypeError(f"relationship must be CorrelationType or str, got {type(relationship).__name__}")
        if rel not in self._required_relationships:
            self._required_relationships.append(rel)
        return self

    def where(
        self,
        field: str,
        operator: Union[ConditionOperator, str],
        value: Any,
    ) -> "NetworkRuleBuilder":
        """Add a declarative field condition predicate."""
        cond = RuleCondition(field=field, operator=operator, value=value)
        self._conditions.append(cond)
        return self

    def set_time_window(self, seconds: float) -> "NetworkRuleBuilder":
        """Set the temporal correlation / sequence window in seconds."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise TypeError(f"seconds must be a float or int, got {type(seconds).__name__}")
        if seconds < 0:
            raise ValueError("seconds must be non-negative")
        self._time_window_seconds = float(seconds)
        return self

    def set_attribute(self, key: str, value: Any) -> "NetworkRuleBuilder":
        """Set a metadata attribute key/value pair."""
        if not isinstance(key, str) or not key.strip():
            raise ValueError("attribute key must be a non-empty string")
        self._attributes[key.strip()] = value
        return self

    def set_rule_id(self, rule_id: str) -> "NetworkRuleBuilder":
        """Set an explicit UUIDv5 rule identifier."""
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        self._rule_id = rule_id.strip()
        return self

    def build(self) -> DetectionRule:
        """
        Validate and construct the immutable DetectionRule.
        """
        det_desc = self._detection_description or self._description
        return create_rule(
            name=self._name,
            description=self._description,
            detection_description=det_desc,
            required_categories=self._required_categories,
            required_event_types=self._required_event_types if self._required_event_types else None,
            required_relationships=self._required_relationships if self._required_relationships else None,
            conditions=self._conditions if self._conditions else None,
            time_window_seconds=self._time_window_seconds,
            rule_id=self._rule_id,
            attributes=self._attributes,
        )


# ==============================================================================
# Canonical Baseline Network Rule Collection
# ==============================================================================

# Deterministic IDs for canonical baseline network detection rules
RULE_NET_01_DNS_OBSERVATION: str = "RULE-NET-01-DNS-QUERY"
RULE_NET_02_HTTP_OBSERVATION: str = "RULE-NET-02-HTTP-REQUEST"
RULE_NET_03_TLS_SNI_OBSERVATION: str = "RULE-NET-03-TLS-SNI"
RULE_NET_04_SSH_PORT_OBSERVATION: str = "RULE-NET-04-SSH-PORT"
RULE_NET_05_HOST_NETWORK_CORRELATION: str = "RULE-NET-05-HOST-NETWORK-CORRELATION"


def create_canonical_network_rules() -> RuleCollection:
    """
    Construct the canonical ForensiX V5.7 baseline network detection rules.

    Provides 5 foundational, deterministic, and forensic-neutral network detection rules:
    1. DNS Query Observation: Matches DNS query activity matching configured test domain.
    2. HTTP Request Observation: Matches HTTP request activity on configured target path.
    3. TLS SNI Observation: Matches TLS ClientHello activity with configured server name.
    4. Network Port Observation: Matches network communication targeting standard port (TCP/22).
    5. Host-Network Correlation: Matches correlated host activity with network observation.

    Returns:
        RuleCollection containing the 5 canonical baseline network detection rules.
    """
    rule1 = create_dns_query_rule(
        domain_pattern="example.org",
        operator=ConditionOperator.ENDS_WITH,
        rule_name="Baseline DNS Query Domain Observation",
        description="Identifies observed DNS query activity ending in 'example.org'.",
        detection_description="Observed DNS query for a domain ending in 'example.org'.",
        attributes={"pattern_id": RULE_NET_01_DNS_OBSERVATION, "baseline": True},
    )

    rule2 = create_http_request_rule(
        target="/api/v1/status",
        target_operator=ConditionOperator.EQUALS,
        rule_name="Baseline HTTP Request Observation",
        description="Identifies observed HTTP communication requesting endpoint '/api/v1/status'.",
        detection_description="Observed HTTP request to '/api/v1/status'.",
        attributes={"pattern_id": RULE_NET_02_HTTP_OBSERVATION, "baseline": True},
    )

    rule3 = create_tls_sni_rule(
        server_name="secure.portal.org",
        operator=ConditionOperator.EQUALS,
        rule_name="Baseline TLS Server Name Indication Observation",
        description="Identifies observed TLS handshake with Server Name Indication 'secure.portal.org'.",
        detection_description="Observed TLS ClientHello with SNI 'secure.portal.org'.",
        attributes={"pattern_id": RULE_NET_03_TLS_SNI_OBSERVATION, "baseline": True},
    )

    rule4 = create_network_protocol_port_rule(
        protocol="TCP",
        port=22,
        is_destination=True,
        rule_name="Baseline SSH Network Port Observation",
        description="Identifies observed network traffic targeting TCP destination port 22.",
        detection_description="Observed network communication directed to TCP destination port 22.",
        attributes={"pattern_id": RULE_NET_04_SSH_PORT_OBSERVATION, "baseline": True},
    )

    rule5 = create_host_network_correlation_rule(
        time_window_seconds=DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS,
        rule_name="Baseline Host and Network Correlation Observation",
        description="Identifies correlated host activity temporally associated with network traffic observations.",
        detection_description="Observed host activity temporally associated with network traffic observation within 300 seconds.",
        attributes={"pattern_id": RULE_NET_05_HOST_NETWORK_CORRELATION, "baseline": True},
    )

    return RuleCollection([rule1, rule2, rule3, rule4, rule5])
