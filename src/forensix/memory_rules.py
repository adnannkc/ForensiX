"""
Forensic Memory Detection Rules for ForensiX (V6.7 Memory Detection & Triage).

Provides strongly typed, declarative detection rule factories, builders, and
canonical memory detection rules integrating memory evidence observations
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
- Explicit boundaries: Rules are grounded in verified artifact fields from V6.2–V6.6.
  Rules requiring unmodeled evidence (e.g. VAD permissions, kernel hooks, binary hashes)
  are strictly prohibited or deferred.
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
DEFAULT_MEMORY_RULE_TIME_WINDOW_SECONDS: float = 300.0

# Canonical rule name constants
RULE_NAME_MEMORY_PROCESS_NAME_PATTERN: str = "Memory Process Name Observation"
RULE_NAME_MEMORY_NETWORK_PORT_PATTERN: str = "Memory Network Socket Port Observation"
RULE_NAME_MEMORY_PROCESS_SOCKET_CORRELATION: str = "Memory Process Correlated With Network Socket"
RULE_NAME_MEMORY_MODULE_DRIVER_PATH_PATTERN: str = "Memory Kernel Module Driver Path Review Indicator"
RULE_NAME_MEMORY_PARENT_CHILD_CORRELATION: str = "Memory Parent-Child Process Relationship Observation"

# Canonical baseline rule pattern IDs
RULE_MEM_01_PROCESS_NAME_OBSERVATION: str = "RULE-MEM-01-PROCESS-NAME"
RULE_MEM_02_LISTENING_PORT_OBSERVATION: str = "RULE-MEM-02-LISTENING-PORT"
RULE_MEM_03_PROCESS_SOCKET_CORRELATION: str = "RULE-MEM-03-PROCESS-NETWORK-CORRELATION"
RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION: str = "RULE-MEM-04-MODULE-DRIVER-PATH"
RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION: str = "RULE-MEM-05-PARENT-CHILD-PROCESS"


# ==============================================================================
# Declarative Factory Functions
# ==============================================================================

def create_memory_process_name_rule(
    process_name_pattern: str,
    *,
    operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    target_event_type: Optional[str] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching in-memory process name observations.

    Forensic Principle:
    A process name match indicates only that a process with the specified name was
    observed in memory. It does NOT assert that the process is malicious, unauthorized,
    or compromised.

    Args:
        process_name_pattern: Process executable name or pattern to match.
        operator: Comparison operator (EQUALS, CONTAINS, IN, STARTS_WITH, ENDS_WITH).
        target_event_type: Optional specific event type ('memory_process_created',
            'memory_process_observed', 'memory_process_exited'). If None, matches
            any memory process event.
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    if not isinstance(process_name_pattern, str) or not process_name_pattern.strip():
        raise ValueError("process_name_pattern must be a non-empty string")

    clean_name = process_name_pattern.strip()
    conds: List[RuleCondition] = []

    if target_event_type is not None:
        if not isinstance(target_event_type, str) or not target_event_type.strip():
            raise ValueError("target_event_type must be a non-empty string if provided")
        clean_et = target_event_type.strip()
        req_event_types: Sequence[str] = [clean_et]
    else:
        req_event_types = ()
        conds.append(
            RuleCondition(
                field="event_type",
                operator=ConditionOperator.IN,
                value=["memory_process_created", "memory_process_observed", "memory_process_exited"],
                description="Match memory process event types",
            )
        )

    conds.append(
        RuleCondition(
            field="process_name",
            operator=operator,
            value=clean_name,
            description=f"Match process name against pattern '{clean_name}'",
        )
    )

    name = rule_name or f"{RULE_NAME_MEMORY_PROCESS_NAME_PATTERN} ({clean_name})"
    desc = (
        description
        or f"Identifies observed in-memory process execution matching name pattern '{clean_name}'."
    )
    det_desc = (
        detection_description
        or f"Observed in-memory process execution matching name pattern '{clean_name}'."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "memory_detection",
        "artifact_category": "process",
        "pattern": clean_name,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.LOG],
        required_event_types=req_event_types if req_event_types else None,
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_memory_network_socket_rule(
    *,
    local_port: Optional[int] = None,
    port_operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    remote_port: Optional[int] = None,
    remote_port_operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    state: Optional[str] = "LISTEN",
    state_operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    protocol: Optional[str] = None,
    target_event_type: Optional[str] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching in-memory network socket observations.

    Forensic Principle:
    A socket observation reflects a network endpoint structure present in memory at
    acquisition time. It does NOT prove active data transfer, external connectivity,
    or malicious communication.

    At least one condition parameter (local_port, remote_port, state, protocol) must be provided.

    Args:
        local_port: Optional local port number (0-65535).
        port_operator: Comparison operator for local port.
        remote_port: Optional remote port number (0-65535).
        remote_port_operator: Comparison operator for remote port.
        state: Optional socket state (e.g. "LISTEN", "ESTABLISHED", "CLOSE_WAIT").
        state_operator: Comparison operator for state.
        protocol: Optional transport protocol ("TCP", "UDP").
        target_event_type: Optional specific event type ('memory_network_socket_observed',
            'memory_network_socket_created').
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

    if target_event_type is not None:
        if not isinstance(target_event_type, str) or not target_event_type.strip():
            raise ValueError("target_event_type must be a non-empty string if provided")
        clean_et = target_event_type.strip()
        req_event_types: Sequence[str] = [clean_et]
    else:
        req_event_types = ()
        conds.append(
            RuleCondition(
                field="event_type",
                operator=ConditionOperator.IN,
                value=["memory_network_socket_observed", "memory_network_socket_created"],
                description="Match memory network socket event types",
            )
        )

    if protocol is not None:
        if not isinstance(protocol, str) or not protocol.strip():
            raise ValueError("protocol must be a non-empty string if provided")
        clean_proto = protocol.strip().upper()
        conds.append(
            RuleCondition(
                field="protocol",
                operator=ConditionOperator.EQUALS,
                value=clean_proto,
                description=f"Match transport protocol '{clean_proto}'",
            )
        )
        summary_parts.append(f"Proto: {clean_proto}")

    if state is not None:
        if not isinstance(state, str) or not state.strip():
            raise ValueError("state must be a non-empty string if provided")
        clean_st = state.strip().upper()
        conds.append(
            RuleCondition(
                field="state",
                operator=state_operator,
                value=clean_st,
                description=f"Match socket state '{clean_st}'",
            )
        )
        summary_parts.append(f"State: {clean_st}")

    if local_port is not None:
        if not isinstance(local_port, int) or isinstance(local_port, bool) or not (0 <= local_port <= 65535):
            raise ValueError(f"local_port must be an integer between 0 and 65535, got {local_port}")
        conds.append(
            RuleCondition(
                field="local_port",
                operator=port_operator,
                value=local_port,
                description=f"Match local port {local_port}",
            )
        )
        summary_parts.append(f"Port: {local_port}")

    if remote_port is not None:
        if not isinstance(remote_port, int) or isinstance(remote_port, bool) or not (0 <= remote_port <= 65535):
            raise ValueError(f"remote_port must be an integer between 0 and 65535, got {remote_port}")
        conds.append(
            RuleCondition(
                field="remote_port",
                operator=remote_port_operator,
                value=remote_port,
                description=f"Match remote port {remote_port}",
            )
        )
        summary_parts.append(f"RemotePort: {remote_port}")

    # Ensure at least one substantive field condition is defined
    substantive_conds = [c for c in conds if c.field != "event_type"]
    if not substantive_conds:
        raise ValueError(
            "At least one condition (local_port, remote_port, state, protocol) must be specified for create_memory_network_socket_rule"
        )

    summary_str = ", ".join(summary_parts)
    name = rule_name or f"{RULE_NAME_MEMORY_NETWORK_PORT_PATTERN} ({summary_str})"
    desc = (
        description
        or f"Identifies observed in-memory network socket matching configured criteria: {summary_str}."
    )
    det_desc = (
        detection_description
        or f"Observed in-memory network socket matching configured criteria: {summary_str}."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "memory_detection",
        "artifact_category": "network_socket",
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.NETWORK],
        required_event_types=req_event_types if req_event_types else None,
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_memory_process_socket_correlation_rule(
    *,
    require_direct_confidence: bool = True,
    require_remote_address: bool = False,
    process_name: Optional[str] = None,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching process-to-network socket correlations.

    Forensic Principle:
    A process-to-socket correlation establishes that an in-memory socket explicitly
    referenced a process PID in the same evidence image. It does NOT prove that the
    process initiated malicious network activity.

    Uses canonical CorrelationType.HOST_NETWORK and enforces:
    `memory_relationship_type == "PROCESS_NETWORK_SOCKET"`

    Args:
        require_direct_confidence: If True, requires confidence == "DIRECT".
        require_remote_address: If True, requires remote_address to exist and be non-null.
        process_name: Optional specific process name to filter on.
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    conds: List[RuleCondition] = [
        RuleCondition(
            field="memory_relationship_type",
            operator=ConditionOperator.EQUALS,
            value="PROCESS_NETWORK_SOCKET",
            description="Require memory correlation subtype PROCESS_NETWORK_SOCKET",
        )
    ]

    if require_direct_confidence:
        conds.append(
            RuleCondition(
                field="confidence",
                operator=ConditionOperator.EQUALS,
                value="DIRECT",
                description="Require direct correlation confidence",
            )
        )

    if require_remote_address:
        conds.append(
            RuleCondition(
                field="remote_address",
                operator=ConditionOperator.EXISTS,
                value=True,
                description="Require remote endpoint address presence",
            )
        )

    if process_name is not None:
        if not isinstance(process_name, str) or not process_name.strip():
            raise ValueError("process_name must be a non-empty string if provided")
        clean_pname = process_name.strip()
        conds.append(
            RuleCondition(
                field="process_name",
                operator=ConditionOperator.EQUALS,
                value=clean_pname,
                description=f"Match participating process name '{clean_pname}'",
            )
        )

    name = rule_name or RULE_NAME_MEMORY_PROCESS_SOCKET_CORRELATION
    desc = (
        description
        or "Identifies observed correlation between an in-memory process and an active network socket via verified PID linkage."
    )
    det_desc = (
        detection_description
        or "Observed correlated in-memory process and network socket via verified PID linkage."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "memory_detection",
        "correlation_type": "PROCESS_NETWORK_SOCKET",
        "canonical_relationship": CorrelationType.HOST_NETWORK.value,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_relationships=[CorrelationType.HOST_NETWORK],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_memory_module_rule(
    *,
    path_pattern: Optional[str] = None,
    path_operator: Union[ConditionOperator, str] = ConditionOperator.CONTAINS,
    module_name: Optional[str] = None,
    module_operator: Union[ConditionOperator, str] = ConditionOperator.EQUALS,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching in-memory kernel module observations.

    Forensic Principle:
    A driver path or module name match serves as a forensic review indicator.
    Kernel modules and driver paths vary by operating system and configuration; a match
    does NOT prove kernel rootkit installation, compromise, or unauthorized loading.

    At least one condition parameter (path_pattern, module_name) must be provided.

    Args:
        path_pattern: Driver file path substring or prefix to match.
        path_operator: Comparison operator for driver_path.
        module_name: Module identifier or name pattern to match.
        module_operator: Comparison operator for module_name.
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

    if path_pattern is not None:
        if not isinstance(path_pattern, str) or not path_pattern.strip():
            raise ValueError("path_pattern must be a non-empty string if provided")
        clean_path = path_pattern.strip()
        # Ensure driver_path is present and non-null before evaluating path pattern
        conds.append(
            RuleCondition(
                field="driver_path",
                operator=ConditionOperator.EXISTS,
                value=True,
                description="Require non-null driver_path",
            )
        )
        conds.append(
            RuleCondition(
                field="driver_path",
                operator=path_operator,
                value=clean_path,
                description=f"Match driver_path against '{clean_path}'",
            )
        )
        summary_parts.append(f"Path: {clean_path}")

    if module_name is not None:
        if not isinstance(module_name, str) or not module_name.strip():
            raise ValueError("module_name must be a non-empty string if provided")
        clean_mname = module_name.strip()
        conds.append(
            RuleCondition(
                field="module_name",
                operator=module_operator,
                value=clean_mname,
                description=f"Match module_name against '{clean_mname}'",
            )
        )
        summary_parts.append(f"Module: {clean_mname}")

    if not conds:
        raise ValueError(
            "At least one condition (path_pattern, module_name) must be specified for create_memory_module_rule"
        )

    summary_str = ", ".join(summary_parts)
    name = rule_name or f"{RULE_NAME_MEMORY_MODULE_DRIVER_PATH_PATTERN} ({summary_str})"
    desc = (
        description
        or f"Identifies observed in-memory kernel module or driver matching review criteria: {summary_str}."
    )
    det_desc = (
        detection_description
        or f"Observed in-memory kernel module or driver matching review criteria: {summary_str}."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "memory_detection",
        "artifact_category": "kernel_module",
        "review_indicator": True,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_categories=[TimelineCategory.LOG],
        required_event_types=["memory_module_observed"],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


def create_memory_parent_child_rule(
    *,
    parent_process_name: Optional[str] = None,
    child_process_name: Optional[str] = None,
    require_direct_confidence: bool = True,
    rule_name: Optional[str] = None,
    description: Optional[str] = None,
    detection_description: Optional[str] = None,
    time_window_seconds: Optional[float] = None,
    rule_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> DetectionRule:
    """
    Create a declarative DetectionRule matching in-memory parent-child process relationships.

    Forensic Principle:
    A parent-child correlation identifies observed execution lineage based on PPID linkage
    within the same memory evidence image. It describes process lineage facts, NOT suspiciousness
    by default.

    Uses canonical CorrelationType.SAME_SOURCE and enforces:
    `memory_relationship_type == "PARENT_CHILD_PROCESS"`

    Args:
        parent_process_name: Optional expected parent process name.
        child_process_name: Optional expected child process name.
        require_direct_confidence: If True, requires confidence == "DIRECT".
        rule_name: Optional custom rule name.
        description: Optional custom rule description.
        detection_description: Optional factual explanation on match.
        time_window_seconds: Optional time window constraint.
        rule_id: Optional explicit UUIDv5 rule ID.
        attributes: Optional custom attributes dict.

    Returns:
        Immutable, deterministic DetectionRule.
    """
    conds: List[RuleCondition] = [
        RuleCondition(
            field="memory_relationship_type",
            operator=ConditionOperator.EQUALS,
            value="PARENT_CHILD_PROCESS",
            description="Require memory correlation subtype PARENT_CHILD_PROCESS",
        )
    ]

    if require_direct_confidence:
        conds.append(
            RuleCondition(
                field="confidence",
                operator=ConditionOperator.EQUALS,
                value="DIRECT",
                description="Require direct correlation confidence",
            )
        )

    summary_parts: List[str] = []
    if parent_process_name is not None:
        if not isinstance(parent_process_name, str) or not parent_process_name.strip():
            raise ValueError("parent_process_name must be a non-empty string if provided")
        clean_parent = parent_process_name.strip()
        conds.append(
            RuleCondition(
                field="supporting_fields.parent_name",
                operator=ConditionOperator.EQUALS,
                value=clean_parent,
                description=f"Match parent process name '{clean_parent}'",
            )
        )
        summary_parts.append(f"Parent: {clean_parent}")

    if child_process_name is not None:
        if not isinstance(child_process_name, str) or not child_process_name.strip():
            raise ValueError("child_process_name must be a non-empty string if provided")
        clean_child = child_process_name.strip()
        conds.append(
            RuleCondition(
                field="supporting_fields.child_name",
                operator=ConditionOperator.EQUALS,
                value=clean_child,
                description=f"Match child process name '{clean_child}'",
            )
        )
        summary_parts.append(f"Child: {clean_child}")

    summary_str = f" ({', '.join(summary_parts)})" if summary_parts else ""
    name = rule_name or f"{RULE_NAME_MEMORY_PARENT_CHILD_CORRELATION}{summary_str}"
    desc = (
        description
        or f"Identifies observed in-memory parent-child execution lineage{summary_str}."
    )
    det_desc = (
        detection_description
        or f"Observed in-memory parent-child process relationship{summary_str}."
    )

    attrs: Dict[str, Any] = {
        "rule_type": "memory_detection",
        "correlation_type": "PARENT_CHILD_PROCESS",
        "canonical_relationship": CorrelationType.SAME_SOURCE.value,
    }
    if attributes:
        attrs.update(attributes)

    return create_rule(
        name=name,
        description=desc,
        detection_description=det_desc,
        required_relationships=[CorrelationType.SAME_SOURCE],
        conditions=conds,
        time_window_seconds=time_window_seconds,
        rule_id=rule_id,
        attributes=attrs,
    )


# ==============================================================================
# Fluent Builder
# ==============================================================================

class MemoryRuleBuilder:
    """
    Fluent builder for constructing declarative ForensiX memory DetectionRules.

    Ensures type safety, non-speculative language validation, and immutability.
    """

    def __init__(self, name: str, description: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must be a non-empty string")
        self._name: str = name.strip()
        self._description: str = description.strip()
        self._detection_description: Optional[str] = None
        self._required_categories: List[TimelineCategory] = []
        self._required_event_types: List[str] = []
        self._required_relationships: List[CorrelationType] = []
        self._conditions: List[RuleCondition] = []
        self._time_window_seconds: Optional[float] = None
        self._rule_id: Optional[str] = None
        self._attributes: Dict[str, Any] = {"rule_type": "memory_detection"}

    def detection_description(self, text: str) -> "MemoryRuleBuilder":
        """Set the factual explanation emitted upon rule match."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("detection_description must be a non-empty string")
        self._detection_description = text.strip()
        return self

    def with_category(self, category: Union[TimelineCategory, str]) -> "MemoryRuleBuilder":
        """Add a required timeline category constraint."""
        cat = category if isinstance(category, TimelineCategory) else TimelineCategory(str(category).strip().lower())
        if cat not in self._required_categories:
            self._required_categories.append(cat)
        return self

    def with_event_type(self, event_type: str) -> "MemoryRuleBuilder":
        """Add a required timeline event type constraint."""
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        et = event_type.strip()
        if et not in self._required_event_types:
            self._required_event_types.append(et)
        return self

    def with_relationship(self, relationship: Union[CorrelationType, str]) -> "MemoryRuleBuilder":
        """Add a required correlation relationship constraint."""
        rel = relationship if isinstance(relationship, CorrelationType) else CorrelationType(str(relationship).strip().upper())
        if rel not in self._required_relationships:
            self._required_relationships.append(rel)
        return self

    def where(
        self,
        field: str,
        operator: Union[ConditionOperator, str],
        value: Any = None,
        description: str = "",
    ) -> "MemoryRuleBuilder":
        """Add a declarative field predicate condition."""
        cond = RuleCondition(field=field, operator=operator, value=value, description=description)
        self._conditions.append(cond)
        return self

    def set_time_window(self, seconds: float) -> "MemoryRuleBuilder":
        """Set the maximum temporal delta window in seconds."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise TypeError(f"seconds must be float or int, got {type(seconds).__name__}")
        if seconds < 0:
            raise ValueError("seconds must be non-negative")
        self._time_window_seconds = float(seconds)
        return self

    def set_attribute(self, key: str, value: Any) -> "MemoryRuleBuilder":
        """Set a metadata attribute."""
        if not isinstance(key, str) or not key.strip():
            raise ValueError("attribute key must be a non-empty string")
        self._attributes[key.strip()] = value
        return self

    def set_rule_id(self, rule_id: str) -> "MemoryRuleBuilder":
        """Set an explicit rule identifier."""
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        self._rule_id = rule_id.strip()
        return self

    def build(self) -> DetectionRule:
        """Construct the immutable DetectionRule."""
        det_desc = self._detection_description or self._description
        return create_rule(
            name=self._name,
            description=self._description,
            detection_description=det_desc,
            required_categories=self._required_categories if self._required_categories else None,
            required_event_types=self._required_event_types if self._required_event_types else None,
            required_relationships=self._required_relationships if self._required_relationships else None,
            conditions=self._conditions if self._conditions else None,
            time_window_seconds=self._time_window_seconds,
            rule_id=self._rule_id,
            attributes=self._attributes,
        )


# ==============================================================================
# Canonical Baseline Memory Rules
# ==============================================================================

def create_canonical_memory_rules() -> RuleCollection:
    """
    Construct the canonical ForensiX V6.7 baseline memory detection rules.

    Provides 5 foundational, deterministic, forensic-neutral memory detection rules:
    1. Process Name Observation: Matches observed process execution of standard diagnostic tool ('nc').
    2. Listening Socket Port Observation: Matches observed listening socket on common service port (TCP 4444).
    3. Process-Network Socket Correlation: Matches direct PID correlation between a process and socket.
    4. Driver Path Review Indicator: Matches kernel driver paths loaded from temporary directories ('/tmp').
    5. Parent-Child Process Correlation: Matches observed parent-child process lineage with direct confidence.

    Note on Deferred Rules:
    - Short-lived process event-pair rule is deferred because cross-event variable binding
      (requiring child.pid == parent.pid across separate event instances) is not supported
      by the current RuleCondition model without risking cross-PID false matches.
    - Code injection (VAD permissions) and kernel hook rules are deferred because V6 memory
      models do not capture VAD structures or kernel symbol pointer tables.

    Returns:
        RuleCollection containing the 5 canonical baseline memory detection rules.
    """
    rule1 = create_memory_process_name_rule(
        process_name_pattern="nc",
        operator=ConditionOperator.EQUALS,
        rule_name="Baseline Memory Process Name Observation (nc)",
        description="Identifies observed in-memory execution of process named 'nc'.",
        detection_description="Observed in-memory process execution named 'nc'.",
        attributes={"pattern_id": RULE_MEM_01_PROCESS_NAME_OBSERVATION, "baseline": True},
    )

    rule2 = create_memory_network_socket_rule(
        local_port=4444,
        state="LISTEN",
        protocol="TCP",
        rule_name="Baseline Memory Listening Port Observation (TCP/4444)",
        description="Identifies observed in-memory TCP socket in LISTEN state on port 4444.",
        detection_description="Observed in-memory TCP socket listening on port 4444.",
        attributes={"pattern_id": RULE_MEM_02_LISTENING_PORT_OBSERVATION, "baseline": True},
    )

    rule3 = create_memory_process_socket_correlation_rule(
        require_direct_confidence=True,
        rule_name="Baseline Memory Process Network Socket Correlation",
        description="Identifies observed direct correlation between an in-memory process and an active network socket.",
        detection_description="Observed direct correlation between an in-memory process and network socket via verified PID linkage.",
        attributes={"pattern_id": RULE_MEM_03_PROCESS_SOCKET_CORRELATION, "baseline": True},
    )

    rule4 = create_memory_module_rule(
        path_pattern="/tmp",
        path_operator=ConditionOperator.CONTAINS,
        rule_name="Baseline Memory Driver Path Review Indicator (/tmp)",
        description="Identifies observed in-memory kernel module or driver loaded from a path containing '/tmp'.",
        detection_description="Observed in-memory kernel module or driver path containing '/tmp' review indicator.",
        attributes={"pattern_id": RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION, "baseline": True},
    )

    rule5 = create_memory_parent_child_rule(
        require_direct_confidence=True,
        rule_name="Baseline Memory Parent-Child Process Relationship",
        description="Identifies observed in-memory parent-child process relationship with direct confidence.",
        detection_description="Observed in-memory parent-child process execution lineage with direct confidence.",
        attributes={"pattern_id": RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION, "baseline": True},
    )

    return RuleCollection([rule1, rule2, rule3, rule4, rule5])
