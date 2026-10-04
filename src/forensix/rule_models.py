"""
Forensic Detection Rule Models for ForensiX (V4.3 Rule Model).

Provides strongly typed, deeply immutable dataclasses representing declarative
detection rules for subsequent evaluation by the V4.4 Detection Engine.

Core Principles:
- Purely declarative specification: Rules describe WHAT conditions must match,
  never HOW detection is executed.
- Zero executable code: Prohibits callables, dynamic expressions, eval/exec,
  shell commands, and arbitrary scripts.
- Factual and explainable: Prohibits unsupported speculative claims of compromise.
- Deeply immutable: Rules and nested conditions cannot be mutated after creation.
- Deterministic identity: Stable RFC 4122 UUIDv5 rule IDs based on rule facts.
- Full JSON serialization compatibility: Roundtrip fidelity with stable key order.
"""

from dataclasses import dataclass
from enum import Enum
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
import uuid

from forensix.correlation_models import (
    DISALLOWED_SPECULATIVE_TERMS,
    CorrelationType,
)
from forensix.timeline_models import (
    TimelineCategory,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)


# Canonical RFC 4122 UUID namespace for ForensiX V4 detection rules
FORENSIX_V4_RULE_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v4/rule"
)


class ConditionOperator(str, Enum):
    """
    Declarative comparison operators for rule conditions.

    Supported operators:
    - EQUALS (==): Exact scalar equality match.
    - NOT_EQUALS (!=): Scalar inequality match.
    - CONTAINS: Substring or collection membership check.
    - IN: Target value is an element of the specified candidate collection.
    - GREATER_THAN (>): Numeric strictly greater than comparison.
    - GREATER_EQUAL (>=): Numeric greater than or equal comparison.
    - LESS_THAN (<): Numeric strictly less than comparison.
    - LESS_EQUAL (<=): Numeric less than or equal comparison.
    - EXISTS: Attribute presence and non-null check.
    """

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    IN = "IN"
    GREATER_THAN = "GREATER_THAN"
    GREATER_EQUAL = "GREATER_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_EQUAL = "LESS_EQUAL"
    EXISTS = "EXISTS"


# Mapping of common symbolic and text aliases to canonical ConditionOperator
_OPERATOR_ALIASES: Dict[str, ConditionOperator] = {
    "==": ConditionOperator.EQUALS,
    "=": ConditionOperator.EQUALS,
    "eq": ConditionOperator.EQUALS,
    "equals": ConditionOperator.EQUALS,
    "!=": ConditionOperator.NOT_EQUALS,
    "ne": ConditionOperator.NOT_EQUALS,
    "not_equals": ConditionOperator.NOT_EQUALS,
    "contains": ConditionOperator.CONTAINS,
    "in": ConditionOperator.IN,
    ">": ConditionOperator.GREATER_THAN,
    "gt": ConditionOperator.GREATER_THAN,
    "greater_than": ConditionOperator.GREATER_THAN,
    ">=": ConditionOperator.GREATER_EQUAL,
    "gte": ConditionOperator.GREATER_EQUAL,
    "greater_equal": ConditionOperator.GREATER_EQUAL,
    "<": ConditionOperator.LESS_THAN,
    "lt": ConditionOperator.LESS_THAN,
    "less_than": ConditionOperator.LESS_THAN,
    "<=": ConditionOperator.LESS_EQUAL,
    "lte": ConditionOperator.LESS_EQUAL,
    "less_equal": ConditionOperator.LESS_EQUAL,
    "exists": ConditionOperator.EXISTS,
    "is_not_null": ConditionOperator.EXISTS,
}


def _validate_operator(val: Union[ConditionOperator, str]) -> ConditionOperator:
    """Validate and normalize a condition operator."""
    if isinstance(val, ConditionOperator):
        return val
    if isinstance(val, str):
        clean = val.strip().lower()
        if clean in _OPERATOR_ALIASES:
            return _OPERATOR_ALIASES[clean]
        clean_upper = val.strip().upper()
        try:
            return ConditionOperator(clean_upper)
        except ValueError:
            valid_ops = sorted([op.value for op in ConditionOperator])
            raise ValueError(
                f"Invalid condition operator: '{val}'. Must be one of: {valid_ops}"
            )
    raise TypeError(
        f"operator must be ConditionOperator or str, got {type(val).__name__}"
    )


@dataclass(frozen=True)
class RuleCondition:
    """
    Immutable, declarative predicate specification for a detection rule.

    Specifies a factual condition over an event attribute, field, or relationship.
    Strictly declarative; contains no executable logic or callbacks.

    Attributes:
        field: Name of the attribute, property, or field to inspect.
        operator: Validated ConditionOperator.
        value: Expected value or collection of values (frozen and JSON-safe).
        description: Human-readable factual explanation of the condition.
    """

    field: str
    operator: ConditionOperator
    value: Any = None
    description: str = ""

    def __init__(
        self,
        field: str,
        operator: Union[ConditionOperator, str],
        value: Any = None,
        description: str = "",
    ) -> None:
        if field is None:
            raise TypeError("RuleCondition missing required argument: 'field'")
        if not isinstance(field, str):
            raise TypeError(f"field must be a string, got {type(field).__name__}")
        clean_field = field.strip()
        if not clean_field:
            raise ValueError("field must be a non-empty string")

        validated_op = _validate_operator(operator)

        # Prohibit executable objects or dangerous expressions in condition values
        if callable(value):
            raise TypeError(
                "Arbitrary executable code or callable objects are strictly disallowed in RuleCondition"
            )
        if isinstance(value, str):
            disallowed_patterns = ("eval(", "exec(", "__import__", "import ")
            for pat in disallowed_patterns:
                if pat in value:
                    raise ValueError(
                        f"Executable code patterns like '{pat}' are disallowed in RuleCondition"
                    )

        # Deeply freeze collection values for immutability
        if isinstance(value, (dict, list, set, tuple)):
            frozen_value = freeze_attributes(value)
        else:
            frozen_value = value

        if description is None:
            clean_desc = ""
        elif not isinstance(description, str):
            raise TypeError(f"description must be a string, got {type(description).__name__}")
        else:
            clean_desc = description.strip()

        object.__setattr__(self, "field", clean_field)
        object.__setattr__(self, "operator", validated_op)
        object.__setattr__(self, "value", frozen_value)
        object.__setattr__(self, "description", clean_desc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert condition to a deterministic JSON-serializable dictionary."""
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": unfreeze_to_dict(self.value),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleCondition":
        """Reconstruct a RuleCondition from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"data must be a dict, got {type(data).__name__}")
        return cls(
            field=data["field"],
            operator=data["operator"],
            value=data.get("value"),
            description=data.get("description", ""),
        )


def _validate_rule_id(val: str) -> str:
    """Validate that a rule ID conforms to the ForensiX RULE-<ID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"rule_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id:
        raise ValueError("rule_id must not be empty")
    if not clean_id.startswith("RULE-"):
        raise ValueError(f"rule_id must start with 'RULE-', got '{val}'")
    suffix = clean_id[len("RULE-"):].strip()
    if not suffix:
        raise ValueError(f"rule_id suffix after 'RULE-' must not be empty, got '{val}'")
    return clean_id


def compute_deterministic_rule_id(
    name: str,
    required_event_types: Optional[Iterable[str]] = None,
    discriminator: Optional[str] = None,
) -> str:
    """
    Compute a deterministic RFC 4122 UUIDv5 rule identifier (RULE-<UUIDv5>).

    Guarantees:
    - Same rule name + same required event types (+ same discriminator)
      always produces the exact same rule ID across runs and platforms.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Cannot compute deterministic rule ID without a valid rule name")

    clean_name = name.strip()
    key_parts = [clean_name]

    if required_event_types:
        sorted_types = sorted(str(t).strip() for t in required_event_types if str(t).strip())
        if sorted_types:
            key_parts.append(",".join(sorted_types))

    if discriminator is not None and str(discriminator).strip():
        key_parts.append(str(discriminator).strip())

    canonical_key = ":".join(key_parts)
    det_uuid = uuid.uuid5(FORENSIX_V4_RULE_NAMESPACE, canonical_key)
    return f"RULE-{det_uuid}"


def _check_speculative_language(text: str, field_name: str) -> None:
    """Verify that a string field contains no prohibited speculative attack assertions."""
    lower_text = text.lower()
    for term in DISALLOWED_SPECULATIVE_TERMS:
        if term in lower_text:
            raise ValueError(
                f"Speculative or interpretive phrase '{term}' is disallowed in {field_name}. "
                "Detection rules must use factual, explainable language."
            )


@dataclass(frozen=True)
class DetectionRule:
    """
    Immutable representation of an explainable, declarative detection rule.

    Contains all specifications required for V4.4 Detection Engine evaluation:
    - Identity and description
    - Required timeline event categories and types
    - Required correlation relationships
    - Declarative attribute conditions
    - Time-window constraint
    - Resulting detection description
    """

    rule_id: str
    name: str
    description: str
    detection_description: str
    required_categories: Tuple[TimelineCategory, ...] = ()
    required_event_types: Tuple[str, ...] = ()
    required_relationships: Tuple[CorrelationType, ...] = ()
    conditions: Tuple[RuleCondition, ...] = ()
    time_window_seconds: Optional[float] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        name: str,
        description: str,
        detection_description: str,
        *,
        rule_id: Optional[str] = None,
        required_categories: Optional[Sequence[Union[TimelineCategory, str]]] = None,
        required_event_types: Optional[Sequence[str]] = None,
        required_relationships: Optional[Sequence[Union[CorrelationType, str]]] = None,
        conditions: Optional[Sequence[Union[RuleCondition, Dict[str, Any]]]] = None,
        time_window_seconds: Optional[Union[float, int]] = None,
        attributes: Any = None,
    ) -> None:
        # 1. Validate name
        if name is None:
            raise TypeError("DetectionRule missing required argument: 'name'")
        if not isinstance(name, str):
            raise TypeError(f"name must be a string, got {type(name).__name__}")
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("name must be a non-empty string")
        _check_speculative_language(clean_name, "name")

        # 2. Validate description
        if description is None:
            raise TypeError("DetectionRule missing required argument: 'description'")
        if not isinstance(description, str):
            raise TypeError(f"description must be a string, got {type(description).__name__}")
        clean_desc = description.strip()
        if not clean_desc:
            raise ValueError("description must be a non-empty string")
        _check_speculative_language(clean_desc, "description")

        # 3. Validate detection_description
        if detection_description is None:
            raise TypeError("DetectionRule missing required argument: 'detection_description'")
        if not isinstance(detection_description, str):
            raise TypeError(
                f"detection_description must be a string, got {type(detection_description).__name__}"
            )
        clean_det_desc = detection_description.strip()
        if not clean_det_desc:
            raise ValueError("detection_description must be a non-empty string")
        _check_speculative_language(clean_det_desc, "detection_description")

        # 4. Validate required_categories
        validated_categories: List[TimelineCategory] = []
        if required_categories is not None:
            if not isinstance(required_categories, (list, tuple, set)):
                raise TypeError(
                    f"required_categories must be a sequence of TimelineCategory or str, got {type(required_categories).__name__}"
                )
            for c in required_categories:
                if isinstance(c, TimelineCategory):
                    validated_categories.append(c)
                elif isinstance(c, str):
                    clean_c = c.strip().lower()
                    try:
                        validated_categories.append(TimelineCategory(clean_c))
                    except ValueError:
                        valid_cats = sorted([cat.value for cat in TimelineCategory])
                        raise ValueError(
                            f"Invalid timeline category: '{c}'. Must be one of: {valid_cats}"
                        )
                else:
                    raise TypeError(
                        f"required_categories item must be TimelineCategory or str, got {type(c).__name__}"
                    )

        frozen_categories = tuple(dict.fromkeys(validated_categories))

        # 5. Validate required_event_types
        validated_event_types: List[str] = []
        if required_event_types is not None:
            if not isinstance(required_event_types, (list, tuple, set)):
                raise TypeError(
                    f"required_event_types must be a sequence of strings, got {type(required_event_types).__name__}"
                )
            for et in required_event_types:
                if not isinstance(et, str):
                    raise TypeError(
                        f"required_event_types item must be a string, got {type(et).__name__}"
                    )
                clean_et = et.strip()
                if not clean_et:
                    raise ValueError("required_event_types items must not be empty strings")
                # Prohibit speculative event types (reusing TimelineEvent principles)
                disallowed_types = {
                    "attack_detected",
                    "compromise_confirmed",
                    "malware_executed",
                    "threat_detected",
                    "incident_confirmed",
                    "anomaly_detected",
                }
                if clean_et.lower() in disallowed_types:
                    raise ValueError(
                        f"Speculative event type '{clean_et}' is disallowed in DetectionRule"
                    )
                validated_event_types.append(clean_et)

        frozen_event_types = tuple(dict.fromkeys(validated_event_types))

        # 6. Validate required_relationships
        validated_relationships: List[CorrelationType] = []
        if required_relationships is not None:
            if not isinstance(required_relationships, (list, tuple, set)):
                raise TypeError(
                    f"required_relationships must be a sequence of CorrelationType or str, got {type(required_relationships).__name__}"
                )
            for r in required_relationships:
                if isinstance(r, CorrelationType):
                    validated_relationships.append(r)
                elif isinstance(r, str):
                    clean_r = r.strip().upper()
                    try:
                        validated_relationships.append(CorrelationType(clean_r))
                    except ValueError:
                        valid_rels = sorted([rel.value for rel in CorrelationType])
                        raise ValueError(
                            f"Invalid relationship type: '{r}'. Must be one of: {valid_rels}"
                        )
                else:
                    raise TypeError(
                        f"required_relationships item must be CorrelationType or str, got {type(r).__name__}"
                    )

        frozen_relationships = tuple(dict.fromkeys(validated_relationships))

        # 7. Validate conditions
        validated_conditions: List[RuleCondition] = []
        if conditions is not None:
            if not isinstance(conditions, (list, tuple, set)):
                raise TypeError(
                    f"conditions must be a sequence of RuleCondition objects, got {type(conditions).__name__}"
                )
            for cond in conditions:
                if isinstance(cond, RuleCondition):
                    validated_conditions.append(cond)
                elif isinstance(cond, dict):
                    validated_conditions.append(RuleCondition.from_dict(cond))
                else:
                    raise TypeError(
                        f"conditions item must be RuleCondition or dict, got {type(cond).__name__}"
                    )

        frozen_conditions = tuple(validated_conditions)

        # 8. Validate time_window_seconds
        validated_window: Optional[float] = None
        if time_window_seconds is not None:
            if isinstance(time_window_seconds, bool) or not isinstance(time_window_seconds, (int, float)):
                raise TypeError(
                    f"time_window_seconds must be a float or int, got {type(time_window_seconds).__name__}"
                )
            if time_window_seconds < 0:
                raise ValueError(
                    f"time_window_seconds must be non-negative, got {time_window_seconds}"
                )
            validated_window = float(time_window_seconds)

        # 9. Validate rule_id
        if rule_id is None:
            validated_rule_id = compute_deterministic_rule_id(clean_name, frozen_event_types)
        else:
            validated_rule_id = _validate_rule_id(rule_id)

        # 10. Validate attributes
        if attributes is None or (isinstance(attributes, (dict, tuple, list)) and len(attributes) == 0):
            frozen_attributes: Tuple[Tuple[str, Any], ...] = _FrozenDict()
        elif isinstance(attributes, (dict, tuple, list)):
            frozen_attributes = freeze_attributes(attributes)
        else:
            raise TypeError(
                f"attributes must be a dict, sequence of pairs, or None, got {type(attributes).__name__}"
            )

        # Assign immutable fields
        object.__setattr__(self, "rule_id", validated_rule_id)
        object.__setattr__(self, "name", clean_name)
        object.__setattr__(self, "description", clean_desc)
        object.__setattr__(self, "detection_description", clean_det_desc)
        object.__setattr__(self, "required_categories", frozen_categories)
        object.__setattr__(self, "required_event_types", frozen_event_types)
        object.__setattr__(self, "required_relationships", frozen_relationships)
        object.__setattr__(self, "conditions", frozen_conditions)
        object.__setattr__(self, "time_window_seconds", validated_window)
        object.__setattr__(self, "attributes", frozen_attributes)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to a deterministic JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "detection_description": self.detection_description,
            "required_categories": [c.value for c in self.required_categories],
            "required_event_types": list(self.required_event_types),
            "required_relationships": [r.value for r in self.required_relationships],
            "conditions": [c.to_dict() for c in self.conditions],
            "time_window_seconds": self.time_window_seconds,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionRule":
        """Reconstruct a DetectionRule from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"data must be a dict, got {type(data).__name__}")
        return cls(
            rule_id=data.get("rule_id"),
            name=data["name"],
            description=data["description"],
            detection_description=data["detection_description"],
            required_categories=data.get("required_categories", ()),
            required_event_types=data.get("required_event_types", ()),
            required_relationships=data.get("required_relationships", ()),
            conditions=[
                RuleCondition.from_dict(c) if isinstance(c, dict) else c
                for c in data.get("conditions", ())
            ],
            time_window_seconds=data.get("time_window_seconds"),
            attributes=data.get("attributes", {}),
        )


# Convenience alias for DetectionRule
Rule = DetectionRule


def create_rule(
    name: str,
    description: str,
    detection_description: str,
    *,
    rule_id: Optional[str] = None,
    required_categories: Optional[Sequence[Union[TimelineCategory, str]]] = None,
    required_event_types: Optional[Sequence[str]] = None,
    required_relationships: Optional[Sequence[Union[CorrelationType, str]]] = None,
    conditions: Optional[Sequence[Union[RuleCondition, Dict[str, Any]]]] = None,
    time_window_seconds: Optional[Union[float, int]] = None,
    attributes: Any = None,
) -> DetectionRule:
    """Convenience factory to construct an immutable DetectionRule."""
    return DetectionRule(
        name=name,
        description=description,
        detection_description=detection_description,
        rule_id=rule_id,
        required_categories=required_categories,
        required_event_types=required_event_types,
        required_relationships=required_relationships,
        conditions=conditions,
        time_window_seconds=time_window_seconds,
        attributes=attributes,
    )


@dataclass(frozen=True)
class RuleCollection:
    """
    Immutable aggregate collection of detection rules.

    Attributes:
        rules: Immutable tuple of DetectionRule instances.
        total_rules: Count of rules in this collection.
    """

    rules: Tuple[DetectionRule, ...]
    total_rules: int

    def __init__(self, rules: Sequence[DetectionRule] = ()) -> None:
        if rules is None:
            rules_seq: Sequence[DetectionRule] = ()
        elif isinstance(rules, (list, tuple, set)):
            rules_seq = list(rules)
        else:
            raise TypeError(
                f"rules must be a sequence of DetectionRule objects, got {type(rules).__name__}"
            )

        validated: List[DetectionRule] = []
        seen_ids: Set[str] = set()
        for item in rules_seq:
            if not isinstance(item, DetectionRule):
                raise TypeError(
                    f"Item in rules must be DetectionRule, got {type(item).__name__}"
                )
            if item.rule_id in seen_ids:
                raise ValueError(f"Duplicate rule_id '{item.rule_id}' in RuleCollection")
            seen_ids.add(item.rule_id)
            validated.append(item)

        object.__setattr__(self, "rules", tuple(validated))
        object.__setattr__(self, "total_rules", len(validated))

    def __len__(self) -> int:
        return self.total_rules

    def __iter__(self) -> Iterator[DetectionRule]:
        return iter(self.rules)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.rules[idx]

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, DetectionRule):
            return item in self.rules
        if isinstance(item, str):
            return any(r.rule_id == item for r in self.rules)
        return False

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Look up a rule by its rule_id."""
        for r in self.rules:
            if r.rule_id == rule_id:
                return r
        return None

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics for the rule collection."""
        return {
            "total_rules": self.total_rules,
            "rule_ids": [r.rule_id for r in self.rules],
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule collection to a deterministic JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "rules": [r.to_dict() for r in self.rules],
        }
