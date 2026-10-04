"""
Forensic Detection Engine for ForensiX (V4.4 Detection Engine).

Evaluates declarative V4.3 DetectionRules against V3 TimelineEvents and V4.1/V4.2
Correlations to produce deterministic, factual, and explainable DetectionResult objects.

Core Principles:
- Factual observation matching: Detection is NOT proof of compromise.
- Strict provenance tracking: Retains matched timeline event IDs, source event IDs,
  source artifact IDs, and correlation IDs.
- Deterministic evaluation: Output results, ordering, and detection IDs are 100% reproducible.
- Non-speculative language: Rejects unsupported conclusions (e.g. 'system compromised').
- Read-only integrity: Never mutates timeline events, correlations, or rule definitions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
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

from forensix.correlation_engine import compute_timestamp_delta
from forensix.correlation_models import (
    DISALLOWED_SPECULATIVE_TERMS,
    Correlation,
    CorrelationCollection,
    CorrelationType,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)
from forensix.timeline_reconstruction import ReconstructedTimeline


# Canonical RFC 4122 UUID namespace for ForensiX V4 detections
FORENSIX_V4_DETECTION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v4/detection"
)

# Internal sentinel to represent missing/non-existent fields
_MISSING = object()


def compute_deterministic_detection_id(
    rule_id: str,
    matched_event_ids: Iterable[str],
    matched_correlation_ids: Optional[Iterable[str]] = None,
    discriminator: Optional[str] = None,
) -> str:
    """
    Compute a deterministic RFC 4122 UUIDv5 detection identifier (DET-<UUIDv5>).

    Guarantees:
    - Same rule ID + same sorted event IDs + same sorted correlation IDs
      always produces the exact same detection ID across runs and platforms.
    """
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("Cannot compute deterministic detection ID without a valid rule ID")

    clean_rule_id = rule_id.strip()
    sorted_events = sorted(str(eid).strip() for eid in matched_event_ids if str(eid).strip())
    if not sorted_events:
        raise ValueError("Cannot compute deterministic detection ID without matched event IDs")

    key_parts = [clean_rule_id, ",".join(sorted_events)]

    if matched_correlation_ids:
        sorted_corrs = sorted(str(cid).strip() for cid in matched_correlation_ids if str(cid).strip())
        if sorted_corrs:
            key_parts.append(",".join(sorted_corrs))

    if discriminator is not None and str(discriminator).strip():
        key_parts.append(str(discriminator).strip())

    canonical_key = ":".join(key_parts)
    det_uuid = uuid.uuid5(FORENSIX_V4_DETECTION_NAMESPACE, canonical_key)
    return f"DET-{det_uuid}"


def _validate_detection_id(val: str) -> str:
    """Validate that a string conforms to the ForensiX DET-<ID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"detection_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id:
        raise ValueError("detection_id must not be empty")
    if not clean_id.startswith("DET-"):
        raise ValueError(f"detection_id must start with 'DET-', got '{val}'")
    suffix = clean_id[len("DET-"):].strip()
    if not suffix:
        raise ValueError(f"detection_id suffix after 'DET-' must not be empty, got '{val}'")
    return clean_id


@dataclass(frozen=True)
class DetectionResult:
    """
    Immutable representation of an explainable, factual detection result.

    Preserves comprehensive forensic provenance:
    - Which rule matched? (rule_id, rule_name)
    - Which timeline events matched? (matched_event_ids)
    - Which correlations supported the match? (matched_correlation_ids)
    - What source artifacts/events produced it? (matched_source_event_ids, matched_source_artifact_ids)
    - What temporal interval was observed? (start_timestamp, end_timestamp, time_delta_seconds)
    - What factual narrative was produced? (explanation)
    """

    detection_id: str
    rule_id: str
    rule_name: str
    matched: bool
    matched_event_ids: Tuple[str, ...]
    matched_source_event_ids: Tuple[str, ...] = ()
    matched_source_artifact_ids: Tuple[str, ...] = ()
    matched_correlation_ids: Tuple[str, ...] = ()
    start_timestamp: Optional[datetime] = None
    end_timestamp: Optional[datetime] = None
    time_delta_seconds: Optional[float] = None
    explanation: str = ""
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        matched_event_ids: Sequence[str],
        *,
        detection_id: Optional[str] = None,
        matched: bool = True,
        matched_source_event_ids: Optional[Sequence[str]] = None,
        matched_source_artifact_ids: Optional[Sequence[str]] = None,
        matched_correlation_ids: Optional[Sequence[str]] = None,
        start_timestamp: Optional[Union[datetime, str]] = None,
        end_timestamp: Optional[Union[datetime, str]] = None,
        time_delta_seconds: Optional[Union[float, int]] = None,
        explanation: str = "",
        description: Optional[str] = None,
        attributes: Any = None,
    ) -> None:
        # 1. Validate rule_id & rule_name
        if rule_id is None:
            raise TypeError("DetectionResult missing required argument: 'rule_id'")
        if not isinstance(rule_id, str):
            raise TypeError(f"rule_id must be a string, got {type(rule_id).__name__}")
        clean_rule_id = rule_id.strip()
        if not clean_rule_id:
            raise ValueError("rule_id must not be empty")

        if rule_name is None:
            raise TypeError("DetectionResult missing required argument: 'rule_name'")
        if not isinstance(rule_name, str):
            raise TypeError(f"rule_name must be a string, got {type(rule_name).__name__}")
        clean_rule_name = rule_name.strip()
        if not clean_rule_name:
            raise ValueError("rule_name must not be empty")

        # 2. Validate matched_event_ids
        if matched_event_ids is None:
            raise TypeError("DetectionResult missing required argument: 'matched_event_ids'")
        if not isinstance(matched_event_ids, (list, tuple, set)):
            raise TypeError(
                f"matched_event_ids must be a sequence of strings, got {type(matched_event_ids).__name__}"
            )
        val_event_ids: List[str] = []
        for it in matched_event_ids:
            if not isinstance(it, str):
                raise TypeError(f"matched_event_ids item must be a string, got {type(it).__name__}")
            s = it.strip()
            if not s:
                raise ValueError("matched_event_ids item must not be empty")
            val_event_ids.append(s)
        frozen_event_ids = tuple(val_event_ids)
        if not frozen_event_ids:
            raise ValueError("matched_event_ids must contain at least one event ID")

        # 3. Validate matched
        if not isinstance(matched, bool):
            raise TypeError(f"matched must be a boolean, got {type(matched).__name__}")

        # 4. Validate matched_correlation_ids
        val_corr_ids: List[str] = []
        if matched_correlation_ids is not None:
            if not isinstance(matched_correlation_ids, (list, tuple, set)):
                raise TypeError(
                    f"matched_correlation_ids must be a sequence of strings, got {type(matched_correlation_ids).__name__}"
                )
            for it in matched_correlation_ids:
                if not isinstance(it, str):
                    raise TypeError(f"matched_correlation_ids item must be a string, got {type(it).__name__}")
                s = it.strip()
                if not s:
                    raise ValueError("matched_correlation_ids item must not be empty")
                val_corr_ids.append(s)
        frozen_corr_ids = tuple(dict.fromkeys(val_corr_ids))

        # 5. Validate detection_id
        if detection_id is None:
            validated_det_id = compute_deterministic_detection_id(
                clean_rule_id, frozen_event_ids, frozen_corr_ids
            )
        else:
            validated_det_id = _validate_detection_id(detection_id)

        # 6. Validate source IDs
        val_src_events: List[str] = []
        if matched_source_event_ids is not None:
            if not isinstance(matched_source_event_ids, (list, tuple, set)):
                raise TypeError(
                    f"matched_source_event_ids must be a sequence of strings, got {type(matched_source_event_ids).__name__}"
                )
            for it in matched_source_event_ids:
                if not isinstance(it, str):
                    raise TypeError(f"matched_source_event_ids item must be a string, got {type(it).__name__}")
                s = it.strip()
                if not s:
                    raise ValueError("matched_source_event_ids item must not be empty")
                val_src_events.append(s)
        frozen_src_events = tuple(dict.fromkeys(val_src_events))

        val_src_artifacts: List[str] = []
        if matched_source_artifact_ids is not None:
            if not isinstance(matched_source_artifact_ids, (list, tuple, set)):
                raise TypeError(
                    f"matched_source_artifact_ids must be a sequence of strings, got {type(matched_source_artifact_ids).__name__}"
                )
            for it in matched_source_artifact_ids:
                if not isinstance(it, str):
                    raise TypeError(f"matched_source_artifact_ids item must be a string, got {type(it).__name__}")
                s = it.strip()
                if not s:
                    raise ValueError("matched_source_artifact_ids item must not be empty")
                val_src_artifacts.append(s)
        frozen_src_artifacts = tuple(dict.fromkeys(val_src_artifacts))

        # 7. Validate timestamps & delta
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

        # 8. Validate explanation / description
        chosen_expl = description if description is not None else explanation
        if chosen_expl is None:
            clean_expl = ""
        elif not isinstance(chosen_expl, str):
            raise TypeError(f"explanation must be a string, got {type(chosen_expl).__name__}")
        else:
            clean_expl = chosen_expl.strip()

        # Enforce non-speculative language policy
        lower_expl = clean_expl.lower()
        for term in DISALLOWED_SPECULATIVE_TERMS:
            if term in lower_expl:
                raise ValueError(
                    f"Speculative or interpretive phrase '{term}' is disallowed in DetectionResult explanation. "
                    "Detection results must use factual, explainable language."
                )

        # 9. Freeze attributes
        if attributes is None or (isinstance(attributes, (dict, tuple, list)) and len(attributes) == 0):
            frozen_attributes: Tuple[Tuple[str, Any], ...] = _FrozenDict()
        elif isinstance(attributes, (dict, tuple, list)):
            frozen_attributes = freeze_attributes(attributes)
        else:
            raise TypeError(
                f"attributes must be a dict, sequence of pairs, or None, got {type(attributes).__name__}"
            )

        # Assign immutable fields
        object.__setattr__(self, "detection_id", validated_det_id)
        object.__setattr__(self, "rule_id", clean_rule_id)
        object.__setattr__(self, "rule_name", clean_rule_name)
        object.__setattr__(self, "matched", matched)
        object.__setattr__(self, "matched_event_ids", frozen_event_ids)
        object.__setattr__(self, "matched_source_event_ids", frozen_src_events)
        object.__setattr__(self, "matched_source_artifact_ids", frozen_src_artifacts)
        object.__setattr__(self, "matched_correlation_ids", frozen_corr_ids)
        object.__setattr__(self, "start_timestamp", validated_start_ts)
        object.__setattr__(self, "end_timestamp", validated_end_ts)
        object.__setattr__(self, "time_delta_seconds", validated_delta)
        object.__setattr__(self, "explanation", clean_expl)
        object.__setattr__(self, "attributes", frozen_attributes)

    @property
    def description(self) -> str:
        """Alias for explanation for compatibility with other ForensiX models."""
        return self.explanation

    @property
    def event_ids(self) -> Tuple[str, ...]:
        """Alias for matched_event_ids."""
        return self.matched_event_ids

    @property
    def correlation_ids(self) -> Tuple[str, ...]:
        """Alias for matched_correlation_ids."""
        return self.matched_correlation_ids

    @property
    def delta_seconds(self) -> Optional[float]:
        """Alias for time_delta_seconds."""
        return self.time_delta_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection result to a deterministic JSON-serializable dictionary."""
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched": self.matched,
            "matched_event_ids": list(self.matched_event_ids),
            "matched_source_event_ids": list(self.matched_source_event_ids),
            "matched_source_artifact_ids": list(self.matched_source_artifact_ids),
            "matched_correlation_ids": list(self.matched_correlation_ids),
            "start_timestamp": self.start_timestamp.isoformat() if self.start_timestamp is not None else None,
            "end_timestamp": self.end_timestamp.isoformat() if self.end_timestamp is not None else None,
            "time_delta_seconds": self.time_delta_seconds,
            "explanation": self.explanation,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionResult":
        """Reconstruct a DetectionResult from a dictionary representation."""
        if not isinstance(data, dict):
            raise TypeError(f"data must be a dict, got {type(data).__name__}")
        return cls(
            detection_id=data.get("detection_id"),
            rule_id=data["rule_id"],
            rule_name=data["rule_name"],
            matched=data.get("matched", True),
            matched_event_ids=data["matched_event_ids"],
            matched_source_event_ids=data.get("matched_source_event_ids", ()),
            matched_source_artifact_ids=data.get("matched_source_artifact_ids", ()),
            matched_correlation_ids=data.get("matched_correlation_ids", ()),
            start_timestamp=data.get("start_timestamp"),
            end_timestamp=data.get("end_timestamp"),
            time_delta_seconds=data.get("time_delta_seconds"),
            explanation=data.get("explanation", ""),
            attributes=data.get("attributes", {}),
        )


@dataclass(frozen=True)
class DetectionResultCollection:
    """
    Immutable aggregate collection of forensic detection results.

    Attributes:
        results: Immutable tuple of DetectionResult instances.
        total_detections: Total count of detections in the collection.
        rule_counts: Immutable tuple of (rule_id, count) pairs.
    """

    results: Tuple[DetectionResult, ...]
    total_detections: int
    rule_counts: Tuple[Tuple[str, int], ...]

    def __init__(self, results: Sequence[DetectionResult] = ()) -> None:
        if results is None:
            results_seq: Sequence[DetectionResult] = ()
        elif isinstance(results, (list, tuple, set)):
            results_seq = list(results)
        else:
            raise TypeError(
                f"results must be a sequence of DetectionResult objects, got {type(results).__name__}"
            )

        validated: List[DetectionResult] = []
        counts: Dict[str, int] = {}
        for item in results_seq:
            if not isinstance(item, DetectionResult):
                raise TypeError(
                    f"Item in results must be DetectionResult, got {type(item).__name__}"
                )
            validated.append(item)
            counts[item.rule_id] = counts.get(item.rule_id, 0) + 1

        object.__setattr__(self, "results", tuple(validated))
        object.__setattr__(self, "total_detections", len(validated))
        object.__setattr__(self, "rule_counts", tuple(sorted(counts.items())))

    def __len__(self) -> int:
        return self.total_detections

    def __iter__(self) -> Iterator[DetectionResult]:
        return iter(self.results)

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.results[idx]

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, DetectionResult):
            return item in self.results
        if isinstance(item, str):
            return any(r.detection_id == item for r in self.results)
        return False

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics for the detection collection."""
        return {
            "total_detections": self.total_detections,
            "rule_counts": dict(self.rule_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection collection to a deterministic JSON-serializable dictionary."""
        return {
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


def detection_sort_key(res: DetectionResult) -> Tuple[Any, ...]:
    """
    Construct a deterministic comparison key for sorting DetectionResult objects.

    Ordering guarantees:
    1. Aware start timestamps first (sorted by UTC instant).
    2. Naive start timestamps second (sorted by naive datetime).
    3. Missing start timestamps third.
    4. Rule ID (lexicographical).
    5. First event ID (lexicographical).
    6. First correlation ID (lexicographical).
    7. Detection ID (lexicographical).
    """
    ts = res.start_timestamp
    if ts is None:
        ts_class = 2
        ts_val: Any = 0
    elif ts.tzinfo is not None and ts.tzinfo.utcoffset(ts) is not None:
        ts_class = 0
        ts_val = ts.astimezone(timezone.utc)
    else:
        ts_class = 1
        ts_val = ts

    eid1 = res.matched_event_ids[0] if res.matched_event_ids else ""
    cid1 = res.matched_correlation_ids[0] if res.matched_correlation_ids else ""

    return (
        ts_class,
        ts_val,
        res.rule_id,
        eid1,
        cid1,
        res.detection_id,
    )


def resolve_field_value(target: Any, field_name: str) -> Any:
    """
    Resolve a named field or nested attribute from an event or correlation object.

    Resolution order:
    1. If target is None, returns _MISSING.
    2. If field_name contains dots (e.g. 'attributes.username' or 'payload.data.id'), resolves path.
    3. Direct property on target object (e.g. event_type, category, source_path).
    4. Direct lookup inside target.attributes (if target has an attributes property).
    5. If target is dict, direct key lookup.
    6. If target is tuple/list of (key, value) pairs (e.g. _FrozenDict), pair key lookup.
    7. Returns _MISSING if field cannot be found.
    """
    if target is None:
        return _MISSING

    # Nested path resolution (e.g. 'attributes.username' or 'payload.data.id')
    if "." in field_name:
        head, rest = field_name.split(".", 1)
        sub_target = resolve_field_value(target, head)
        if sub_target is not _MISSING:
            return resolve_field_value(sub_target, rest)
        # If head is 'attributes', fallback to getattr(target, 'attributes')
        if head == "attributes" and hasattr(target, "attributes"):
            return resolve_field_value(getattr(target, "attributes"), rest)
        return _MISSING

    # 1. Direct attribute on object (exclude private attributes and callable methods)
    if hasattr(target, field_name) and not field_name.startswith("_"):
        val = getattr(target, field_name)
        if not callable(val):
            if isinstance(val, Enum):
                return val.value
            return val

    # 2. Lookup inside target.attributes if present
    if hasattr(target, "attributes"):
        target_attrs = getattr(target, "attributes")
        if target_attrs is not target and target_attrs is not None:
            attr_val = resolve_field_value(target_attrs, field_name)
            if attr_val is not _MISSING:
                return attr_val

    # 3. If target is a dictionary directly
    if isinstance(target, dict):
        if field_name in target:
            val = target[field_name]
            if isinstance(val, Enum):
                return val.value
            return val

    # 4. If target is _FrozenDict or sequence of (key, value) pairs
    if isinstance(target, (tuple, list)):
        for item in target:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == field_name:
                val = item[1]
                if isinstance(val, Enum):
                    return val.value
                return val

    return _MISSING


def evaluate_condition_operator(
    actual: Any,
    operator: ConditionOperator,
    expected: Any,
) -> bool:
    """
    Evaluate a ConditionOperator predicate between actual and expected values.

    Handles missing fields, None, empty values, numeric zero, and boolean False explicitly.
    """
    if operator == ConditionOperator.EXISTS:
        if expected is False:
            return actual is _MISSING or actual is None
        return actual is not _MISSING and actual is not None

    # For all other operators, missing field cannot produce a match
    if actual is _MISSING:
        return False

    if operator == ConditionOperator.EQUALS:
        # Scalar equality check
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            # Disallow bool vs numeric comparison (in Python bool is a subclass of int)
            if isinstance(actual, bool) or isinstance(expected, bool):
                return actual is expected
            return float(actual) == float(expected)
        if isinstance(actual, Enum):
            actual = actual.value
        if isinstance(expected, Enum):
            expected = expected.value
        return actual == expected

    if operator == ConditionOperator.NOT_EQUALS:
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            if isinstance(actual, bool) or isinstance(expected, bool):
                return actual is not expected
            return float(actual) != float(expected)
        if isinstance(actual, Enum):
            actual = actual.value
        if isinstance(expected, Enum):
            expected = expected.value
        return actual != expected

    if operator == ConditionOperator.CONTAINS:
        if actual is None or expected is None:
            return False
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        if isinstance(actual, (list, tuple, set, _FrozenList)):
            return expected in actual
        if isinstance(actual, (dict, _FrozenDict)):
            return expected in actual
        return False

    if operator == ConditionOperator.IN:
        if actual is None or expected is None:
            return False
        if isinstance(expected, (list, tuple, set, _FrozenList)):
            return actual in expected
        if isinstance(expected, str) and isinstance(actual, str):
            return actual in expected
        return False

    # Numeric / Ordered comparisons
    if operator in (
        ConditionOperator.GREATER_THAN,
        ConditionOperator.GREATER_EQUAL,
        ConditionOperator.LESS_THAN,
        ConditionOperator.LESS_EQUAL,
    ):
        if actual is None or expected is None:
            return False
        # Do not compare booleans numerically
        if isinstance(actual, bool) or isinstance(expected, bool):
            return False
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            act_num = float(actual)
            exp_num = float(expected)
            if operator == ConditionOperator.GREATER_THAN:
                return act_num > exp_num
            if operator == ConditionOperator.GREATER_EQUAL:
                return act_num >= exp_num
            if operator == ConditionOperator.LESS_THAN:
                return act_num < exp_num
            if operator == ConditionOperator.LESS_EQUAL:
                return act_num <= exp_num
        # Date comparisons
        if isinstance(actual, datetime) and isinstance(expected, datetime):
            try:
                if operator == ConditionOperator.GREATER_THAN:
                    return actual > expected
                if operator == ConditionOperator.GREATER_EQUAL:
                    return actual >= expected
                if operator == ConditionOperator.LESS_THAN:
                    return actual < expected
                if operator == ConditionOperator.LESS_EQUAL:
                    return actual <= expected
            except TypeError:
                return False
        return False

    return False


def evaluate_single_condition(
    condition: RuleCondition,
    candidate_events: Sequence[TimelineEvent],
    correlation: Optional[Correlation] = None,
) -> bool:
    """
    Evaluate a single RuleCondition against a candidate set of events and optional correlation.

    Supports:
    - Specific target prefix: 'events[0].field', 'events[1].field', 'correlation.field'.
    - General field: matches if ANY event in the candidate sequence (or correlation) satisfies the condition.
    """
    field_name = condition.field

    # Explicit event indexing: 'events[0].field'
    if field_name.startswith("events[") and "]." in field_name:
        idx_end = field_name.index("].")
        idx_str = field_name[len("events["):idx_end]
        target_field = field_name[idx_end + 2:]
        try:
            ev_idx = int(idx_str)
            if 0 <= ev_idx < len(candidate_events):
                act_val = resolve_field_value(candidate_events[ev_idx], target_field)
                return evaluate_condition_operator(act_val, condition.operator, condition.value)
            return False
        except ValueError:
            return False

    # Explicit correlation prefix: 'correlation.field'
    if field_name.startswith("correlation."):
        target_field = field_name[len("correlation."):]
        if correlation is not None:
            act_val = resolve_field_value(correlation, target_field)
            return evaluate_condition_operator(act_val, condition.operator, condition.value)
        return False

    # Check correlation first if it has the field directly
    if correlation is not None:
        corr_val = resolve_field_value(correlation, field_name)
        if corr_val is not _MISSING:
            if evaluate_condition_operator(corr_val, condition.operator, condition.value):
                return True

    # Check candidate events: condition is satisfied if at least one event in the sequence matches
    for ev in candidate_events:
        act_val = resolve_field_value(ev, field_name)
        if act_val is not _MISSING:
            if evaluate_condition_operator(act_val, condition.operator, condition.value):
                return True

    # If field is missing on all events and correlation, evaluate with _MISSING (handles EXISTS=False)
    return evaluate_condition_operator(_MISSING, condition.operator, condition.value)


class DetectionEngine:
    """
    Deterministic rule evaluation engine for ForensiX.

    Evaluates V4.3 DetectionRules against V3 TimelineEvents and V4.1 Correlations
    and produces factual DetectionResult objects.
    """

    def __init__(
        self,
        rules: Optional[Union[RuleCollection, Sequence[DetectionRule]]] = None,
    ) -> None:
        if rules is not None:
            if isinstance(rules, RuleCollection):
                self._rules = rules.rules
            elif isinstance(rules, (list, tuple)):
                for idx, r in enumerate(rules):
                    if not isinstance(r, DetectionRule):
                        raise TypeError(
                            f"Item at index {idx} in rules is not a DetectionRule, got {type(r).__name__}"
                        )
                self._rules = tuple(rules)
            else:
                raise TypeError(
                    f"rules must be a RuleCollection or sequence of DetectionRules, got {type(rules).__name__}"
                )
        else:
            self._rules = ()

    @property
    def rules(self) -> Tuple[DetectionRule, ...]:
        """Return the immutable tuple of configured rules."""
        return self._rules

    def evaluate(
        self,
        timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
        correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
        rules: Optional[Union[RuleCollection, Sequence[DetectionRule]]] = None,
    ) -> DetectionResultCollection:
        """
        Evaluate rules against timeline events and correlations to produce detection results.

        Args:
            timeline: ReconstructedTimeline or sequence of TimelineEvent objects.
            correlations: Optional CorrelationCollection or sequence of Correlation objects.
            rules: Optional override of DetectionRules to evaluate.

        Returns:
            DetectionResultCollection containing all discovered detections in deterministic order.
        """
        # 1. Validate timeline input
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

        # Build fast lookup map for timeline events by event_id
        event_map: Dict[str, TimelineEvent] = {e.event_id: e for e in events}

        # 2. Validate correlations input
        corr_list: List[Correlation] = []
        if correlations is not None:
            if isinstance(correlations, CorrelationCollection):
                corr_list = list(correlations.correlations)
            elif isinstance(correlations, (list, tuple)):
                for idx, c in enumerate(correlations):
                    if not isinstance(c, Correlation):
                        raise TypeError(
                            f"Item at index {idx} in correlations is not a Correlation, got {type(c).__name__}"
                        )
                    corr_list.append(c)
            else:
                raise TypeError(
                    f"correlations must be a CorrelationCollection or sequence of Correlation objects, got {type(correlations).__name__}"
                )

        # 3. Determine active rules
        if rules is not None:
            if isinstance(rules, RuleCollection):
                active_rules = rules.rules
            elif isinstance(rules, (list, tuple)):
                for idx, r in enumerate(rules):
                    if not isinstance(r, DetectionRule):
                        raise TypeError(
                            f"Item at index {idx} in rules is not a DetectionRule, got {type(r).__name__}"
                        )
                active_rules = tuple(rules)
            else:
                raise TypeError(
                    f"rules must be a RuleCollection or sequence of DetectionRules, got {type(rules).__name__}"
                )
        else:
            active_rules = self._rules

        if not active_rules or not events:
            return DetectionResultCollection(())

        detections: List[DetectionResult] = []
        seen_detections: Set[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = set()

        for rule in active_rules:
            # Branch A: Rule specifies required correlation relationships
            if rule.required_relationships:
                required_rels = set(rule.required_relationships)
                # Match against provided correlations
                for corr in corr_list:
                    if corr.relationship_type in required_rels:
                        # Extract the events involved in this correlation
                        corr_events: List[TimelineEvent] = [
                            event_map[eid] for eid in corr.event_ids if eid in event_map
                        ]
                        if len(corr_events) < len(corr.event_ids):
                            # Missing one or more underlying events from the timeline
                            continue

                        # Check required categories if specified
                        if rule.required_categories:
                            event_cats = {e.category for e in corr_events}
                            if not all(rc in event_cats for rc in rule.required_categories):
                                continue

                        # Check required event types if specified
                        if rule.required_event_types:
                            event_types = {e.event_type for e in corr_events}
                            if not all(ret in event_types for ret in rule.required_event_types):
                                continue

                        # Check time window if specified on rule
                        if rule.time_window_seconds is not None:
                            # Re-verify correlation time delta against rule window
                            if corr.time_delta_seconds is None:
                                continue
                            if corr.time_delta_seconds > rule.time_window_seconds:
                                continue

                        # Evaluate all rule conditions (logical AND)
                        all_conditions_met = True
                        for cond in rule.conditions:
                            if not evaluate_single_condition(cond, corr_events, corr):
                                all_conditions_met = False
                                break

                        if all_conditions_met:
                            dedup_key = (
                                rule.rule_id,
                                tuple(sorted(corr.event_ids)),
                                (corr.correlation_id,),
                            )
                            if dedup_key not in seen_detections:
                                # Gather source provenance from events and correlation
                                src_events = list(corr.source_event_ids)
                                src_artifacts = list(corr.source_artifact_ids)
                                for ev in corr_events:
                                    if ev.source_event_id and ev.source_event_id not in src_events:
                                        src_events.append(ev.source_event_id)
                                    if ev.source_artifact_id and ev.source_artifact_id not in src_artifacts:
                                        src_artifacts.append(ev.source_artifact_id)

                                det = DetectionResult(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    matched=True,
                                    matched_event_ids=corr.event_ids,
                                    matched_source_event_ids=src_events,
                                    matched_source_artifact_ids=src_artifacts,
                                    matched_correlation_ids=(corr.correlation_id,),
                                    start_timestamp=corr.start_timestamp,
                                    end_timestamp=corr.end_timestamp,
                                    time_delta_seconds=corr.time_delta_seconds,
                                    explanation=rule.detection_description,
                                    attributes={
                                        "relationship_type": corr.relationship_type.value,
                                        "rule_description": rule.description,
                                    },
                                )
                                detections.append(det)
                                seen_detections.add(dedup_key)

            # Branch B: Rule has NO required relationships (matches individual events or event pairs)
            else:
                # Single-event rule (0 or 1 required event type and 0 or 1 category)
                if len(rule.required_event_types) <= 1:
                    for ev in events:
                        # Check category if specified
                        if rule.required_categories:
                            if ev.category not in rule.required_categories:
                                continue

                        # Check event type if specified
                        if rule.required_event_types:
                            if ev.event_type not in rule.required_event_types:
                                continue

                        # Evaluate conditions
                        all_conditions_met = True
                        for cond in rule.conditions:
                            if not evaluate_single_condition(cond, [ev], None):
                                all_conditions_met = False
                                break

                        if all_conditions_met:
                            dedup_key = (rule.rule_id, (ev.event_id,), ())
                            if dedup_key not in seen_detections:
                                src_events = (ev.source_event_id,) if ev.source_event_id else ()
                                src_artifacts = (ev.source_artifact_id,) if ev.source_artifact_id else ()

                                det = DetectionResult(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    matched=True,
                                    matched_event_ids=(ev.event_id,),
                                    matched_source_event_ids=src_events,
                                    matched_source_artifact_ids=src_artifacts,
                                    matched_correlation_ids=(),
                                    start_timestamp=ev.timestamp,
                                    end_timestamp=ev.timestamp,
                                    time_delta_seconds=0.0 if ev.timestamp else None,
                                    explanation=rule.detection_description,
                                    attributes={"rule_description": rule.description},
                                )
                                detections.append(det)
                                seen_detections.add(dedup_key)

                # Multi-event sequence rule without predefined correlation
                else:
                    req_types = list(rule.required_event_types)
                    num_req = len(req_types)

                    def search_sequences(
                        event_start_idx: int,
                        type_idx: int,
                        current_seq: List[TimelineEvent],
                    ) -> None:
                        if type_idx == num_req:
                            # Evaluate all rule conditions on this sequence
                            all_conditions_met = True
                            for cond in rule.conditions:
                                if not evaluate_single_condition(cond, current_seq, None):
                                    all_conditions_met = False
                                    break

                            if all_conditions_met:
                                ev_ids = tuple(e.event_id for e in current_seq)
                                dedup_key = (rule.rule_id, ev_ids, ())
                                if dedup_key not in seen_detections:
                                    src_evs = [e.source_event_id for e in current_seq if e.source_event_id]
                                    src_arts = [e.source_artifact_id for e in current_seq if e.source_artifact_id]
                                    first_ev = current_seq[0]
                                    last_ev = current_seq[-1]
                                    seq_delta = compute_timestamp_delta(first_ev.timestamp, last_ev.timestamp)

                                    det = DetectionResult(
                                        rule_id=rule.rule_id,
                                        rule_name=rule.name,
                                        matched=True,
                                        matched_event_ids=ev_ids,
                                        matched_source_event_ids=src_evs,
                                        matched_source_artifact_ids=src_arts,
                                        matched_correlation_ids=(),
                                        start_timestamp=first_ev.timestamp,
                                        end_timestamp=last_ev.timestamp,
                                        time_delta_seconds=seq_delta,
                                        explanation=rule.detection_description,
                                        attributes={"rule_description": rule.description},
                                    )
                                    detections.append(det)
                                    seen_detections.add(dedup_key)
                            return

                        target_type = req_types[type_idx]
                        for idx in range(event_start_idx, len(events)):
                            cand_ev = events[idx]
                            if cand_ev.event_type != target_type:
                                continue
                            if rule.required_categories and cand_ev.category not in rule.required_categories:
                                continue

                            # Time window check from the first event in the sequence
                            if current_seq and rule.time_window_seconds is not None:
                                delta = compute_timestamp_delta(current_seq[0].timestamp, cand_ev.timestamp)
                                if delta is None or delta > rule.time_window_seconds:
                                    continue

                            current_seq.append(cand_ev)
                            search_sequences(idx + 1, type_idx + 1, current_seq)
                            current_seq.pop()

                    search_sequences(0, 0, [])

        # Sort discovered detections in deterministic order
        detections.sort(key=detection_sort_key)
        return DetectionResultCollection(detections)


def evaluate_rules(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    rules: Union[RuleCollection, Sequence[DetectionRule]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
) -> DetectionResultCollection:
    """
    Convenience function to evaluate multiple rules against timeline events and correlations.
    """
    engine = DetectionEngine(rules=rules)
    return engine.evaluate(timeline=timeline, correlations=correlations)


def evaluate_rule(
    rule: DetectionRule,
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
) -> DetectionResultCollection:
    """
    Convenience function to evaluate a single rule against timeline events and correlations.
    """
    engine = DetectionEngine(rules=[rule])
    return engine.evaluate(timeline=timeline, correlations=correlations)
