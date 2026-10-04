# ForensiX V4.3 — Detection Rule Model

This document specifies the technical design, declarative architecture, and forensic principles of the **Detection Rule Model (`DetectionRule`, `Rule`, `RuleCondition`, `ConditionOperator`, `RuleCollection`)** introduced in **ForensiX V4.3 (Event Correlation & Rule-Based Detection)**.

---

## 1. Purpose

The V4.3 Detection Rule Model establishes a formal, declarative, and deeply immutable specification of detection patterns. 

Key objectives:
- **Declarative representation**: Express WHAT a rule requires (event types, categories, correlation relationships, attribute conditions, time window) without containing executable logic.
- **Explainability**: Rules are structured so an investigator can immediately understand why a match occurs.
- **Zero code execution**: Strictly prohibits executable callbacks, dynamic Python expressions, `eval()`, `exec()`, or shell commands inside rule definitions.
- **Factual forensic language**: Strictly prohibits speculative claims of compromise ("confirmed attack", "system compromised").
- **Deterministic identity & serialization**: Guarantees identical RFC 4122 UUIDv5 IDs and clean JSON roundtrip fidelity across runs and environments.

---

## 2. Why the Rule Model Exists

In ForensiX:
- **V3** reconstructs chronological observations (`TimelineEvent`, `ReconstructedTimeline`).
- **V4.1** represents explicit relationships (`Correlation`, `CorrelationCollection`).
- **V4.2** discovers these relationships (`CorrelationEngine`).
- **V4.3** formalizes detection rules as data structures (`DetectionRule`, `RuleCondition`).
- **V4.4** will evaluate these rules against timeline events and correlations (`DetectionEngine`).

Separating the **Rule Model (V4.3)** from the **Detection Engine (V4.4)** guarantees that rules remain inspectable, declarative, serializable, and auditable as forensic data assets rather than arbitrary black-box code.

---

## 3. Relationship to V4.1 and V4.2

- **To V4.1 (Correlation Model)**:
  - Detection rules can explicitly specify required correlation relationships (`required_relationships: Tuple[CorrelationType, ...]`), allowing rules to mandate relationships like `AUTHENTICATION_PRIVILEGE` or `SAME_USER`.
  - Reuses the `FORENSIX_V4_RULE_NAMESPACE` UUIDv5 pattern and `DISALLOWED_SPECULATIVE_TERMS`.
- **To V4.2 (Correlation Engine)**:
  - Rules inherit the same time-window semantics ($\text{delta} \le \text{window\_seconds}$).
  - Consumes output of V4.2 indirectly when evaluated by the future V4.4 Detection Engine.

---

## 4. Rule Architecture

```
Timeline Events (V3) + Correlations (V4.1 / V4.2)
                     ↓
       DetectionRule (V4.3 Specification)
         - Name & Description
         - Required Event Types & Categories
         - Required Correlation Relationships
         - Declarative RuleConditions
         - Time Window (seconds)
         - Factual Detection Description
                     ↓
       V4.4 Detection Engine (Evaluator) [PLANNED]
                     ↓
       V4.4 Detection Results [PLANNED]
```

---

## 5. Rule Fields (`DetectionRule` / `Rule`)

`DetectionRule` is a frozen dataclass with complete validation:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `rule_id` | `str` | Yes | Identifier formatted as `RULE-<ID>`. Auto-computed via RFC 4122 UUIDv5 if omitted. |
| `name` | `str` | Yes | Human-readable factual rule name. |
| `description` | `str` | Yes | Factual explanation of rule purpose and logic. |
| `detection_description` | `str` | Yes | Factual template/statement produced when rule matches. |
| `required_categories` | `Tuple[TimelineCategory, ...]` | No | Timeline categories required by the rule (default: empty tuple). |
| `required_event_types` | `Tuple[str, ...] ` | No | Event types required by the rule (default: empty tuple). |
| `required_relationships`| `Tuple[CorrelationType, ...]` | No | V4.1 relationship types required between events (default: empty tuple). |
| `conditions` | `Tuple[RuleCondition, ...]` | No | Declarative predicate conditions (default: empty tuple). |
| `time_window_seconds` | `Optional[float]` | No | Maximum time window in seconds (default: None = unconstrained). |
| `attributes` | `Tuple[Tuple[str, Any], ...]` | No | Deeply frozen metadata attributes (`_FrozenDict`). |

---

## 6. Condition Structure (`RuleCondition` & `ConditionOperator`)

`RuleCondition` represents an individual declarative predicate on an event attribute, field, or relationship.

### Supported Operators (`ConditionOperator`)
- `EQUALS` (`==`, `eq`, `equals`): Scalar equality match.
- `NOT_EQUALS` (`!=`, `ne`, `not_equals`): Scalar inequality match.
- `CONTAINS` (`contains`): Substring or collection containment.
- `IN` (`in`): Membership in target collection.
- `GREATER_THAN` (`>`, `gt`): Numeric greater-than comparison.
- `GREATER_EQUAL` (`>=`, `gte`): Numeric greater-than-or-equal comparison.
- `LESS_THAN` (`<`, `lt`): Numeric less-than comparison.
- `LESS_EQUAL` (`<=`, `lte`): Numeric less-than-or-equal comparison.
- `EXISTS` (`exists`, `is_not_null`): Attribute presence and non-null check.

### Zero-Code Security Enforcement
- `callable(value)` is strictly rejected with `TypeError`.
- String values containing expressions like `eval(`, `exec(`, or `import ` are rejected with `ValueError`.
- Collections passed as `value` are deeply frozen into immutable tuples via `freeze_attributes`.

---

## 7. Aggregate Collection (`RuleCollection`)

`RuleCollection` is an immutable container for rules:
- `rules: Tuple[DetectionRule, ...]`
- `total_rules: int`
- Methods: `__len__`, `__iter__`, `__getitem__`, `__contains__`, `get_rule(rule_id)`, `summary`, `to_dict()`.
- Enforces uniqueness of `rule_id` across the collection.

---

## 8. Validation Rules

- **Rule ID**: Must start with `RULE-` and have non-empty suffix.
- **Name, Description, Detection Description**: Must be non-empty strings. Rejects prohibited speculative phrases ("confirmed attack", "attacker confirmed", "system compromised", "malware confirmed", "intrusion confirmed").
- **Required Event Types**: Non-empty strings; rejects speculative types ("attack_detected", "anomaly_detected").
- **Required Categories**: Must be valid `TimelineCategory` instances or strings.
- **Required Relationships**: Must be valid `CorrelationType` instances or strings.
- **Time Window**: Non-negative numeric float/int ($>= 0.0$); boolean types rejected.

---

## 9. Immutability & Determinism

- **Deep Immutability**: All dataclasses are frozen (`@dataclass(frozen=True)`). Field assignments raise `FrozenInstanceError`.
- **Deterministic Identity**: `compute_deterministic_rule_id(name, required_event_types)` generates an RFC 4122 UUIDv5 identifier under `FORENSIX_V4_RULE_NAMESPACE`.
- **Deterministic Serialization**: Stable key ordering in `to_dict()` and full roundtrip fidelity with `from_dict()`.

---

## 10. Code Example

```python
from forensix import (
    ConditionOperator,
    CorrelationType,
    DetectionRule,
    RuleCondition,
    TimelineCategory,
    create_rule,
)

rule = create_rule(
    name="SSH Login Followed by Sudo",
    description="Identifies SSH login followed by privilege elevation",
    detection_description="Successful SSH authentication was followed by sudo activity for the same user within 5 minutes",
    required_categories=[TimelineCategory.AUTHENTICATION],
    required_event_types=["ssh_login_success", "sudo_command"],
    required_relationships=[CorrelationType.AUTHENTICATION_PRIVILEGE, CorrelationType.SAME_USER],
    conditions=[
        RuleCondition("status", ConditionOperator.EQUALS, "SUCCESS"),
        RuleCondition("command", ConditionOperator.EXISTS),
    ],
    time_window_seconds=300.0,
    attributes={"mitre_id": "T1078"},
)

print(rule.rule_id)  # RULE-<UUIDv5>
print(rule.time_window_seconds)  # 300.0
```

---

## 11. What V4.3 Does NOT Implement

In strict adherence to milestone boundaries:
- **No rule evaluation**: V4.3 does NOT evaluate events against rules.
- **No detection engine**: Belongs to V4.4 (`DetectionEngine`).
- **No detection result model**: `DetectionResult` belongs to V4.4.
- **No initial production rules**: V4.5 will implement the initial detection rules.
- **No reporting or CLI changes**: Addressed in V4.6 and V4.7.

---

## 12. Milestone Status

| Component | Status | Notes |
| :--- | :--- | :--- |
| **V4.1 Correlation Model** | **IMPLEMENTED** | Immutable `Correlation`, `CorrelationCollection`, and deterministic IDs. |
| **V4.2 Correlation Engine** | **IMPLEMENTED** | `CorrelationEngine`, `CorrelationConfig`, `correlate_events`. |
| **V4.3 Rule Model** | **IMPLEMENTED** | `DetectionRule`, `RuleCondition`, `ConditionOperator`, `RuleCollection`. |
| **V4.4 Detection Engine** | **PLANNED** | Rule evaluation against timeline events and correlations. |
| **V4.5 Initial Detection Rules** | **PLANNED** | 4 initial factual detection patterns. |
| **V4.6 Reporting Integration** | **PLANNED** | Additive JSON and HTML reporting. |
| **V4.7 CLI / Triage Integration**| **PLANNED** | Command line options and triage orchestration. |
| **V4.8 Final Hardening** | **PLANNED** | Comprehensive end-to-end verification. |
