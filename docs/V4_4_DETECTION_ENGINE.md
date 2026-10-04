# ForensiX V4.4 — Detection Engine

This document specifies the technical design, architectural principles, evaluation semantics, and forensic standards of the **Detection Engine (`DetectionEngine`, `DetectionResult`, `DetectionResultCollection`, `evaluate_rule`, `evaluate_rules`)** implemented in **ForensiX V4.4 (Event Correlation & Rule-Based Detection)**.

---

## 1. Purpose

The V4.4 Detection Engine transforms declarative detection rules (formalized in V4.3) into factual, explainable, and deterministic detection results by evaluating them against chronological timeline observations (V3) and discovered correlation relationships (V4.1 / V4.2).

Key objectives:
- **Factual observation evaluation**: Determines pattern matches based strictly on observed forensic events and correlations. Detection is **NOT** a verdict of compromise.
- **Traceable forensic provenance**: Preserves exact links to matched timeline events, source log lines, source artifact IDs, and correlation records.
- **Strict non-speculative language**: Enforces the project policy rejecting speculative or judgmental language (e.g., "system compromised", "attacker confirmed").
- **Deterministic reproducibility**: Guarantees identical detection counts, detection IDs (UUIDv5), ordering, and serialized outputs across executions.
- **Deep immutability & read-only safety**: Leaves timeline events, reconstructed timelines, correlations, and rules completely unmutated.

---

## 2. Architecture & Pipeline Position

```
+-------------------------------------------------------------+
|                     Forensic Evidence                       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  V1 & V2 Host Forensics                     |
|  (Filesystem, Logs, Auth Activity, Accounts, Persistence)   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              V3 Timeline Reconstruction                     |
|           (TimelineEvent, ReconstructedTimeline)           |
+-------------------------------------------------------------+
                              |
               +--------------+--------------+
               |                             |
               v                             v
+-----------------------------+ +-----------------------------+
|    V4.1 Correlation Model   | |     V4.3 Rule Model         |
|   V4.2 Correlation Engine   | |   (DetectionRule, Condition)|
+-----------------------------+ +-----------------------------+
               |                             |
               +--------------+--------------+
                              |
                              v
+-------------------------------------------------------------+
|                  V4.4 Detection Engine                      |
|         (DetectionEngine, evaluate_rule, evaluate_rules)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                   V4.4 Detection Results                    |
|          (DetectionResult, DetectionResultCollection)       |
+-------------------------------------------------------------+
                              | [FUTURE MILESTONES]
                              v
                    V4.5 Initial Detection Rules
                    V4.6 Detection Reporting
                    V4.7 CLI & Triage Integration
                    V4.8 Final Testing & Hardening
```

---

## 3. Engine API

The detection engine provides both an object-oriented interface and lightweight functional convenience helpers:

### 3.1 `DetectionEngine` Class

```python
class DetectionEngine:
    def __init__(
        self,
        rules: Optional[Union[RuleCollection, Sequence[DetectionRule]]] = None,
    ) -> None: ...

    @property
    def rules(self) -> Tuple[DetectionRule, ...]: ...

    def evaluate(
        self,
        timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
        correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
        rules: Optional[Union[RuleCollection, Sequence[DetectionRule]]] = None,
    ) -> DetectionResultCollection: ...
```

### 3.2 Convenience Functions

```python
def evaluate_rules(
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    rules: Union[RuleCollection, Sequence[DetectionRule]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
) -> DetectionResultCollection:
    """Evaluate multiple rules against timeline events and correlations."""

def evaluate_rule(
    rule: DetectionRule,
    timeline: Union[ReconstructedTimeline, Sequence[TimelineEvent]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
) -> DetectionResultCollection:
    """Evaluate a single rule against timeline events and correlations."""
```

---

## 4. Rule Evaluation Semantics

The detection engine strictly respects the declarative specification of V4.3 `DetectionRule` without inventing unrepresented logic:

1. **Correlation-Aware Rules (`rule.required_relationships` is populated)**:
   - The engine iterates over provided `Correlation` objects.
   - Verifies correlation relationship matches one of `rule.required_relationships`.
   - Locates underlying timeline events in the provided timeline. If any constituent event is missing, the correlation match is rejected.
   - Verifies required event types (`rule.required_event_types`) and categories (`rule.required_categories`).
   - Verifies correlation time delta against `rule.time_window_seconds`.
   - Evaluates all `rule.conditions` (logical AND).
   - If satisfied, emits a `DetectionResult` linked to the correlation and constituent events.

2. **Single-Event Rules (`rule.required_relationships` is empty, $\le 1$ event type)**:
   - Evaluated on each candidate `TimelineEvent`.
   - Filters by `rule.required_categories` and `rule.required_event_types`.
   - Evaluates all `rule.conditions` (logical AND).
   - If satisfied, emits a `DetectionResult` linked to that individual event.

3. **Multi-Event Sequence Rules (`rule.required_relationships` is empty, $\ge 2$ event types)**:
   - Evaluates candidate ordered event subsequences $(e_0, e_1, \dots, e_{N-1})$ matching `rule.required_event_types` in chronological order.
   - Filters candidate events by `rule.required_categories`.
   - Enforces time window: $\text{delta}(e_0, e_{N-1}) \le \text{rule.time\_window\_seconds}$.
   - Evaluates all `rule.conditions` (logical AND) against the sequence.
   - If satisfied, emits a `DetectionResult` covering the sequence.

---

## 5. Field Resolution & Condition Semantics

### 5.1 Field Resolution (`resolve_field_value`)

Field resolution operates deterministically:
1. Returns `_MISSING` sentinel if target is `None` or field does not exist.
2. Supports dot-notation paths (e.g. `attributes.username`, `meta.subfield`).
3. Checks direct object properties (e.g., `event_type`, `category`, `source_path`, `source_event_id`, `timestamp`).
4. Checks nested keys inside `target.attributes` (whether dict, `_FrozenDict`, or pair sequences).
5. Supports explicit positional indexing in multi-event rules (e.g., `events[0].username`, `events[1].command`, `correlation.relationship_type`).

### 5.2 Condition Operators (`ConditionOperator`)

All 9 operators defined in V4.3 are supported with explicit semantics:

| Operator | Comparison Semantics | Missing Field Behavior | Notes |
| :--- | :--- | :--- | :--- |
| `EQUALS` | `actual == expected` | Returns `False` | Strict scalar comparison; boolean vs int disallowance (`True != 1`) |
| `NOT_EQUALS` | `actual != expected` | Returns `False` | Does not match missing data |
| `CONTAINS` | `expected in actual` | Returns `False` | Substring match for strings; item membership for collections |
| `IN` | `actual in expected` | Returns `False` | Item membership within collection or substring within string |
| `GREATER_THAN` | `actual > expected` | Returns `False` | Numeric (`int`, `float`) or chronological (`datetime`) |
| `GREATER_EQUAL`| `actual >= expected`| Returns `False` | Numeric (`int`, `float`) or chronological (`datetime`) |
| `LESS_THAN` | `actual < expected` | Returns `False` | Numeric (`int`, `float`) or chronological (`datetime`) |
| `LESS_EQUAL` | `actual <= expected`| Returns `False` | Numeric (`int`, `float`) or chronological (`datetime`) |
| `EXISTS` | Presence check | `expected is False` -> `True` | `0`, `0.0`, `False`, `""` exist; `None` or `_MISSING` do not |

### 5.3 Missing-Data & Falsy Value Preservation

- Forensic data frequently contains legitimate falsy values (`0`, `0.0`, `False`, `""`, `()`). The engine preserves these values explicitly and never conflates them with missing fields.
- Non-existent fields resolve to the `_MISSING` sentinel, which fails all operators except `EXISTS(value=False)`.

---

## 6. Correlation Usage & Temporal Semantics

- **Separation of Concerns**: V4.2 discovers correlation relationships; V4.4 evaluates rules against those discoveries. V4.4 never re-runs correlation discovery internally.
- **Time Window**: Evaluated as $\text{delta} \le \text{window\_seconds}$ with inclusive boundary equality, reusing `compute_timestamp_delta`.
- **Timestamp Class Partitioning**:
  - Aware + Aware: Compared by exact UTC instant across differing timezone offsets.
  - Naive + Naive: Compared directly.
  - Aware + Naive: Mismatch rejected without fabricating synthetic timezones.
  - Missing Timestamps: Preserved as `None`; no synthetic timestamps fabricated.

---

## 7. DetectionResult Model

`DetectionResult` is a frozen, deeply immutable dataclass:

| Field | Type | Description |
| :--- | :--- | :--- |
| `detection_id` | `str` | Deterministic identifier (`DET-<UUIDv5>`) |
| `rule_id` | `str` | Identifier of the matching rule (`RULE-<UUIDv5>`) |
| `rule_name` | `str` | Human-readable name of matching rule |
| `matched` | `bool` | Boolean match indicator (defaults to `True`) |
| `matched_event_ids` | `Tuple[str, ...]` | Immutable tuple of underlying timeline event IDs |
| `matched_source_event_ids` | `Tuple[str, ...]` | Source log/artifact event IDs (e.g. `AUTH-001`) |
| `matched_source_artifact_ids` | `Tuple[str, ...]` | Source artifact identifiers (e.g. `ART-AUTH-LOG`) |
| `matched_correlation_ids` | `Tuple[str, ...]` | Supporting correlation IDs (if correlation-aware) |
| `start_timestamp` | `Optional[datetime]` | Start timestamp of observed match |
| `end_timestamp` | `Optional[datetime]` | End timestamp of observed match |
| `time_delta_seconds` | `Optional[float]` | Observed duration between start and end |
| `explanation` | `str` | Factual, non-speculative narrative |
| `attributes` | `_FrozenDict` | Immutable key-value attributes |

### 7.1 Deterministic Identity (`compute_deterministic_detection_id`)

Detection IDs are generated via RFC 4122 UUIDv5 under the canonical namespace:
```
FORENSIX_V4_DETECTION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v4/detection"
)
```
Key components:
$$\text{key} = \text{rule\_id} : \text{sorted(matched\_event\_ids)} [: \text{sorted(matched\_correlation\_ids)}]$$
Format: `DET-<UUIDv5>`

### 7.2 Deterministic Ordering (`detection_sort_key`)

Detections in a `DetectionResultCollection` are deterministically ordered:
1. Aware start timestamps (UTC instant)
2. Naive start timestamps (naive datetime)
3. Missing start timestamps
4. Rule ID (lexicographical)
5. First event ID (lexicographical)
6. First correlation ID (lexicographical)
7. Detection ID (lexicographical)

### 7.3 Duplicate Prevention

Detections matching identical `(rule_id, event_ids, correlation_ids)` are deduplicated, while legitimate independent matches across distinct events or rules are strictly preserved.

---

## 8. Non-Speculative Language Enforcement

To maintain strict scientific and forensic objectivity, explanations are validated against `DISALLOWED_SPECULATIVE_TERMS`:
- Prohibits: "confirmed attack", "attacker confirmed", "system compromised", "malware confirmed", "intrusion confirmed", etc.
- Descriptions must describe observed factual evidence (e.g. "An SSH login followed by privileged sudo execution was observed for the same identity within 300 seconds").

---

## 9. Limitations & Explicit Scope Boundaries

- **Milestone Boundary**: V4.4 implements ONLY the Detection Engine. It does NOT include:
  - V4.5 Initial Detection Rules (production detection catalog)
  - V4.6 Detection Reporting (JSON/HTML detection reports)
  - V4.7 CLI & Triage Integration
  - V4.8 Final Testing & Hardening
- **No Machine Learning or AI**: Evaluation is 100% deterministic and rule-based.
- **Evidence Safety**: Read-only operations only. Subprocess execution, filesystem mutations, and network requests are strictly prohibited.
