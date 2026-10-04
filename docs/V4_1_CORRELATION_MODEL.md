# ForensiX V4.1 — Event Correlation Model

This document specifies the foundational **Correlation Model (`Correlation`, `CorrelationType`, `CorrelationCollection`)** introduced in **ForensiX V4.1 (Event Correlation & Rule-Based Detection)**.

---

## 1. Purpose

The purpose of the V4.1 Correlation Model is to provide a strongly typed, deeply immutable representation of explicit, deterministic relationships between discrete V3 timeline events (`TimelineEvent`).

ForensiX separates raw evidence facts (V1/V2), chronological observation (V3), and relationship analysis (V4). The Correlation Model bridges timeline reconstruction and subsequent rule-based detection by:
1. Identifying and representing explicit relationships between timeline events.
2. Preserving complete forensic provenance back to V3 timeline event IDs, V2 source event IDs, and V2 source artifact IDs.
3. Enforcing factual, explainable language while strictly rejecting speculative attack labels.
4. Guaranteeing deterministic, reproducible identity and serialization.

---

## 2. Architecture & Layering

The correlation model builds strictly ON TOP OF V3 timeline events without altering or duplicating V2/V3 parsing logic:

```
Evidence
    ↓
V1 Evidence Foundation (hasher, evidence)
    ↓
V2 Host/System Forensics (artifacts, logs, auth, accounts, persistence, unified)
    ↓
V3 Timeline Events (TimelineEvent, ReconstructedTimeline)
    ↓
V4.1 Correlation Model (Correlation, CorrelationType, CorrelationCollection)  <-- [IMPLEMENTED]
    ↓
V4.2 Correlation Engine                                                     <-- [PLANNED]
    ↓
V4.3 Rule Model                                                             <-- [PLANNED]
    ↓
V4.4 Detection Engine                                                       <-- [PLANNED]
    ↓
V4.5 Initial Detection Rules                                                <-- [PLANNED]
    ↓
V4.6 Reporting / Presentation Integration                                   <-- [PLANNED]
    ↓
V4.7 CLI / Triage Integration                                               <-- [PLANNED]
```

---

## 3. Supported Relationship Types

The relationship model defines an explicit enum `CorrelationType` (also aliased as `RelationshipType`):

| Relationship Type | Enum Value | Forensic Description |
| :--- | :--- | :--- |
| `TEMPORAL` | `"TEMPORAL"` | Events occurring within a defined temporal window. |
| `SAME_USER` | `"SAME_USER"` | Events sharing the same user/account identity. |
| `SAME_SOURCE` | `"SAME_SOURCE"` | Events originating from the same source (IP, hostname, service). |
| `SAME_PATH` | `"SAME_PATH"` | Events referencing the same filesystem path or resource. |
| `SAME_SESSION` | `"SAME_SESSION"` | Events occurring within the same logon/terminal session. |
| `AUTHENTICATION_PRIVILEGE` | `"AUTHENTICATION_PRIVILEGE"` | Authentication activity associated with subsequent privilege activity. |

Uncontrolled free-form relationship strings and speculative categories are strictly rejected.

---

## 4. Model Specification: `Correlation`

`Correlation` is a frozen dataclass with complete field validation:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `correlation_id` | `str` | Yes | Identifier formatted as `CORR-<UUIDv4/v5>`. Auto-computed deterministically if omitted. |
| `relationship_type` | `CorrelationType` | Yes | Validated relationship type enum. |
| `event_ids` | `Tuple[str, ...]` | Yes | Tuple of at least 2 distinct timeline event IDs (`TIMELINE-...`). |
| `source_event_ids` | `Tuple[str, ...]` | No | Tuple of originating V2 source event IDs (`AUTH-...`, `LOG-...`, `EVT-...`). |
| `source_artifact_ids` | `Tuple[str, ...]` | No | Tuple of originating V2 source artifact IDs (`ART-...`). |
| `start_timestamp` | `Optional[datetime]` | No | Earliest timestamp among correlated events (typed datetime or None). |
| `end_timestamp` | `Optional[datetime]` | No | Latest timestamp among correlated events (typed datetime or None). |
| `time_delta_seconds` | `Optional[float]` | No | Time interval in seconds between start and end (falsy `0.0` is preserved). |
| `description` | `str` | Yes | Factual, explainable description of the relationship. |
| `attributes` | `Tuple[Tuple[str, Any], ...]` | No | Deeply frozen key-value pairs (`_FrozenDict`) containing structured metadata. |

### Property Aliases
- `timeline_event_ids`: Alias for `event_ids`.
- `explanation`: Alias for `description`.
- `delta_seconds`: Alias for `time_delta_seconds`.

---

## 5. Aggregate Model: `CorrelationCollection`

`CorrelationCollection` is a frozen dataclass representing an aggregate set of correlations:
- `correlations: Tuple[Correlation, ...]`
- `total_correlations: int`
- `relationship_counts: Tuple[Tuple[str, int], ...]`
- Methods: `__len__`, `__iter__`, `__getitem__`, `__contains__`, `summary`, `to_dict()`

---

## 6. Forensic Principles & Assumptions

1. **Correlation is NOT proof of compromise**:
   - A correlation indicates an observed relationship (e.g. user `alice` logged in and then ran `sudo`). It does not assert malicious intent or system compromise.
2. **Rejection of Speculative Language**:
   - The model prohibits phrases such as `confirmed attack`, `attacker confirmed`, `system compromised`, `malware confirmed`, and `intrusion confirmed`.
3. **Evidence Immutability**:
   - The model never modifies evidence files or V3 timeline event structures.
4. **Subprocess and Network Isolation**:
   - Zero subprocess execution and zero network access.
5. **Preservation of Non-Fabricated Provenance**:
   - `source_event_ids` and `source_artifact_ids` are retained only when present in evidence; no fake IDs are ever generated.

---

## 7. Deterministic Identity Generation

`Correlation` IDs are deterministic by default using RFC 4122 UUIDv5 within a dedicated ForensiX namespace:
```python
FORENSIX_V4_CORRELATION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v4/correlation"
)
```

The canonical key is constructed from:
- Normalized relationship type string (`rel_type`)
- Lexicographically sorted timeline event IDs (`','.join(sorted_ids)`)
- Optional discriminator string (if provided)

```python
canonical_key = f"{rel_str}:{','.join(sorted_ids)}"
correlation_id = f"CORR-{uuid.uuid5(FORENSIX_V4_CORRELATION_NAMESPACE, canonical_key)}"
```

Guarantees:
- Independent runs processing the same timeline events produce identical `correlation_id` values.
- Event order reversal (e.g. `[E1, E2]` vs `[E2, E1]`) produces identical IDs.
- Existing V2/V3 identifiers are preserved rather than modified.

---

## 8. Timestamp Semantics & Awareness Handling

- **Aware Timestamps**: When all events share aware timestamps (e.g. UTC), `start_timestamp`, `end_timestamp`, and `time_delta_seconds` are accurately calculated.
- **Naive Timestamps**: When all events share naive timestamps, deltas are calculated directly without assuming a local or UTC timezone.
- **Awareness Mismatches**: When events have mixed awareness (one aware, one naive), ForensiX does **NOT** raise a `TypeError` and does **NOT** guess a timezone. `time_delta_seconds` remains `None` to prevent silent misinterpretation.
- **Falsy Values**: `time_delta_seconds = 0.0` is strictly preserved and not treated as `None`.

---

## 9. Code Examples

### Constructing via Factory Function
```python
from datetime import datetime, timezone
from forensix.correlation_models import CorrelationType, create_correlation
from forensix.timeline_models import create_timeline_event, TimelineCategory

ev1 = create_timeline_event(
    category=TimelineCategory.AUTHENTICATION,
    event_type="ssh_login_success",
    description="Accepted publickey for alice",
    timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc),
    source_event_id="AUTH-100",
    source_artifact_id="ART-100",
)
ev2 = create_timeline_event(
    category=TimelineCategory.AUTHENTICATION,
    event_type="sudo_command",
    description="COMMAND=/bin/cat /etc/shadow",
    timestamp=datetime(2026, 4, 1, 10, 2, 0, tzinfo=timezone.utc),
    source_event_id="AUTH-200",
    source_artifact_id="ART-100",
)

corr = create_correlation(
    relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
    event_ids=[ev1, ev2],
    description="Observed SSH authentication followed by sudo activity for user alice",
    attributes={"user": "alice", "command": "/bin/cat /etc/shadow"},
)

# Output is deterministic and immutable
print(corr.correlation_id)  # CORR-<UUIDv5>
print(corr.time_delta_seconds)  # 120.0
print(corr.source_event_ids)  # ('AUTH-100', 'AUTH-200')
```

---

## 10. Milestone Status

| Component | Status | Notes |
| :--- | :--- | :--- |
| **V4.1 Correlation Model** | **IMPLEMENTED** | `Correlation`, `CorrelationType`, `CorrelationCollection`, deterministic ID, tests. |
| **V4.2 Correlation Engine** | **PLANNED** | Configurable time-window correlation engine. |
| **V4.3 Rule Model** | **PLANNED** | Declarative, explainable detection rule model. |
| **V4.4 Detection Engine** | **PLANNED** | Evaluation engine for detection rules. |
| **V4.5 Initial Detection Rules** | **PLANNED** | 4 initial factual detection patterns. |
| **V4.6 Reporting** | **PLANNED** | Additive JSON/HTML reporting for correlations & detections. |
| **V4.7 CLI/Triage Integration** | **PLANNED** | CLI command and pipeline integration. |
| **V4.8 Final Testing & Hardening** | **PLANNED** | Full end-to-end verification and evidence hashing checks. |
