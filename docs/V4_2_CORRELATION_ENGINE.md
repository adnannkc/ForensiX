# ForensiX V4.2 — Correlation Engine

This document specifies the architecture, implementation, and forensic principles of the **Correlation Engine (`CorrelationEngine`, `CorrelationConfig`, `correlate_events`)** introduced in **ForensiX V4.2 (Event Correlation & Rule-Based Detection)**.

---

## 1. Purpose

The V4.2 Correlation Engine evaluates existing chronological V3 timeline events (`TimelineEvent` / `ReconstructedTimeline`) to discover explicit, deterministic relationships between them and instantiate immutable V4.1 `Correlation` objects.

Key objectives:
- **Discover explicit relationships**: Evaluate factual criteria connecting events across time, identity, source, path, session, and privilege escalation.
- **Strictly factual representation**: Correlation is an analytical observation, **NOT proof of compromise**.
- **Evidence safety & zero side effects**: Evidence files and input timeline events are read-only and deeply immutable.
- **Deterministic & reproducible**: Repeated runs over identical inputs yield identical correlation IDs, counts, contents, and ordering.

---

## 2. Architecture & Data Flow

The engine operates on top of V3 timeline events and feeds into V4.1 correlation models:

```
Evidence Files
      ↓
V1/V2 Host Forensics
      ↓
V3 ReconstructedTimeline / TimelineEvent sequence
      ↓
V4.2 Correlation Engine (CorrelationEngine, CorrelationConfig)  <-- [IMPLEMENTED]
      ↓
V4.1 Correlation Objects & CorrelationCollection               <-- [IMPLEMENTED]
      ↓
V4.3 Rule Model                                                <-- [PLANNED]
      ↓
V4.4 Detection Engine                                          <-- [PLANNED]
```

---

## 3. Codebase Components Reused

V4.2 builds directly upon existing V1–V3 and V4.1 components without duplicating parsing or modeling logic:
- **V3 `TimelineEvent`**: Observational event input representation.
- **V3 `ReconstructedTimeline`**: Chronologically ordered, deduplicated input collection.
- **V3 `TimelineCategory`**: Categories inspected during authentication/privilege checks.
- **V3 Timestamp Normalizer & Semantics**: UTC instant comparisons for aware timestamps; calendar comparisons for naive timestamps; strict awareness mismatch handling.
- **V2 `normalize_relative_path`** (`forensix.identifier`): Standard POSIX path normalization for `SAME_PATH`.
- **V4.1 `Correlation`**: Frozen dataclass representation for discovered relationships.
- **V4.1 `CorrelationCollection`**: Aggregate collection holding discovered correlations.
- **V4.1 `CorrelationType`**: Explicit 6-type relationship enumeration.
- **V4.1 `create_correlation`**: Factory function ensuring deep immutability and RFC 4122 UUIDv5 identity.

---

## 4. New Components Introduced

- **`CorrelationConfig`**: Immutable configuration dataclass defining `time_window_seconds` (default: 300.0s), `relationship_types`, and optional `max_correlations`.
- **`CorrelationEngine`**: Discovery engine evaluating pairs of events against explicit relationship conditions.
- **`correlate_events`**: Functional convenience entry point.
- **Helper Functions**:
  - `compute_timestamp_delta`: Safe timestamp interval calculation adhering to V3 semantics.
  - `is_chronologically_ordered`: Strict order checking for aware/naive timestamps.
  - `extract_user_identity`: Extract explicit user/username attributes without guessing.
  - `extract_source_identity`: Extract explicit IP/hostname attributes without guessing.
  - `extract_path_identity`: Extract and normalize explicit path attributes or `source_path`.
  - `extract_session_identity`: Extract explicit session IDs without guessing.
  - `correlation_sort_key`: Deterministic multi-attribute comparator for stable output ordering.

---

## 5. Supported Relationship Types & Conditions

The engine discovers exactly the 6 relationship types defined in V4.1:

| Relationship Type | Discovery Condition | Temporal Window Enforced |
| :--- | :--- | :--- |
| `TEMPORAL` | Both events have compatible timestamps and `delta <= window_seconds`. | Yes |
| `SAME_USER` | Both events explicitly share identical user/account identity (`user1 == user2`). | Yes (if timestamps present) |
| `SAME_SOURCE` | Both events explicitly share identical source identity (`source1 == source2`). | Yes (if timestamps present) |
| `SAME_PATH` | Both events reference identical normalized paths (`path1 == path2`). | Yes (if timestamps present) |
| `SAME_SESSION` | Both events explicitly share identical session identifiers (`sess1 == sess2`). | Yes (if timestamps present) |
| `AUTHENTICATION_PRIVILEGE` | (1) One auth event, (2) One privilege event, (3) Auth precedes privilege, (4) User compatible, (5) `delta <= window_seconds`. | Yes |

---

## 6. Time-Window Semantics & Boundary Behavior

- **Window Condition**: The boundary matching condition is **inclusive**:
  $$\text{delta} \le \text{window\_seconds}$$
  - An event occurring at exactly $\text{delta} = 300.0\text{s}$ with a 300.0s window **matches**.
  - An event occurring at $\text{delta} = 300.1\text{s}$ with a 300.0s window **does not match**.
- **Configuration**: Default window is 300.0 seconds (5 minutes). Negative values are rejected with `ValueError`. Non-numeric types are rejected with `TypeError`.

---

## 7. Timestamp Behavior & Awareness Handling

Adheres strictly to ForensiX V3 timestamp rules:
- **Aware + Aware**: Converted to UTC instants and compared with sub-millisecond precision.
- **Naive + Naive**: Compared directly without synthetic timezone assignment.
- **Aware + Naive Mismatch**: `compute_timestamp_delta` returns `None`. The engine does **NOT** raise an unhandled exception and does **NOT** assume a local timezone. Temporal relationships cannot be formed across awareness mismatches.
- **Missing Timestamps (`None`)**: Events with missing timestamps cannot satisfy temporal delta conditions. They may still participate in non-temporal relationships (`SAME_USER`, `SAME_PATH`, etc.) if identity matches.

---

## 8. Deterministic Behavior & Stable Ordering

- **Deterministic Identity**: Each discovered correlation receives an RFC 4122 UUIDv5 ID computed from the relationship type and lexicographically sorted timeline event IDs.
- **Deterministic Output Order**: Discovered correlations are sorted using `correlation_sort_key`:
  1. Timestamp class (Aware $\rightarrow$ Naive $\rightarrow$ Missing).
  2. Start timestamp instant.
  3. Relationship type value (lexicographical).
  4. First event ID (lexicographical).
  5. Second event ID (lexicographical).
  6. Correlation ID (lexicographical).
- **Repeated Execution**: Identical inputs always produce identical correlation collections and IDs across multiple runs and environments.

---

## 9. Duplicate Prevention vs. Legitimate Multi-Type Discovery

- **Duplicate Prevention**: The engine tracks `(relationship_type, (event_id_a, event_id_b))` pairs to ensure the same relationship type is never reported twice for the same pair of events.
- **Multi-Type Preservation**: Legitimate distinct relationship types between the same two events (e.g. `TEMPORAL`, `SAME_USER`, and `AUTHENTICATION_PRIVILEGE`) are all independently discovered and preserved in the output collection.

---

## 10. Immutability & Provenance

- **Input Immutability**: Input `TimelineEvent`s and `ReconstructedTimeline` objects are never mutated.
- **Output Immutability**: All returned objects are frozen dataclasses (`CorrelationCollection`, `Correlation`, `_FrozenDict`).
- **Provenance Preservation**: All discovered correlations retain:
  - `event_ids`: IDs of involved timeline events (`TIMELINE-...`).
  - `source_event_ids`: Originating V2 source event IDs (`AUTH-...`, `LOG-...`, `EVT-...`).
  - `source_artifact_ids`: Originating V2 source artifact IDs (`ART-...`).

---

## 11. Testing & Validation

The test suite in `tests/test_correlation_engine.py` covers 33 distinct scenarios:
- Empty timeline, single event, and unrelated events.
- Positive and negative matches for all 6 relationship types.
- Exact time-window boundaries (just inside, exact, just outside).
- Order inversion and user mismatch in `AUTHENTICATION_PRIVILEGE`.
- Missing attributes and missing timestamps.
- Aware, naive, and awareness-mismatch timestamp behavior.
- Duplicate prevention and multi-type discovery.
- Deep input/output immutability and provenance fidelity.
- Deterministic repeated execution and stable ordering.
- JSON serialization compatibility and regression tests against V3 and V4.1.

---

## 12. Limitations & What V4.2 Does NOT Implement

In strict compliance with milestone boundaries:
- **No detection rules or rule model**: Belongs to V4.3 (`RuleModel`) and V4.4 (`DetectionEngine`).
- **No automated attack chain or compromise verdicts**: Correlation is purely observational.
- **No reporting modifications**: Reporting integration occurs in V4.6.
- **No CLI modifications**: CLI/triage integration occurs in V4.7.
- **No network/PCAP or memory forensics**: Out of scope for ForensiX V4.

---

## 13. Milestone Status

| Component | Status | Notes |
| :--- | :--- | :--- |
| **V4.1 Correlation Model** | **IMPLEMENTED** | Immutable `Correlation`, `CorrelationCollection`, and deterministic IDs. |
| **V4.2 Correlation Engine** | **IMPLEMENTED** | `CorrelationEngine`, `CorrelationConfig`, `correlate_events`. |
| **V4.3 Rule Model** | **PLANNED** | Declarative detection rule specification. |
| **V4.4 Detection Engine** | **PLANNED** | Rule evaluation against timeline events and correlations. |
| **V4.5 Initial Detection Rules** | **PLANNED** | Factual detection rules. |
| **V4.6 Reporting Integration** | **PLANNED** | Additive JSON and HTML reporting. |
| **V4.7 CLI / Triage Integration**| **PLANNED** | Command line options and triage orchestration. |
| **V4.8 Final Hardening** | **PLANNED** | Comprehensive end-to-end verification. |
