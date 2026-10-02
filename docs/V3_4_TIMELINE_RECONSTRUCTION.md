# ForensiX V3.4 — Timeline Reconstruction, Ordering & Deduplication

This document describes the **Timeline Reconstruction Engine (`timeline_reconstruction`)** introduced in **ForensiX V3.4 (Timeline Reconstruction)**.

---

## 1. Purpose

In digital forensic investigations, evidence is gathered across diverse subsystems (filesystem metadata, logs, authentication records, etc.) and translated into discrete `TimelineEvent` records by the V3.3 Artifact Adapter layer.

However, individual adapters emit events in arbitrary or source-specific sequences. Disparate sources present:
- Out-of-order event streams.
- Mixed timestamp representations (UTC-aware offsets, timezone-naive datetimes, and yearless or missing timestamps).
- Duplicate observations resulting from overlapping evidence sources or multiple adapter runs.

**ForensiX V3.4 solves this by providing a deterministic, non-interpretive reconstruction layer that:**
1. Validates input `TimelineEvent` collections.
2. Orders events chronologically using strict, type-safe timestamp partitioning and stable secondary tie-breaking.
3. Conservatively deduplicates exact factual observations.
4. Packages the result into an immutable `ReconstructedTimeline` container.

---

## 2. Architecture

```text
Forensic Artifacts
        ↓
V3.3 Artifact Adapters
        ↓
TimelineEvent objects (Unordered, possibly duplicate)
        ↓
V3.4 Timeline Reconstruction (reconstruct_timeline)
        ↓
Deterministic Ordering (TimestampClass partitioning + secondary tie-breaking)
        ↓
Conservative Deduplication (Factual fingerprint matching)
        ↓
ReconstructedTimeline (Immutable chronological sequence)
```

---

## 3. Input Specification

The reconstruction layer accepts:
- A sequence of valid `TimelineEvent` instances (`Sequence[TimelineEvent]`).
- Or an existing `ReconstructedTimeline` (for idempotent re-processing).

Validation guarantees:
- If `None` is provided, a `ValueError` is raised.
- If any element is not a `TimelineEvent`, an explicit `TypeError` is raised.
- Empty collections are accepted and produce an empty `ReconstructedTimeline`.
- Input sequence order does **not** influence final chronological ordering.

---

## 4. Deterministic Ordering Policy

To avoid Python runtime comparison errors between offset-aware and offset-naive datetimes, and to avoid fabricating assumptions about unknown timezones, ForensiX V3.4 implements an explicit **Three-Class Partitioning** strategy:

```text
TimestampClass.AWARE (0)  →  TimestampClass.NAIVE (1)  →  TimestampClass.MISSING (2)
```

### 1. Timezone-Aware Timestamps (`TimestampClass.AWARE`)
- Events with explicit timezone offsets (e.g. `Z`, `+05:30`, `-04:00`).
- Normalized to UTC instant (`event.timestamp.astimezone(timezone.utc)`).
- Timezone representations denoting the exact same instant (e.g., `2026-09-30T14:30:00+05:30` and `2026-09-30T09:00:00Z`) occupy the exact same chronological instant.
- Ordered strictly forward chronologically.

### 2. Timezone-Naive Timestamps (`TimestampClass.NAIVE`)
- Events with calendar date and time but no timezone reference (`event.timestamp.tzinfo is None`).
- **Forensic Principle**: A naive timestamp must remain naive. ForensiX does **not** assume UTC, the local investigator timezone, or the evidence host timezone.
- Ordered chronologically relative to other naive timestamps by naive datetime values.
- Partitioned after aware events to prevent false equivalence or runtime comparison errors.

### 3. Missing Timestamps (`TimestampClass.MISSING`)
- Events where no calendar datetime could be resolved (e.g., yearless BSD syslog lines where `timestamp is None`).
- ForensiX does **not** assign today's date, collection time, or any fabricated timestamp.
- Partitioned together and ordered deterministically by provenance.

---

## 5. Secondary Ordering & Tie-Breaking Rules

When two or more events share identical timestamps (or when timestamps are missing), ForensiX breaks ties using a deterministic, multi-attribute key based solely on immutable event facts:

```python
timeline_sort_key = (
    timestamp_class.value,       # 0 = AWARE, 1 = NAIVE, 2 = MISSING
    normalized_instant_key,      # UTC datetime for aware, naive datetime for naive, 0 for missing
    event.source_path or "",     # Lexicographical source path
    event.source_line or -1,     # 1-indexed source line (-1 for unindexed/file-level)
    event.source_artifact_id or "",
    event.source_event_id or "",
    event.event_type,            # Factual classification string
    event.description,           # Human-readable description
    event.event_id,              # Final unique tie-breaker
)
```

This ensures:
- 100% deterministic, reproducible sorting across platforms and executions.
- Zero reliance on object memory addresses, current execution time, or random seeds.

---

## 6. Conservative Deduplication Policy

ForensiX V3.4 deduplicates **true duplicate observations** while strictly preserving distinct evidence.

### Duplicate Identity Rule
Two events are considered duplicates if and only if all factual fields match exactly:

$$\text{Event}_1 \equiv \text{Event}_2 \iff \text{Fingerprint}(\text{Event}_1) = \text{Fingerprint}(\text{Event}_2)$$

Where the factual fingerprint consists of:
1. Normalized timestamp instant (UTC datetime, naive datetime, or None)
2. Raw timestamp string (`raw_timestamp`)
3. Event category (`category`)
4. Event type (`event_type`)
5. Description (`description`)
6. Source path (`source_path`)
7. Source line number (`source_line`)
8. Source artifact ID (`source_artifact_id`)
9. Source event ID (`source_event_id`)
10. Raw unparsed line (`raw_data`)
11. Frozen attributes (`attributes`)

### Event ID Handling
`event_id` is intentionally excluded from the duplicate fingerprint. When evidence files are processed by multiple adapter passes, different random UUIDs (`TIMELINE-<UUIDv4>`) may be assigned to the exact same observation. If all factual fields match, the observation is identified as a duplicate and only the first occurrence in canonical sort order is preserved.

### Distinct Events Preserved
Events are **never** merged if they differ in:
- Timestamps or raw timestamps
- Source paths (different files)
- Source line numbers (different lines in the same log)
- Source artifact IDs or source event IDs
- Event types or descriptions
- Contextual attributes or raw evidence lines

---

## 7. Immutability and Idempotence

- **Immutability**: Source `TimelineEvent` objects are never mutated. `ReconstructedTimeline` returns references to the original immutable event instances.
- **Idempotence**:
  $$\text{reconstruct}(\text{reconstruct}(\text{events})) = \text{reconstruct}(\text{events})$$
  Reconstructing an already reconstructed timeline produces an identical result without side effects.
- **Source List Safety**: Passing a mutable list to `reconstruct_timeline` does not alter the caller's list.

---

## 8. Safety Boundaries

In strict accordance with the milestone scope, **ForensiX V3.4 does NOT implement**:
- **Threat Detection or Risk Scoring**: No malicious/benign scoring, severity levels, or anomaly detection.
- **Causality or Correlation**: Does not infer attack paths, lateral movement, or causal links between consecutive events.
- **Timeline Querying & Filtering**: Filtering by date ranges, categories, or keywords belongs to **V3.5**.
- **Timeline Reporting**: HTML, CSV, and JSON report generation belongs to **V3.6**.
- **CLI Integration**: Public CLI commands belong to **V3.7**.

---

## 9. Future Milestones

Reconstructed timelines produced by V3.4 serve as the chronological foundation for:
- **V3.5 (Timeline Querying & Filtering)**: Querying across event types, timestamps, categories, and entities.
- **V3.6 (Timeline Reporting)**: Rendering structured timeline views in triage reports.
- **V3.7 (CLI Integration)**: Exposing timeline workflows in the ForensiX CLI.
- **V3.8 (Determinism & Safety Verification)**: Final cross-version validation across all V3 milestones.
