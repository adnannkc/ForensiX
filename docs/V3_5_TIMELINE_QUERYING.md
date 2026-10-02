# ForensiX V3.5 — Timeline Querying

## Purpose

The **Timeline Querying** subsystem (`forensix.timeline_query`) provides a safe, deterministic, immutable, and strictly factual querying layer over an already reconstructed forensic timeline (`ReconstructedTimeline` from V3.4).

Digital forensic investigations require querying observed historical events without altering the chronological sequence, mutating underlying evidence, or introducing speculative conclusions. Timeline querying functions strictly as a data access and filtering mechanism, enabling examiners to narrow their scope across observed criteria (such as time windows, event classifications, source files, and tracking identifiers) with forensic rigor.

---

## Input

The primary input to the query engine is:

* `ReconstructedTimeline`: An immutable timeline produced by V3.4 `reconstruct_timeline()`.
* Alternatively, any immutable sequence of `TimelineEvent` objects (or an existing `TimelineQueryResult` for chaining queries).

Querying never re-parses raw evidence files and performs zero filesystem or network I/O.

---

## Supported Filters

Queries are specified via the immutable `TimelineQuery` dataclass or via keyword arguments to `query_timeline(timeline, **kwargs)`.

| Filter Field | Type | Matching Semantics | Description |
| :--- | :--- | :--- | :--- |
| `start` | `datetime`, `str`, or `None` | Inclusive lower bound (`>=`) | Earliest event timestamp. Strings are validated via V3.2 normalizer. |
| `end` | `datetime`, `str`, or `None` | Inclusive upper bound (`<=`) | Latest event timestamp. Strings are validated via V3.2 normalizer. |
| `category` | `TimelineCategory`, `str`, or `None` | Exact enum value match | Category filter (`FILESYSTEM`, `LOG`, `AUTHENTICATION`, `ACCOUNT`, `PERSISTENCE`). |
| `event_type` | `str` or `None` | Exact string match | Specific event type (e.g., `ssh_login`, `sudo_execution`). Non-empty string. |
| `source_path` | `str`, `Path`, or `None` | Exact string match | Path of the evidence source file (e.g., `/var/log/auth.log`). |
| `source_artifact_id`| `str` or `None` | Exact string match | Identifier of the parent artifact record (e.g., `ART-101`). |
| `source_event_id` | `str` or `None` | Exact string match | Identifier of the underlying specialized event record (e.g., `EVT-202`). |
| `text` | `str` or `None` | Substring inclusion | Substring search across `description`, `raw_data`, `event_type`, and attributes. |
| `case_sensitive` | `bool` (default: `False`) | Case sensitivity toggle | If `False`, substring matching is case-insensitive. |

---

## Combination Semantics (Logical AND)

All supplied non-`None` filters are evaluated using **logical AND**. 

An event is included in the query result if and only if it satisfies **all** specified filter criteria. If any filter does not match, the event is excluded:

```text
matches = (
    category_matches
    AND event_type_matches
    AND source_path_matches
    AND source_artifact_matches
    AND source_event_matches
    AND timestamp_range_matches
    AND text_matches
)
```

No boolean OR groupings or complex query expressions are introduced in V3.5 to preserve strict predictability and forensic clarity.

---

## Timestamp Semantics

Forensic timelines frequently combine disparate log sources, some of which contain timezone offsets, while others contain naive wall-clock time or no timestamp at all (e.g., yearless logs). V3.5 follows strict rules to prevent forensic errors:

### 1. Timezone-Aware Timestamps
When querying with timezone-aware boundaries (`tzinfo is not None`), comparisons against timezone-aware events are evaluated using normalized instant-in-time semantics (converting both to UTC for comparison).

### 2. Timezone-Naive Timestamps
When querying with timezone-naive boundaries (`tzinfo is None`), comparisons against timezone-naive events are evaluated directly as wall-clock values without timezone assumptions.

### 3. Missing Timestamps (`timestamp=None`)
Events lacking normalized timestamps (such as yearless syslog events) **never match** timestamp range filters (`start` or `end`). However, they remain fully accessible and queryable via non-time filters (such as `category`, `source_path`, or `text`).

### 4. Incompatible Timezone Awareness
To maintain absolute forensic integrity, the engine **never assumes or fabricates timezones** (it will never guess local time, system time, or UTC for naive records):
* Query construction rejects mixed awareness between `start` and `end` (e.g., an aware `start` with a naive `end` raises `ValueError`).
* During matching, an aware query filter against a naive event (or a naive query filter against an aware event) is treated safely as **non-matching** (`False`).

---

## Ordering Preservation

The query engine **does not re-sort or reorder events**.

Input events from a `ReconstructedTimeline` are already sorted into canonical V3.4 chronological order:
1. Timezone-aware events (ordered by UTC instant, then tie-broken deterministically)
2. Timezone-naive events (ordered by naive datetime, then tie-broken deterministically)
3. Missing timestamp events (ordered deterministically by category, source, artifact, event ID)

Query results retain this exact canonical sequence:

```text
ReconstructedTimeline (V3.4 Canonical Order)
                     ↓
          query_timeline()
                     ↓
  TimelineQueryResult (Preserved Canonical Order)
```

---

## Immutability & Determinism

* **Deep Immutability**: All returned results are encapsulated in `TimelineQueryResult`, where `events` is stored as an immutable `tuple`. The original `ReconstructedTimeline` and its underlying `TimelineEvent` instances are never modified.
* **Deterministic Execution**: Given identical inputs and query specifications, `query_timeline()` guarantees identical results with zero variance across invocations.

---

## Scope Boundary

In accordance with ForensiX architectural separation of concerns, **V3.5 does NOT perform**:

* Threat detection, intrusion analysis, or anomaly scoring
* Multi-event correlation or automated attack graph reconstruction
* Risk scoring, confidence scoring, or severity ranking
* Speculative or automated incident conclusions
* Report generation (deferred to V3.6)
* Command-line interface integration (deferred to V3.7)

V3.5 is strictly an objective, factual data querying layer.

---

## Python API Example

```python
from datetime import datetime, timezone
from forensix.timeline_models import TimelineCategory
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.timeline_query import TimelineQuery, query_timeline

# 1. Timeline is already reconstructed using V3.4
timeline = reconstruct_timeline(events)

# 2. Construct a factual query
query = TimelineQuery(
    start=datetime(2023, 5, 1, 9, 0, 0, tzinfo=timezone.utc),
    end=datetime(2023, 5, 1, 17, 0, 0, tzinfo=timezone.utc),
    category=TimelineCategory.AUTHENTICATION,
    event_type="ssh_login",
    source_path="/var/log/auth.log",
)

# 3. Execute the query
result = query_timeline(timeline, query)

# 4. Access matched events in preserved canonical order
print(f"Matched {result.total_events} events:")
for event in result.events:
    print(f"[{event.timestamp.isoformat()}] {event.description} (source={event.source_path})")
```
