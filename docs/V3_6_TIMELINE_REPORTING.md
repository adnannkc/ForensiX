# ForensiX V3.6 — Timeline Reporting

## Purpose

The **Timeline Reporting** subsystem (`forensix.timeline_reporting`) provides structured, deterministic, and immutable presentation of factual timeline events. It transforms chronological forensic data from reconstructed timelines (`ReconstructedTimeline` from V3.4) and filtered query results (`TimelineQueryResult` from V3.5) into:

1. **Machine-Readable JSON**: Standardized, predictable UTF-8 JSON representations suitable for automated parsing, archival, and downstream ingestion.
2. **Human-Readable HTML**: Standalone, securely escaped HTML5 forensic reports with an embedded dark-theme stylesheet, interactive detail accordions, and metric cards for human investigators.

Reporting operates strictly on already reconstructed or queried timeline events. It performs zero evidence discovery, introduces no speculative conclusions, and preserves complete forensic provenance.

---

## Input Types

The reporting API accepts:

* `ReconstructedTimeline`: Canonical timeline produced by V3.4 `reconstruct_timeline()`.
* `TimelineQueryResult`: Filtered subset produced by V3.5 `query_timeline()`. When reporting a query result, the report reflects only the filtered events (e.g. `event_count` reflects the matched count, not the total original timeline), and captures applied query filters.
* `Sequence[TimelineEvent]`: Any immutable sequence of valid `TimelineEvent` objects.
* `TimelineReport`: An existing report instance (for re-rendering or updating metadata).

Input timelines and events are never mutated, re-sorted, or re-deduplicated.

---

## Supported Output Formats

### 1. Structured JSON Report
Rendered via `render_timeline_json()` or written via `write_timeline_json_report()`.

Key schema elements:
* `report_type`: Fixed identifier (`"timeline"`).
* `report_version`: Schema version (`"3.6"`).
* `forensix_version`: Package version (`"2.0.1"`).
* `metadata`: Optional caller-supplied case details (`case_id`, `case_name`, `investigator`, `generated_at`, `query`).
* `summary`: Aggregate metrics including `event_count`, deterministic `categories` counts, `event_types` counts, and `timestamp_coverage`.
* `events`: Ordered list of serialized events preserving all factual properties and provenance.

### 2. Standalone HTML5 Report
Rendered via `render_timeline_html()` or written via `write_timeline_html_report()`.

Key layout components:
* **Header**: ForensiX version, report schema version, and optional case metadata cards.
* **Applied Query Filters Box**: Rendered when the source input is a `TimelineQueryResult`.
* **Summary Metrics Grid**: Metric boxes showing Total Events, Timestamped Events (aware/naive breakdown), Missing Timestamps, and Unique Categories/Types.
* **Breakdown Tables**: Deterministically sorted category and event-type distribution tables.
* **Chronological Timeline Table**: Complete table containing Row #, Timestamp, Category, Event Type, Description, Source Path, Line Number, Artifact ID, and a collapsible Provenance & Data drawer.
* **Self-Contained Styling**: Embedded CSS with dark slate forensic palette; zero CDN requests, zero external fonts, zero external JavaScript.

---

## Provenance Preservation

Forensic reports must never sacrifice investigative lineage. Every event row retains:

* `source_path`: Exact path to the source evidence file.
* `source_line`: Exact line number within the source file (if applicable).
* `source_artifact_id`: Identifier of the parent artifact record.
* `source_event_id`: Identifier of the underlying event record.
* `raw_timestamp`: Unmodified timestamp text as observed in the raw evidence.
* `raw_data`: Verbatim raw log line or metadata snippet.
* `attributes`: Complete attribute dictionary with full preservation of falsy values (`0`, `False`, empty strings, and nested structures).

---

## Timestamp Fidelity

* **Aware Timestamps**: Rendered deterministically in ISO 8601 with a `Z` suffix for UTC instants (e.g., `2026-09-30T09:00:00Z`).
* **Naive Timestamps**: Rendered in ISO 8601 without synthetic timezones (e.g., `2026-09-30T09:00:00`). Never guesses or fabricates timezone offsets.
* **Missing Timestamps**: Serialized as `null` in JSON and displayed as `None` in HTML, while preserving original `raw_timestamp` strings (e.g., for yearless syslog messages).

---

## Security & HTML Escaping

All evidence data (filenames, usernames, descriptions, raw log lines, attributes) is treated as untrusted input:

* Every value rendered into HTML is escaped using `html.escape(..., quote=True)`.
* Special characters (`<`, `>`, `&`, `"`, `'`) and embedded scripts (e.g., `<script>alert(1)</script>`) are rendered as inert text, preventing cross-site scripting (XSS) or DOM injection.
* No external JavaScript or network assets are loaded, ensuring safe use in air-gapped environments.

---

## Immutability & Determinism

* **Deep Immutability**: All report generation functions leave source `TimelineEvent` records and `ReconstructedTimeline` containers unmodified.
* **Deterministic Output**: Generating a report twice from the same timeline produces identical output.
* **No Implicit Dynamic Data**: Report generation does not inject `datetime.now()` or host environment variables unless explicitly provided by the caller.

---

## Scope Boundary

In accordance with ForensiX architectural separation of concerns, **V3.6 does NOT perform**:

* Threat detection, anomaly detection, or malware classification
* Risk scoring, severity ranking, or priority weighting
* Automated investigative conclusions or attack graph construction
* CLI command integration (deferred to V3.7)
* Final release verification (deferred to V3.8)
* Dynamic dashboard servers or interactive web applications (HTML output is purely a static report)

---

## Python API Example

```python
from datetime import datetime, timezone
from pathlib import Path
from forensix.timeline_models import TimelineCategory
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.timeline_query import TimelineQuery, query_timeline
from forensix.timeline_reporting import (
    generate_timeline_report,
    render_timeline_json,
    render_timeline_html,
    write_timeline_json_report,
    write_timeline_html_report,
)

# 1. Reconstruct timeline from evidence adapters
timeline = reconstruct_timeline(events)

# 2. Optionally query for a specific subset
query = TimelineQuery(category=TimelineCategory.AUTHENTICATION)
query_result = query_timeline(timeline, query)

# 3. Generate structured report model
report = generate_timeline_report(
    query_result,
    case_id="CASE-2026-0042",
    case_name="Server Intrusion Triage",
    investigator="Examiner J. Doe",
    generated_at="2026-10-02T10:00:00Z",
)

# 4. Render or write JSON report
json_output = render_timeline_json(report, indent=2)
write_timeline_json_report(report, Path("reports/timeline.json"))

# 5. Render or write HTML report
html_output = render_timeline_html(report)
write_timeline_html_report(report, Path("reports/timeline.html"))
```
