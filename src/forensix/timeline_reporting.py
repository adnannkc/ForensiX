"""
Forensic Timeline Reporting Layer for ForensiX (V3.6).

Transforms factual timeline events (from ReconstructedTimeline or TimelineQueryResult)
into structured, deterministic, machine-readable JSON and human-readable HTML reports
without modifying underlying evidence, altering event ordering, or introducing speculative conclusions.

Core Principles:
1. Strict Provenance & Factuality: Preserves source paths, line numbers, artifact/event IDs,
   raw timestamps, and raw data. Never invents conclusions, threat classifications, or risk scores.
2. Canonical Ordering Preservation: Report rows strictly follow the canonical chronological
   sequence established by V3.4 reconstruction / V3.5 querying.
3. Timezone Fidelity:
   - Aware timestamps: formatted deterministically as ISO 8601 UTC (ending in 'Z').
   - Naive timestamps: formatted as ISO 8601 without synthetic timezones.
   - Missing timestamps: represented as None / null in JSON and clearly noted in HTML.
4. Deep Immutability: Source timelines and events are never mutated.
5. Deterministic Output: Repeated report generation on identical inputs yields byte-for-byte identical output.
   Default generation includes no implicit datetime.now() or system environment metadata.
6. HTML Safety: All evidence-controlled content is strictly escaped using html.escape(..., quote=True).
   Zero external dependencies or CDN links; 100% self-contained offline utility.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    unfreeze_to_dict,
)
from forensix.timeline_query import TimelineQueryResult
from forensix.timeline_reconstruction import ReconstructedTimeline
from forensix.timestamp_normalizer import (
    format_iso_timestamp,
    is_timezone_aware,
)


REPORT_TYPE: str = "timeline"
REPORT_VERSION: str = "3.6"


def esc(val: Any) -> str:
    """Safely escape arbitrary values for HTML output."""
    if val is None:
        return "<em>None</em>"
    return html.escape(str(val), quote=True)


def serialize_timeline_event(event: TimelineEvent) -> Dict[str, Any]:
    """
    Serialize a TimelineEvent to a deterministic, JSON-safe dictionary.

    Guarantees:
    - Consistent ISO 8601 formatting for aware timestamps with Z suffix for UTC.
    - Naive timestamps remain naive without fake timezones.
    - Missing timestamps are represented as None (null).
    - Raw timestamp and raw data are preserved.
    - Complete provenance (source_path, source_line, source_artifact_id, source_event_id) preserved.
    - Attributes preserve empty dicts, 0, False, and empty strings.
    """
    ts_str: Optional[str] = None
    if event.timestamp is not None:
        ts_str = format_iso_timestamp(event.timestamp, use_z=True)

    cat_str = (
        event.category.value
        if isinstance(event.category, TimelineCategory)
        else str(event.category)
    )

    return {
        "event_id": event.event_id,
        "timestamp": ts_str,
        "raw_timestamp": event.raw_timestamp,
        "category": cat_str,
        "event_type": event.event_type,
        "description": event.description,
        "source_path": event.source_path,
        "source_line": event.source_line,
        "source_artifact_id": event.source_artifact_id,
        "source_event_id": event.source_event_id,
        "raw_data": event.raw_data,
        "attributes": unfreeze_to_dict(event.attributes),
    }


@dataclass(frozen=True)
class TimelineReport:
    """
    Immutable representation of a structured forensic timeline report.

    Attributes:
        report_type: Fixed identifier ('timeline').
        report_version: Version of the reporting schema ('3.6').
        forensix_version: ForensiX package version ('2.0.1').
        case_id: Optional case identifier supplied by caller.
        case_name: Optional case name supplied by caller.
        investigator: Optional investigator identifier supplied by caller.
        generated_at: Optional ISO timestamp of report generation (explicit only).
        query_summary: Optional dictionary summarizing query filters if generated from TimelineQueryResult.
        event_count: Total count of events included in this report.
        categories: Deterministically sorted mapping of category names to event counts.
        event_types: Deterministically sorted mapping of event_type names to event counts.
        timestamp_coverage: Deterministically sorted mapping of timestamp classification metrics.
        events: Immutable tuple of TimelineEvent instances in canonical order.
    """

    report_type: str
    report_version: str
    forensix_version: str
    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    generated_at: Optional[str]
    query_summary: Optional[Dict[str, Any]]
    event_count: int
    categories: Dict[str, int]
    event_types: Dict[str, int]
    timestamp_coverage: Dict[str, int]
    events: Tuple[TimelineEvent, ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on events collection."""
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))

    def __len__(self) -> int:
        return self.event_count

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.events[idx]

    def __iter__(self) -> Iterator[TimelineEvent]:
        return iter(self.events)

    def __contains__(self, item: Any) -> bool:
        return item in self.events

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to a deterministic, JSON-serializable dictionary."""
        return {
            "report_type": self.report_type,
            "report_version": self.report_version,
            "forensix_version": self.forensix_version,
            "metadata": {
                "case_id": self.case_id,
                "case_name": self.case_name,
                "investigator": self.investigator,
                "generated_at": self.generated_at,
                "query": self.query_summary,
            },
            "summary": {
                "event_count": self.event_count,
                "categories": self.categories,
                "event_types": self.event_types,
                "timestamp_coverage": self.timestamp_coverage,
            },
            "event_count": self.event_count,
            "categories": self.categories,
            "event_types": self.event_types,
            "timestamp_coverage": self.timestamp_coverage,
            "events": [serialize_timeline_event(e) for e in self.events],
        }


def generate_timeline_report(
    timeline: Union[TimelineReport, ReconstructedTimeline, TimelineQueryResult, Sequence[TimelineEvent]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> TimelineReport:
    """
    Generate an immutable TimelineReport from a ReconstructedTimeline, TimelineQueryResult,
    or sequence of TimelineEvents.

    Preserves the canonical event order exactly as provided. Does not re-sort or re-filter.

    Args:
        timeline: ReconstructedTimeline, TimelineQueryResult, or sequence of TimelineEvent objects.
        case_id: Optional case identifier string.
        case_name: Optional case name string.
        investigator: Optional investigator name/ID string.
        generated_at: Optional generation timestamp string or datetime.

    Returns:
        TimelineReport: Immutable structured forensic report.

    Raises:
        ValueError: If timeline is None.
        TypeError: If timeline elements are not TimelineEvents.
    """
    if timeline is None:
        raise ValueError("timeline cannot be None")

    if isinstance(timeline, TimelineReport):
        # If already a report and no metadata overrides, return directly
        if case_id is None and case_name is None and investigator is None and generated_at is None:
            return timeline
        # Otherwise create a new report with updated metadata
        return TimelineReport(
            report_type=timeline.report_type,
            report_version=timeline.report_version,
            forensix_version=timeline.forensix_version,
            case_id=case_id if case_id is not None else timeline.case_id,
            case_name=case_name if case_name is not None else timeline.case_name,
            investigator=investigator if investigator is not None else timeline.investigator,
            generated_at=(
                (format_iso_timestamp(generated_at, use_z=True) if isinstance(generated_at, datetime) else str(generated_at))
                if generated_at is not None
                else timeline.generated_at
            ),
            query_summary=timeline.query_summary,
            event_count=timeline.event_count,
            categories=timeline.categories,
            event_types=timeline.event_types,
            timestamp_coverage=timeline.timestamp_coverage,
            events=timeline.events,
        )

    query_summary: Optional[Dict[str, Any]] = None
    if isinstance(timeline, TimelineQueryResult):
        event_seq: Sequence[TimelineEvent] = timeline.events
        query_summary = timeline.query.to_dict()
    elif isinstance(timeline, ReconstructedTimeline):
        event_seq = timeline.events
    elif isinstance(timeline, (tuple, list)):
        event_seq = timeline
    else:
        try:
            event_seq = tuple(timeline)
        except Exception as err:
            raise TypeError(f"Unsupported timeline type: {type(timeline).__name__}") from err

    # Validate elements
    validated_events: List[TimelineEvent] = []
    for i, item in enumerate(event_seq):
        if not isinstance(item, TimelineEvent):
            raise TypeError(
                f"Element at index {i} is not a TimelineEvent (got {type(item).__name__}). "
                "Timeline reporting requires valid TimelineEvent instances."
            )
        validated_events.append(item)

    event_tuple = tuple(validated_events)
    total_events = len(event_tuple)

    # Compute category breakdown
    cat_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}
    timestamped_count = 0
    missing_count = 0
    aware_count = 0
    naive_count = 0

    for ev in event_tuple:
        # Category
        cat_key = (
            ev.category.value
            if isinstance(ev.category, TimelineCategory)
            else str(ev.category)
        )
        cat_counts[cat_key] = cat_counts.get(cat_key, 0) + 1

        # Event type
        type_counts[ev.event_type] = type_counts.get(ev.event_type, 0) + 1

        # Timestamps
        if ev.timestamp is not None:
            timestamped_count += 1
            if is_timezone_aware(ev.timestamp):
                aware_count += 1
            else:
                naive_count += 1
        else:
            missing_count += 1

    sorted_categories = dict(sorted(cat_counts.items()))
    sorted_event_types = dict(sorted(type_counts.items()))
    timestamp_coverage = {
        "total_events": total_events,
        "timestamped_events": timestamped_count,
        "missing_timestamp_events": missing_count,
        "aware_timestamps": aware_count,
        "naive_timestamps": naive_count,
    }

    # Format generated_at if supplied
    gen_at_str: Optional[str] = None
    if generated_at is not None:
        if isinstance(generated_at, datetime):
            gen_at_str = format_iso_timestamp(generated_at, use_z=True)
        elif isinstance(generated_at, str):
            clean_gen = generated_at.strip()
            if clean_gen:
                gen_at_str = clean_gen
        else:
            raise TypeError(
                f"generated_at must be str, datetime, or None, got {type(generated_at).__name__}"
            )

    return TimelineReport(
        report_type=REPORT_TYPE,
        report_version=REPORT_VERSION,
        forensix_version=__version__,
        case_id=case_id.strip() if case_id and isinstance(case_id, str) else None,
        case_name=case_name.strip() if case_name and isinstance(case_name, str) else None,
        investigator=investigator.strip() if investigator and isinstance(investigator, str) else None,
        generated_at=gen_at_str,
        query_summary=query_summary,
        event_count=total_events,
        categories=sorted_categories,
        event_types=sorted_event_types,
        timestamp_coverage=timestamp_coverage,
        events=event_tuple,
    )


def render_timeline_json(
    timeline: Union[TimelineReport, ReconstructedTimeline, TimelineQueryResult, Sequence[TimelineEvent]],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> str:
    """
    Render a timeline as a formatted, deterministic UTF-8 JSON string.

    Args:
        timeline: TimelineReport, ReconstructedTimeline, TimelineQueryResult, or sequence of TimelineEvents.
        indent: Indentation spaces for pretty-printed JSON (default: 2).
        case_id: Optional case identifier string.
        case_name: Optional case name string.
        investigator: Optional investigator identifier string.
        generated_at: Optional report generation timestamp string or datetime.

    Returns:
        str: Valid JSON string representation.
    """
    report = generate_timeline_report(
        timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def write_timeline_json_report(
    timeline: Union[TimelineReport, ReconstructedTimeline, TimelineQueryResult, Sequence[TimelineEvent]],
    output_path: Union[str, Path],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> Path:
    """
    Write a rendered JSON timeline report to the destination path.

    Boundary rule: Writes only the destination file. Never modifies evidence files.

    Args:
        timeline: Timeline data source.
        output_path: Target file path.
        indent: Indentation spaces for JSON formatting.
        case_id: Optional case identifier.
        case_name: Optional case name.
        investigator: Optional investigator.
        generated_at: Optional generation timestamp.

    Returns:
        Path: Resolved Path to the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_timeline_json(
        timeline,
        indent=indent,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    path.write_text(content, encoding="utf-8")
    return path


def render_timeline_html(
    timeline: Union[TimelineReport, ReconstructedTimeline, TimelineQueryResult, Sequence[TimelineEvent]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> str:
    """
    Render a timeline as a standalone, securely escaped HTML5 forensic report.

    Features:
    - 100% self-contained: embedded CSS, no external scripts, fonts, or CDNs.
    - Security guaranteed: every evidence field is strictly HTML-escaped.
    - Factual presentation: includes metadata, summaries, coverage, and canonical event table.
    - Interactive details: collapsible <details> blocks for inspection of raw data, line provenance,
      and complex attributes.

    Args:
        timeline: Timeline data source.
        case_id: Optional case identifier.
        case_name: Optional case name.
        investigator: Optional investigator.
        generated_at: Optional generation timestamp.

    Returns:
        str: Standalone HTML5 document string.
    """
    report = generate_timeline_report(
        timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )

    # 1. Metadata Block
    meta_items: List[str] = []
    if report.case_id:
        meta_items.append(f"<div><span class='label'>Case ID:</span> <code>{esc(report.case_id)}</code></div>")
    if report.case_name:
        meta_items.append(f"<div><span class='label'>Case Name:</span> <strong>{esc(report.case_name)}</strong></div>")
    if report.investigator:
        meta_items.append(f"<div><span class='label'>Investigator:</span> {esc(report.investigator)}</div>")
    if report.generated_at:
        meta_items.append(f"<div><span class='label'>Report Generated:</span> <time>{esc(report.generated_at)}</time></div>")

    meta_html = ""
    if meta_items:
        meta_html = f"<div class='case-metadata'>{''.join(meta_items)}</div>"

    # 2. Query Summary Block if present
    query_html = ""
    if report.query_summary:
        q_rows: List[str] = []
        for k, v in sorted(report.query_summary.items()):
            if v is not None:
                q_rows.append(f"<li><code>{esc(k)}</code>: <strong>{esc(v)}</strong></li>")
        if q_rows:
            query_html = (
                "<div class='query-box'>"
                "<div class='box-title'>Applied Query Filters (Logical AND)</div>"
                f"<ul class='query-list'>{''.join(q_rows)}</ul>"
                "</div>"
            )

    # 3. Category Breakdown Table
    cat_rows = "".join(
        f"<tr><td><span class='badge badge-cat'>{esc(cat)}</span></td><td class='num'>{cnt}</td></tr>"
        for cat, cnt in report.categories.items()
    )
    cat_table = (
        f"<table class='summary-table'><thead><tr><th>Category</th><th class='num'>Events</th></tr></thead>"
        f"<tbody>{cat_rows}</tbody></table>"
        if cat_rows
        else "<p class='empty-text'>No categories recorded.</p>"
    )

    # 4. Event Type Breakdown Table
    type_rows = "".join(
        f"<tr><td><code>{esc(etype)}</code></td><td class='num'>{cnt}</td></tr>"
        for etype, cnt in report.event_types.items()
    )
    type_table = (
        f"<table class='summary-table'><thead><tr><th>Event Type</th><th class='num'>Events</th></tr></thead>"
        f"<tbody>{type_rows}</tbody></table>"
        if type_rows
        else "<p class='empty-text'>No event types recorded.</p>"
    )

    # 5. Timeline Event Rows
    table_rows: List[str] = []
    for idx, ev in enumerate(report.events, start=1):
        # Format timestamp cell
        if ev.timestamp is not None:
            ts_str = format_iso_timestamp(ev.timestamp, use_z=True)
            if is_timezone_aware(ev.timestamp):
                ts_cell = f"<time class='ts-aware'>{esc(ts_str)}</time>"
            else:
                ts_cell = f"<time class='ts-naive'>{esc(ts_str)} <span class='badge-sub'>(naive)</span></time>"
        elif ev.raw_timestamp:
            ts_cell = f"<span class='ts-missing'><em>None</em> <span class='badge-sub'>raw: {esc(ev.raw_timestamp)}</span></span>"
        else:
            ts_cell = "<span class='ts-missing'><em>None</em></span>"

        cat_val = ev.category.value if isinstance(ev.category, TimelineCategory) else str(ev.category)
        line_str = str(ev.source_line) if ev.source_line is not None else "-"
        art_id_str = f"<code>{esc(ev.source_artifact_id)}</code>" if ev.source_artifact_id else "-"
        path_str = f"<span class='path-cell'>{esc(ev.source_path)}</span>" if ev.source_path else "-"

        # Details expansion
        details_parts: List[str] = [
            f"<div><strong>Event ID:</strong> <code>{esc(ev.event_id)}</code></div>"
        ]
        if ev.source_event_id:
            details_parts.append(f"<div><strong>Source Event ID:</strong> <code>{esc(ev.source_event_id)}</code></div>")
        if ev.raw_timestamp:
            details_parts.append(f"<div><strong>Raw Timestamp:</strong> <code>{esc(ev.raw_timestamp)}</code></div>")
        if ev.raw_data:
            details_parts.append(
                f"<div><strong>Raw Data:</strong><pre class='raw-line'>{esc(ev.raw_data)}</pre></div>"
            )
        if ev.attributes:
            attr_dict = unfreeze_to_dict(ev.attributes)
            if attr_dict:
                attr_json = json.dumps(attr_dict, indent=2, ensure_ascii=False)
                details_parts.append(
                    f"<div><strong>Attributes:</strong><pre class='payload-pre'>{esc(attr_json)}</pre></div>"
                )

        details_html = (
            f"<details><summary>Provenance &amp; Data</summary><div class='details-content'>{''.join(details_parts)}</div></details>"
        )

        table_rows.append(
            f"<tr>"
            f"<td class='num'>{idx}</td>"
            f"<td>{ts_cell}</td>"
            f"<td><span class='badge badge-cat'>{esc(cat_val)}</span></td>"
            f"<td><code>{esc(ev.event_type)}</code></td>"
            f"<td>{esc(ev.description)}</td>"
            f"<td>{path_str}</td>"
            f"<td class='num'>{esc(line_str)}</td>"
            f"<td>{art_id_str}</td>"
            f"<td>{details_html}</td>"
            f"</tr>"
        )

    events_tbody = (
        "\n".join(table_rows)
        if table_rows
        else "<tr><td colspan='9' class='empty-cell'><em>No timeline events recorded.</em></td></tr>"
    )

    tc = report.timestamp_coverage

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ForensiX Timeline Report</title>
<style>
:root {{
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-alt: #334155;
  --border: #475569;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --code-bg: #0b0f19;
  --success: #22c55e;
  --warning: #f59e0b;
  --danger: #ef4444;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background-color: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  padding: 2rem;
}}
.container {{ max-width: 1400px; margin: 0 auto; }}
header {{
  border-bottom: 2px solid var(--border);
  padding-bottom: 1.5rem;
  margin-bottom: 2rem;
}}
h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: 0.25rem; font-weight: 700; }}
.subtitle {{ color: var(--text-muted); font-size: 0.9rem; }}
.case-metadata {{
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  background-color: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem 1.25rem;
  margin-top: 1.25rem;
  font-size: 0.875rem;
}}
.case-metadata .label {{ color: var(--text-muted); text-transform: uppercase; font-size: 0.75rem; font-weight: 600; margin-right: 0.25rem; }}
.query-box {{
  background-color: var(--surface);
  border-left: 4px solid var(--accent);
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 4px;
  padding: 1rem 1.25rem;
  margin-bottom: 2rem;
}}
.box-title {{ font-size: 0.8125rem; text-transform: uppercase; color: var(--accent); font-weight: bold; margin-bottom: 0.5rem; }}
.query-list {{ list-style-type: none; display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; }}
.grid-4 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}}
.grid-2 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}}
.metric-box {{
  background: var(--surface);
  padding: 1.25rem;
  border-radius: 6px;
  border: 1px solid var(--border);
}}
.metric-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: bold; }}
.metric-val {{ font-size: 1.75rem; font-weight: bold; color: var(--accent); margin-top: 0.25rem; }}
.metric-sub {{ font-size: 0.8125rem; color: var(--text-muted); margin-top: 0.25rem; }}
.section-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.25rem;
}}
.section-card h2 {{
  font-size: 1.125rem;
  color: var(--text);
  margin-bottom: 0.75rem;
  font-weight: 600;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}}
th, td {{
  padding: 0.65rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}}
th {{
  background-color: var(--surface-alt);
  color: var(--text-muted);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.05em;
}}
td.num, th.num {{ text-align: right; }}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background-color: var(--code-bg);
  padding: 0.15rem 0.35rem;
  border-radius: 3px;
  font-size: 0.8125rem;
  color: var(--accent);
}}
.path-cell {{ font-family: ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }}
.ts-aware {{ color: var(--success); font-family: ui-monospace, monospace; font-size: 0.8125rem; }}
.ts-naive {{ color: var(--warning); font-family: ui-monospace, monospace; font-size: 0.8125rem; }}
.ts-missing {{ color: var(--text-muted); font-size: 0.8125rem; }}
.badge-sub {{ font-size: 0.7rem; color: var(--text-muted); }}
.badge {{
  display: inline-block;
  padding: 0.15rem 0.4rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.badge-cat {{ background-color: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }}
details summary {{ cursor: pointer; color: var(--accent); font-size: 0.8125rem; user-select: none; }}
details summary:hover {{ text-decoration: underline; }}
.details-content {{
  margin-top: 0.5rem;
  padding: 0.5rem;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}}
.raw-line {{
  font-family: ui-monospace, monospace;
  background-color: var(--surface);
  padding: 0.4rem;
  border-radius: 3px;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 0.75rem;
  max-height: 200px;
  overflow-y: auto;
  border: 1px solid var(--border);
}}
.payload-pre {{
  font-family: ui-monospace, monospace;
  background-color: var(--surface);
  padding: 0.4rem;
  border-radius: 3px;
  max-height: 220px;
  overflow: auto;
  font-size: 0.75rem;
  border: 1px solid var(--border);
}}
.empty-cell {{ text-align: center; color: var(--text-muted); padding: 2rem; }}
.empty-text {{ color: var(--text-muted); font-size: 0.875rem; }}
footer {{
  text-align: center;
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 0.8125rem;
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>ForensiX Timeline Report</h1>
    <div class="subtitle">ForensiX v{esc(report.forensix_version)} &bull; Report Schema v{esc(report.report_version)}</div>
    {meta_html}
  </header>

  {query_html}

  <section class="grid-4">
    <div class="metric-box">
      <div class="metric-title">Total Events</div>
      <div class="metric-val">{report.event_count}</div>
      <div class="metric-sub">Chronological observations</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Timestamped Events</div>
      <div class="metric-val">{tc["timestamped_events"]}</div>
      <div class="metric-sub">{tc["aware_timestamps"]} aware, {tc["naive_timestamps"]} naive</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Missing Timestamps</div>
      <div class="metric-val">{tc["missing_timestamp_events"]}</div>
      <div class="metric-sub">Yearless / undated records</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Categories</div>
      <div class="metric-val">{len(report.categories)}</div>
      <div class="metric-sub">{len(report.event_types)} distinct event types</div>
    </div>
  </section>

  <section class="grid-2">
    <div class="section-card">
      <h2>Category Breakdown</h2>
      {cat_table}
    </div>
    <div class="section-card">
      <h2>Event Type Breakdown</h2>
      {type_table}
    </div>
  </section>

  <section class="section-card" style="margin-bottom: 2rem;">
    <h2>Chronological Timeline Events ({report.event_count})</h2>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th class="num">#</th>
            <th>Timestamp</th>
            <th>Category</th>
            <th>Event Type</th>
            <th>Description</th>
            <th>Source Path</th>
            <th class="num">Line</th>
            <th>Artifact ID</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {events_tbody}
        </tbody>
      </table>
    </div>
  </section>

  <footer>
    ForensiX &bull; Automated Digital Forensics &amp; Incident Triage Platform &bull; Factual &amp; Deterministic Reporting
  </footer>
</div>
</body>
</html>
"""


def write_timeline_html_report(
    timeline: Union[TimelineReport, ReconstructedTimeline, TimelineQueryResult, Sequence[TimelineEvent]],
    output_path: Union[str, Path],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> Path:
    """
    Write a rendered HTML timeline report to the destination path.

    Boundary rule: Writes only the destination file. Never modifies evidence files.

    Args:
        timeline: Timeline data source.
        output_path: Target file path.
        case_id: Optional case identifier.
        case_name: Optional case name.
        investigator: Optional investigator.
        generated_at: Optional generation timestamp.

    Returns:
        Path: Resolved Path to the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_timeline_html(
        timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    path.write_text(content, encoding="utf-8")
    return path
