"""
Forensic Correlation Reporting Layer for ForensiX (V4.6 Correlation Reporting).

Transforms factual Correlation objects (from CorrelationCollection or sequence)
into structured, deterministic, machine-readable JSON and human-readable HTML reports
without modifying underlying evidence, altering event ordering, or introducing speculative conclusions.

Core Principles:
1. Strict Provenance & Factuality: Preserves correlation IDs, relationship types, event IDs,
   source artifact IDs, source event IDs, timestamps, and time deltas. Never invents conclusions
   or asserts attacker compromise.
2. Canonical Ordering: Rows strictly follow deterministic sorting (correlation_sort_key).
3. Timezone Fidelity: Aware timestamps formatted as ISO 8601 UTC ('Z'), naive timestamps preserved.
4. Deep Immutability: Input Correlation instances and collections are never mutated.
5. Deterministic Output: Repeated report generation on identical inputs yields byte-for-byte identical output.
6. HTML Safety: All evidence-controlled content is strictly escaped using html.escape(..., quote=True).
   100% self-contained offline utility; no external CDNs or scripts.
"""

from dataclasses import dataclass
from datetime import datetime
import html
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.correlation_engine import correlation_sort_key
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    unfreeze_to_dict,
)
from forensix.timestamp_normalizer import format_iso_timestamp

REPORT_TYPE_CORRELATION: str = "correlation"
REPORT_VERSION_CORRELATION: str = "4.6"


def esc(val: Any) -> str:
    """Safely escape arbitrary values for HTML output."""
    if val is None:
        return "<em>None</em>"
    return html.escape(str(val), quote=True)


def serialize_correlation(correlation: Correlation) -> Dict[str, Any]:
    """
    Serialize a Correlation object to a deterministic, JSON-safe dictionary.

    Guarantees:
    - Consistent ISO 8601 formatting for aware timestamps with Z suffix for UTC.
    - Naive timestamps remain naive without fake timezones.
    - Missing timestamps represented as None (null).
    - Preserves all provenance: event_ids, source_event_ids, source_artifact_ids.
    - Preserves attributes, delta_seconds, and description.
    """
    start_ts_str: Optional[str] = None
    if correlation.start_timestamp is not None:
        start_ts_str = format_iso_timestamp(correlation.start_timestamp, use_z=True)

    end_ts_str: Optional[str] = None
    if correlation.end_timestamp is not None:
        end_ts_str = format_iso_timestamp(correlation.end_timestamp, use_z=True)

    rel_type_str = (
        correlation.relationship_type.value
        if isinstance(correlation.relationship_type, CorrelationType)
        else str(correlation.relationship_type)
    )

    return {
        "correlation_id": correlation.correlation_id,
        "relationship_type": rel_type_str,
        "event_ids": list(correlation.event_ids),
        "source_event_ids": list(correlation.source_event_ids),
        "source_artifact_ids": list(correlation.source_artifact_ids),
        "start_timestamp": start_ts_str,
        "end_timestamp": end_ts_str,
        "time_delta_seconds": correlation.time_delta_seconds,
        "description": correlation.description,
        "attributes": unfreeze_to_dict(correlation.attributes),
    }


@dataclass(frozen=True)
class CorrelationReport:
    """
    Immutable representation of a structured forensic correlation report.

    Attributes:
        report_type: Fixed identifier ('correlation').
        report_version: Version of the reporting schema ('4.6').
        forensix_version: ForensiX package version ('2.0.1').
        case_id: Optional case identifier supplied by caller.
        case_name: Optional case name supplied by caller.
        investigator: Optional investigator identifier supplied by caller.
        generated_at: Optional ISO timestamp of report generation (explicit only).
        total_correlations: Count of correlations in this report.
        relationship_counts: Deterministically sorted mapping of relationship types to counts.
        correlations: Immutable tuple of Correlation instances in deterministic order.
    """

    report_type: str
    report_version: str
    forensix_version: str
    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    generated_at: Optional[str]
    total_correlations: int
    relationship_counts: Dict[str, int]
    correlations: Tuple[Correlation, ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on collections."""
        if not isinstance(self.correlations, tuple):
            object.__setattr__(self, "correlations", tuple(self.correlations))

    def __len__(self) -> int:
        return self.total_correlations

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.correlations[idx]

    def __iter__(self) -> Iterator[Correlation]:
        return iter(self.correlations)

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, Correlation):
            return item in self.correlations
        if isinstance(item, str):
            return any(c.correlation_id == item for c in self.correlations)
        return False

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
            },
            "summary": {
                "total_correlations": self.total_correlations,
                "relationship_counts": dict(self.relationship_counts),
            },
            "correlations": [serialize_correlation(c) for c in self.correlations],
        }


def generate_correlation_report(
    correlations: Union[CorrelationReport, CorrelationCollection, Sequence[Correlation]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> CorrelationReport:
    """
    Generate an immutable CorrelationReport from a CorrelationCollection or sequence of Correlations.

    Orders correlations deterministically using correlation_sort_key.

    Args:
        correlations: CorrelationReport, CorrelationCollection, or sequence of Correlation objects.
        case_id: Optional case identifier string.
        case_name: Optional case name string.
        investigator: Optional investigator identifier string.
        generated_at: Optional generation timestamp string or datetime.

    Returns:
        CorrelationReport: Immutable structured correlation report.

    Raises:
        ValueError: If correlations is None.
        TypeError: If elements are not Correlation instances.
    """
    if correlations is None:
        raise ValueError("correlations cannot be None")

    if isinstance(correlations, CorrelationReport):
        if case_id is None and case_name is None and investigator is None and generated_at is None:
            return correlations
        return CorrelationReport(
            report_type=correlations.report_type,
            report_version=correlations.report_version,
            forensix_version=correlations.forensix_version,
            case_id=case_id if case_id is not None else correlations.case_id,
            case_name=case_name if case_name is not None else correlations.case_name,
            investigator=investigator if investigator is not None else correlations.investigator,
            generated_at=(
                (format_iso_timestamp(generated_at, use_z=True) if isinstance(generated_at, datetime) else str(generated_at))
                if generated_at is not None
                else correlations.generated_at
            ),
            total_correlations=correlations.total_correlations,
            relationship_counts=correlations.relationship_counts,
            correlations=correlations.correlations,
        )

    if isinstance(correlations, Correlation):
        corr_seq = [correlations]
    elif isinstance(correlations, CorrelationCollection):
        corr_seq = correlations.correlations
    elif isinstance(correlations, (list, tuple, set)):
        corr_seq = list(correlations)
    else:
        try:
            corr_seq = tuple(correlations)
        except Exception as err:
            raise TypeError(f"Unsupported correlations type: {type(correlations).__name__}") from err

    validated: List[Correlation] = []
    counts: Dict[str, int] = {}
    for i, item in enumerate(corr_seq):
        if not isinstance(item, Correlation):
            raise TypeError(
                f"Element at index {i} is not a Correlation (got {type(item).__name__}). "
                "Correlation reporting requires valid Correlation instances."
            )
        validated.append(item)
        r_type = (
            item.relationship_type.value
            if isinstance(item.relationship_type, CorrelationType)
            else str(item.relationship_type)
        )
        counts[r_type] = counts.get(r_type, 0) + 1

    # Deterministic sorting
    sorted_corrs = sorted(validated, key=correlation_sort_key)
    sorted_counts = dict(sorted(counts.items()))

    gen_at_str: Optional[str] = None
    if generated_at is not None:
        if isinstance(generated_at, datetime):
            gen_at_str = format_iso_timestamp(generated_at, use_z=True)
        elif isinstance(generated_at, str):
            clean = generated_at.strip()
            if clean:
                gen_at_str = clean
        else:
            raise TypeError(f"generated_at must be str, datetime, or None, got {type(generated_at).__name__}")

    return CorrelationReport(
        report_type=REPORT_TYPE_CORRELATION,
        report_version=REPORT_VERSION_CORRELATION,
        forensix_version=__version__,
        case_id=case_id.strip() if case_id and isinstance(case_id, str) else None,
        case_name=case_name.strip() if case_name and isinstance(case_name, str) else None,
        investigator=investigator.strip() if investigator and isinstance(investigator, str) else None,
        generated_at=gen_at_str,
        total_correlations=len(sorted_corrs),
        relationship_counts=sorted_counts,
        correlations=tuple(sorted_corrs),
    )


def render_correlation_json(
    correlations: Union[CorrelationReport, CorrelationCollection, Sequence[Correlation]],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> str:
    """
    Render a correlation report as a formatted, deterministic UTF-8 JSON string.
    """
    report = generate_correlation_report(
        correlations,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def write_correlation_json_report(
    correlations: Union[CorrelationReport, CorrelationCollection, Sequence[Correlation]],
    output_path: Union[str, Path],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> Path:
    """
    Write a rendered JSON correlation report to the destination path.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_correlation_json(
        correlations,
        indent=indent,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    path.write_text(content, encoding="utf-8")
    return path


def render_correlation_html(
    correlations: Union[CorrelationReport, CorrelationCollection, Sequence[Correlation]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> str:
    """
    Render a correlation report as a standalone, securely escaped HTML5 forensic report.
    """
    report = generate_correlation_report(
        correlations,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )

    # Metadata HTML
    meta_items: List[str] = []
    if report.case_id:
        meta_items.append(f"<div><span class='label'>Case ID:</span> <code>{esc(report.case_id)}</code></div>")
    if report.case_name:
        meta_items.append(f"<div><span class='label'>Case Name:</span> <strong>{esc(report.case_name)}</strong></div>")
    if report.investigator:
        meta_items.append(f"<div><span class='label'>Investigator:</span> {esc(report.investigator)}</div>")
    if report.generated_at:
        meta_items.append(f"<div><span class='label'>Report Generated:</span> <time>{esc(report.generated_at)}</time></div>")

    meta_html = f"<div class='metadata-bar'>{''.join(meta_items)}</div>" if meta_items else ""

    # Relationship counts badges
    badge_items: List[str] = []
    for r_type, count in report.relationship_counts.items():
        badge_items.append(f"<span class='badge'>{esc(r_type)}: <strong>{count}</strong></span>")
    badges_html = " ".join(badge_items) if badge_items else "<em>None</em>"

    # Correlation table rows
    rows: List[str] = []
    for c in report.correlations:
        start_ts = format_iso_timestamp(c.start_timestamp, use_z=True) if c.start_timestamp else "None"
        end_ts = format_iso_timestamp(c.end_timestamp, use_z=True) if c.end_timestamp else "None"
        delta_str = f"{c.time_delta_seconds:.1f}s" if c.time_delta_seconds is not None else "N/A"

        event_ids_str = ", ".join(c.event_ids)
        src_events_str = ", ".join(c.source_event_ids) if c.source_event_ids else "None"
        src_arts_str = ", ".join(c.source_artifact_ids) if c.source_artifact_ids else "None"

        attrs_json = json.dumps(unfreeze_to_dict(c.attributes), indent=2) if c.attributes else ""

        row = f"""<tr>
            <td><code>{esc(c.correlation_id)}</code></td>
            <td><span class='rel-badge'>{esc(c.relationship_type.value if hasattr(c.relationship_type, 'value') else c.relationship_type)}</span></td>
            <td>{esc(start_ts)}</td>
            <td>{esc(end_ts)}</td>
            <td>{esc(delta_str)}</td>
            <td>{esc(c.description)}</td>
            <td>
                <div><strong>Events:</strong> <code>{esc(event_ids_str)}</code></div>
                <div><strong>Source Events:</strong> <code>{esc(src_events_str)}</code></div>
                <div><strong>Artifacts:</strong> <code>{esc(src_arts_str)}</code></div>
                {f"<details><summary>Attributes</summary><pre>{esc(attrs_json)}</pre></details>" if attrs_json else ""}
            </td>
        </tr>"""
        rows.append(row)

    table_body = "\n".join(rows) if rows else "<tr><td colspan='7'><em>No correlations identified.</em></td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForensiX Correlation Report</title>
<style>
  :root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --accent-dark: #0284c7;
    --border: #334155;
    --badge-bg: #1e3a5f;
    --badge-text: #7dd3fc;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .header {{
    border-bottom: 2px solid var(--accent);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  h1 {{ margin: 0 0 8px 0; font-size: 24px; color: var(--accent); }}
  .version-tag {{ font-size: 13px; color: var(--text-secondary); }}
  .metadata-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    background: var(--bg-secondary);
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 24px;
    font-size: 14px;
  }}
  .metadata-bar code {{ color: var(--accent); }}
  .summary-card {{
    background: var(--bg-secondary);
    padding: 16px;
    border-radius: 6px;
    margin-bottom: 24px;
    border-left: 4px solid var(--accent);
  }}
  .badge {{
    display: inline-block;
    background: var(--badge-bg);
    color: var(--badge-text);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    margin-right: 6px;
    margin-bottom: 6px;
  }}
  .rel-badge {{
    display: inline-block;
    background: #1e293b;
    border: 1px solid var(--accent);
    color: var(--accent);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 12px;
    font-weight: bold;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border-radius: 6px;
    overflow: hidden;
    font-size: 13px;
  }}
  th, td {{
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  th {{
    background: #111e33;
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
  }}
  tr:hover {{ background: rgba(56, 189, 248, 0.04); }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
  details {{ margin-top: 6px; }}
  summary {{ cursor: pointer; color: var(--accent); font-size: 11px; }}
  pre {{
    background: var(--bg-primary);
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 11px;
    color: #e2e8f0;
  }}
</style>
</head>
<body>
<div class="header">
  <h1>ForensiX Correlation Report</h1>
  <div class="version-tag">ForensiX Automated Digital Forensics & Incident Triage Platform (v{esc(report.forensix_version)}) | Schema v{esc(report.report_version)}</div>
</div>

{meta_html}

<div class="summary-card">
  <div><strong>Total Correlations Identified:</strong> {report.total_correlations}</div>
  <div style="margin-top: 8px;"><strong>Relationship Distribution:</strong> {badges_html}</div>
</div>

<h2>Correlations</h2>
<table>
  <thead>
    <tr>
      <th>Correlation ID</th>
      <th>Relationship</th>
      <th>Start Timestamp</th>
      <th>End Timestamp</th>
      <th>Delta</th>
      <th>Factual Description</th>
      <th>Provenance & Evidence References</th>
    </tr>
  </thead>
  <tbody>
    {table_body}
  </tbody>
</table>
</body>
</html>
"""


def write_correlation_html_report(
    correlations: Union[CorrelationReport, CorrelationCollection, Sequence[Correlation]],
    output_path: Union[str, Path],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
) -> Path:
    """
    Write a rendered HTML correlation report to the destination path.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_correlation_html(
        correlations,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
    )
    path.write_text(content, encoding="utf-8")
    return path
