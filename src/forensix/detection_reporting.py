"""
Forensic Detection & Investigation Reporting Layer for ForensiX (V4.6 Detection Reporting).

Transforms factual DetectionResult objects (from DetectionResultCollection or sequence)
and integrated investigations (Detections + Correlations + Timeline Events) into
structured, deterministic, machine-readable JSON and human-readable HTML reports.

Core Principles:
1. Strict Provenance Chain: Trace from Detection -> Matched Correlation -> Supporting Timeline Events -> Source Artifact / Line.
   Never invents conclusions or asserts compromise.
2. Canonical Ordering: Rows strictly follow deterministic sorting (detection_sort_key, correlation_sort_key).
3. Timezone Fidelity: Aware timestamps formatted as ISO 8601 UTC ('Z'), naive timestamps preserved.
4. Deep Immutability: Input DetectionResult, Correlation, and TimelineEvent instances are never mutated.
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
from forensix.correlation_models import Correlation, CorrelationCollection, unfreeze_to_dict
from forensix.correlation_reporting import serialize_correlation
from forensix.detection_engine import (
    DetectionResult,
    DetectionResultCollection,
    detection_sort_key,
)
from forensix.timeline_models import TimelineEvent
from forensix.timeline_reconstruction import ReconstructedTimeline, timeline_sort_key
from forensix.timeline_reporting import serialize_timeline_event
from forensix.timestamp_normalizer import format_iso_timestamp

REPORT_TYPE_DETECTION: str = "detection"
REPORT_TYPE_INVESTIGATION: str = "correlation_detection"
REPORT_VERSION_DETECTION: str = "4.6"


def esc(val: Any) -> str:
    """Safely escape arbitrary values for HTML output."""
    if val is None:
        return "<em>None</em>"
    return html.escape(str(val), quote=True)


def serialize_detection(
    detection: DetectionResult,
    event_map: Optional[Dict[str, TimelineEvent]] = None,
    corr_map: Optional[Dict[str, Correlation]] = None,
) -> Dict[str, Any]:
    """
    Serialize a DetectionResult object to a deterministic, JSON-safe dictionary.

    Optionally resolves full underlying Correlation and TimelineEvent objects
    when event_map and corr_map are provided.
    """
    start_ts_str: Optional[str] = None
    if detection.start_timestamp is not None:
        start_ts_str = format_iso_timestamp(detection.start_timestamp, use_z=True)

    end_ts_str: Optional[str] = None
    if detection.end_timestamp is not None:
        end_ts_str = format_iso_timestamp(detection.end_timestamp, use_z=True)

    data: Dict[str, Any] = {
        "detection_id": detection.detection_id,
        "rule_id": detection.rule_id,
        "rule_name": detection.rule_name,
        "matched": detection.matched,
        "matched_event_ids": list(detection.matched_event_ids),
        "matched_source_event_ids": list(detection.matched_source_event_ids),
        "matched_source_artifact_ids": list(detection.matched_source_artifact_ids),
        "matched_correlation_ids": list(detection.matched_correlation_ids),
        "start_timestamp": start_ts_str,
        "end_timestamp": end_ts_str,
        "time_delta_seconds": detection.time_delta_seconds,
        "explanation": detection.explanation,
        "attributes": unfreeze_to_dict(detection.attributes),
    }

    # If correlation map provided, attach resolved correlation objects
    if corr_map is not None:
        resolved_corrs: List[Dict[str, Any]] = []
        for cid in detection.matched_correlation_ids:
            if cid in corr_map:
                resolved_corrs.append(serialize_correlation(corr_map[cid]))
        data["correlations"] = resolved_corrs

    # If event map provided, attach resolved timeline event objects
    if event_map is not None:
        resolved_events: List[Dict[str, Any]] = []
        for eid in detection.matched_event_ids:
            if eid in event_map:
                resolved_events.append(serialize_timeline_event(event_map[eid]))
        data["supporting_events"] = resolved_events

    return data


@dataclass(frozen=True)
class DetectionReport:
    """
    Immutable representation of a structured forensic detection report.

    Attributes:
        report_type: Fixed identifier ('detection').
        report_version: Version of the reporting schema ('4.6').
        forensix_version: ForensiX package version ('2.0.1').
        case_id: Optional case identifier.
        case_name: Optional case name.
        investigator: Optional investigator identifier.
        generated_at: Optional ISO timestamp of report generation.
        total_detections: Total count of detections in this report.
        matched_detections: Count of matched detections (matched=True).
        rule_counts: Deterministically sorted mapping of rule IDs to detection counts.
        detections: Immutable tuple of DetectionResult instances in deterministic order.
    """

    report_type: str
    report_version: str
    forensix_version: str
    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    generated_at: Optional[str]
    total_detections: int
    matched_detections: int
    rule_counts: Dict[str, int]
    detections: Tuple[DetectionResult, ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on collections."""
        if not isinstance(self.detections, tuple):
            object.__setattr__(self, "detections", tuple(self.detections))

    def __len__(self) -> int:
        return self.total_detections

    def __getitem__(self, idx: Union[int, slice]) -> Any:
        return self.detections[idx]

    def __iter__(self) -> Iterator[DetectionResult]:
        return iter(self.detections)

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, DetectionResult):
            return item in self.detections
        if isinstance(item, str):
            return any(d.detection_id == item for d in self.detections)
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
                "total_detections": self.total_detections,
                "matched_detections": self.matched_detections,
                "rule_counts": dict(self.rule_counts),
            },
            "detections": [serialize_detection(d) for d in self.detections],
        }


def generate_detection_report(
    detections: Union[DetectionReport, DetectionResultCollection, Sequence[DetectionResult]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> DetectionReport:
    """
    Generate an immutable DetectionReport from a DetectionResultCollection or sequence of DetectionResults.

    Orders detections deterministically using detection_sort_key.

    Args:
        detections: DetectionReport, DetectionResultCollection, or sequence of DetectionResult objects.
        case_id: Optional case identifier string.
        case_name: Optional case name string.
        investigator: Optional investigator identifier string.
        generated_at: Optional generation timestamp string or datetime.
        matched_only: If True, only include detections where matched=True.

    Returns:
        DetectionReport: Immutable structured detection report.

    Raises:
        ValueError: If detections is None.
        TypeError: If elements are not DetectionResult instances.
    """
    if detections is None:
        raise ValueError("detections cannot be None")

    if isinstance(detections, DetectionReport):
        if case_id is None and case_name is None and investigator is None and generated_at is None and not matched_only:
            return detections
        filtered_dets = [d for d in detections.detections if (not matched_only or d.matched)]
        return DetectionReport(
            report_type=detections.report_type,
            report_version=detections.report_version,
            forensix_version=detections.forensix_version,
            case_id=case_id if case_id is not None else detections.case_id,
            case_name=case_name if case_name is not None else detections.case_name,
            investigator=investigator if investigator is not None else detections.investigator,
            generated_at=(
                (format_iso_timestamp(generated_at, use_z=True) if isinstance(generated_at, datetime) else str(generated_at))
                if generated_at is not None
                else detections.generated_at
            ),
            total_detections=len(filtered_dets),
            matched_detections=sum(1 for d in filtered_dets if d.matched),
            rule_counts=detections.rule_counts,
            detections=tuple(filtered_dets),
        )

    if isinstance(detections, DetectionResult):
        det_seq = [detections]
    elif isinstance(detections, DetectionResultCollection):
        det_seq = detections.results
    elif isinstance(detections, (list, tuple, set)):
        det_seq = list(detections)
    else:
        try:
            det_seq = tuple(detections)
        except Exception as err:
            raise TypeError(f"Unsupported detections type: {type(detections).__name__}") from err

    validated: List[DetectionResult] = []
    counts: Dict[str, int] = {}
    matched_count = 0

    for i, item in enumerate(det_seq):
        if not isinstance(item, DetectionResult):
            raise TypeError(
                f"Element at index {i} is not a DetectionResult (got {type(item).__name__}). "
                "Detection reporting requires valid DetectionResult instances."
            )
        if matched_only and not item.matched:
            continue
        validated.append(item)
        if item.matched:
            matched_count += 1
        counts[item.rule_id] = counts.get(item.rule_id, 0) + 1

    sorted_dets = sorted(validated, key=detection_sort_key)
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

    return DetectionReport(
        report_type=REPORT_TYPE_DETECTION,
        report_version=REPORT_VERSION_DETECTION,
        forensix_version=__version__,
        case_id=case_id.strip() if case_id and isinstance(case_id, str) else None,
        case_name=case_name.strip() if case_name and isinstance(case_name, str) else None,
        investigator=investigator.strip() if investigator and isinstance(investigator, str) else None,
        generated_at=gen_at_str,
        total_detections=len(sorted_dets),
        matched_detections=matched_count,
        rule_counts=sorted_counts,
        detections=tuple(sorted_dets),
    )


def render_detection_json(
    detections: Union[DetectionReport, DetectionResultCollection, Sequence[DetectionResult]],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> str:
    """Render a detection report as a formatted, deterministic UTF-8 JSON string."""
    report = generate_detection_report(
        detections,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def write_detection_json_report(
    detections: Union[DetectionReport, DetectionResultCollection, Sequence[DetectionResult]],
    output_path: Union[str, Path],
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> Path:
    """Write a rendered JSON detection report to the destination path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_detection_json(
        detections,
        indent=indent,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    path.write_text(content, encoding="utf-8")
    return path


def render_detection_html(
    detections: Union[DetectionReport, DetectionResultCollection, Sequence[DetectionResult]],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> str:
    """Render a detection report as a standalone, securely escaped HTML5 forensic report."""
    report = generate_detection_report(
        detections,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )

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

    badge_items: List[str] = []
    for r_id, count in report.rule_counts.items():
        badge_items.append(f"<span class='badge'><code>{esc(r_id)}</code>: <strong>{count}</strong></span>")
    badges_html = " ".join(badge_items) if badge_items else "<em>None</em>"

    rows: List[str] = []
    for d in report.detections:
        start_ts = format_iso_timestamp(d.start_timestamp, use_z=True) if d.start_timestamp else "None"
        end_ts = format_iso_timestamp(d.end_timestamp, use_z=True) if d.end_timestamp else "None"
        delta_str = f"{d.time_delta_seconds:.1f}s" if d.time_delta_seconds is not None else "N/A"

        event_ids_str = ", ".join(d.matched_event_ids)
        src_events_str = ", ".join(d.matched_source_event_ids) if d.matched_source_event_ids else "None"
        src_arts_str = ", ".join(d.matched_source_artifact_ids) if d.matched_source_artifact_ids else "None"
        corrs_str = ", ".join(d.matched_correlation_ids) if d.matched_correlation_ids else "None"

        attrs_json = json.dumps(unfreeze_to_dict(d.attributes), indent=2) if d.attributes else ""

        match_badge = (
            "<span class='badge-success'>MATCHED</span>"
            if d.matched
            else "<span class='badge-muted'>UNMATCHED</span>"
        )

        row = f"""<tr>
            <td><code>{esc(d.detection_id)}</code></td>
            <td>
                <strong>{esc(d.rule_name)}</strong><br>
                <code style='font-size: 11px; color: var(--text-secondary);'>{esc(d.rule_id)}</code><br>
                {match_badge}
            </td>
            <td>{esc(start_ts)}</td>
            <td>{esc(end_ts)}</td>
            <td>{esc(delta_str)}</td>
            <td>{esc(d.explanation)}</td>
            <td>
                <div><strong>Matched Events:</strong> <code>{esc(event_ids_str)}</code></div>
                <div><strong>Source Events:</strong> <code>{esc(src_events_str)}</code></div>
                <div><strong>Artifacts:</strong> <code>{esc(src_arts_str)}</code></div>
                <div><strong>Correlations:</strong> <code>{esc(corrs_str)}</code></div>
                {f"<details><summary>Attributes</summary><pre>{esc(attrs_json)}</pre></details>" if attrs_json else ""}
            </td>
        </tr>"""
        rows.append(row)

    table_body = "\n".join(rows) if rows else "<tr><td colspan='7'><em>No detections identified.</em></td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForensiX Detection Report</title>
<style>
  :root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
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
  .badge-success {{
    display: inline-block;
    background: #064e3b;
    color: #6ee7b7;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    margin-top: 4px;
  }}
  .badge-muted {{
    display: inline-block;
    background: #334155;
    color: #94a3b8;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    margin-top: 4px;
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
  <h1>ForensiX Detection Report</h1>
  <div class="version-tag">ForensiX Automated Digital Forensics & Incident Triage Platform (v{esc(report.forensix_version)}) | Schema v{esc(report.report_version)}</div>
</div>

{meta_html}

<div class="summary-card">
  <div><strong>Total Detections:</strong> {report.total_detections} (Matched: {report.matched_detections})</div>
  <div style="margin-top: 8px;"><strong>Rule Matches:</strong> {badges_html}</div>
</div>

<h2>Detection Results</h2>
<table>
  <thead>
    <tr>
      <th>Detection ID</th>
      <th>Rule Information</th>
      <th>Start Timestamp</th>
      <th>End Timestamp</th>
      <th>Delta</th>
      <th>Factual Explanation</th>
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


def write_detection_html_report(
    detections: Union[DetectionReport, DetectionResultCollection, Sequence[DetectionResult]],
    output_path: Union[str, Path],
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> Path:
    """Write a rendered HTML detection report to the destination path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_detection_html(
        detections,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    path.write_text(content, encoding="utf-8")
    return path


@dataclass(frozen=True)
class CorrelationDetectionReport:
    """
    Immutable representation of an integrated investigation report connecting
    timeline events, correlations, and detection results into a traceable view.

    Allows examiners to trace from Detection -> Matched Correlation -> Supporting Timeline Events -> Evidence Artifacts.
    """

    report_type: str
    report_version: str
    forensix_version: str
    case_id: Optional[str]
    case_name: Optional[str]
    investigator: Optional[str]
    generated_at: Optional[str]
    event_count: int
    correlation_count: int
    detection_count: int
    matched_detections: int
    rule_counts: Dict[str, int]
    relationship_counts: Dict[str, int]
    detections: Tuple[DetectionResult, ...]
    correlations: Tuple[Correlation, ...]
    timeline_events: Tuple[TimelineEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.detections, tuple):
            object.__setattr__(self, "detections", tuple(self.detections))
        if not isinstance(self.correlations, tuple):
            object.__setattr__(self, "correlations", tuple(self.correlations))
        if not isinstance(self.timeline_events, tuple):
            object.__setattr__(self, "timeline_events", tuple(self.timeline_events))

    def to_dict(self) -> Dict[str, Any]:
        """Convert investigation report to a deterministic, JSON-serializable dictionary."""
        event_map = {e.event_id: e for e in self.timeline_events}
        corr_map = {c.correlation_id: c for c in self.correlations}

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
                "event_count": self.event_count,
                "correlation_count": self.correlation_count,
                "detection_count": self.detection_count,
                "matched_detections": self.matched_detections,
                "rule_counts": dict(self.rule_counts),
                "relationship_counts": dict(self.relationship_counts),
            },
            "detections": [
                serialize_detection(d, event_map=event_map, corr_map=corr_map)
                for d in self.detections
            ],
            "correlations": [serialize_correlation(c) for c in self.correlations],
            "timeline_events": [serialize_timeline_event(e) for e in self.timeline_events],
        }


# Convenience alias
InvestigationReport = CorrelationDetectionReport


def generate_correlation_detection_report(
    detections: Union[DetectionResultCollection, Sequence[DetectionResult]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
    timeline: Optional[Union[ReconstructedTimeline, Sequence[TimelineEvent]]] = None,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> CorrelationDetectionReport:
    """
    Generate an integrated CorrelationDetectionReport connecting detections, correlations, and events.
    """
    if detections is None:
        raise ValueError("detections cannot be None")

    if isinstance(detections, CorrelationDetectionReport):
        if (
            case_id is None
            and case_name is None
            and investigator is None
            and generated_at is None
            and not matched_only
            and correlations is None
            and timeline is None
        ):
            return detections
        filtered_dets = [d for d in detections.detections if (not matched_only or d.matched)]
        corrs_to_use = (
            correlations.correlations
            if isinstance(correlations, CorrelationCollection)
            else (list(correlations) if correlations is not None else list(detections.correlations))
        )
        events_to_use = (
            timeline.events
            if isinstance(timeline, ReconstructedTimeline)
            else (list(timeline) if timeline is not None else list(detections.timeline_events))
        )
        return generate_correlation_detection_report(
            detections=filtered_dets,
            correlations=corrs_to_use,
            timeline=events_to_use,
            case_id=case_id if case_id is not None else detections.case_id,
            case_name=case_name if case_name is not None else detections.case_name,
            investigator=investigator if investigator is not None else detections.investigator,
            generated_at=generated_at if generated_at is not None else detections.generated_at,
            matched_only=False,
        )

    # Validate detections
    if isinstance(detections, DetectionResultCollection):
        det_seq = detections.results
    elif isinstance(detections, (list, tuple, set)):
        det_seq = list(detections)
    else:
        try:
            det_seq = tuple(detections)
        except Exception as err:
            raise TypeError(f"Unsupported detections type: {type(detections).__name__}") from err

    validated_dets: List[DetectionResult] = []
    rule_counts: Dict[str, int] = {}
    matched_count = 0
    for i, d in enumerate(det_seq):
        if not isinstance(d, DetectionResult):
            raise TypeError(f"Item at index {i} in detections is not DetectionResult (got {type(d).__name__})")
        if matched_only and not d.matched:
            continue
        validated_dets.append(d)
        if d.matched:
            matched_count += 1
        rule_counts[d.rule_id] = rule_counts.get(d.rule_id, 0) + 1

    sorted_dets = sorted(validated_dets, key=detection_sort_key)

    # Validate correlations
    validated_corrs: List[Correlation] = []
    rel_counts: Dict[str, int] = {}
    if correlations is not None:
        if isinstance(correlations, CorrelationCollection):
            corr_seq = correlations.correlations
        elif isinstance(correlations, (list, tuple, set)):
            corr_seq = list(correlations)
        else:
            corr_seq = tuple(correlations)

        for i, c in enumerate(corr_seq):
            if not isinstance(c, Correlation):
                raise TypeError(f"Item at index {i} in correlations is not Correlation (got {type(c).__name__})")
            validated_corrs.append(c)
            r_val = c.relationship_type.value if hasattr(c.relationship_type, "value") else str(c.relationship_type)
            rel_counts[r_val] = rel_counts.get(r_val, 0) + 1

    sorted_corrs = sorted(validated_corrs, key=correlation_sort_key)

    # Validate timeline events
    validated_events: List[TimelineEvent] = []
    if timeline is not None:
        if isinstance(timeline, ReconstructedTimeline):
            ev_seq = timeline.events
        elif isinstance(timeline, (list, tuple, set)):
            ev_seq = list(timeline)
        else:
            ev_seq = tuple(timeline)

        for i, e in enumerate(ev_seq):
            if not isinstance(e, TimelineEvent):
                raise TypeError(f"Item at index {i} in timeline is not TimelineEvent (got {type(e).__name__})")
            validated_events.append(e)

    sorted_events = sorted(validated_events, key=timeline_sort_key)

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

    return CorrelationDetectionReport(
        report_type=REPORT_TYPE_INVESTIGATION,
        report_version=REPORT_VERSION_DETECTION,
        forensix_version=__version__,
        case_id=case_id.strip() if case_id and isinstance(case_id, str) else None,
        case_name=case_name.strip() if case_name and isinstance(case_name, str) else None,
        investigator=investigator.strip() if investigator and isinstance(investigator, str) else None,
        generated_at=gen_at_str,
        event_count=len(sorted_events),
        correlation_count=len(sorted_corrs),
        detection_count=len(sorted_dets),
        matched_detections=matched_count,
        rule_counts=dict(sorted(rule_counts.items())),
        relationship_counts=dict(sorted(rel_counts.items())),
        detections=tuple(sorted_dets),
        correlations=tuple(sorted_corrs),
        timeline_events=tuple(sorted_events),
    )


# Alias
generate_investigation_report = generate_correlation_detection_report


def render_correlation_detection_json(
    detections: Union[DetectionResultCollection, Sequence[DetectionResult]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
    timeline: Optional[Union[ReconstructedTimeline, Sequence[TimelineEvent]]] = None,
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> str:
    """Render an integrated correlation and detection report as a formatted JSON string."""
    report = generate_correlation_detection_report(
        detections=detections,
        correlations=correlations,
        timeline=timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def write_correlation_detection_json_report(
    detections: Union[DetectionResultCollection, Sequence[DetectionResult]],
    output_path: Union[str, Path],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
    timeline: Optional[Union[ReconstructedTimeline, Sequence[TimelineEvent]]] = None,
    indent: int = 2,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> Path:
    """Write an integrated correlation and detection JSON report to the destination path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_correlation_detection_json(
        detections=detections,
        correlations=correlations,
        timeline=timeline,
        indent=indent,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    path.write_text(content, encoding="utf-8")
    return path


def render_correlation_detection_html(
    detections: Union[DetectionResultCollection, Sequence[DetectionResult]],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
    timeline: Optional[Union[ReconstructedTimeline, Sequence[TimelineEvent]]] = None,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> str:
    """Render an integrated correlation and detection report as a standalone HTML5 forensic report."""
    report = generate_correlation_detection_report(
        detections=detections,
        correlations=correlations,
        timeline=timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )

    event_map = {e.event_id: e for e in report.timeline_events}
    corr_map = {c.correlation_id: c for c in report.correlations}

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

    # Detections HTML blocks
    det_blocks: List[str] = []
    for d in report.detections:
        start_ts = format_iso_timestamp(d.start_timestamp, use_z=True) if d.start_timestamp else "None"
        end_ts = format_iso_timestamp(d.end_timestamp, use_z=True) if d.end_timestamp else "None"
        delta_str = f"{d.time_delta_seconds:.1f}s" if d.time_delta_seconds is not None else "N/A"

        # Resolved correlations
        corr_items: List[str] = []
        for cid in d.matched_correlation_ids:
            if cid in corr_map:
                c_obj = corr_map[cid]
                r_type = c_obj.relationship_type.value if hasattr(c_obj.relationship_type, "value") else c_obj.relationship_type
                c_delta = f"{c_obj.time_delta_seconds:.1f}s" if c_obj.time_delta_seconds is not None else "N/A"
                corr_items.append(
                    f"<li><code>{esc(cid)}</code> &mdash; <strong>{esc(r_type)}</strong> (delta: {esc(c_delta)}) &mdash; {esc(c_obj.description)}</li>"
                )
            else:
                corr_items.append(f"<li><code>{esc(cid)}</code></li>")

        # Resolved supporting events
        event_rows: List[str] = []
        for eid in d.matched_event_ids:
            if eid in event_map:
                ev = event_map[eid]
                ev_ts = format_iso_timestamp(ev.timestamp, use_z=True) if ev.timestamp else (ev.raw_timestamp or "None")
                cat_val = ev.category.value if hasattr(ev.category, "value") else str(ev.category)
                prov_parts = []
                if ev.source_path:
                    prov_parts.append(f"Path: {esc(ev.source_path)}")
                if ev.source_line is not None:
                    prov_parts.append(f"Line: {ev.source_line}")
                if ev.source_event_id:
                    prov_parts.append(f"Event ID: {esc(ev.source_event_id)}")
                if ev.source_artifact_id:
                    prov_parts.append(f"Artifact: {esc(ev.source_artifact_id)}")
                prov_str = " | ".join(prov_parts) if prov_parts else "N/A"

                event_rows.append(f"""<tr>
                    <td><code>{esc(ev.event_id)}</code></td>
                    <td>{esc(ev_ts)}</td>
                    <td><span class='cat-badge'>{esc(cat_val)}</span></td>
                    <td><code>{esc(ev.event_type)}</code></td>
                    <td>{esc(ev.description)}</td>
                    <td><small>{prov_str}</small></td>
                </tr>""")
            else:
                event_rows.append(f"<tr><td><code>{esc(eid)}</code></td><td colspan='5'><em>Event details omitted</em></td></tr>")

        block = f"""<div class='detection-card'>
            <div class='det-header'>
                <span class='det-title'>{esc(d.rule_name)}</span>
                <span class='badge-success'>MATCHED</span>
            </div>
            <div class='det-meta'>
                <div><strong>Detection ID:</strong> <code>{esc(d.detection_id)}</code></div>
                <div><strong>Rule ID:</strong> <code>{esc(d.rule_id)}</code></div>
                <div><strong>Time Range:</strong> {esc(start_ts)} &rarr; {esc(end_ts)} (Delta: {esc(delta_str)})</div>
            </div>
            <div class='det-explanation'><strong>Factual Explanation:</strong> {esc(d.explanation)}</div>
            {f"<div class='sub-section'><strong>Supporting Correlations:</strong><ul>{''.join(corr_items)}</ul></div>" if corr_items else ""}
            <div class='sub-section'>
                <strong>Supporting Timeline Events:</strong>
                <table class='nested-table'>
                    <thead><tr><th>Event ID</th><th>Timestamp</th><th>Category</th><th>Event Type</th><th>Description</th><th>Source Provenance</th></tr></thead>
                    <tbody>{''.join(event_rows)}</tbody>
                </table>
            </div>
        </div>"""
        det_blocks.append(block)

    dets_html = "\n".join(det_blocks) if det_blocks else "<p><em>No detection matches identified.</em></p>"

    corr_list_items: List[str] = []
    for c in report.correlations:
        rel_label = c.relationship_type.value if hasattr(c.relationship_type, "value") else c.relationship_type
        corr_list_items.append(f"<li><code>{esc(c.correlation_id)}</code> &mdash; <strong>{esc(rel_label)}</strong> &mdash; {esc(c.description)}</li>")
    corrs_html = f"<ul>{''.join(corr_list_items)}</ul>" if corr_list_items else "<p><em>No correlations recorded.</em></p>"

    ev_list_items: List[str] = []
    for e in report.timeline_events:
        ev_list_items.append(f"<li><code>{esc(e.event_id)}</code> &mdash; {esc(e.event_type)} &mdash; {esc(e.description)}</li>")
    events_html = f"<ul>{''.join(ev_list_items)}</ul>" if ev_list_items else "<p><em>No timeline events recorded.</em></p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForensiX Correlation & Detection Investigation Report</title>
<style>
  :root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --border: #334155;
    --card-border: #475569;
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
  .summary-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--bg-secondary);
    padding: 16px;
    border-radius: 6px;
    border-left: 4px solid var(--accent);
  }}
  .stat-val {{ font-size: 24px; font-weight: bold; color: var(--text-primary); }}
  .stat-lbl {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; }}
  .detection-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }}
  .det-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
  .det-title {{ font-size: 18px; font-weight: bold; color: var(--accent); }}
  .badge-success {{
    background: #064e3b;
    color: #6ee7b7;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 0.5px;
  }}
  .det-meta {{
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 12px;
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .det-meta code {{ color: #e2e8f0; }}
  .det-explanation {{
    background: rgba(56, 189, 248, 0.05);
    border-left: 3px solid var(--accent);
    padding: 10px 14px;
    margin-bottom: 16px;
    font-size: 14px;
  }}
  .sub-section {{ margin-top: 14px; font-size: 13px; }}
  .sub-section ul {{ margin: 6px 0 0 0; padding-left: 20px; }}
  .nested-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 8px;
    font-size: 12px;
  }}
  .nested-table th, .nested-table td {{
    padding: 8px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  .nested-table th {{
    background: #111e33;
    color: var(--text-secondary);
    font-size: 11px;
  }}
  .cat-badge {{
    background: #1e3a5f;
    color: #7dd3fc;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
  }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>ForensiX Correlation & Detection Investigation Report</h1>
  <div class="version-tag">ForensiX Automated Digital Forensics & Incident Triage Platform (v{esc(report.forensix_version)}) | Schema v{esc(report.report_version)}</div>
</div>

{meta_html}

<div class="summary-section">
  <h2>Investigation Summary</h2>
  <div class="summary-bar">
    <div class="stat-card"><div class="stat-val">{report.event_count}</div><div class="stat-lbl">Timeline Events</div></div>
    <div class="stat-card"><div class="stat-val">{report.correlation_count}</div><div class="stat-lbl">Correlations</div></div>
    <div class="stat-card"><div class="stat-val">{report.detection_count}</div><div class="stat-lbl">Detections Matched</div></div>
  </div>
</div>

<h2>Detection Results</h2>
{dets_html}

<h2>Correlations</h2>
<div class="correlations-section">
  {corrs_html}
</div>

<h2>Timeline Events</h2>
<div class="timeline-section">
  {events_html}
</div>

</body>
</html>
"""


def write_correlation_detection_html_report(
    detections: Union[DetectionResultCollection, Sequence[DetectionResult]],
    output_path: Union[str, Path],
    correlations: Optional[Union[CorrelationCollection, Sequence[Correlation]]] = None,
    timeline: Optional[Union[ReconstructedTimeline, Sequence[TimelineEvent]]] = None,
    *,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    investigator: Optional[str] = None,
    generated_at: Optional[Union[str, datetime]] = None,
    matched_only: bool = False,
) -> Path:
    """Write an integrated correlation and detection HTML report to the destination path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_correlation_detection_html(
        detections=detections,
        correlations=correlations,
        timeline=timeline,
        case_id=case_id,
        case_name=case_name,
        investigator=investigator,
        generated_at=generated_at,
        matched_only=matched_only,
    )
    path.write_text(content, encoding="utf-8")
    return path
