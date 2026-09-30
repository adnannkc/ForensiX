"""
HTML Presentation Layer for ForensiX Reports (V2.8).

Generates completely standalone, self-contained HTML forensic reports.
Contains zero external dependencies or CDN links, ensuring offline air-gapped forensic utility.

Security & Integrity Guarantees:
- All evidence-controlled content (paths, raw lines, payloads, usernames) is strictly
  escaped using html.escape(..., quote=True).
- Special characters and embedded scripts/tags in evidence never become executable HTML/JS.
- Clean semantic HTML5 layout with embedded CSS.
"""

import html
import json
from pathlib import Path
from typing import Union

from forensix.report_models import ForensicReport


def esc(value: Union[str, int, float, None]) -> str:
    """Safely escape text for inclusion in HTML attributes or body text."""
    if value is None:
        return "<em>None</em>"
    return html.escape(str(value), quote=True)


def render_html_report(report: ForensicReport) -> str:
    """
    Render a ForensicReport as a standalone, securely escaped HTML5 document.

    Includes the 6 required sections:
    1. Case Information
    2. Investigation Summary
    3. Artifact Statistics
    4. Artifacts
    5. Source / Lineage Information
    6. Audit Information
    """
    if not isinstance(report, ForensicReport):
        raise TypeError(f"report must be ForensicReport, got {type(report).__name__}")

    meta = report.metadata

    # 1. Category and Status statistics tables
    cat_rows = "".join(
        f"<tr><td><code>{esc(cat)}</code></td><td class='num'>{cnt}</td></tr>"
        for cat, cnt in report.category_breakdown
    )
    stat_rows = "".join(
        f"<tr><td><span class='badge badge-{esc(stat.lower())}'>{esc(stat)}</span></td><td class='num'>{cnt}</td></tr>"
        for stat, cnt in report.status_breakdown
    )

    # 2. Artifact rows (Section 4)
    art_rows = []
    for art in report.artifacts:
        line_str = str(art.line_number) if art.line_number is not None else "-"
        raw_cell = f"<pre class='raw-line'>{esc(art.raw_data)}</pre>" if art.raw_data else "<em>None</em>"
        payload_json = (
            json.dumps(art.specialized_payload.to_dict(), indent=2, ensure_ascii=False)
            if hasattr(art.specialized_payload, "to_dict")
            else "{}"
        )
        art_rows.append(
            f"<tr>"
            f"<td><code>{esc(art.unified_id)}</code></td>"
            f"<td><span class='badge'>{esc(art.category)}</span></td>"
            f"<td><code>{esc(art.artifact_type)}</code></td>"
            f"<td><code>{esc(art.source_id)}</code></td>"
            f"<td><span class='path-cell'>{esc(art.source_path)}</span></td>"
            f"<td class='num'>{esc(line_str)}</td>"
            f"<td><span class='badge badge-{esc(art.status.lower())}'>{esc(art.status)}</span></td>"
            f"<td>{raw_cell}</td>"
            f"<td><details><summary>Payload</summary><pre class='payload-pre'>{esc(payload_json)}</pre></details></td>"
            f"</tr>"
        )
    artifacts_table_content = "\n".join(art_rows) if art_rows else "<tr><td colspan='9'><em>No artifacts recorded.</em></td></tr>"

    # 3. Source / Lineage rows (Section 5)
    lineage_rows = []
    for art in report.artifacts:
        lineage_rows.append(
            f"<tr>"
            f"<td><code>{esc(art.unified_id)}</code></td>"
            f"<td><code>{esc(art.source_id)}</code></td>"
            f"<td>{esc(art.source_event_id) if art.source_event_id else '<em>None</em>'}</td>"
            f"<td>{esc(art.source_artifact_id) if art.source_artifact_id else '<em>None</em>'}</td>"
            f"<td><span class='path-cell'>{esc(art.source_path)}</span></td>"
            f"</tr>"
        )
    lineage_table_content = "\n".join(lineage_rows) if lineage_rows else "<tr><td colspan='5'><em>No lineage records available.</em></td></tr>"

    # 4. Audit Trail rows (Section 6)
    audit_rows = []
    for ev in report.audit_trail:
        audit_rows.append(
            f"<tr>"
            f"<td><code>{esc(ev.audit_id)}</code></td>"
            f"<td><span class='badge'>{esc(ev.event_type)}</span></td>"
            f"<td><time>{esc(ev.timestamp)}</time></td>"
            f"<td>{esc(ev.actor) if ev.actor else '<em>System</em>'}</td>"
            f"<td>{esc(ev.related_id) if ev.related_id else '-'}</td>"
            f"<td>{esc(ev.description)}</td>"
            f"</tr>"
        )
    audit_table_content = "\n".join(audit_rows) if audit_rows else "<tr><td colspan='6'><em>No audit events recorded.</em></td></tr>"

    # 5. Optional Pipeline Execution & Traceability (Section 7)
    stages_section = ""
    if report.stage_results or report.trace_records:
        stage_rows = []
        for s in report.stage_results:
            st_name = getattr(s, "stage_name", "") or getattr(s, "stage_id", "")
            status = getattr(s, "status", "")
            rec_cnt = getattr(s, "records_produced", 0)
            dur = getattr(s, "duration_seconds", None)
            dur_str = f"{dur:.4f}" if dur is not None else "-"
            warns = list(getattr(s, "warnings", ()))
            errs = [getattr(e, "error_message", getattr(e, "message", str(e))) for e in getattr(s, "errors", ())]
            issues = warns + errs
            issues_cell = f"<pre class='raw-line'>{esc('; '.join(issues))}</pre>" if issues else "<em>None</em>"
            stage_rows.append(
                f"<tr>"
                f"<td><code>{esc(st_name)}</code></td>"
                f"<td><span class='badge badge-{esc(status.lower())}'>{esc(status)}</span></td>"
                f"<td class='num'>{rec_cnt}</td>"
                f"<td class='num'>{esc(dur_str)}</td>"
                f"<td>{issues_cell}</td>"
                f"</tr>"
            )
        stages_table_content = "\n".join(stage_rows) if stage_rows else "<tr><td colspan='5'><em>No stage records.</em></td></tr>"

        trace_rows = []
        for tr in report.trace_records:
            t_stage = getattr(tr, "stage_id", "")
            t_status = getattr(tr, "stage_status", "")
            t_in = ", ".join(getattr(tr, "input_identifiers", ())) or "None"
            t_out = ", ".join(getattr(tr, "output_identifiers", ())) or "None"
            t_src_art = ", ".join(getattr(tr, "source_artifact_ids", ())) or "None"
            t_src_evt = ", ".join(getattr(tr, "source_event_ids", ())) or "None"
            t_paths = ", ".join(getattr(tr, "source_paths", ())) or "None"
            t_ts = getattr(tr, "timestamp", "")
            trace_rows.append(
                f"<tr>"
                f"<td><code>{esc(t_stage)}</code></td>"
                f"<td><span class='badge badge-{esc(t_status.lower())}'>{esc(t_status)}</span></td>"
                f"<td><span class='path-cell'>{esc(t_in)}</span></td>"
                f"<td><span class='path-cell'>{esc(t_out)}</span></td>"
                f"<td>{esc(t_src_art)}</td>"
                f"<td>{esc(t_src_evt)}</td>"
                f"<td><span class='path-cell'>{esc(t_paths)}</span></td>"
                f"<td><time>{esc(t_ts)}</time></td>"
                f"</tr>"
            )
        trace_table_content = "\n".join(trace_rows) if trace_rows else "<tr><td colspan='8'><em>No trace records.</em></td></tr>"

        stages_section = f"""
<!-- 7. Pipeline Execution & Traceability -->
<h2>7. Pipeline Execution & Traceability</h2>
<div class="section" style="overflow-x: auto;">
  <h3 style="margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase;">Stage Execution Results</h3>
  <table>
    <thead>
      <tr>
        <th>Stage</th>
        <th>Status</th>
        <th class="num">Records Produced</th>
        <th class="num">Duration (s)</th>
        <th>Warnings & Errors</th>
      </tr>
    </thead>
    <tbody>
      {stages_table_content}
    </tbody>
  </table>
  <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase;">Provenance Trace Records</h3>
  <table>
    <thead>
      <tr>
        <th>Stage</th>
        <th>Status</th>
        <th>Input Identifiers</th>
        <th>Output Identifiers</th>
        <th>Source Artifact IDs</th>
        <th>Source Event IDs</th>
        <th>Source Evidence Paths</th>
        <th>Timestamp (UTC)</th>
      </tr>
    </thead>
    <tbody>
      {trace_table_content}
    </tbody>
  </table>
</div>
"""

    triage_box = (
        f"""    <div class="metric-box">
      <div class="metric-title">Triage ID</div>
      <div class="metric-val" style="font-size: 1rem;"><code>{esc(meta.triage_id)}</code></div>
    </div>\n"""
        if meta.triage_id
        else ""
    )

    # Standalone HTML Template with embedded CSS (Zero external CDN)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForensiX Forensic Report - {esc(meta.report_id)}</title>
<style>
:root {{
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-alt: #334155;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --border: #475569;
  --code-bg: #090d16;
  --success: #22c55e;
  --warning: #f59e0b;
  --danger: #ef4444;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 2rem;
}}
.container {{ max-width: 1400px; margin: 0 auto; }}
header {{
  border-bottom: 2px solid var(--border);
  padding-bottom: 1.5rem;
  margin-bottom: 2rem;
}}
h1 {{ color: var(--accent); font-size: 1.875rem; margin-bottom: 0.5rem; }}
h2 {{ color: var(--text); font-size: 1.25rem; margin-top: 2rem; margin-bottom: 1rem; border-left: 4px solid var(--accent); padding-left: 0.5rem; }}
.section {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 2rem;
}}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
.grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
.metric-box {{
  background: var(--surface-alt);
  padding: 1rem;
  border-radius: 4px;
  border: 1px solid var(--border);
}}
.metric-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: bold; }}
.metric-val {{ font-size: 1.5rem; font-weight: bold; color: var(--accent); margin-top: 0.25rem; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
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
}}
td.num {{ text-align: right; }}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background-color: var(--code-bg);
  padding: 0.2rem 0.4rem;
  border-radius: 3px;
  font-size: 0.8125rem;
  color: var(--accent);
}}
.path-cell {{ font-family: ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }}
.raw-line {{
  font-family: ui-monospace, monospace;
  background-color: var(--code-bg);
  padding: 0.35rem 0.5rem;
  border-radius: 3px;
  max-width: 400px;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 0.75rem;
}}
.payload-pre {{
  font-family: ui-monospace, monospace;
  background-color: var(--code-bg);
  padding: 0.5rem;
  border-radius: 3px;
  max-width: 500px;
  max-height: 250px;
  overflow: auto;
  font-size: 0.75rem;
}}
.badge {{
  display: inline-block;
  padding: 0.15rem 0.4rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
  background-color: var(--surface-alt);
}}
.badge-success, .badge-parsed {{ background-color: rgba(34, 197, 94, 0.2); color: var(--success); }}
.badge-unparsed, .badge-warning {{ background-color: rgba(245, 158, 11, 0.2); color: var(--warning); }}
.badge-failure, .badge-malformed {{ background-color: rgba(239, 68, 68, 0.2); color: var(--danger); }}
.badge-collected {{ background-color: rgba(56, 189, 248, 0.2); color: var(--accent); }}
details summary {{ cursor: pointer; color: var(--accent); font-size: 0.8125rem; }}
footer {{
  text-align: center;
  margin-top: 3rem;
  color: var(--text-muted);
  font-size: 0.8125rem;
  border-top: 1px solid var(--border);
  padding-top: 1rem;
}}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>ForensiX Forensic Investigation Report</h1>
  <p style="color: var(--text-muted);">Platform Version: <code>{esc(meta.forensix_version)}</code> | Generated: <code>{esc(meta.created_at)}</code></p>
</header>

<!-- 1. Case Information -->
<h2>1. Case Information</h2>
<div class="section">
  <div class="grid-4">
    <div class="metric-box">
      <div class="metric-title">Report ID</div>
      <div class="metric-val" style="font-size: 1rem;"><code>{esc(meta.report_id)}</code></div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Case ID</div>
      <div class="metric-val" style="font-size: 1rem;">{esc(meta.case_id)}</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Case Name</div>
      <div class="metric-val" style="font-size: 1rem;">{esc(meta.case_name)}</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Investigator</div>
      <div class="metric-val" style="font-size: 1rem;">{esc(meta.investigator)}</div>
    </div>
{triage_box}  </div>
</div>

<!-- 2. Investigation Summary -->
<h2>2. Investigation Summary</h2>
<div class="section">
  <div class="grid-4">
    <div class="metric-box">
      <div class="metric-title">Evidence Target Root</div>
      <div class="metric-val" style="font-size: 0.9rem;"><code>{esc(meta.evidence_root)}</code></div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Total Host Artifacts</div>
      <div class="metric-val">{report.total_artifacts}</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Distinct Categories</div>
      <div class="metric-val">{len(report.category_breakdown)}</div>
    </div>
    <div class="metric-box">
      <div class="metric-title">Audit Trail Entries</div>
      <div class="metric-val">{len(report.audit_trail)}</div>
    </div>
  </div>
</div>

<!-- 3. Artifact Statistics -->
<h2>3. Artifact Statistics</h2>
<div class="section grid-2">
  <div>
    <h3 style="margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase;">Category Breakdown</h3>
    <table>
      <thead><tr><th>Category</th><th class="num">Count</th></tr></thead>
      <tbody>{cat_rows if cat_rows else '<tr><td colspan="2"><em>No categories</em></td></tr>'}</tbody>
    </table>
  </div>
  <div>
    <h3 style="margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase;">Status Breakdown</h3>
    <table>
      <thead><tr><th>Status</th><th class="num">Count</th></tr></thead>
      <tbody>{stat_rows if stat_rows else '<tr><td colspan="2"><em>No status records</em></td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- 4. Artifacts -->
<h2>4. Artifacts</h2>
<div class="section" style="overflow-x: auto;">
  <table>
    <thead>
      <tr>
        <th>Unified ID</th>
        <th>Category</th>
        <th>Type</th>
        <th>Source ID</th>
        <th>Source Path</th>
        <th class="num">Line</th>
        <th>Status</th>
        <th>Raw Data / Line</th>
        <th>Specialized Payload</th>
      </tr>
    </thead>
    <tbody>
      {artifacts_table_content}
    </tbody>
  </table>
</div>

<!-- 5. Source / Lineage Information -->
<h2>5. Source / Lineage Information</h2>
<div class="section" style="overflow-x: auto;">
  <table>
    <thead>
      <tr>
        <th>Unified ID</th>
        <th>Source Record ID</th>
        <th>Source Event ID (EVT-xxx)</th>
        <th>Source Artifact ID (ART-xxx)</th>
        <th>Source Evidence Path</th>
      </tr>
    </thead>
    <tbody>
      {lineage_table_content}
    </tbody>
  </table>
</div>

<!-- 6. Audit Information -->
<h2>6. Audit Information</h2>
<div class="section" style="overflow-x: auto;">
  <table>
    <thead>
      <tr>
        <th>Audit ID</th>
        <th>Event Type</th>
        <th>Timestamp (UTC)</th>
        <th>Actor</th>
        <th>Related ID</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {audit_table_content}
    </tbody>
  </table>
</div>

{stages_section}
<footer>
  <p>ForensiX Digital Forensics & Incident Triage Platform | Confidential Investigative Data</p>
</footer>

</div>
</body>
</html>
"""


def write_html_report(
    report: ForensicReport,
    output_path: Union[str, Path],
) -> Path:
    """
    Write a rendered HTML forensic report to the explicitly requested destination path.

    Strict boundary: Writes only the destination report file. Never accesses evidence.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_html_report(report)
    path.write_text(content, encoding="utf-8")
    return path
