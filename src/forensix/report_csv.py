"""
CSV Presentation & Serialization Layer for ForensiX Reports (V2.8).

Converts ForensicReport objects into a standardized, documented tabular CSV format.
Uses Python's standard csv module to ensure robust RFC 4180 compliance, proper quoting,
and correct Unicode escaping.

Documented CSV Schema:
1.  unified_id: Unique HostArtifact tracking ID (HOSTART-xxx)
2.  category: High-level host category (filesystem, log, account, persistence, etc.)
3.  artifact_type: Canonical V2.6 artifact classification
4.  source_id: Original specialized identifier (ART-, EVT-, AUTH-, USER-, PERSIST-, etc.)
5.  source_event_id: Reference to underlying log event ID (EVT-xxx) if applicable
6.  source_artifact_id: Reference to parent evidence file ID (ART-xxx) if applicable
7.  source_path: Exact source path preserved from evidence
8.  line_number: Line number where applicable, or empty string
9.  status: Analyzer status (PARSED, UNPARSED, MALFORMED, COLLECTED, etc.)
10. raw_data: Decoded raw line or configuration text
11. payload_json: Complete serialized specialized payload as a JSON string
"""

import csv
import io
import json
from pathlib import Path
from typing import List, Sequence, Union

from forensix.report_models import ForensicReport

CSV_HEADERS: Sequence[str] = (
    "unified_id",
    "category",
    "artifact_type",
    "source_id",
    "source_event_id",
    "source_artifact_id",
    "source_path",
    "line_number",
    "status",
    "raw_data",
    "payload_json",
)


def render_csv_report(report: ForensicReport) -> str:
    """
    Render artifacts from a ForensicReport as a standard RFC 4180 CSV string.

    Guarantees:
    - Standard CSV quoting and escaping via python csv module
    - Full UTF-8 Unicode support
    - Documented schema retaining all common indexable attributes
    - Preservation of specialized payload data serialized in the payload_json column
    """
    if not isinstance(report, ForensicReport):
        raise TypeError(f"report must be ForensicReport, got {type(report).__name__}")

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")

    # Header row
    writer.writerow(CSV_HEADERS)

    # Data rows
    for art in report.artifacts:
        payload_str = (
            json.dumps(art.specialized_payload.to_dict(), ensure_ascii=False)
            if hasattr(art.specialized_payload, "to_dict")
            else ""
        )
        row = [
            art.unified_id,
            art.category,
            art.artifact_type,
            art.source_id,
            art.source_event_id or "",
            art.source_artifact_id or "",
            art.source_path,
            str(art.line_number) if art.line_number is not None else "",
            art.status,
            art.raw_data or "",
            payload_str,
        ]
        writer.writerow(row)

    return output.getvalue()


def write_csv_report(
    report: ForensicReport,
    output_path: Union[str, Path],
) -> Path:
    """
    Write a rendered CSV forensic report to the explicitly requested destination path.

    Strict boundary: Writes only the destination report file. Never accesses evidence.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_csv_report(report)
    path.write_text(content, encoding="utf-8")
    return path
