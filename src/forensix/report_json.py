"""
JSON Presentation & Serialization Layer for ForensiX Reports (V2.8).

Converts ForensicReport objects into canonical, UTF-8 JSON representations.
Guarantees 100% JSON-safe primitive types, deterministic formatting, and preservation
of complete specialized payloads and null values.
"""

import json
from pathlib import Path
from typing import Union

from forensix.report_models import ForensicReport


def render_json_report(report: ForensicReport, indent: int = 2) -> str:
    """
    Render a ForensicReport instance as a formatted UTF-8 JSON string.

    Guarantees:
    - Standard JSON compliance
    - Deterministic structure
    - Preserves nested specialized payloads, raw data, and null values
    - Zero Python object pointers or non-serializable types
    """
    if not isinstance(report, ForensicReport):
        raise TypeError(f"report must be ForensicReport, got {type(report).__name__}")

    report_dict = report.to_dict()
    return json.dumps(report_dict, indent=indent, ensure_ascii=False)


def write_json_report(
    report: ForensicReport,
    output_path: Union[str, Path],
    indent: int = 2,
) -> Path:
    """
    Write a rendered JSON forensic report to the explicitly requested destination path.

    Strict boundary: Writes only the destination report file. Never accesses evidence.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_json_report(report, indent=indent)
    path.write_text(content, encoding="utf-8")
    return path
