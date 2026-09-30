"""
Forensic Report Generation Module for ForensiX.

Responsible for serializing a ForensicAnalysisResult into a standardized,
human-readable JSON forensic report stored under the reports/ directory,
keeping reports strictly separated from original evidence files.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Union
import json
import re

from forensix.analyzer import ForensicAnalysisResult

DEFAULT_REPORTS_DIR = Path("reports")
DEFAULT_INDENT = 4


def sanitize_filename(name: str) -> str:
    """
    Sanitize an identifier to ensure it forms a safe, path-traversal-free filename.

    Removes traversal dot sequences, replaces path separators and unsafe characters
    with underscores, strips leading/trailing periods/underscores, and collapses
    multiple consecutive underscores.

    Args:
        name: Raw identifier or candidate filename.

    Returns:
        str: Sanitized safe filename string.
    """
    # Remove traversal dot sequences (e.g. '..')
    sanitized = re.sub(r"\.\.+", "", name)
    # Replace path separators and unsafe characters with '_'
    sanitized = re.sub(r"[/\\|&;:?*<>\"`]", "_", sanitized)
    sanitized = re.sub(r"[^\w\-.]", "_", sanitized)
    # Strip leading/trailing underscores and periods
    sanitized = sanitized.strip("._")
    # Collapse multiple consecutive underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    return sanitized or "report"


def generate_json_report(
    analysis_result: Union[ForensicAnalysisResult, Dict[str, Any]],
    output_dir: Union[str, Path] = DEFAULT_REPORTS_DIR,
    filename: Optional[str] = None,
    indent: int = DEFAULT_INDENT,
) -> Path:
    """
    Generate a formatted JSON forensic report from a ForensicAnalysisResult.

    Forensic Design Principles:
    - The generated report is a derived artifact; original evidence is NEVER modified.
    - Reports are saved in UTF-8 encoding with deterministic, indented JSON formatting.
    - Generated reports are isolated in the reports/ directory and never mixed with evidence files.
    - Filenames are derived safely from the evidence ID to prevent path traversal.

    Args:
        analysis_result: A ForensicAnalysisResult instance or compatible dictionary.
        output_dir: Target directory for generated reports (default: 'reports').
        filename: Optional explicit filename. If omitted, '<evidence_id>.json' is used.
        indent: Indentation level for pretty-printed JSON (default: 4).

    Returns:
        Path: Resolved absolute path to the generated JSON report.

    Raises:
        ValueError: If analysis_result data structure is missing required sections,
                    or if a path traversal attempt is detected.
        OSError: If the report directory cannot be created or the file cannot be written.
    """
    # Extract data dictionary from dataclass or dict
    if isinstance(analysis_result, ForensicAnalysisResult):
        data = analysis_result.to_dict()
    elif isinstance(analysis_result, dict):
        data = analysis_result
    else:
        raise TypeError(
            f"Expected ForensicAnalysisResult or dict, got {type(analysis_result).__name__}"
        )

    # Validate essential schema sections
    required_sections = ("evidence", "file", "metadata", "hashes")
    missing_sections = [sec for sec in required_sections if sec not in data]
    if missing_sections:
        raise ValueError(
            f"Incomplete analysis result; missing required sections: {missing_sections}"
        )

    # Prepare output directory
    target_dir = Path(output_dir).resolve()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise OSError(f"Failed to create report directory '{target_dir}': {err.strerror}") from err

    # Determine safe filename
    if filename is None:
        evidence_id = str(data.get("evidence", {}).get("evidence_id", "evidence"))
        safe_name = sanitize_filename(evidence_id)
        report_filename = f"{safe_name}.json"
    else:
        safe_name = sanitize_filename(filename)
        report_filename = safe_name if safe_name.endswith(".json") else f"{safe_name}.json"

    report_path = (target_dir / report_filename).resolve()

    # Guard against path traversal: ensure resolved path is inside target_dir
    try:
        report_path.relative_to(target_dir)
    except ValueError as err:
        raise ValueError(f"Path traversal detected: '{report_filename}' resolves outside target directory") from err

    # Serialize to JSON with human-readable indentation
    try:
        json_content = json.dumps(data, indent=indent, ensure_ascii=False) + "\n"
        report_path.write_text(json_content, encoding="utf-8")
    except PermissionError as err:
        raise PermissionError(f"Permission denied writing report to '{report_path}'") from err
    except OSError as err:
        raise OSError(f"Failed to write forensic report to '{report_path}': {err.strerror}") from err

    return report_path
