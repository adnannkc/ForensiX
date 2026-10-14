"""
Forensic Memory Command-Line Interface for ForensiX (V6.8).

Orchestrates artifact-based memory incident triage from the CLI:
1. Validates and parses input paths representing extracted memory artifacts.
2. Reconstructs in-memory artifact collections into strongly typed models.
3. Executes end-to-end memory timeline reconstruction, memory correlation,
   and rule-based detection via existing V6.7 run_memory_triage().
4. Generates structured JSON or self-contained HTML investigation reports
   via existing V4.6 / V6.7 reporting serializers.
5. Emits factual, deterministic terminal summaries and standard exit codes.

Strict Boundaries:
- Non-Destructive: Treats evidence as strictly read-only; never alters evidence files.
- Deterministic: Produces stable output ordering and deterministic identifiers.
- Artifact-Based: Operates on already-extracted memory artifacts (JSON). Does not
  perform live hardware acquisition or automatic raw image extraction.
- Clear Diagnostics: Returns exit code 1 with actionable errors; exit code 0 on success;
  exit code 2 on CLI argument syntax errors.
"""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.detection_reporting import CorrelationDetectionReport
from forensix.memory_models import (
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
)
from forensix.memory_triage import (
    MemoryTriageConfig,
    MemoryTriageResult,
    run_memory_triage,
)

SUPPORTED_FORMATS: Tuple[str, ...] = ("html", "json")
DEFAULT_FORMAT: str = "html"
DEFAULT_REPORTS_DIR = Path("reports")
RAW_IMAGE_EXTENSIONS: Tuple[str, ...] = (
    ".raw",
    ".lime",
    ".dmp",
    ".vmem",
    ".dd",
    ".bin",
    ".img",
)


def _deserialize_process_artifact(data: Dict[str, Any]) -> MemoryProcessArtifact:
    """Reconstruct a MemoryProcessArtifact from its serialized dictionary representation."""
    raw_attrs = data.get("raw_attributes", {})
    if isinstance(raw_attrs, dict):
        frozen_attrs = tuple((str(k), v) for k, v in sorted(raw_attrs.items()))
    elif isinstance(raw_attrs, (list, tuple)):
        frozen_attrs = tuple((str(k), v) for k, v in raw_attrs if isinstance(k, (str, int)))
    else:
        frozen_attrs = ()

    source_indices = data.get("source_row_indices", ())
    if isinstance(source_indices, (list, tuple)):
        clean_indices = tuple(int(i) for i in source_indices if isinstance(i, int) and i >= 0)
    else:
        clean_indices = ()

    return MemoryProcessArtifact(
        artifact_id=data["artifact_id"],
        evidence_id=data["evidence_id"],
        pid=int(data["pid"]),
        process_name=str(data["process_name"]),
        source_plugin=str(data.get("source_plugin", "unknown")),
        ppid=int(data["ppid"]) if data.get("ppid") is not None else None,
        created_at=str(data["created_at"]) if data.get("created_at") is not None else None,
        exit_time=str(data["exit_time"]) if data.get("exit_time") is not None else None,
        offset=str(data["offset"]) if data.get("offset") is not None else None,
        execution_id=str(data["execution_id"]) if data.get("execution_id") is not None else None,
        source_row_indices=clean_indices,
        raw_attributes=frozen_attrs,
    )


def _deserialize_module_artifact(data: Dict[str, Any]) -> MemoryModuleArtifact:
    """Reconstruct a MemoryModuleArtifact from its serialized dictionary representation."""
    raw_attrs = data.get("raw_attributes", {})
    if isinstance(raw_attrs, dict):
        frozen_attrs = tuple((str(k), v) for k, v in sorted(raw_attrs.items()))
    elif isinstance(raw_attrs, (list, tuple)):
        frozen_attrs = tuple((str(k), v) for k, v in raw_attrs if isinstance(k, (str, int)))
    else:
        frozen_attrs = ()

    source_indices = data.get("source_row_indices", ())
    if isinstance(source_indices, (list, tuple)):
        clean_indices = tuple(int(i) for i in source_indices if isinstance(i, int) and i >= 0)
    else:
        clean_indices = ()

    return MemoryModuleArtifact(
        artifact_id=data["artifact_id"],
        evidence_id=data["evidence_id"],
        module_name=str(data["module_name"]),
        source_plugin=str(data.get("source_plugin", "unknown")),
        base_address=str(data["base_address"]) if data.get("base_address") is not None else None,
        size_bytes=int(data["size_bytes"]) if data.get("size_bytes") is not None else None,
        offset=str(data["offset"]) if data.get("offset") is not None else None,
        driver_path=str(data["driver_path"]) if data.get("driver_path") is not None else None,
        execution_id=str(data["execution_id"]) if data.get("execution_id") is not None else None,
        source_row_indices=clean_indices,
        raw_attributes=frozen_attrs,
    )


def _deserialize_network_artifact(data: Dict[str, Any]) -> MemoryNetworkArtifact:
    """Reconstruct a MemoryNetworkArtifact from its serialized dictionary representation."""
    raw_attrs = data.get("raw_attributes", {})
    if isinstance(raw_attrs, dict):
        frozen_attrs = tuple((str(k), v) for k, v in sorted(raw_attrs.items()))
    elif isinstance(raw_attrs, (list, tuple)):
        frozen_attrs = tuple((str(k), v) for k, v in raw_attrs if isinstance(k, (str, int)))
    else:
        frozen_attrs = ()

    source_indices = data.get("source_row_indices", ())
    if isinstance(source_indices, (list, tuple)):
        clean_indices = tuple(int(i) for i in source_indices if isinstance(i, int) and i >= 0)
    else:
        clean_indices = ()

    return MemoryNetworkArtifact(
        artifact_id=data["artifact_id"],
        evidence_id=data["evidence_id"],
        protocol=str(data["protocol"]),
        source_plugin=str(data.get("source_plugin", "unknown")),
        local_address=str(data["local_address"]) if data.get("local_address") is not None else None,
        local_port=int(data["local_port"]) if data.get("local_port") is not None else None,
        remote_address=str(data["remote_address"]) if data.get("remote_address") is not None else None,
        remote_port=int(data["remote_port"]) if data.get("remote_port") is not None else None,
        state=str(data["state"]) if data.get("state") is not None else None,
        pid=int(data["pid"]) if data.get("pid") is not None else None,
        process_name=str(data["process_name"]) if data.get("process_name") is not None else None,
        offset=str(data["offset"]) if data.get("offset") is not None else None,
        created_at=str(data["created_at"]) if data.get("created_at") is not None else None,
        execution_id=str(data["execution_id"]) if data.get("execution_id") is not None else None,
        source_row_indices=clean_indices,
        raw_attributes=frozen_attrs,
    )


def _deserialize_timeline_event(data: Dict[str, Any]) -> MemoryTimelineEvent:
    """Reconstruct a MemoryTimelineEvent from its serialized dictionary representation."""
    cat_raw = data.get("artifact_category", "PROCESS")
    if isinstance(cat_raw, str):
        try:
            category = MemoryTimelineCategory(cat_raw)
        except ValueError:
            category = MemoryTimelineCategory.PROCESS
    else:
        category = MemoryTimelineCategory.PROCESS

    from datetime import datetime, timezone
    ts_val = None
    if data.get("timestamp"):
        try:
            ts_val = datetime.fromisoformat(str(data["timestamp"]))
            if ts_val.tzinfo is None:
                ts_val = ts_val.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            ts_val = None

    source_indices = data.get("source_row_indices", ())
    if isinstance(source_indices, (list, tuple)):
        clean_indices = tuple(int(i) for i in source_indices if isinstance(i, int) and i >= 0)
    else:
        clean_indices = ()

    attrs = data.get("attributes", {})
    if isinstance(attrs, dict):
        frozen_attrs = tuple((str(k), v) for k, v in sorted(attrs.items()))
    elif isinstance(attrs, (list, tuple)):
        frozen_attrs = tuple((str(k), v) for k, v in attrs)
    else:
        frozen_attrs = ()

    return MemoryTimelineEvent(
        event_id=data["event_id"],
        timestamp=ts_val,
        artifact_category=category,
        event_type=str(data.get("event_type", "MEMORY_EVENT")),
        description=str(data.get("description", "")),
        evidence_id=str(data["evidence_id"]),
        artifact_id=data.get("artifact_id"),
        execution_id=data.get("execution_id"),
        source_plugin=str(data.get("source_plugin", "unknown")),
        source_row_indices=clean_indices,
        raw_timestamp=data.get("raw_timestamp"),
        timestamp_origin=data.get("timestamp_origin"),
        timestamp_limitation=data.get("timestamp_limitation"),
        attributes=frozen_attrs,
    )


def _deserialize_artifact_dict(item: Dict[str, Any]) -> Any:
    """
    Deserialize a single memory artifact dictionary by inspecting its identifier prefix.

    Raises:
        ValueError, TypeError, KeyError: If artifact fields or format are invalid.
    """
    if not isinstance(item, dict):
        raise TypeError(f"Artifact entry must be a dictionary, got {type(item).__name__}")

    aid = item.get("artifact_id")
    eid = item.get("event_id")

    if aid and isinstance(aid, str):
        if aid.startswith("MEMPROC-"):
            return _deserialize_process_artifact(item)
        if aid.startswith("MEMMOD-"):
            return _deserialize_module_artifact(item)
        if aid.startswith("MEMNET-"):
            return _deserialize_network_artifact(item)

    if eid and isinstance(eid, str) and eid.startswith("MEMEVT-"):
        return _deserialize_timeline_event(item)

    # Secondary heuristic by required distinct field names
    if "pid" in item and "process_name" in item and "evidence_id" in item and "protocol" not in item:
        return _deserialize_process_artifact(item)
    if "module_name" in item and "evidence_id" in item:
        return _deserialize_module_artifact(item)
    if "protocol" in item and "evidence_id" in item:
        return _deserialize_network_artifact(item)

    raise ValueError(
        f"Unsupported or unrecognized memory artifact schema: missing valid artifact_id prefix "
        f"(expected MEMPROC-, MEMMOD-, or MEMNET-). Keys present: {sorted(item.keys())}"
    )


def load_memory_artifacts(
    evidence_path: Path,
) -> Tuple[List[Any], Optional[str]]:
    """
    Load and reconstruct memory artifacts from a file or directory of JSON artifact files.

    Returns:
        Tuple[List[Any], Optional[str]]: (reconstructed_artifacts, error_message_if_any)
    """
    if not evidence_path.exists():
        return [], f"Evidence path does not exist: '{evidence_path}'"

    # Check for raw image files
    if evidence_path.is_file():
        ext = evidence_path.suffix.lower()
        if ext in RAW_IMAGE_EXTENSIONS:
            return [], (
                f"Raw memory image '{evidence_path.name}' is not supported in artifact-based memory triage. "
                f"ForensiX memory CLI expects pre-extracted memory artifact JSON files (MEMPROC-, MEMMOD-, MEMNET-). "
                f"Direct raw image extraction requires Volatility 3 and will be supported in a future phase."
            )

        try:
            with open(evidence_path, "r", encoding="utf-8") as f:
                content = json.load(f)
        except json.JSONDecodeError as err:
            return [], f"Malformed JSON in evidence file '{evidence_path}': {err}"
        except (PermissionError, OSError) as err:
            return [], f"Cannot read evidence file '{evidence_path}': {err}"

        items_to_parse: List[Any] = []
        if isinstance(content, list):
            items_to_parse = content
        elif isinstance(content, dict):
            if "artifacts" in content and isinstance(content["artifacts"], list):
                items_to_parse = content["artifacts"]
            else:
                items_to_parse = [content]
        else:
            return [], f"Invalid memory artifact file '{evidence_path}': expected JSON array or object"

        artifacts: List[Any] = []
        for idx, entry in enumerate(items_to_parse):
            try:
                art = _deserialize_artifact_dict(entry)
                artifacts.append(art)
            except Exception as err:
                return [], f"Failed to parse artifact at index {idx} in '{evidence_path}': {err}"

        return artifacts, None

    elif evidence_path.is_dir():
        json_files = sorted(
            p for p in evidence_path.iterdir()
            if p.is_file() and p.suffix.lower() == ".json"
        )
        if not json_files:
            # Check if any raw image files are in the directory to give a helpful diagnostic
            raw_files = [
                p.name for p in evidence_path.iterdir()
                if p.is_file() and p.suffix.lower() in RAW_IMAGE_EXTENSIONS
            ]
            if raw_files:
                return [], (
                    f"Evidence directory '{evidence_path}' contains raw memory images ({', '.join(raw_files[:3])}), "
                    f"but no JSON memory artifact files. Raw image extraction is not enabled in this phase."
                )
            return [], f"Evidence directory '{evidence_path}' contains no JSON memory artifact files"

        all_artifacts: List[Any] = []
        for jf in json_files:
            file_arts, err = load_memory_artifacts(jf)
            if err:
                return [], err
            all_artifacts.extend(file_arts)

        return all_artifacts, None

    else:
        return [], f"Evidence path is neither a file nor a directory: '{evidence_path}'"


def build_memory_parser(
    prog: str = "python3 -m forensix memory",
) -> argparse.ArgumentParser:
    """
    Build and configure the command-line argument parser for V6.8 memory forensics triage.

    Args:
        prog: Program name displayed in help and usage strings.

    Returns:
        argparse.ArgumentParser configured with all memory triage options.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V6 Memory Forensics Triage)",
        epilog=(
            "Executes the ForensiX memory triage pipeline over extracted memory artifacts:\n"
            "artifact loading -> memory timeline reconstruction -> memory correlation ->\n"
            "memory rule detection -> integrated investigation reporting (JSON/HTML)."
        ),
    )

    # Positional argument: evidence path
    parser.add_argument(
        "evidence",
        help="Path to an extracted memory artifact JSON file or directory containing memory artifact files.",
    )

    # Case metadata
    parser.add_argument(
        "--case-id",
        default=None,
        help="Incident case tracking identifier (e.g. CASE-2026-001).",
    )
    parser.add_argument(
        "--case-name",
        default=None,
        help="Human-readable title or description for the investigation.",
    )
    parser.add_argument(
        "--investigator",
        default=None,
        help="Name or identification of the handling forensic investigator.",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        "--output-dir",
        dest="output",
        default=None,
        help="Destination file path or directory for generated investigation report.",
    )
    parser.add_argument(
        "--format",
        default=None,
        help=f"Report presentation format ('html' or 'json', default: '{DEFAULT_FORMAT}').",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Generate report in JSON format (shortcut for --format json).",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        default=False,
        help="Generate report in HTML format (shortcut for --format html).",
    )

    # Detection options
    parser.add_argument(
        "--matched-only",
        action="store_true",
        default=False,
        help="Filter report to include only matched detection rules (default: include all evaluated rules).",
    )

    # Verbose execution
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Display detailed stage-by-stage progress information.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def execute_memory_cli(
    argv: Optional[Sequence[str]] = None,
    parser: Optional[argparse.ArgumentParser] = None,
) -> Tuple[int, Optional[CorrelationDetectionReport]]:
    """
    Execute ForensiX Memory Forensics Triage from CLI arguments.

    Pipeline stages:
    1. Parse and validate CLI inputs (evidence path, format flags, case metadata).
    2. Validate destination path safety (prevent overwriting evidence).
    3. Load already-extracted memory artifacts from JSON file or directory.
    4. Run memory triage pipeline via existing V6.7 run_memory_triage().
    5. Write integrated investigation report (JSON or HTML) via existing V6.7 / V4.6 reporting.
    6. Print concise, factual terminal summary.

    Exit-code semantics:
        0: Successful execution (even if matched detections == 0 or > 0).
        1: User input error, invalid path, format mismatch, or processing failure.
        2: CLI syntax error / unrecognized argument (argparse default).

    Returns:
        Tuple[int, Optional[CorrelationDetectionReport]]: (exit_code, report_instance)
    """
    if parser is None:
        parser = build_memory_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2, None

    evidence_path = Path(args.evidence)

    # 1. Validate evidence existence
    if not evidence_path.exists():
        print(
            f"Error: Evidence path does not exist: '{args.evidence}'",
            file=sys.stderr,
        )
        return 1, None

    # Case ID validation if provided
    if args.case_id is not None and not args.case_id.strip():
        print("Error: Case ID cannot be empty or whitespace.", file=sys.stderr)
        return 1, None

    # 2. Validate output format
    if getattr(args, "json", False) and getattr(args, "html", False):
        print("Error: Cannot specify both --json and --html formats.", file=sys.stderr)
        return 1, None
    elif getattr(args, "json", False):
        report_format = "json"
    elif getattr(args, "html", False):
        report_format = "html"
    elif args.format is not None:
        report_format = args.format.lower().strip()
        if report_format not in SUPPORTED_FORMATS:
            print(
                f"Error: Unsupported report format: '{args.format}'. Supported formats: {', '.join(SUPPORTED_FORMATS)}",
                file=sys.stderr,
            )
            return 1, None
    else:
        if args.output:
            out_p = Path(args.output)
            if not out_p.is_dir():
                out_ext = out_p.suffix.lower()
                if out_ext == ".json":
                    report_format = "json"
                elif out_ext in (".html", ".htm"):
                    report_format = "html"
                else:
                    report_format = DEFAULT_FORMAT
            else:
                report_format = DEFAULT_FORMAT
        else:
            report_format = DEFAULT_FORMAT

    # 3. Determine target report output path safely
    resolved_evidence = evidence_path.resolve()
    slug = args.case_id.strip() if args.case_id else "memory_triage"
    cleaned_slug = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in slug).strip("_")
    safe_slug = cleaned_slug if cleaned_slug else "memory_triage"

    if args.output:
        out_target = Path(args.output).resolve()
        if out_target.is_dir() or str(args.output).endswith(("/", "\\")) or not out_target.suffix:
            out_target.mkdir(parents=True, exist_ok=True)
            target_output = out_target / f"{safe_slug}_investigation.{report_format}"
        else:
            target_output = out_target
    else:
        DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        target_output = (DEFAULT_REPORTS_DIR / f"{safe_slug}_investigation.{report_format}").resolve()

    # Safety check: target report cannot overwrite or enter evidence path
    if target_output == resolved_evidence:
        print(
            f"Error: Output report path cannot be identical to evidence path: '{target_output}'",
            file=sys.stderr,
        )
        return 1, None

    if resolved_evidence.is_dir() and resolved_evidence in target_output.parents:
        print(
            f"Error: Output report path cannot be within evidence directory: '{target_output}'",
            file=sys.stderr,
        )
        return 1, None

    # 4. Load memory artifacts
    if args.verbose:
        print("[1/3] Loading Memory Artifacts...")

    artifacts, load_error = load_memory_artifacts(evidence_path)
    if load_error:
        print(f"Error: {load_error}", file=sys.stderr)
        return 1, None

    if not artifacts:
        print(f"Error: No memory artifacts found in '{args.evidence}'", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: {len(artifacts)} artifacts loaded")

    # 5. Execute memory triage pipeline
    if args.verbose:
        print("[2/3] Executing Memory Triage Pipeline...")

    try:
        triage_config = MemoryTriageConfig(
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
            matched_only=args.matched_only,
            report_formats=(report_format,),
        )
        triage_result: MemoryTriageResult = run_memory_triage(
            artifacts=artifacts,
            config=triage_config,
        )
    except Exception as err:
        print(f"Error: Memory triage execution failed: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        matched_count = sum(1 for d in triage_result.detections if d.matched)
        print(f"      Completed: {len(triage_result.detections)} evaluations ({matched_count} matched)")

    # 6. Generate and write investigation report
    if args.verbose:
        print("[3/3] Generating Memory Triage Report...")

    try:
        written_path = triage_result.write_report(
            output_path=target_output,
            format=report_format,
            matched_only=args.matched_only,
        )
    except (PermissionError, OSError) as err:
        print(
            f"Error: Failed to write memory triage report to '{target_output}': {err}",
            file=sys.stderr,
        )
        return 1, None
    except Exception as err:
        print(f"Error: Memory triage report generation failed: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: Report written to '{written_path}'")

    # 7. Display factual terminal summary
    report = triage_result.generate_report(matched_only=args.matched_only)

    print("=" * 60)
    print(f"ForensiX Memory Forensics Triage (v{__version__})")
    print("=" * 60)
    print(f"Evidence Root           : {resolved_evidence}")
    if report.case_id:
        print(f"Case ID                 : {report.case_id}")
    if report.case_name:
        print(f"Case Name               : {report.case_name}")
    if report.investigator:
        print(f"Investigator            : {report.investigator}")
    print(f"Artifacts Analyzed      : {triage_result.total_artifacts}")
    print(f"Timeline Events         : {report.event_count}")
    print(f"Correlations Identified : {report.correlation_count}")
    print(f"Detection Results       : {report.detection_count}")
    print(f"Matched Detections      : {report.matched_detections}")
    if report.rule_counts:
        print("Rule Matches            :")
        for r_name, r_cnt in sorted(report.rule_counts.items()):
            print(f"  {r_name}: {r_cnt}")
    print(f"Format                  : {report_format.upper()}")
    print(f"Report Path             : {written_path}")
    print("-" * 60)
    print("Status                  : SUCCESS")
    print("=" * 60)

    return 0, report


def memory_main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for ForensiX Memory Forensics Triage (V6.8).

    Returns:
        int: 0 on success, non-zero on error.
    """
    exit_code, _ = execute_memory_cli(argv)
    return exit_code
