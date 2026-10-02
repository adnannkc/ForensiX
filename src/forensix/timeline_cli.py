"""
Command-Line Interface for ForensiX Timeline Reconstruction and Querying (V3.7).

Orchestrates the complete ForensiX V3 Timeline pipeline from the CLI:
1. Evidence directory analysis via existing V2 Triage Orchestration.
2. Artifact adaptation into TimelineEvent objects via V3.3 Artifact Adapters.
3. Chronological timeline reconstruction, ordering, and deduplication via V3.4 Reconstruction.
4. Optional factual multi-criteria filtering via V3.5 Timeline Querying.
5. Structured JSON and self-contained HTML reporting via V3.6 Timeline Reporting.

Strict Boundaries:
- Pure orchestration: delegates all forensic extraction, ordering, querying, and reporting to existing V3 modules.
- Non-destructive: treats evidence as strictly read-only; never alters, executes, or deletes evidence.
- Deterministic: produces stable, reproducible outputs without implicit timestamps or environment metadata.
- Clear error handling: provides clean user-facing error messages and standard exit codes without tracebacks.
"""

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence, Tuple

from forensix import __version__
from forensix.artifact_adapters import adapt_artifacts
from forensix.timeline_models import TimelineCategory
from forensix.timeline_query import TimelineQuery, query_timeline
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.timeline_reporting import (
    TimelineReport,
    generate_timeline_report,
    write_timeline_html_report,
    write_timeline_json_report,
)
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


SUPPORTED_FORMATS: Tuple[str, ...] = ("html", "json")
DEFAULT_FORMAT: str = "html"
DEFAULT_REPORTS_DIR = Path("reports")


def build_timeline_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V3.7 timeline analysis."""
    parser = argparse.ArgumentParser(
        prog="python3 -m forensix timeline",
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V3 Timeline)",
        epilog=(
            "Reconstructs an immutable chronological timeline from evidence artifacts,\n"
            "applies optional factual query filters, and generates structured JSON or HTML reports."
        ),
    )

    # Positional evidence directory
    parser.add_argument(
        "evidence_directory",
        help="Path to the evidence directory containing forensic artifacts and logs.",
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
        default=None,
        help="Destination path for generated timeline report (e.g. ./reports/timeline.html).",
    )
    parser.add_argument(
        "--format",
        default=None,
        help=f"Report presentation format to generate ('html' or 'json', default: '{DEFAULT_FORMAT}').",
    )

    # V3.5 Timeline filter options (Logical AND)
    filter_group = parser.add_argument_group("Timeline Query Filters (Logical AND)")
    filter_group.add_argument(
        "--start",
        default=None,
        help="Earliest event timestamp (inclusive, ISO 8601 string, e.g. '2026-09-30T09:00:00Z').",
    )
    filter_group.add_argument(
        "--end",
        default=None,
        help="Latest event timestamp (inclusive, ISO 8601 string, e.g. '2026-09-30T17:00:00Z').",
    )
    filter_group.add_argument(
        "--category",
        default=None,
        help=(
            "Filter events by factual category. Valid choices: "
            + ", ".join(c.name for c in TimelineCategory)
        ),
    )
    filter_group.add_argument(
        "--event-type",
        default=None,
        help="Filter events by exact event type classification (e.g. 'ssh_login', 'file_created').",
    )
    filter_group.add_argument(
        "--source-path",
        default=None,
        help="Filter events by exact source file path (e.g. '/var/log/auth.log').",
    )
    filter_group.add_argument(
        "--source-artifact-id",
        default=None,
        help="Filter events by parent forensic artifact tracking ID.",
    )
    filter_group.add_argument(
        "--source-event-id",
        default=None,
        help="Filter events by underlying event record ID.",
    )
    filter_group.add_argument(
        "--text",
        default=None,
        help="Filter events by factual text substring across description, raw data, and attributes.",
    )
    filter_group.add_argument(
        "--case-sensitive",
        action="store_true",
        default=False,
        help="Enable case-sensitive matching for text search (default: case-insensitive).",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def execute_timeline_cli(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[int, Optional[TimelineReport]]:
    """
    Execute V3.7 Timeline CLI pipeline from command-line arguments.

    Steps:
    1. Parse and validate arguments (evidence directory, formats, categories, timestamps).
    2. Extract evidence artifacts via existing V2 Triage Orchestrator (read-only, no V2 file reports).
    3. Adapt artifacts into TimelineEvent objects via V3.3 adapters.
    4. Reconstruct, order, and deduplicate events via V3.4 reconstruction.
    5. Optionally filter events via V3.5 querying.
    6. Generate and write report via V3.6 reporting.
    7. Output concise terminal summary.

    Returns:
        Tuple[int, Optional[TimelineReport]]: (exit_code, report_instance)
            exit_code: 0 on success, 1 on user input/runtime error.
    """
    parser = build_timeline_parser()
    args = parser.parse_args(argv)

    evidence_path = Path(args.evidence_directory)

    # 1. Validate evidence directory existence and type
    if not evidence_path.exists():
        print(
            f"Error: Evidence directory does not exist: '{args.evidence_directory}'",
            file=sys.stderr,
        )
        return 1, None

    if not evidence_path.is_dir():
        print(
            f"Error: Evidence path is not a directory: '{args.evidence_directory}'",
            file=sys.stderr,
        )
        return 1, None

    # 2. Validate output format
    raw_format = args.format
    if raw_format is not None:
        report_format = raw_format.lower().strip()
        if report_format not in SUPPORTED_FORMATS:
            print(
                f"Error: Unsupported timeline format: '{raw_format}'. Supported formats: {', '.join(SUPPORTED_FORMATS)}",
                file=sys.stderr,
            )
            return 1, None
    else:
        # If output file specified with known extension, infer format; otherwise default to HTML
        if args.output:
            out_ext = Path(args.output).suffix.lower()
            if out_ext == ".json":
                report_format = "json"
            elif out_ext in (".html", ".htm"):
                report_format = "html"
            else:
                report_format = DEFAULT_FORMAT
        else:
            report_format = DEFAULT_FORMAT

    # 3. Validate category option against TimelineCategory enum
    selected_category: Optional[TimelineCategory] = None
    if args.category is not None:
        cat_clean = args.category.strip().upper()
        valid_cats = {c.name: c for c in TimelineCategory}
        if cat_clean not in valid_cats:
            cat_list = "\n".join(f"  {c.name}" for c in TimelineCategory)
            print(
                f"Error: Invalid category: '{args.category}'\nValid categories:\n{cat_list}",
                file=sys.stderr,
            )
            return 1, None
        selected_category = valid_cats[cat_clean]

    # 4. Construct V3.5 TimelineQuery and validate query filters
    has_filter = any(
        x is not None
        for x in (
            args.start,
            args.end,
            selected_category,
            args.event_type,
            args.source_path,
            args.source_artifact_id,
            args.source_event_id,
            args.text,
        )
    )

    query: Optional[TimelineQuery] = None
    if has_filter:
        try:
            query = TimelineQuery(
                start=args.start,
                end=args.end,
                category=selected_category,
                event_type=args.event_type,
                source_path=args.source_path,
                source_artifact_id=args.source_artifact_id,
                source_event_id=args.source_event_id,
                text=args.text,
                case_sensitive=args.case_sensitive,
            )
        except (ValueError, TypeError) as err:
            print(f"Error: Invalid timeline filter: {err}", file=sys.stderr)
            return 1, None

    # 5. Execute evidence analysis via existing V2 Triage Orchestrator (read-only)
    try:
        triage_config = TriageConfig(
            evidence_path=str(evidence_path.resolve()),
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
            skip_reports=True,  # Suppress V2 file reports; timeline report will be generated
            collect_audit=False,
        )
        orchestrator = TriageOrchestrator(triage_config)
        triage_result = orchestrator.run()
    except (ValueError, TypeError) as err:
        print(f"Error: Evidence analysis configuration error: {err}", file=sys.stderr)
        return 1, None
    except Exception as err:
        print(f"Error: Evidence analysis failed: {err}", file=sys.stderr)
        return 1, None

    # 6. Adapt extracted forensic artifacts into TimelineEvents via V3.3
    if triage_result.artifacts and triage_result.artifacts.artifacts:
        raw_events = adapt_artifacts(
            triage_result.artifacts.artifacts,
            ignore_unsupported=True,
        )
    else:
        raw_events = ()

    # 7. Reconstruct canonical chronological timeline via V3.4
    reconstructed = reconstruct_timeline(raw_events)

    # 8. Apply V3.5 query filtering if specified
    if query is not None:
        timeline_target = query_timeline(reconstructed, query)
        filtered_events_count = timeline_target.total_events
    else:
        timeline_target = reconstructed
        filtered_events_count = reconstructed.total_events

    # 9. Determine target report output path safely
    if args.output:
        target_output = Path(args.output).resolve()
    else:
        DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        slug = args.case_id.strip() if args.case_id else "timeline"
        # Sanitize slug
        safe_slug = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in slug)
        target_output = (DEFAULT_REPORTS_DIR / f"{safe_slug}_timeline.{report_format}").resolve()

    # Prevent overwriting evidence directory
    resolved_evidence = evidence_path.resolve()
    if target_output == resolved_evidence or resolved_evidence in target_output.parents:
        print(
            f"Error: Output report path cannot be within or identical to evidence path: '{target_output}'",
            file=sys.stderr,
        )
        return 1, None

    # 10. Generate and write V3.6 timeline report
    try:
        report = generate_timeline_report(
            timeline_target,
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
        )
        if report_format == "json":
            written_path = write_timeline_json_report(report, target_output)
        else:
            written_path = write_timeline_html_report(report, target_output)
    except (PermissionError, OSError) as err:
        print(
            f"Error: Failed to write timeline report to '{target_output}': {err}",
            file=sys.stderr,
        )
        return 1, None

    # 11. Output concise terminal summary
    print("=" * 60)
    print(f"ForensiX Timeline Analysis (v{__version__})")
    print("=" * 60)
    print(f"Evidence       : {evidence_path.resolve()}")
    if report.case_id:
        print(f"Case ID        : {report.case_id}")
    if report.case_name:
        print(f"Case Name      : {report.case_name}")
    if report.investigator:
        print(f"Investigator   : {report.investigator}")
    print(f"Total Events   : {reconstructed.total_events}")
    if has_filter:
        print(f"Filtered Events: {filtered_events_count}")
    print(f"Format         : {report_format.upper()}")
    print(f"Report         : {written_path}")
    print("-" * 60)
    print("Status         : SUCCESS")
    print("=" * 60)

    return 0, report


def timeline_main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for V3.7 Timeline Reconstruction & Querying.

    Returns:
        int: 0 on success, non-zero on error.
    """
    exit_code, _ = execute_timeline_cli(argv)
    return exit_code
