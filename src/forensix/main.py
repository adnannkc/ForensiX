"""
Command-Line Interface for ForensiX (V1 Evidence Foundation).

Provides entry-point orchestration for analyzing a single evidence file,
generating a standardized JSON report, and outputting a concise terminal summary.
"""

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence

from forensix import __version__
from forensix.analyzer import analyze_evidence
from forensix.reporter import DEFAULT_REPORTS_DIR, generate_json_report
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageStatus,
)
from forensix.timeline_cli import (
    build_timeline_parser,
    execute_timeline_cli,
    timeline_main,
)
from forensix.triage_orchestrator import TriageOrchestrator


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V1 single-file analysis."""
    parser = argparse.ArgumentParser(
        prog="python3 -m forensix",
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V1)",
        epilog=(
            "Analyzes evidence files in binary read-only mode and writes JSON reports to reports/.\n"
            "For automated multi-stage incident triage, use: python3 -m forensix triage --help\n"
            "For timeline reconstruction and querying, use: python3 -m forensix timeline --help\n"
            "For integrated correlation & detection investigation, use: python3 -m forensix investigate --help"
        ),
    )

    parser.add_argument(
        "evidence_file",
        help="Path to the forensic evidence file to analyze.",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_REPORTS_DIR,
        type=Path,
        help=f"Directory to store generated JSON reports (default: {DEFAULT_REPORTS_DIR}/).",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def build_triage_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V2.9 automated triage."""
    parser = argparse.ArgumentParser(
        prog="python3 -m forensix triage",
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V2.9 Triage Orchestrator)",
        epilog="Executes deterministic 9-stage pipeline and outputs structured reports to the configured directory.",
    )

    parser.add_argument(
        "evidence_directory",
        help="Path to the evidence directory containing forensic artifacts and logs.",
    )

    parser.add_argument(
        "--case-id",
        default=None,
        help="Incident case tracking identifier (e.g. CASE-2026-001).",
    )

    parser.add_argument(
        "--case-name",
        default=None,
        help="Human-readable title or description for the incident investigation.",
    )

    parser.add_argument(
        "--investigator",
        default=None,
        help="Name or identification of the handling forensic investigator.",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        type=Path,
        help="Destination directory for generated reports (JSON, CSV, HTML).",
    )

    parser.add_argument(
        "--format",
        action="append",
        dest="formats",
        choices=["json", "csv", "html"],
        help="Report presentation format to generate (can be specified multiple times: --format json --format html).",
    )

    parser.add_argument(
        "--skip-reports",
        action="store_true",
        default=False,
        help="Skip generating physical report files on disk.",
    )

    parser.add_argument(
        "--disable-stage",
        action="append",
        dest="disabled_stages",
        choices=list(ALL_TRIAGE_STAGES),
        help="Disable a specific triage stage from execution (can be specified multiple times).",
    )

    parser.add_argument(
        "--v4",
        action="store_true",
        default=False,
        help="Execute the V4 integrated investigation pipeline (evidence -> timeline -> correlation -> detection -> reporting).",
    )

    parser.add_argument(
        "--matched-only",
        action="store_true",
        default=False,
        help="Filter detection report to only include matched detection rules.",
    )

    parser.add_argument(
        "--log-year",
        type=int,
        default=None,
        dest="log_year",
        help=(
            "Explicit four-digit calendar year context (e.g. 2026) for yearless "
            "BSD/RFC3164 syslog timestamps. ForensiX never infers or guesses the year automatically."
        ),
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def execute_triage_cli(argv: Optional[Sequence[str]] = None) -> tuple[int, Optional[TriageResult]]:
    """
    Execute V2.9 Automated Triage Orchestration from command-line arguments.

    Validates inputs, constructs TriageConfig, executes TriageOrchestrator,
    and displays a concise, deterministic terminal summary with stage statuses and report paths.

    Exit-code semantics:
        0: Successful triage pipeline execution (stages_failed == 0).
        1: Pipeline execution failure (stages_failed > 0) or CLI input validation error.
        2: CLI syntax error / unrecognized argument / missing required positional argument (argparse default).

    Returns:
        tuple[int, Optional[TriageResult]]: (exit_code, result)
            exit_code: 0 on successful pipeline completion, 1 on error or pipeline failure.
            result: TriageResult instance if execution proceeded, or None on input validation failure.
    """
    parser = build_triage_parser()
    args = parser.parse_args(argv)

    if getattr(args, "v4", False) or getattr(args, "matched_only", False):
        from forensix.triage_cli import execute_investigation_cli
        v4_code, v4_report = execute_investigation_cli(argv)
        return v4_code, None

    evidence_path = Path(args.evidence_directory)

    # 1. Input Validation: evidence path existence and directory check
    if not evidence_path.exists():
        print(f"Error: Evidence directory does not exist: '{args.evidence_directory}'", file=sys.stderr)
        return 1, None

    if not evidence_path.is_dir():
        print(f"Error: Evidence path is not a directory: '{args.evidence_directory}'", file=sys.stderr)
        return 1, None

    # 2. Case ID validation if provided
    if args.case_id is not None and not args.case_id.strip():
        print("Error: Case ID cannot be empty or whitespace.", file=sys.stderr)
        return 1, None

    # 3. Resolve report formats
    if args.formats:
        report_formats = tuple(args.formats)
    else:
        report_formats = ("json", "csv", "html")

    # 4. Resolve enabled stages
    if args.disabled_stages:
        for st in args.disabled_stages:
            if st not in ALL_TRIAGE_STAGES:
                print(f"Error: Invalid stage name to disable: '{st}'. Valid stages: {ALL_TRIAGE_STAGES}", file=sys.stderr)
                return 1, None
        disabled_set = set(args.disabled_stages)
        enabled_stages = tuple(s for s in ALL_TRIAGE_STAGES if s not in disabled_set)
    else:
        enabled_stages = ALL_TRIAGE_STAGES

    # 5. Construct TriageConfig and invoke TriageOrchestrator
    try:
        config = TriageConfig(
            evidence_path=str(evidence_path.resolve()),
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
            output_dir=str(Path(args.output_dir).resolve()) if args.output_dir else None,
            enabled_stages=enabled_stages,
            report_formats=report_formats,
            skip_reports=args.skip_reports,
            log_timestamp_year=getattr(args, "log_year", None),
        )
        orchestrator = TriageOrchestrator(config)
        result = orchestrator.run()
    except (ValueError, TypeError) as err:
        print(f"Error: Configuration error: {err}", file=sys.stderr)
        return 1, None
    except Exception as err:
        print(f"Internal Error: An unexpected error occurred: {err}", file=sys.stderr)
        return 1, None

    # 6. Display concise, structured terminal summary
    print("=" * 60)
    print(f"ForensiX Automated Incident Triage (v{__version__})")
    print("=" * 60)
    if result.config.case_id:
        print(f"Case ID      : {result.config.case_id}")
    if result.config.case_name:
        print(f"Case Name    : {result.config.case_name}")
    if result.config.investigator:
        print(f"Investigator : {result.config.investigator}")
    print(f"Evidence     : {result.summary.evidence_root}")
    print(f"Triage ID    : {result.triage_id}")
    print("-" * 60)
    print("Pipeline Stages:")

    total_stages = len(result.stage_results)
    for idx, stage in enumerate(result.stage_results, start=1):
        num_str = f"[{idx}/{total_stages}]"
        st_name = stage.stage_id
        status = stage.status
        dur_str = f"{stage.duration_seconds:.4f}s" if stage.duration_seconds is not None else "-"
        rec_str = f"{stage.records_produced} records"

        pad = 28 - len(st_name)
        dots = "." * max(pad, 2)
        print(f"  {num_str} {st_name} {dots} {status} ({rec_str}, {dur_str})")

        if status == TriageStageStatus.FAILED.value:
            err_msg = stage.errors[0].error_message if stage.errors else "Stage execution failed"
            print(f"        Error: {err_msg}")
        elif status == TriageStageStatus.SKIPPED.value:
            reason = stage.warnings[0] if stage.warnings else "Prerequisite not satisfied"
            print(f"        Reason: {reason}")
        elif status == TriageStageStatus.PARTIAL.value:
            warn = stage.warnings[0] if stage.warnings else "Partial output produced"
            print(f"        Warning: {warn}")

    print("-" * 60)
    if result.report_files:
        print("Generated Reports:")
        for fmt, p in result.report_files:
            print(f"  {fmt.upper():<5} : {p}")
        print("-" * 60)
    elif not result.config.skip_reports and result.report:
        print("Report : In-memory report generated (no output directory specified)")
        print("-" * 60)

    status_label = "SUCCESS" if result.summary.is_success else "FAILED"
    print(f"Triage Result : {status_label}")
    print(f"Total Duration: {result.summary.total_duration_seconds:.4f}s")
    print(f"Artifacts     : {result.summary.total_artifacts} total")
    print("=" * 60)

    exit_code = 0 if result.summary.is_success else 1
    return exit_code, result


def triage_main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for V2.9 Automated Triage Orchestration.

    Validates inputs, constructs TriageConfig, executes TriageOrchestrator,
    and displays a concise, deterministic summary with stage statuses and report paths.

    Returns:
        int: 0 on successful pipeline completion, non-zero on error or failure.
    """
    exit_code, _ = execute_triage_cli(argv)
    return exit_code



def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for ForensiX.

    Supports:
    - V1 Single Evidence File Analysis: python3 -m forensix <file> [-o output_dir]
    - V2.9 End-to-End Automated Triage: python3 -m forensix triage <evidence_dir> [options]

    Returns:
        int: 0 on success, non-zero on failure.
    """
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and raw_args[0] in ("investigate", "triage-v4"):
        from forensix.triage_cli import investigation_main
        return investigation_main(raw_args[1:])
    if raw_args and raw_args[0] == "triage":
        if any(flag in raw_args for flag in ("--v4", "--investigate", "--matched-only")):
            from forensix.triage_cli import triage_main as triage_v4_main
            filtered_args = [a for a in raw_args[1:] if a != "--v4"]
            return triage_v4_main(filtered_args)
        return triage_main(raw_args[1:])
    if raw_args and raw_args[0] == "timeline":
        return timeline_main(raw_args[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    evidence_path = Path(args.evidence_file)

    # Validate target exists and is a regular file before starting analysis
    if not evidence_path.exists():
        print(f"Error: Evidence file does not exist: '{args.evidence_file}'", file=sys.stderr)
        return 1

    if evidence_path.is_dir():
        print(
            f"Error: Expected a regular evidence file, but target is a directory: '{args.evidence_file}'",
            file=sys.stderr,
        )
        return 1

    if not evidence_path.is_file():
        print(
            f"Error: Target path is not a regular file: '{args.evidence_file}'",
            file=sys.stderr,
        )
        return 1

    try:
        # 1. Orchestrate analysis (Registration -> Metadata -> Hashing -> Unified Result)
        analysis_result = analyze_evidence(evidence_path)

        # 2. Generate JSON forensic report
        report_path = generate_json_report(analysis_result, output_dir=args.output_dir)

        # 3. Display concise terminal summary
        print("=" * 50)
        print("ForensiX Analysis Complete")
        print("=" * 50)
        print(f"Evidence ID : {analysis_result.evidence.evidence_id}")
        print(f"File        : {analysis_result.file.filename}")
        print(f"Size        : {analysis_result.file.size} bytes")
        print(f"Type        : {analysis_result.file.type or 'unknown'}")
        print(f"MD5         : {analysis_result.hashes.md5}")
        print(f"SHA-256     : {analysis_result.hashes.sha256}")
        print(f"Report      : {report_path}")
        print("=" * 50)
        return 0

    except (FileNotFoundError, IsADirectoryError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except PermissionError as err:
        print(
            f"Error: Permission denied accessing evidence or writing report: {err}",
            file=sys.stderr,
        )
        return 1
    except OSError as err:
        print(f"Error: Filesystem I/O failure: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Internal Error: An unexpected error occurred: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
