"""
Command-Line Interface for ForensiX Integrated Incident Triage and Investigation (V4.7).

Orchestrates the complete ForensiX investigation pipeline from the CLI:
1. Evidence directory analysis via existing V1/V2 Triage Orchestrator (read-only, no intermediate file reports).
2. Artifact adaptation into TimelineEvent objects via existing V3.3 Artifact Adapters.
3. Chronological timeline reconstruction via existing V3.4 Reconstruction.
4. Deterministic event correlation via existing V4.2 CorrelationEngine.
5. Declarative rule loading via existing V4.5 get_initial_rules().
6. Deterministic detection evaluation via existing V4.4 DetectionEngine.
7. Integrated forensic reporting via existing V4.6 CorrelationDetectionReport serializers (JSON / HTML).
8. Concise, factual terminal summary output.

Strict Forensic Boundaries:
- Pure orchestration: delegates all forensic extraction, correlation, detection, and reporting to existing modules.
- Non-destructive: evidence is strictly read-only; never alters, creates, renames, or executes files in evidence.
- Deterministic: produces reproducible outputs; no unstable ordering, random IDs, or implicit timestamps.
- Non-speculative: factual reporting only; detections represent observed rule patterns, not proof of compromise.
- Clean error handling: friendly error messages with standard exit codes, no raw Python tracebacks.
"""

import argparse
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.artifact_adapters import adapt_artifacts
from forensix.correlation_engine import CorrelationEngine
from forensix.correlation_models import CorrelationCollection
from forensix.detection_engine import DetectionEngine, DetectionResultCollection
from forensix.detection_reporting import (
    CorrelationDetectionReport,
    generate_correlation_detection_report,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
)
from forensix.initial_rules import get_initial_rules
from forensix.timeline_reconstruction import reconstruct_timeline
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


SUPPORTED_FORMATS: Tuple[str, ...] = ("html", "json")
DEFAULT_FORMAT: str = "html"
DEFAULT_REPORTS_DIR = Path("reports")


def build_investigation_parser(
    prog: str = "python3 -m forensix investigate",
) -> argparse.ArgumentParser:
    """
    Build and configure the command-line argument parser for V4 integrated triage and investigation.

    Args:
        prog: Program name displayed in help and usage strings.

    Returns:
        argparse.ArgumentParser configured with all investigation options.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V4 Integrated Triage)",
        epilog=(
            "Executes the full ForensiX investigation pipeline:\n"
            "evidence analysis -> timeline reconstruction -> event correlation ->\n"
            "rule-based detection -> integrated investigation reporting (JSON/HTML)."
        ),
    )

    # Positional argument: evidence directory
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

    # Optional compatibility flag
    parser.add_argument(
        "--v4",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )

    # Detection options
    parser.add_argument(
        "--matched-only",
        action="store_true",
        default=False,
        help="Filter report to include only matched detection rules (default: include all evaluated rules).",
    )

    # Explicit year context for yearless BSD syslog timestamps
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


def execute_investigation_cli(
    argv: Optional[Sequence[str]] = None,
    parser: Optional[argparse.ArgumentParser] = None,
) -> Tuple[int, Optional[CorrelationDetectionReport]]:
    """
    Execute V4 integrated incident triage & investigation pipeline from CLI arguments.

    Pipeline stages executed in deterministic order:
    1. Parse and validate CLI inputs (evidence directory, formats, case metadata).
    2. Extract evidence artifacts via existing V1/V2 TriageOrchestrator (read-only, skip file reports).
    3. Adapt artifacts into TimelineEvent objects via existing V3.3 adapt_artifacts.
    4. Reconstruct canonical chronological timeline via existing V3.4 reconstruct_timeline.
    5. Identify deterministic relationships via existing V4.2 CorrelationEngine.
    6. Load canonical initial detection rules via existing V4.5 get_initial_rules().
    7. Evaluate detection rules via existing V4.4 DetectionEngine.
    8. Generate and write integrated investigation report via existing V4.6 reporting.
    9. Output concise, factual terminal summary.

    Exit-code semantics:
        0: Successful execution (even if matched detections > 0 or == 0).
        1: User input error, invalid evidence path, or processing failure.
        2: CLI syntax error / unrecognized argument (argparse SystemExit default).

    Returns:
        Tuple[int, Optional[CorrelationDetectionReport]]: (exit_code, report_instance)
    """
    if parser is None:
        parser = build_investigation_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2, None

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

    # Case ID validation if provided
    if args.case_id is not None and not args.case_id.strip():
        print("Error: Case ID cannot be empty or whitespace.", file=sys.stderr)
        return 1, None

    # Log timestamp year validation if provided
    log_year = getattr(args, "log_year", None)
    if log_year is not None:
        try:
            log_year = int(log_year)
            if not (1 <= log_year <= 9999):
                print(f"Error: --log-year must be between 1 and 9999, got {args.log_year}.", file=sys.stderr)
                return 1, None
        except (ValueError, TypeError):
            print(f"Error: Invalid --log-year '{args.log_year}'. Must be an integer year.", file=sys.stderr)
            return 1, None
    else:
        log_year = None

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
        # If output specified with known extension, infer format; otherwise default to HTML
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
    slug = args.case_id.strip() if args.case_id else "triage"
    cleaned_slug = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in slug).strip("_")
    safe_slug = cleaned_slug if cleaned_slug else "triage"

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

    # Crucial safety check: target report cannot enter evidence directory
    if target_output == resolved_evidence or resolved_evidence in target_output.parents:
        print(
            f"Error: Output report path cannot be within or identical to evidence path: '{target_output}'",
            file=sys.stderr,
        )
        return 1, None

    # 4. Stage 1: Evidence / Host Analysis via existing V1/V2 TriageOrchestrator
    if args.verbose:
        print("[1/6] Evidence Analysis...")

    try:
        triage_config = TriageConfig(
            evidence_path=str(resolved_evidence),
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
            skip_reports=True,  # Suppress intermediate V2 file reports
            collect_audit=False,
            log_timestamp_year=log_year,
        )
        orchestrator = TriageOrchestrator(triage_config)
        triage_result = orchestrator.run()
    except (ValueError, TypeError) as err:
        print(f"Error: Evidence analysis configuration error: {err}", file=sys.stderr)
        return 1, None
    except Exception as err:
        print(f"Error: Evidence analysis failed: {err}", file=sys.stderr)
        return 1, None

    artifact_count = triage_result.summary.total_artifacts if triage_result.summary else 0
    if args.verbose:
        print(f"      Completed: {artifact_count} artifacts identified")

    # 5. Stage 2: Timeline Reconstruction via existing V3.3 adapters + V3.4 reconstruct_timeline
    if args.verbose:
        print("[2/6] Timeline Reconstruction...")

    try:
        if triage_result.artifacts and triage_result.artifacts.artifacts:
            raw_events = adapt_artifacts(
                triage_result.artifacts.artifacts,
                ignore_unsupported=True,
                log_timestamp_year=log_year,
            )
        else:
            raw_events = ()
        reconstructed = reconstruct_timeline(raw_events)
    except Exception as err:
        print(f"Error: Timeline reconstruction failed: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: {reconstructed.total_events} events reconstructed")

    # 6. Stage 3: Event Correlation via existing V4.2 CorrelationEngine
    if args.verbose:
        print("[3/6] Event Correlation...")

    try:
        correlation_engine = CorrelationEngine()
        correlations = correlation_engine.correlate(reconstructed.events)
    except Exception as err:
        print(f"Error: Event correlation failed: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: {len(correlations)} correlations identified")

    # 7. Stage 4: Load Initial Detection Rules via existing V4.5 get_initial_rules()
    if args.verbose:
        print("[4/6] Loading Initial Detection Rules...")

    try:
        rules = get_initial_rules()
    except Exception as err:
        print(f"Error: Failed to load initial detection rules: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: {len(rules)} rules loaded")

    # 8. Stage 5: Detection Evaluation via existing V4.4 DetectionEngine
    if args.verbose:
        print("[5/6] Detection Evaluation...")

    try:
        detection_engine = DetectionEngine(rules=rules)
        detection_results = detection_engine.evaluate(
            timeline=reconstructed.events,
            correlations=correlations,
        )
    except Exception as err:
        print(f"Error: Detection evaluation failed: {err}", file=sys.stderr)
        return 1, None

    matched_count = sum(1 for d in detection_results if d.matched)
    if args.verbose:
        print(f"      Completed: {len(detection_results)} evaluations ({matched_count} matched)")

    # 9. Stage 6: Report Generation via existing V4.6 reporting serializers
    if args.verbose:
        print("[6/6] Generating Investigation Report...")

    try:
        report = generate_correlation_detection_report(
            detections=detection_results,
            correlations=correlations,
            timeline=reconstructed.events,
            case_id=args.case_id.strip() if args.case_id else None,
            case_name=args.case_name.strip() if args.case_name else None,
            investigator=args.investigator.strip() if args.investigator else None,
            matched_only=args.matched_only,
        )

        if report_format == "json":
            written_path = write_correlation_detection_json_report(
                detections=detection_results,
                output_path=target_output,
                correlations=correlations,
                timeline=reconstructed.events,
                case_id=args.case_id.strip() if args.case_id else None,
                case_name=args.case_name.strip() if args.case_name else None,
                investigator=args.investigator.strip() if args.investigator else None,
                matched_only=args.matched_only,
            )
        else:
            written_path = write_correlation_detection_html_report(
                detections=detection_results,
                output_path=target_output,
                correlations=correlations,
                timeline=reconstructed.events,
                case_id=args.case_id.strip() if args.case_id else None,
                case_name=args.case_name.strip() if args.case_name else None,
                investigator=args.investigator.strip() if args.investigator else None,
                matched_only=args.matched_only,
            )
    except (PermissionError, OSError) as err:
        print(
            f"Error: Failed to write investigation report to '{target_output}': {err}",
            file=sys.stderr,
        )
        return 1, None
    except Exception as err:
        print(f"Error: Investigation report generation failed: {err}", file=sys.stderr)
        return 1, None

    if args.verbose:
        print(f"      Completed: Report written to '{written_path}'")

    # 10. Display concise, factual terminal summary
    print("=" * 60)
    print(f"ForensiX Incident Triage & Investigation (v{__version__})")
    print("=" * 60)
    print(f"Evidence Root           : {resolved_evidence}")
    if report.case_id:
        print(f"Case ID                 : {report.case_id}")
    if report.case_name:
        print(f"Case Name               : {report.case_name}")
    if report.investigator:
        print(f"Investigator            : {report.investigator}")
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


def investigation_main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for ForensiX Integrated Incident Triage & Investigation (V4.7).

    Returns:
        int: 0 on success, non-zero on error.
    """
    exit_code, _ = execute_investigation_cli(argv)
    return exit_code


# Canonical aliases providing both 'investigation' and 'triage' nomenclature
build_triage_parser = build_investigation_parser
execute_triage_cli = execute_investigation_cli
triage_main = investigation_main

build_v4_triage_parser = build_investigation_parser
execute_triage_v4_cli = execute_investigation_cli
triage_v4_main = investigation_main
