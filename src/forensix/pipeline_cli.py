"""
ForensiX V9 - Controlled Investigation Pipeline Command-Line Interface.

Provides CLI entry points for orchestrating multi-domain digital forensics triage
across Host, Network, and Memory evidence with Schema 8.0 reporting and custody tracking.
"""

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
import sys
import time
from typing import List, Optional, Sequence

from forensix import __version__
from forensix.case_config import (
    ALL_DOMAINS,
    SUPPORTED_REPORT_FORMATS,
    CaseConfig,
    load_case_config_from_file,
    validate_case_config,
)
from forensix.pipeline_engine import (
    EXIT_CONFIG_ERROR,
    InvestigationPipeline,
    PipelineExecutionResult,
    run_pipeline,
)
from forensix.pipeline_models import PipelineRunStatus


def build_pipeline_parser() -> argparse.ArgumentParser:
    """Build command-line parser for the investigation pipeline."""
    parser = argparse.ArgumentParser(
        prog="forensix run",
        description="ForensiX V9 - Controlled Multi-Domain Investigation Pipeline",
        epilog=(
            "Accepts a case configuration file or explicit evidence flags, executes "
            "all 12 investigation stages in strict dependency order, and generates "
            "Schema 8.0 reports, custody ledgers, and pipeline_manifest.json.\n\n"
            "Exit Codes:\n"
            "  0: SUCCESS (All stages and verifications passed)\n"
            "  1: CONFIG_ERROR / VALIDATION_FAILURE (Invalid inputs, paths, or schema)\n"
            "  2: VERIFICATION_OR_PARTIAL (Manifest discrepancy or partial domain success)\n"
            "  3: CUSTODY_FAILURE (Custody chain verification or lock failed)\n"
            "  4: FILESYSTEM_IO_ERROR (Output clobber protection or I/O failure)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Configuration file option
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Path to case configuration file (JSON or YAML format).",
    )

    # Case metadata
    parser.add_argument(
        "--case-id",
        default=None,
        help="Incident tracking identifier (e.g. CASE-2026-001).",
    )
    parser.add_argument(
        "--case-name",
        default=None,
        help="Human-readable incident title.",
    )
    parser.add_argument(
        "--investigator",
        default=None,
        help="Lead forensic investigator name.",
    )
    parser.add_argument(
        "--actor-role",
        default="Forensic Analyst",
        help="Role designation of the active custodian (default: 'Forensic Analyst').",
    )
    parser.add_argument(
        "--actor-org",
        default=None,
        help="Forensic laboratory or organization name.",
    )

    # Evidence inputs
    parser.add_argument(
        "--evidence-host-dir",
        "--host-dir",
        type=Path,
        default=None,
        help="Path to evidence directory containing host filesystem and logs.",
    )
    parser.add_argument(
        "--evidence-pcap",
        "--pcap",
        type=Path,
        nargs="+",
        default=None,
        help="One or more PCAP capture files for network evidence analysis.",
    )
    parser.add_argument(
        "--evidence-mem",
        "--mem",
        type=Path,
        nargs="+",
        default=None,
        help="One or more memory artifact JSON files or directories.",
    )

    # Custody and verification
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Path to preflight evidence manifest JSON for integrity verification.",
    )
    parser.add_argument(
        "--custody-ledger",
        type=Path,
        default=None,
        help="Path to existing custody ledger JSON to resume.",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Destination directory for reports, ledgers, and manifest (default: reports/).",
    )
    parser.add_argument(
        "--format",
        nargs="+",
        choices=list(SUPPORTED_REPORT_FORMATS),
        default=None,
        help="Report formats to generate (choices: json, html; default: both).",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        choices=list(ALL_DOMAINS),
        default=None,
        help="Specific analysis domains to enable (default: all available).",
    )
    parser.add_argument(
        "--log-year",
        type=int,
        default=None,
        help="Explicit calendar year for yearless BSD syslog timestamps.",
    )

    # Operational flags
    parser.add_argument(
        "--allow-symlinks",
        action="store_true",
        help="Follow symlinks when inspecting evidence directories.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing output files if destination directory contains reports.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Halt pipeline on first domain failure rather than attempting remaining domains.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed diagnostic messages during execution.",
    )
    parser.add_argument(
        "--show-findings",
        action="store_true",
        default=False,
        help="Print detailed observed rule matches in the terminal following the execution summary.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def format_stage_name(stage_id: str) -> str:
    """Format stage_id to uppercase for terminal display."""
    return stage_id.upper()


def print_pipeline_summary(result: PipelineExecutionResult) -> None:
    """Render a clean, professional terminal summary box for the pipeline execution."""
    manifest = result.run_manifest
    print("\n" + "=" * 78)
    print("ForensiX V9 - Controlled Investigation Pipeline Execution Summary")
    print("=" * 78)
    print(f"Case ID      : {manifest.case_id or 'UNSPECIFIED'}")
    print(f"Case Name    : {manifest.case_name or 'UNSPECIFIED'}")
    print(f"Investigator : {manifest.investigator or 'UNSPECIFIED'}")
    print(f"Run ID       : {manifest.run_id}")
    print(f"Run Status   : {manifest.run_status}")
    print(f"Duration     : {manifest.total_duration_seconds:.4f}s")
    print(f"Version      : ForensiX {manifest.forensix_version}")
    print("-" * 78)
    print("Stage Execution Summary:")

    total_stages = len(manifest.stages)
    for idx, st in enumerate(manifest.stages, start=1):
        num_str = f"[{idx:02d}/{total_stages:02d}]"
        st_name = format_stage_name(st.stage_id)
        pad = 26 - len(st_name)
        dots = "." * max(pad, 2)
        dur_str = f"{st.duration_seconds:.4f}s"
        rec_str = f"{st.records_produced} records" if st.records_produced > 0 else "-"
        print(f"  {num_str} {st_name} {dots} {st.status:<9} ({dur_str}, {rec_str})")

        for err in st.errors:
            print(f"        [ERROR]   {err}")
        for warn in st.warnings:
            print(f"        [WARNING] {warn}")

    print("-" * 78)
    if manifest.generated_files:
        print("Generated Artifacts & Cryptographic Digests:")
        for gf in manifest.generated_files:
            size_kb = gf.size_bytes / 1024.0
            print(f"  • {gf.relative_path:<36} ({size_kb:.1f} KB, {gf.file_type})")
            print(f"    SHA-256: {gf.sha256}")
    elif result.output_files:
        print("Output Files:")
        for out_p in result.output_files:
            print(f"  • {out_p.name}")
    else:
        print("Output Files: None written")

    print("=" * 78)
    print(f"Final Exit Code : {result.exit_code} (Status: {manifest.run_status})")
    print("=" * 78 + "\n")


def _parse_iso_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string into a timezone-aware UTC datetime."""
    if not ts:
        return None
    clean = str(ts).strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _format_dt(dt: datetime) -> str:
    """Format datetime as YYYY-MM-DD HH:MM:SS with microseconds truncated."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def print_pipeline_findings(result: PipelineExecutionResult) -> None:
    """Render observed rule matches to the terminal when --show-findings is enabled."""
    if result.report is None:
        print("No report findings were generated for this run.")
        return

    details = result.report.details if isinstance(result.report.details, Mapping) else {}
    detections = details.get("detections", [])
    matched_dets = [d for d in detections if d.get("matched", True)]

    # Group matches by rule_name in order of first appearance
    grouped: dict = {}
    for d in matched_dets:
        r_name = d.get("rule_name") or "Unknown Rule"
        grouped.setdefault(r_name, []).append(d)

    total_rules = len(grouped)
    total_matches = len(matched_dets)

    # Derived overall timeline range: timeline_events if present, otherwise detections start/end
    timeline_events = details.get("timeline_events", [])
    collected_dts = []
    if timeline_events:
        for ev in timeline_events:
            ts = ev.get("timestamp")
            parsed = _parse_iso_timestamp(ts)
            if parsed is not None:
                collected_dts.append(parsed)
    else:
        for d in matched_dets:
            for k in ("start_timestamp", "end_timestamp"):
                ts = d.get(k)
                parsed = _parse_iso_timestamp(ts)
                if parsed is not None:
                    collected_dts.append(parsed)

    if collected_dts:
        earliest_dt = min(collected_dts)
        latest_dt = max(collected_dts)
        matched_range_str = f"{_format_dt(earliest_dt)} to {_format_dt(latest_dt)} UTC"
    else:
        matched_range_str = "None observed"

    border = "  " + "=" * 69
    print("\n" + border)
    print("  ForensiX - What was found")
    print(border)
    print("  Times are shown to the second. Full precision is kept in the JSON report.")
    manifest = result.run_manifest
    if manifest:
        print(f"  Case      : {manifest.case_id or 'UNSPECIFIED'}")
        print(f"  Status    : {manifest.run_status}")
    print()

    kind_noun = "kind" if total_rules == 1 else "kinds"
    match_noun = "time" if total_matches == 1 else "times"
    print(f"  {total_rules} {kind_noun} of pattern matched, {total_matches} {match_noun} in total.\n")

    if not grouped:
        print("  No rule matches observed.\n")
    else:
        displayed_rules = list(grouped.items())[:25]
        for idx, (rule_name, matches) in enumerate(displayed_rules, start=1):
            count = len(matches)
            rule_time_str = "time" if count == 1 else "times"

            parsed_dts = []
            unparsed_count = 0
            for m in matches:
                raw_ts = m.get("start_timestamp")
                parsed = _parse_iso_timestamp(raw_ts)
                if parsed is not None:
                    parsed_dts.append(parsed)
                else:
                    unparsed_count += 1

            if parsed_dts:
                start_dt = min(parsed_dts)
                end_dt = max(parsed_dts)
                if start_dt == end_dt:
                    time_line = f"     At {_format_dt(start_dt)} UTC."
                else:
                    time_line = f"     Between {_format_dt(start_dt)} and {_format_dt(end_dt)} UTC."
            else:
                time_line = "     Time: None recorded"

            explanation = ""
            for m in matches:
                if m.get("explanation"):
                    explanation = str(m["explanation"])
                    break

            print(f"  {idx}. {rule_name} ({count} {rule_time_str})")
            print(time_line)
            if explanation:
                print(f"     {explanation}")
            print()

        if total_rules > 25:
            remaining = total_rules - 25
            print(f"  ... and {remaining} more kinds not shown. See the report for the full list.\n")

    print(f"  Matched range: {matched_range_str}\n")

    html_path = None
    json_path = None
    for p in result.output_files:
        p_str = str(p)
        if p_str.endswith(".html"):
            html_path = p_str
        elif p_str.endswith(".json") and "report" in Path(p_str).name:
            json_path = p_str

    print("  Where to look next")
    print(f"     HTML report : {html_path or 'Not generated'}")
    print(f"     JSON report : {json_path or 'Not generated'}\n")
    print("  Matches are observations to review, not conclusions about compromise.")
    print(border + "\n")


def execute_pipeline_cli(argv: Optional[Sequence[str]] = None) -> int:
    """Execute the pipeline CLI with the given command line arguments."""
    parser = build_pipeline_parser()
    args = parser.parse_args(argv)

    # 1. Resolve configuration
    try:
        if args.config is not None:
            if not args.config.exists():
                print(f"Error: Configuration file not found: '{args.config}'", file=sys.stderr)
                return EXIT_CONFIG_ERROR

            base_config = load_case_config_from_file(args.config)

            # Apply explicit CLI overrides if provided
            evidence_pcaps = (
                tuple(args.evidence_pcap)
                if args.evidence_pcap is not None
                else base_config.evidence_pcap_files
            )
            evidence_mems = (
                tuple(args.evidence_mem)
                if args.evidence_mem is not None
                else base_config.evidence_mem_files
            )
            report_fmts = (
                tuple(args.format)
                if args.format is not None
                else base_config.report_formats
            )
            domains = (
                tuple(args.domains)
                if args.domains is not None
                else base_config.enabled_domains
            )

            config = CaseConfig(
                case_id=args.case_id if args.case_id is not None else base_config.case_id,
                case_name=args.case_name if args.case_name is not None else base_config.case_name,
                investigator=args.investigator if args.investigator is not None else base_config.investigator,
                actor_role=args.actor_role if args.actor_role != "Forensic Analyst" else base_config.actor_role,
                actor_org=args.actor_org if args.actor_org is not None else base_config.actor_org,
                evidence_host_dir=args.evidence_host_dir if args.evidence_host_dir is not None else base_config.evidence_host_dir,
                evidence_pcap_files=evidence_pcaps,
                evidence_mem_files=evidence_mems,
                manifest_path=args.manifest if args.manifest is not None else base_config.manifest_path,
                custody_ledger_path=args.custody_ledger if args.custody_ledger is not None else base_config.custody_ledger_path,
                output_dir=args.output_dir if args.output_dir is not None else base_config.output_dir,
                report_formats=report_fmts,
                enabled_domains=domains,
                log_year=args.log_year if args.log_year is not None else base_config.log_year,
                allow_symlinks=args.allow_symlinks or base_config.allow_symlinks,
                overwrite=args.overwrite or base_config.overwrite,
                fail_fast=args.fail_fast or base_config.fail_fast,
            )
        else:
            # Build directly from CLI arguments
            pcaps = tuple(args.evidence_pcap) if args.evidence_pcap else ()
            mems = tuple(args.evidence_mem) if args.evidence_mem else ()
            fmts = tuple(args.format) if args.format else ("json", "html")
            domains = tuple(args.domains) if args.domains else ALL_DOMAINS
            out_d = args.output_dir if args.output_dir is not None else Path("reports")

            config = CaseConfig(
                case_id=args.case_id,
                case_name=args.case_name,
                investigator=args.investigator,
                actor_role=args.actor_role,
                actor_org=args.actor_org,
                evidence_host_dir=args.evidence_host_dir,
                evidence_pcap_files=pcaps,
                evidence_mem_files=mems,
                manifest_path=args.manifest,
                custody_ledger_path=args.custody_ledger,
                output_dir=out_d,
                report_formats=fmts,
                enabled_domains=domains,
                log_year=args.log_year,
                allow_symlinks=args.allow_symlinks,
                overwrite=args.overwrite,
                fail_fast=args.fail_fast,
            )

        # Validate configuration semantics
        val_errors = validate_case_config(config)
        if val_errors:
            print("Configuration Validation Errors:", file=sys.stderr)
            for err in val_errors:
                print(f"  • {err}", file=sys.stderr)
            return EXIT_CONFIG_ERROR

    except Exception as exc:
        print(f"Configuration Error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # 2. Execute pipeline
    if args.verbose:
        print(f"Starting ForensiX Investigation Pipeline (case_id: {config.case_id or 'none'})...")

    result = run_pipeline(config)

    # 3. Render summary
    print_pipeline_summary(result)
    if args.show_findings:
        print_pipeline_findings(result)

    return result.exit_code


def pipeline_main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entrypoint for forensix run."""
    return execute_pipeline_cli(argv)


if __name__ == "__main__":
    sys.exit(pipeline_main())
