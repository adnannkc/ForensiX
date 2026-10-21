"""
ForensiX V9 - Controlled Investigation Pipeline Command-Line Interface.

Provides CLI entry points for orchestrating multi-domain digital forensics triage
across Host, Network, and Memory evidence with Schema 8.0 reporting and custody tracking.
"""

import argparse
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

    return result.exit_code


def pipeline_main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entrypoint for forensix run."""
    return execute_pipeline_cli(argv)


if __name__ == "__main__":
    sys.exit(pipeline_main())
