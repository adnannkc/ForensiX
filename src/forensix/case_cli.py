"""
ForensiX V9 - Controlled Investigation Pipeline & Case Runner Command-Line Interface.

Provides CLI entry points for running the multi-domain investigation pipeline (Host,
Network, Memory evidence with Schema 8.0 reporting and custody tracking) and optionally
serving the offline, local read-only investigation dashboard on the output folder.
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional, Sequence

from forensix import __version__
from forensix.case_config import (
    ALL_DOMAINS,
    SUPPORTED_REPORT_FORMATS,
    CaseConfig,
    load_case_config_from_file,
    validate_case_config,
)
from forensix.dashboard_cli import execute_dashboard_cli
from forensix.dashboard_service import ALLOWED_LOOPBACK_HOSTS
from forensix.pipeline_cli import (
    build_pipeline_parser,
    print_pipeline_summary,
)
from forensix.pipeline_engine import (
    EXIT_CONFIG_ERROR,
    run_pipeline,
)


def build_case_parser() -> argparse.ArgumentParser:
    """
    Build command-line parser for 'forensix case'.

    Reuses all arguments from build_pipeline_parser(), and adds:
    - --serve: Start the local read-only dashboard on the output folder.
    - -p, --port: Port number to bind local dashboard server (default: 8765, 0 for ephemeral).
    - --host: Loopback host address to bind (default: 127.0.0.1).
    """
    base_parser = build_pipeline_parser()
    parser = argparse.ArgumentParser(
        prog="forensix case",
        description="ForensiX V9 - Controlled Multi-Domain Investigation Pipeline & Case Runner",
        epilog=(
            "Accepts a case configuration file or explicit evidence flags, executes "
            "all 12 investigation stages in strict dependency order, and optionally "
            "serves the local investigation dashboard on the output folder.\n\n"
            "Exit Codes:\n"
            "  0: SUCCESS (All stages and verifications passed)\n"
            "  1: CONFIG_ERROR / VALIDATION_FAILURE (Invalid inputs, paths, or schema)\n"
            "  2: VERIFICATION_OR_PARTIAL (Manifest discrepancy or partial domain success)\n"
            "  3: CUSTODY_FAILURE (Custody chain verification or lock failed)\n"
            "  4: FILESYSTEM_IO_ERROR (Output clobber protection or I/O failure)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Transfer actions from pipeline parser
    for action in base_parser._actions:
        if action.dest == "help":
            continue
        parser._add_action(action)

    # Add case-specific dashboard orchestration options
    parser.add_argument(
        "--serve",
        action="store_true",
        default=False,
        help="Start the local read-only investigation dashboard on the output folder after the pipeline run.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8765,
        help="Port number to bind local dashboard server (default: 8765, 0 for ephemeral).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback host address to bind dashboard (strictly restricted to loopback, default: 127.0.0.1).",
    )

    return parser


def execute_case_cli(
    argv: Optional[Sequence[str]] = None,
    block: bool = True,
) -> int:
    """
    Execute 'forensix case' command-line orchestration.

    Runs run_pipeline(config) identically to pipeline_cli, and conditionally
    launches the local dashboard on the output folder if --serve was requested.

    Rules:
    - Exit 1: config error / validation failure, skip dashboard, return 1.
    - Exit 3 or 4: custody or I/O failure, skip dashboard, return that code.
    - Exit 0 or 2 with --serve:
        * For exit 2, print warning banner first:
          "Run finished with exit 2: partial results or manifest discrepancy. Read the run summary before relying on these findings."
        * Call execute_dashboard_cli([str(config.output_dir), "--port", str(port), "--host", host], block=block).
        * If dashboard fails to start (bad host, port in use), print error and return pipeline exit code.
    - Without --serve: return the pipeline's exit code.
    """
    parser = build_case_parser()
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

    # Early host check: validate dashboard bind address if --serve is requested
    if args.serve:
        clean_host = str(args.host).strip().lower()
        if clean_host not in ALLOWED_LOOPBACK_HOSTS:
            print(
                f"Error: ForensiX dashboard can only bind to loopback ({sorted(ALLOWED_LOOPBACK_HOSTS)}), "
                f"got external host: '{args.host}'. External exposure is blocked for forensic data protection.",
                file=sys.stderr,
            )
            return EXIT_CONFIG_ERROR

    # 2. Execute pipeline
    if args.verbose:
        print(f"Starting ForensiX Investigation Pipeline (case_id: {config.case_id or 'none'})...")

    result = run_pipeline(config)

    # 3. Render summary
    print_pipeline_summary(result)

    # 4. Handle exit code and optional dashboard serving
    if result.exit_code == 1:
        return 1

    if result.exit_code in (3, 4):
        return result.exit_code

    if args.serve and result.exit_code in (0, 2):
        if result.exit_code == 2:
            print("Run finished with exit 2: partial results or manifest discrepancy. Read the run summary before relying on these findings.")
        print(f"\nStarting ForensiX investigation dashboard on '{config.output_dir}'...")

        dashboard_args = [str(config.output_dir), "--port", str(args.port), "--host", str(args.host)]
        try:
            dash_exit_code, _ = execute_dashboard_cli(dashboard_args, block=block)
            if dash_exit_code != 0:
                # Dashboard failed to start (e.g. invalid host or port collision error already printed by execute_dashboard_cli)
                return result.exit_code
        except Exception as exc:
            print(f"Error starting dashboard: {exc}", file=sys.stderr)
            return result.exit_code
        return result.exit_code

    return result.exit_code


def case_main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entrypoint for 'forensix case'."""
    return execute_case_cli(argv, block=True)


if __name__ == "__main__":
    sys.exit(case_main())
