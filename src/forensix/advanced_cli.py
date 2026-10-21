"""
Command-Line Interface for ForensiX Advanced Forensic Triage (V8.5).

Provides CLI entry-point orchestration for Schema 8.0 Advanced Forensic Reports,
manifest baseline integrity verification, and runtime chain-of-custody tracking.

Exit Code Contract:
- 0: Successful operation with 0 verification discrepancies
- 1: Configuration, case conflict, or argument error
- 2: Verification discrepancy detected (mismatch, missing files, or entry errors)
- 3: Custody integrity or chain verification failure
- 4: Filesystem, I/O, or permission error
"""

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence, Tuple

from forensix import __version__
from forensix.advanced_orchestrator import (
    AdvancedTriageConfig,
    AdvancedTriageResult,
    CustodyIntegrityError,
    run_advanced_triage,
)
from forensix.custody_models import CustodyActor

EXIT_SUCCESS = 0
EXIT_CONFIG_ERROR = 1
EXIT_VERIFICATION_DISCREPANCY = 2
EXIT_CUSTODY_FAILURE = 3
EXIT_FILESYSTEM_IO_ERROR = 4


def build_advanced_parser(prog: str = "python3 -m forensix advanced") -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V8.5 advanced forensic triage."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description="ForensiX - Automated Digital Forensics Platform (Schema 8.0 Advanced Triage)",
        epilog="Executes manifest baseline verification, custody ledger tracking, and generates Schema 8.0 reports.",
    )

    parser.add_argument(
        "evidence_directory",
        help="Path to the evidence directory to analyze.",
    )

    parser.add_argument(
        "-m",
        "--manifest",
        dest="manifest_path",
        default=None,
        type=Path,
        help="Path to the evidence manifest baseline JSON file to verify.",
    )

    parser.add_argument(
        "-l",
        "--ledger",
        dest="custody_ledger_path",
        default=None,
        type=Path,
        help="Path to an existing custody ledger JSON file to resume.",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=Path("reports"),
        type=Path,
        help="Directory to store generated forensic reports and custody ledgers (default: reports/).",
    )

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

    parser.add_argument(
        "--actor-role",
        default="Forensic Analyst",
        help="Role designation of the active custodian (default: 'Forensic Analyst').",
    )

    parser.add_argument(
        "--actor-org",
        default=None,
        help="Organization or agency of the active custodian.",
    )

    parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format(s) to generate (default: both).",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Allow overwriting existing report and ledger output files.",
    )

    parser.add_argument(
        "--allow-symlinks",
        action="store_true",
        default=False,
        help="Allow following symbolic links that resolve strictly within the evidence root.",
    )

    parser.add_argument(
        "--verify-only",
        action="store_true",
        default=False,
        help="Execute manifest verification and custody tracking only.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def execute_advanced_cli(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[int, Optional[AdvancedTriageResult]]:
    """
    Execute the advanced triage CLI with argument validation and formatted terminal summary.

    Args:
        argv: Command-line arguments. If None, sys.argv[1:] is used.

    Returns:
        Tuple[int, Optional[AdvancedTriageResult]]: Exit code and execution result.
    """
    parser = build_advanced_parser()

    # Intercept parsing errors gracefully without printing full stack trace
    try:
        args = parser.parse_args(argv)
    except SystemExit as err:
        return (err.code if isinstance(err.code, int) else EXIT_CONFIG_ERROR, None)

    # Resolve report formats
    if args.format == "both":
        formats = ("html", "json")
    elif args.format == "html":
        formats = ("html",)
    else:
        formats = ("json",)

    # Construct case metadata
    case_meta = {}
    if args.case_id:
        case_meta["case_id"] = str(args.case_id).strip()
    if args.case_name:
        case_meta["case_name"] = str(args.case_name).strip()
    if args.investigator:
        case_meta["investigator"] = str(args.investigator).strip()

    # Construct actor
    actor_identity = args.investigator or "ForensiX Analyst"
    actor = CustodyActor(
        declared_identity=actor_identity,
        role=args.actor_role,
        organization=args.actor_org,
    )

    config = AdvancedTriageConfig(
        evidence_directory=args.evidence_directory,
        output_dir=args.output_dir,
        case_metadata=case_meta,
        manifest_path=args.manifest_path,
        custody_ledger_path=args.custody_ledger_path,
        actor=actor,
        formats=formats,
        allow_symlinks=args.allow_symlinks,
        overwrite=args.overwrite,
        verify_only=args.verify_only,
    )

    try:
        result = run_advanced_triage(config)

        # Print clean, professional terminal summary
        print("=" * 60)
        print("ForensiX Advanced Forensic Triage Summary (Schema 8.0)")
        print("=" * 60)
        print(f"Case ID            : {result.report.case_metadata.get('case_id') or 'N/A'}")
        print(f"Report ID          : {result.report.report_id}")
        print(f"Evidence Target    : {Path(config.evidence_directory).name}")

        if result.manifest_verification:
            mv = result.manifest_verification
            status_str = "VERIFIED" if mv.overall_status else "DISCREPANCY DETECTED"
            print(f"Manifest Status    : {status_str} ({mv.verified_count}/{mv.total_entries} matched, "
                  f"{mv.mismatch_count} mismatch, {mv.missing_count} missing, {mv.error_count} errors)")
        else:
            print("Manifest Status    : NONE (Manifest not provided)")

        chain_status = result.custody_verification.integrity_status
        total_evts = len(result.custody_ledger)
        term_h = result.custody_ledger.terminal_hash or "none"
        short_term = f"{term_h[:12]}...{term_h[-8:]}" if len(term_h) == 64 else term_h
        print(f"Custody Chain      : {chain_status} ({total_evts} events, terminal digest: {short_term})")

        if result.json_report_path:
            print(f"JSON Report        : {result.json_report_path}")
        if result.html_report_path:
            print(f"HTML Report        : {result.html_report_path}")
        if result.ledger_path:
            print(f"Custody Ledger     : {result.ledger_path}")

        print("=" * 60)

        if not result.execution_success:
            print("Notice: Manifest integrity verification detected discrepancies.", file=sys.stderr)
            return (EXIT_VERIFICATION_DISCREPANCY, result)

        return (EXIT_SUCCESS, result)

    except CustodyIntegrityError as err:
        print(f"Custody Integrity Failure: {err}", file=sys.stderr)
        return (EXIT_CUSTODY_FAILURE, None)
    except (FileNotFoundError, NotADirectoryError, FileExistsError, PermissionError, IsADirectoryError) as err:
        print(f"Filesystem Error: {err}", file=sys.stderr)
        return (EXIT_FILESYSTEM_IO_ERROR, None)
    except (ValueError, TypeError) as err:
        print(f"Configuration Error: {err}", file=sys.stderr)
        return (EXIT_CONFIG_ERROR, None)
    except OSError as err:
        print(f"I/O Failure: {err}", file=sys.stderr)
        return (EXIT_FILESYSTEM_IO_ERROR, None)
    except Exception as err:
        print(f"Internal Error: An unexpected error occurred: {err}", file=sys.stderr)
        return (EXIT_CONFIG_ERROR, None)


def advanced_main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entry point for V8.5 Advanced Forensic Triage."""
    exit_code, _ = execute_advanced_cli(argv)
    return exit_code
