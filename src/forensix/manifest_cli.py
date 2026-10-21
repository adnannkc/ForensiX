"""
Command-Line Interface for ForensiX Manifest Engine (V8.6).

Provides dedicated CLI subcommands for:
1. `create`: Deterministic generation of Schema 8.0 forensic manifest baselines.
2. `verify`: Cryptographic integrity verification of evidence directories against manifests.

Approved Exit Code Contract:
- 0: Generation succeeded, or verification completed with zero discrepancies.
- 1: Configuration, schema, or command argument error.
- 2: Manifest verification discrepancy (hash mismatch, missing evidence file, or entry error).
- 4: Filesystem or I/O error (file not found, permission denied, collision, etc.).
"""

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.manifest_generator import (
    ManifestGeneratorConfig,
    generate_manifest,
    save_manifest,
)
from forensix.manifest_models import ManifestRecord
from forensix.manifest_verifier import (
    ManifestVerificationResult,
    verify_manifest,
)

EXIT_SUCCESS = 0
EXIT_CONFIG_ERROR = 1
EXIT_VERIFICATION_DISCREPANCY = 2
EXIT_FILESYSTEM_IO_ERROR = 4


def build_manifest_parser(prog: str = "python3 -m forensix manifest") -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V8.6 forensic manifest operations."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description="ForensiX - Forensic Manifest Engine (Schema 8.0)",
        epilog="Generates deterministic manifest baselines and verifies cryptographic evidence integrity.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: create
    create_parser = subparsers.add_parser(
        "create",
        help="Generate a deterministic cryptographic manifest baseline for an evidence directory.",
        description="Recursively scan evidence files and generate a ForensiX Schema 8.0 ManifestRecord.",
    )
    create_parser.add_argument(
        "evidence_directory",
        help="Path to the evidence directory to inventory.",
    )
    create_parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        type=Path,
        help="Path to write the generated manifest JSON file.",
    )
    create_parser.add_argument(
        "--case-id",
        dest="case_id",
        default=None,
        help="Incident case tracking identifier.",
    )
    create_parser.add_argument(
        "--investigator",
        dest="investigator",
        default=None,
        help="Name or identification of handling investigator.",
    )
    create_parser.add_argument(
        "--algorithms",
        dest="algorithms",
        choices=["sha256", "md5", "both"],
        default="both",
        help="Cryptographic hashing algorithms to compute (default: both).",
    )
    create_parser.add_argument(
        "--allow-symlinks",
        dest="allow_symlinks",
        action="store_true",
        default=False,
        help="Follow symbolic links that resolve strictly within the evidence root.",
    )
    create_parser.add_argument(
        "--overwrite",
        dest="overwrite",
        action="store_true",
        default=False,
        help="Allow overwriting an existing output manifest file.",
    )

    # Subcommand: verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify evidence directory integrity against an existing manifest baseline.",
        description="Verify evidence files against cryptographic digests recorded in a ForensiX Schema 8.0 manifest.",
    )
    verify_parser.add_argument(
        "evidence_directory",
        help="Path to the evidence directory containing files to verify.",
    )
    verify_parser.add_argument(
        "-m",
        "--manifest",
        dest="manifest",
        required=True,
        type=Path,
        help="Path to the manifest JSON baseline file to verify against.",
    )
    verify_parser.add_argument(
        "--allow-symlinks",
        dest="allow_symlinks",
        action="store_true",
        default=False,
        help="Follow symbolic links that resolve strictly within the evidence root.",
    )

    return parser


def execute_manifest_cli(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[int, Optional[Union[ManifestRecord, ManifestVerificationResult]]]:
    """
    Execute the manifest CLI with argument validation, error containment, and factual summary output.

    Args:
        argv: Command-line arguments. If None, sys.argv[1:] is used.

    Returns:
        Tuple[int, Optional[Union[ManifestRecord, ManifestVerificationResult]]]: Exit code and result object.
    """
    parser = build_manifest_parser()

    # Intercept parsing errors gracefully without raw tracebacks
    try:
        args = parser.parse_args(argv)
    except SystemExit as err:
        code = 0 if err.code == 0 else EXIT_CONFIG_ERROR
        return (code, None)

    if not getattr(args, "subcommand", None):
        parser.print_help(sys.stderr)
        return (EXIT_CONFIG_ERROR, None)

    try:
        if args.subcommand == "create":
            if args.algorithms == "both":
                algos: Tuple[str, ...] = ("sha256", "md5")
            elif args.algorithms == "sha256":
                algos = ("sha256",)
            elif args.algorithms == "md5":
                algos = ("md5",)
            else:
                algos = (str(args.algorithms),)

            manifest = generate_manifest(
                evidence_dir=args.evidence_directory,
                output_path=args.output,
                case_id=args.case_id,
                investigator=args.investigator,
                algorithms=algos,
                allow_symlinks=args.allow_symlinks,
                overwrite=args.overwrite,
            )

            print("=" * 60)
            print("ForensiX Forensic Manifest Generation Summary (Schema 8.0)")
            print("=" * 60)
            print(f"Manifest ID        : {manifest.manifest_id}")
            print(f"Case ID            : {manifest.case_id or 'N/A'}")
            print(f"Investigator       : {manifest.investigator or 'N/A'}")
            ev_name = Path(args.evidence_directory).name or str(args.evidence_directory)
            print(f"Evidence Target    : {ev_name}")
            print(f"Total Entries      : {len(manifest.entries)}")
            print(f"Algorithms         : {', '.join(sorted(algos))}")
            if args.output:
                out_name = Path(args.output).name or str(args.output)
                print(f"Output File        : {out_name}")
            print("=" * 60)

            return (EXIT_SUCCESS, manifest)

        elif args.subcommand == "verify":
            verification = verify_manifest(
                manifest=args.manifest,
                base_dir=args.evidence_directory,
                allow_symlinks=args.allow_symlinks,
            )

            print("=" * 60)
            print("ForensiX Forensic Manifest Verification Summary (Schema 8.0)")
            print("=" * 60)
            print(f"Manifest ID        : {verification.manifest_id}")
            ev_name = Path(args.evidence_directory).name or str(args.evidence_directory)
            print(f"Evidence Target    : {ev_name}")
            status_str = "VERIFIED (Zero Discrepancies)" if verification.overall_status else "DISCREPANCY DETECTED"
            print(f"Verification Status: {status_str}")
            print(f"Total Entries      : {verification.total_entries}")
            print(f"Verified (Matched) : {verification.verified_count}")
            print(f"Hash Mismatches    : {verification.mismatch_count}")
            print(f"Missing Files      : {verification.missing_count}")
            print(f"Errors / Rejections: {verification.error_count}")
            print("=" * 60)

            if not verification.overall_status:
                print("Notice: Manifest verification detected discrepancies or errors.", file=sys.stderr)
                return (EXIT_VERIFICATION_DISCREPANCY, verification)

            return (EXIT_SUCCESS, verification)

        else:
            print(f"Configuration Error: Unknown subcommand '{args.subcommand}'", file=sys.stderr)
            return (EXIT_CONFIG_ERROR, None)

    except (FileNotFoundError, NotADirectoryError, FileExistsError, PermissionError, IsADirectoryError) as err:
        print(f"Filesystem Error: {err}", file=sys.stderr)
        return (EXIT_FILESYSTEM_IO_ERROR, None)
    except (ValueError, TypeError, KeyError) as err:
        print(f"Configuration Error: {err}", file=sys.stderr)
        return (EXIT_CONFIG_ERROR, None)
    except OSError as err:
        print(f"Filesystem Error: {err}", file=sys.stderr)
        return (EXIT_FILESYSTEM_IO_ERROR, None)
    except Exception as err:
        print(f"Internal Error: An unexpected error occurred: {err}", file=sys.stderr)
        return (EXIT_CONFIG_ERROR, None)


def manifest_main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entry point for V8.6 Forensic Manifest Engine."""
    exit_code, _ = execute_manifest_cli(argv)
    return exit_code
