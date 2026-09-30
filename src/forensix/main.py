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


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python3 -m forensix",
        description="ForensiX - Automated Digital Forensics & Incident Triage Platform (V1)",
        epilog="Analyzes evidence files in binary read-only mode and writes JSON reports to reports/.",
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for ForensiX.

    Orchestrates:
    1. Parsing and validating command-line arguments.
    2. Registering the evidence item.
    3. Extracting file metadata and identification hints.
    4. Streaming dual cryptographic hashes (MD5 and SHA-256).
    5. Constructing a unified ForensicAnalysisResult.
    6. Generating an indented, isolated JSON report.
    7. Printing a clean, concise terminal summary.

    Returns:
        int: 0 on success, non-zero on failure.
    """
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
