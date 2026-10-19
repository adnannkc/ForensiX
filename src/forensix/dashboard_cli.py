"""
Command-Line Interface for ForensiX Local Read-Only Dashboard & Pivot Drill-Down (V7.5).

Provides entry-point orchestration for starting the offline, loopback-only ForensiX
dashboard server, ingesting report files or directories, and serving the interactive UI.

Strict Boundaries:
- Read-Only & Non-Destructive: Never modifies evidence files or input reports.
- Loopback Enforcement: Binds strictly to loopback addresses ('127.0.0.1', 'localhost').
- Air-Gapped & Offline: Zero external requests, CDN dependencies, or telemetries.
- Defensive Error Handling: Returns clean, non-sensitive error messages and exit codes without tracebacks.
"""

import argparse
from pathlib import Path
import signal
import sys
import time
from typing import Optional, Sequence, Tuple

from forensix import __version__
from forensix.dashboard_service import (
    ALLOWED_LOOPBACK_HOSTS,
    DEFAULT_DASHBOARD_HOST,
    DEFAULT_DASHBOARD_PORT,
    DashboardReportRegistry,
    DashboardServer,
    create_dashboard_server,
)
from forensix.report_reader import (
    DEFAULT_MAX_REPORT_SIZE_BYTES,
    ReportReaderError,
)


def build_dashboard_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for ForensiX Dashboard (V7.5)."""
    parser = argparse.ArgumentParser(
        prog="python3 -m forensix dashboard",
        description="ForensiX - Local Read-Only Investigation Dashboard & Cross-Domain Pivoting (V7.5)",
        epilog=(
            "Starts a local, read-only HTTP dashboard bound strictly to loopback (127.0.0.1).\n"
            "Pre-loads and indexes forensic reports for interactive exploration and pivot drill-down."
        ),
    )

    parser.add_argument(
        "report_paths",
        nargs="*",
        metavar="REPORT_PATH",
        help="Optional path(s) to forensic report JSON file(s) or director(ies) to ingest and index.",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_DASHBOARD_PORT,
        help=f"Port number to bind local dashboard server (default: {DEFAULT_DASHBOARD_PORT}, 0 for ephemeral).",
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_DASHBOARD_HOST,
        help=f"Loopback host address to bind (strictly restricted to loopback, default: {DEFAULT_DASHBOARD_HOST}).",
    )

    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        default=False,
        help="Recursively scan subdirectories for JSON report files when directory paths are specified.",
    )

    parser.add_argument(
        "--max-report-size",
        type=int,
        default=DEFAULT_MAX_REPORT_SIZE_BYTES,
        help=f"Maximum allowed size in bytes per report file (default: {DEFAULT_MAX_REPORT_SIZE_BYTES}).",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    return parser


def execute_dashboard_cli(
    argv: Optional[Sequence[str]] = None,
    block: bool = True,
    server_instance: Optional[DashboardServer] = None,
) -> Tuple[int, Optional[DashboardServer]]:
    """
    Execute V7.5 Dashboard CLI from command-line arguments.

    Validates inputs, constructs and populates the DashboardReportRegistry,
    starts the loopback DashboardServer, and manages clean lifecycle execution.

    Args:
        argv: Command-line arguments sequence, or None for sys.argv.
        block: If True, blocks on server.serve_forever() until interrupted.
               If False, starts server in background thread and returns immediately (for testing).
        server_instance: Optional pre-configured DashboardServer instance (for dependency injection).

    Returns:
        Tuple[int, Optional[DashboardServer]]: (exit_code, server_instance)
            exit_code: 0 on clean exit, 1 on validation or runtime error.
    """
    parser = build_dashboard_parser()
    args = parser.parse_args(argv)

    # 1. Validate maximum report size limit (non-negative integer, allows 0)
    if args.max_report_size < 0:
        print(
            f"Error: Invalid maximum report size: {args.max_report_size}. Size limit must be a non-negative integer.",
            file=sys.stderr,
        )
        return 1, None

    # 2. Validate port number (0 is allowed for dynamic ephemeral allocation)
    if args.port < 0 or args.port > 65535:
        print(
            f"Error: Invalid port number: {args.port}. Port must be between 1 and 65535 (or 0 for ephemeral).",
            file=sys.stderr,
        )
        return 1, None

    # 2. Validate loopback host
    clean_host = args.host.strip().lower()
    if clean_host not in ALLOWED_LOOPBACK_HOSTS:
        print(
            f"Error: ForensiX dashboard can only bind to loopback ({sorted(ALLOWED_LOOPBACK_HOSTS)}), "
            f"got external host: '{args.host}'. External exposure is blocked for forensic data protection.",
            file=sys.stderr,
        )
        return 1, None

    # 3. Initialize in-memory registry and ingest reports
    registry = DashboardReportRegistry()
    report_paths = args.report_paths

    if report_paths:
        for raw_path in report_paths:
            p = Path(raw_path)
            if not p.exists():
                print(f"Error: Report path does not exist: '{raw_path}'", file=sys.stderr)
                return 1, None

            if p.is_file():
                try:
                    registry.register_file(p, max_size_bytes=args.max_report_size)
                except ReportReaderError as err:
                    print(
                        f"Error: Failed to ingest report file '{raw_path}': {err}",
                        file=sys.stderr,
                    )
                    return 1, None
                except ValueError as err:
                    print(
                        f"Error: Invalid report file '{raw_path}': {err}",
                        file=sys.stderr,
                    )
                    return 1, None
                except OSError as err:
                    print(
                        f"Error: Could not read report file '{raw_path}': {err}",
                        file=sys.stderr,
                    )
                    return 1, None
            elif p.is_dir():
                try:
                    registry.register_directory(
                        p,
                        recursive=args.recursive,
                        max_size_bytes=args.max_report_size,
                    )
                except Exception as err:
                    print(
                        f"Error: Failed to process report directory '{raw_path}': {err}",
                        file=sys.stderr,
                    )
                    return 1, None
            else:
                print(
                    f"Error: Unsupported path type (neither file nor directory): '{raw_path}'",
                    file=sys.stderr,
                )
                return 1, None
    else:
        # Default behavior when no paths are passed: check if default 'reports' directory exists
        default_dir = Path("reports")
        if default_dir.is_dir():
            try:
                registry.register_directory(
                    default_dir,
                    recursive=args.recursive,
                    max_size_bytes=args.max_report_size,
                )
            except (PermissionError, OSError) as err:
                print(
                    f"Error: Failed to process default report directory '{default_dir.name}': {type(err).__name__}",
                    file=sys.stderr,
                )
                return 1, None
            except Exception as err:
                print(
                    f"Error: Unexpected failure processing default report directory '{default_dir.name}': {type(err).__name__}",
                    file=sys.stderr,
                )
                return 1, None
        elif default_dir.exists():
            print(
                f"Error: Default report path '{default_dir.name}' exists but is not a directory.",
                file=sys.stderr,
            )
            return 1, None

    # 4. Create and bind server
    if server_instance is not None:
        server = server_instance
    else:
        try:
            server = create_dashboard_server(
                registry=registry,
                host=clean_host,
                port=args.port,
            )
        except OSError as err:
            print(
                f"Error: Failed to bind dashboard server to {clean_host}:{args.port}: {err}. "
                "Please specify an available port using --port.",
                file=sys.stderr,
            )
            return 1, None
        except Exception as err:
            print(f"Error: Server configuration error: {err}", file=sys.stderr)
            return 1, None

    bound_port = server.bound_port
    dashboard_url = f"http://{clean_host}:{bound_port}/"
    report_count = len(registry.list_reports())
    pivot_counts = registry.get_pivot_counts()
    total_pivot_keys = sum(pivot_counts.values())

    skipped = registry.skipped_reports
    skipped_count = len(skipped)

    # 5. Display clean, informative startup banner
    print("=" * 60)
    print(f"ForensiX Local Investigation Dashboard (v{__version__})")
    print("=" * 60)
    print(f"Host       : {clean_host}")
    print(f"Port       : {bound_port}")
    print(f"URL        : {dashboard_url}")
    print("Binding    : Loopback Only (Offline & Air-Gapped)")
    if skipped_count > 0:
        print(f"Reports    : {report_count} ingested, {skipped_count} skipped ({total_pivot_keys} pivot keys indexed)")
        for item in skipped:
            print(f"  [SKIPPED] {item['filename']}: {item['reason']}")
    else:
        print(f"Reports    : {report_count} ingested ({total_pivot_keys} pivot keys indexed)")
    print("Status     : ACTIVE (Press Ctrl+C to stop)")
    print("=" * 60)

    # 6. Execute server lifecycle
    if not block:
        server.start_background()
        return 0, server

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ForensiX dashboard server...")
    finally:
        server.stop()
        print("Dashboard server stopped cleanly.")

    return 0, server


def dashboard_main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Main CLI entry point for ForensiX Dashboard (V7.5).

    Returns:
        int: 0 on clean exit, non-zero on error.
    """
    exit_code, _ = execute_dashboard_cli(argv, block=True)
    return exit_code
