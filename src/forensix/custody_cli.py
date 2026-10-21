"""
Command-Line Interface for ForensiX Custody Engine (V8.7).

Provides dedicated CLI subcommands for:
1. `init`: Initialize a new ForensiX Schema 8.0 chain-of-custody ledger.
2. `transfer`: Record a formal bilateral custody transfer and optional receipt.
3. `audit`: Perform comprehensive cryptographic, possession-continuity, and digest audit.

Exit Code Contract:
- 0: Successful operation or verified audit (status == 'VERIFIED').
- 1: Command syntax, argument, or configuration error.
- 2: Non-tampered discrepancy detected or incomplete history ('DISCREPANCY_DETECTED', 'INCOMPLETE_HISTORY').
- 3: Cryptographic or structural chain integrity failure ('TAMPERED').
- 4: Filesystem, I/O, or collision error (including post-commit receipt write failure).
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Optional, Sequence, Tuple, Union

from forensix import __version__
from forensix.custody_ledger import (
    CustodyLedger,
    StaleLedgerError,
)
from forensix.custody_models import CustodyActor
from forensix.custody_transfer import (
    CustodyAuditResult,
    CustodyTransferReceipt,
    CustodyTransferRecord,
    audit_custody_ledger,
    generate_transfer_receipt,
    record_transfer,
)

EXIT_SUCCESS = 0
EXIT_CONFIG_ERROR = 1
EXIT_AUDIT_DISCREPANCY = 2
EXIT_CUSTODY_FAILURE = 3
EXIT_FILESYSTEM_IO_ERROR = 4


def build_custody_parser(prog: str = "python3 -m forensix custody") -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser for V8.7 custody operations."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description="ForensiX - Forensic Chain-of-Custody Engine (Schema 8.0)",
        epilog="Initializes custody ledgers, records bilateral transfers, and audits chain integrity.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ForensiX {__version__}",
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # -------------------------------------------------------------------------
    # Subcommand: init
    # -------------------------------------------------------------------------
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new ForensiX Schema 8.0 custody ledger file.",
        description="Create an empty, validated custody ledger container.",
    )
    init_parser.add_argument(
        "-o",
        "--output",
        dest="output",
        required=True,
        type=Path,
        help="Destination path for the new custody ledger JSON file.",
    )
    init_parser.add_argument(
        "--case-id",
        dest="case_id",
        default=None,
        help="Incident case tracking identifier (e.g. CASE-2026-001).",
    )
    init_parser.add_argument(
        "--description",
        dest="description",
        default=None,
        help="Factual description of ledger context.",
    )
    init_parser.add_argument(
        "--overwrite",
        dest="overwrite",
        action="store_true",
        default=False,
        help="Allow overwriting an existing destination ledger file.",
    )

    # -------------------------------------------------------------------------
    # Subcommand: transfer
    # -------------------------------------------------------------------------
    transfer_parser = subparsers.add_parser(
        "transfer",
        help="Record a formal bilateral custody transfer between declared custodians.",
        description="Commit a formal custody transfer record and generate an optional receipt.",
    )
    transfer_parser.add_argument(
        "-l",
        "--ledger",
        dest="ledger",
        required=True,
        type=Path,
        help="Path to the custody ledger JSON file to update.",
    )
    transfer_parser.add_argument(
        "--evidence-id",
        dest="evidence_id",
        required=True,
        help="ForensiX evidence tracking identifier (e.g. EV-1001).",
    )
    # Releasing Actor
    transfer_parser.add_argument(
        "--from-name",
        dest="from_name",
        required=True,
        help="Full declared name/ID of releasing custodian.",
    )
    transfer_parser.add_argument(
        "--from-role",
        dest="from_role",
        default=None,
        help="Role designation of releasing custodian.",
    )
    transfer_parser.add_argument(
        "--from-org",
        dest="from_org",
        default=None,
        help="Organization or unit of releasing custodian.",
    )
    transfer_parser.add_argument(
        "--from-contact",
        dest="from_contact",
        default=None,
        help="Contact info of releasing custodian.",
    )
    # Receiving Actor
    transfer_parser.add_argument(
        "--to-name",
        dest="to_name",
        required=True,
        help="Full declared name/ID of receiving custodian.",
    )
    transfer_parser.add_argument(
        "--to-role",
        dest="to_role",
        default=None,
        help="Role designation of receiving custodian.",
    )
    transfer_parser.add_argument(
        "--to-org",
        dest="to_org",
        default=None,
        help="Organization or unit of receiving custodian.",
    )
    transfer_parser.add_argument(
        "--to-contact",
        dest="to_contact",
        default=None,
        help="Contact info of receiving custodian.",
    )
    # Locations
    transfer_parser.add_argument(
        "--from-loc",
        dest="from_loc",
        required=True,
        help="Originating storage locker, lab, or station.",
    )
    transfer_parser.add_argument(
        "--to-loc",
        dest="to_loc",
        required=True,
        help="Destination storage locker, lab, or station.",
    )
    # Context
    transfer_parser.add_argument(
        "--reason",
        dest="reason",
        required=True,
        help="Factual purpose for transfer.",
    )
    transfer_parser.add_argument(
        "--auth",
        dest="auth",
        default=None,
        help="Legal or administrative reference identifier.",
    )
    transfer_parser.add_argument(
        "--condition",
        dest="condition",
        default=None,
        help="Factual packaging or physical condition notes.",
    )
    transfer_parser.add_argument(
        "--sha256",
        dest="sha256",
        default=None,
        help="Verified SHA-256 hex digest of evidence at handover.",
    )
    transfer_parser.add_argument(
        "--md5",
        dest="md5",
        default=None,
        help="Verified MD5 hex digest of evidence at handover.",
    )
    transfer_parser.add_argument(
        "--verification-method",
        dest="verification_method",
        default=None,
        help="Method used to verify evidence digests.",
    )
    # Receipt Outputs
    transfer_parser.add_argument(
        "--receipt-out",
        dest="receipt_out",
        default=None,
        type=Path,
        help="Destination path to write printable text transfer receipt.",
    )
    transfer_parser.add_argument(
        "--receipt-json",
        dest="receipt_json",
        default=None,
        type=Path,
        help="Destination path to write machine-readable JSON transfer receipt.",
    )

    # -------------------------------------------------------------------------
    # Subcommand: audit
    # -------------------------------------------------------------------------
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit custody ledger cryptographic integrity, continuity, and digests.",
        description="Verify cryptographic hash chain, possession continuity, chronology, and digest baselines.",
    )
    audit_parser.add_argument(
        "-l",
        "--ledger",
        dest="ledger",
        required=True,
        type=Path,
        help="Path to the custody ledger JSON file to audit.",
    )
    audit_parser.add_argument(
        "-m",
        "--manifest",
        dest="manifest",
        default=None,
        type=Path,
        help="Optional path to Schema 8.0 manifest baseline file.",
    )
    audit_parser.add_argument(
        "-e",
        "--evidence-dir",
        dest="evidence_dir",
        default=None,
        type=Path,
        help="Optional evidence directory root (required if manifest needs on-demand verification).",
    )
    audit_parser.add_argument(
        "--allow-symlinks",
        dest="allow_symlinks",
        action="store_true",
        default=False,
        help="Follow regular file symlinks contained within evidence root during verification.",
    )
    audit_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Output structured audit result in pure JSON format to stdout.",
    )
    audit_parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        type=Path,
        help="Optional destination file path to write audit report.",
    )

    return parser


def execute_custody_cli(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[int, Optional[Union[CustodyLedger, CustodyTransferReceipt, CustodyAuditResult]]]:
    """
    Execute the custody CLI with argument validation, error containment, and exit code reporting.

    Args:
        argv: Command line arguments.

    Returns:
        Tuple[int, Optional[Union[CustodyLedger, CustodyTransferReceipt, CustodyAuditResult]]]
    """
    parser = build_custody_parser()

    class InterceptingParser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            raise ValueError(message)

    # Intercept parsing errors gracefully
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    try:
        args = parser.parse_args(raw_args)
    except SystemExit as exc:
        code = 0 if exc.code == 0 else EXIT_CONFIG_ERROR
        return code, None
    except Exception as exc:
        sys.stderr.write(f"Configuration Error: {exc}\n")
        return EXIT_CONFIG_ERROR, None

    # Dispatch Subcommands
    subcmd = getattr(args, "subcommand", None)

    # -------------------------------------------------------------------------
    # 1. custody init
    # -------------------------------------------------------------------------
    if subcmd == "init":
        out_path = Path(args.output).resolve()
        try:
            ledger = CustodyLedger(case_id=args.case_id, description=args.description)
            ledger.save_to_file(path=out_path, overwrite=args.overwrite)
            sys.stdout.write(
                f"SUCCESS: Initialized empty ForensiX Schema 8.0 custody ledger at '{out_path}'\n"
                f"  Ledger ID: {ledger.ledger_id}\n"
                f"  Case ID:   {ledger.case_id or 'None'}\n"
            )
            return EXIT_SUCCESS, ledger
        except FileExistsError as err:
            sys.stderr.write(f"Filesystem Error: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None
        except IsADirectoryError as err:
            sys.stderr.write(f"Filesystem Error: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None
        except ValueError as err:
            sys.stderr.write(f"Configuration Error: {err}\n")
            return EXIT_CONFIG_ERROR, None
        except Exception as err:
            sys.stderr.write(f"Filesystem Error: Failed to initialize custody ledger: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

    # -------------------------------------------------------------------------
    # 2. custody transfer
    # -------------------------------------------------------------------------
    if subcmd == "transfer":
        ledger_path = Path(args.ledger).resolve()
        if not ledger_path.exists():
            sys.stderr.write(f"Filesystem Error: Ledger file does not exist: '{ledger_path}'\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

        try:
            ledger = CustodyLedger.load_from_file(ledger_path)
        except StaleLedgerError as err:
            sys.stderr.write(f"Filesystem Error: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None
        except ValueError as err:
            sys.stderr.write(f"Configuration Error: {err}\n")
            return EXIT_CONFIG_ERROR, None
        except Exception as err:
            sys.stderr.write(f"Filesystem Error: Failed to load custody ledger: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

        # Build Actors
        try:
            releasing_actor = CustodyActor(
                declared_identity=args.from_name,
                role=args.from_role,
                organization=args.from_org,
                contact_info=args.from_contact,
            )
            receiving_actor = CustodyActor(
                declared_identity=args.to_name,
                role=args.to_role,
                organization=args.to_org,
                contact_info=args.to_contact,
            )
        except Exception as err:
            sys.stderr.write(f"Configuration Error: Invalid actor metadata: {err}\n")
            return EXIT_CONFIG_ERROR, None

        # Parse Hashes
        hashes_list = []
        if args.sha256:
            hashes_list.append(("sha256", args.sha256.strip().lower()))
        if args.md5:
            hashes_list.append(("md5", args.md5.strip().lower()))

        # Record Transfer in memory
        try:
            ev, transfer = record_transfer(
                ledger=ledger,
                evidence_id=args.evidence_id,
                releasing_actor=releasing_actor,
                receiving_actor=receiving_actor,
                source_location=args.from_loc,
                destination_location=args.to_loc,
                reason=args.reason,
                authorization_ref=args.auth,
                condition_notes=args.condition,
                hashes=hashes_list,
                verification_method=args.verification_method,
            )
        except Exception as err:
            sys.stderr.write(f"Configuration Error: Failed to construct transfer record: {err}\n")
            return EXIT_CONFIG_ERROR, None

        # Commit Ledger to Disk
        try:
            ledger.save_to_file(path=ledger_path, overwrite=True)
        except StaleLedgerError as err:
            sys.stderr.write(f"Filesystem Error: Stale ledger state detected: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None
        except Exception as err:
            sys.stderr.write(f"Filesystem Error: Failed to commit transfer to ledger file: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

        # Generate Receipt
        receipt: Optional[CustodyTransferReceipt] = None
        receipt_write_error: Optional[str] = None
        if args.receipt_out or args.receipt_json:
            receipt = generate_transfer_receipt(transfer=transfer, ledger=ledger)

            if args.receipt_out:
                out_txt = Path(args.receipt_out).resolve()
                try:
                    out_txt.parent.mkdir(parents=True, exist_ok=True)
                    out_txt.write_text(receipt.render_text(), encoding="utf-8")
                except Exception as err:
                    receipt_write_error = f"Failed to write text receipt to '{out_txt}': {err}"

            if args.receipt_json and not receipt_write_error:
                out_js = Path(args.receipt_json).resolve()
                try:
                    out_js.parent.mkdir(parents=True, exist_ok=True)
                    out_js.write_text(receipt.to_json(indent=2), encoding="utf-8")
                except Exception as err:
                    receipt_write_error = f"Failed to write JSON receipt to '{out_js}': {err}"

        # Dual reporting if receipt failed after commit
        if receipt_write_error:
            sys.stdout.write(
                f"SUCCESS: Transfer '{transfer.transfer_id}' successfully committed to ledger '{ledger_path.name}'.\n"
            )
            sys.stderr.write(
                f"ERROR: {receipt_write_error}\n"
                f"NOTE: The transfer record is committed and safely preserved in the ledger file.\n"
            )
            return EXIT_FILESYSTEM_IO_ERROR, receipt

        # Clean Success Output
        sys.stdout.write(
            f"SUCCESS: Committed formal custody transfer to '{ledger_path.name}'\n"
            f"  Transfer ID:         {transfer.transfer_id}\n"
            f"  Evidence Item:       {transfer.evidence_id}\n"
            f"  Releasing Custodian: {transfer.releasing_actor.declared_identity}\n"
            f"  Receiving Custodian: {transfer.receiving_actor.declared_identity}\n"
            f"  Source Location:     {transfer.source_location}\n"
            f"  Destination:         {transfer.destination_location}\n"
            f"  Committed Hash:      {ev.record_hash}\n"
        )
        if args.receipt_out:
            sys.stdout.write(f"  Receipt (text):      {args.receipt_out}\n")
        if args.receipt_json:
            sys.stdout.write(f"  Receipt (JSON):      {args.receipt_json}\n")

        return EXIT_SUCCESS, receipt or transfer

    # -------------------------------------------------------------------------
    # 3. custody audit
    # -------------------------------------------------------------------------
    if subcmd == "audit":
        ledger_path = Path(args.ledger).resolve()
        if not ledger_path.exists():
            sys.stderr.write(f"Filesystem Error: Ledger file does not exist: '{ledger_path}'\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

        try:
            audit_res = audit_custody_ledger(
                ledger_or_path=ledger_path,
                manifest=args.manifest,
                evidence_directory=args.evidence_dir,
                allow_symlinks=args.allow_symlinks,
            )
        except Exception as err:
            sys.stderr.write(f"Filesystem Error: Unexpected audit failure: {err}\n")
            return EXIT_FILESYSTEM_IO_ERROR, None

        # Write or print output
        output_text = (
            audit_res.to_json(indent=2)
            if args.json_output
            else audit_res.render_summary()
        )

        if args.output:
            out_file = Path(args.output).resolve()
            try:
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_file.write_text(output_text, encoding="utf-8")
            except Exception as err:
                sys.stderr.write(f"Filesystem Error: Failed to write audit report to '{out_file}': {err}\n")
                return EXIT_FILESYSTEM_IO_ERROR, audit_res
        else:
            sys.stdout.write(output_text)

        # Determine exit code from audit_status
        if audit_res.audit_status == "VERIFIED":
            return EXIT_SUCCESS, audit_res
        elif audit_res.audit_status in ("DISCREPANCY_DETECTED", "INCOMPLETE_HISTORY"):
            return EXIT_AUDIT_DISCREPANCY, audit_res
        elif audit_res.audit_status == "TAMPERED":
            return EXIT_CUSTODY_FAILURE, audit_res
        else:
            return EXIT_CONFIG_ERROR, audit_res

    sys.stderr.write("Configuration Error: Subcommand required ('init', 'transfer', 'audit')\n")
    return EXIT_CONFIG_ERROR, None


def custody_main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for forensix custody."""
    exit_code, _ = execute_custody_cli(argv)
    return exit_code
