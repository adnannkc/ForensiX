"""
Command Line Interface for ForensiX investigator notes.

Provides subcommands:
  forensix note add   - Append an investigator note
  forensix note list  - List investigator notes for a case
"""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional, TextIO

from forensix.case_config import load_case_config_from_file
from forensix.notes_models import InvestigatorNote
from forensix.notes_storage import add_note, load_notes


def build_note_subparser(parser: argparse.ArgumentParser) -> None:
    """Register note add and note list subcommands."""
    subparsers = parser.add_subparsers(dest="note_action", metavar="ACTION", required=True)

    # forensix note add
    add_parser = subparsers.add_parser("add", help="Add an investigator note to a case.")
    add_parser.add_argument("--case-id", help="Case tracking identifier (e.g. CASE-2026-001).")
    add_parser.add_argument("-c", "--config", help="Path to case.json configuration file.")
    add_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        help="Directory containing case results (where notes_<case_id>.json resides).",
    )
    add_parser.add_argument("--author", required=True, help="Author/analyst name (required, max 128 chars).")
    add_parser.add_argument(
        "--target",
        default="case",
        help="Note target ('case', 'evidence:<name>', or 'finding:<rule_name>'). Default: 'case'.",
    )
    add_parser.add_argument("--text", required=True, help="Note observation text (max 2000 chars).")

    # forensix note list
    list_parser = subparsers.add_parser("list", help="List investigator notes for a case.")
    list_parser.add_argument("--case-id", help="Case tracking identifier.")
    list_parser.add_argument("-c", "--config", help="Path to case.json configuration file.")
    list_parser.add_argument(
        "-o",
        "--output",
        dest="output_dir",
        help="Directory containing case results.",
    )
    list_parser.add_argument("--target", help="Filter notes by target (optional).")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output notes as machine-readable JSON.",
    )


def resolve_case_context(args: argparse.Namespace) -> tuple:
    """Resolve (case_id, output_dir, evidence_roots) from CLI args and optional config."""
    case_id = getattr(args, "case_id", None)
    output_dir = getattr(args, "output_dir", None)
    config_path = getattr(args, "config", None)
    evidence_roots = []

    if config_path:
        cfg = load_case_config_from_file(config_path)
        if not case_id:
            case_id = cfg.case_id
        if not output_dir:
            output_dir = str(cfg.output_dir)
        if cfg.evidence_host_dir:
            evidence_roots.append(cfg.evidence_host_dir)

    if not case_id:
        raise ValueError("Missing --case-id (or specify --config).")
    if not output_dir:
        raise ValueError("Missing -o/--output directory (or specify --config).")

    return case_id, Path(output_dir).resolve(), evidence_roots


def handle_note_add(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    """Handler for forensix note add."""
    try:
        case_id, output_dir, evidence_roots = resolve_case_context(args)
        note = InvestigatorNote(
            author=args.author,
            target=args.target,
            text=args.text,
        )
        saved_file = add_note(
            case_id=case_id,
            note=note,
            output_dir=output_dir,
            evidence_roots=evidence_roots,
        )
        stdout.write(f"Added note {note.note_id} to {saved_file}\n")
        return 0
    except Exception as exc:
        stderr.write(f"Error adding note: {exc}\n")
        return 1


def handle_note_list(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    """Handler for forensix note list."""
    try:
        case_id, output_dir, _ = resolve_case_context(args)
        doc = load_notes(output_dir, case_id=case_id)

        target_filter = getattr(args, "target", None)
        notes = doc.notes
        if target_filter:
            notes = [n for n in notes if n.target == target_filter]

        if getattr(args, "json", False):
            payload = {
                "schema_version": doc.schema_version,
                "case_id": doc.case_id,
                "notes": [n.to_dict() for n in notes],
            }
            stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
            return 0

        stdout.write(f"Investigator Notes for Case: {doc.case_id} ({len(notes)} note(s))\n")
        stdout.write("-" * 72 + "\n")
        if not notes:
            stdout.write("No investigator notes recorded.\n")
            return 0

        for i, n in enumerate(notes, 1):
            stdout.write(f"[{i}] {n.note_id} | {n.created_at}\n")
            stdout.write(f"    Author: {n.author}\n")
            stdout.write(f"    Target: {n.target}\n")
            stdout.write(f"    Text  : {n.text}\n")
            stdout.write("-" * 72 + "\n")

        return 0
    except Exception as exc:
        stderr.write(f"Error listing notes: {exc}\n")
        return 1


def run_note_cli(
    argv: Optional[List[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Entry point for standalone invocation or test harness."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = argparse.ArgumentParser(
        prog="forensix note",
        description="Manage separate investigator notes for ForensiX cases.",
    )
    build_note_subparser(parser)

    try:
        args = parser.parse_args(argv)
    except SystemExit as se:
        return se.code

    if args.note_action == "add":
        return handle_note_add(args, out, err)
    elif args.note_action == "list":
        return handle_note_list(args, out, err)

    err.write(f"Unknown note action: {args.note_action}\n")
    return 1
