"""
Storage and persistence engine for ForensiX investigator notes.

Ensures notes are written only to notes_<case_id>.json outside evidence directories
using atomic write semantics.
"""

import json
import os
from pathlib import Path
from typing import Optional, Sequence, Union
import uuid

from forensix.notes_models import InvestigatorNote, NotesDocument


def get_notes_filename(case_id: str) -> str:
    """Return standard filename for case notes: notes_<case_id>.json."""
    clean_id = case_id.strip()
    return f"notes_{clean_id}.json"


def check_evidence_root_separation(
    target_path: Path, evidence_roots: Optional[Sequence[Union[str, Path]]] = None
) -> None:
    """Assert target_path does not collide with or reside within any evidence root directory."""
    if not evidence_roots:
        return

    resolved_target = target_path.resolve()
    for root in evidence_roots:
        if root is None:
            continue
        resolved_root = Path(root).resolve()
        if resolved_target == resolved_root:
            raise ValueError(
                f"Notes destination cannot overwrite evidence root: '{resolved_target}'"
            )
        try:
            resolved_target.relative_to(resolved_root)
            is_within = True
        except ValueError:
            is_within = False

        if is_within:
            raise ValueError(
                f"Notes destination cannot reside within evidence directory: '{resolved_target}'"
            )


def load_notes(path_or_dir: Union[str, Path], case_id: Optional[str] = None) -> NotesDocument:
    """
    Load NotesDocument from file path or output directory.

    If target does not exist and case_id is provided, returns an empty NotesDocument.
    """
    p = Path(path_or_dir).resolve()
    if p.is_dir():
        if not case_id:
            raise ValueError("case_id required when path_or_dir points to a directory")
        target_file = p / get_notes_filename(case_id)
    else:
        target_file = p

    if not target_file.exists():
        cid = case_id if case_id else "UNKNOWN"
        return NotesDocument(case_id=cid)

    if not target_file.is_file():
        raise ValueError(f"Notes path is not a regular file: '{target_file}'")

    with target_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return NotesDocument.from_dict(data)


def save_notes(
    doc: NotesDocument,
    output_dir: Union[str, Path],
    evidence_roots: Optional[Sequence[Union[str, Path]]] = None,
) -> Path:
    """
    Persist NotesDocument atomically to notes_<case_id>.json in output_dir.

    Raises ValueError if destination resides within or equals any evidence root.
    """
    out_path = Path(output_dir).resolve()
    dest = out_path / get_notes_filename(doc.case_id)

    # Check evidence root separation
    check_evidence_root_separation(dest, evidence_roots=evidence_roots)

    dest.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write via temporary sibling file
    temp_file = dest.with_name(f".{dest.name}.tmp.{uuid.uuid4().hex}")
    content = doc.to_json(indent=2)

    try:
        temp_file.write_text(content, encoding="utf-8")
        os.replace(temp_file, dest)
    finally:
        if temp_file.exists():
            try:
                temp_file.unlink()
            except OSError:
                pass

    return dest


def add_note(
    case_id: str,
    note: InvestigatorNote,
    output_dir: Union[str, Path],
    evidence_roots: Optional[Sequence[Union[str, Path]]] = None,
) -> Path:
    """
    Append an investigator note to notes_<case_id>.json without altering existing notes.

    Loads the existing document if present, appends the new note, and saves atomically.
    """
    out_path = Path(output_dir).resolve()
    notes_file = out_path / get_notes_filename(case_id)

    if notes_file.exists():
        doc = load_notes(notes_file, case_id=case_id)
    else:
        doc = NotesDocument(case_id=case_id)

    doc.append_note(note)
    return save_notes(doc, output_dir=out_path, evidence_roots=evidence_roots)
