"""
Investigator Notes Domain Models for ForensiX.

Provides immutable representations and schema definitions for investigator annotations
stored strictly separately from evidence files, reports, and custody records.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
import uuid

NOTES_SCHEMA_VERSION: str = "1.0"

_RE_UUIDV4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

ALLOWED_NOTE_KEYS = frozenset({"note_id", "created_at", "author", "target", "text"})


def generate_note_id() -> str:
    """Generate a canonical NOTE-<UUIDv4> identifier."""
    return f"NOTE-{uuid.uuid4()}"


def is_valid_note_id(note_id: Any) -> bool:
    """Validate that note_id strictly matches NOTE-<UUIDv4>."""
    if not isinstance(note_id, str) or not note_id.startswith("NOTE-"):
        return False
    raw_uuid = note_id[5:]
    return bool(_RE_UUIDV4.match(raw_uuid))


def validate_target(target: str) -> str:
    """
    Validate that target strictly matches one of the three allowed forms:
    1. 'case'
    2. 'evidence:<name>' (where <name> is non-empty)
    3. 'finding:<rule_name>' (where <rule_name> is non-empty)
    """
    if not isinstance(target, str):
        raise TypeError("target must be a string")
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("target cannot be empty")

    if cleaned == "case":
        return cleaned

    if cleaned.startswith("evidence:"):
        ev_name = cleaned[9:].strip()
        if not ev_name:
            raise ValueError(
                f"Invalid target '{cleaned}': 'evidence:' must be followed by a non-empty evidence name"
            )
        return f"evidence:{ev_name}"

    if cleaned.startswith("finding:"):
        finding_name = cleaned[8:].strip()
        if not finding_name:
            raise ValueError(
                f"Invalid target '{cleaned}': 'finding:' must be followed by a non-empty finding rule name"
            )
        return f"finding:{finding_name}"

    raise ValueError(
        f"Invalid note target '{cleaned}'. Allowed target forms are: 'case', "
        "'evidence:<name>', or 'finding:<rule_name>'"
    )


@dataclass
class InvestigatorNote:
    """
    Representation of an individual investigator note.

    Attributes:
        author: Examiner/analyst identifier (1-128 chars).
        target: Target identifier ('case', 'evidence:<name>', or 'finding:<rule_name>').
        text: Factual observation text (1-2000 chars).
        note_id: Unique NOTE-<UUIDv4> identifier.
        created_at: ISO 8601 UTC timestamp string.
    """

    author: str
    target: str
    text: str
    note_id: Optional[str] = None
    created_at: Optional[str] = None

    def __post_init__(self) -> None:
        # Validate and bound author
        if not isinstance(self.author, str):
            raise TypeError("author must be a string")
        clean_author = self.author.strip()
        if not clean_author:
            raise ValueError("author cannot be empty or whitespace")
        if len(clean_author) > 128:
            raise ValueError(
                f"author length ({len(clean_author)}) exceeds maximum limit of 128 characters"
            )
        self.author = clean_author

        # Validate target form
        self.target = validate_target(self.target)

        # Validate and bound text
        if not isinstance(self.text, str):
            raise TypeError("text must be a string")
        clean_text = self.text.strip()
        if not clean_text:
            raise ValueError("text cannot be empty or whitespace")
        if len(clean_text) > 2000:
            raise ValueError(
                f"text length ({len(clean_text)}) exceeds maximum limit of 2000 characters"
            )
        self.text = clean_text

        # Validate / assign note_id
        if self.note_id is None or not self.note_id.strip():
            self.note_id = generate_note_id()
        else:
            self.note_id = self.note_id.strip()
            if not is_valid_note_id(self.note_id):
                raise ValueError(
                    f"Invalid note_id '{self.note_id}': must conform to canonical NOTE-<UUIDv4>"
                )

        # Validate / assign created_at
        if self.created_at is None or not self.created_at.strip():
            self.created_at = datetime.now(timezone.utc).isoformat()
        else:
            self.created_at = self.created_at.strip()
            if not (self.created_at.endswith("Z") or self.created_at.endswith("+00:00")):
                raise ValueError(
                    f"created_at '{self.created_at}' must be a UTC ISO 8601 timestamp ending in 'Z' or '+00:00'"
                )

    def to_dict(self) -> Dict[str, Any]:
        """Convert note to a JSON-serializable dictionary."""
        return {
            "note_id": self.note_id,
            "created_at": self.created_at,
            "author": self.author,
            "target": self.target,
            "text": self.text,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InvestigatorNote":
        """Reconstitute an InvestigatorNote from dictionary while forbidding unknown/verdict fields."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")

        # Check for unauthorized fields
        extra_keys = set(data.keys()) - ALLOWED_NOTE_KEYS
        if extra_keys:
            raise ValueError(
                f"Forbidden or unrecognized fields in note: {sorted(extra_keys)}. "
                "Verdicts, conclusions, severity, and extra fields are forbidden."
            )

        return cls(
            note_id=data.get("note_id"),
            created_at=data.get("created_at"),
            author=data.get("author", ""),
            target=data.get("target", ""),
            text=data.get("text", ""),
        )


@dataclass
class NotesDocument:
    """
    Container document for all investigator notes attached to a case.

    Stored strictly in notes_<case_id>.json.
    """

    case_id: str
    schema_version: str = NOTES_SCHEMA_VERSION
    notes: List[InvestigatorNote] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str):
            raise TypeError("case_id must be a string")
        clean_cid = self.case_id.strip()
        if not clean_cid:
            raise ValueError("case_id cannot be empty or whitespace")
        self.case_id = clean_cid

        if not isinstance(self.schema_version, str):
            raise TypeError("schema_version must be a string")
        self.schema_version = self.schema_version.strip()

        if not isinstance(self.notes, list):
            self.notes = list(self.notes)

    def append_note(self, note: InvestigatorNote) -> None:
        """Append an investigator note to the document."""
        if not isinstance(note, InvestigatorNote):
            raise TypeError(f"Expected InvestigatorNote, got {type(note).__name__}")
        self.notes.append(note)

    def to_dict(self) -> Dict[str, Any]:
        """Convert document to JSON dictionary."""
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "notes": [n.to_dict() for n in self.notes],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize document to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NotesDocument":
        """Deserialize NotesDocument from dictionary."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")

        case_id = data.get("case_id", "")
        schema_version = data.get("schema_version", NOTES_SCHEMA_VERSION)
        raw_notes = data.get("notes", [])
        if not isinstance(raw_notes, list):
            raise TypeError("notes must be a list")

        notes = [InvestigatorNote.from_dict(item) for item in raw_notes]
        return cls(case_id=case_id, schema_version=schema_version, notes=notes)
