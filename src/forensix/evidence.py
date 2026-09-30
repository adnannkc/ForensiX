"""
Forensic Evidence Registration Module for ForensiX.

Responsible for registering evidence items with a unique tracking identifier,
recording the original file path and registration timestamp, without modifying
or copying the underlying evidence file.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union
import uuid


@dataclass(frozen=True)
class EvidenceRecord:
    """
    Immutable representation of a registered forensic evidence item.

    Attributes:
        evidence_id: Unique identifier generated for the evidence item (e.g., 'EV-<UUID>').
        original_path: Canonical absolute path to the original evidence file.
        registered_at: ISO 8601 UTC timestamp recording when registration occurred.
    """

    evidence_id: str
    original_path: str
    registered_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert the evidence record to a JSON-serializable dictionary."""
        return asdict(self)


def generate_evidence_id() -> str:
    """
    Generate a unique forensic evidence identifier.

    The ID is generated using a random UUIDv4 and prefixed with 'EV-'.
    It is completely independent of filenames and cryptographic hashes.

    Returns:
        str: Unique evidence ID formatted as 'EV-<UUID>'.
    """
    return f"EV-{uuid.uuid4()}"


def register_evidence(
    file_path: Union[str, Path],
    evidence_id: Optional[str] = None,
) -> EvidenceRecord:
    """
    Register a forensic evidence file.

    Forensic Safety Principles:
    - Does NOT modify, rename, copy, or open the evidence file for writing.
    - Validates that the target path exists and points to a regular file.
    - Captures an immutable registration timestamp in UTC.

    Args:
        file_path: Path to the evidence file (str or Path).
        evidence_id: Optional explicit evidence ID; if omitted, a unique ID is generated.

    Returns:
        EvidenceRecord: The registered evidence object.

    Raises:
        FileNotFoundError: If the evidence file does not exist.
        IsADirectoryError: If the path points to a directory.
        ValueError: If the path is not a regular file.
    """
    target = Path(file_path).resolve()

    if not target.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {target}")

    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {target}")

    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: {target}")

    eid = evidence_id if evidence_id is not None else generate_evidence_id()
    registration_time = datetime.now(timezone.utc).isoformat()

    return EvidenceRecord(
        evidence_id=eid,
        original_path=str(target),
        registered_at=registration_time,
    )
