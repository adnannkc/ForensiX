"""
Forensic File Metadata and Identification Analyzer for ForensiX.

Responsible for inspecting file-system metadata (size, POSIX permissions, timestamps),
identifying basic file characteristics (extension, MIME type hint), and orchestrating
unified forensic analysis results without modifying original evidence files.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import mimetypes
import os
from pathlib import Path
import stat
from typing import Any, Dict, Optional, Union

from forensix.evidence import EvidenceRecord, register_evidence
from forensix.hasher import compute_hashes


@dataclass(frozen=True)
class FileInfo:
    """
    Immutable representation of basic file identification attributes.

    Attributes:
        filename: Name of the file including extension.
        size: Size of the file in bytes.
        extension: File extension suffix (e.g. '.txt') or empty string.
        type: Basic file type / MIME hint (e.g. 'text/plain') or None.
    """

    filename: str
    size: int
    extension: str
    type: Optional[str] = None

    @property
    def mime_type(self) -> Optional[str]:
        """Backward-compatible alias for the type attribute."""
        return self.type

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "filename": self.filename,
            "size": self.size,
            "extension": self.extension,
            "type": self.type,
        }


@dataclass(frozen=True)
class FileMetadata:
    """
    Immutable representation of filesystem metadata.

    Attributes:
        permissions: Standard 4-digit POSIX octal string (e.g. '0644').
        modified: ISO 8601 UTC timestamp of last content modification.
        accessed: ISO 8601 UTC timestamp of last access.
        created: ISO 8601 UTC timestamp of file creation/birth, or None if unavailable.
    """

    permissions: str
    modified: str
    accessed: str
    created: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class HashResult:
    """
    Immutable representation of cryptographic hash digests.

    Attributes:
        md5: Hexadecimal MD5 digest.
        sha256: Hexadecimal SHA-256 digest.
    """

    md5: str
    sha256: str

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class ForensicAnalysisResult:
    """
    Unified, immutable data structure combining all forensic analysis sections.

    Sections:
        evidence: EvidenceRecord from evidence registration (ID, path, registered_at).
        file: FileInfo containing name, size, extension, and MIME type hint.
        metadata: FileMetadata containing permissions and filesystem timestamps.
        hashes: HashResult containing MD5 and SHA-256 cryptographic digests.
    """

    evidence: EvidenceRecord
    file: FileInfo
    metadata: FileMetadata
    hashes: HashResult

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the complete unified forensic analysis result into a nested dictionary.
        Prepares the data model for JSON serialization in subsequent reporting.
        """
        return {
            "evidence": self.evidence.to_dict(),
            "file": self.file.to_dict(),
            "metadata": self.metadata.to_dict(),
            "hashes": self.hashes.to_dict(),
        }


def _get_birthtime(stat_result: os.stat_result) -> Optional[float]:
    """
    Attempt to extract file birth/creation timestamp if supported by the OS and filesystem.

    On Linux, standard POSIX stat() does not universally expose st_birthtime.
    We do NOT substitute st_ctime (which represents inode status change time, NOT creation time).

    Returns:
        Optional[float]: Epoch timestamp in seconds if available, otherwise None.
    """
    if hasattr(stat_result, "st_birthtime"):
        return getattr(stat_result, "st_birthtime")

    return None


def extract_file_info(
    file_path: Union[str, Path],
    stat_result: Optional[os.stat_result] = None,
) -> Dict[str, Any]:
    """
    Extract basic file identity attributes.

    Note on File Identification:
    - Suffix/extension and MIME types derived here are identification hints based on standard
      library filename mappings (mimetypes module).
    - They do NOT inspect raw file headers (magic bytes) and do NOT guarantee or prove the actual
      file format or content authenticity.

    Args:
        file_path: Path to the target evidence file.
        stat_result: Optional pre-collected os.stat_result to avoid redundant stat calls.

    Returns:
        Dict[str, Any]: Basic file attributes including:
            - path: Canonical absolute path
            - filename: Name of the file with extension
            - size: File size in bytes
            - extension: Extension string (e.g. '.txt') or empty string ''
            - mime_type: Guessed MIME type (e.g. 'text/plain') or None
    """
    target = Path(file_path).resolve()
    _validate_target(target)

    if stat_result is None:
        stat_result = target.stat()

    mime_type, _ = mimetypes.guess_type(target)

    return {
        "path": str(target),
        "filename": target.name,
        "size": stat_result.st_size,
        "extension": target.suffix,
        "mime_type": mime_type,
    }


def extract_metadata(
    file_path: Union[str, Path],
    stat_result: Optional[os.stat_result] = None,
) -> Dict[str, Any]:
    """
    Extract filesystem metadata for an evidence file.

    Forensic Metadata Considerations:
    - Permissions: Recorded as standard 4-digit POSIX octal string (e.g. '0644').
    - Timestamps: Recorded in ISO 8601 UTC format.
    - Created/Birth time: Only recorded if exposed by OS/filesystem; otherwise set to None.
    - atime (access time): Represents the last recorded read time. Reading file content
      during forensic analysis (e.g. hashing) can alter atime on filesystems mounted with
      default relatime/strictatime. In strict forensics, write-blocking mounts or read-only
      copies should be used.

    Args:
        file_path: Path to the target evidence file.
        stat_result: Optional pre-collected os.stat_result to avoid redundant stat calls.

    Returns:
        Dict[str, Any]: Filesystem metadata dictionary:
            - permissions: 4-digit octal string (e.g. '0644')
            - modified: ISO 8601 timestamp string in UTC
            - accessed: ISO 8601 timestamp string in UTC
            - created: ISO 8601 timestamp string in UTC or None
    """
    target = Path(file_path).resolve()
    _validate_target(target)

    if stat_result is None:
        stat_result = target.stat()

    permissions_octal = f"{stat.S_IMODE(stat_result.st_mode):04o}"
    modified_iso = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat()
    accessed_iso = datetime.fromtimestamp(stat_result.st_atime, tz=timezone.utc).isoformat()

    birthtime = _get_birthtime(stat_result)
    created_iso = (
        datetime.fromtimestamp(birthtime, tz=timezone.utc).isoformat()
        if birthtime is not None
        else None
    )

    return {
        "permissions": permissions_octal,
        "modified": modified_iso,
        "accessed": accessed_iso,
        "created": created_iso,
    }


def analyze_file_metadata(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Extract both file identification and filesystem metadata using a single stat call.

    Args:
        file_path: Path to the target evidence file.

    Returns:
        Dict[str, Any]: Structured dictionary with 'file' and 'metadata' sections.
    """
    target = Path(file_path).resolve()
    _validate_target(target)

    # Perform a single stat call to minimize filesystem access
    stat_result = target.stat()

    return {
        "file": extract_file_info(target, stat_result=stat_result),
        "metadata": extract_metadata(target, stat_result=stat_result),
    }


def analyze_evidence(
    file_path: Union[str, Path],
    evidence_id: Optional[str] = None,
) -> ForensicAnalysisResult:
    """
    Orchestrate unified forensic analysis on an evidence file.

    Reuses and combines:
    1. Evidence Registration (register_evidence from evidence.py)
    2. File Metadata & Identification (analyze_file_metadata from analyzer.py)
    3. Dual Cryptographic Hashing (compute_hashes from hasher.py)

    Args:
        file_path: Path to the evidence file.
        evidence_id: Optional custom evidence ID string.

    Returns:
        ForensicAnalysisResult: An immutable, typed analysis result containing
            evidence, file, metadata, and hashes sections.
    """
    target = Path(file_path).resolve()

    # 1. Register evidence (also validates existence, regularity, directory check)
    evidence_record = register_evidence(target, evidence_id=evidence_id)

    # 2. Extract file identification and filesystem metadata
    meta_dict = analyze_file_metadata(target)

    # 3. Calculate cryptographic hashes
    hashes_dict = compute_hashes(target)

    file_info = FileInfo(
        filename=meta_dict["file"]["filename"],
        size=meta_dict["file"]["size"],
        extension=meta_dict["file"]["extension"],
        type=meta_dict["file"]["mime_type"],
    )

    file_metadata = FileMetadata(
        permissions=meta_dict["metadata"]["permissions"],
        modified=meta_dict["metadata"]["modified"],
        accessed=meta_dict["metadata"]["accessed"],
        created=meta_dict["metadata"]["created"],
    )

    hash_result = HashResult(
        md5=hashes_dict["md5"],
        sha256=hashes_dict["sha256"],
    )

    return ForensicAnalysisResult(
        evidence=evidence_record,
        file=file_info,
        metadata=file_metadata,
        hashes=hash_result,
    )


def _validate_target(target: Path) -> None:
    """Validate that the target exists, is accessible, and is a regular file."""
    if not target.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {target}")
    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {target}")
    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: {target}")
