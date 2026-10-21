"""
Forensic Manifest Models for ForensiX (V8.1).

Provides strongly typed, deeply immutable dataclasses representing evidence and report
manifest entries and records, including path sanitization rules, hash algorithm specifications,
and deterministic entry sorting.

Strict Security & Forensic Safety Principles:
- Manifest paths must strictly represent relative POSIX paths within a designated package root.
- Rejects empty paths, absolute POSIX paths, Windows drive/absolute paths, and any '..' traversal
  segments rather than silently normalizing or transforming them.
- Non-negative integer sizes with explicit rejection of booleans.
- Requires at least one valid cryptographic digest per entry.
- Deterministic entry sorting by relative_path and strict duplicate path rejection.
"""

from dataclasses import dataclass
from enum import Enum
import re
import types
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import uuid

from forensix.timestamp_normalizer import normalize_timestamp

MANIFEST_SCHEMA_VERSION: str = "8.0"

_RE_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RE_MD5_HEX = re.compile(r"^[0-9a-f]{32}$")
_RE_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:")


class HashAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms for manifest verification."""

    SHA256 = "sha256"
    MD5 = "md5"


class ManifestArtifactType(str, Enum):
    """Categorization of artifacts listed in a manifest."""

    EVIDENCE = "evidence"
    REPORT = "report"
    CUSTODY_LOG = "custody_log"
    ANCILLARY = "ancillary"


class ManifestVerificationStatus(str, Enum):
    """Verification outcome classifications for individual manifest entries."""

    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    FILE_MISSING = "FILE_MISSING"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    PATH_TRAVERSAL_DETECTED = "PATH_TRAVERSAL_DETECTED"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    SYMLINK_REJECTED = "SYMLINK_REJECTED"


def generate_manifest_id() -> str:
    """
    Generate a canonical tracking identifier for a manifest record (MANIFEST-<UUIDv4>).

    Returns:
        str: Unique identifier string conforming to MANIFEST-<UUIDv4>.
    """
    return f"MANIFEST-{uuid.uuid4()}"


def is_valid_manifest_id(manifest_id: Any) -> bool:
    """
    Validate that an identifier strictly conforms to MANIFEST-<UUIDv4>.

    Args:
        manifest_id: Candidate identifier string.

    Returns:
        bool: True if valid MANIFEST-<UUIDv4>, False otherwise.
    """
    if not isinstance(manifest_id, str):
        return False
    if not manifest_id.startswith("MANIFEST-"):
        return False
    raw_uuid = manifest_id[9:]
    try:
        val = uuid.UUID(raw_uuid)
        return val.version == 4 and str(val) == raw_uuid
    except (ValueError, AttributeError, TypeError):
        return False


def validate_relative_entry_path(path: Any) -> str:
    """
    Strictly validate a relative POSIX path for a manifest entry.

    Security Requirements:
    - Must be a non-empty string.
    - Must use forward slashes ('/') exclusively; backslashes ('\\') are rejected.
    - Must NOT be an absolute path (no leading '/').
    - Must NOT contain Windows drive letters (e.g. 'C:') or UNC shares ('\\\\').
    - Must NOT contain traversal segments ('..') or current-dir segments ('.').
    - Must NOT contain empty segments ('//') or trailing slashes (must point to a file).

    Args:
        path: Candidate path string.

    Returns:
        str: Validated relative POSIX path.

    Raises:
        TypeError: If path is not a string.
        ValueError: If path is empty, absolute, or contains traversal/invalid segments.
    """
    if not isinstance(path, str):
        raise TypeError(f"relative_path must be a string, got {type(path).__name__}")

    clean = path.strip()
    if not clean:
        raise ValueError("relative_path cannot be empty or whitespace")

    if "\\" in clean:
        raise ValueError(
            f"Invalid relative_path '{path}': backslashes are not permitted in manifest POSIX relative paths"
        )

    if clean.startswith("/"):
        raise ValueError(
            f"Invalid relative_path '{path}': absolute paths with leading '/' are prohibited in manifests"
        )

    if _RE_WINDOWS_DRIVE.match(clean) or clean.startswith("//"):
        raise ValueError(
            f"Invalid relative_path '{path}': Windows drive letters or UNC paths are prohibited in manifests"
        )

    if clean.endswith("/"):
        raise ValueError(
            f"Invalid relative_path '{path}': manifest paths must point to files, cannot have trailing '/'"
        )

    segments = clean.split("/")
    for segment in segments:
        if segment == "":
            raise ValueError(
                f"Invalid relative_path '{path}': redundant or empty path segment '//' detected"
            )
        if segment == ".":
            raise ValueError(
                f"Invalid relative_path '{path}': redundant current-directory segment '.' detected"
            )
        if segment == "..":
            raise ValueError(
                f"Invalid relative_path '{path}': path traversal segment '..' is strictly prohibited"
            )

    return clean


def _freeze_hashes(
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]],
) -> Tuple[Tuple[str, str], ...]:
    """Validate and freeze hash pairs into a sorted tuple."""
    items: List[Tuple[str, str]] = []
    if isinstance(hashes, Mapping):
        for k, v in hashes.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Hash algorithm and digest must both be strings")
            items.append((k.strip().lower(), v.strip().lower()))
    elif isinstance(hashes, (list, tuple)):
        for pair in hashes:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise TypeError(f"Expected (algorithm, digest) 2-tuple, got {pair!r}")
            k, v = pair
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Hash algorithm and digest must both be strings")
            items.append((k.strip().lower(), v.strip().lower()))
    else:
        raise TypeError(f"hashes must be a Mapping or Sequence of pairs, got {type(hashes).__name__}")

    if not items:
        raise ValueError("ManifestEntry must contain at least one valid cryptographic hash")

    validated: List[Tuple[str, str]] = []
    for algo, digest in items:
        if algo == "sha256":
            if not _RE_SHA256_HEX.match(digest):
                raise ValueError(
                    f"Invalid SHA-256 digest '{digest}': must be exactly 64 lowercase hex characters"
                )
        elif algo == "md5":
            if not _RE_MD5_HEX.match(digest):
                raise ValueError(
                    f"Invalid MD5 digest '{digest}': must be exactly 32 lowercase hex characters"
                )
        else:
            if not algo or not re.match(r"^[a-zA-Z0-9_-]+$", algo):
                raise ValueError(f"Invalid hash algorithm name: '{algo}'")
            if not isinstance(digest, str) or not re.match(r"^[0-9a-f]+$", digest):
                raise ValueError(
                    f"Invalid digest for '{algo}': must be lowercase hex characters"
                )
        validated.append((algo, digest))

    return tuple(sorted(validated, key=lambda x: x[0]))


def _freeze_metadata_value(val: Any) -> Any:
    """Recursively freeze mutable structures (dict, list, set) into immutable mapping proxies and tuples."""
    if isinstance(val, (dict, Mapping)):
        return types.MappingProxyType({k: _freeze_metadata_value(v) for k, v in val.items()})
    elif isinstance(val, (list, tuple, set)):
        return tuple(_freeze_metadata_value(item) for item in val)
    return val


def _unfreeze_metadata_value(val: Any) -> Any:
    """Recursively unfreeze frozen structures (MappingProxyType, tuple) into mutable dicts/lists for JSON serialization."""
    if isinstance(val, (types.MappingProxyType, Mapping)):
        return {k: _unfreeze_metadata_value(v) for k, v in val.items()}
    elif isinstance(val, (tuple, list)):
        return [_unfreeze_metadata_value(item) for item in val]
    return val


def _freeze_metadata(
    metadata: Union[Mapping[str, Any], Sequence[Tuple[str, Any]]],
) -> Tuple[Tuple[str, Any], ...]:
    """Validate and recursively freeze metadata into sorted tuple of (key, value) pairs."""
    items: List[Tuple[str, Any]] = []
    if isinstance(metadata, Mapping):
        for k, v in metadata.items():
            if not isinstance(k, str):
                raise TypeError("Metadata keys must be strings")
            items.append((k.strip(), _freeze_metadata_value(v)))
    elif isinstance(metadata, (list, tuple)):
        for pair in metadata:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise TypeError(f"Expected (key, value) 2-tuple, got {pair!r}")
            k, v = pair
            if not isinstance(k, str):
                raise TypeError("Metadata keys must be strings")
            items.append((k.strip(), _freeze_metadata_value(v)))
    else:
        raise TypeError(f"metadata must be a Mapping or Sequence of pairs, got {type(metadata).__name__}")

    return tuple(sorted(items, key=lambda x: x[0]))


@dataclass(frozen=True)
class ManifestEntry:
    """
    Immutable representation of an individual file or artifact registered in a manifest.

    Attributes:
        relative_path: Validated POSIX-style relative path from the manifest base directory.
        size_bytes: Non-negative file size in bytes.
        hashes: Immutable tuple of (algorithm, digest) pairs sorted alphabetically by algorithm.
        artifact_type: Classification string from ManifestArtifactType.
        evidence_id: Optional ForensiX evidence tracking identifier (e.g. EV-...).
        metadata: Immutable tuple of extra key-value metadata pairs.
    """

    relative_path: str
    size_bytes: int
    hashes: Union[Mapping[str, str], Sequence[Tuple[str, str]]]
    artifact_type: Union[ManifestArtifactType, str] = ManifestArtifactType.EVIDENCE
    evidence_id: Optional[str] = None
    metadata: Union[Mapping[str, Any], Sequence[Tuple[str, Any]]] = ()

    def __post_init__(self) -> None:
        """Validate and defensively freeze all fields."""
        # 1. Path validation
        valid_path = validate_relative_entry_path(self.relative_path)
        object.__setattr__(self, "relative_path", valid_path)

        # 2. Size validation: explicitly reject booleans
        if type(self.size_bytes) is not int or isinstance(self.size_bytes, bool):
            raise TypeError(f"size_bytes must be an integer, got {type(self.size_bytes).__name__}")
        if self.size_bytes < 0:
            raise ValueError(f"size_bytes must be non-negative, got {self.size_bytes}")

        # 3. Hashes validation & freezing
        frozen_hashes = _freeze_hashes(self.hashes)
        object.__setattr__(self, "hashes", frozen_hashes)

        # 4. Artifact Type
        art_type = self.artifact_type.value if isinstance(self.artifact_type, ManifestArtifactType) else str(self.artifact_type)
        valid_types = {e.value for e in ManifestArtifactType}
        if art_type not in valid_types:
            raise ValueError(
                f"Invalid artifact_type '{self.artifact_type}': must be one of {sorted(valid_types)}"
            )
        object.__setattr__(self, "artifact_type", art_type)

        # 5. Evidence ID
        if self.evidence_id is not None:
            if not isinstance(self.evidence_id, str):
                raise TypeError("evidence_id must be a string or None")
            clean_eid = self.evidence_id.strip()
            object.__setattr__(self, "evidence_id", clean_eid if clean_eid else None)

        # 6. Metadata freezing
        frozen_meta = _freeze_metadata(self.metadata)
        object.__setattr__(self, "metadata", frozen_meta)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to a clean, pure JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
            "hashes": dict(self.hashes),
            "artifact_type": self.artifact_type,
            "evidence_id": self.evidence_id,
        }
        if self.metadata:
            d["metadata"] = {k: _unfreeze_metadata_value(v) for k, v in self.metadata}
        return d


@dataclass(frozen=True)
class ManifestRecord:
    """
    Immutable representation of a complete investigation package manifest.

    Attributes:
        manifest_id: Unique manifest tracking identifier conforming to MANIFEST-<UUIDv4>.
        manifest_version: Version of the manifest schema, fixed to '8.0'.
        created_at: ISO 8601 UTC timestamp string of manifest creation.
        forensix_version: Software release version creating the manifest.
        case_id: Optional incident tracking identifier.
        investigator: Optional handling investigator name/ID.
        entries: Immutable tuple of ManifestEntry instances, deterministically sorted by relative_path.
    """

    manifest_id: str
    manifest_version: str
    created_at: str
    forensix_version: str
    entries: Sequence[ManifestEntry]
    case_id: Optional[str] = None
    investigator: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate record fields, enforce deterministic sorting, and reject duplicate paths."""
        # 1. Manifest ID
        if not is_valid_manifest_id(self.manifest_id):
            raise ValueError(
                f"Invalid manifest_id '{self.manifest_id}': must conform to canonical MANIFEST-<UUIDv4>"
            )

        # 2. Schema version
        if not isinstance(self.manifest_version, str) or self.manifest_version.strip() != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"manifest_version must be '{MANIFEST_SCHEMA_VERSION}', got '{self.manifest_version}'"
            )
        object.__setattr__(self, "manifest_version", MANIFEST_SCHEMA_VERSION)

        # 3. Created At timestamp
        if not isinstance(self.created_at, str):
            raise TypeError("created_at must be an ISO 8601 timestamp string")
        clean_ts = self.created_at.strip()
        if not clean_ts:
            raise ValueError("created_at cannot be empty or whitespace")
        normalize_timestamp(clean_ts, to_utc=False)
        object.__setattr__(self, "created_at", clean_ts)

        # 4. Software version
        if not isinstance(self.forensix_version, str) or not self.forensix_version.strip():
            raise ValueError("forensix_version must be a non-empty string")
        object.__setattr__(self, "forensix_version", self.forensix_version.strip())

        # 5. Optional metadata
        for field_name in ("case_id", "investigator"):
            val = getattr(self, field_name)
            if val is not None:
                if not isinstance(val, str):
                    raise TypeError(f"{field_name} must be a string or None")
                cleaned = val.strip()
                object.__setattr__(self, field_name, cleaned if cleaned else None)

        # 6. Entries validation and duplicate detection
        if not isinstance(self.entries, (list, tuple)):
            raise TypeError(f"entries must be a Sequence of ManifestEntry instances, got {type(self.entries).__name__}")

        validated_entries: List[ManifestEntry] = []
        seen_paths: set = set()
        for idx, entry in enumerate(self.entries):
            if not isinstance(entry, ManifestEntry):
                raise TypeError(
                    f"Entry at index {idx} must be a ManifestEntry instance, got {type(entry).__name__}"
                )
            if entry.relative_path in seen_paths:
                raise ValueError(
                    f"Duplicate relative_path detected in manifest: '{entry.relative_path}'"
                )
            seen_paths.add(entry.relative_path)
            validated_entries.append(entry)

        # Deterministically sort entries alphabetically by relative_path
        sorted_entries = tuple(sorted(validated_entries, key=lambda e: e.relative_path))
        object.__setattr__(self, "entries", sorted_entries)

    @property
    def entry_count(self) -> int:
        """Total number of entries in the manifest."""
        return len(self.entries)

    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest record to a pure, JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "created_at": self.created_at,
            "forensix_version": self.forensix_version,
            "case_id": self.case_id,
            "investigator": self.investigator,
            "entry_count": self.entry_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        return d
