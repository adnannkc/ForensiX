"""
Forensic Manifest Integrity Verification Engine for ForensiX (V8.2).

Provides a deterministic, strictly read-only integrity verification engine that evaluates
evidence files against recorded manifest baseline digests without altering underlying evidence,
following symlinks outside designated evidence roots, or loading large evidence files into memory.

Core Principles & Evidentiary Boundaries:
1. Strict Read-Only Evidence Access:
   Evidence files are opened strictly in binary read-only mode ('rb'). No file modifications,
   renames, touches, or deletions are ever performed.
2. Bounded-Memory Streaming:
   Files are read in fixed 64 KB chunks to guarantee small, constant memory overhead regardless
   of evidence file size (from bytes to gigabytes).
3. Path Containment & Escape Prevention:
   All relative paths are canonicalized against the designated base directory.
   Resolution is strictly verified using standard-library path containment (is_relative_to).
   String-prefix checks are rejected to prevent path collision vulnerabilities.
4. Symlink Safety Policy:
   By default (allow_symlinks=False), all symbolic links are rejected without following them.
   When explicitly permitted (allow_symlinks=True), links are resolved and verified to remain
   strictly contained within the base directory root.
5. TOCTOU & Concurrency Notice:
   On POSIX filesystems without kernel-level directory subtree pinning, external concurrent
   processes with write permissions could theoretically modify files after verification.
   For maximum defensibility, evidence targets should be mounted read-only at the OS or
   hardware write-blocker level.
6. Honest Evidentiary Reporting:
   A successful hash match confirms solely that current file bytes match the recorded digest.
   It does NOT establish legal chain of custody, absence of pre-acquisition tampering, or lack of malware.
7. Determinism:
   To ensure byte-for-byte deterministic output for identical inputs and filesystem states,
   dynamic execution timestamps are intentionally omitted from the core analytical result model.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from forensix.hasher import DEFAULT_CHUNK_SIZE
from forensix.manifest_models import (
    ManifestEntry,
    ManifestRecord,
    ManifestVerificationStatus,
    validate_relative_entry_path,
)

MANIFEST_VERIFICATION_NOTICE: str = (
    "NOTICE: Cryptographic verification confirms that current file contents match recorded "
    "manifest digests. Verification does NOT establish original authenticity, absence of "
    "pre-collection tampering, absence of malware, or legal validity of evidence."
)

SUPPORTED_ALGORITHMS: Tuple[str, ...] = ("sha256", "md5")


@dataclass(frozen=True)
class ManifestEntryVerification:
    """
    Immutable representation of the verification outcome for an individual manifest entry.

    Attributes:
        relative_path: Validated relative POSIX path matching the manifest entry.
        status: ManifestVerificationStatus indicating the exact outcome.
        expected_hashes: Tuple of (algorithm, digest) pairs expected from the manifest entry.
        computed_hashes: Tuple of (algorithm, digest) pairs actually computed from file bytes.
        algorithm_matches: Tuple of (algorithm, bool) indicating per-algorithm match outcomes.
        file_size_bytes: Actual size in bytes if readable on disk, or None if missing/unreadable.
        error_message: Explanatory error message or warning without leaking sensitive host paths.
    """

    relative_path: str
    status: ManifestVerificationStatus
    expected_hashes: Tuple[Tuple[str, str], ...] = ()
    computed_hashes: Tuple[Tuple[str, str], ...] = ()
    algorithm_matches: Tuple[Tuple[str, bool], ...] = ()
    file_size_bytes: Optional[int] = None
    error_message: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate and defensively freeze entry verification fields."""
        if not isinstance(self.status, ManifestVerificationStatus):
            if isinstance(self.status, str):
                try:
                    object.__setattr__(self, "status", ManifestVerificationStatus(self.status))
                except ValueError:
                    raise ValueError(f"Invalid verification status: '{self.status}'")
            else:
                raise TypeError(f"status must be ManifestVerificationStatus, got {type(self.status).__name__}")

        if not isinstance(self.expected_hashes, tuple):
            object.__setattr__(self, "expected_hashes", tuple(self.expected_hashes))
        if not isinstance(self.computed_hashes, tuple):
            object.__setattr__(self, "computed_hashes", tuple(self.computed_hashes))
        if not isinstance(self.algorithm_matches, tuple):
            object.__setattr__(self, "algorithm_matches", tuple(self.algorithm_matches))

    @property
    def is_verified(self) -> bool:
        """True iff this entry's status is VERIFIED."""
        return self.status == ManifestVerificationStatus.VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry verification result to a clean, JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "relative_path": self.relative_path,
            "status": self.status.value,
            "expected_hashes": dict(self.expected_hashes),
            "computed_hashes": dict(self.computed_hashes),
            "algorithm_matches": dict(self.algorithm_matches),
            "file_size_bytes": self.file_size_bytes,
        }
        if self.error_message is not None:
            d["error_message"] = self.error_message
        return d


@dataclass(frozen=True)
class ManifestVerificationResult:
    """
    Immutable representation of the overall manifest integrity verification result.

    Note: Execution timestamps are intentionally omitted from this core model to ensure
    100% deterministic output for identical evidence and manifest inputs.

    Attributes:
        manifest_id: Identifier of the verified manifest.
        manifest_version: Version of the manifest schema ('8.0').
        base_dir: Sanitized base directory string.
        total_entries: Total number of manifest entries evaluated.
        verified_count: Count of entries with status VERIFIED.
        mismatch_count: Count of entries with status MISMATCH.
        missing_count: Count of entries with status FILE_MISSING.
        error_count: Count of entries with PERMISSION_DENIED, PATH_TRAVERSAL_DETECTED,
                     UNSUPPORTED_ALGORITHM, or SYMLINK_REJECTED.
        overall_status: True iff total_entries > 0 and verified_count == total_entries.
        entry_results: Deterministically sorted tuple of ManifestEntryVerification instances.
        evidentiary_notice: Standard disclaimer documenting the boundaries of cryptographic verification.
    """

    manifest_id: str
    manifest_version: str
    base_dir: str
    total_entries: int
    verified_count: int
    mismatch_count: int
    missing_count: int
    error_count: int
    overall_status: bool
    entry_results: Tuple[ManifestEntryVerification, ...]
    evidentiary_notice: str = MANIFEST_VERIFICATION_NOTICE

    def __post_init__(self) -> None:
        """Enforce internal consistency of counts and overall status."""
        if not isinstance(self.entry_results, tuple):
            object.__setattr__(self, "entry_results", tuple(self.entry_results))

        # Re-derive counts to prevent fabricated or inconsistent summary metrics
        derived_total = len(self.entry_results)
        derived_verified = sum(1 for e in self.entry_results if e.status == ManifestVerificationStatus.VERIFIED)
        derived_mismatch = sum(1 for e in self.entry_results if e.status == ManifestVerificationStatus.MISMATCH)
        derived_missing = sum(1 for e in self.entry_results if e.status == ManifestVerificationStatus.FILE_MISSING)
        derived_error = sum(
            1 for e in self.entry_results
            if e.status in (
                ManifestVerificationStatus.PERMISSION_DENIED,
                ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED,
                ManifestVerificationStatus.UNSUPPORTED_ALGORITHM,
                ManifestVerificationStatus.SYMLINK_REJECTED,
            )
        )

        object.__setattr__(self, "total_entries", derived_total)
        object.__setattr__(self, "verified_count", derived_verified)
        object.__setattr__(self, "mismatch_count", derived_mismatch)
        object.__setattr__(self, "missing_count", derived_missing)
        object.__setattr__(self, "error_count", derived_error)

        is_overall_success = bool(derived_total > 0 and derived_verified == derived_total)
        object.__setattr__(self, "overall_status", is_overall_success)

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete verification result to a pure, JSON-serializable dictionary."""
        return {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "base_dir": self.base_dir,
            "total_entries": self.total_entries,
            "verified_count": self.verified_count,
            "mismatch_count": self.mismatch_count,
            "missing_count": self.missing_count,
            "error_count": self.error_count,
            "overall_status": self.overall_status,
            "entry_results": [r.to_dict() for r in self.entry_results],
            "evidentiary_notice": self.evidentiary_notice,
        }


def _is_path_contained(base_dir: Path, candidate_path: Path) -> bool:
    """
    Check if candidate_path is strictly within base_dir using path canonicalization.

    Avoids prefix string matching to prevent sibling-directory containment escapes.
    """
    try:
        candidate_path.resolve().relative_to(base_dir.resolve())
        return True
    except (ValueError, RuntimeError):
        return False


@dataclass(frozen=True)
class _RawManifestEntry:
    """Lightweight representation for entries from dictionaries that fail strict model validation."""

    relative_path: str
    size_bytes: int = 0
    hashes: Tuple[Tuple[str, str], ...] = ()
    artifact_type: str = "evidence"
    evidence_id: Optional[str] = None
    metadata: Tuple[Any, ...] = ()
    parse_error: Optional[str] = None


def _verify_single_entry(
    entry: Union[ManifestEntry, _RawManifestEntry, Any],
    resolved_base: Path,
    allow_symlinks: bool,
    chunk_size: int,
) -> ManifestEntryVerification:
    """
    Verify an individual manifest entry against the filesystem under resolved_base.

    Follows strict safety and failure isolation rules without raising unhandled exceptions.
    """
    raw_h = getattr(entry, "hashes", ())
    if isinstance(raw_h, Mapping):
        expected_pairs = tuple(sorted((str(k).strip().lower(), str(v).strip().lower()) for k, v in raw_h.items()))
    elif isinstance(raw_h, (list, tuple)):
        expected_pairs = tuple(sorted((str(k).strip().lower(), str(v).strip().lower()) for k, v in raw_h))
    else:
        expected_pairs = ()

    # 1. Path safety and containment check
    try:
        clean_rel = validate_relative_entry_path(entry.relative_path)
    except (ValueError, TypeError) as err:
        return ManifestEntryVerification(
            relative_path=str(entry.relative_path),
            status=ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED,
            expected_hashes=expected_pairs,
            error_message=f"Invalid manifest relative path: {err}",
        )

    target_path = resolved_base / clean_rel

    # Check for symlink segments along the path
    # If symlinks are disallowed, neither the target nor any parent under base_dir may be a symlink
    if not allow_symlinks:
        current = target_path
        while current != resolved_base and current != current.parent:
            if current.is_symlink():
                return ManifestEntryVerification(
                    relative_path=clean_rel,
                    status=ManifestVerificationStatus.SYMLINK_REJECTED,
                    expected_hashes=expected_pairs,
                    error_message=f"Symbolic link detected on path '{clean_rel}'; symlinks are rejected by policy",
                )
            current = current.parent
    else:
        # allow_symlinks is True: verify resolved target is strictly contained in resolved_base
        if not _is_path_contained(resolved_base, target_path):
            return ManifestEntryVerification(
                relative_path=clean_rel,
                status=ManifestVerificationStatus.PATH_TRAVERSAL_DETECTED,
                expected_hashes=expected_pairs,
                error_message=f"Path resolves outside evidence base directory: '{clean_rel}'",
            )

    # 2. Check existence
    if not target_path.exists():
        # Distinguish broken symlinks from regular missing files
        if target_path.is_symlink():
            if not allow_symlinks:
                return ManifestEntryVerification(
                    relative_path=clean_rel,
                    status=ManifestVerificationStatus.SYMLINK_REJECTED,
                    expected_hashes=expected_pairs,
                    error_message=f"Broken symbolic link rejected by policy: '{clean_rel}'",
                )
            return ManifestEntryVerification(
                relative_path=clean_rel,
                status=ManifestVerificationStatus.FILE_MISSING,
                expected_hashes=expected_pairs,
                error_message=f"Target of symbolic link does not exist for '{clean_rel}'",
            )
        return ManifestEntryVerification(
            relative_path=clean_rel,
            status=ManifestVerificationStatus.FILE_MISSING,
            expected_hashes=expected_pairs,
            error_message=f"File not found on disk: '{clean_rel}'",
        )

    # 3. Check regular file status (reject directories, FIFO pipes, sockets, devices)
    if not target_path.is_file():
        if target_path.is_dir():
            return ManifestEntryVerification(
                relative_path=clean_rel,
                status=ManifestVerificationStatus.PERMISSION_DENIED,
                expected_hashes=expected_pairs,
                error_message=f"Target path is a directory, not a regular evidence file: '{clean_rel}'",
            )
        return ManifestEntryVerification(
            relative_path=clean_rel,
            status=ManifestVerificationStatus.PERMISSION_DENIED,
            expected_hashes=expected_pairs,
            error_message=f"Target is a special device or non-regular file: '{clean_rel}'",
        )

    # 4. Check algorithm support
    # To prevent misleading verification, if ANY algorithm in the entry is unsupported,
    # the entry cannot be fully verified.
    unsupported_algos = [algo for algo, _ in expected_pairs if algo not in SUPPORTED_ALGORITHMS]
    if unsupported_algos:
        return ManifestEntryVerification(
            relative_path=clean_rel,
            status=ManifestVerificationStatus.UNSUPPORTED_ALGORITHM,
            expected_hashes=expected_pairs,
            error_message=(
                f"Manifest entry contains unsupported algorithm(s) {unsupported_algos}. "
                f"Supported algorithms are: {list(SUPPORTED_ALGORITHMS)}"
            ),
        )

    # 5. Read-only streaming hash computation
    algos_needed = {algo for algo, _ in expected_pairs}
    hashers: Dict[str, Any] = {}
    for algo in algos_needed:
        if algo == "sha256":
            hashers["sha256"] = hashlib.sha256()
        elif algo == "md5":
            try:
                hashers["md5"] = hashlib.md5(usedforsecurity=False)
            except TypeError:
                hashers["md5"] = hashlib.md5()

    total_bytes = 0
    try:
        with target_path.open(mode="rb") as stream:
            while chunk := stream.read(chunk_size):
                total_bytes += len(chunk)
                for h in hashers.values():
                    h.update(chunk)
    except PermissionError:
        return ManifestEntryVerification(
            relative_path=clean_rel,
            status=ManifestVerificationStatus.PERMISSION_DENIED,
            expected_hashes=expected_pairs,
            error_message=f"Permission denied opening evidence file: '{clean_rel}'",
        )
    except OSError as err:
        return ManifestEntryVerification(
            relative_path=clean_rel,
            status=ManifestVerificationStatus.PERMISSION_DENIED,
            expected_hashes=expected_pairs,
            error_message=f"OS error reading evidence file '{clean_rel}': {err.strerror or str(err)}",
        )

    # 6. Compare computed digests against expected digests
    computed_pairs = tuple(sorted((algo, h.hexdigest()) for algo, h in hashers.items()))
    computed_dict = dict(computed_pairs)

    algorithm_matches: List[Tuple[str, bool]] = []
    all_matched = True

    for algo, expected_digest in expected_pairs:
        actual_digest = computed_dict.get(algo)
        matched = (actual_digest == expected_digest.lower())
        algorithm_matches.append((algo, matched))
        if not matched:
            all_matched = False

    status = ManifestVerificationStatus.VERIFIED if all_matched else ManifestVerificationStatus.MISMATCH

    return ManifestEntryVerification(
        relative_path=clean_rel,
        status=status,
        expected_hashes=expected_pairs,
        computed_hashes=computed_pairs,
        algorithm_matches=tuple(sorted(algorithm_matches, key=lambda x: x[0])),
        file_size_bytes=total_bytes,
        error_message=None if all_matched else f"Cryptographic digest mismatch detected for '{clean_rel}'",
    )


def verify_manifest(
    manifest: Union[ManifestRecord, Mapping[str, Any], Path, str],
    base_dir: Union[Path, str],
    allow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ManifestVerificationResult:
    """
    Verify the cryptographic integrity of evidence files described in a manifest.

    Guarantees:
    - Evidence files are opened strictly in binary read-only mode ('rb').
    - Evidence files are never modified, renamed, deleted, or executed.
    - Path traversal outside base_dir is strictly blocked.
    - Symlinks are rejected by default (allow_symlinks=False).
    - Multi-algorithm entries require all supported algorithms to match.
    - Unsupported algorithms cannot produce a false success status.
    - Produces deterministically ordered results (sorted by relative_path).

    Args:
        manifest: ManifestRecord instance, deserialized dict, or path to manifest JSON file.
        base_dir: Root directory containing evidence files.
        allow_symlinks: If False (default), symlinks are rejected. If True, symlinks must resolve within base_dir.
        chunk_size: Buffer size for streaming file reads (default: 65,536 bytes).

    Returns:
        ManifestVerificationResult: Complete, immutable verification outcome.

    Raises:
        FileNotFoundError: If base_dir does not exist or manifest file does not exist.
        NotADirectoryError: If base_dir is not a directory.
        ValueError: If manifest format or content is invalid.
    """
    # 1. Validate base directory
    base_path = Path(base_dir).resolve()
    if not base_path.exists():
        raise FileNotFoundError(f"Evidence base directory does not exist: '{base_dir}'")
    if not base_path.is_dir():
        raise NotADirectoryError(f"Evidence base path is not a directory: '{base_dir}'")

    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size}")

    # 2. Ingest and parse manifest
    manifest_id: str
    manifest_version: str
    entries_to_verify: Sequence[Union[ManifestEntry, _RawManifestEntry, Any]]

    if isinstance(manifest, ManifestRecord):
        manifest_id = manifest.manifest_id
        manifest_version = manifest.manifest_version
        entries_to_verify = manifest.entries
    elif isinstance(manifest, (dict, Mapping)):
        # Construct ManifestRecord from mapping or retain raw entries if invalid
        entries_data = manifest.get("entries", [])
        parsed_entries = []
        for e in entries_data:
            if isinstance(e, ManifestEntry):
                parsed_entries.append(e)
            elif isinstance(e, (dict, Mapping)):
                try:
                    parsed_entries.append(
                        ManifestEntry(
                            relative_path=e["relative_path"],
                            size_bytes=e["size_bytes"],
                            hashes=e["hashes"],
                            artifact_type=e.get("artifact_type", "evidence"),
                            evidence_id=e.get("evidence_id"),
                            metadata=e.get("metadata", ()),
                        )
                    )
                except Exception as parse_err:
                    raw_h = e.get("hashes", {})
                    if isinstance(raw_h, Mapping):
                        frozen_h = tuple(sorted((str(k).strip().lower(), str(v).strip().lower()) for k, v in raw_h.items()))
                    elif isinstance(raw_h, (list, tuple)):
                        frozen_h = tuple(sorted((str(k).strip().lower(), str(v).strip().lower()) for k, v in raw_h if len(k) == 2))
                    else:
                        frozen_h = ()
                    parsed_entries.append(
                        _RawManifestEntry(
                            relative_path=str(e.get("relative_path", "")),
                            size_bytes=int(e.get("size_bytes", 0)) if isinstance(e.get("size_bytes"), int) and not isinstance(e.get("size_bytes"), bool) else 0,
                            hashes=frozen_h,
                            parse_error=str(parse_err),
                        )
                    )
            else:
                raise TypeError(f"Invalid entry object in manifest: {type(e).__name__}")

        has_raw = any(isinstance(e, _RawManifestEntry) for e in parsed_entries)
        if not has_raw:
            record = ManifestRecord(
                manifest_id=manifest["manifest_id"],
                manifest_version=manifest.get("manifest_version", "8.0"),
                created_at=manifest["created_at"],
                forensix_version=manifest["forensix_version"],
                case_id=manifest.get("case_id"),
                investigator=manifest.get("investigator"),
                entries=parsed_entries,
            )
            entries_to_verify = record.entries
            manifest_id = record.manifest_id
            manifest_version = record.manifest_version
        else:
            manifest_id = str(manifest.get("manifest_id", "MANIFEST-UNKNOWN"))
            manifest_version = str(manifest.get("manifest_version", "8.0"))
            entries_to_verify = tuple(parsed_entries)
    elif isinstance(manifest, (str, Path)):
        manifest_file = Path(manifest).resolve()
        if not manifest_file.exists():
            raise FileNotFoundError(f"Manifest file does not exist: '{manifest}'")
        if not manifest_file.is_file():
            raise ValueError(f"Manifest path is not a regular file: '{manifest}'")

        try:
            with manifest_file.open(mode="rb") as stream:
                content = json.load(stream)
        except Exception as err:
            raise ValueError(f"Failed to parse manifest JSON '{manifest}': {err}") from err

        return verify_manifest(
            manifest=content,
            base_dir=base_path,
            allow_symlinks=allow_symlinks,
            chunk_size=chunk_size,
        )
    else:
        raise TypeError(
            f"manifest must be a ManifestRecord, dict, or path to manifest JSON, got {type(manifest).__name__}"
        )

    # 3. Deterministically sort entries by relative_path
    sorted_entries = sorted(entries_to_verify, key=lambda e: str(e.relative_path))

    # 4. Verify each entry
    results: List[ManifestEntryVerification] = []
    for entry in sorted_entries:
        entry_result = _verify_single_entry(
            entry=entry,
            resolved_base=base_path,
            allow_symlinks=allow_symlinks,
            chunk_size=chunk_size,
        )
        results.append(entry_result)

    # 5. Construct and return immutable result
    return ManifestVerificationResult(
        manifest_id=manifest_id,
        manifest_version=manifest_version,
        base_dir=str(base_path),
        total_entries=len(results),
        verified_count=0,  # Auto-computed in __post_init__
        mismatch_count=0,
        missing_count=0,
        error_count=0,
        overall_status=False,
        entry_results=tuple(results),
        evidentiary_notice=MANIFEST_VERIFICATION_NOTICE,
    )
