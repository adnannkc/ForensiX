"""
Forensic Manifest Generation Engine for ForensiX (V8.6).

Provides automated, deterministic, and strictly read-only generation and safe persistence
of ForensiX Schema 8.0 Manifest baselines for forensic evidence directories.

Core Principles & Evidentiary Guarantees:
1. Strict Read-Only Access:
   - Evidence files are opened strictly in binary read-only mode ('rb').
   - Zero modifications, touches, renames, or deletions of evidence files or timestamps.
2. Bounded-Memory Single-Pass Multi-Hashing:
   - Computes SHA-256 and MD5 cryptographic digests in a single streaming read pass
     using 64 KB chunks by default, ensuring constant minimal memory overhead.
3. Path Sanitization & Containment:
   - All manifest relative paths strictly conform to POSIX relative format and are
     validated against validate_relative_entry_path (no leading slashes, backslashes,
     Windows drive letters, or '..' traversal segments).
4. Symlink Safety & Loop Detection:
   - Symlinks are ignored/skipped by default (allow_symlinks=False).
   - When allow_symlinks=True, regular file symlinks are followed and cataloged if their targets
     remain strictly within evidence root. Directory symlinks are verified for containment and
     pruned from traversal recursion with a stderr warning to prevent redundant subtrees and loops.
   - Escaping symlinks raise ValueError. Broken symlinks raise ValueError.
5. Deterministic Lexicographic Sorting:
   - Filesystem traversal sorts directory and file names at every level, guaranteeing
     deterministic, reproducible entry order.
6. Safe Atomic Output Persistence:
   - Rejects writing manifest output files inside or overlapping the evidence root.
   - Refuses to overwrite existing files when overwrite=False using exclusive file creation.
   - Uses temporary sibling files and atomic replacement (os.replace) when overwrite=True.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid

from forensix import __version__
from forensix.hasher import DEFAULT_CHUNK_SIZE
from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    HashAlgorithm,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    generate_manifest_id,
    validate_relative_entry_path,
)

VALID_ALGORITHMS: Tuple[str, ...] = ("sha256", "md5")


@dataclass(frozen=True)
class ManifestGeneratorConfig:
    """
    Immutable configuration for forensic manifest generation.

    Attributes:
        evidence_directory: Root directory containing evidence files to catalog.
        output_path: Optional destination path to write the generated manifest JSON.
        case_id: Optional incident tracking identifier.
        investigator: Optional handling investigator name or ID.
        algorithms: Tuple of cryptographic hash algorithms to compute (subset of 'sha256', 'md5').
        allow_symlinks: If True, resolves symlinks and validates they remain in-root. If False, skips symlinks.
        chunk_size: Streaming buffer size in bytes (default: 65,536).
        overwrite: If True, allows atomic replacement of existing manifest file at output_path.
        forensix_version: Software release version recording manifest creation.
    """

    evidence_directory: Union[str, Path]
    output_path: Optional[Union[str, Path]] = None
    case_id: Optional[str] = None
    investigator: Optional[str] = None
    algorithms: Tuple[str, ...] = ("sha256", "md5")
    allow_symlinks: bool = False
    chunk_size: int = DEFAULT_CHUNK_SIZE
    overwrite: bool = False
    forensix_version: str = __version__

    def __post_init__(self) -> None:
        """Validate configuration parameters defensively."""
        if not self.evidence_directory:
            raise ValueError("evidence_directory cannot be empty")

        if self.output_path is not None:
            if not isinstance(self.output_path, (str, Path)):
                raise TypeError(f"output_path must be a string or Path, got {type(self.output_path).__name__}")
            if isinstance(self.output_path, str) and not self.output_path.strip():
                raise ValueError("output_path cannot be empty or whitespace")

        if not isinstance(self.algorithms, (list, tuple)):
            raise TypeError(f"algorithms must be a sequence of strings, got {type(self.algorithms).__name__}")
        if not self.algorithms:
            raise ValueError("algorithms cannot be empty; at least one cryptographic algorithm must be selected")

        cleaned_algos: List[str] = []
        for algo in self.algorithms:
            if not isinstance(algo, str):
                raise TypeError(f"Algorithm name must be a string, got {type(algo).__name__}")
            norm = algo.strip().lower()
            if norm not in VALID_ALGORITHMS:
                raise ValueError(
                    f"Unsupported algorithm '{algo}'. Supported algorithms: {sorted(VALID_ALGORITHMS)}"
                )
            if norm not in cleaned_algos:
                cleaned_algos.append(norm)

        object.__setattr__(self, "algorithms", tuple(cleaned_algos))

        if type(self.chunk_size) is not int or isinstance(self.chunk_size, bool):
            raise TypeError(f"chunk_size must be an integer, got {type(self.chunk_size).__name__}")
        if self.chunk_size <= 0:
            raise ValueError(f"chunk_size must be a positive integer, got {self.chunk_size}")


def _stream_hashes_and_size(
    file_path: Path,
    algorithms: Sequence[str],
    chunk_size: int,
) -> Tuple[int, Dict[str, str]]:
    """
    Read an evidence file in binary read-only mode and compute multiple cryptographic
    hashes simultaneously in a single streaming pass.

    Args:
        file_path: Path to regular file on disk.
        algorithms: List of algorithm names ('sha256', 'md5').
        chunk_size: Buffer size for streaming read.

    Returns:
        Tuple[int, Dict[str, str]]: (total_bytes, {algo: lowercase_hex_digest})
    """
    hashers: Dict[str, Any] = {}
    if "sha256" in algorithms:
        hashers["sha256"] = hashlib.sha256()
    if "md5" in algorithms:
        hashers["md5"] = hashlib.md5()

    total_bytes = 0
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            for h in hashers.values():
                h.update(chunk)

    digests = {algo: h.hexdigest().lower() for algo, h in hashers.items()}
    return total_bytes, digests


def save_manifest(
    manifest: ManifestRecord,
    output_path: Union[str, Path],
    overwrite: bool = False,
    evidence_root: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Atomically save a ManifestRecord to a JSON file on disk, enforcing evidence root
    isolation and race-safe exclusive creation.

    Args:
        manifest: ManifestRecord instance to persist.
        output_path: Destination target path.
        overwrite: If False, raises FileExistsError if target exists. If True, atomically replaces.
        evidence_root: Optional evidence directory root to prevent manifest-evidence collision.

    Returns:
        Path: Resolved canonical Path of the saved manifest file.

    Raises:
        ValueError: If destination path overlaps or resides within evidence_root.
        FileExistsError: If destination exists and overwrite is False.
        IsADirectoryError: If destination is an existing directory.
        OSError: If filesystem operations fail.
    """
    if not isinstance(manifest, ManifestRecord):
        raise TypeError(f"manifest must be a ManifestRecord instance, got {type(manifest).__name__}")

    dest = Path(output_path).resolve()

    # 1. Enforce evidence directory separation
    if evidence_root is not None:
        ev_root = Path(evidence_root).resolve()
        if dest == ev_root or dest.is_relative_to(ev_root):
            raise ValueError(
                f"Forensic safety violation: manifest output path '{dest}' "
                f"overlaps or resides inside evidence directory '{ev_root}'"
            )

    # 2. Reject directory destinations
    if dest.is_dir():
        raise IsADirectoryError(f"Destination path is a directory: '{dest}'")

    dest.parent.mkdir(parents=True, exist_ok=True)

    content = json.dumps(manifest.to_dict(), indent=2, sort_keys=False) + "\n"

    # 3. Safe atomic write
    if not overwrite:
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            raise FileExistsError(
                f"Manifest destination already exists and overwrite is False: '{dest}'"
            )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                pass
            raise
    else:
        temp_dest = dest.parent / f".tmp.{dest.name}.{os.getpid()}.{uuid.uuid4().hex}"
        try:
            with open(temp_dest, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temp_dest, dest)
        except Exception:
            try:
                temp_dest.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    return dest


def generate_manifest(
    evidence_dir: Union[str, Path, ManifestGeneratorConfig],
    output_path: Optional[Union[str, Path]] = None,
    case_id: Optional[str] = None,
    investigator: Optional[str] = None,
    algorithms: Tuple[str, ...] = ("sha256", "md5"),
    allow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> ManifestRecord:
    """
    Generate an immutable ForensiX Schema 8.0 ManifestRecord by scanning an evidence directory.

    Args:
        evidence_dir: Path to evidence directory or pre-constructed ManifestGeneratorConfig.
        output_path: Optional path to write manifest JSON file.
        case_id: Optional case identifier.
        investigator: Optional investigator designation.
        algorithms: Tuple of algorithms ('sha256', 'md5').
        allow_symlinks: If False (default), skips symlinks. If True, follows in-root symlinks.
        chunk_size: Buffer size for streaming read.
        overwrite: If True, allows atomic replacement of existing file at output_path.

    Returns:
        ManifestRecord: Immutable, deterministically sorted Schema 8.0 manifest record.

    Raises:
        FileNotFoundError: If evidence directory does not exist.
        NotADirectoryError: If evidence path is not a directory.
        ValueError: If symlinks escape evidence root or configuration is invalid.
    """
    if isinstance(evidence_dir, ManifestGeneratorConfig):
        cfg = evidence_dir
    else:
        cfg = ManifestGeneratorConfig(
            evidence_directory=evidence_dir,
            output_path=output_path,
            case_id=case_id,
            investigator=investigator,
            algorithms=algorithms,
            allow_symlinks=allow_symlinks,
            chunk_size=chunk_size,
            overwrite=overwrite,
        )

    # 1. Validate Evidence Directory
    raw_ev = Path(cfg.evidence_directory)
    if not raw_ev.exists():
        raise FileNotFoundError(f"Evidence directory does not exist: '{cfg.evidence_directory}'")
    if not raw_ev.is_dir():
        raise NotADirectoryError(f"Evidence path is not a directory: '{cfg.evidence_directory}'")
    ev_root = raw_ev.resolve()

    # Pre-flight check on output_path if provided
    if cfg.output_path is not None:
        out_dest = Path(cfg.output_path).resolve()
        if out_dest == ev_root or out_dest.is_relative_to(ev_root):
            raise ValueError(
                f"Forensic safety violation: manifest output path '{out_dest}' "
                f"overlaps or resides inside evidence directory '{ev_root}'"
            )
        if out_dest.is_dir():
            raise IsADirectoryError(f"Manifest output path is an existing directory: '{out_dest}'")
        if not cfg.overwrite and out_dest.exists():
            raise FileExistsError(
                f"Manifest destination already exists and overwrite is False: '{out_dest}'"
            )

    entries: List[ManifestEntry] = []
    visited_dirs: Set[Tuple[int, int]] = set()

    # Record initial root device and inode if supported
    try:
        root_stat = ev_root.stat()
        visited_dirs.add((root_stat.st_dev, root_stat.st_ino))
    except OSError:
        pass

    # 2. Deterministic Recursive Directory Traversal
    for current_dir, dir_names, file_names in os.walk(ev_root, followlinks=False):
        # Deterministically sort directory and file names
        dir_names.sort()
        file_names.sort()

        current_path = Path(current_dir)

        # Handle directory traversal symlink policies when allow_symlinks=True
        if cfg.allow_symlinks:
            pruned_dirs = []
            for d in list(dir_names):
                d_path = current_path / d
                if d_path.is_symlink():
                    try:
                        resolved_dir = d_path.resolve()
                    except (OSError, RuntimeError) as err:
                        raise ValueError(f"Failed to resolve directory symlink '{d_path}': {err}") from err

                    # Prevent escaping evidence root
                    if not resolved_dir.is_relative_to(ev_root):
                        raise ValueError(
                            f"Symlink escape detected: directory symlink '{d_path}' "
                            f"resolves to '{resolved_dir}', which is outside evidence root '{ev_root}'"
                        )

                    # Cycle detection using (st_dev, st_ino)
                    try:
                        d_stat = resolved_dir.stat()
                        dir_ident = (d_stat.st_dev, d_stat.st_ino)
                        if dir_ident in visited_dirs:
                            # Prune cycle to avoid infinite loop
                            import sys
                            sys.stderr.write(
                                f"[WARNING] Directory symlink '{d_path}' cycle pruned from traversal per ForensiX symlink policy.\n"
                            )
                            pruned_dirs.append(d)
                            continue
                        visited_dirs.add(dir_ident)
                    except OSError:
                        pass

                    # Directory symlinks are pruned per ForensiX symlink policy (file symlinks only are cataloged)
                    import sys
                    sys.stderr.write(
                        f"[WARNING] Directory symlink '{d_path}' pruned from traversal per ForensiX symlink policy (file symlinks only are cataloged).\n"
                    )
                    pruned_dirs.append(d)
            for p in pruned_dirs:
                if p in dir_names:
                    dir_names.remove(p)

        for fname in file_names:
            f_path = current_path / fname

            # 3. Handle Symlinks
            if f_path.is_symlink():
                if not cfg.allow_symlinks:
                    # Default policy: ignore/skip symlinks
                    continue

                # When allow_symlinks=True, verify target remains inside evidence root
                try:
                    resolved_target = f_path.resolve()
                except (OSError, RuntimeError) as err:
                    raise ValueError(f"Failed to resolve symlink '{f_path}': {err}") from err

                if not resolved_target.exists():
                    raise ValueError(f"Broken symlink detected in evidence: '{f_path}' points to nonexistent target")

                if not resolved_target.is_relative_to(ev_root):
                    raise ValueError(
                        f"Symlink escape detected: evidence symlink '{f_path}' "
                        f"resolves to '{resolved_target}', which is outside evidence root '{ev_root}'"
                    )

                if not resolved_target.is_file():
                    # Symlink points to directory or special device, skip
                    continue
            else:
                # Regular filesystem object check
                if not f_path.is_file():
                    # Skip special non-regular files (pipes, sockets, block/char devices)
                    continue

            # 4. Compute POSIX Relative Path & Validate
            rel_path = f_path.relative_to(ev_root).as_posix()
            valid_rel_path = validate_relative_entry_path(rel_path)

            # 5. Compute Hashes & Byte Count
            total_bytes, digests = _stream_hashes_and_size(
                file_path=f_path,
                algorithms=cfg.algorithms,
                chunk_size=cfg.chunk_size,
            )

            # 6. Instantiate ManifestEntry
            entry = ManifestEntry(
                relative_path=valid_rel_path,
                size_bytes=total_bytes,
                hashes=digests,
                artifact_type=ManifestArtifactType.EVIDENCE,
                evidence_id=None,
            )
            entries.append(entry)

    # 7. Construct Immutable ManifestRecord (sorted deterministically)
    manifest_record = ManifestRecord(
        manifest_id=generate_manifest_id(),
        manifest_version=MANIFEST_SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        forensix_version=cfg.forensix_version,
        case_id=cfg.case_id,
        investigator=cfg.investigator,
        entries=entries,
    )

    # 8. Persist if output_path is specified
    if cfg.output_path is not None:
        save_manifest(
            manifest=manifest_record,
            output_path=cfg.output_path,
            overwrite=cfg.overwrite,
            evidence_root=ev_root,
        )

    return manifest_record
