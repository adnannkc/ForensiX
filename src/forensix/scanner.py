"""
Filesystem Artifact Scanner for ForensiX (V2.1).

Responsible for recursively inspecting a Linux host evidence directory,
identifying known and generic forensic artifacts, safely extracting metadata
and cryptographic hashes, and packaging the results into an immutable collection,
while preserving original evidence integrity and preventing symlink escapes.
"""

from datetime import datetime, timezone
import mimetypes
import os
from pathlib import Path
import stat
from typing import List, Optional, Union

from forensix.analyzer import _get_birthtime
from forensix.artifacts import (
    ArtifactCollectionResult,
    ArtifactRecord,
    ArtifactStatus,
    generate_artifact_id,
)
from forensix.evidence import generate_evidence_id
from forensix.hasher import compute_hashes
from forensix.identifier import identify_artifact, normalize_relative_path


def _is_within_directory(base_dir: Path, target_path: Path) -> bool:
    """Verify if target_path resolves within base_dir to guard against symlink escapes."""
    try:
        target_path.resolve().relative_to(base_dir.resolve())
        return True
    except (ValueError, RuntimeError):
        return False


def scan_evidence_directory(
    evidence_dir: Union[str, Path],
    evidence_id: Optional[str] = None,
) -> ArtifactCollectionResult:
    """
    Recursively scan and catalog a Linux host evidence directory.

    Forensic Safety & Integrity Principles:
    - Evidence directory and its contents are treated strictly as read-only.
    - Symlinks pointing outside the evidence root are strictly blocked from being
      followed or read, preventing leakage of the investigator's host system.
    - Individual unreadable files or broken symlinks do not halt analysis of the
      remaining artifacts.
    - Processing order is deterministic (lexicographically sorted).

    Args:
        evidence_dir: Path to the target evidence directory.
        evidence_id: Optional explicit evidence collection ID.

    Returns:
        ArtifactCollectionResult: Complete, immutable collection of discovered artifacts.

    Raises:
        FileNotFoundError: If the evidence directory does not exist.
        NotADirectoryError: If the evidence path is not a directory.
    """
    root_path = Path(evidence_dir).resolve()

    if not root_path.exists():
        raise FileNotFoundError(f"Evidence directory does not exist: '{root_path}'")

    if not root_path.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: '{root_path}'")

    eid = evidence_id if evidence_id is not None else generate_evidence_id()
    collected_at = datetime.now(timezone.utc).isoformat()

    artifacts: List[ArtifactRecord] = []

    # Deterministic recursive walk: sort directory and file names
    for current_dir, dir_names, file_names in os.walk(root_path, followlinks=False):
        dir_names.sort()
        file_names.sort()

        current_path = Path(current_dir)

        for fname in file_names:
            file_path = current_path / fname
            rel_path = file_path.relative_to(root_path)
            norm_rel_path = normalize_relative_path(rel_path)

            category, artifact_type, is_known = identify_artifact(norm_rel_path)
            art_id = generate_artifact_id()

            # Handle symbolic links
            if file_path.is_symlink():
                try:
                    resolved = file_path.resolve()
                    if not _is_within_directory(root_path, resolved):
                        artifacts.append(
                            ArtifactRecord(
                                artifact_id=art_id,
                                relative_path=norm_rel_path,
                                source_path=str(file_path),
                                category=category.value,
                                artifact_type=artifact_type.value,
                                is_known=is_known,
                                size=0,
                                permissions=None,
                                modified=None,
                                accessed=None,
                                created=None,
                                md5=None,
                                sha256=None,
                                status=ArtifactStatus.OUT_OF_BOUNDS_SYMLINK.value,
                                error=f"Symbolic link points outside evidence directory: {os.readlink(file_path)}",
                            )
                        )
                        continue
                    if not resolved.exists():
                        artifacts.append(
                            ArtifactRecord(
                                artifact_id=art_id,
                                relative_path=norm_rel_path,
                                source_path=str(file_path),
                                category=category.value,
                                artifact_type=artifact_type.value,
                                is_known=is_known,
                                size=0,
                                permissions=None,
                                modified=None,
                                accessed=None,
                                created=None,
                                md5=None,
                                sha256=None,
                                status=ArtifactStatus.BROKEN_SYMLINK.value,
                                error="Broken symbolic link (target does not exist)",
                            )
                        )
                        continue
                except OSError as err:
                    artifacts.append(
                        ArtifactRecord(
                            artifact_id=art_id,
                            relative_path=norm_rel_path,
                            source_path=str(file_path),
                            category=category.value,
                            artifact_type=artifact_type.value,
                            is_known=is_known,
                            size=0,
                            permissions=None,
                            modified=None,
                            accessed=None,
                            created=None,
                            md5=None,
                            sha256=None,
                            status=ArtifactStatus.UNREADABLE.value,
                            error=f"Error inspecting symlink: {err}",
                        )
                    )
                    continue

            # Regular file processing
            try:
                stat_result = file_path.stat()
            except PermissionError as err:
                artifacts.append(
                    ArtifactRecord(
                        artifact_id=art_id,
                        relative_path=norm_rel_path,
                        source_path=str(file_path),
                        category=category.value,
                        artifact_type=artifact_type.value,
                        is_known=is_known,
                        size=0,
                        permissions=None,
                        modified=None,
                        accessed=None,
                        created=None,
                        md5=None,
                        sha256=None,
                        status=ArtifactStatus.PERMISSION_DENIED.value,
                        error=f"Permission denied accessing metadata: {err}",
                    )
                )
                continue
            except OSError as err:
                artifacts.append(
                    ArtifactRecord(
                        artifact_id=art_id,
                        relative_path=norm_rel_path,
                        source_path=str(file_path),
                        category=category.value,
                        artifact_type=artifact_type.value,
                        is_known=is_known,
                        size=0,
                        permissions=None,
                        modified=None,
                        accessed=None,
                        created=None,
                        md5=None,
                        sha256=None,
                        status=ArtifactStatus.UNREADABLE.value,
                        error=f"OS error reading metadata: {err}",
                    )
                )
                continue

            permissions = f"{stat.S_IMODE(stat_result.st_mode):04o}"
            modified = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat()
            accessed = datetime.fromtimestamp(stat_result.st_atime, tz=timezone.utc).isoformat()
            birthtime = _get_birthtime(stat_result)
            created = (
                datetime.fromtimestamp(birthtime, tz=timezone.utc).isoformat()
                if birthtime is not None
                else None
            )

            mime_type, _ = mimetypes.guess_type(file_path)

            # Compute cryptographic hashes in read-only mode
            try:
                hashes = compute_hashes(file_path)
                md5 = hashes["md5"]
                sha256 = hashes["sha256"]
                status = ArtifactStatus.COLLECTED.value
                error = None
            except PermissionError as err:
                md5 = None
                sha256 = None
                status = ArtifactStatus.PERMISSION_DENIED.value
                error = f"Permission denied reading file content: {err}"
            except OSError as err:
                md5 = None
                sha256 = None
                status = ArtifactStatus.UNREADABLE.value
                error = f"OS error computing hashes: {err}"

            artifacts.append(
                ArtifactRecord(
                    artifact_id=art_id,
                    relative_path=norm_rel_path,
                    source_path=str(file_path),
                    category=category.value,
                    artifact_type=artifact_type.value,
                    is_known=is_known,
                    size=stat_result.st_size,
                    permissions=permissions,
                    modified=modified,
                    accessed=accessed,
                    created=created,
                    md5=md5,
                    sha256=sha256,
                    status=status,
                    mime_type=mime_type,
                    error=error,
                )
            )

    # Compute summary counts
    total_artifacts = len(artifacts)
    known_artifacts = sum(1 for a in artifacts if a.is_known)
    generic_artifacts = sum(
        1 for a in artifacts if not a.is_known and a.status == ArtifactStatus.COLLECTED.value
    )
    unreadable_artifacts = sum(
        1 for a in artifacts if a.status != ArtifactStatus.COLLECTED.value
    )

    return ArtifactCollectionResult(
        evidence_id=eid,
        evidence_root=str(root_path),
        collected_at=collected_at,
        artifacts=tuple(artifacts),
        total_artifacts=total_artifacts,
        known_artifacts=known_artifacts,
        generic_artifacts=generic_artifacts,
        unreadable_artifacts=unreadable_artifacts,
    )
