"""
Forensic Artifact Adapters for ForensiX (V3.3 Timeline Reconstruction).

Provides a deterministic, forensically sound adapter layer that translates factual
evidence records (filesystem artifacts, logs, authentication records, and unified host artifacts)
into immutable V3.1 TimelineEvent objects using V3.2 timestamp normalization.

Core Architectural Flow:
    Forensic Artifact
           ↓
    Artifact Adapter
           ↓
    Timestamp Normalization (timestamp_normalizer)
           ↓
    TimelineEvent

Strict Forensic Boundaries:
1. Extraction and translation only: No detection, threat scoring, suspicion assessment,
   or incident determination.
2. Fact-based event types only: No speculative event classifications (e.g. malware_executed).
3. No fabricated timestamps: Events are emitted only when an explicit, verifiable timestamp exists.
4. Timezone fidelity: Timezone-aware timestamps are deterministically normalized to UTC;
   timezone-naive timestamps remain strictly naive without assuming local or UTC offsets.
5. Strict audit provenance: Retains source paths, line numbers, artifact IDs, event IDs,
   and raw lines without fabrication.
6. Deterministic output: Given identical input, produces identical event content and ordering.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
import posixpath
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.account_models import (
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.analyzer import FileMetadata, ForensicAnalysisResult
from forensix.artifacts import ArtifactRecord
from forensix.auth_models import AuthenticationRecord
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timestamp_normalizer import (
    NormalizedTimestamp,
    normalize_bsd_timestamp,
    parse_timestamp,
)
from forensix.unified_models import HostArtifact, HostArtifactCategory


# Canonical ordering of filesystem event types when multiple timestamps exist
FILESYSTEM_EVENT_TYPE_ORDER: Tuple[str, ...] = (
    "file_created",
    "file_modified",
    "file_accessed",
    "file_metadata_changed",
)

# Canonical ForensiX V3 namespace for deterministic artifact identity (RFC 4122 UUIDv5)
FORENSIX_V3_ARTIFACT_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v3/artifact"
)


def _normalize_evidence_path(path: Union[str, Path]) -> str:
    """
    Normalize an evidence path string for deterministic identity computation.

    Converts backslashes to forward slashes, normalizes relative dot components,
    and strips leading slashes for relative paths.
    """
    p_str = str(path).strip().replace("\\", "/")
    norm = posixpath.normpath(p_str)
    if not p_str.startswith("/"):
        norm = norm.lstrip("/")
    return norm


def compute_deterministic_artifact_id(
    path: Optional[Union[str, Path]] = None,
    sha256: Optional[str] = None,
    relative_path: Optional[Union[str, Path]] = None,
) -> str:
    """
    Compute a deterministic, forensically sound V3 artifact identifier.

    In V2, scanner-generated artifact IDs (ART-<UUIDv4>) are run-specific random UUIDs.
    In V3 timeline reconstruction, timeline event provenance must be deterministic across
    independent scans of identical evidence.

    Provenance Identity Semantics:
    1. Identity is derived strictly from immutable evidence facts available at the V3 boundary:
       - Normalized relative path within the evidence container (preferred) or normalized source path.
       - Cryptographic SHA-256 digest of file content when available.
    2. Format: ART-<UUIDv5> generated per RFC 4122 within the ForensiX V3 artifact namespace.
       - UUIDv5 uses SHA-1 hashing over a fixed namespace and canonical name, guaranteeing
         reproducibility across runs, platforms, and Python versions.
       - The 'ART-' prefix and standard 36-character UUID formatting preserve backward
         compatibility with existing ForensiX tooling and reports.
    3. Collision Resistance & Fact Differentiation:
       - Identical facts (path + sha256) always generate identical IDs.
       - Different paths with identical content do NOT collapse.
       - Identical paths with different content (different SHA-256) do NOT collapse.
       - Files without SHA-256 are identified by normalized path.

    Raises:
        ValueError: If both path and relative_path are missing or empty.
    """
    target_path = relative_path if (relative_path is not None and str(relative_path).strip()) else path
    if target_path is None or not str(target_path).strip():
        raise ValueError("Cannot compute deterministic artifact ID: path or relative_path must be provided")

    norm_path = _normalize_evidence_path(target_path)
    clean_sha = sha256.strip().lower() if (sha256 is not None and str(sha256).strip()) else None

    if clean_sha:
        canonical_key = f"{norm_path}:{clean_sha}"
    else:
        canonical_key = f"{norm_path}"

    det_uuid = uuid.uuid5(FORENSIX_V3_ARTIFACT_NAMESPACE, canonical_key)
    return f"ART-{det_uuid}"


def _safe_normalize(val: Union[datetime, str, int, float]) -> NormalizedTimestamp:
    """
    Safely normalize a timestamp value via V3.2 timestamp_normalizer.

    Accepts datetime objects, valid ISO 8601 strings, space/slash-separated datetime strings,
    and POSIX numeric timestamps (float/int).

    Raises:
        ValueError: If the timestamp is date-only, incomplete, or malformed.
        TypeError: If the timestamp type is invalid.
    """
    if isinstance(val, (int, float)):
        # Convert numeric epoch to explicit UTC datetime for normalization
        dt_val = datetime.fromtimestamp(val, tz=timezone.utc)
        return parse_timestamp(dt_val)
    return parse_timestamp(val)


class BaseArtifactAdapter(ABC):
    """Abstract base class defining the artifact adapter contract."""

    @abstractmethod
    def can_adapt(self, artifact: Any) -> bool:
        """Return True if this adapter supports the given artifact."""
        pass

    @abstractmethod
    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """
        Adapt a forensic artifact into an immutable tuple of TimelineEvent instances.

        Returns an empty tuple if no factual timestamps are present.
        Raises TypeError if the artifact type is unsupported.
        Raises ValueError if the artifact contains malformed data or timestamps.
        """
        pass


class FilesystemAdapter(BaseArtifactAdapter):
    """
    Adapter converting filesystem artifacts and metadata into TimelineEvents.

    Supported inputs:
    - ArtifactRecord (V2.1 filesystem artifact record)
    - ForensicAnalysisResult (V1 unified analysis result)
    - FileMetadata (V1 filesystem metadata)
    - HostArtifact with category 'filesystem' or ArtifactRecord payload
    - Dictionary with filesystem metadata keys ('source_path'/'path' and timestamps)

    Factual event mappings:
    - crtime / birthtime / created  → file_created
    - mtime / modified             → file_modified
    - atime / accessed             → file_accessed
    - ctime / metadata_changed     → file_metadata_changed

    Guarantees:
    - Only emits events for timestamps that actually exist (no timestamp fabrication).
    - Preserves source path, source artifact ID, and file attributes.
    - Emits multiple events in canonical order when multiple timestamps are present.
    """

    def can_adapt(self, artifact: Any) -> bool:
        """Check if artifact is a supported filesystem artifact type."""
        if isinstance(artifact, (ArtifactRecord, ForensicAnalysisResult, FileMetadata)):
            return True
        if isinstance(artifact, HostArtifact):
            return (
                artifact.category == HostArtifactCategory.FILESYSTEM.value
                or isinstance(artifact.specialized_payload, ArtifactRecord)
            )
        if isinstance(artifact, dict):
            has_fs_keys = any(
                k in artifact
                for k in (
                    "modified",
                    "accessed",
                    "created",
                    "mtime",
                    "atime",
                    "crtime",
                    "birthtime",
                    "ctime",
                    "metadata_changed",
                )
            )
            is_log_or_auth = "auth_id" in artifact or (
                "event_type" in artifact and ("service" in artifact or "raw_line" in artifact)
            )
            return has_fs_keys and not is_log_or_auth
        return False

    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """
        Adapt filesystem artifact to a tuple of TimelineEvents.

        Raises:
            TypeError: If the artifact is not supported.
            ValueError: If source_path is missing or timestamps are malformed.
        """
        if artifact is None:
            raise ValueError("Artifact cannot be None")

        if not self.can_adapt(artifact):
            raise TypeError(
                f"Unsupported artifact type for FilesystemAdapter: {type(artifact).__name__}"
            )

        if isinstance(artifact, HostArtifact):
            if isinstance(artifact.specialized_payload, ArtifactRecord):
                return self._adapt_artifact_record(
                    artifact.specialized_payload,
                )
            raise TypeError(
                f"HostArtifact payload {type(artifact.specialized_payload).__name__} is not a supported filesystem artifact"
            )

        if isinstance(artifact, ArtifactRecord):
            return self._adapt_artifact_record(artifact)

        if isinstance(artifact, ForensicAnalysisResult):
            return self._adapt_forensic_analysis_result(artifact)

        if isinstance(artifact, FileMetadata):
            return self._adapt_file_metadata(artifact)

        if isinstance(artifact, dict):
            return self._adapt_dict(artifact)

        raise TypeError(f"Unhandled filesystem artifact type: {type(artifact).__name__}")

    def _adapt_artifact_record(
        self,
        rec: ArtifactRecord,
        source_artifact_id: Optional[str] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract events from an ArtifactRecord."""
        source_path = rec.source_path
        if not source_path:
            raise ValueError("ArtifactRecord missing required 'source_path'")

        if source_artifact_id is not None:
            art_id = source_artifact_id
        else:
            art_id = compute_deterministic_artifact_id(
                path=rec.source_path,
                relative_path=rec.relative_path,
                sha256=rec.sha256,
            )

        # Common attributes for all events originating from this file
        attrs: Dict[str, Any] = {}
        if rec.artifact_id is not None:
            attrs["v2_artifact_id"] = rec.artifact_id
        if rec.relative_path is not None:
            attrs["relative_path"] = rec.relative_path
        if rec.size is not None:
            attrs["file_size"] = rec.size
        if rec.permissions is not None:
            attrs["permissions"] = rec.permissions
        if rec.artifact_type is not None:
            attrs["artifact_type"] = rec.artifact_type
        if rec.category is not None:
            attrs["artifact_category"] = rec.category
        if rec.status is not None:
            attrs["status"] = rec.status
        if rec.mime_type is not None:
            attrs["mime_type"] = rec.mime_type
        if rec.md5 is not None:
            attrs["md5"] = rec.md5
        if rec.sha256 is not None:
            attrs["sha256"] = rec.sha256

        events: List[TimelineEvent] = []

        # 1. file_created (crtime / birthtime)
        if rec.created is not None:
            norm = _safe_normalize(rec.created)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_created",
                    description=f"File created: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 2. file_modified (mtime)
        if rec.modified is not None:
            norm = _safe_normalize(rec.modified)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_modified",
                    description=f"File modified: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 3. file_accessed (atime)
        if rec.accessed is not None:
            norm = _safe_normalize(rec.accessed)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_accessed",
                    description=f"File accessed: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 4. file_metadata_changed (ctime) if present on extended record
        ctime_val = getattr(rec, "ctime", None) or getattr(rec, "metadata_changed", None)
        if ctime_val is not None:
            norm = _safe_normalize(ctime_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_metadata_changed",
                    description=f"File metadata changed: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        return tuple(events)

    def _adapt_forensic_analysis_result(
        self,
        res: ForensicAnalysisResult,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract events from a V1 ForensicAnalysisResult."""
        source_path = str(getattr(res.evidence, "original_path", getattr(res.evidence, "path", "")))
        art_id = res.evidence.evidence_id

        attrs: Dict[str, Any] = {
            "filename": res.file.filename,
            "file_size": res.file.size,
            "extension": res.file.extension,
        }
        if res.file.mime_type is not None:
            attrs["mime_type"] = res.file.mime_type
        if res.metadata.permissions is not None:
            attrs["permissions"] = res.metadata.permissions
        if res.hashes.md5:
            attrs["md5"] = res.hashes.md5
        if res.hashes.sha256:
            attrs["sha256"] = res.hashes.sha256

        events: List[TimelineEvent] = []

        if res.metadata.created is not None:
            norm = _safe_normalize(res.metadata.created)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_created",
                    description=f"File created: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        if res.metadata.modified is not None:
            norm = _safe_normalize(res.metadata.modified)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_modified",
                    description=f"File modified: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        if res.metadata.accessed is not None:
            norm = _safe_normalize(res.metadata.accessed)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_accessed",
                    description=f"File accessed: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        ctime_val = getattr(res.metadata, "ctime", None)
        if ctime_val is not None:
            norm = _safe_normalize(ctime_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_metadata_changed",
                    description=f"File metadata changed: {source_path}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path,
                    source_line=None,
                    source_artifact_id=art_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        return tuple(events)

    def _adapt_file_metadata(
        self,
        meta: FileMetadata,
        source_path: Optional[str] = None,
        source_artifact_id: Optional[str] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract events from a FileMetadata record."""
        target_path = source_path or getattr(meta, "source_path", None)

        attrs: Dict[str, Any] = {}
        if meta.permissions is not None:
            attrs["permissions"] = meta.permissions

        events: List[TimelineEvent] = []

        if meta.created is not None:
            norm = _safe_normalize(meta.created)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_created",
                    description=f"File created: {target_path}" if target_path else "File created",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=target_path,
                    source_line=None,
                    source_artifact_id=source_artifact_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        if meta.modified is not None:
            norm = _safe_normalize(meta.modified)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_modified",
                    description=f"File modified: {target_path}" if target_path else "File modified",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=target_path,
                    source_line=None,
                    source_artifact_id=source_artifact_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        if meta.accessed is not None:
            norm = _safe_normalize(meta.accessed)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_accessed",
                    description=f"File accessed: {target_path}" if target_path else "File accessed",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=target_path,
                    source_line=None,
                    source_artifact_id=source_artifact_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        ctime_val = getattr(meta, "ctime", None)
        if ctime_val is not None:
            norm = _safe_normalize(ctime_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_metadata_changed",
                    description=f"File metadata changed: {target_path}" if target_path else "File metadata changed",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=target_path,
                    source_line=None,
                    source_artifact_id=source_artifact_id,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        return tuple(events)

    def _adapt_dict(self, data: Dict[str, Any]) -> Tuple[TimelineEvent, ...]:
        """Extract events from a dictionary containing filesystem metadata."""
        source_path = data.get("source_path") or data.get("path")
        if not source_path:
            raise ValueError("Filesystem artifact dictionary missing required 'source_path' or 'path'")
        source_path_str = str(source_path)

        art_id = data.get("artifact_id") or data.get("source_artifact_id")

        # Non-timestamp attributes
        ts_keys = {
            "created", "modified", "accessed", "mtime", "atime", "crtime",
            "birthtime", "ctime", "metadata_changed", "source_path", "path",
            "artifact_id", "source_artifact_id",
        }
        attrs = {k: v for k, v in data.items() if k not in ts_keys and v is not None}

        events: List[TimelineEvent] = []

        # 1. Created (crtime / birthtime)
        created_val = data.get("created") or data.get("crtime") or data.get("birthtime")
        if created_val is not None:
            norm = _safe_normalize(created_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_created",
                    description=f"File created: {source_path_str}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path_str,
                    source_line=None,
                    source_artifact_id=str(art_id) if art_id is not None else None,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 2. Modified (mtime)
        modified_val = data.get("modified") or data.get("mtime")
        if modified_val is not None:
            norm = _safe_normalize(modified_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_modified",
                    description=f"File modified: {source_path_str}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path_str,
                    source_line=None,
                    source_artifact_id=str(art_id) if art_id is not None else None,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 3. Accessed (atime)
        accessed_val = data.get("accessed") or data.get("atime")
        if accessed_val is not None:
            norm = _safe_normalize(accessed_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_accessed",
                    description=f"File accessed: {source_path_str}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path_str,
                    source_line=None,
                    source_artifact_id=str(art_id) if art_id is not None else None,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        # 4. Metadata changed (ctime)
        ctime_val = data.get("ctime") or data.get("metadata_changed")
        if ctime_val is not None:
            norm = _safe_normalize(ctime_val)
            events.append(
                create_timeline_event(
                    category=TimelineCategory.FILESYSTEM,
                    event_type="file_metadata_changed",
                    description=f"File metadata changed: {source_path_str}",
                    timestamp=norm.normalized_datetime,
                    raw_timestamp=norm.raw_timestamp,
                    source_path=source_path_str,
                    source_line=None,
                    source_artifact_id=str(art_id) if art_id is not None else None,
                    source_event_id=None,
                    raw_data=None,
                    attributes=attrs,
                )
            )

        return tuple(events)


class LogAdapter(BaseArtifactAdapter):
    """
    Adapter converting parsed log events (LogEvent) into TimelineEvents.

    Supported inputs:
    - LogEvent (V2.2 parsed log event)
    - HostArtifact with category 'log' or LogEvent payload
    - Dictionary with log event keys

    Guarantees:
    - Category is strictly TimelineCategory.LOG.
    - Preserves source_path, line_number, source_artifact_id, source_event_id, and raw_line.
    - Normalizes timestamp via V3.2 if available; preserves raw_timestamp.
    - If timestamp cannot be normalized (e.g. yearless syslog), timestamp remains None
      unless an explicit log_timestamp_year context is provided.
    - Attributes preserve hostname, service, pid, and custom parsed attributes.
    """

    def __init__(self, log_timestamp_year: Optional[int] = None) -> None:
        self.log_timestamp_year = log_timestamp_year

    def can_adapt(self, artifact: Any) -> bool:
        """Check if artifact is a supported log artifact type."""
        if isinstance(artifact, LogEvent):
            return True
        if isinstance(artifact, HostArtifact):
            return (
                artifact.category == HostArtifactCategory.LOG.value
                or isinstance(artifact.specialized_payload, LogEvent)
            )
        if isinstance(artifact, dict):
            return (
                "event_type" in artifact
                and ("source_path" in artifact or "path" in artifact)
                and ("raw_message" in artifact or "raw_line" in artifact or "service" in artifact)
                and "auth_id" not in artifact
            )
        return False

    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """
        Adapt log artifact to a tuple containing one TimelineEvent.

        Raises:
            TypeError: If the artifact is not supported.
            ValueError: If source_path or event_type is missing.
        """
        if artifact is None:
            raise ValueError("Artifact cannot be None")

        if not self.can_adapt(artifact):
            raise TypeError(
                f"Unsupported artifact type for LogAdapter: {type(artifact).__name__}"
            )

        if isinstance(artifact, HostArtifact):
            if isinstance(artifact.specialized_payload, LogEvent):
                return self._adapt_log_event(artifact.specialized_payload)
            raise TypeError(
                f"HostArtifact payload {type(artifact.specialized_payload).__name__} is not a LogEvent"
            )

        if isinstance(artifact, LogEvent):
            return self._adapt_log_event(artifact)

        if isinstance(artifact, dict):
            return self._adapt_dict(artifact)

        raise TypeError(f"Unhandled log artifact type: {type(artifact).__name__}")

    def _adapt_log_event(
        self,
        evt: LogEvent,
        source_artifact_id: Optional[str] = None,
        log_timestamp_year: Optional[int] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract a TimelineEvent from a LogEvent."""
        norm_dt: Optional[datetime] = None
        raw_ts: Optional[str] = evt.raw_timestamp
        effective_year = log_timestamp_year if log_timestamp_year is not None else self.log_timestamp_year

        # Attempt normalization from normalized_timestamp first, then raw_timestamp
        target_ts_str = evt.normalized_timestamp or evt.raw_timestamp
        if target_ts_str is not None:
            try:
                norm_res = parse_timestamp(target_ts_str)
                norm_dt = norm_res.normalized_datetime
                if raw_ts is None:
                    raw_ts = norm_res.raw_timestamp
            except ValueError:
                # If target is incomplete/yearless (e.g. BSD syslog), check if explicit year is provided
                if effective_year is not None and evt.raw_timestamp:
                    dt = normalize_bsd_timestamp(evt.raw_timestamp, log_timestamp_year=effective_year)
                    if dt is not None:
                        norm_dt = dt
                else:
                    norm_dt = None

        target_art_id = source_artifact_id if source_artifact_id is not None else evt.source_artifact_id

        attrs: Dict[str, Any] = dict(evt.attributes) if evt.attributes else {}
        if evt.source_artifact_id is not None:
            attrs["v2_artifact_id"] = evt.source_artifact_id
        if evt.service is not None:
            attrs["service"] = evt.service
        if evt.pid is not None:
            attrs["pid"] = evt.pid
        if evt.hostname is not None:
            attrs["hostname"] = evt.hostname

        desc = evt.raw_message.strip() if evt.raw_message and evt.raw_message.strip() else f"Log event: {evt.event_type}"

        event = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type=evt.event_type,
            description=desc,
            timestamp=norm_dt,
            raw_timestamp=raw_ts,
            source_path=evt.source_path,
            source_line=evt.line_number,
            source_artifact_id=target_art_id,
            source_event_id=evt.event_id,
            raw_data=evt.raw_line,
            attributes=attrs,
        )
        return (event,)

    def _adapt_dict(
        self,
        data: Dict[str, Any],
        log_timestamp_year: Optional[int] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract a TimelineEvent from a log event dictionary."""
        source_path = data.get("source_path") or data.get("path")
        if not source_path:
            raise ValueError("Log artifact dictionary missing required 'source_path'")

        event_type = data.get("event_type")
        if not event_type:
            raise ValueError("Log artifact dictionary missing required 'event_type'")

        raw_ts = data.get("raw_timestamp")
        target_ts = data.get("normalized_timestamp") or raw_ts
        norm_dt: Optional[datetime] = None
        effective_year = log_timestamp_year if log_timestamp_year is not None else self.log_timestamp_year

        if target_ts is not None:
            try:
                norm_res = parse_timestamp(target_ts)
                norm_dt = norm_res.normalized_datetime
                if raw_ts is None:
                    raw_ts = norm_res.raw_timestamp
            except ValueError:
                if effective_year is not None and raw_ts:
                    dt = normalize_bsd_timestamp(str(raw_ts), log_timestamp_year=effective_year)
                    if dt is not None:
                        norm_dt = dt
                else:
                    norm_dt = None

        attrs = dict(data.get("attributes", {}))
        for key in ("service", "pid", "hostname"):
            if key in data and data[key] is not None:
                attrs[key] = data[key]

        raw_msg = data.get("raw_message", "")
        desc = raw_msg.strip() if raw_msg and raw_msg.strip() else f"Log event: {event_type}"

        event = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type=event_type,
            description=desc,
            timestamp=norm_dt,
            raw_timestamp=raw_ts,
            source_path=str(source_path),
            source_line=data.get("line_number"),
            source_artifact_id=data.get("source_artifact_id"),
            source_event_id=data.get("event_id") or data.get("source_event_id"),
            raw_data=data.get("raw_line"),
            attributes=attrs,
        )
        return (event,)


class AuthenticationAdapter(BaseArtifactAdapter):
    """
    Adapter converting authentication activity records (AuthenticationRecord) into TimelineEvents.

    Supported inputs:
    - AuthenticationRecord (V2.3 authentication activity record)
    - HostArtifact with category 'authentication' or AuthenticationRecord payload
    - Dictionary with authentication record keys

    Guarantees:
    - Category is strictly TimelineCategory.AUTHENTICATION.
    - Preserves source_path, line_number, source_artifact_id, source_event_id (auth_id), and raw_line.
    - Normalizes timestamp via V3.2 if available; preserves raw_timestamp.
    - Attributes preserve username, source_ip, source_port, authentication_method, status, service, hostname.
    """

    def __init__(self, log_timestamp_year: Optional[int] = None) -> None:
        self.log_timestamp_year = log_timestamp_year

    def can_adapt(self, artifact: Any) -> bool:
        """Check if artifact is a supported authentication artifact type."""
        if isinstance(artifact, AuthenticationRecord):
            return True
        if isinstance(artifact, HostArtifact):
            return (
                artifact.category == HostArtifactCategory.AUTHENTICATION.value
                or isinstance(artifact.specialized_payload, AuthenticationRecord)
            )
        if isinstance(artifact, dict):
            return (
                ("auth_id" in artifact or "authentication_method" in artifact)
                and ("source_path" in artifact or "path" in artifact)
                and "event_type" in artifact
            )
        return False

    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """
        Adapt authentication artifact to a tuple containing one TimelineEvent.

        Raises:
            TypeError: If the artifact is not supported.
            ValueError: If source_path or event_type is missing.
        """
        if artifact is None:
            raise ValueError("Artifact cannot be None")

        if not self.can_adapt(artifact):
            raise TypeError(
                f"Unsupported artifact type for AuthenticationAdapter: {type(artifact).__name__}"
            )

        if isinstance(artifact, HostArtifact):
            if isinstance(artifact.specialized_payload, AuthenticationRecord):
                return self._adapt_auth_record(artifact.specialized_payload)
            raise TypeError(
                f"HostArtifact payload {type(artifact.specialized_payload).__name__} is not an AuthenticationRecord"
            )

        if isinstance(artifact, AuthenticationRecord):
            return self._adapt_auth_record(artifact)

        if isinstance(artifact, dict):
            return self._adapt_dict(artifact)

        raise TypeError(f"Unhandled authentication artifact type: {type(artifact).__name__}")

    def _adapt_auth_record(
        self,
        auth: AuthenticationRecord,
        source_artifact_id: Optional[str] = None,
        log_timestamp_year: Optional[int] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract a TimelineEvent from an AuthenticationRecord."""
        norm_dt: Optional[datetime] = None
        raw_ts: Optional[str] = auth.raw_timestamp
        effective_year = log_timestamp_year if log_timestamp_year is not None else self.log_timestamp_year

        target_ts_str = auth.normalized_timestamp or auth.raw_timestamp
        if target_ts_str is not None:
            try:
                norm_res = parse_timestamp(target_ts_str)
                norm_dt = norm_res.normalized_datetime
                if raw_ts is None:
                    raw_ts = norm_res.raw_timestamp
            except ValueError:
                if effective_year is not None and auth.raw_timestamp:
                    dt = normalize_bsd_timestamp(auth.raw_timestamp, log_timestamp_year=effective_year)
                    if dt is not None:
                        norm_dt = dt
                else:
                    norm_dt = None

        target_art_id = source_artifact_id if source_artifact_id is not None else auth.source_artifact_id

        attrs: Dict[str, Any] = dict(auth.attributes) if auth.attributes else {}
        if auth.source_artifact_id is not None:
            attrs["v2_artifact_id"] = auth.source_artifact_id
        if auth.username is not None:
            attrs["username"] = auth.username
        if auth.source_ip is not None:
            attrs["source_ip"] = auth.source_ip
        if auth.source_port is not None:
            attrs["source_port"] = auth.source_port
        if auth.authentication_method is not None:
            attrs["authentication_method"] = auth.authentication_method
        if auth.status is not None:
            attrs["status"] = auth.status
        if auth.service is not None:
            attrs["service"] = auth.service
        if auth.hostname is not None:
            attrs["hostname"] = auth.hostname
        if auth.event_id is not None:
            attrs["log_event_id"] = auth.event_id

        desc = auth.raw_message.strip() if auth.raw_message and auth.raw_message.strip() else f"Authentication activity: {auth.event_type} [{auth.status}]"

        event = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type=auth.event_type,
            description=desc,
            timestamp=norm_dt,
            raw_timestamp=raw_ts,
            source_path=auth.source_path,
            source_line=auth.line_number,
            source_artifact_id=target_art_id,
            source_event_id=auth.auth_id,
            raw_data=auth.raw_line,
            attributes=attrs,
        )
        return (event,)

    def _adapt_dict(
        self,
        data: Dict[str, Any],
        log_timestamp_year: Optional[int] = None,
    ) -> Tuple[TimelineEvent, ...]:
        """Extract a TimelineEvent from an authentication dictionary."""
        source_path = data.get("source_path") or data.get("path")
        if not source_path:
            raise ValueError("Authentication artifact dictionary missing required 'source_path'")

        event_type = data.get("event_type")
        if not event_type:
            raise ValueError("Authentication artifact dictionary missing required 'event_type'")

        raw_ts = data.get("raw_timestamp")
        target_ts = data.get("normalized_timestamp") or raw_ts
        norm_dt: Optional[datetime] = None
        effective_year = log_timestamp_year if log_timestamp_year is not None else self.log_timestamp_year

        if target_ts is not None:
            try:
                norm_res = parse_timestamp(target_ts)
                norm_dt = norm_res.normalized_datetime
                if raw_ts is None:
                    raw_ts = norm_res.raw_timestamp
            except ValueError:
                if effective_year is not None and raw_ts:
                    dt = normalize_bsd_timestamp(str(raw_ts), log_timestamp_year=effective_year)
                    if dt is not None:
                        norm_dt = dt
                else:
                    norm_dt = None

        attrs = dict(data.get("attributes", {}))
        for key in ("username", "source_ip", "source_port", "authentication_method", "status", "service", "hostname"):
            if key in data and data[key] is not None:
                attrs[key] = data[key]

        raw_msg = data.get("raw_message", "")
        status = data.get("status", "INFO")
        desc = raw_msg.strip() if raw_msg and raw_msg.strip() else f"Authentication activity: {event_type} [{status}]"

        event = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type=event_type,
            description=desc,
            timestamp=norm_dt,
            raw_timestamp=raw_ts,
            source_path=str(source_path),
            source_line=data.get("line_number"),
            source_artifact_id=data.get("source_artifact_id"),
            source_event_id=data.get("auth_id") or data.get("source_event_id"),
            raw_data=data.get("raw_line"),
            attributes=attrs,
        )
        return (event,)


# Singleton adapter instances for polymorphic dispatch
_DEFAULT_FILESYSTEM_ADAPTER = FilesystemAdapter()
_DEFAULT_LOG_ADAPTER = LogAdapter()
_DEFAULT_AUTH_ADAPTER = AuthenticationAdapter()

_ALL_ADAPTERS: Tuple[BaseArtifactAdapter, ...] = (
    _DEFAULT_FILESYSTEM_ADAPTER,
    _DEFAULT_LOG_ADAPTER,
    _DEFAULT_AUTH_ADAPTER,
)


def can_adapt_artifact(artifact: Any) -> bool:
    """Return True if any registered adapter can handle the given artifact."""
    if artifact is None:
        return False
    return any(adapter.can_adapt(artifact) for adapter in _ALL_ADAPTERS)


def adapt_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]:
    """
    Polymorphically adapt any supported forensic artifact into an immutable tuple of TimelineEvents.

    Dispatch order:
    1. FilesystemAdapter (ArtifactRecord, ForensicAnalysisResult, FileMetadata, filesystem HostArtifact)
    2. LogAdapter (LogEvent, log HostArtifact)
    3. AuthenticationAdapter (AuthenticationRecord, authentication HostArtifact)

    Args:
        artifact: Forensic artifact record, result, or host artifact.

    Returns:
        Tuple[TimelineEvent, ...]: Immutable tuple of extracted TimelineEvents.

    Raises:
        ValueError: If artifact is None or contains malformed data.
        TypeError: If artifact type is unsupported for timeline adaptation.
    """
    if artifact is None:
        raise ValueError("Artifact cannot be None")

    # Check registered adapters in order
    for adapter in _ALL_ADAPTERS:
        if adapter.can_adapt(artifact):
            return adapter.adapt(artifact)

    # Explicit check for known V2 models that lack chronological timestamps
    non_timeline_types = (
        UserAccount,
        GroupRecord,
        ShadowRecord,
        SudoRule,
        SshKeyInfo,
        PersistenceRecord,
    )
    if isinstance(artifact, non_timeline_types):
        raise TypeError(
            f"V2 artifact type '{type(artifact).__name__}' does not contain factual chronological timestamps "
            "and cannot be adapted into timeline events in V3.3."
        )

    if isinstance(artifact, HostArtifact):
        raise TypeError(
            f"HostArtifact with category '{artifact.category}' does not contain factual chronological timestamps "
            "and cannot be adapted into timeline events in V3.3."
        )

    raise TypeError(
        f"Unsupported artifact type for timeline adaptation: {type(artifact).__name__}. "
        "Must be a supported filesystem, log, or authentication artifact."
    )


def adapt_filesystem_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]:
    """Convenience adapter specifically for filesystem artifacts."""
    return _DEFAULT_FILESYSTEM_ADAPTER.adapt(artifact)


def adapt_log_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]:
    """Convenience adapter specifically for log artifacts."""
    return _DEFAULT_LOG_ADAPTER.adapt(artifact)


def adapt_auth_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]:
    """Convenience adapter specifically for authentication artifacts."""
    return _DEFAULT_AUTH_ADAPTER.adapt(artifact)


def adapt_artifacts(
    artifacts: Sequence[Any],
    ignore_unsupported: bool = False,
    log_timestamp_year: Optional[int] = None,
) -> Tuple[TimelineEvent, ...]:
    """
    Adapt a sequence of forensic artifacts into an immutable tuple of TimelineEvents.

    Preserves input collection ordering without performing timeline reconstruction,
    cross-artifact sorting, or event deduplication (which belong to V3.4).

    Builds a deterministic provenance map linking filesystem artifact records to their
    deterministic V3 artifact IDs so that dependent log and authentication events share
    the exact same deterministic source_artifact_id for their parent log file.

    Args:
        artifacts: Sequence of forensic artifacts.
        ignore_unsupported: If True, skip unsupported artifacts silently.
                           If False (default), raise TypeError on unsupported artifacts.
        log_timestamp_year: Optional explicit calendar year context for BSD syslog timestamps.

    Returns:
        Tuple[TimelineEvent, ...]: Immutable tuple of extracted events in sequence.

    Raises:
        TypeError: If an unsupported artifact is encountered and ignore_unsupported is False.
        ValueError: If an artifact is None or contains malformed data.
    """
    if artifacts is None:
        raise ValueError("Artifacts sequence cannot be None")

    # Step 1: Pre-build deterministic artifact ID maps from filesystem artifacts
    v2_to_det_id: Dict[str, str] = {}
    path_to_det_id: Dict[str, str] = {}

    for art in artifacts:
        if art is None:
            continue
        rec = None
        if isinstance(art, ArtifactRecord):
            rec = art
        elif isinstance(art, HostArtifact) and isinstance(art.specialized_payload, ArtifactRecord):
            rec = art.specialized_payload

        if rec is not None:
            try:
                det_id = compute_deterministic_artifact_id(
                    path=rec.source_path,
                    relative_path=rec.relative_path,
                    sha256=rec.sha256,
                )
                if rec.artifact_id:
                    v2_to_det_id[rec.artifact_id] = det_id
                if rec.source_path:
                    path_to_det_id[_normalize_evidence_path(rec.source_path)] = det_id
                if rec.relative_path:
                    norm_rel = _normalize_evidence_path(rec.relative_path)
                    path_to_det_id[norm_rel] = det_id
                    path_to_det_id["/" + norm_rel.lstrip("/")] = det_id
            except ValueError:
                pass

    # Step 2: Adapt artifacts with deterministic provenance resolution
    collected: List[TimelineEvent] = []
    for art in artifacts:
        if art is None:
            raise ValueError("Artifact in sequence cannot be None")
        if not can_adapt_artifact(art):
            if ignore_unsupported:
                continue
            # Let adapt_artifact raise the descriptive TypeError
            adapt_artifact(art)

        # Resolve deterministic parent artifact ID for log/auth events
        if isinstance(art, LogEvent):
            resolved_art_id = None
            if art.source_artifact_id and art.source_artifact_id in v2_to_det_id:
                resolved_art_id = v2_to_det_id[art.source_artifact_id]
            elif art.source_path and _normalize_evidence_path(art.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(art.source_path)]
            events = _DEFAULT_LOG_ADAPTER._adapt_log_event(
                art,
                source_artifact_id=resolved_art_id,
                log_timestamp_year=log_timestamp_year,
            )
        elif isinstance(art, HostArtifact) and isinstance(art.specialized_payload, LogEvent):
            log_payload = art.specialized_payload
            resolved_art_id = None
            src_aid = art.source_artifact_id or log_payload.source_artifact_id
            if src_aid and src_aid in v2_to_det_id:
                resolved_art_id = v2_to_det_id[src_aid]
            elif art.source_path and _normalize_evidence_path(art.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(art.source_path)]
            elif log_payload.source_path and _normalize_evidence_path(log_payload.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(log_payload.source_path)]
            events = _DEFAULT_LOG_ADAPTER._adapt_log_event(
                log_payload,
                source_artifact_id=resolved_art_id,
                log_timestamp_year=log_timestamp_year,
            )
        elif isinstance(art, AuthenticationRecord):
            resolved_art_id = None
            if art.source_artifact_id and art.source_artifact_id in v2_to_det_id:
                resolved_art_id = v2_to_det_id[art.source_artifact_id]
            elif art.source_path and _normalize_evidence_path(art.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(art.source_path)]
            events = _DEFAULT_AUTH_ADAPTER._adapt_auth_record(
                art,
                source_artifact_id=resolved_art_id,
                log_timestamp_year=log_timestamp_year,
            )
        elif isinstance(art, HostArtifact) and isinstance(art.specialized_payload, AuthenticationRecord):
            auth_payload = art.specialized_payload
            resolved_art_id = None
            src_aid = art.source_artifact_id or auth_payload.source_artifact_id
            if src_aid and src_aid in v2_to_det_id:
                resolved_art_id = v2_to_det_id[src_aid]
            elif art.source_path and _normalize_evidence_path(art.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(art.source_path)]
            elif auth_payload.source_path and _normalize_evidence_path(auth_payload.source_path) in path_to_det_id:
                resolved_art_id = path_to_det_id[_normalize_evidence_path(auth_payload.source_path)]
            events = _DEFAULT_AUTH_ADAPTER._adapt_auth_record(
                auth_payload,
                source_artifact_id=resolved_art_id,
                log_timestamp_year=log_timestamp_year,
            )
        else:
            events = adapt_artifact(art)

        collected.extend(events)

    return tuple(collected)
