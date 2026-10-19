"""
Forensic Report Reader and Ingestion Layer for ForensiX (V7.1).

Provides safe, deterministic, and read-only ingestion and schema validation for
persisted ForensiX forensic JSON reports (V1 through V6) to prepare them for
future dashboard querying and visualization.

Core Design and Forensic Safety Principles:
1. Strict Read-Only Access:
   - Report files are opened strictly in read-only mode ('rb').
   - Zero modifications, renames, deletions, or writes to evidence or report files.
2. Safe File Validation & Single-Snapshot Bounded Read:
   - Validates existence, path resolution, and regular file status.
   - Handles symlinks deliberately by resolving target paths safely.
   - Defensive bounded size limits prevent unbounded memory consumption by reading
     at most max_size_bytes + 1 bytes.
   - Cryptographic SHA-256 and parsed JSON are derived from the exact same byte snapshot
     in a single read operation.
3. Protected Ingested Payload:
   - IngestedReport.raw_data is deeply immutable via types.MappingProxyType and tuples.
   - Callers cannot mutate nested dictionaries or lists in-place.
   - Safe unfreezing is available via raw_dict() and to_dict(include_raw=True).
4. Explicit Schema Detection:
   - Distinguishes V1 Evidence Analysis, V2 Host Triage, V3 Timeline, V4 Correlation,
     V4 Detection, and V4/V5/V6 Integrated Investigation reports.
   - Enforces strict canonical REPORT-<UUIDv4> format for V2 Host Triage reports.
   - Rejects unrecognized, ambiguous, or incomplete structures with clear errors.
5. Non-Speculative Representation & Metadata Normalization:
   - Only records facts present in the real report; never invents integrity or provenance.
   - Accurately computes summary metrics directly from verified report payloads.
   - Normalizes whitespace-only metadata strings (such as case_id) to None.
6. Zero External Dependencies:
   - Built entirely using the Python standard library.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import types
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.hasher import DEFAULT_CHUNK_SIZE


# Default maximum allowed report file size (50 MB)
DEFAULT_MAX_REPORT_SIZE_BYTES: int = 50 * 1024 * 1024


class ReportReaderError(Exception):
    """Base exception for all forensic report reader errors."""
    pass


class ReportNotFoundError(ReportReaderError, FileNotFoundError):
    """Raised when the specified report file does not exist."""
    pass


class ReportInvalidFileError(ReportReaderError, ValueError):
    """Raised when the specified target path is a directory or not a regular file."""
    pass


class ReportSizeLimitError(ReportReaderError, ValueError):
    """Raised when the report file exceeds the allowable size limit."""
    pass


class ReportParseError(ReportReaderError, ValueError):
    """Raised when the report file contains invalid or malformed JSON."""
    pass


class ReportSchemaError(ReportReaderError, ValueError):
    """Raised when the report JSON structure does not match any recognized ForensiX schema."""
    pass


class ReportType(str, Enum):
    """Supported ForensiX forensic report schema classifications."""

    EVIDENCE_ANALYSIS = "evidence_analysis"          # V1 Single-file analysis
    HOST_TRIAGE = "host_triage"                      # V2 End-to-end host triage
    TIMELINE = "timeline"                            # V3 Chronological timeline
    CORRELATION = "correlation"                      # V4 Event correlation
    DETECTION = "detection"                          # V4 Rule detection
    CORRELATION_DETECTION = "correlation_detection"  # V4/V5/V6 Integrated investigation


def freeze_payload(obj: Any) -> Any:
    """
    Recursively freeze mappings into types.MappingProxyType and sequences into tuples.

    Guarantees deep immutability for ingested forensic report payloads, preventing
    accidental or deliberate in-place mutation of nested dictionaries and lists.

    Args:
        obj: Raw deserialized JSON object or mapping/sequence.

    Returns:
        Deeply immutable structure.
    """
    if isinstance(obj, types.MappingProxyType):
        return types.MappingProxyType({k: freeze_payload(v) for k, v in obj.items()})
    elif isinstance(obj, (dict, Mapping)):
        return types.MappingProxyType({k: freeze_payload(v) for k, v in obj.items()})
    elif isinstance(obj, (list, tuple)):
        return tuple(freeze_payload(item) for item in obj)
    return obj


def unfreeze_payload(obj: Any) -> Any:
    """
    Recursively unfreeze mapping proxies into standard dictionaries and tuples into lists.

    Produces a pure, JSON-serializable mutable structure suitable for callers needing
    standard dict mutation or json.dumps() compatibility, without mutating the source.

    Args:
        obj: Immutable structure (MappingProxyType, tuple, etc.).

    Returns:
        Deeply mutable dictionary/list structure.
    """
    if isinstance(obj, (types.MappingProxyType, Mapping)):
        return {k: unfreeze_payload(v) for k, v in obj.items()}
    elif isinstance(obj, (tuple, list)):
        return [unfreeze_payload(item) for item in obj]
    return obj


def _is_valid_report_id(report_id: Any) -> bool:
    """
    Validate canonical ForensiX REPORT-<UUIDv4> format strictly.

    Requirements:
    1. Must be a string.
    2. Must start with prefix 'REPORT-'.
    3. Remainder must be a valid RFC 4122 UUID version 4 in canonical hyphenated representation.

    Args:
        report_id: Candidate identifier to validate.

    Returns:
        bool: True if valid canonical REPORT-<UUIDv4>, False otherwise.
    """
    if not isinstance(report_id, str):
        return False
    if not report_id.startswith("REPORT-"):
        return False
    raw_uuid = report_id[7:]
    try:
        val = uuid.UUID(raw_uuid)
        return val.version == 4 and str(val) == raw_uuid.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def _normalize_string_metadata(val: Any) -> Optional[str]:
    """
    Normalize metadata string by trimming surrounding whitespace and converting
    empty or whitespace-only strings to None.

    Non-string values are converted to string and trimmed if not None.

    Args:
        val: Input metadata value.

    Returns:
        Optional[str]: Cleaned string or None if empty/whitespace-only/None.
    """
    if val is None:
        return None
    if isinstance(val, str):
        cleaned = val.strip()
        return cleaned if cleaned else None
    cleaned = str(val).strip()
    return cleaned if cleaned else None


@dataclass(frozen=True)
class CaseMetadataView:
    """
    Immutable representation of administrative case context extracted from a report.

    Attributes:
        case_id: Incident case identifier, or None.
        case_name: Human-readable incident title, or None.
        investigator: Handling investigator name/ID, or None.
        created_at: ISO 8601 UTC timestamp of report generation, or None.
        forensix_version: ForensiX release version generating the report, or None.
        evidence_root: Source evidence file or directory path, or None.
        report_id: Unique report tracking identifier, or None.
        triage_id: Triage execution identifier, or None.
        extra_metadata: Immutable tuple of other key-value metadata pairs.
    """

    case_id: Optional[str] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    created_at: Optional[str] = None
    forensix_version: Optional[str] = None
    evidence_root: Optional[str] = None
    report_id: Optional[str] = None
    triage_id: Optional[str] = None
    extra_metadata: Tuple[Tuple[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata view to a clean JSON-serializable dictionary."""
        d: Dict[str, Any] = {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "created_at": self.created_at,
            "forensix_version": self.forensix_version,
            "evidence_root": self.evidence_root,
            "report_id": self.report_id,
            "triage_id": self.triage_id,
        }
        if self.extra_metadata:
            d["extra_metadata"] = dict(self.extra_metadata)
        return d


@dataclass(frozen=True)
class ReportSummaryCounts:
    """
    Factual, verified aggregate counts extracted directly from report payloads.

    Attributes:
        artifact_count: Count of forensic artifacts in host triage or evidence records.
        event_count: Count of chronological timeline events.
        correlation_count: Count of identified event correlations.
        detection_count: Count of detection rule evaluations.
        matched_detection_count: Count of detections where matched is True.
        audit_event_count: Count of provenance audit trail events.
    """

    artifact_count: int = 0
    event_count: int = 0
    correlation_count: int = 0
    detection_count: int = 0
    matched_detection_count: int = 0
    audit_event_count: int = 0

    def to_dict(self) -> Dict[str, int]:
        """Convert counts to a standard dictionary."""
        return {
            "artifact_count": self.artifact_count,
            "event_count": self.event_count,
            "correlation_count": self.correlation_count,
            "detection_count": self.detection_count,
            "matched_detection_count": self.matched_detection_count,
            "audit_event_count": self.audit_event_count,
        }


@dataclass(frozen=True)
class IngestedReport:
    """
    Immutable representation of a safely ingested and validated ForensiX JSON report.

    Attributes:
        report_type: Classified ReportType enum.
        source_path: Resolved canonical absolute path to the report file.
        file_size_bytes: Size of the accepted byte snapshot in bytes.
        sha256: Hexadecimal SHA-256 cryptographic digest of the exact accepted bytes.
        metadata: Normalized CaseMetadataView instance.
        counts: Factual ReportSummaryCounts instance.
        raw_data: Complete parsed report mapping (read-only MappingProxyType/tuple structure).
        warnings: Immutable tuple of non-fatal validation warnings or missing optional fields.
    """

    report_type: ReportType
    source_path: Path
    file_size_bytes: int
    sha256: str
    metadata: CaseMetadataView
    counts: ReportSummaryCounts
    raw_data: Mapping[str, Any]
    warnings: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Enforce deep immutability for raw_data and warnings."""
        object.__setattr__(self, "raw_data", freeze_payload(self.raw_data))
        if not isinstance(self.warnings, tuple):
            object.__setattr__(self, "warnings", tuple(self.warnings))

    @property
    def is_investigation(self) -> bool:
        """Check if this report is an integrated correlation and detection investigation."""
        return self.report_type == ReportType.CORRELATION_DETECTION

    @property
    def is_timeline(self) -> bool:
        """Check if this report is a chronological timeline report."""
        return self.report_type == ReportType.TIMELINE

    @property
    def is_triage(self) -> bool:
        """Check if this report is a V2 automated host triage report."""
        return self.report_type == ReportType.HOST_TRIAGE

    @property
    def is_evidence_analysis(self) -> bool:
        """Check if this report is a V1 single-file evidence analysis report."""
        return self.report_type == ReportType.EVIDENCE_ANALYSIS

    def raw_dict(self) -> Dict[str, Any]:
        """
        Return a deep, mutable dictionary copy of raw_data.

        Ensures standard json.dumps() compatibility and enables callers to
        safely mutate or serialize the payload without modifying the stored snapshot.

        Returns:
            Dict[str, Any]: Deeply unfrozen copy of raw_data.
        """
        return unfreeze_payload(self.raw_data)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        """
        Convert ingested report metadata and summary view to a JSON-serializable dictionary.

        Args:
            include_raw: If True, includes a deep mutable copy of raw_data under 'raw_data'
                         key, ensuring standard json.dumps() compatibility and strictly
                         preventing any mutation of the internal read-only snapshot.
                         Defaults to False.

        Returns:
            Dict[str, Any]: Pure, JSON-serializable dictionary.
        """
        d: Dict[str, Any] = {
            "report_type": self.report_type.value,
            "source_path": str(self.source_path),
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "metadata": self.metadata.to_dict(),
            "counts": self.counts.to_dict(),
            "warnings": list(self.warnings),
        }
        if include_raw:
            d["raw_data"] = self.raw_dict()
        return d


def _compute_file_sha256(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Compute SHA-256 digest of a file strictly in read-only binary mode.

    Args:
        path: Resolved file path.
        chunk_size: Buffer size for streaming read.

    Returns:
        str: Hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def detect_report_schema(data: Any) -> ReportType:
    """
    Safely inspect a parsed JSON object and classify its ForensiX report schema.

    Enforces strict structural requirements for each schema to avoid silent misclassification.

    Args:
        data: Parsed dictionary from a JSON report.

    Returns:
        ReportType: Classified schema enum.

    Raises:
        ReportSchemaError: If data is not a dict or does not match any known schema.
    """
    if not isinstance(data, (dict, Mapping)):
        raise ReportSchemaError(
            f"Report JSON root must be an object/dict, got {type(data).__name__}"
        )

    # 1. Explicit report_type key (V3, V4, V5, V6 standards)
    explicit_type = data.get("report_type")
    if isinstance(explicit_type, str):
        norm_type = explicit_type.strip().lower()

        if norm_type == "correlation_detection":
            # Verify required V4.6 / V5 / V6 investigation sections
            required = ("detections", "correlations", "timeline_events")
            missing = [r for r in required if r not in data]
            if missing:
                raise ReportSchemaError(
                    f"Invalid 'correlation_detection' report: missing required sections {missing}"
                )
            if not isinstance(data["detections"], (list, tuple)):
                raise ReportSchemaError("'detections' section must be a list")
            if not isinstance(data["correlations"], (list, tuple)):
                raise ReportSchemaError("'correlations' section must be a list")
            if not isinstance(data["timeline_events"], (list, tuple)):
                raise ReportSchemaError("'timeline_events' section must be a list")
            return ReportType.CORRELATION_DETECTION

        if norm_type == "timeline":
            # Verify required V3.6 timeline sections
            if "events" not in data:
                raise ReportSchemaError("Invalid 'timeline' report: missing 'events' section")
            if not isinstance(data["events"], (list, tuple)):
                raise ReportSchemaError("'events' section must be a list")
            return ReportType.TIMELINE

        if norm_type == "detection":
            # Verify required V4.6 detection report sections
            if "detections" not in data:
                raise ReportSchemaError("Invalid 'detection' report: missing 'detections' section")
            if not isinstance(data["detections"], (list, tuple)):
                raise ReportSchemaError("'detections' section must be a list")
            return ReportType.DETECTION

        if norm_type == "correlation":
            # Verify required V4.6 correlation report sections
            if "correlations" not in data:
                raise ReportSchemaError("Invalid 'correlation' report: missing 'correlations' section")
            if not isinstance(data["correlations"], (list, tuple)):
                raise ReportSchemaError("'correlations' section must be a list")
            return ReportType.CORRELATION

        raise ReportSchemaError(
            f"Unrecognized 'report_type' value: '{explicit_type}'. "
            f"Supported types: {[t.value for t in ReportType]}"
        )

    # 2. V2 Host Triage ForensicReport signature
    if (
        "metadata" in data
        and isinstance(data["metadata"], (dict, Mapping))
        and "artifacts" in data
        and isinstance(data["artifacts"], (list, tuple))
        and "audit_trail" in data
        and isinstance(data["audit_trail"], (list, tuple))
    ):
        meta = data["metadata"]
        report_id = meta.get("report_id")
        if _is_valid_report_id(report_id):
            return ReportType.HOST_TRIAGE

    # 3. V1 Evidence Analysis ForensicAnalysisResult signature
    if (
        "evidence" in data
        and isinstance(data["evidence"], (dict, Mapping))
        and "file" in data
        and isinstance(data["file"], (dict, Mapping))
        and "metadata" in data
        and isinstance(data["metadata"], (dict, Mapping))
        and "hashes" in data
        and isinstance(data["hashes"], (dict, Mapping))
    ):
        ev = data["evidence"]
        h = data["hashes"]
        if "evidence_id" in ev and ("sha256" in h or "md5" in h):
            return ReportType.EVIDENCE_ANALYSIS

    keys_found = sorted(data.keys())
    raise ReportSchemaError(
        f"Unrecognized or unsupported ForensiX report schema. Root object keys present: {keys_found}"
    )


def _extract_metadata_and_counts(
    report_type: ReportType,
    data: Mapping[str, Any],
) -> Tuple[CaseMetadataView, ReportSummaryCounts, List[str]]:
    """
    Extract factual case metadata, summary counts, and validation warnings.

    Args:
        report_type: Classified schema enum.
        data: Parsed report mapping.

    Returns:
        Tuple[CaseMetadataView, ReportSummaryCounts, List[str]]:
            Extracted metadata, counts, and any non-fatal validation warnings.
    """
    warnings: List[str] = []

    if report_type == ReportType.CORRELATION_DETECTION:
        meta_dict = data.get("metadata", {})
        if not isinstance(meta_dict, (dict, Mapping)):
            meta_dict = {}
            warnings.append("Report 'metadata' section is not a dictionary.")

        case_id = meta_dict.get("case_id")
        case_name = meta_dict.get("case_name")
        investigator = meta_dict.get("investigator")
        created_at = meta_dict.get("generated_at")
        forensix_version = data.get("forensix_version")

        detections = data.get("detections", [])
        correlations = data.get("correlations", [])
        events = data.get("timeline_events", [])

        matched_count = sum(
            1 for d in detections if isinstance(d, (dict, Mapping)) and d.get("matched") is True
        )

        metadata = CaseMetadataView(
            case_id=_normalize_string_metadata(case_id),
            case_name=_normalize_string_metadata(case_name),
            investigator=_normalize_string_metadata(investigator),
            created_at=_normalize_string_metadata(created_at),
            forensix_version=_normalize_string_metadata(forensix_version),
        )
        counts = ReportSummaryCounts(
            detection_count=len(detections),
            matched_detection_count=matched_count,
            correlation_count=len(correlations),
            event_count=len(events),
        )
        return metadata, counts, warnings

    elif report_type == ReportType.TIMELINE:
        meta_dict = data.get("metadata", {})
        if not isinstance(meta_dict, (dict, Mapping)):
            meta_dict = {}
            warnings.append("Report 'metadata' section is not a dictionary.")

        case_id = meta_dict.get("case_id")
        case_name = meta_dict.get("case_name")
        investigator = meta_dict.get("investigator")
        created_at = meta_dict.get("generated_at")
        forensix_version = data.get("forensix_version")

        events = data.get("events", [])

        metadata = CaseMetadataView(
            case_id=_normalize_string_metadata(case_id),
            case_name=_normalize_string_metadata(case_name),
            investigator=_normalize_string_metadata(investigator),
            created_at=_normalize_string_metadata(created_at),
            forensix_version=_normalize_string_metadata(forensix_version),
        )
        counts = ReportSummaryCounts(
            event_count=len(events),
        )
        return metadata, counts, warnings

    elif report_type == ReportType.DETECTION:
        meta_dict = data.get("metadata", {})
        if not isinstance(meta_dict, (dict, Mapping)):
            meta_dict = {}
            warnings.append("Report 'metadata' section is not a dictionary.")

        case_id = meta_dict.get("case_id")
        case_name = meta_dict.get("case_name")
        investigator = meta_dict.get("investigator")
        created_at = meta_dict.get("generated_at")
        forensix_version = data.get("forensix_version")

        detections = data.get("detections", [])
        matched_count = sum(
            1 for d in detections if isinstance(d, (dict, Mapping)) and d.get("matched") is True
        )

        metadata = CaseMetadataView(
            case_id=_normalize_string_metadata(case_id),
            case_name=_normalize_string_metadata(case_name),
            investigator=_normalize_string_metadata(investigator),
            created_at=_normalize_string_metadata(created_at),
            forensix_version=_normalize_string_metadata(forensix_version),
        )
        counts = ReportSummaryCounts(
            detection_count=len(detections),
            matched_detection_count=matched_count,
        )
        return metadata, counts, warnings

    elif report_type == ReportType.CORRELATION:
        meta_dict = data.get("metadata", {})
        if not isinstance(meta_dict, (dict, Mapping)):
            meta_dict = {}
            warnings.append("Report 'metadata' section is not a dictionary.")

        case_id = meta_dict.get("case_id")
        case_name = meta_dict.get("case_name")
        investigator = meta_dict.get("investigator")
        created_at = meta_dict.get("generated_at")
        forensix_version = data.get("forensix_version")

        correlations = data.get("correlations", [])

        metadata = CaseMetadataView(
            case_id=_normalize_string_metadata(case_id),
            case_name=_normalize_string_metadata(case_name),
            investigator=_normalize_string_metadata(investigator),
            created_at=_normalize_string_metadata(created_at),
            forensix_version=_normalize_string_metadata(forensix_version),
        )
        counts = ReportSummaryCounts(
            correlation_count=len(correlations),
        )
        return metadata, counts, warnings

    elif report_type == ReportType.HOST_TRIAGE:
        meta = data.get("metadata", {})
        case_id = meta.get("case_id")
        case_name = meta.get("case_name")
        investigator = meta.get("investigator")
        created_at = meta.get("created_at")
        forensix_version = meta.get("forensix_version")
        evidence_root = meta.get("evidence_root")
        report_id = meta.get("report_id")
        triage_id = meta.get("triage_id")

        artifacts = data.get("artifacts", [])
        audit_trail = data.get("audit_trail", [])

        metadata = CaseMetadataView(
            case_id=_normalize_string_metadata(case_id),
            case_name=_normalize_string_metadata(case_name),
            investigator=_normalize_string_metadata(investigator),
            created_at=_normalize_string_metadata(created_at),
            forensix_version=_normalize_string_metadata(forensix_version),
            evidence_root=_normalize_string_metadata(evidence_root),
            report_id=_normalize_string_metadata(report_id),
            triage_id=_normalize_string_metadata(triage_id),
        )
        counts = ReportSummaryCounts(
            artifact_count=len(artifacts),
            audit_event_count=len(audit_trail),
        )
        return metadata, counts, warnings

    elif report_type == ReportType.EVIDENCE_ANALYSIS:
        ev = data.get("evidence", {})
        fl = data.get("file", {})
        analysis_ts = data.get("analysis_timestamp")

        report_id = ev.get("evidence_id")
        evidence_root = ev.get("original_path")
        created_at = ev.get("registered_at") or analysis_ts

        extras: List[Tuple[str, Any]] = []
        if "filename" in fl:
            extras.append(("filename", fl["filename"]))
        if "size" in fl:
            extras.append(("size_bytes", fl["size"]))
        if "type" in fl and fl["type"]:
            extras.append(("mime_type", fl["type"]))

        metadata = CaseMetadataView(
            report_id=_normalize_string_metadata(report_id),
            evidence_root=_normalize_string_metadata(evidence_root),
            created_at=_normalize_string_metadata(created_at),
            extra_metadata=tuple(extras),
        )
        counts = ReportSummaryCounts(
            artifact_count=1,
        )
        return metadata, counts, warnings

    raise ReportSchemaError(f"Unhandled report type for extraction: {report_type}")


def read_report(
    file_path: Union[str, Path],
    max_size_bytes: int = DEFAULT_MAX_REPORT_SIZE_BYTES,
) -> IngestedReport:
    """
    Safely ingest, validate, and summarize an existing ForensiX JSON report file.

    Forensic and Security Guarantees:
    - Path Validation: Handles symlinks and relative paths by resolving to an absolute canonical path.
    - Regular File Requirement: Rejects directories, missing targets, or special device nodes.
    - Read-Only Access: Opens file strictly in read-only mode ('rb'). Never modifies or touches evidence.
    - Defensive Size Bounding: Validates file size before reading and enforces max_size_bytes during
      the actual read by reading at most max_size_bytes + 1 bytes. Protects against memory exhaustion
      even if the file size changes concurrently.
    - Cryptographic Integrity: Computes SHA-256 hash directly from the accepted byte buffer.
    - Exact Content Guarantee: The returned SHA-256 and parsed JSON are derived from the exact same
      byte snapshot read in a single operation. Note: This single-read snapshot guarantees internal
      consistency for this ingestion operation, but does not claim filesystem-level atomic locking
      against concurrent external writes.
    - Deep Immutability: IngestedReport.raw_data is deeply frozen using MappingProxyType and tuples.
      Callers cannot mutate the stored snapshot in-place.
    - Schema Integrity: Strictly detects and validates known ForensiX schemas; rejects unknown or corrupted data.

    Args:
        file_path: Filesystem path to the report JSON file (str or Path).
        max_size_bytes: Maximum allowed report size in bytes (default 50 MB).

    Returns:
        IngestedReport: Deeply immutable, validated ingested report container.

    Raises:
        ReportNotFoundError: If file_path does not exist or points to a broken symlink.
        ReportInvalidFileError: If file_path is a directory or not a regular file.
        ReportSizeLimitError: If max_size_bytes is not a non-negative integer or if file_path size exceeds max_size_bytes.
        ReportParseError: If file_path does not contain valid JSON or valid UTF-8.
        ReportSchemaError: If file_path JSON does not conform to any recognized ForensiX schema.
    """
    # 0. Validate max_size_bytes parameter before filesystem operations
    if type(max_size_bytes) is not int or max_size_bytes < 0:
        raise ReportSizeLimitError(
            f"Invalid max_size_bytes: {max_size_bytes!r}. Limit must be a non-negative integer."
        )

    if file_path is None:
        raise ReportNotFoundError("Report file path cannot be None")

    raw_path = Path(file_path)

    # 1. Existence and symlink resolution check
    if not raw_path.exists():
        raise ReportNotFoundError(f"Report file does not exist: '{file_path}'")

    try:
        resolved_path = raw_path.resolve(strict=True)
    except FileNotFoundError as err:
        raise ReportNotFoundError(f"Broken symlink or non-existent target: '{file_path}'") from err
    except (PermissionError, OSError) as err:
        raise ReportInvalidFileError(f"Cannot resolve report path '{file_path}': {err}") from err

    # 2. File type validation
    if raw_path.is_dir() or resolved_path.is_dir():
        raise ReportInvalidFileError(
            f"Expected a regular report file, but target is a directory: '{file_path}'"
        )

    if not resolved_path.is_file():
        raise ReportInvalidFileError(
            f"Target path is not a regular file: '{file_path}'"
        )

    # 3. Input-size limit preliminary check
    try:
        stat_result = resolved_path.stat()
        initial_size = stat_result.st_size
    except OSError as err:
        raise ReportInvalidFileError(f"Failed to inspect report file stat: '{file_path}': {err}") from err

    if initial_size > max_size_bytes:
        raise ReportSizeLimitError(
            f"Report file size ({initial_size} bytes) exceeds maximum allowed limit "
            f"({max_size_bytes} bytes): '{file_path}'"
        )

    # 4. Bounded single-snapshot read (strictly read-only binary mode)
    # Read at most max_size_bytes + 1 to detect growth beyond limit without unbounded allocation
    try:
        with open(resolved_path, "rb") as f:
            content_bytes = f.read(max_size_bytes + 1)
    except (PermissionError, OSError) as err:
        raise ReportInvalidFileError(f"Cannot read report file: '{file_path}': {err}") from err

    if len(content_bytes) > max_size_bytes:
        raise ReportSizeLimitError(
            f"Report file content exceeds maximum allowed limit ({max_size_bytes} bytes): '{file_path}'"
        )

    file_size_bytes = len(content_bytes)
    file_sha256 = hashlib.sha256(content_bytes).hexdigest()

    # 5. Decode accepted bytes as UTF-8 and parse JSON
    try:
        decoded_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ReportParseError(
            f"Report file is not valid UTF-8: '{resolved_path.name}': {err}"
        ) from err

    try:
        raw_data = json.loads(decoded_text)
    except json.JSONDecodeError as err:
        raise ReportParseError(
            f"Malformed JSON in report file '{resolved_path.name}': {err.msg} (line {err.lineno}, col {err.colno})"
        ) from err

    # 6. Schema detection and structure validation
    report_type = detect_report_schema(raw_data)

    # 7. Extract normalized metadata, summary counts, and validation warnings
    metadata, counts, warnings = _extract_metadata_and_counts(report_type, raw_data)

    return IngestedReport(
        report_type=report_type,
        source_path=resolved_path,
        file_size_bytes=file_size_bytes,
        sha256=file_sha256,
        metadata=metadata,
        counts=counts,
        raw_data=raw_data,
        warnings=tuple(warnings),
    )
