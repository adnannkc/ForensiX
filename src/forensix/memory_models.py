"""
Forensic Memory Evidence Models for ForensiX (V6.1).

Provides strongly typed, deeply immutable dataclasses representing memory evidence images
and Volatility execution provenance records.

Core Principles:
1. Forensic integrity: Never modifies original evidence files. Hashing is performed strictly
   streamingly in read-only chunks without loading large memory images into RAM.
2. Deterministic identity: Memory evidence identity is derived deterministically via RFC 4122
   UUIDv5 over stable forensic facts (SHA-256 hash, file size, canonical format), strictly
   excluding volatile properties such as file path, registration time, or host environment.
3. Execution provenance: Tracks tool execution state, exit codes, sanitized arguments, timing,
   and output hashes without storing secrets, sensitive memory dumps, or complete environment variables.
4. Non-speculative: Factual software execution and forensic metadata only.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Dict, Optional, Sequence, Tuple, Union
import uuid

from forensix.hasher import DEFAULT_CHUNK_SIZE, compute_hashes

# Canonical RFC 4122 UUID namespace for ForensiX V6 deterministic memory evidence
FORENSIX_V6_MEMORY_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v6/memory"
)

# Known memory image magic headers for reliable format classification
_LIME_MAGIC: bytes = b"LiME"
_LIME_MAGIC_BE: bytes = b"EMiL"
_WIN_CRASH_MAGIC: bytes = b"PAGE"
_WIN_CRASH_MAGIC_DUMP: bytes = b"PAGEDUMP"
_WIN_CRASH_MAGIC_64: bytes = b"DU64"
_ELF_CORE_MAGIC: bytes = b"\x7fELF"
_ELF_CLASS_32: int = 1
_ELF_CLASS_64: int = 2
_ELF_DATA_LSB: int = 1  # Little-endian
_ELF_DATA_MSB: int = 2  # Big-endian
_ELF_ET_CORE: int = 4

# Standard schema version for V6.1 memory models
MEMORY_SCHEMA_VERSION: str = "1.0.0"


class VolatilityExecutionStatus(str, Enum):
    """
    Execution lifecycle status of a Volatility invocation.

    Describes software process execution state only. Does NOT indicate forensic
    threat conclusions or guarantee finding correctness.
    """

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


def compute_deterministic_memory_id(
    sha256: str,
    file_size: int,
    evidence_format: Optional[str] = None,
) -> str:
    """
    Generate a deterministic UUIDv5 tracking identifier for a memory evidence image.

    Stable Inputs:
    - sha256: Hex digest of SHA-256 hash over the raw evidence bytes.
    - file_size: Total size of the file in bytes.
    - evidence_format: Canonical format classification (e.g. 'lime', 'raw') if reliably determined.

    Volatile inputs such as file paths, registration times, hostnames, or OS environments
    are strictly excluded to ensure identical evidence bytes always yield identical identifiers.

    Returns:
        str: Deterministic identifier formatted as 'MEM-<UUIDv5>'.

    Raises:
        ValueError: If sha256 or file_size are invalid.
    """
    if not isinstance(sha256, str) or not sha256.strip():
        raise ValueError("sha256 must be a non-empty hex string")
    clean_hash = sha256.strip().lower()
    if len(clean_hash) != 64 or not all(c in "0123456789abcdef" for c in clean_hash):
        raise ValueError(f"sha256 must be a 64-character lowercase hexadecimal string, got '{sha256}'")

    if not isinstance(file_size, int) or file_size < 0:
        raise ValueError(f"file_size must be a non-negative integer, got {file_size}")

    fmt_part = f"|format:{evidence_format.strip().lower()}" if evidence_format and str(evidence_format).strip() else ""
    canonical_key = f"sha256:{clean_hash}|size:{file_size}{fmt_part}"
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEM-{det_uuid}"


def compute_deterministic_execution_id(
    tool: str,
    plugin: str,
    sanitized_args: Sequence[str],
    input_evidence_hash: Optional[str] = None,
) -> str:
    """
    Generate a deterministic UUIDv5 tracking identifier for a Volatility execution record.

    Stable Inputs:
    - tool: Tool binary name (e.g. 'volatility3')
    - plugin: Plugin identifier (e.g. 'linux.pslist')
    - sanitized_args: Sorted or ordered sanitized command line arguments
    - input_evidence_hash: SHA-256 hash of the input evidence image if available

    Returns:
        str: Deterministic identifier formatted as 'VOLEXEC-<UUIDv5>'.
    """
    clean_tool = str(tool).strip().lower()
    clean_plugin = str(plugin).strip().lower()
    args_part = "|args:" + ",".join(str(a).strip() for a in sanitized_args)
    hash_part = f"|in_hash:{input_evidence_hash.strip().lower()}" if input_evidence_hash and str(input_evidence_hash).strip() else ""
    canonical_key = f"tool:{clean_tool}|plugin:{clean_plugin}{args_part}{hash_part}"
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"VOLEXEC-{det_uuid}"


def _validate_memory_id(val: str) -> str:
    """Validate that a string conforms to the ForensiX MEM-<UUID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"evidence_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id.startswith("MEM-"):
        raise ValueError(f"evidence_id must start with 'MEM-', got '{val}'")
    suffix = clean_id[len("MEM-"):].strip()
    try:
        uuid.UUID(suffix)
    except (ValueError, AttributeError) as err:
        raise ValueError(f"evidence_id must contain a valid UUID suffix, got '{val}'") from err
    return clean_id


def detect_memory_format(file_path: Union[str, Path]) -> Optional[str]:
    """
    Detect the memory image format by inspecting file headers in read-only binary mode.

    Inspects only the leading header bytes without loading the file into memory.
    Requires reliable content-based signature validation. Does not infer format
    solely from filename extensions.

    Returns:
        Optional[str]: 'lime', 'crash_dump', 'elf_core', or None if unknown or unverified.
    """
    target = Path(file_path).resolve()
    if not target.is_file():
        return None

    try:
        with target.open("rb") as f:
            header = f.read(32)
    except (OSError, PermissionError):
        return None

    if len(header) < 4:
        return None

    if header.startswith(_LIME_MAGIC) or header.startswith(_LIME_MAGIC_BE):
        return "lime"
    if header.startswith(_WIN_CRASH_MAGIC_DUMP) or header.startswith(_WIN_CRASH_MAGIC) or header.startswith(_WIN_CRASH_MAGIC_64):
        return "crash_dump"
    if header.startswith(_ELF_CORE_MAGIC):
        # ELF header validation:
        # Requires at least 18 bytes to inspect EI_CLASS (byte 4), EI_DATA (byte 5),
        # and e_type (bytes 16..17, uint16 in determined byte order).
        if len(header) < 18:
            return None

        ei_class = header[4]
        if ei_class not in (_ELF_CLASS_32, _ELF_CLASS_64):
            return None

        ei_data = header[5]
        if ei_data == _ELF_DATA_LSB:
            byteorder = "little"
        elif ei_data == _ELF_DATA_MSB:
            byteorder = "big"
        else:
            return None

        e_type = int.from_bytes(header[16:18], byteorder=byteorder)
        if e_type == _ELF_ET_CORE:
            return "elf_core"

        # Not an ELF core (e.g. ET_EXEC = 2, ET_DYN = 3, ET_REL = 1, etc.)
        return None

    return None


@dataclass(frozen=True)
class MemoryEvidenceRecord:
    """
    Immutable representation of a registered forensic memory-image evidence file.

    Strict Boundaries:
    - Factual evidence metadata only.
    - Deeply immutable and deterministically serializable.
    - Does not embed credentials or sensitive memory image contents.
    - Identity is derived from stable forensic facts (SHA-256 and size).

    Attributes:
        evidence_id: Deterministic tracking identifier (MEM-<UUIDv5>).
        file_path: Canonical resolved absolute path string to the evidence file.
        size_bytes: Size of the evidence file in bytes.
        sha256: Hexadecimal SHA-256 cryptographic digest of the evidence file.
        format: Classified evidence format (e.g. 'raw', 'lime') if reliably determined, or None.
        schema_version: Model/schema specification version.
    """

    evidence_id: str
    file_path: str
    size_bytes: int
    sha256: str
    format: Optional[str] = None
    schema_version: str = MEMORY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validate all fields strictly on instantiation."""
        # 1. Validate evidence_id
        clean_id = _validate_memory_id(self.evidence_id)
        object.__setattr__(self, "evidence_id", clean_id)

        # 2. Validate file_path
        if not isinstance(self.file_path, (str, Path)):
            raise TypeError(f"file_path must be a str or Path, got {type(self.file_path).__name__}")
        str_path = str(self.file_path).strip()
        if not str_path:
            raise ValueError("file_path must not be empty")
        resolved = str(Path(str_path).resolve())
        object.__setattr__(self, "file_path", resolved)

        # 3. Validate size_bytes
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise TypeError(f"size_bytes must be an integer, got {type(self.size_bytes).__name__}")
        if self.size_bytes < 0:
            raise ValueError(f"size_bytes must be non-negative, got {self.size_bytes}")

        # 4. Validate sha256
        if not isinstance(self.sha256, str):
            raise TypeError(f"sha256 must be a string, got {type(self.sha256).__name__}")
        clean_sha = self.sha256.strip().lower()
        if len(clean_sha) != 64 or not all(c in "0123456789abcdef" for c in clean_sha):
            raise ValueError(f"sha256 must be a valid 64-character lowercase hex string, got '{self.sha256}'")
        object.__setattr__(self, "sha256", clean_sha)

        # 5. Validate format
        if self.format is not None:
            if not isinstance(self.format, str):
                raise TypeError(f"format must be a str or None, got {type(self.format).__name__}")
            clean_fmt = self.format.strip().lower()
            object.__setattr__(self, "format", clean_fmt or None)

        # 6. Validate schema_version
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be a non-empty string")
        object.__setattr__(self, "schema_version", self.schema_version.strip())

    def to_dict(self) -> Dict[str, Any]:
        """Convert the record to a standard JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "file_path": self.file_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "format": self.format,
            "schema_version": self.schema_version,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize the record to a deterministic JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryEvidenceRecord":
        """Deserialize a MemoryEvidenceRecord from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for MemoryEvidenceRecord deserialization, got {type(data).__name__}")

        required_keys = {"evidence_id", "file_path", "size_bytes", "sha256"}
        missing = required_keys - set(data.keys())
        if missing:
            raise KeyError(f"Missing required fields for MemoryEvidenceRecord: {sorted(missing)}")

        return cls(
            evidence_id=data["evidence_id"],
            file_path=data["file_path"],
            size_bytes=data["size_bytes"],
            sha256=data["sha256"],
            format=data.get("format"),
            schema_version=data.get("schema_version", MEMORY_SCHEMA_VERSION),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "MemoryEvidenceRecord":
        """Deserialize a MemoryEvidenceRecord from a JSON string."""
        if not isinstance(json_str, str):
            raise TypeError(f"Expected str for JSON deserialization, got {type(json_str).__name__}")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as err:
            raise ValueError(f"Failed to decode JSON string: {err}") from err
        return cls.from_dict(data)


def register_memory_evidence(
    file_path: Union[str, Path],
    format_hint: Optional[str] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> MemoryEvidenceRecord:
    """
    Register a forensic memory evidence image file.

    Follows ForensiX forensic integrity principles:
    - Never modifies, copies, or truncates the evidence file.
    - Streams file contents in fixed-size chunks strictly via binary read-only access
      without loading the entire image into RAM.
    - Calculates the SHA-256 hash using the project's established hasher utility.
    - Inspects file headers to classify image format if reliably detectable.
    - Derives a deterministic UUIDv5 identifier based strictly on immutable content facts.

    Args:
        file_path: Filesystem path to the memory evidence image (str or Path).
        format_hint: Optional manual format override (e.g. 'raw', 'lime').
        chunk_size: Streaming chunk size in bytes (default 65,536).

    Returns:
        MemoryEvidenceRecord: Deeply immutable, registered memory evidence representation.

    Raises:
        FileNotFoundError: If the evidence file does not exist.
        IsADirectoryError: If the path points to a directory.
        ValueError: If the path is not a regular file or is invalid.
        PermissionError: If read permissions are denied on the target file.
    """
    target = Path(file_path).resolve()

    if not target.exists():
        raise FileNotFoundError(f"Memory evidence file does not exist: {target}")
    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {target}")
    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: {target}")

    # Calculate cryptographic hashes using chunked streaming
    hashes = compute_hashes(target, chunk_size=chunk_size)
    sha256_digest = hashes["sha256"]

    # Retrieve file size
    try:
        file_size = target.stat().st_size
    except OSError as err:
        raise OSError(f"Failed to read file size for {target}: {err}") from err

    # Determine format classification
    detected_format = detect_memory_format(target)
    if format_hint and str(format_hint).strip():
        final_format = str(format_hint).strip().lower()
    else:
        final_format = detected_format

    # Generate deterministic UUIDv5 identifier
    evidence_id = compute_deterministic_memory_id(
        sha256=sha256_digest,
        file_size=file_size,
        evidence_format=final_format,
    )

    return MemoryEvidenceRecord(
        evidence_id=evidence_id,
        file_path=str(target),
        size_bytes=file_size,
        sha256=sha256_digest,
        format=final_format,
        schema_version=MEMORY_SCHEMA_VERSION,
    )


@dataclass(frozen=True)
class VolatilityExecutionError:
    """
    Structured, factual representation of a Volatility execution failure.

    Describes execution facts without speculating on threat intent or compromise.
    Guarantees no raw memory dumps or secrets are stored.
    """

    error_type: str
    error_message: str
    details: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate error fields and freeze details."""
        if not isinstance(self.error_type, str) or not self.error_type.strip():
            raise ValueError("error_type must be a non-empty string")
        if not isinstance(self.error_message, str):
            raise TypeError("error_message must be a string")
        if not isinstance(self.details, tuple):
            if isinstance(self.details, dict):
                frozen = tuple((str(k), v) for k, v in sorted(self.details.items()))
                object.__setattr__(self, "details", frozen)
            elif isinstance(self.details, (list, tuple)):
                object.__setattr__(self, "details", tuple(self.details))
            else:
                raise TypeError("details must be a tuple, list, or dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert error representation to a JSON-serializable dictionary."""
        return {
            "error_type": self.error_type,
            "error_message": self.error_message,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VolatilityExecutionError":
        """Deserialize a VolatilityExecutionError from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for VolatilityExecutionError, got {type(data).__name__}")
        details_raw = data.get("details", ())
        if isinstance(details_raw, dict):
            details_tuple = tuple((str(k), v) for k, v in sorted(details_raw.items()))
        elif isinstance(details_raw, (list, tuple)):
            details_tuple = tuple(details_raw)
        else:
            details_tuple = ()
        return cls(
            error_type=data.get("error_type", "UNKNOWN_ERROR"),
            error_message=data.get("error_message", ""),
            details=details_tuple,
        )


@dataclass(frozen=True)
class VolatilityExecutionRecord:
    """
    Immutable representation of Volatility execution provenance.

    Strict Boundaries:
    - Captures software execution facts only (tool, plugin, exit status, timing).
    - Never stores credentials, full environment variables, or raw memory dumps.
    - Clearly distinguishes attempted commands from successfully executed commands.
    - Does NOT claim a successful process exit proves forensic findings are correct.

    Attributes:
        record_id: Unique tracking identifier (VOLEXEC-<UUID>).
        tool: Tool name or binary identifier (e.g. 'volatility3').
        tool_version: Detected or reported version string, or None if undetermined.
        plugin: Name of the Volatility plugin invoked (e.g. 'linux.pslist').
        sanitized_args: Deeply frozen tuple of sanitized command-line arguments.
        started_at: ISO 8601 UTC timestamp when execution began, or None.
        completed_at: ISO 8601 UTC timestamp when execution completed, or None.
        duration_seconds: Elapsed execution duration in seconds, or None.
        exit_code: Process exit code (integer), or None if execution could not be spawned.
        status: Execution lifecycle status string from VolatilityExecutionStatus.
        error: Structured error information if execution or parsing failed, or None.
        input_evidence_hash: SHA-256 hash of the input memory evidence file, or None.
        output_hashes: Immutable tuple of (artifact_name, sha256_hash) pairs for outputs.
        executed: True if the subprocess was successfully spawned, False if execution was
                  attempted but failed prior to process invocation (e.g. missing executable).
    """

    record_id: str
    tool: str
    plugin: str
    sanitized_args: Tuple[str, ...]
    status: str
    executed: bool = False
    tool_version: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    exit_code: Optional[int] = None
    error: Optional[VolatilityExecutionError] = None
    input_evidence_hash: Optional[str] = None
    output_hashes: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Validate all fields strictly on instantiation."""
        # 1. Validate record_id
        if not isinstance(self.record_id, str) or not self.record_id.strip():
            raise ValueError("record_id must be a non-empty string")
        clean_id = self.record_id.strip()
        object.__setattr__(self, "record_id", clean_id)

        # 2. Validate tool
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("tool must be a non-empty string")
        object.__setattr__(self, "tool", self.tool.strip())

        # 3. Validate plugin
        if not isinstance(self.plugin, str) or not self.plugin.strip():
            raise ValueError("plugin must be a non-empty string")
        object.__setattr__(self, "plugin", self.plugin.strip())

        # 4. Freeze sanitized_args
        if isinstance(self.sanitized_args, (list, tuple)):
            clean_args = tuple(str(a) for a in self.sanitized_args)
            object.__setattr__(self, "sanitized_args", clean_args)
        else:
            raise TypeError("sanitized_args must be a tuple or list of strings")

        # 5. Validate status
        valid_statuses = {s.value for s in VolatilityExecutionStatus}
        status_val = self.status.value if isinstance(self.status, VolatilityExecutionStatus) else str(self.status)
        if status_val not in valid_statuses:
            raise ValueError(f"status must be one of {sorted(valid_statuses)}, got '{self.status}'")
        object.__setattr__(self, "status", status_val)

        # 6. Validate executed flag
        if not isinstance(self.executed, bool):
            raise TypeError(f"executed must be a bool, got {type(self.executed).__name__}")

        # 7. Validate exit_code
        if self.exit_code is not None:
            if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
                raise TypeError(f"exit_code must be an integer or None, got {type(self.exit_code).__name__}")

        # 8. Validate duration_seconds
        if self.duration_seconds is not None:
            if not isinstance(self.duration_seconds, (int, float)) or isinstance(self.duration_seconds, bool):
                raise TypeError(f"duration_seconds must be a float/int or None, got {type(self.duration_seconds).__name__}")
            if self.duration_seconds < 0:
                raise ValueError(f"duration_seconds must be non-negative, got {self.duration_seconds}")
            object.__setattr__(self, "duration_seconds", float(self.duration_seconds))

        # 9. Freeze output_hashes
        if isinstance(self.output_hashes, dict):
            frozen_hashes = tuple((str(k), str(v)) for k, v in sorted(self.output_hashes.items()))
            object.__setattr__(self, "output_hashes", frozen_hashes)
        elif isinstance(self.output_hashes, (list, tuple)):
            clean_hashes = []
            for item in self.output_hashes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_hashes.append((str(item[0]), str(item[1])))
                else:
                    raise TypeError("output_hashes items must be 2-tuples of (artifact_name, hash)")
            object.__setattr__(self, "output_hashes", tuple(clean_hashes))
        else:
            raise TypeError("output_hashes must be a sequence of (artifact_name, hash) pairs or a dict")

        # 10. Validate input_evidence_hash
        if self.input_evidence_hash is not None:
            if not isinstance(self.input_evidence_hash, str):
                raise TypeError("input_evidence_hash must be a string or None")
            clean_in_hash = self.input_evidence_hash.strip().lower()
            object.__setattr__(self, "input_evidence_hash", clean_in_hash or None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the record to a standard JSON-serializable dictionary."""
        return {
            "record_id": self.record_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "plugin": self.plugin,
            "sanitized_args": list(self.sanitized_args),
            "status": self.status,
            "executed": self.executed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "error": self.error.to_dict() if self.error else None,
            "input_evidence_hash": self.input_evidence_hash,
            "output_hashes": [list(item) for item in self.output_hashes],
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize the record to a deterministic JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VolatilityExecutionRecord":
        """Deserialize a VolatilityExecutionRecord from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for VolatilityExecutionRecord deserialization, got {type(data).__name__}")

        required = {"record_id", "tool", "plugin", "sanitized_args", "status"}
        missing = required - set(data.keys())
        if missing:
            raise KeyError(f"Missing required fields for VolatilityExecutionRecord: {sorted(missing)}")

        err_obj = None
        if data.get("error"):
            err_obj = VolatilityExecutionError.from_dict(data["error"])

        raw_out_hashes = data.get("output_hashes", ())
        if isinstance(raw_out_hashes, list):
            out_hashes_tuple = tuple((item[0], item[1]) for item in raw_out_hashes if len(item) == 2)
        elif isinstance(raw_out_hashes, tuple):
            out_hashes_tuple = raw_out_hashes
        else:
            out_hashes_tuple = ()

        return cls(
            record_id=data["record_id"],
            tool=data["tool"],
            tool_version=data.get("tool_version"),
            plugin=data["plugin"],
            sanitized_args=tuple(data["sanitized_args"]),
            status=data["status"],
            executed=bool(data.get("executed", False)),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            duration_seconds=data.get("duration_seconds"),
            exit_code=data.get("exit_code"),
            error=err_obj,
            input_evidence_hash=data.get("input_evidence_hash"),
            output_hashes=out_hashes_tuple,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "VolatilityExecutionRecord":
        """Deserialize a VolatilityExecutionRecord from a JSON string."""
        if not isinstance(json_str, str):
            raise TypeError(f"Expected str for JSON deserialization, got {type(json_str).__name__}")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as err:
            raise ValueError(f"Failed to decode JSON string: {err}") from err
        return cls.from_dict(data)


def compute_deterministic_process_id(
    evidence_id: str,
    plugin: str,
    pid: int,
    process_name: str,
    created_at: Optional[str] = None,
    offset: Optional[str] = None,
    content_digest: Optional[str] = None,
) -> str:
    """
    Generate a deterministic UUIDv5 tracking identifier for a memory process artifact.

    Stable Forensic Inputs:
    - evidence_id: Source memory evidence ID (e.g. 'MEM-<UUID>').
    - plugin: Source Volatility plugin name (e.g. 'linux.pslist').
    - pid: Process identifier integer.
    - process_name: Clean process image / comm name.
    - created_at: Normalized ISO timestamp string or None.
    - offset: Hexadecimal memory offset or None.
    - content_digest: Deterministic SHA-256 digest of row content (if disambiguating different rows).

    Returns:
        str: Deterministic identifier formatted as 'MEMPROC-<UUIDv5>'.
    """
    clean_eid = str(evidence_id).strip().lower()
    clean_plugin = str(plugin).strip().lower()
    clean_name = str(process_name).strip()
    clean_created = str(created_at).strip().lower() if created_at and str(created_at).strip() else "none"
    clean_offset = str(offset).strip().lower() if offset and str(offset).strip() else "none"
    clean_digest = f"|digest:{content_digest.strip().lower()}" if content_digest and str(content_digest).strip() else ""

    canonical_key = (
        f"evidence:{clean_eid}|plugin:{clean_plugin}|pid:{int(pid)}|"
        f"name:{clean_name}|created:{clean_created}|offset:{clean_offset}{clean_digest}"
    )
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMPROC-{det_uuid}"


@dataclass(frozen=True)
class MemoryProcessArtifact:
    """
    Immutable representation of an observed process artifact derived from memory evidence.

    Forensic Principles:
    - Captures factual process observations from memory without speculative threat scoring.
    - Maintains strict chain-of-custody referencing source memory evidence and execution record.
    - Retains exact source row indices for auditability without duplicating raw sensitive data.
    """

    artifact_id: str
    evidence_id: str
    pid: int
    process_name: str
    source_plugin: str
    ppid: Optional[int] = None
    created_at: Optional[str] = None
    exit_time: Optional[str] = None
    offset: Optional[str] = None
    execution_id: Optional[str] = None
    source_row_indices: Tuple[int, ...] = ()
    raw_attributes: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate process artifact fields and freeze nested structures."""
        # 1. Validate artifact_id
        if not isinstance(self.artifact_id, str) or not self.artifact_id.startswith("MEMPROC-"):
            raise ValueError(f"artifact_id must start with 'MEMPROC-', got '{self.artifact_id}'")
        suffix = self.artifact_id[len("MEMPROC-"):]
        try:
            uuid.UUID(suffix)
        except (ValueError, AttributeError) as err:
            raise ValueError(f"artifact_id must contain a valid UUID suffix, got '{self.artifact_id}'") from err

        # 2. Validate evidence_id
        _validate_memory_id(self.evidence_id)

        # 3. Validate pid
        if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid < 0:
            raise ValueError(f"pid must be a non-negative integer, got {self.pid}")

        # 4. Validate process_name
        if not isinstance(self.process_name, str) or not self.process_name.strip():
            raise ValueError("process_name must be a non-empty string")
        clean_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", self.process_name).strip()
        if not clean_name:
            raise ValueError("process_name cannot consist solely of control characters")
        object.__setattr__(self, "process_name", clean_name)

        # 5. Validate source_plugin
        if not isinstance(self.source_plugin, str) or not self.source_plugin.strip():
            raise ValueError("source_plugin must be a non-empty string")

        # 6. Validate ppid
        if self.ppid is not None:
            if not isinstance(self.ppid, int) or isinstance(self.ppid, bool) or self.ppid < 0:
                raise ValueError(f"ppid must be a non-negative integer or None, got {self.ppid}")

        # 7. Validate execution_id
        if self.execution_id is not None:
            if not isinstance(self.execution_id, str) or not self.execution_id.startswith("VOLEXEC-"):
                raise ValueError(f"execution_id must start with 'VOLEXEC-', got '{self.execution_id}'")

        # 8. Freeze source_row_indices
        if isinstance(self.source_row_indices, (list, tuple)):
            clean_indices = tuple(int(i) for i in self.source_row_indices if isinstance(i, int) and i >= 0)
            object.__setattr__(self, "source_row_indices", clean_indices)
        else:
            raise TypeError("source_row_indices must be a tuple or list of non-negative integers")

        # 9. Freeze raw_attributes
        if isinstance(self.raw_attributes, dict):
            frozen = tuple((str(k), v) for k, v in sorted(self.raw_attributes.items()))
            object.__setattr__(self, "raw_attributes", frozen)
        elif isinstance(self.raw_attributes, (list, tuple)):
            clean_attrs = []
            for item in self.raw_attributes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_attrs.append((str(item[0]), item[1]))
                else:
                    raise TypeError("raw_attributes items must be (key, value) pairs")
            object.__setattr__(self, "raw_attributes", tuple(clean_attrs))
        else:
            raise TypeError("raw_attributes must be a sequence of (key, value) pairs or a dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert process artifact to a JSON-serializable dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "evidence_id": self.evidence_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "process_name": self.process_name,
            "created_at": self.created_at,
            "exit_time": self.exit_time,
            "offset": self.offset,
            "source_plugin": self.source_plugin,
            "execution_id": self.execution_id,
            "source_row_indices": list(self.source_row_indices),
            "raw_attributes": dict(self.raw_attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize process artifact to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class ProcessRejectionRecord:
    """
    Immutable structured record of a rejected process output row during extraction.

    Guarantees no raw sensitive values are leaked in the diagnostic message.
    """

    row_index: int
    reason_code: str
    field_name: Optional[str]
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.row_index, int) or isinstance(self.row_index, bool) or self.row_index < 0:
            raise ValueError(f"row_index must be a non-negative integer, got {self.row_index}")
        if not isinstance(self.reason_code, str) or not self.reason_code.strip():
            raise ValueError("reason_code must be a non-empty string")
        if not isinstance(self.message, str):
            raise TypeError("message must be a string")

    def to_dict(self) -> Dict[str, Any]:
        """Convert rejection record to a JSON-serializable dictionary."""
        return {
            "row_index": self.row_index,
            "reason_code": self.reason_code,
            "field_name": self.field_name,
            "message": self.message,
        }


@dataclass(frozen=True)
class ProcessExtractionResult:
    """
    Immutable aggregate outcome of extracting process artifacts from a Volatility execution.
    """

    evidence_id: str
    execution_record: VolatilityExecutionRecord
    artifacts: Tuple[MemoryProcessArtifact, ...]
    rejections: Tuple[ProcessRejectionRecord, ...]
    duplicate_row_count: int = 0

    def __post_init__(self) -> None:
        _validate_memory_id(self.evidence_id)
        if not isinstance(self.execution_record, VolatilityExecutionRecord):
            raise TypeError(f"execution_record must be a VolatilityExecutionRecord, got {type(self.execution_record).__name__}")
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.rejections, tuple):
            object.__setattr__(self, "rejections", tuple(self.rejections))
        if not isinstance(self.duplicate_row_count, int) or self.duplicate_row_count < 0:
            raise ValueError(f"duplicate_row_count must be a non-negative integer, got {self.duplicate_row_count}")

    @property
    def total_rows(self) -> int:
        """Total number of rows inspected across valid, rejected, and duplicate rows."""
        return len(self.artifacts) + len(self.rejections) + self.duplicate_row_count

    @property
    def valid_count(self) -> int:
        """Number of successfully extracted valid process artifacts."""
        return len(self.artifacts)

    @property
    def rejected_count(self) -> int:
        """Number of rejected invalid process rows."""
        return len(self.rejections)

    def to_dict(self) -> Dict[str, Any]:
        """Convert extraction result to a JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "execution_record": self.execution_record.to_dict(),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "rejections": [r.to_dict() for r in self.rejections],
            "total_rows": self.total_rows,
            "valid_count": self.valid_count,
            "rejected_count": self.rejected_count,
            "duplicate_row_count": self.duplicate_row_count,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize extraction result to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def compute_deterministic_module_id(
    evidence_id: str,
    plugin: str,
    module_name: str,
    base_address: Optional[str] = None,
    size_bytes: Optional[int] = None,
    offset: Optional[str] = None,
    content_digest: Optional[str] = None,
) -> str:
    """
    Generate a deterministic UUIDv5 tracking identifier for a memory kernel module / driver artifact.

    Stable Forensic Inputs:
    - evidence_id: Source memory evidence ID (e.g. 'MEM-<UUID>').
    - plugin: Source Volatility plugin name (e.g. 'linux.lsmod', 'windows.modules').
    - module_name: Clean module or driver name (e.g. 'ext4', 'tcpip.sys').
    - base_address: Normalized lowercase hex base memory address or None.
    - size_bytes: Module size in bytes or None.
    - offset: Normalized lowercase hex kernel structure offset or None.
    - content_digest: Deterministic SHA-256 digest of row content (disambiguating distinct rows).

    Guarantees & Limitations:
    - Uses RFC 4122 UUIDv5 (SHA-1 over FORENSIX_V6_MEMORY_NAMESPACE + canonical key).
    - Guarantees deterministic repeatability across executions and environments.
    - Does not provide a mathematical proof of absolute collision-free injectivity across infinite inputs,
      though the probability of collision in 128-bit space (~2^-64 birthday bound) is negligible in forensics.

    Returns:
        str: Deterministic identifier formatted as 'MEMMOD-<UUIDv5>'.
    """
    clean_eid = str(evidence_id).strip().lower()
    clean_plugin = str(plugin).strip().lower()
    clean_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(module_name)).strip()
    clean_base = str(base_address).strip().lower() if base_address and str(base_address).strip() else "none"
    clean_size = str(size_bytes) if size_bytes is not None else "none"
    clean_offset = str(offset).strip().lower() if offset and str(offset).strip() else "none"
    clean_digest = f"|digest:{content_digest.strip().lower()}" if content_digest and str(content_digest).strip() else ""

    canonical_key = (
        f"evidence:{clean_eid}|plugin:{clean_plugin}|name:{clean_name}|"
        f"base:{clean_base}|size:{clean_size}|offset:{clean_offset}{clean_digest}"
    )
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMMOD-{det_uuid}"


@dataclass(frozen=True)
class MemoryModuleArtifact:
    """
    Immutable representation of an observed kernel module or driver artifact derived from memory evidence.

    Forensic Principles:
    - Captures factual kernel module / driver structures without speculative classification.
    - Maintains strict chain-of-custody referencing source memory evidence and execution record.
    - Retains exact source row indices for auditability without duplicating raw sensitive data.
    """

    artifact_id: str
    evidence_id: str
    module_name: str
    source_plugin: str
    base_address: Optional[str] = None
    size_bytes: Optional[int] = None
    offset: Optional[str] = None
    driver_path: Optional[str] = None
    execution_id: Optional[str] = None
    source_row_indices: Tuple[int, ...] = ()
    raw_attributes: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate module artifact fields and freeze nested structures."""
        # 1. Validate artifact_id
        if not isinstance(self.artifact_id, str) or not self.artifact_id.startswith("MEMMOD-"):
            raise ValueError(f"artifact_id must start with 'MEMMOD-', got '{self.artifact_id}'")
        suffix = self.artifact_id[len("MEMMOD-"):]
        try:
            uuid.UUID(suffix)
        except (ValueError, AttributeError) as err:
            raise ValueError(f"artifact_id must contain a valid UUID suffix, got '{self.artifact_id}'") from err

        # 2. Validate evidence_id
        _validate_memory_id(self.evidence_id)

        # 3. Validate module_name
        if not isinstance(self.module_name, str) or not self.module_name.strip():
            raise ValueError("module_name must be a non-empty string")
        clean_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", self.module_name).strip()
        if not clean_name:
            raise ValueError("module_name cannot consist solely of control characters")
        object.__setattr__(self, "module_name", clean_name)

        # 4. Validate source_plugin
        if not isinstance(self.source_plugin, str) or not self.source_plugin.strip():
            raise ValueError("source_plugin must be a non-empty string")

        # 5. Validate base_address
        if self.base_address is not None:
            if not isinstance(self.base_address, str) or not self.base_address.strip():
                raise ValueError(f"base_address must be a non-empty hex string or None, got '{self.base_address}'")
            clean_base = self.base_address.strip().lower()
            if not clean_base.startswith("0x"):
                raise ValueError(f"base_address must start with '0x', got '{self.base_address}'")
            try:
                int(clean_base, 16)
            except ValueError as err:
                raise ValueError(f"base_address must be a valid hexadecimal string, got '{self.base_address}'") from err
            object.__setattr__(self, "base_address", clean_base)

        # 6. Validate size_bytes
        if self.size_bytes is not None:
            if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool) or self.size_bytes < 0:
                raise ValueError(f"size_bytes must be a non-negative integer or None, got {self.size_bytes}")

        # 7. Validate offset
        if self.offset is not None:
            if not isinstance(self.offset, str) or not self.offset.strip():
                raise ValueError(f"offset must be a non-empty hex string or None, got '{self.offset}'")
            clean_off = self.offset.strip().lower()
            if not clean_off.startswith("0x"):
                raise ValueError(f"offset must start with '0x', got '{self.offset}'")
            try:
                int(clean_off, 16)
            except ValueError as err:
                raise ValueError(f"offset must be a valid hexadecimal string, got '{self.offset}'") from err
            object.__setattr__(self, "offset", clean_off)

        # 8. Validate driver_path
        if self.driver_path is not None:
            if not isinstance(self.driver_path, str):
                raise TypeError(f"driver_path must be a str or None, got {type(self.driver_path).__name__}")
            clean_path = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", self.driver_path).strip()
            object.__setattr__(self, "driver_path", clean_path or None)

        # 9. Validate execution_id
        if self.execution_id is not None:
            if not isinstance(self.execution_id, str) or not self.execution_id.startswith("VOLEXEC-"):
                raise ValueError(f"execution_id must start with 'VOLEXEC-', got '{self.execution_id}'")

        # 10. Freeze source_row_indices
        if isinstance(self.source_row_indices, (list, tuple)):
            clean_indices = tuple(int(i) for i in self.source_row_indices if isinstance(i, int) and i >= 0)
            object.__setattr__(self, "source_row_indices", clean_indices)
        else:
            raise TypeError("source_row_indices must be a tuple or list of non-negative integers")

        # 11. Freeze raw_attributes
        if isinstance(self.raw_attributes, dict):
            frozen = tuple((str(k), v) for k, v in sorted(self.raw_attributes.items()))
            object.__setattr__(self, "raw_attributes", frozen)
        elif isinstance(self.raw_attributes, (list, tuple)):
            clean_attrs = []
            for item in self.raw_attributes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_attrs.append((str(item[0]), item[1]))
                else:
                    raise TypeError("raw_attributes items must be (key, value) pairs")
            object.__setattr__(self, "raw_attributes", tuple(clean_attrs))
        else:
            raise TypeError("raw_attributes must be a sequence of (key, value) pairs or a dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert module artifact to a JSON-serializable dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "evidence_id": self.evidence_id,
            "module_name": self.module_name,
            "source_plugin": self.source_plugin,
            "base_address": self.base_address,
            "size_bytes": self.size_bytes,
            "offset": self.offset,
            "driver_path": self.driver_path,
            "execution_id": self.execution_id,
            "source_row_indices": list(self.source_row_indices),
            "raw_attributes": dict(self.raw_attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize module artifact to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class ModuleRejectionRecord:
    """
    Immutable structured record of a rejected kernel module / driver output row during extraction.

    Guarantees no raw sensitive values are leaked in the diagnostic message.
    """

    row_index: int
    reason_code: str
    field_name: Optional[str]
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.row_index, int) or isinstance(self.row_index, bool) or self.row_index < 0:
            raise ValueError(f"row_index must be a non-negative integer, got {self.row_index}")
        if not isinstance(self.reason_code, str) or not self.reason_code.strip():
            raise ValueError("reason_code must be a non-empty string")
        if not isinstance(self.message, str):
            raise TypeError("message must be a string")

    def to_dict(self) -> Dict[str, Any]:
        """Convert rejection record to a JSON-serializable dictionary."""
        return {
            "row_index": self.row_index,
            "reason_code": self.reason_code,
            "field_name": self.field_name,
            "message": self.message,
        }


@dataclass(frozen=True)
class ModuleExtractionResult:
    """
    Immutable aggregate outcome of extracting kernel module / driver artifacts from a Volatility execution.
    """

    evidence_id: str
    execution_record: VolatilityExecutionRecord
    artifacts: Tuple[MemoryModuleArtifact, ...]
    rejections: Tuple[ModuleRejectionRecord, ...]
    duplicate_row_count: int = 0

    def __post_init__(self) -> None:
        _validate_memory_id(self.evidence_id)
        if not isinstance(self.execution_record, VolatilityExecutionRecord):
            raise TypeError(f"execution_record must be a VolatilityExecutionRecord, got {type(self.execution_record).__name__}")
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.rejections, tuple):
            object.__setattr__(self, "rejections", tuple(self.rejections))
        if not isinstance(self.duplicate_row_count, int) or self.duplicate_row_count < 0:
            raise ValueError(f"duplicate_row_count must be a non-negative integer, got {self.duplicate_row_count}")

    @property
    def total_rows(self) -> int:
        """Total number of rows inspected across valid, rejected, and duplicate rows."""
        return len(self.artifacts) + len(self.rejections) + self.duplicate_row_count

    @property
    def valid_count(self) -> int:
        """Number of successfully extracted valid module artifacts."""
        return len(self.artifacts)

    @property
    def rejected_count(self) -> int:
        """Number of rejected invalid module rows."""
        return len(self.rejections)

    def to_dict(self) -> Dict[str, Any]:
        """Convert extraction result to a JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "execution_record": self.execution_record.to_dict(),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "rejections": [r.to_dict() for r in self.rejections],
            "total_rows": self.total_rows,
            "valid_count": self.valid_count,
            "rejected_count": self.rejected_count,
            "duplicate_row_count": self.duplicate_row_count,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize extraction result to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def compute_deterministic_network_id(
    evidence_id: str,
    plugin: str,
    protocol: str,
    local_address: Optional[str] = None,
    local_port: Optional[int] = None,
    remote_address: Optional[str] = None,
    remote_port: Optional[int] = None,
    state: Optional[str] = None,
    pid: Optional[int] = None,
    offset: Optional[str] = None,
    content_digest: Optional[str] = None,
) -> str:
    """
    Generate a deterministic UUIDv5 tracking identifier for a memory network socket / connection artifact.

    Stable Forensic Inputs:
    - evidence_id: Source memory evidence ID (e.g. 'MEM-<UUID>').
    - plugin: Source Volatility plugin name (e.g. 'linux.sockstat', 'windows.netstat').
    - protocol: Socket protocol (e.g. 'TCP', 'UDP').
    - local_address: Local binding IP address or endpoint string or None.
    - local_port: Local port integer (0..65535) or None.
    - remote_address: Remote foreign IP address or endpoint string or None.
    - remote_port: Remote port integer (0..65535) or None.
    - state: Connection state string (e.g. 'ESTABLISHED', 'LISTEN') or None.
    - pid: Bound process identifier integer or None.
    - offset: Hexadecimal memory offset of socket structure or None.
    - content_digest: Deterministic SHA-256 digest of row content (disambiguating distinct rows).

    Guarantees & Limitations:
    - Uses RFC 4122 UUIDv5 (SHA-1 over FORENSIX_V6_MEMORY_NAMESPACE + canonical key).
    - Guarantees deterministic repeatability across executions and environments.
    - Does not provide a mathematical proof of absolute collision-free injectivity across infinite inputs,
      though the probability of collision in 128-bit space (~2^-64 birthday bound) is negligible in forensics.

    Returns:
        str: Deterministic identifier formatted as 'MEMNET-<UUIDv5>'.
    """
    clean_eid = str(evidence_id).strip().lower()
    clean_plugin = str(plugin).strip().lower()
    clean_proto = str(protocol).strip().upper()
    clean_laddr = str(local_address).strip().lower() if local_address and str(local_address).strip() else "none"
    clean_lport = str(local_port) if local_port is not None else "none"
    clean_raddr = str(remote_address).strip().lower() if remote_address and str(remote_address).strip() else "none"
    clean_rport = str(remote_port) if remote_port is not None else "none"
    clean_state = str(state).strip().upper() if state and str(state).strip() else "none"
    clean_pid = str(pid) if pid is not None else "none"
    clean_offset = str(offset).strip().lower() if offset and str(offset).strip() else "none"
    clean_digest = f"|digest:{content_digest.strip().lower()}" if content_digest and str(content_digest).strip() else ""

    canonical_key = (
        f"evidence:{clean_eid}|plugin:{clean_plugin}|proto:{clean_proto}|"
        f"laddr:{clean_laddr}|lport:{clean_lport}|raddr:{clean_raddr}|rport:{clean_rport}|"
        f"state:{clean_state}|pid:{clean_pid}|offset:{clean_offset}{clean_digest}"
    )
    det_uuid = uuid.uuid5(FORENSIX_V6_MEMORY_NAMESPACE, canonical_key)
    return f"MEMNET-{det_uuid}"


@dataclass(frozen=True)
class MemoryNetworkArtifact:
    """
    Immutable representation of an observed network socket or connection artifact derived from memory evidence.

    Forensic Principles:
    - Captures factual network endpoint observations from memory without speculative threat scoring.
    - Does not claim that a socket proves malicious communication, successful transfer, or compromise.
    - Maintains strict chain-of-custody referencing source memory evidence and execution record.
    - Retains exact source row indices for auditability without duplicating raw sensitive data.
    """

    artifact_id: str
    evidence_id: str
    protocol: str
    source_plugin: str
    local_address: Optional[str] = None
    local_port: Optional[int] = None
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    state: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    offset: Optional[str] = None
    created_at: Optional[str] = None
    execution_id: Optional[str] = None
    source_row_indices: Tuple[int, ...] = ()
    raw_attributes: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Validate network artifact fields and freeze nested structures."""
        # 1. Validate artifact_id
        if not isinstance(self.artifact_id, str) or not self.artifact_id.startswith("MEMNET-"):
            raise ValueError(f"artifact_id must start with 'MEMNET-', got '{self.artifact_id}'")
        suffix = self.artifact_id[len("MEMNET-"):]
        try:
            uuid.UUID(suffix)
        except (ValueError, AttributeError) as err:
            raise ValueError(f"artifact_id must contain a valid UUID suffix, got '{self.artifact_id}'") from err

        # 2. Validate evidence_id
        _validate_memory_id(self.evidence_id)

        # 3. Validate protocol
        if not isinstance(self.protocol, str) or not self.protocol.strip():
            raise ValueError("protocol must be a non-empty string")
        object.__setattr__(self, "protocol", self.protocol.strip().upper())

        # 4. Validate source_plugin
        if not isinstance(self.source_plugin, str) or not self.source_plugin.strip():
            raise ValueError("source_plugin must be a non-empty string")

        # 5. Validate local_port
        if self.local_port is not None:
            if not isinstance(self.local_port, int) or isinstance(self.local_port, bool) or not (0 <= self.local_port <= 65535):
                raise ValueError(f"local_port must be an integer between 0 and 65535, got {self.local_port}")

        # 6. Validate remote_port
        if self.remote_port is not None:
            if not isinstance(self.remote_port, int) or isinstance(self.remote_port, bool) or not (0 <= self.remote_port <= 65535):
                raise ValueError(f"remote_port must be an integer between 0 and 65535, got {self.remote_port}")

        # 7. Validate pid
        if self.pid is not None:
            if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid < 0:
                raise ValueError(f"pid must be a non-negative integer or None, got {self.pid}")

        # 8. Clean process_name
        if self.process_name is not None:
            if not isinstance(self.process_name, str):
                raise TypeError(f"process_name must be a str or None, got {type(self.process_name).__name__}")
            clean_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", self.process_name).strip()
            object.__setattr__(self, "process_name", clean_name or None)

        # 9. Clean state
        if self.state is not None:
            if not isinstance(self.state, str):
                raise TypeError(f"state must be a str or None, got {type(self.state).__name__}")
            clean_st = self.state.strip().upper()
            object.__setattr__(self, "state", clean_st or None)

        # 10. Validate offset
        if self.offset is not None:
            if not isinstance(self.offset, str) or not self.offset.strip():
                raise ValueError(f"offset must be a non-empty hex string or None, got '{self.offset}'")
            clean_off = self.offset.strip().lower()
            if not clean_off.startswith("0x"):
                raise ValueError(f"offset must start with '0x', got '{self.offset}'")
            try:
                int(clean_off, 16)
            except ValueError as err:
                raise ValueError(f"offset must be a valid hexadecimal string, got '{self.offset}'") from err
            object.__setattr__(self, "offset", clean_off)

        # 11. Validate execution_id
        if self.execution_id is not None:
            if not isinstance(self.execution_id, str) or not self.execution_id.startswith("VOLEXEC-"):
                raise ValueError(f"execution_id must start with 'VOLEXEC-', got '{self.execution_id}'")

        # 12. Freeze source_row_indices
        if isinstance(self.source_row_indices, (list, tuple)):
            clean_indices = tuple(int(i) for i in self.source_row_indices if isinstance(i, int) and i >= 0)
            object.__setattr__(self, "source_row_indices", clean_indices)
        else:
            raise TypeError("source_row_indices must be a tuple or list of non-negative integers")

        # 13. Freeze raw_attributes
        if isinstance(self.raw_attributes, dict):
            frozen = tuple((str(k), v) for k, v in sorted(self.raw_attributes.items()))
            object.__setattr__(self, "raw_attributes", frozen)
        elif isinstance(self.raw_attributes, (list, tuple)):
            clean_attrs = []
            for item in self.raw_attributes:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    clean_attrs.append((str(item[0]), item[1]))
                else:
                    raise TypeError("raw_attributes items must be (key, value) pairs")
            object.__setattr__(self, "raw_attributes", tuple(clean_attrs))
        else:
            raise TypeError("raw_attributes must be a sequence of (key, value) pairs or a dict")

    def to_dict(self) -> Dict[str, Any]:
        """Convert network artifact to a JSON-serializable dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "evidence_id": self.evidence_id,
            "protocol": self.protocol,
            "source_plugin": self.source_plugin,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
            "process_name": self.process_name,
            "offset": self.offset,
            "created_at": self.created_at,
            "execution_id": self.execution_id,
            "source_row_indices": list(self.source_row_indices),
            "raw_attributes": dict(self.raw_attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize network artifact to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class NetworkRejectionRecord:
    """
    Immutable structured record of a rejected network socket output row during extraction.

    Guarantees no raw sensitive values are leaked in the diagnostic message.
    """

    row_index: int
    reason_code: str
    field_name: Optional[str]
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.row_index, int) or isinstance(self.row_index, bool) or self.row_index < 0:
            raise ValueError(f"row_index must be a non-negative integer, got {self.row_index}")
        if not isinstance(self.reason_code, str) or not self.reason_code.strip():
            raise ValueError("reason_code must be a non-empty string")
        if not isinstance(self.message, str):
            raise TypeError("message must be a string")

    def to_dict(self) -> Dict[str, Any]:
        """Convert rejection record to a JSON-serializable dictionary."""
        return {
            "row_index": self.row_index,
            "reason_code": self.reason_code,
            "field_name": self.field_name,
            "message": self.message,
        }


@dataclass(frozen=True)
class NetworkExtractionResult:
    """
    Immutable aggregate outcome of extracting network socket artifacts from a Volatility execution.
    """

    evidence_id: str
    execution_record: VolatilityExecutionRecord
    artifacts: Tuple[MemoryNetworkArtifact, ...]
    rejections: Tuple[NetworkRejectionRecord, ...]
    duplicate_row_count: int = 0

    def __post_init__(self) -> None:
        _validate_memory_id(self.evidence_id)
        if not isinstance(self.execution_record, VolatilityExecutionRecord):
            raise TypeError(f"execution_record must be a VolatilityExecutionRecord, got {type(self.execution_record).__name__}")
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.rejections, tuple):
            object.__setattr__(self, "rejections", tuple(self.rejections))
        if not isinstance(self.duplicate_row_count, int) or self.duplicate_row_count < 0:
            raise ValueError(f"duplicate_row_count must be a non-negative integer, got {self.duplicate_row_count}")

    @property
    def total_rows(self) -> int:
        """Total number of rows inspected across valid, rejected, and duplicate rows."""
        return len(self.artifacts) + len(self.rejections) + self.duplicate_row_count

    @property
    def valid_count(self) -> int:
        """Number of successfully extracted valid network artifacts."""
        return len(self.artifacts)

    @property
    def rejected_count(self) -> int:
        """Number of rejected invalid network rows."""
        return len(self.rejections)

    def to_dict(self) -> Dict[str, Any]:
        """Convert extraction result to a JSON-serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "execution_record": self.execution_record.to_dict(),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "rejections": [r.to_dict() for r in self.rejections],
            "total_rows": self.total_rows,
            "valid_count": self.valid_count,
            "rejected_count": self.rejected_count,
            "duplicate_row_count": self.duplicate_row_count,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize extraction result to a JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
