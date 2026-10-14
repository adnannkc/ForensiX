"""
Forensic Memory Process Extraction and Normalization for ForensiX (V6.2).

Extracts, validates, and normalizes observed process artifacts from Volatility 3
plugin execution results (such as linux.pslist and windows.pslist) into immutable,
auditable MemoryProcessArtifact models.

Core Principles:
1. Fact-based observation: Normalizes observed process structures without speculative
   threat scoring or compromise claims.
2. Complete audit traceability: Retains exact source row indices linking each artifact
   back to the raw Volatility execution output without duplicating sensitive payloads.
3. No silent data loss: Rejects conflicting alias values and tracks exact duplicate rows
   deterministically without dropping evidence.
4. Deep immutability: Converts all mappings and sequences to deeply frozen tuples.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from forensix.memory_models import (
    MemoryProcessArtifact,
    ProcessExtractionResult,
    ProcessRejectionRecord,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    _validate_memory_id,
    compute_deterministic_process_id,
)
from forensix.timestamp_normalizer import (
    format_iso_timestamp,
    normalize_timestamp,
)
from forensix.volatility_adapter import (
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityOutputLimitExceededError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
)

# Supported plugin field alias precedence tuples
_PID_ALIASES: Tuple[str, ...] = ("PID", "Pid", "pid")
_PPID_ALIASES: Tuple[str, ...] = ("PPID", "Ppid", "ppid")
_NAME_ALIASES: Tuple[str, ...] = ("ImageFileName", "COMM", "Name", "name")
_CREATE_TIME_ALIASES: Tuple[str, ...] = ("CreateTime", "CreationTime", "Start Time", "StartTime")
_EXIT_TIME_ALIASES: Tuple[str, ...] = ("ExitTime", "Exit Time")
_OFFSET_ALIASES: Tuple[str, ...] = ("Offset", "Offset(V)", "Offset(P)")


def _freeze_value(val: Any) -> Any:
    """Recursively freeze dictionaries, lists, and sets into deeply immutable tuples."""
    if isinstance(val, dict):
        return tuple((str(k), _freeze_value(v)) for k, v in sorted(val.items()))
    elif isinstance(val, (list, tuple, set)):
        return tuple(_freeze_value(x) for x in val)
    return val


def _extract_aliased_field(
    row: Dict[str, Any],
    aliases: Tuple[str, ...],
    field_name: str,
    row_index: int,
    normalize_fn: Optional[Callable[[Any], Any]] = None,
) -> Tuple[Optional[Any], Optional[ProcessRejectionRecord]]:
    """
    Extract a field value using recognized alias precedence while checking for conflicting values.

    Args:
        row: Source dictionary mapping for a process row.
        aliases: Ordered tuple of recognized column names.
        field_name: Canonical attribute name for reporting.
        row_index: 0-indexed position in source output.
        normalize_fn: Optional callable to normalize values prior to conflict comparison.

    Returns:
        Tuple of (extracted_value, rejection_record). If conflicting non-null values are
        detected across aliases, returns (None, ProcessRejectionRecord).
    """
    found_values: List[Tuple[str, Any]] = []
    for alias in aliases:
        if alias in row and row[alias] is not None:
            val = row[alias]
            # Skip empty strings for string aliases
            if isinstance(val, str) and not val.strip():
                continue
            norm_val = normalize_fn(val) if normalize_fn else val
            found_values.append((alias, norm_val))

    if not found_values:
        return None, None

    if len(found_values) == 1:
        return found_values[0][1], None

    # Check for conflicts among multiple present aliases
    first_alias, first_val = found_values[0]
    for other_alias, other_val in found_values[1:]:
        if other_val != first_val:
            return None, ProcessRejectionRecord(
                row_index=row_index,
                reason_code="CONFLICTING_ALIASES",
                field_name=field_name,
                message=f"Conflicting non-null values detected across alias keys '{first_alias}' and '{other_alias}'",
            )

    return first_val, None


def _normalize_pid_value(val: Any) -> Optional[int]:
    """Parse and validate a process ID value as a non-negative integer."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        clean = val.strip()
        if clean.isdigit():
            return int(clean)
        try:
            parsed = int(clean, 0)  # Support hex strings like '0x10'
            return parsed if parsed >= 0 else None
        except (ValueError, TypeError):
            return None
    return None


def _normalize_timestamp_str(raw_val: Any) -> Optional[str]:
    """Deterministically normalize a raw timestamp representation into an ISO 8601 string."""
    if raw_val is None:
        return None
    if isinstance(raw_val, datetime):
        return format_iso_timestamp(normalize_timestamp(raw_val))
    if isinstance(raw_val, str):
        clean = raw_val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null", "-", "0"):
            return None
        try:
            norm_dt = normalize_timestamp(clean)
            return format_iso_timestamp(norm_dt)
        except (ValueError, TypeError):
            return None
    return None


def _normalize_offset_str(raw_val: Any) -> Optional[str]:
    """Format a memory offset as a standardized lowercase hexadecimal string."""
    if raw_val is None:
        return None
    if isinstance(raw_val, int) and not isinstance(raw_val, bool):
        return hex(raw_val)
    if isinstance(raw_val, str):
        clean = raw_val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null"):
            return None
        if clean.startswith("0x") or clean.startswith("0X"):
            try:
                int(clean, 16)
                return clean.lower()
            except ValueError:
                return None
        if clean.isdigit():
            return hex(int(clean))
    return None


def extract_process_artifacts(
    volatility_result: VolatilityResult,
    evidence_id: str,
) -> ProcessExtractionResult:
    """
    Extract, validate, and normalize process observations from a completed VolatilityResult.

    Failure Contract:
    - If the underlying execution failed (status != SUCCESS), raises the corresponding
      typed VolatilityError exception carrying the execution_record.
    - If the execution succeeded with 0 process rows, returns a ProcessExtractionResult
      with valid_count=0 and total_rows=0 (cleanly distinguished from execution failure).
    - If rows contain invalid or missing required fields (PID, name), records them in rejections.
    - If rows are exact duplicates, deduplicates them while tracking source_row_indices and
      duplicate_row_count.

    Args:
        volatility_result: Immutable VolatilityResult from VolatilityAdapter.run_plugin.
        evidence_id: Validated memory evidence tracking identifier (MEM-<UUID>).

    Returns:
        ProcessExtractionResult: Aggregate result with normalized artifacts and rejections.

    Raises:
        VolatilityMissingSymbolsError: If execution failed due to missing symbol tables.
        VolatilityUnsupportedPluginError: If execution failed due to unknown/unsupported plugin.
        VolatilityTimeoutError: If execution timed out.
        VolatilityOutputLimitExceededError: If execution output limit was exceeded.
        VolatilityExecutionFailureError: If execution failed with a non-zero exit code.
        ValueError: If evidence_id is invalid.
    """
    _validate_memory_id(evidence_id)
    if not isinstance(volatility_result, VolatilityResult):
        raise TypeError(f"volatility_result must be a VolatilityResult, got {type(volatility_result).__name__}")

    rec = volatility_result.execution_record

    # 1. Enforce Failure-Handling Contract
    if rec.status != VolatilityExecutionStatus.SUCCESS.value:
        exit_code = rec.exit_code if rec.exit_code is not None else 1
        err_msg = rec.error.error_message if rec.error else f"Volatility execution failed with status {rec.status}"
        error_type = rec.error.error_type if rec.error else "EXECUTION_FAILURE"

        if error_type == "MISSING_SYMBOLS":
            raise VolatilityMissingSymbolsError(err_msg, exit_code=exit_code, execution_record=rec)
        elif error_type == "UNSUPPORTED_PLUGIN":
            raise VolatilityUnsupportedPluginError(err_msg, exit_code=exit_code, execution_record=rec)
        elif error_type == "TIMEOUT" or rec.status == VolatilityExecutionStatus.TIMEOUT.value:
            raise VolatilityTimeoutError(err_msg, execution_record=rec)
        elif error_type == "OUTPUT_LIMIT_EXCEEDED":
            raise VolatilityOutputLimitExceededError(err_msg, execution_record=rec)
        else:
            raise VolatilityExecutionFailureError(err_msg, exit_code=exit_code, execution_record=rec)

    # 2. Extract and Normalize Process Records
    rejections: List[ProcessRejectionRecord] = []
    # Dict mapping canonical content key to list of matching artifacts or artifact builder
    # Used for exact duplicate collapsing and disambiguating different rows
    extracted_artifacts: List[MemoryProcessArtifact] = []
    seen_exact_rows: Dict[Tuple[Any, ...], int] = {}  # canonical row tuple -> index in extracted_artifacts
    duplicate_count = 0

    plugin_name = rec.plugin

    for row_idx, row in enumerate(volatility_result.data):
        if not isinstance(row, dict):
            rejections.append(
                ProcessRejectionRecord(
                    row_index=row_idx,
                    reason_code="MALFORMED_RECORD",
                    field_name=None,
                    message="Source row is not a dictionary mapping",
                )
            )
            continue

        # Extract PID with alias conflict detection
        raw_pid_val, pid_rej = _extract_aliased_field(
            row, _PID_ALIASES, "pid", row_idx, normalize_fn=_normalize_pid_value
        )
        if pid_rej:
            rejections.append(pid_rej)
            continue

        if raw_pid_val is None:
            # Check if any PID key was present but invalid vs completely missing
            has_pid_key = any(k in row and row[k] is not None for k in _PID_ALIASES)
            reason = "INVALID_PID" if has_pid_key else "MISSING_PID"
            msg = "Row contains invalid or non-numeric PID" if has_pid_key else "Row is missing required PID field"
            rejections.append(
                ProcessRejectionRecord(row_index=row_idx, reason_code=reason, field_name="pid", message=msg)
            )
            continue

        pid_val = _normalize_pid_value(raw_pid_val)
        if pid_val is None:
            rejections.append(
                ProcessRejectionRecord(
                    row_index=row_idx,
                    reason_code="INVALID_PID",
                    field_name="pid",
                    message="PID must be a non-negative integer",
                )
            )
            continue

        # Extract Process Name with alias conflict detection
        raw_name_val, name_rej = _extract_aliased_field(
            row, _NAME_ALIASES, "process_name", row_idx, normalize_fn=lambda s: str(s).strip()
        )
        if name_rej:
            rejections.append(name_rej)
            continue

        if not raw_name_val or not str(raw_name_val).strip():
            rejections.append(
                ProcessRejectionRecord(
                    row_index=row_idx,
                    reason_code="MISSING_PROCESS_NAME",
                    field_name="process_name",
                    message="Row is missing required process image/comm name",
                )
            )
            continue

        clean_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(raw_name_val)).strip()
        if not clean_name:
            rejections.append(
                ProcessRejectionRecord(
                    row_index=row_idx,
                    reason_code="MISSING_PROCESS_NAME",
                    field_name="process_name",
                    message="Process name contains only non-printable control characters",
                )
            )
            continue

        # Extract optional PPID with alias conflict detection
        raw_ppid_val, ppid_rej = _extract_aliased_field(
            row, _PPID_ALIASES, "ppid", row_idx, normalize_fn=_normalize_pid_value
        )
        if ppid_rej:
            rejections.append(ppid_rej)
            continue
        ppid_val = _normalize_pid_value(raw_ppid_val) if raw_ppid_val is not None else None

        # Extract optional creation timestamp with alias conflict detection
        raw_create_val, create_rej = _extract_aliased_field(
            row, _CREATE_TIME_ALIASES, "created_at", row_idx, normalize_fn=_normalize_timestamp_str
        )
        if create_rej:
            rejections.append(create_rej)
            continue
        created_at_str = _normalize_timestamp_str(raw_create_val) if raw_create_val is not None else None

        # Extract optional exit timestamp with alias conflict detection
        raw_exit_val, exit_rej = _extract_aliased_field(
            row, _EXIT_TIME_ALIASES, "exit_time", row_idx, normalize_fn=_normalize_timestamp_str
        )
        if exit_rej:
            rejections.append(exit_rej)
            continue
        exit_time_str = _normalize_timestamp_str(raw_exit_val) if raw_exit_val is not None else None

        # Extract optional memory offset with alias conflict detection
        raw_offset_val, offset_rej = _extract_aliased_field(
            row, _OFFSET_ALIASES, "offset", row_idx, normalize_fn=_normalize_offset_str
        )
        if offset_rej:
            rejections.append(offset_rej)
            continue
        offset_str = _normalize_offset_str(raw_offset_val) if raw_offset_val is not None else None

        # Freeze secondary attributes without leaking sensitive command-lines or mutability
        known_keys = set(_PID_ALIASES + _PPID_ALIASES + _NAME_ALIASES + _CREATE_TIME_ALIASES + _EXIT_TIME_ALIASES + _OFFSET_ALIASES)
        extra_attrs = tuple(
            (str(k), _freeze_value(v)) for k, v in sorted(row.items()) if k not in known_keys
        )

        # Check for exact duplicate rows (all normalized values + extra attributes match)
        exact_row_signature = (
            pid_val,
            ppid_val,
            clean_name,
            created_at_str,
            exit_time_str,
            offset_str,
            extra_attrs,
        )

        if exact_row_signature in seen_exact_rows:
            # Exact duplicate source row: append row index to existing artifact and increment count
            existing_idx = seen_exact_rows[exact_row_signature]
            existing_art = extracted_artifacts[existing_idx]
            updated_indices = existing_art.source_row_indices + (row_idx,)
            object.__setattr__(existing_art, "source_row_indices", updated_indices)
            duplicate_count += 1
            continue

        # Deterministic Identity Key
        # If multiple distinct rows share the same (evidence_id, plugin, pid, name, created_at, offset),
        # disambiguate them using content digest of their exact distinct attributes
        content_bytes = repr(exact_row_signature).encode("utf-8")
        content_digest = hashlib.sha256(content_bytes).hexdigest()[:16]

        artifact_id = compute_deterministic_process_id(
            evidence_id=evidence_id,
            plugin=plugin_name,
            pid=pid_val,
            process_name=clean_name,
            created_at=created_at_str,
            offset=offset_str,
            content_digest=content_digest,
        )

        artifact = MemoryProcessArtifact(
            artifact_id=artifact_id,
            evidence_id=evidence_id,
            pid=pid_val,
            process_name=clean_name,
            source_plugin=plugin_name,
            ppid=ppid_val,
            created_at=created_at_str,
            exit_time=exit_time_str,
            offset=offset_str,
            execution_id=rec.record_id,
            source_row_indices=(row_idx,),
            raw_attributes=extra_attrs,
        )

        seen_exact_rows[exact_row_signature] = len(extracted_artifacts)
        extracted_artifacts.append(artifact)

    # 3. Deterministic Sorting: by PID, process name, creation timestamp, and first row index
    sorted_artifacts = tuple(
        sorted(
            extracted_artifacts,
            key=lambda a: (a.pid, a.process_name, a.created_at or "", a.source_row_indices[0]),
        )
    )

    return ProcessExtractionResult(
        evidence_id=evidence_id,
        execution_record=rec,
        artifacts=sorted_artifacts,
        rejections=tuple(rejections),
        duplicate_row_count=duplicate_count,
    )
