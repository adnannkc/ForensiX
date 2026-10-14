"""
Forensic Memory Kernel Module and Driver Extraction for ForensiX (V6.3).

Extracts, validates, and normalizes observed kernel module and driver artifacts from
Volatility 3 plugin execution results (such as linux.lsmod, windows.modules, and windows.driverscan)
into immutable, auditable MemoryModuleArtifact models.

Core Principles:
1. Fact-based observation: Normalizes observed kernel structures without speculative
   rootkit or malware scoring.
2. Complete audit traceability: Retains exact source row indices linking each artifact
   back to the raw Volatility execution output without duplicating sensitive payloads.
3. Plugin-aware field mapping: Distinguishes between module base memory addresses and
   driver object structure offsets based on plugin semantics (e.g. linux.lsmod vs windows.driverscan).
4. No silent data loss: Rejects conflicting alias values and tracks exact duplicate rows
   deterministically without dropping evidence.
5. Deep immutability: Converts all mappings and sequences to deeply frozen tuples.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from forensix.memory_models import (
    MemoryModuleArtifact,
    ModuleExtractionResult,
    ModuleRejectionRecord,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    _validate_memory_id,
    compute_deterministic_module_id,
)
from forensix.volatility_adapter import (
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityOutputLimitExceededError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
)

# Linux kernel module aliases (e.g. linux.lsmod, linux.check_modules)
# In linux.lsmod, 'Offset' represents the module's load base address in memory.
_LINUX_NAME_ALIASES: Tuple[str, ...] = ("Name", "Module Name", "COMM")
_LINUX_BASE_ALIASES: Tuple[str, ...] = ("Offset", "Base", "BaseAddress", "Module Base")
_LINUX_SIZE_ALIASES: Tuple[str, ...] = ("Size", "SizeOfImage", "ModuleSize")
_LINUX_OFFSET_ALIASES: Tuple[str, ...] = ("StructOffset", "ObjectOffset")
_LINUX_PATH_ALIASES: Tuple[str, ...] = ("Path", "FilePath")

# Windows driver scan aliases (windows.driverscan)
# In windows.driverscan, 'Offset' is the physical/virtual _DRIVER_OBJECT structure offset,
# while 'Start' or 'Base' represents the driver code load base address.
_WIN_DRIVERSCAN_NAME_ALIASES: Tuple[str, ...] = ("Driver Name", "DriverName", "Name", "BaseDllName")
_WIN_DRIVERSCAN_BASE_ALIASES: Tuple[str, ...] = ("Start", "Base", "BaseAddress", "Module Base")
_WIN_DRIVERSCAN_SIZE_ALIASES: Tuple[str, ...] = ("Size", "SizeOfImage", "ModuleSize")
_WIN_DRIVERSCAN_OFFSET_ALIASES: Tuple[str, ...] = ("Offset", "Offset(V)", "Offset(P)", "DriverOffset")
_WIN_DRIVERSCAN_PATH_ALIASES: Tuple[str, ...] = ("Path", "DriverPath", "FilePath")

# Windows general modules aliases (windows.modules)
# In windows.modules, 'Base' is the module base address, and 'Path' is the driver binary path.
_WIN_MODULES_NAME_ALIASES: Tuple[str, ...] = ("Name", "BaseDllName", "Driver Name", "Module Name", "COMM")
_WIN_MODULES_BASE_ALIASES: Tuple[str, ...] = ("Base", "BaseAddress", "Start", "Module Base")
_WIN_MODULES_SIZE_ALIASES: Tuple[str, ...] = ("Size", "SizeOfImage", "ModuleSize")
_WIN_MODULES_OFFSET_ALIASES: Tuple[str, ...] = ("Offset", "Offset(V)", "Offset(P)")
_WIN_MODULES_PATH_ALIASES: Tuple[str, ...] = ("Path", "FilePath", "DriverPath")


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
) -> Tuple[Optional[Any], Optional[ModuleRejectionRecord]]:
    """
    Extract a field value using recognized alias precedence while checking for conflicting values.

    Args:
        row: Source dictionary mapping for a kernel module / driver row.
        aliases: Ordered tuple of recognized column names.
        field_name: Canonical attribute name for reporting.
        row_index: 0-indexed position in source output.
        normalize_fn: Optional callable to normalize values prior to conflict comparison.

    Returns:
        Tuple of (extracted_value, rejection_record). If conflicting non-null values are
        detected across aliases, returns (None, ModuleRejectionRecord).
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
            return None, ModuleRejectionRecord(
                row_index=row_index,
                reason_code="CONFLICTING_ALIASES",
                field_name=field_name,
                message=f"Conflicting non-null values detected across alias keys '{first_alias}' and '{other_alias}'",
            )

    return first_val, None


def _normalize_module_name(val: Any) -> Optional[str]:
    """Parse and clean a kernel module or driver name."""
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip()
    return clean if clean else None


def _normalize_hex_address(raw_val: Any) -> Optional[str]:
    """Standardize a memory address (base or offset) into a lowercase hexadecimal string."""
    if raw_val is None or isinstance(raw_val, bool):
        return None
    if isinstance(raw_val, int):
        return hex(raw_val).lower() if raw_val >= 0 else None
    if isinstance(raw_val, str):
        clean = raw_val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null", "-"):
            return None
        if clean.startswith("0x") or clean.startswith("0X"):
            try:
                parsed = int(clean, 16)
                return hex(parsed).lower() if parsed >= 0 else None
            except ValueError:
                return None
        if clean.isdigit():
            try:
                parsed = int(clean)
                return hex(parsed).lower() if parsed >= 0 else None
            except ValueError:
                return None
    return None


def _normalize_size_bytes(raw_val: Any) -> Optional[int]:
    """Parse a module size value into a non-negative integer."""
    if raw_val is None or isinstance(raw_val, bool):
        return None
    if isinstance(raw_val, int):
        return raw_val if raw_val >= 0 else None
    if isinstance(raw_val, str):
        clean = raw_val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null", "-"):
            return None
        if clean.isdigit():
            return int(clean)
        if clean.startswith("0x") or clean.startswith("0X"):
            try:
                parsed = int(clean, 16)
                return parsed if parsed >= 0 else None
            except ValueError:
                return None
    return None


def _normalize_path_str(raw_val: Any) -> Optional[str]:
    """Parse and clean an optional driver binary file path."""
    if raw_val is None or isinstance(raw_val, bool):
        return None
    s = str(raw_val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-"):
        return None
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip()
    return clean if clean else None


def extract_module_artifacts(
    volatility_result: VolatilityResult,
    evidence_id: str,
) -> ModuleExtractionResult:
    """
    Extract, validate, and normalize kernel module and driver observations from a VolatilityResult.

    Failure Contract:
    - If the underlying execution failed (status != SUCCESS), raises the corresponding
      typed VolatilityError exception carrying the execution_record.
    - If the execution succeeded with 0 rows, returns a ModuleExtractionResult
      with valid_count=0 and total_rows=0 (cleanly distinguished from execution failure).
    - If rows contain invalid or missing required fields (module_name), records them in rejections.
    - If rows are exact duplicates, deduplicates them while tracking source_row_indices and
      duplicate_row_count.

    Args:
        volatility_result: Immutable VolatilityResult from VolatilityAdapter.run_plugin.
        evidence_id: Validated memory evidence tracking identifier (MEM-<UUID>).

    Returns:
        ModuleExtractionResult: Aggregate result with normalized artifacts and rejections.

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

    # 2. Select plugin-specific alias mappings
    plugin_lower = rec.plugin.strip().lower()
    if "driverscan" in plugin_lower:
        name_aliases = _WIN_DRIVERSCAN_NAME_ALIASES
        base_aliases = _WIN_DRIVERSCAN_BASE_ALIASES
        size_aliases = _WIN_DRIVERSCAN_SIZE_ALIASES
        offset_aliases = _WIN_DRIVERSCAN_OFFSET_ALIASES
        path_aliases = _WIN_DRIVERSCAN_PATH_ALIASES
    elif "linux" in plugin_lower or "lsmod" in plugin_lower:
        name_aliases = _LINUX_NAME_ALIASES
        base_aliases = _LINUX_BASE_ALIASES
        size_aliases = _LINUX_SIZE_ALIASES
        offset_aliases = _LINUX_OFFSET_ALIASES
        path_aliases = _LINUX_PATH_ALIASES
    else:
        # Default Windows modules mapping
        name_aliases = _WIN_MODULES_NAME_ALIASES
        base_aliases = _WIN_MODULES_BASE_ALIASES
        size_aliases = _WIN_MODULES_SIZE_ALIASES
        offset_aliases = _WIN_MODULES_OFFSET_ALIASES
        path_aliases = _WIN_MODULES_PATH_ALIASES

    known_keys = set(name_aliases + base_aliases + size_aliases + offset_aliases + path_aliases)

    # 3. Extract and Normalize Module Records
    rejections: List[ModuleRejectionRecord] = []
    extracted_artifacts: List[MemoryModuleArtifact] = []
    seen_exact_rows: Dict[Tuple[Any, ...], int] = {}
    duplicate_count = 0

    plugin_name = rec.plugin

    for row_idx, row in enumerate(volatility_result.data):
        if not isinstance(row, dict):
            rejections.append(
                ModuleRejectionRecord(
                    row_index=row_idx,
                    reason_code="MALFORMED_RECORD",
                    field_name=None,
                    message="Source row is not a dictionary mapping",
                )
            )
            continue

        # Extract Module Name with alias conflict detection
        raw_name_val, name_rej = _extract_aliased_field(
            row, name_aliases, "module_name", row_idx, normalize_fn=_normalize_module_name
        )
        if name_rej:
            rejections.append(name_rej)
            continue

        if not raw_name_val or not str(raw_name_val).strip():
            has_name_key = any(k in row and row[k] is not None for k in name_aliases)
            reason = "MISSING_MODULE_NAME"
            msg = "Module name contains only non-printable control characters" if has_name_key else "Row is missing required module/driver name"
            rejections.append(
                ModuleRejectionRecord(row_index=row_idx, reason_code=reason, field_name="module_name", message=msg)
            )
            continue

        clean_name = _normalize_module_name(raw_name_val)
        if not clean_name:
            rejections.append(
                ModuleRejectionRecord(
                    row_index=row_idx,
                    reason_code="MISSING_MODULE_NAME",
                    field_name="module_name",
                    message="Module name contains only non-printable control characters",
                )
            )
            continue

        # Extract optional Base Address with alias conflict detection
        base_key_present = any(
            k in row
            and row[k] is not None
            and not (isinstance(row[k], str) and row[k].strip().lower() in ("", "n/a", "none", "null", "-"))
            for k in base_aliases
        )
        raw_base_val, base_rej = _extract_aliased_field(
            row, base_aliases, "base_address", row_idx, normalize_fn=_normalize_hex_address
        )
        if base_rej:
            rejections.append(base_rej)
            continue

        base_str: Optional[str] = None
        if base_key_present:
            if raw_base_val is None:
                rejections.append(
                    ModuleRejectionRecord(
                        row_index=row_idx,
                        reason_code="INVALID_BASE_ADDRESS",
                        field_name="base_address",
                        message="Base address must be a valid non-negative hexadecimal or decimal number",
                    )
                )
                continue
            base_str = raw_base_val

        # Extract optional Size with alias conflict detection
        size_key_present = any(
            k in row
            and row[k] is not None
            and not (isinstance(row[k], str) and row[k].strip().lower() in ("", "n/a", "none", "null", "-"))
            for k in size_aliases
        )
        raw_size_val, size_rej = _extract_aliased_field(
            row, size_aliases, "size_bytes", row_idx, normalize_fn=_normalize_size_bytes
        )
        if size_rej:
            rejections.append(size_rej)
            continue

        size_val: Optional[int] = None
        if size_key_present:
            if raw_size_val is None:
                rejections.append(
                    ModuleRejectionRecord(
                        row_index=row_idx,
                        reason_code="INVALID_SIZE",
                        field_name="size_bytes",
                        message="Size must be a valid non-negative integer",
                    )
                )
                continue
            size_val = raw_size_val

        # Extract optional Offset with alias conflict detection
        offset_key_present = any(
            k in row
            and row[k] is not None
            and not (isinstance(row[k], str) and row[k].strip().lower() in ("", "n/a", "none", "null", "-"))
            for k in offset_aliases
        )
        raw_offset_val, offset_rej = _extract_aliased_field(
            row, offset_aliases, "offset", row_idx, normalize_fn=_normalize_hex_address
        )
        if offset_rej:
            rejections.append(offset_rej)
            continue

        offset_str: Optional[str] = None
        if offset_key_present:
            if raw_offset_val is None:
                rejections.append(
                    ModuleRejectionRecord(
                        row_index=row_idx,
                        reason_code="INVALID_OFFSET",
                        field_name="offset",
                        message="Offset must be a valid non-negative hexadecimal or decimal number",
                    )
                )
                continue
            offset_str = raw_offset_val

        # Extract optional Driver Path with alias conflict detection
        raw_path_val, path_rej = _extract_aliased_field(
            row, path_aliases, "driver_path", row_idx, normalize_fn=_normalize_path_str
        )
        if path_rej:
            rejections.append(path_rej)
            continue
        path_str = _normalize_path_str(raw_path_val) if raw_path_val is not None else None

        # Freeze secondary attributes without leaking secrets or mutability
        extra_attrs = tuple(
            (str(k), _freeze_value(v)) for k, v in sorted(row.items()) if k not in known_keys
        )

        # Check for exact duplicate rows (all normalized values + extra attributes match)
        exact_row_signature = (
            clean_name,
            base_str,
            size_val,
            offset_str,
            path_str,
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
        # Disambiguate distinct rows sharing name/base/size using content digest of exact distinct attributes
        content_bytes = repr(exact_row_signature).encode("utf-8")
        content_digest = hashlib.sha256(content_bytes).hexdigest()[:16]

        artifact_id = compute_deterministic_module_id(
            evidence_id=evidence_id,
            plugin=plugin_name,
            module_name=clean_name,
            base_address=base_str,
            size_bytes=size_val,
            offset=offset_str,
            content_digest=content_digest,
        )

        artifact = MemoryModuleArtifact(
            artifact_id=artifact_id,
            evidence_id=evidence_id,
            module_name=clean_name,
            source_plugin=plugin_name,
            base_address=base_str,
            size_bytes=size_val,
            offset=offset_str,
            driver_path=path_str,
            execution_id=rec.record_id,
            source_row_indices=(row_idx,),
            raw_attributes=extra_attrs,
        )

        seen_exact_rows[exact_row_signature] = len(extracted_artifacts)
        extracted_artifacts.append(artifact)

    # 4. Deterministic Sorting: by module name, base address, size, and first row index
    sorted_artifacts = tuple(
        sorted(
            extracted_artifacts,
            key=lambda a: (a.module_name, a.base_address or "", a.size_bytes or 0, a.source_row_indices[0]),
        )
    )

    return ModuleExtractionResult(
        evidence_id=evidence_id,
        execution_record=rec,
        artifacts=sorted_artifacts,
        rejections=tuple(rejections),
        duplicate_row_count=duplicate_count,
    )
