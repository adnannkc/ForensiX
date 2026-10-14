"""
Forensic Memory Network Socket and Connection Extraction for ForensiX (V6.4).

Extracts, validates, and normalizes observed network socket and connection artifacts from
Volatility 3 plugin execution results (such as linux.sockstat, windows.netstat, and windows.netscan)
into immutable, auditable MemoryNetworkArtifact models.

Core Principles:
1. Fact-based observation: Captures factual socket and connection endpoints without
   speculative threat scoring or compromise claims.
2. Complete audit traceability: Retains exact source row indices linking each artifact
   back to the raw Volatility execution output without duplicating sensitive payloads.
3. Plugin-aware field mapping: Explicitly normalizes plugin-specific columns across Linux
   and Windows socket/connection structures.
4. No silent data loss: Rejects conflicting alias values and tracks exact duplicate rows
   deterministically without dropping evidence.
5. Deep immutability: Converts all mappings and sequences to deeply frozen tuples.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from forensix.memory_models import (
    MemoryNetworkArtifact,
    NetworkExtractionResult,
    NetworkRejectionRecord,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    _validate_memory_id,
    compute_deterministic_network_id,
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

# Linux network socket aliases (e.g. linux.sockstat, linux.netstat, linux.netscan)
_LINUX_PROTO_ALIASES: Tuple[str, ...] = ("Proto", "Protocol", "Family")
_LINUX_LADDR_ALIASES: Tuple[str, ...] = ("Local Address", "LocalAddr", "Local IP", "LocalIP", "LAddr")
_LINUX_LPORT_ALIASES: Tuple[str, ...] = ("Local Port", "LocalPort", "LPort")
_LINUX_RADDR_ALIASES: Tuple[str, ...] = ("Foreign Address", "ForeignAddr", "Remote Address", "RemoteAddr", "Remote IP", "RemoteIP", "RAddr")
_LINUX_RPORT_ALIASES: Tuple[str, ...] = ("Foreign Port", "ForeignPort", "Remote Port", "RemotePort", "RPort")
_LINUX_STATE_ALIASES: Tuple[str, ...] = ("State", "Status")
_LINUX_PID_ALIASES: Tuple[str, ...] = ("PID", "Pid", "pid")
_LINUX_NAME_ALIASES: Tuple[str, ...] = ("COMM", "Process", "Process Name", "ImageFileName", "Name")
_LINUX_OFFSET_ALIASES: Tuple[str, ...] = ("Offset", "Offset(V)", "Offset(P)")
_LINUX_CREATED_ALIASES: Tuple[str, ...] = ("Created", "CreateTime", "CreationTime")

# Windows network connection aliases (windows.netstat, windows.netscan)
_WIN_PROTO_ALIASES: Tuple[str, ...] = ("Proto", "Protocol")
_WIN_LADDR_ALIASES: Tuple[str, ...] = ("LocalAddr", "Local Address", "Local IP", "LocalIP", "LAddr")
_WIN_LPORT_ALIASES: Tuple[str, ...] = ("LocalPort", "Local Port", "LPort")
_WIN_RADDR_ALIASES: Tuple[str, ...] = ("ForeignAddr", "Foreign Address", "RemoteAddr", "Remote Address", "Remote IP", "RAddr")
_WIN_RPORT_ALIASES: Tuple[str, ...] = ("ForeignPort", "Foreign Port", "RemotePort", "Remote Port", "RPort")
_WIN_STATE_ALIASES: Tuple[str, ...] = ("State", "Status")
_WIN_PID_ALIASES: Tuple[str, ...] = ("PID", "Pid", "OwnerPID", "pid")
_WIN_NAME_ALIASES: Tuple[str, ...] = ("Owner", "Process", "Process Name", "ImageFileName", "Name")
_WIN_OFFSET_ALIASES: Tuple[str, ...] = ("Offset", "Offset(V)", "Offset(P)")
_WIN_CREATED_ALIASES: Tuple[str, ...] = ("Created", "CreateTime", "CreationTime", "TimeCreated")


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
) -> Tuple[Optional[Any], Optional[NetworkRejectionRecord]]:
    """
    Extract a field value using recognized alias precedence while checking for conflicting values.

    Args:
        row: Source dictionary mapping for a socket row.
        aliases: Ordered tuple of recognized column names.
        field_name: Canonical attribute name for reporting.
        row_index: 0-indexed position in source output.
        normalize_fn: Optional callable to normalize values prior to conflict comparison.

    Returns:
        Tuple of (extracted_value, rejection_record). If conflicting non-null values are
        detected across aliases, returns (None, NetworkRejectionRecord).
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
            return None, NetworkRejectionRecord(
                row_index=row_index,
                reason_code="CONFLICTING_ALIASES",
                field_name=field_name,
                message=f"Conflicting non-null values detected across alias keys '{first_alias}' and '{other_alias}'",
            )

    return first_val, None


def _normalize_protocol_str(val: Any) -> Optional[str]:
    """Parse and normalize socket protocol string."""
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-"):
        return None
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip().upper()
    return clean if clean else None


def _normalize_port_value(val: Any) -> Optional[int]:
    """Parse a network port integer (0..65535). Returns -1 if invalid number/range."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if (0 <= val <= 65535) else -1
    if isinstance(val, str):
        clean = val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null", "-", "*"):
            return None
        if clean.isdigit():
            p = int(clean)
            return p if (0 <= p <= 65535) else -1
        try:
            p = int(clean, 0)
            return p if (0 <= p <= 65535) else -1
        except (ValueError, TypeError):
            return -1
    return -1


def _normalize_address_str(val: Any) -> Optional[str]:
    """Parse and clean an IP address or host string."""
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-", "*:*"):
        return None
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1].strip()
    return clean.lower() if clean else None


def _split_endpoint(addr_val: Any, port_val: Any) -> Tuple[Optional[str], Optional[int]]:
    """Parse IP address and port from separate or combined host:port representation."""
    extracted_port = _normalize_port_value(port_val) if port_val is not None else None
    addr_str: Optional[str] = None

    if addr_val is not None:
        raw_s = str(addr_val).strip()
        if raw_s.startswith("[") and "]:" in raw_s:
            host_part, port_part = raw_s[1:].split("]:", 1)
            addr_str = host_part
            if extracted_port is None:
                extracted_port = _normalize_port_value(port_part)
        elif raw_s.count(":") == 1 and not raw_s.startswith(":"):
            host_part, port_part = raw_s.split(":", 1)
            addr_str = host_part
            if extracted_port is None:
                extracted_port = _normalize_port_value(port_part)
        else:
            addr_str = raw_s

    norm_addr = _normalize_address_str(addr_str)
    return norm_addr, extracted_port


def _normalize_state_str(val: Any) -> Optional[str]:
    """Parse and normalize TCP/socket state string."""
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-", "*"):
        return None
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip().upper()
    return clean if clean else None


def _normalize_pid_value(val: Any) -> Optional[int]:
    """Parse and validate process ID."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        clean = val.strip()
        if clean.isdigit():
            p = int(clean)
            return p if p >= 0 else None
        try:
            p = int(clean, 0)
            return p if p >= 0 else None
        except (ValueError, TypeError):
            return None
    return None


def _normalize_process_name(val: Any) -> Optional[str]:
    """Parse process image or comm name."""
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-"):
        return None
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip()
    return clean if clean else None


def _normalize_hex_str(val: Any) -> Optional[str]:
    """Format memory offset as standardized lowercase hexadecimal."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int) and val >= 0:
        return hex(val).lower()
    if isinstance(val, str):
        clean = val.strip()
        if not clean or clean.lower() in ("n/a", "none", "null", "-"):
            return None
        if clean.startswith("0x") or clean.startswith("0X"):
            try:
                p = int(clean, 16)
                return hex(p).lower() if p >= 0 else None
            except ValueError:
                return None
        if clean.isdigit():
            p = int(clean)
            return hex(p).lower() if p >= 0 else None
    return None


def _normalize_timestamp_str(raw_val: Any) -> Optional[str]:
    """Deterministically normalize timestamp to ISO 8601 UTC string."""
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


def extract_network_artifacts(
    volatility_result: VolatilityResult,
    evidence_id: str,
) -> NetworkExtractionResult:
    """
    Extract, validate, and normalize network socket / connection observations from a VolatilityResult.

    Failure Contract:
    - If the underlying execution failed (status != SUCCESS), raises the corresponding
      typed VolatilityError exception carrying the execution_record.
    - If the execution succeeded with 0 rows, returns a NetworkExtractionResult
      with valid_count=0 and total_rows=0 (cleanly distinguished from execution failure).
    - If rows contain invalid or missing required fields (protocol), records them in rejections.
    - If rows are exact duplicates, deduplicates them while tracking source_row_indices and
      duplicate_row_count.

    Args:
        volatility_result: Immutable VolatilityResult from VolatilityAdapter.run_plugin.
        evidence_id: Validated memory evidence tracking identifier (MEM-<UUID>).

    Returns:
        NetworkExtractionResult: Aggregate result with normalized artifacts and rejections.

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
    if "linux" in plugin_lower or "sockstat" in plugin_lower:
        proto_aliases = _LINUX_PROTO_ALIASES
        laddr_aliases = _LINUX_LADDR_ALIASES
        lport_aliases = _LINUX_LPORT_ALIASES
        raddr_aliases = _LINUX_RADDR_ALIASES
        rport_aliases = _LINUX_RPORT_ALIASES
        state_aliases = _LINUX_STATE_ALIASES
        pid_aliases = _LINUX_PID_ALIASES
        name_aliases = _LINUX_NAME_ALIASES
        offset_aliases = _LINUX_OFFSET_ALIASES
        created_aliases = _LINUX_CREATED_ALIASES
    else:
        # Default Windows network aliases (windows.netstat, windows.netscan)
        proto_aliases = _WIN_PROTO_ALIASES
        laddr_aliases = _WIN_LADDR_ALIASES
        lport_aliases = _WIN_LPORT_ALIASES
        raddr_aliases = _WIN_RADDR_ALIASES
        rport_aliases = _WIN_RPORT_ALIASES
        state_aliases = _WIN_STATE_ALIASES
        pid_aliases = _WIN_PID_ALIASES
        name_aliases = _WIN_NAME_ALIASES
        offset_aliases = _WIN_OFFSET_ALIASES
        created_aliases = _WIN_CREATED_ALIASES

    known_keys = set(
        proto_aliases
        + laddr_aliases
        + lport_aliases
        + raddr_aliases
        + rport_aliases
        + state_aliases
        + pid_aliases
        + name_aliases
        + offset_aliases
        + created_aliases
    )

    # 3. Extract and Normalize Network Records
    rejections: List[NetworkRejectionRecord] = []
    extracted_artifacts: List[MemoryNetworkArtifact] = []
    seen_exact_rows: Dict[Tuple[Any, ...], int] = {}
    duplicate_count = 0

    plugin_name = rec.plugin

    for row_idx, row in enumerate(volatility_result.data):
        if not isinstance(row, dict):
            rejections.append(
                NetworkRejectionRecord(
                    row_index=row_idx,
                    reason_code="MALFORMED_RECORD",
                    field_name=None,
                    message="Source row is not a dictionary mapping",
                )
            )
            continue

        # Extract Protocol (required)
        raw_proto_val, proto_rej = _extract_aliased_field(
            row, proto_aliases, "protocol", row_idx, normalize_fn=_normalize_protocol_str
        )
        if proto_rej:
            rejections.append(proto_rej)
            continue

        if not raw_proto_val or not str(raw_proto_val).strip():
            rejections.append(
                NetworkRejectionRecord(
                    row_index=row_idx,
                    reason_code="MISSING_PROTOCOL",
                    field_name="protocol",
                    message="Row is missing required socket/connection protocol",
                )
            )
            continue

        proto_str = _normalize_protocol_str(raw_proto_val)
        if not proto_str:
            rejections.append(
                NetworkRejectionRecord(
                    row_index=row_idx,
                    reason_code="MISSING_PROTOCOL",
                    field_name="protocol",
                    message="Protocol is invalid or empty",
                )
            )
            continue

        # Extract Local Address & Port
        raw_laddr, laddr_rej = _extract_aliased_field(row, laddr_aliases, "local_address", row_idx)
        if laddr_rej:
            rejections.append(laddr_rej)
            continue

        raw_lport, lport_rej = _extract_aliased_field(row, lport_aliases, "local_port", row_idx)
        if lport_rej:
            rejections.append(lport_rej)
            continue

        laddr_str, lport_val = _split_endpoint(raw_laddr, raw_lport)
        if lport_val == -1:
            rejections.append(
                NetworkRejectionRecord(
                    row_index=row_idx,
                    reason_code="INVALID_PORT",
                    field_name="local_port",
                    message="Local port must be an integer between 0 and 65535",
                )
            )
            continue

        # Extract Remote Address & Port
        raw_raddr, raddr_rej = _extract_aliased_field(row, raddr_aliases, "remote_address", row_idx)
        if raddr_rej:
            rejections.append(raddr_rej)
            continue

        raw_rport, rport_rej = _extract_aliased_field(row, rport_aliases, "remote_port", row_idx)
        if rport_rej:
            rejections.append(rport_rej)
            continue

        raddr_str, rport_val = _split_endpoint(raw_raddr, raw_rport)
        if rport_val == -1:
            rejections.append(
                NetworkRejectionRecord(
                    row_index=row_idx,
                    reason_code="INVALID_PORT",
                    field_name="remote_port",
                    message="Remote port must be an integer between 0 and 65535",
                )
            )
            continue

        # Extract State
        raw_state, state_rej = _extract_aliased_field(
            row, state_aliases, "state", row_idx, normalize_fn=_normalize_state_str
        )
        if state_rej:
            rejections.append(state_rej)
            continue
        state_str = _normalize_state_str(raw_state)

        # Extract PID
        raw_pid, pid_rej = _extract_aliased_field(
            row, pid_aliases, "pid", row_idx, normalize_fn=_normalize_pid_value
        )
        if pid_rej:
            rejections.append(pid_rej)
            continue

        pid_present = any(
            k in row and row[k] is not None and not (isinstance(row[k], str) and row[k].strip().lower() in ("", "n/a", "none", "null", "-"))
            for k in pid_aliases
        )
        pid_val: Optional[int] = None
        if pid_present:
            if raw_pid is None:
                rejections.append(
                    NetworkRejectionRecord(
                        row_index=row_idx,
                        reason_code="INVALID_PID",
                        field_name="pid",
                        message="PID must be a non-negative integer",
                    )
                )
                continue
            pid_val = raw_pid

        # Extract Process Name
        raw_name, name_rej = _extract_aliased_field(
            row, name_aliases, "process_name", row_idx, normalize_fn=_normalize_process_name
        )
        if name_rej:
            rejections.append(name_rej)
            continue
        name_str = _normalize_process_name(raw_name)

        # Extract Offset
        raw_offset, offset_rej = _extract_aliased_field(
            row, offset_aliases, "offset", row_idx, normalize_fn=_normalize_hex_str
        )
        if offset_rej:
            rejections.append(offset_rej)
            continue

        offset_present = any(
            k in row and row[k] is not None and not (isinstance(row[k], str) and row[k].strip().lower() in ("", "n/a", "none", "null", "-"))
            for k in offset_aliases
        )
        offset_str: Optional[str] = None
        if offset_present:
            if raw_offset is None:
                rejections.append(
                    NetworkRejectionRecord(
                        row_index=row_idx,
                        reason_code="INVALID_OFFSET",
                        field_name="offset",
                        message="Offset must be a valid non-negative hexadecimal or decimal number",
                    )
                )
                continue
            offset_str = raw_offset

        # Extract Created Timestamp
        raw_created, created_rej = _extract_aliased_field(
            row, created_aliases, "created_at", row_idx, normalize_fn=_normalize_timestamp_str
        )
        if created_rej:
            rejections.append(created_rej)
            continue
        created_str = _normalize_timestamp_str(raw_created)

        # Freeze secondary attributes
        extra_attrs = tuple(
            (str(k), _freeze_value(v)) for k, v in sorted(row.items()) if k not in known_keys
        )

        # Exact duplicate row signature
        exact_row_signature = (
            proto_str,
            laddr_str,
            lport_val,
            raddr_str,
            rport_val,
            state_str,
            pid_val,
            name_str,
            offset_str,
            created_str,
            extra_attrs,
        )

        if exact_row_signature in seen_exact_rows:
            # Exact duplicate source row: append row index and increment count
            existing_idx = seen_exact_rows[exact_row_signature]
            existing_art = extracted_artifacts[existing_idx]
            updated_indices = existing_art.source_row_indices + (row_idx,)
            object.__setattr__(existing_art, "source_row_indices", updated_indices)
            duplicate_count += 1
            continue

        # Deterministic Identity Key
        content_bytes = repr(exact_row_signature).encode("utf-8")
        content_digest = hashlib.sha256(content_bytes).hexdigest()[:16]

        artifact_id = compute_deterministic_network_id(
            evidence_id=evidence_id,
            plugin=plugin_name,
            protocol=proto_str,
            local_address=laddr_str,
            local_port=lport_val,
            remote_address=raddr_str,
            remote_port=rport_val,
            state=state_str,
            pid=pid_val,
            offset=offset_str,
            content_digest=content_digest,
        )

        artifact = MemoryNetworkArtifact(
            artifact_id=artifact_id,
            evidence_id=evidence_id,
            protocol=proto_str,
            source_plugin=plugin_name,
            local_address=laddr_str,
            local_port=lport_val,
            remote_address=raddr_str,
            remote_port=rport_val,
            state=state_str,
            pid=pid_val,
            process_name=name_str,
            offset=offset_str,
            created_at=created_str,
            execution_id=rec.record_id,
            source_row_indices=(row_idx,),
            raw_attributes=extra_attrs,
        )

        seen_exact_rows[exact_row_signature] = len(extracted_artifacts)
        extracted_artifacts.append(artifact)

    # 4. Deterministic Sorting
    sorted_artifacts = tuple(
        sorted(
            extracted_artifacts,
            key=lambda a: (
                a.protocol,
                a.local_address or "",
                a.local_port or 0,
                a.remote_address or "",
                a.remote_port or 0,
                a.pid or 0,
                a.source_row_indices[0],
            ),
        )
    )

    return NetworkExtractionResult(
        evidence_id=evidence_id,
        execution_record=rec,
        artifacts=sorted_artifacts,
        rejections=tuple(rejections),
        duplicate_row_count=duplicate_count,
    )
