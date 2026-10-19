"""
Local Read-Only Dashboard Service for ForensiX (V7.2).

Provides a secure, deterministic, loopback-only HTTP service using Python standard-library
components to expose verified forensic reports ingested via forensix.report_reader.

Security and Architectural Principles:
1. Strict Loopback Binding:
   - Binds exclusively to loopback addresses ('127.0.0.1', 'localhost').
   - Rejects '0.0.0.0', '::1', or any public/external network interface.
2. Read-Only / Method Policy:
   - Strictly serves HTTP GET requests.
   - Rejects POST, PUT, DELETE, PATCH, OPTIONS, and HEAD with 405 Method Not Allowed.
   - Zero evidence acquisition, analysis execution, uploads, or report modifications.
3. No Arbitrary Filesystem Access in Handlers:
   - Handlers query an in-memory DashboardReportRegistry of approved, pre-loaded reports.
   - File reading is performed exclusively during startup/configuration via read_report().
   - Route parameters are strictly validated against alphanumeric/hyphen identifiers;
     path traversal attempts (e.g. '../', '%2e%2e', '%2f') are rejected immediately.
4. Privacy and Path Sanitization:
   - Local dashboard-host report-storage paths (e.g. source file locations on the analyst host)
     are strictly scrubbed and omitted from API responses; only filenames are exposed.
   - Exception details and Python stack traces are never leaked in HTTP error responses.
   - Target-System Forensic Provenance: Evidentiary fields such as metadata.evidence_root
     and path references inside raw forensic report details (raw_data) represent target-system
     evidence data intentionally retained from the source reports for investigation.
     They are preserved intact as authentic forensic facts, distinct from host storage paths.
5. Predictable and Bounded Operations:
   - Output lists are deterministically sorted by report identifier.
   - All responses use standard JSON with security headers (nosniff, no-store).
   - Ingested reports are deeply immutable; API handlers cannot mutate internal state.
6. Zero External Dependencies:
   - Built entirely using the Python standard library (http.server, urllib.parse, json).
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import threading
import types
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union
import urllib.parse

from forensix import __version__
from forensix.dashboard_ui import get_static_asset
from forensix.report_reader import (
    DEFAULT_MAX_REPORT_SIZE_BYTES,
    IngestedReport,
    ReportInvalidFileError,
    ReportNotFoundError,
    ReportParseError,
    ReportReaderError,
    ReportSchemaError,
    ReportSizeLimitError,
    ReportType,
    read_report,
)


DEFAULT_DASHBOARD_HOST: str = "127.0.0.1"
DEFAULT_DASHBOARD_PORT: int = 8080

# Permitted loopback host addresses (canonical IPv4 loopback)
ALLOWED_LOOPBACK_HOSTS: Tuple[str, ...] = ("127.0.0.1", "localhost")

# Permitted loopback hostnames for HTTP Host header validation
ALLOWED_DASHBOARD_HOSTNAMES: Tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "::1",
    "[::1]",
)

# Strict regex for report identifiers: alphanumeric, underscore, hyphen, dot; 1-128 chars
SAFE_REPORT_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

# V7.4 Pivot query limits
DEFAULT_PIVOT_MAX_RESULTS: int = 100
MAX_PIVOT_RESULTS_LIMIT: int = 1000


def is_valid_dashboard_host(
    host_header: Optional[str],
    bound_port: int,
    allow_omitted_port: bool = True,
) -> bool:
    """
    Validate that an incoming HTTP Host header is an approved loopback host
    and matches the server's actual bound port.

    Protects against DNS rebinding attacks while safely handling harmless
    formatting variations (case-insensitivity, whitespace, trailing dots, IPv6 brackets).

    Args:
        host_header: Raw Host header string from client.
        bound_port: Actual TCP port the server is bound to.
        allow_omitted_port: If True, permits loopback host without an explicit port.

    Returns:
        bool: True if host is valid loopback and matches bound port, False otherwise.
    """
    if not host_header or not isinstance(host_header, str):
        return False

    raw = host_header.strip()
    if not raw:
        return False

    # Check for IPv6 literal in brackets, e.g. [::1] or [::1]:8080
    if raw.startswith("["):
        closing = raw.find("]")
        if closing == -1:
            return False  # Malformed unclosed bracket
        host_part = raw[1:closing].strip().lower()
        remainder = raw[closing + 1 :].strip()
        if remainder:
            if not remainder.startswith(":"):
                return False  # Malformed characters after bracket
            port_str = remainder[1:].strip()
        else:
            port_str = None
    elif ":" in raw:
        parts = raw.split(":")
        if len(parts) != 2:
            return False  # Malformed (e.g. raw IPv6 without brackets or multiple colons)
        host_part = parts[0].strip().lower()
        port_str = parts[1].strip()
    else:
        host_part = raw.strip().lower()
        port_str = None

    # Strip optional trailing dot (RFC 7230 FQDN)
    host_part = host_part.rstrip(".")

    # Validate hostname / IP is loopback
    is_loopback = False
    if host_part in ("localhost", "127.0.0.1", "::1"):
        is_loopback = True
    else:
        try:
            ip = ipaddress.ip_address(host_part)
            if ip.is_loopback:
                is_loopback = True
        except ValueError:
            is_loopback = False

    if not is_loopback:
        return False

    # Validate port if present
    if port_str is not None:
        try:
            port_val = int(port_str)
        except ValueError:
            return False  # Malformed non-numeric port
        if port_val < 1 or port_val > 65535:
            return False  # Invalid port range
        if port_val != bound_port:
            return False  # Port mismatch
    else:
        # Port omitted: permitted if server is on port 80 or if allow_omitted_port is enabled
        if not allow_omitted_port and bound_port != 80:
            return False

    return True


def is_safe_report_id(report_id: Any) -> bool:
    """
    Validate that a report identifier contains only safe alphanumeric/hyphen characters
    and does not contain path traversal tokens.

    Args:
        report_id: Identifier candidate.

    Returns:
        bool: True if safe for routing and registry lookup, False otherwise.
    """
    if not isinstance(report_id, str):
        return False
    if report_id in (".", ".."):
        return False
    if "/" in report_id or "\\" in report_id or "\x00" in report_id:
        return False
    return bool(SAFE_REPORT_ID_REGEX.match(report_id))


# -----------------------------------------------------------------------------
# V7.4 In-Memory Pivot Index Models & Normalization
# -----------------------------------------------------------------------------


class PivotFieldType(str, Enum):
    """
    Allowlisted forensic pivot field types for cross-report drill-down.
    """

    CASE_ID = "case_id"
    SHA256 = "sha256"
    ARTIFACT_ID = "artifact_id"
    EVENT_ID = "event_id"
    RULE_ID = "rule_id"
    IP_ADDRESS = "ip_address"
    PID = "pid"


# Regex for strictly validating 64-character hexadecimal SHA-256 digests
_SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


def normalize_sha256(val: Any) -> Optional[str]:
    """
    Validate and normalize a candidate SHA-256 cryptographic digest.

    Requirements:
    - Must be a string of length 64 containing only hexadecimal characters (0-9, a-f, A-F).
    - Normalizes by returning the canonical lowercase representation.
    - Non-string, malformed, or wrong-length values safely return None.

    Args:
        val: Candidate hash value.

    Returns:
        Optional[str]: 64-character lowercase hexadecimal string, or None if invalid.
    """
    if not isinstance(val, str):
        return None
    cleaned = val.strip()
    if len(cleaned) != 64:
        return None
    if not _SHA256_HEX_REGEX.match(cleaned):
        return None
    return cleaned.lower()


def normalize_ip_address_pivot(val: Any) -> Optional[str]:
    """
    Validate and normalize an IP address for deterministic pivot lookup.

    Requirements:
    - Validates IPv4 and IPv6 addresses using the standard-library ipaddress module.
    - Returns the canonical string representation (e.g. '192.168.1.1' or '::1').
    - Non-string, empty, or invalid values safely return None without throwing.

    Args:
        val: Candidate IP address string.

    Returns:
        Optional[str]: Canonical IP string, or None if invalid.
    """
    if not isinstance(val, str):
        return None
    cleaned = val.strip()
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        # Check if candidate is an IPv4 address with leading zeros in octets (e.g. "192.168.001.001")
        parts = cleaned.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                canonical_v4 = ".".join(str(int(p)) for p in parts)
                addr = ipaddress.ip_address(canonical_v4)
                return str(addr)
            except ValueError:
                return None
        return None


def normalize_pid(val: Any) -> Optional[int]:
    """
    Validate and normalize an observed process identifier (PID).

    Requirements:
    - Must be a non-negative integer (booleans are strictly rejected).
    - Integer-convertible digit strings are accepted.
    - Negative integers or non-numeric types return None.
    - Does NOT claim global uniqueness or cross-host process identity.

    Args:
        val: Candidate PID value.

    Returns:
        Optional[int]: Non-negative integer PID, or None if invalid.
    """
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned.isdigit():
            try:
                pid_int = int(cleaned)
                return pid_int if pid_int >= 0 else None
            except ValueError:
                return None
    return None


def normalize_case_id(val: Any) -> Optional[str]:
    """
    Normalize case identifier string preserving exact case while ignoring empty/whitespace.

    Args:
        val: Candidate case identifier.

    Returns:
        Optional[str]: Stripped non-empty string, or None.
    """
    if not isinstance(val, str):
        return None
    cleaned = val.strip()
    return cleaned if cleaned else None


def _deep_freeze(val: Any) -> Any:
    """Recursively convert mutable mappings to MappingProxyType and sequences to tuples."""
    if isinstance(val, (dict, Mapping)):
        return types.MappingProxyType({k: _deep_freeze(v) for k, v in val.items()})
    if isinstance(val, (list, tuple, set)):
        return tuple(_deep_freeze(item) for item in val)
    return val


def _unfreeze_for_dict(val: Any) -> Any:
    """Recursively convert MappingProxyType to dict and tuples to lists for detached serialization."""
    if isinstance(val, (types.MappingProxyType, dict, Mapping)):
        return {k: _unfreeze_for_dict(v) for k, v in val.items()}
    if isinstance(val, (tuple, list, set)):
        return [_unfreeze_for_dict(v) for v in val]
    return val


IDENTIFIER_KIND_EVIDENCE_ID = "evidence_id"
IDENTIFIER_KIND_UNIFIED_ID = "unified_artifact_id"
IDENTIFIER_KIND_SOURCE_ID = "source_id"
IDENTIFIER_KIND_SOURCE_ARTIFACT_ID = "source_artifact_id"
IDENTIFIER_KIND_CORRELATION_ID = "correlation_id"
IDENTIFIER_KIND_REPORT_ID = "report_id"

ALLOWED_IDENTIFIER_KINDS: Tuple[str, ...] = (
    IDENTIFIER_KIND_EVIDENCE_ID,
    IDENTIFIER_KIND_UNIFIED_ID,
    IDENTIFIER_KIND_SOURCE_ID,
    IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
    IDENTIFIER_KIND_CORRELATION_ID,
    IDENTIFIER_KIND_REPORT_ID,
    "payload_artifact_id",
)


@dataclass(frozen=True)
class PivotReference:
    """
    Immutable representation of an indexed field occurrence in an ingested report.

    Attributes:
        report_id: Unique registry identifier of the containing IngestedReport.
        report_type: Schema classification of the containing report.
        field_type: Allowlisted PivotFieldType classification.
        field_path: Exact JSON property path where the value was observed (e.g. 'hashes.sha256').
        observed_value: Original value as observed in the report data (deeply immutable).
        normalized_value: Canonical string used for deterministic index lookup.
        identifier_kind: Specific identifier namespace classification (e.g. 'evidence_id'), or None.
        timestamp: ISO 8601 UTC timestamp string if explicitly present, or None.
        evidence_scope: Defensible scope identifier (e.g. evidence_id or evidence_root) or None.
        context: Deeply immutable mapping of factual contextual fields grounded in source data.
    """

    report_id: str
    report_type: ReportType
    field_type: PivotFieldType
    field_path: str
    observed_value: Any
    normalized_value: str
    identifier_kind: Optional[str] = None
    timestamp: Optional[str] = None
    evidence_scope: Optional[str] = None
    context: Mapping[str, Any] = types.MappingProxyType({})

    def __post_init__(self) -> None:
        """Enforce deep recursive immutability for all attributes."""
        object.__setattr__(self, "observed_value", _deep_freeze(self.observed_value))
        if isinstance(self.context, (dict, Mapping)):
            object.__setattr__(self, "context", _deep_freeze(self.context))
        else:
            object.__setattr__(self, "context", types.MappingProxyType({}))

    def to_dict(self) -> Dict[str, Any]:
        """Convert reference to a detached, JSON-serializable dictionary."""
        return {
            "report_id": self.report_id,
            "report_type": (
                self.report_type.value
                if hasattr(self.report_type, "value")
                else str(self.report_type)
            ),
            "field_type": (
                self.field_type.value
                if hasattr(self.field_type, "value")
                else str(self.field_type)
            ),
            "identifier_kind": self.identifier_kind,
            "field_path": self.field_path,
            "observed_value": _unfreeze_for_dict(self.observed_value),
            "normalized_value": self.normalized_value,
            "timestamp": self.timestamp,
            "evidence_scope": self.evidence_scope,
            "context": _unfreeze_for_dict(self.context),
        }


@dataclass(frozen=True)
class PivotQueryResult:
    """
    Immutable representation of a bounded pivot query result set.

    Attributes:
        field_type: Queried PivotFieldType.
        queried_value: Raw input value passed to the query (deeply immutable).
        normalized_query: Normalized string used for lookup (or None if normalization failed).
        scope: Queried evidence scope filter, or None.
        identifier_kind: Queried identifier namespace filter, or None.
        total_matches: Total number of matching index entries across all reports.
        returned_matches: Number of matching entries returned in matches (bounded by max_results).
        truncated: True if total_matches exceeded max_results.
        matches: Immutable tuple of matching PivotReference instances.
    """

    field_type: PivotFieldType
    queried_value: Any
    normalized_query: Optional[str] = None
    scope: Optional[str] = None
    identifier_kind: Optional[str] = None
    total_matches: int = 0
    returned_matches: int = 0
    truncated: bool = False
    matches: Tuple[PivotReference, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "queried_value", _deep_freeze(self.queried_value))
        if not isinstance(self.matches, tuple):
            object.__setattr__(self, "matches", tuple(self.matches))

    def to_dict(self) -> Dict[str, Any]:
        """Convert query result to a detached, JSON-serializable dictionary."""
        return {
            "field_type": (
                self.field_type.value
                if hasattr(self.field_type, "value")
                else str(self.field_type)
            ),
            "queried_value": _unfreeze_for_dict(self.queried_value),
            "normalized_query": self.normalized_query,
            "scope": self.scope,
            "identifier_kind": self.identifier_kind,
            "total_matches": self.total_matches,
            "returned_matches": self.returned_matches,
            "truncated": self.truncated,
            "matches": [m.to_dict() for m in self.matches],
        }


def _extract_timeline_events_pivots(
    events: Any,
    section_name: str,
    report: IngestedReport,
    report_id: str,
    evidence_scope: Optional[str],
    pivots: List[PivotReference],
) -> None:
    """Extract pivots from a sequence of timeline event dictionaries."""
    if not isinstance(events, (list, tuple)):
        return
    for i, ev in enumerate(events):
        if not isinstance(ev, (dict, Mapping)):
            continue
        attrs = ev.get("attributes") if isinstance(ev.get("attributes"), (dict, Mapping)) else {}
        ev_scope = attrs.get("evidence_id") if isinstance(attrs.get("evidence_id"), str) else None
        ev_scope = ev_scope or evidence_scope
        ev_ts = ev.get("timestamp") if isinstance(ev.get("timestamp"), str) else None

        # EVENT_ID
        eid = ev.get("event_id")
        if isinstance(eid, str) and eid.strip():
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.EVENT_ID,
                    field_path=f"{section_name}[{i}].event_id",
                    observed_value=eid,
                    normalized_value=eid.strip(),
                    timestamp=ev_ts,
                    evidence_scope=ev_scope,
                    context={
                        "category": str(ev.get("category")),
                        "event_type": str(ev.get("event_type")),
                        "description": str(ev.get("description", "")),
                    },
                )
            )

        # ARTIFACT_ID (source_artifact_id)
        said = ev.get("source_artifact_id")
        if isinstance(said, str) and said.strip():
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.ARTIFACT_ID,
                    field_path=f"{section_name}[{i}].source_artifact_id",
                    observed_value=said,
                    normalized_value=said.strip(),
                    identifier_kind=IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                    timestamp=ev_ts,
                    evidence_scope=ev_scope,
                    context={"id_type": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID},
                )
            )

        # EVENT_ID (source_event_id)
        seid = ev.get("source_event_id")
        if isinstance(seid, str) and seid.strip():
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.EVENT_ID,
                    field_path=f"{section_name}[{i}].source_event_id",
                    observed_value=seid,
                    normalized_value=seid.strip(),
                    timestamp=ev_ts,
                    evidence_scope=ev_scope,
                    context={"id_type": "source_event_id"},
                )
            )

        # IP addresses from attributes (strictly exclude non-IP generic keys like 'source' and 'host')
        for ip_key in ("source_ip", "src_ip", "destination_ip", "dst_ip", "remote_ip", "remote_address", "local_address", "ip_address", "ip"):
            ip_val = attrs.get(ip_key)
            norm_ip = normalize_ip_address_pivot(ip_val)
            if norm_ip:
                pivots.append(
                    PivotReference(
                        report_id=report_id,
                        report_type=report.report_type,
                        field_type=PivotFieldType.IP_ADDRESS,
                        field_path=f"{section_name}[{i}].attributes.{ip_key}",
                        observed_value=ip_val,
                        normalized_value=norm_ip,
                        timestamp=ev_ts,
                        evidence_scope=ev_scope,
                        context={"endpoint_key": ip_key, "category": str(ev.get("category")), "event_type": str(ev.get("event_type"))},
                    )
                )

        # PID from attributes
        pid_val = attrs.get("pid")
        norm_pid = normalize_pid(pid_val)
        if norm_pid is not None:
            proc_name = attrs.get("process_name") or attrs.get("comm") or ev.get("event_type")
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.PID,
                    field_path=f"{section_name}[{i}].attributes.pid",
                    observed_value=pid_val,
                    normalized_value=str(norm_pid),
                    timestamp=ev_ts,
                    evidence_scope=ev_scope,
                    context={"process_name": str(proc_name) if proc_name else None},
                )
            )

        # SHA-256 from attributes (validate length and hex before accepting generic 'hash' or 'file_hash')
        for sha_key in ("sha256", "file_sha256", "hash", "file_hash"):
            sha_val = attrs.get(sha_key)
            if sha_key in ("hash", "file_hash"):
                if not (isinstance(sha_val, str) and len(sha_val.strip()) == 64):
                    continue
            norm_sha = normalize_sha256(sha_val)
            if norm_sha:
                sp = attrs.get("path") or attrs.get("source_path") or ev.get("source_path")
                pivots.append(
                    PivotReference(
                        report_id=report_id,
                        report_type=report.report_type,
                        field_type=PivotFieldType.SHA256,
                        field_path=f"{section_name}[{i}].attributes.{sha_key}",
                        observed_value=sha_val,
                        normalized_value=norm_sha,
                        timestamp=ev_ts,
                        evidence_scope=ev_scope,
                        context={"source_path": str(sp) if sp else None},
                    )
                )


def _extract_detections_pivots(
    detections: Any,
    section_name: str,
    report: IngestedReport,
    report_id: str,
    evidence_scope: Optional[str],
    pivots: List[PivotReference],
) -> None:
    """Extract pivots from a sequence of detection dictionaries."""
    if not isinstance(detections, (list, tuple)):
        return
    for i, det in enumerate(detections):
        if not isinstance(det, (dict, Mapping)):
            continue
        ts = det.get("start_timestamp") if isinstance(det.get("start_timestamp"), str) else None

        # RULE_ID
        rule_id = det.get("rule_id")
        if isinstance(rule_id, str) and rule_id.strip():
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.RULE_ID,
                    field_path=f"{section_name}[{i}].rule_id",
                    observed_value=rule_id,
                    normalized_value=rule_id.strip(),
                    timestamp=ts,
                    evidence_scope=evidence_scope,
                    context={
                        "rule_name": str(det.get("rule_name", "")),
                        "matched": bool(det.get("matched")),
                    },
                )
            )

        # EVENT_ID (matched_event_ids)
        matched_events = det.get("matched_event_ids")
        if isinstance(matched_events, (list, tuple)):
            for k, eid in enumerate(matched_events):
                if isinstance(eid, str) and eid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"{section_name}[{i}].matched_event_ids[{k}]",
                            observed_value=eid,
                            normalized_value=eid.strip(),
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"rule_id": str(rule_id) if rule_id else None},
                        )
                    )

        # ARTIFACT_ID (matched_source_artifact_ids, matched_correlation_ids)
        matched_artifacts = det.get("matched_source_artifact_ids")
        if isinstance(matched_artifacts, (list, tuple)):
            for k, aid in enumerate(matched_artifacts):
                if isinstance(aid, str) and aid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"{section_name}[{i}].matched_source_artifact_ids[{k}]",
                            observed_value=aid,
                            normalized_value=aid.strip(),
                            identifier_kind=IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"rule_id": str(rule_id) if rule_id else None, "id_type": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID},
                        )
                    )

        matched_corrs = det.get("matched_correlation_ids")
        if isinstance(matched_corrs, (list, tuple)):
            for k, cid in enumerate(matched_corrs):
                if isinstance(cid, str) and cid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"{section_name}[{i}].matched_correlation_ids[{k}]",
                            observed_value=cid,
                            normalized_value=cid.strip(),
                            identifier_kind=IDENTIFIER_KIND_CORRELATION_ID,
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"rule_id": str(rule_id) if rule_id else None, "id_type": IDENTIFIER_KIND_CORRELATION_ID},
                        )
                    )

        # EVENT_ID (matched_source_event_ids)
        matched_source_events = det.get("matched_source_event_ids")
        if isinstance(matched_source_events, (list, tuple)):
            for k, seid in enumerate(matched_source_events):
                if isinstance(seid, str) and seid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"{section_name}[{i}].matched_source_event_ids[{k}]",
                            observed_value=seid,
                            normalized_value=seid.strip(),
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"rule_id": str(rule_id) if rule_id else None, "id_type": "matched_source_event_ids"},
                        )
                    )


def _extract_correlations_pivots(
    correlations: Any,
    section_name: str,
    report: IngestedReport,
    report_id: str,
    evidence_scope: Optional[str],
    pivots: List[PivotReference],
) -> None:
    """Extract pivots from a sequence of correlation dictionaries."""
    if not isinstance(correlations, (list, tuple)):
        return
    for i, corr in enumerate(correlations):
        if not isinstance(corr, (dict, Mapping)):
            continue
        ts = corr.get("start_timestamp") if isinstance(corr.get("start_timestamp"), str) else None
        cid = corr.get("correlation_id")

        # ARTIFACT_ID (correlation_id itself)
        if isinstance(cid, str) and cid.strip():
            pivots.append(
                PivotReference(
                    report_id=report_id,
                    report_type=report.report_type,
                    field_type=PivotFieldType.ARTIFACT_ID,
                    field_path=f"{section_name}[{i}].correlation_id",
                    observed_value=cid,
                    normalized_value=cid.strip(),
                    identifier_kind=IDENTIFIER_KIND_CORRELATION_ID,
                    timestamp=ts,
                    evidence_scope=evidence_scope,
                    context={
                        "id_type": IDENTIFIER_KIND_CORRELATION_ID,
                        "relationship_type": str(corr.get("relationship_type", "")),
                    },
                )
            )

        # EVENT_ID (event_ids)
        event_ids = corr.get("event_ids")
        if isinstance(event_ids, (list, tuple)):
            for k, eid in enumerate(event_ids):
                if isinstance(eid, str) and eid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"{section_name}[{i}].event_ids[{k}]",
                            observed_value=eid,
                            normalized_value=eid.strip(),
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={
                                "correlation_id": str(cid) if cid else None,
                                "relationship_type": str(corr.get("relationship_type", "")),
                            },
                        )
                    )

        # ARTIFACT_ID (source_artifact_ids)
        source_artifacts = corr.get("source_artifact_ids")
        if isinstance(source_artifacts, (list, tuple)):
            for k, aid in enumerate(source_artifacts):
                if isinstance(aid, str) and aid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"{section_name}[{i}].source_artifact_ids[{k}]",
                            observed_value=aid,
                            normalized_value=aid.strip(),
                            identifier_kind=IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"correlation_id": str(cid) if cid else None, "id_type": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID},
                        )
                    )

        # EVENT_ID (source_event_ids)
        source_events = corr.get("source_event_ids")
        if isinstance(source_events, (list, tuple)):
            for k, seid in enumerate(source_events):
                if isinstance(seid, str) and seid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"{section_name}[{i}].source_event_ids[{k}]",
                            observed_value=seid,
                            normalized_value=seid.strip(),
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={"correlation_id": str(cid) if cid else None, "id_type": "source_event_ids"},
                        )
                    )

        # RULE_ID (rule_ids)
        rule_ids = corr.get("rule_ids")
        if isinstance(rule_ids, (list, tuple)):
            for k, rid in enumerate(rule_ids):
                if isinstance(rid, str) and rid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.RULE_ID,
                            field_path=f"{section_name}[{i}].rule_ids[{k}]",
                            observed_value=rid,
                            normalized_value=rid.strip(),
                            timestamp=ts,
                            evidence_scope=evidence_scope,
                            context={
                                "correlation_id": str(cid) if cid else None,
                                "relationship_type": str(corr.get("relationship_type", "")),
                            },
                        )
                    )


def extract_report_pivots(
    report: IngestedReport,
    report_id: str,
) -> List[PivotReference]:
    """
    Extract grounded, non-speculative pivot references from an IngestedReport.

    Follows strict schema-aware extraction per ReportType without modifying raw data.
    Safely skips missing, null, or malformed optional fields.
    """
    pivots: List[PivotReference] = []
    raw_data = report.raw_data
    if not isinstance(raw_data, (dict, Mapping)):
        return pivots

    # Determine default evidence scope from metadata and evidence attributes
    meta = report.metadata
    meta_dict = raw_data.get("metadata") if isinstance(raw_data.get("metadata"), (dict, Mapping)) else {}
    ev_dict = raw_data.get("evidence") if isinstance(raw_data.get("evidence"), (dict, Mapping)) else {}

    evidence_scope = (
        meta_dict.get("evidence_root")
        or meta.evidence_root
        or meta_dict.get("report_id")
        or meta.report_id
        or meta_dict.get("triage_id")
        or meta.triage_id
        or ev_dict.get("original_path")
        or ev_dict.get("evidence_id")
    )

    # 1. Universal: CASE_ID
    case_val = None
    case_path = None
    if "case_id" in meta_dict:
        case_val = meta_dict["case_id"]
        case_path = "metadata.case_id"
    elif "case_id" in raw_data:
        case_val = raw_data["case_id"]
        case_path = "case_id"
    elif meta.case_id:
        case_val = meta.case_id
        case_path = "metadata.case_id"

    norm_case = normalize_case_id(case_val)
    if norm_case:
        pivots.append(
            PivotReference(
                report_id=report_id,
                report_type=report.report_type,
                field_type=PivotFieldType.CASE_ID,
                field_path=case_path or "metadata.case_id",
                observed_value=case_val,
                normalized_value=norm_case,
                timestamp=meta.created_at,
                evidence_scope=evidence_scope,
                context={"case_name": meta.case_name} if meta.case_name else {},
            )
        )

    # 2. Schema-specific extraction
    if report.report_type == ReportType.EVIDENCE_ANALYSIS:
        # evidence.evidence_id
        ev = raw_data.get("evidence")
        if isinstance(ev, (dict, Mapping)):
            ev_id = ev.get("evidence_id")
            if isinstance(ev_id, str) and ev_id.strip():
                pivots.append(
                    PivotReference(
                        report_id=report_id,
                        report_type=report.report_type,
                        field_type=PivotFieldType.ARTIFACT_ID,
                        field_path="evidence.evidence_id",
                        observed_value=ev_id,
                        normalized_value=ev_id.strip(),
                        identifier_kind=IDENTIFIER_KIND_EVIDENCE_ID,
                        timestamp=ev.get("registered_at"),
                        evidence_scope=ev.get("original_path") or evidence_scope,
                        context={"id_type": IDENTIFIER_KIND_EVIDENCE_ID, "original_path": ev.get("original_path")},
                    )
                )
        # hashes.sha256
        h = raw_data.get("hashes")
        if isinstance(h, (dict, Mapping)):
            sha_val = h.get("sha256")
            norm_sha = normalize_sha256(sha_val)
            if norm_sha:
                fl = raw_data.get("file") if isinstance(raw_data.get("file"), (dict, Mapping)) else {}
                pivots.append(
                    PivotReference(
                        report_id=report_id,
                        report_type=report.report_type,
                        field_type=PivotFieldType.SHA256,
                        field_path="hashes.sha256",
                        observed_value=sha_val,
                        normalized_value=norm_sha,
                        timestamp=raw_data.get("metadata", {}).get("modified") if isinstance(raw_data.get("metadata"), (dict, Mapping)) else None,
                        evidence_scope=evidence_scope,
                        context={"filename": fl.get("filename"), "size_bytes": fl.get("size")},
                    )
                )

    elif report.report_type == ReportType.HOST_TRIAGE:
        # metadata.report_id
        meta_dict = raw_data.get("metadata")
        if isinstance(meta_dict, (dict, Mapping)):
            rep_id_val = meta_dict.get("report_id")
            if isinstance(rep_id_val, str) and rep_id_val.strip():
                pivots.append(
                    PivotReference(
                        report_id=report_id,
                        report_type=report.report_type,
                        field_type=PivotFieldType.ARTIFACT_ID,
                        field_path="metadata.report_id",
                        observed_value=rep_id_val,
                        normalized_value=rep_id_val.strip(),
                        identifier_kind=IDENTIFIER_KIND_REPORT_ID,
                        timestamp=meta_dict.get("created_at"),
                        evidence_scope=evidence_scope,
                        context={"id_type": IDENTIFIER_KIND_REPORT_ID},
                    )
                )

        # artifacts
        arts = raw_data.get("artifacts")
        if isinstance(arts, (list, tuple)):
            for i, art in enumerate(arts):
                if not isinstance(art, (dict, Mapping)):
                    continue
                art_scope = art.get("evidence_id") if isinstance(art.get("evidence_id"), str) else None
                art_scope = art_scope or evidence_scope

                # unified_id
                uid = art.get("unified_id")
                if isinstance(uid, str) and uid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"artifacts[{i}].unified_id",
                            observed_value=uid,
                            normalized_value=uid.strip(),
                            identifier_kind=IDENTIFIER_KIND_UNIFIED_ID,
                            timestamp=None,
                            evidence_scope=art_scope,
                            context={"id_type": IDENTIFIER_KIND_UNIFIED_ID, "category": art.get("category"), "artifact_type": art.get("artifact_type")},
                        )
                    )

                # source_id
                sid = art.get("source_id")
                if isinstance(sid, str) and sid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"artifacts[{i}].source_id",
                            observed_value=sid,
                            normalized_value=sid.strip(),
                            identifier_kind=IDENTIFIER_KIND_SOURCE_ID,
                            timestamp=None,
                            evidence_scope=art_scope,
                            context={"id_type": IDENTIFIER_KIND_SOURCE_ID, "category": art.get("category"), "artifact_type": art.get("artifact_type")},
                        )
                    )

                # source_artifact_id
                said = art.get("source_artifact_id")
                if isinstance(said, str) and said.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.ARTIFACT_ID,
                            field_path=f"artifacts[{i}].source_artifact_id",
                            observed_value=said,
                            normalized_value=said.strip(),
                            identifier_kind=IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                            timestamp=None,
                            evidence_scope=art_scope,
                            context={"id_type": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID},
                        )
                    )

                # source_event_id
                seid = art.get("source_event_id")
                if isinstance(seid, str) and seid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"artifacts[{i}].source_event_id",
                            observed_value=seid,
                            normalized_value=seid.strip(),
                            timestamp=None,
                            evidence_scope=art_scope,
                            context={"id_type": "source_event_id"},
                        )
                    )

                # specialized_payload
                payload = art.get("specialized_payload")
                if isinstance(payload, (dict, Mapping)):
                    # payload.artifact_id (e.g. MEMPROC-, MEMNET-, MEMMOD-)
                    pay_aid = payload.get("artifact_id")
                    if isinstance(pay_aid, str) and pay_aid.strip():
                        pivots.append(
                            PivotReference(
                                report_id=report_id,
                                report_type=report.report_type,
                                field_type=PivotFieldType.ARTIFACT_ID,
                                field_path=f"artifacts[{i}].specialized_payload.artifact_id",
                                observed_value=pay_aid,
                                normalized_value=pay_aid.strip(),
                                identifier_kind="payload_artifact_id",
                                timestamp=None,
                                evidence_scope=art_scope,
                                context={"id_type": "payload_artifact_id"},
                            )
                        )

                    # sha256
                    sha_val = payload.get("sha256")
                    norm_sha = normalize_sha256(sha_val)
                    if norm_sha:
                        pivots.append(
                            PivotReference(
                                report_id=report_id,
                                report_type=report.report_type,
                                field_type=PivotFieldType.SHA256,
                                field_path=f"artifacts[{i}].specialized_payload.sha256",
                                observed_value=sha_val,
                                normalized_value=norm_sha,
                                timestamp=None,
                                evidence_scope=art_scope,
                                context={"category": art.get("category"), "source_path": art.get("source_path")},
                            )
                        )

                    # IP addresses
                    for ip_key in ("source_ip", "src_ip", "destination_ip", "dst_ip", "remote_ip", "local_address", "remote_address", "ip_address", "ip"):
                        ip_val = payload.get(ip_key)
                        norm_ip = normalize_ip_address_pivot(ip_val)
                        if norm_ip:
                            pivots.append(
                                PivotReference(
                                    report_id=report_id,
                                    report_type=report.report_type,
                                    field_type=PivotFieldType.IP_ADDRESS,
                                    field_path=f"artifacts[{i}].specialized_payload.{ip_key}",
                                    observed_value=ip_val,
                                    normalized_value=norm_ip,
                                    timestamp=payload.get("timestamp") if isinstance(payload.get("timestamp"), str) else None,
                                    evidence_scope=art_scope,
                                    context={"endpoint_key": ip_key, "category": art.get("category")},
                                )
                            )

                    # PID
                    pid_val = payload.get("pid")
                    norm_pid = normalize_pid(pid_val)
                    if norm_pid is not None:
                        proc_name = payload.get("process_name") or payload.get("command") or payload.get("user")
                        pivots.append(
                            PivotReference(
                                report_id=report_id,
                                report_type=report.report_type,
                                field_type=PivotFieldType.PID,
                                field_path=f"artifacts[{i}].specialized_payload.pid",
                                observed_value=pid_val,
                                normalized_value=str(norm_pid),
                                timestamp=payload.get("timestamp") or payload.get("created_at"),
                                evidence_scope=art_scope,
                                context={"process_name": str(proc_name) if proc_name else None},
                            )
                        )

        # audit_trail
        trail = raw_data.get("audit_trail")
        if isinstance(trail, (list, tuple)):
            for j, aevt in enumerate(trail):
                if not isinstance(aevt, (dict, Mapping)):
                    continue
                eid = aevt.get("event_id")
                if isinstance(eid, str) and eid.strip():
                    pivots.append(
                        PivotReference(
                            report_id=report_id,
                            report_type=report.report_type,
                            field_type=PivotFieldType.EVENT_ID,
                            field_path=f"audit_trail[{j}].event_id",
                            observed_value=eid,
                            normalized_value=eid.strip(),
                            timestamp=aevt.get("timestamp") if isinstance(aevt.get("timestamp"), str) else None,
                            evidence_scope=evidence_scope,
                            context={"event_type": str(aevt.get("event_type") or aevt.get("action") or "")},
                        )
                    )

    elif report.report_type == ReportType.TIMELINE:
        _extract_timeline_events_pivots(raw_data.get("events"), "events", report, report_id, evidence_scope, pivots)

    elif report.report_type == ReportType.DETECTION:
        _extract_detections_pivots(raw_data.get("detections"), "detections", report, report_id, evidence_scope, pivots)

    elif report.report_type == ReportType.CORRELATION:
        _extract_correlations_pivots(raw_data.get("correlations"), "correlations", report, report_id, evidence_scope, pivots)

    elif report.report_type == ReportType.CORRELATION_DETECTION:
        _extract_detections_pivots(raw_data.get("detections"), "detections", report, report_id, evidence_scope, pivots)
        _extract_correlations_pivots(raw_data.get("correlations"), "correlations", report, report_id, evidence_scope, pivots)
        _extract_timeline_events_pivots(raw_data.get("timeline_events"), "timeline_events", report, report_id, evidence_scope, pivots)

    # Deterministic deduplication of references with the exact same (field_type, normalized_value, identifier_kind, field_path)
    deduped: List[PivotReference] = []
    seen: Set[Tuple[PivotFieldType, str, Optional[str], str]] = set()
    for ref in pivots:
        key = (ref.field_type, ref.normalized_value, ref.identifier_kind, ref.field_path)
        if key not in seen:
            seen.add(key)
            deduped.append(ref)

    return deduped


def sanitize_skipped_reason(err: Union[Exception, str]) -> str:
    """
    Sanitize an ingestion exception or error message into a safe, actionable,
    non-sensitive failure reason that never leaks absolute filesystem paths,
    report contents, or stack traces.

    Preserves useful diagnostic categories:
    - Malformed JSON / invalid UTF-8
    - Unsupported or corrupted schema
    - File size limit exceeded
    - Empty file (0 bytes)
    - Unreadable or missing file / permission denied
    - Invalid data structure or identifier
    """
    if isinstance(err, ReportSizeLimitError):
        return "Report size exceeds maximum allowed limit."
    elif isinstance(err, ReportParseError):
        msg = str(err).lower()
        if "empty" in msg or "0 bytes" in msg:
            return "Report file is empty (0 bytes)."
        return "Malformed JSON payload or invalid UTF-8 encoding."
    elif isinstance(err, ReportSchemaError):
        return "Unrecognized or unsupported ForensiX report schema."
    elif isinstance(err, ReportNotFoundError):
        return "Report file not found or inaccessible."
    elif isinstance(err, ReportInvalidFileError):
        return "Target is not a regular report file."
    elif isinstance(err, PermissionError):
        return "Permission denied reading report file."
    elif isinstance(err, OSError):
        return "I/O error reading report file."
    elif isinstance(err, ValueError):
        return "Invalid report structure or identifier."
    elif isinstance(err, Exception):
        return f"Failed to ingest report: {type(err).__name__}."
    elif isinstance(err, str):
        # Scrub any absolute paths (e.g. /tmp/... or C:\...)
        cleaned = re.sub(r"(/[a-zA-Z0-9_\.\-]+)+", "<path>", err)
        cleaned = re.sub(r"([A-Za-z]:\\[a-zA-Z0-9_\.\-\\]+)", "<path>", cleaned)
        return cleaned.strip()
    return "Unknown ingestion failure."


class DashboardReportRegistry:
    """
    In-memory registry of approved and verified ForensiX IngestedReport instances.

    Guarantees:
    - Pure in-memory lookup; HTTP request handlers never touch the filesystem.
    - Path sanitization: local storage absolute paths are omitted from output schemas.
    - Deterministic ordering: reports are ordered deterministically by identifier.
    - Deep immutability: registered reports cannot be mutated through registry queries.
    - In-Memory Pivot Indexing: Indexes allowlisted pivot fields (CASE_ID, SHA256, ARTIFACT_ID,
      EVENT_ID, RULE_ID, IP_ADDRESS, PID) across all 6 ForensiX report schemas for instant,
      bounded cross-report drill-down without copying full raw report payloads.
    """

    def __init__(self) -> None:
        self._reports: Dict[str, IngestedReport] = {}
        self._pivot_index: Dict[PivotFieldType, Dict[str, List[PivotReference]]] = {
            ft: {} for ft in PivotFieldType
        }
        self._report_pivots: Dict[str, List[PivotReference]] = {}
        self._skipped_reports: List[Dict[str, Any]] = []

    @property
    def skipped_reports(self) -> List[Dict[str, Any]]:
        """Return a defensive copy of the list of skipped/rejected report files during ingestion."""
        return [dict(entry) for entry in self._skipped_reports]

    def record_skipped_file(
        self,
        filename: str,
        reason: Union[Exception, str],
        path: Optional[Union[str, Path]] = None,
    ) -> None:
        """
        Record a skipped or rejected report file and reason for ingestion visibility.

        Args:
            filename: Base filename of the rejected report file.
            reason: Actionable failure reason or exception (sanitized to remove host paths).
            path: Optional source path (only basename is retained).
        """
        sanitized = sanitize_skipped_reason(reason)
        entry: Dict[str, Any] = {
            "filename": Path(filename).name if filename else "unknown",
            "reason": sanitized,
        }
        if path is not None:
            entry["path"] = Path(path).name
        self._skipped_reports.append(entry)

    def get_skipped_reports(self) -> List[Dict[str, Any]]:
        """Return a defensive copy of the list of skipped/rejected report entries."""
        return [dict(entry) for entry in self._skipped_reports]

    def get_ingestion_summary(self) -> Dict[str, Any]:
        """
        Return an ingestion summary distinguishing successfully ingested reports from rejected reports.
        """
        ingested = len(self._reports)
        skipped = len(self._skipped_reports)
        return {
            "total_scanned": ingested + skipped,
            "ingested_count": ingested,
            "skipped_count": skipped,
            "skipped_reports": [dict(entry) for entry in self._skipped_reports],
        }

    def register_report(
        self,
        report: IngestedReport,
        report_id: Optional[str] = None,
        allow_replace: bool = False,
    ) -> str:
        """
        Register an already ingested report with a unique, URL-safe identifier and index its pivots.

        Args:
            report: IngestedReport instance.
            report_id: Optional custom identifier. If None, derives 'rep-<sha256[:12]>'.
            allow_replace: If True, replaces existing report with same ID without error.

        Returns:
            str: Assigned unique report identifier in the registry.

        Raises:
            TypeError: If report is not an IngestedReport instance.
            ValueError: If custom report_id contains invalid characters or collides (when allow_replace=False).
        """
        if not isinstance(report, IngestedReport):
            raise TypeError(
                f"Expected IngestedReport instance, got {type(report).__name__}"
            )

        if report_id is not None:
            clean_id = str(report_id).strip()
            if not is_safe_report_id(clean_id):
                raise ValueError(
                    f"Invalid report identifier: '{report_id}'. "
                    "Must be alphanumeric with hyphens, underscores, or periods (1-128 chars)."
                )
            if clean_id in self._reports and self._reports[clean_id] is not report:
                if not allow_replace:
                    raise ValueError(
                        f"Report identifier collision: '{clean_id}' already registered."
                    )
        else:
            # Deterministic ID derived from sha256 prefix: rep-<sha256[:12]>
            clean_id = f"rep-{report.sha256[:12]}"
            base_id = clean_id
            counter = 1
            while clean_id in self._reports and self._reports[clean_id] is not report:
                clean_id = f"{base_id}-{counter}"
                counter += 1

        # Clean up old pivot index entries if replacing or re-registering
        if clean_id in self._reports:
            self._remove_report_from_index(clean_id)

        self._reports[clean_id] = report

        # Extract and index pivots
        pivots = extract_report_pivots(report, clean_id)
        self._report_pivots[clean_id] = pivots
        for ref in pivots:
            self._pivot_index[ref.field_type].setdefault(ref.normalized_value, []).append(ref)

        return clean_id

    def remove_report(self, report_id: str) -> bool:
        """
        Unregister a report and purge all its indexed pivot references.

        Args:
            report_id: Registry identifier to remove.

        Returns:
            bool: True if report was present and removed, False otherwise.
        """
        if report_id not in self._reports:
            return False
        del self._reports[report_id]
        self._remove_report_from_index(report_id)
        return True

    def _remove_report_from_index(self, report_id: str) -> None:
        """Remove all indexed pivot references for a specific report identifier."""
        old_refs = self._report_pivots.pop(report_id, None)
        if old_refs:
            for ref in old_refs:
                bucket = self._pivot_index[ref.field_type].get(ref.normalized_value)
                if bucket:
                    self._pivot_index[ref.field_type][ref.normalized_value] = [
                        r for r in bucket if r.report_id != report_id
                    ]
                    if not self._pivot_index[ref.field_type][ref.normalized_value]:
                        del self._pivot_index[ref.field_type][ref.normalized_value]

    def clear(self) -> None:
        """Clear all registered reports and reset the pivot index."""
        self._reports.clear()
        self._pivot_index = {ft: {} for ft in PivotFieldType}
        self._report_pivots.clear()

    def get_pivot_counts(self) -> Dict[str, int]:
        """Return count of unique indexed keys per allowlisted PivotFieldType."""
        return {
            ft.value: len(self._pivot_index[ft]) for ft in PivotFieldType
        }

    def query_pivots(
        self,
        field: Union[PivotFieldType, str],
        value: Any,
        scope: Optional[str] = None,
        identifier_kind: Optional[str] = None,
        max_results: int = 100,
    ) -> PivotQueryResult:
        """
        Perform a deterministic, read-only lookup in the in-memory pivot index.

        Args:
            field: Allowlisted PivotFieldType enum or field name string.
            value: Observed value to query (normalized according to field rules).
            scope: Optional evidence/host scope filter. Mandatory for exact PID matches.
            identifier_kind: Optional identifier namespace filter (e.g. 'evidence_id', 'source_artifact_id').
            max_results: Maximum number of matches to return (default: 100).

        Returns:
            PivotQueryResult containing immutable matches and truncation metadata.

        Raises:
            ValueError: If field is not a supported PivotFieldType, or max_results < 1.
            TypeError: If field or max_results have invalid types.
        """
        if isinstance(field, PivotFieldType):
            field_type = field
        elif isinstance(field, str):
            clean_field = field.strip().lower()
            try:
                field_type = PivotFieldType(clean_field)
            except ValueError:
                valid_types = [ft.value for ft in PivotFieldType]
                raise ValueError(
                    f"Unsupported pivot field type: '{field}'. Supported fields: {valid_types}"
                )
        else:
            raise TypeError(
                f"field must be PivotFieldType or str, got {type(field).__name__}"
            )

        if isinstance(max_results, bool) or not isinstance(max_results, int):
            raise TypeError(
                f"max_results must be an integer, got {type(max_results).__name__}"
            )
        if max_results < 1:
            raise ValueError(f"max_results must be >= 1, got {max_results}")

        clean_scope = (
            str(scope).strip()
            if scope is not None and str(scope).strip()
            else None
        )

        clean_id_kind: Optional[str] = (
            str(identifier_kind).strip().lower()
            if identifier_kind is not None and str(identifier_kind).strip()
            else None
        )
        if clean_id_kind in ("unified_id", "unified_artifact_id"):
            clean_id_kind = IDENTIFIER_KIND_UNIFIED_ID

        # Support prefix format e.g. "evidence_id:EV-01" or "correlation_id:CORR-01"
        queried_val = value
        if isinstance(value, str) and ":" in value:
            prefix, remainder = value.split(":", 1)
            prefix_lower = prefix.strip().lower()
            known_kinds = {
                "evidence_id": IDENTIFIER_KIND_EVIDENCE_ID,
                "unified_id": IDENTIFIER_KIND_UNIFIED_ID,
                "unified_artifact_id": IDENTIFIER_KIND_UNIFIED_ID,
                "source_id": IDENTIFIER_KIND_SOURCE_ID,
                "source_artifact_id": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                "correlation_id": IDENTIFIER_KIND_CORRELATION_ID,
                "report_id": IDENTIFIER_KIND_REPORT_ID,
                "payload_artifact_id": "payload_artifact_id",
            }
            if prefix_lower in known_kinds:
                if clean_id_kind is None:
                    clean_id_kind = known_kinds[prefix_lower]
                queried_val = remainder.strip()

        norm_query: Optional[str] = None
        if field_type == PivotFieldType.SHA256:
            norm_query = normalize_sha256(queried_val)
        elif field_type == PivotFieldType.IP_ADDRESS:
            norm_query = normalize_ip_address_pivot(queried_val)
        elif field_type == PivotFieldType.PID:
            norm_pid_int = normalize_pid(queried_val)
            norm_query = str(norm_pid_int) if norm_pid_int is not None else None
        elif field_type == PivotFieldType.CASE_ID:
            norm_query = normalize_case_id(queried_val)
        elif field_type in (PivotFieldType.RULE_ID, PivotFieldType.EVENT_ID, PivotFieldType.ARTIFACT_ID):
            norm_query = str(queried_val).strip() if isinstance(queried_val, str) and queried_val.strip() else None

        if norm_query is None:
            return PivotQueryResult(
                field_type=field_type,
                queried_value=value,
                normalized_query=None,
                scope=clean_scope,
                identifier_kind=clean_id_kind,
                total_matches=0,
                returned_matches=0,
                truncated=False,
                matches=(),
            )

        candidates = self._pivot_index[field_type].get(norm_query, [])

        if field_type == PivotFieldType.ARTIFACT_ID:
            if clean_id_kind is not None:
                candidates = [ref for ref in candidates if ref.identifier_kind == clean_id_kind]
            else:
                # Ensure unrelated identifier namespaces cannot appear as equivalent matches
                # merely because their strings are equal.
                distinct_kinds = {ref.identifier_kind for ref in candidates}
                if len(distinct_kinds) > 1:
                    candidates = []
        elif clean_id_kind is not None:
            candidates = [ref for ref in candidates if ref.identifier_kind == clean_id_kind]

        if field_type == PivotFieldType.PID:
            # PID matching must remain scoped to a defensible shared evidence or host identity.
            # If the required scope is unavailable, do not return an exact PID match.
            if clean_scope is None:
                filtered: List[PivotReference] = []
            else:
                filtered = [
                    ref for ref in candidates if ref.evidence_scope == clean_scope
                ]
        else:
            if clean_scope is not None:
                filtered = [
                    ref for ref in candidates if ref.evidence_scope == clean_scope
                ]
            else:
                filtered = list(candidates)

        total_matches = len(filtered)
        truncated = total_matches > max_results
        result_slice = tuple(filtered[:max_results])

        return PivotQueryResult(
            field_type=field_type,
            queried_value=value,
            normalized_query=norm_query,
            scope=clean_scope,
            identifier_kind=clean_id_kind,
            total_matches=total_matches,
            returned_matches=len(result_slice),
            truncated=truncated,
            matches=result_slice,
        )


    def register_file(
        self,
        file_path: Union[str, Path],
        report_id: Optional[str] = None,
        max_size_bytes: int = DEFAULT_MAX_REPORT_SIZE_BYTES,
    ) -> str:
        """
        Ingest a report file using read_report() and register it.

        Args:
            file_path: Path to the forensic report JSON file.
            report_id: Optional custom identifier.
            max_size_bytes: Maximum allowed size limit.

        Returns:
            str: Assigned registry report identifier.
        """
        ingested = read_report(file_path, max_size_bytes=max_size_bytes)
        return self.register_report(ingested, report_id=report_id)

    def register_directory(
        self,
        dir_path: Union[str, Path],
        recursive: bool = False,
        max_size_bytes: int = DEFAULT_MAX_REPORT_SIZE_BYTES,
    ) -> List[str]:
        """
        Scan a directory for JSON report files and register all valid ForensiX reports.

        Args:
            dir_path: Directory path to scan.
            recursive: If True, recursively search subdirectories.
            max_size_bytes: Maximum allowed size per report file.

        Returns:
            List[str]: List of assigned report identifiers for successfully ingested reports.
        """
        p = Path(dir_path).resolve(strict=True)
        if not p.is_dir():
            raise ValueError(f"Target path is not a directory: '{dir_path}'")

        registered_ids: List[str] = []
        pattern = "**/*.json" if recursive else "*.json"
        for json_path in sorted(p.glob(pattern)):
            if json_path.is_file():
                try:
                    rep_id = self.register_file(
                        json_path, max_size_bytes=max_size_bytes
                    )
                    registered_ids.append(rep_id)
                except (ReportReaderError, ValueError, OSError) as err:
                    # Non-report or invalid JSON files are tracked for forensic completeness
                    self.record_skipped_file(
                        filename=json_path.name,
                        reason=err,
                        path=json_path,
                    )
        return registered_ids

    def get(self, report_id: str) -> Optional[IngestedReport]:
        """Look up an IngestedReport by its registry identifier."""
        return self._reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        """
        Return a deterministically sorted list of sanitized report summaries.

        Guarantees that local storage absolute paths are never leaked.
        """
        result: List[Dict[str, Any]] = []
        for rep_id in sorted(self._reports.keys()):
            report = self._reports[rep_id]
            result.append(
                {
                    "id": rep_id,
                    "report_type": report.report_type.value,
                    "filename": report.source_path.name,
                    "file_size_bytes": report.file_size_bytes,
                    "sha256": report.sha256,
                    "metadata": report.metadata.to_dict(),
                    "counts": report.counts.to_dict(),
                }
            )
        return result

    def get_report_view(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Return a sanitized overview dictionary for a specific report."""
        report = self.get(report_id)
        if report is None:
            return None
        return {
            "id": report_id,
            "report_type": report.report_type.value,
            "filename": report.source_path.name,
            "file_size_bytes": report.file_size_bytes,
            "sha256": report.sha256,
            "metadata": report.metadata.to_dict(),
            "counts": report.counts.to_dict(),
            "warnings": list(report.warnings),
        }

    def get_report_metadata(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Return strictly the administrative metadata for a specific report."""
        report = self.get(report_id)
        if report is None:
            return None
        return {
            "id": report_id,
            "metadata": report.metadata.to_dict(),
        }

    def get_report_summary(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Return factual summary counts for a specific report."""
        report = self.get(report_id)
        if report is None:
            return None
        return {
            "id": report_id,
            "report_type": report.report_type.value,
            "counts": report.counts.to_dict(),
        }

    def get_report_details(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Return complete parsed report details (raw payload) as an independent dictionary.
        """
        report = self.get(report_id)
        if report is None:
            return None
        return {
            "id": report_id,
            "report_type": report.report_type.value,
            "raw_data": report.raw_dict(),
        }

    def __len__(self) -> int:
        return len(self._reports)

    def __contains__(self, report_id: str) -> bool:
        return report_id in self._reports


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """
    Read-only HTTP request handler for the ForensiX Local Dashboard.

    Enforces:
    - GET-only method policy (all others return 405 Method Not Allowed).
    - Strict JSON output with security headers (nosniff, no-store).
    - Predictable error responses with zero local path or stack trace leakage.
    - Rejection of path traversal and malformed route tokens.
    """

    server: "DashboardServer"

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr request logging for silent, clean execution."""
        pass

    def _send_json_response(
        self,
        status_code: int,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Serialize data to JSON and send with standard security headers."""
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(
        self,
        status_code: int,
        code: str,
        message: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send a structured JSON error response without internal stack trace details."""
        data = {
            "error": {
                "code": code,
                "message": message,
            }
        }
        self._send_json_response(status_code, data, headers=headers)

    def _send_bytes_response(
        self,
        status_code: int,
        content_type: str,
        data: bytes,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send raw binary/text response with security headers for UI assets."""
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';",
        )
        self.send_header("Cache-Control", "no-cache")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def parse_request(self) -> bool:
        """
        Parse and validate incoming HTTP request.

        Enforces:
        - Host header validation against approved loopback hosts and bound port (DNS rebinding protection).
        - Rejection of malformed request targets starting with '//' or containing '//'
          with 400 Bad Request and standard JSON error format before routing.
        """
        if not super().parse_request():
            return False

        # Validate Host header
        host_header = self.headers.get("Host")
        bound_port = getattr(self.server, "bound_port", getattr(self.server, "server_port", 0))
        if not is_valid_dashboard_host(host_header, bound_port):
            self._send_error(
                400,
                "INVALID_HOST",
                f"Invalid or unapproved Host header: {host_header!r}. Access is restricted to local loopback.",
            )
            return False

        words = getattr(self, "requestline", "").split()
        target = words[1] if len(words) >= 2 else self.path
        target_path = target.split("?", 1)[0]
        raw_url_path = self.path.split("?", 1)[0]
        if (
            target.startswith("//")
            or self.path.startswith("//")
            or "//" in target_path
            or "//" in raw_url_path
        ):
            self._send_error(
                400,
                "MALFORMED_REQUEST",
                "Path traversal or malformed URL path sequence detected.",
            )
            return False

        return True

    # -------------------------------------------------------------------------
    # Method Enforcement: Reject non-GET requests
    # -------------------------------------------------------------------------

    def do_POST(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method POST is not allowed. Dashboard service is strictly read-only.",
            headers={"Allow": "GET"},
        )

    def do_PUT(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method PUT is not allowed. Dashboard service is strictly read-only.",
            headers={"Allow": "GET"},
        )

    def do_DELETE(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method DELETE is not allowed. Dashboard service is strictly read-only.",
            headers={"Allow": "GET"},
        )

    def do_PATCH(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method PATCH is not allowed. Dashboard service is strictly read-only.",
            headers={"Allow": "GET"},
        )

    def do_OPTIONS(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method OPTIONS is not allowed.",
            headers={"Allow": "GET"},
        )

    def do_HEAD(self) -> None:
        self._send_error(
            405,
            "METHOD_NOT_ALLOWED",
            "Method HEAD is not allowed.",
            headers={"Allow": "GET"},
        )

    # -------------------------------------------------------------------------
    # V7.4 Pivot Endpoint Query Handler
    # -------------------------------------------------------------------------

    def _handle_pivots_query(self, query_str: str) -> None:
        """
        Handle read-only GET /api/pivots cross-report queries.

        Validates query parameters:
        - field: required, must be valid PivotFieldType
        - value: required, non-empty after validation
        - max_results: optional, integer between 1 and MAX_PIVOT_RESULTS_LIMIT (default: 100)
        - identifier_kind: optional, only valid for ARTIFACT_ID queries
        - scope: optional, required for exact PID matching (unscoped PID queries return 0 matches)
        Rejects unknown or duplicate query parameters and malformed percent-encoding.
        """
        # 1. Defensive malformed percent-encoding check
        if "%" in query_str:
            if re.search(r"%(?![0-9a-fA-F]{2})", query_str):
                self._send_error(
                    400,
                    "MALFORMED_REQUEST",
                    "Malformed percent-encoding sequence in request URL.",
                )
                return

        try:
            params = urllib.parse.parse_qs(
                query_str,
                keep_blank_values=True,
                errors="strict",
            )
        except (UnicodeDecodeError, ValueError):
            self._send_error(
                400,
                "MALFORMED_REQUEST",
                "Malformed percent-encoding or invalid UTF-8 sequence in query string.",
            )
            return

        # 2. Strict parameter name validation (reject unknown parameters)
        allowed_params = {"field", "value", "max_results", "identifier_kind", "scope"}
        unknown_params = set(params.keys()) - allowed_params
        if unknown_params:
            self._send_error(
                400,
                "INVALID_PARAMETER",
                f"Unknown query parameter(s): {', '.join(sorted(unknown_params))}.",
            )
            return

        # 3. Reject duplicate parameters
        for param_name, param_values in params.items():
            if len(param_values) > 1:
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    f"Duplicate query parameter '{param_name}' is not allowed.",
                )
                return

        # 4. Validate required 'field' parameter
        if "field" not in params:
            self._send_error(
                400,
                "INVALID_PARAMETER",
                "Missing required query parameter 'field'.",
            )
            return

        raw_field = params["field"][0]
        if not raw_field or not raw_field.strip():
            self._send_error(
                400,
                "INVALID_PARAMETER",
                "Query parameter 'field' cannot be empty or whitespace.",
            )
            return

        clean_field = raw_field.strip().lower()
        try:
            field_type = PivotFieldType(clean_field)
        except ValueError:
            valid_fields = [ft.value for ft in PivotFieldType]
            self._send_error(
                400,
                "INVALID_PARAMETER",
                f"Unsupported pivot field type: '{raw_field}'. Supported fields: {valid_fields}.",
            )
            return

        # 5. Validate required 'value' parameter
        if "value" not in params:
            self._send_error(
                400,
                "INVALID_PARAMETER",
                "Missing required query parameter 'value'.",
            )
            return

        raw_value = params["value"][0]
        if not raw_value or not raw_value.strip():
            self._send_error(
                400,
                "INVALID_PARAMETER",
                "Query parameter 'value' cannot be empty or whitespace.",
            )
            return

        # 6. Validate optional 'max_results' parameter
        max_results = DEFAULT_PIVOT_MAX_RESULTS
        if "max_results" in params:
            raw_mr = params["max_results"][0]
            if not raw_mr or not raw_mr.strip():
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    "Query parameter 'max_results' cannot be empty or whitespace.",
                )
                return
            try:
                mr_val = int(raw_mr.strip())
            except (ValueError, TypeError):
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    "Query parameter 'max_results' must be a valid integer.",
                )
                return
            if mr_val < 1:
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    f"Query parameter 'max_results' must be greater than or equal to 1, got {mr_val}.",
                )
                return
            if mr_val > MAX_PIVOT_RESULTS_LIMIT:
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    f"Query parameter 'max_results' exceeds maximum allowed limit of {MAX_PIVOT_RESULTS_LIMIT}, got {mr_val}.",
                )
                return
            max_results = mr_val

        # 7. Validate optional 'identifier_kind' parameter
        identifier_kind_val: Optional[str] = None
        if "identifier_kind" in params:
            if field_type != PivotFieldType.ARTIFACT_ID:
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    f"Query parameter 'identifier_kind' is only applicable to 'artifact_id' field queries, got '{field_type.value}'.",
                )
                return
            raw_ik = params["identifier_kind"][0]
            if not raw_ik or not raw_ik.strip():
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    "Query parameter 'identifier_kind' cannot be empty or whitespace.",
                )
                return
            clean_ik = raw_ik.strip().lower()
            if clean_ik in ("unified_id", "unified_artifact_id"):
                clean_ik = IDENTIFIER_KIND_UNIFIED_ID
            if clean_ik not in ALLOWED_IDENTIFIER_KINDS:
                self._send_error(
                    400,
                    "INVALID_PARAMETER",
                    f"Unsupported identifier kind: '{raw_ik}'. Supported kinds: {sorted(ALLOWED_IDENTIFIER_KINDS)}.",
                )
                return
            identifier_kind_val = clean_ik

        # 8. Check prefix syntax and conflicting parameters for ARTIFACT_ID
        query_value = raw_value
        if field_type == PivotFieldType.ARTIFACT_ID and ":" in raw_value:
            prefix, remainder = raw_value.split(":", 1)
            prefix_lower = prefix.strip().lower()
            known_prefix_kinds = {
                "evidence_id": IDENTIFIER_KIND_EVIDENCE_ID,
                "unified_id": IDENTIFIER_KIND_UNIFIED_ID,
                "unified_artifact_id": IDENTIFIER_KIND_UNIFIED_ID,
                "source_id": IDENTIFIER_KIND_SOURCE_ID,
                "source_artifact_id": IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
                "correlation_id": IDENTIFIER_KIND_CORRELATION_ID,
                "report_id": IDENTIFIER_KIND_REPORT_ID,
                "payload_artifact_id": "payload_artifact_id",
            }
            if prefix_lower in known_prefix_kinds:
                canonical_prefix_kind = known_prefix_kinds[prefix_lower]
                if identifier_kind_val is not None and identifier_kind_val != canonical_prefix_kind:
                    self._send_error(
                        400,
                        "INVALID_PARAMETER",
                        f"Conflicting identifier kind: parameter '{identifier_kind_val}' conflicts with value prefix '{prefix_lower}'.",
                    )
                    return
                if not remainder.strip():
                    self._send_error(
                        400,
                        "INVALID_PARAMETER",
                        "Query parameter 'value' remainder after prefix cannot be empty or whitespace.",
                    )
                    return
                if identifier_kind_val is None:
                    identifier_kind_val = canonical_prefix_kind
                query_value = remainder.strip()

        # 9. Handle optional 'scope' parameter
        scope_val: Optional[str] = None
        if "scope" in params:
            raw_scope = params["scope"][0]
            if raw_scope is not None and raw_scope.strip():
                scope_val = raw_scope.strip()
            else:
                scope_val = None

        # 10. Execute query against in-memory registry
        try:
            result = self.server.registry.query_pivots(
                field=field_type,
                value=query_value,
                scope=scope_val,
                identifier_kind=identifier_kind_val,
                max_results=max_results,
            )
        except (ValueError, TypeError) as err:
            self._send_error(400, "INVALID_PARAMETER", str(err))
            return
        except Exception:
            self._send_error(
                500,
                "INTERNAL_ERROR",
                "An unexpected error occurred while executing the pivot query.",
            )
            return

        # 11. Serialize to JSON and send with standard security headers
        self._send_json_response(200, result.to_dict())

    # -------------------------------------------------------------------------
    # GET Request Dispatcher
    # -------------------------------------------------------------------------

    def do_GET(self) -> None:
        """Handle incoming read-only HTTP GET queries."""
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            raw_path = parsed_url.path
        except Exception:
            self._send_error(400, "MALFORMED_REQUEST", "Failed to parse request URL.")
            return

        # 1. Reject path traversal and malformed paths (including leading '//')
        words = getattr(self, "requestline", "").split()
        request_target = words[1] if len(words) >= 2 else self.path
        target_path = request_target.split("?", 1)[0]
        raw_url_path = self.path.split("?", 1)[0]
        lower_target_path = target_path.lower()
        lower_raw_url_path = raw_url_path.lower()
        lower_raw_path = raw_path.lower()

        if (
            request_target.startswith("//")
            or self.path.startswith("//")
            or raw_path.startswith("//")
            or "//" in target_path
            or "//" in raw_url_path
            or "//" in raw_path
            or ".." in raw_path
            or ".." in target_path
            or "\\" in target_path
            or "\\" in raw_path
            or "%2e" in lower_target_path
            or "%2f" in lower_target_path
            or "%5c" in lower_target_path
            or "%2e" in lower_raw_url_path
            or "%2f" in lower_raw_url_path
            or "%5c" in lower_raw_url_path
            or "%2e" in lower_raw_path
            or "%2f" in lower_raw_path
            or "%5c" in lower_raw_path
        ):
            self._send_error(
                400,
                "MALFORMED_REQUEST",
                "Path traversal or malformed URL path sequence detected.",
            )
            return

        # Normalize trailing slashes
        norm_path = raw_path.rstrip("/")
        if not norm_path:
            norm_path = "/"

        # 2. Static UI assets (V7.3 offline dashboard)
        static_asset = get_static_asset(norm_path)
        if static_asset is not None:
            content_type, asset_bytes = static_asset
            self._send_bytes_response(200, content_type, asset_bytes)
            return

        registry = self.server.registry

        # 3. Health endpoint
        if norm_path in ("/api/health", "/health"):
            self._send_json_response(
                200,
                {
                    "status": "ok",
                    "service": "ForensiX Local Dashboard Service",
                    "version": __version__,
                    "reports_count": len(registry),
                },
            )
            return

        # 3. Reports collection endpoint
        if norm_path == "/api/reports":
            reports_list = registry.list_reports()
            resp_data: Dict[str, Any] = {
                "total": len(reports_list),
                "reports": reports_list,
            }
            if registry.skipped_reports:
                resp_data["skipped_count"] = len(registry.skipped_reports)
                resp_data["skipped_reports"] = registry.get_skipped_reports()
            self._send_json_response(200, resp_data)
            return

        # 3b. Ingestion summary endpoint
        if norm_path in ("/api/ingestion", "/api/reports/ingestion"):
            self._send_json_response(200, registry.get_ingestion_summary())
            return

        # 4. Pivot query endpoint: GET /api/pivots
        if norm_path == "/api/pivots":
            self._handle_pivots_query(parsed_url.query)
            return

        # 5. Individual report endpoints: /api/reports/<report_id>[/(metadata|summary|details)]
        if norm_path.startswith("/api/reports/"):
            remainder = norm_path[len("/api/reports/") :]
            parts = remainder.split("/")

            if len(parts) == 1:
                # GET /api/reports/<report_id>
                report_id = urllib.parse.unquote(parts[0])
                if not is_safe_report_id(report_id):
                    self._send_error(
                        400,
                        "INVALID_REPORT_ID",
                        f"Report identifier '{report_id}' is malformed.",
                    )
                    return

                view = registry.get_report_view(report_id)
                if view is None:
                    self._send_error(
                        404,
                        "NOT_FOUND",
                        f"Report '{report_id}' was not found in the registry.",
                    )
                    return
                self._send_json_response(200, view)
                return

            elif len(parts) == 2:
                # GET /api/reports/<report_id>/<sub_endpoint>
                report_id = urllib.parse.unquote(parts[0])
                sub_endpoint = parts[1].lower()

                if not is_safe_report_id(report_id):
                    self._send_error(
                        400,
                        "INVALID_REPORT_ID",
                        f"Report identifier '{report_id}' is malformed.",
                    )
                    return

                if sub_endpoint == "metadata":
                    meta_view = registry.get_report_metadata(report_id)
                    if meta_view is None:
                        self._send_error(
                            404,
                            "NOT_FOUND",
                            f"Report '{report_id}' was not found in the registry.",
                        )
                        return
                    self._send_json_response(200, meta_view)
                    return

                elif sub_endpoint == "summary":
                    summary_view = registry.get_report_summary(report_id)
                    if summary_view is None:
                        self._send_error(
                            404,
                            "NOT_FOUND",
                            f"Report '{report_id}' was not found in the registry.",
                        )
                        return
                    self._send_json_response(200, summary_view)
                    return

                elif sub_endpoint == "details":
                    details_view = registry.get_report_details(report_id)
                    if details_view is None:
                        self._send_error(
                            404,
                            "NOT_FOUND",
                            f"Report '{report_id}' was not found in the registry.",
                        )
                        return
                    self._send_json_response(200, details_view)
                    return

                else:
                    self._send_error(
                        404,
                        "NOT_FOUND",
                        f"Unknown report sub-resource '{sub_endpoint}'.",
                    )
                    return

            else:
                self._send_error(404, "NOT_FOUND", "Resource path not found.")
                return

        # 5. Fallback 404 for unknown paths
        self._send_error(404, "NOT_FOUND", f"Endpoint '{raw_path}' not found.")


class DashboardServer(HTTPServer):
    """
    Loopback-only HTTP server hosting the ForensiX Dashboard service.

    Enforces:
    - Loopback address binding only ('127.0.0.1', 'localhost').
    - Explicit rejection of '0.0.0.0', '::1', or public/external network interfaces.
    - Clean lifecycle management via start_background() and stop().
    """

    def __init__(
        self,
        server_address: Tuple[str, int],
        RequestHandlerClass: Any,
        registry: DashboardReportRegistry,
    ) -> None:
        host, port = server_address
        if host not in ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"ForensiX dashboard service can only bind to loopback ({ALLOWED_LOOPBACK_HOSTS}), "
                f"got external host: '{host}'."
            )
        self.registry = registry
        self._thread: Optional[threading.Thread] = None
        self._is_serving: bool = False
        self._is_stopped: bool = False
        self._serving_event: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()
        super().__init__(server_address, RequestHandlerClass)

    @property
    def bound_port(self) -> int:
        """Return the actual bound port."""
        return self.server_address[1]

    def _is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested via BaseServer internals or stop flag."""
        return bool(getattr(self, "_BaseServer__shutdown_request", False) or self._is_stopped)

    def _notify_shutdown_complete(self) -> None:
        """Signal BaseServer shutdown completion event if present."""
        evt = getattr(self, "_BaseServer__is_shut_down", None)
        if isinstance(evt, threading.Event):
            evt.set()

    def _reset_shutdown_state(self) -> None:
        """Reset BaseServer shutdown completion event if present."""
        evt = getattr(self, "_BaseServer__is_shut_down", None)
        if isinstance(evt, threading.Event):
            evt.clear()

    def serve_forever(self, poll_interval: float = 0.05) -> None:
        """Override serve_forever to track serving state deterministically."""
        with self._lock:
            if self._is_stopped:
                return
        self._reset_shutdown_state()
        try:
            with selectors.DefaultSelector() as selector:
                try:
                    selector.register(self, selectors.EVENT_READ)
                except (OSError, ValueError):
                    with self._lock:
                        if self._is_stopped:
                            return
                    raise

                with self._lock:
                    if self._is_stopped:
                        return
                    self._is_serving = True
                    self._serving_event.set()

                while not self._is_shutdown_requested():
                    ready = selector.select(poll_interval)
                    if self._is_shutdown_requested():
                        break
                    if ready:
                        self._handle_request_noblock()
                    self.service_actions()
        finally:
            self._notify_shutdown_complete()
            with self._lock:
                self._is_serving = False
                self._serving_event.set()

    def start_background(self) -> None:
        """Start the server in a non-blocking background daemon thread."""
        with self._lock:
            if self._is_stopped:
                raise RuntimeError("Cannot start a dashboard server that has been stopped.")
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self.serve_forever, daemon=True)
            self._thread.start()
        # Deterministically wait until the server loop has entered serve_forever
        self._serving_event.wait(timeout=5.0)

    def stop(self) -> None:
        """
        Cleanly shutdown and release socket resources.

        Guarantees:
        - Safe to call before server startup (never blocks indefinitely in shutdown()).
        - Safe to call on running background servers.
        - Safe and idempotent on repeated calls.
        - Avoids socket and thread leaks without deadlocks.
        """
        with self._lock:
            if self._is_stopped:
                return
            self._is_stopped = True
            was_serving = self._is_serving
            thread = self._thread
            self._serving_event.set()

        shutdown_err: Optional[Exception] = None
        # Only invoke shutdown() if the server was actually in serve_forever loop
        if was_serving:
            try:
                super().shutdown()
            except OSError:
                # Expected race: socket closed or reset concurrently during shutdown
                pass
            except Exception as exc:
                # Capture unexpected exceptions without masking cleanup
                shutdown_err = exc

        # If a background thread was started, ensure it terminates cleanly
        thread_err: Optional[Exception] = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
            if thread.is_alive():
                thread_err = RuntimeError("Dashboard server background thread failed to terminate within timeout.")

        # Always close server socket to release file descriptors and port bindings
        try:
            self.server_close()
        except OSError:
            pass

        # Propagate unexpected shutdown or thread termination errors
        if shutdown_err is not None:
            raise shutdown_err
        if thread_err is not None:
            raise thread_err


def create_dashboard_server(
    registry: Optional[DashboardReportRegistry] = None,
    host: str = DEFAULT_DASHBOARD_HOST,
    port: int = DEFAULT_DASHBOARD_PORT,
) -> DashboardServer:
    """
    Factory helper to create a configured DashboardServer.

    Args:
        registry: Pre-populated DashboardReportRegistry instance, or None to create empty.
        host: Host address (must be loopback, default '127.0.0.1').
        port: Port number (default 8080, or 0 for dynamic ephemeral allocation).

    Returns:
        DashboardServer: Configured server instance.
    """
    if registry is None:
        registry = DashboardReportRegistry()
    return DashboardServer((host, port), DashboardRequestHandler, registry)
