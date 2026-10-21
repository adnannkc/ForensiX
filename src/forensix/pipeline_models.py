"""
ForensiX V9 - Controlled Investigation Pipeline Data Models.

Provides strongly typed, deeply immutable models representing pipeline stage identifiers,
lifecycle execution states, overall run outcomes, stage execution records, and the final
machine-readable run manifest.

Forensic Principles:
1. Deep Immutability: All record models are frozen dataclasses with tuple collections.
2. Determinism: Stable field ordering and JSON-serializable structures.
3. Factual Reporting: Records exact stage completion or failure states without speculative scoring.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import uuid


class PipelineStageId(str, Enum):
    """
    Standard stages of the ForensiX V9 investigation pipeline in dependency order.
    """

    CONFIG_VALIDATION = "config_validation"
    PREFLIGHT_VERIFICATION = "preflight_verification"
    CUSTODY_INITIALIZATION = "custody_initialization"
    HOST_ANALYSIS = "host_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    MEMORY_ANALYSIS = "memory_analysis"
    TIMELINE_RECONSTRUCTION = "timeline_reconstruction"
    CORRELATION = "correlation"
    DETECTION = "detection"
    REPORT_SYNTHESIS = "report_synthesis"
    CUSTODY_FINALIZATION = "custody_finalization"
    RUN_MANIFEST = "run_manifest"


ALL_PIPELINE_STAGES: Tuple[str, ...] = tuple(s.value for s in PipelineStageId)


class StageStatus(str, Enum):
    """
    Execution status of an individual pipeline stage.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


ALL_STAGE_STATUSES: Tuple[str, ...] = tuple(s.value for s in StageStatus)


class PipelineRunStatus(str, Enum):
    """
    Overall execution outcome of an investigation pipeline run.
    """

    SUCCESS = "SUCCESS"                  # Every enabled stage completed successfully
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"  # A domain stage failed but downstream report was produced
    FAILURE = "FAILURE"                  # Critical preflight or custody stage failed; execution halted


ALL_RUN_STATUSES: Tuple[str, ...] = tuple(s.value for s in PipelineRunStatus)


def generate_run_id() -> str:
    """Generate a unique tracking identifier for a pipeline run (RUN-<UUIDv4>)."""
    return f"RUN-{uuid.uuid4()}"


def _freeze_dict_to_tuples(data: Any) -> Tuple[Tuple[str, Any], ...]:
    """Helper to deeply freeze mapping into sorted tuple of (key, value) pairs."""
    if not data:
        return ()
    if isinstance(data, dict):
        items = []
        for k, v in sorted(data.items()):
            if isinstance(v, dict):
                items.append((str(k), _freeze_dict_to_tuples(v)))
            elif isinstance(v, (list, tuple)):
                items.append((str(k), tuple(v)))
            else:
                items.append((str(k), v))
        return tuple(items)
    if isinstance(data, (list, tuple)):
        clean = []
        for pair in data:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                clean.append((str(pair[0]), pair[1]))
        return tuple(clean)
    return ()


@dataclass(frozen=True)
class StageRecord:
    """
    Immutable representation of an individual pipeline stage execution outcome.
    """

    stage_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    records_produced: int = 0
    errors: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    metadata: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise ValueError("stage_id must be a non-empty string")
        st_val = self.status.value if isinstance(self.status, StageStatus) else str(self.status)
        if st_val not in ALL_STAGE_STATUSES:
            raise ValueError(f"Invalid status: '{st_val}'. Expected one of {ALL_STAGE_STATUSES}")
        object.__setattr__(self, "status", st_val)

        if not isinstance(self.records_produced, int) or isinstance(self.records_produced, bool):
            raise TypeError("records_produced must be an integer")
        if self.records_produced < 0:
            raise ValueError("records_produced cannot be negative")

        if not isinstance(self.errors, tuple):
            object.__setattr__(self, "errors", tuple(str(e) for e in self.errors))
        if not isinstance(self.warnings, tuple):
            object.__setattr__(self, "warnings", tuple(str(w) for w in self.warnings))
        if not isinstance(self.metadata, tuple):
            object.__setattr__(self, "metadata", _freeze_dict_to_tuples(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        """Convert stage record to a JSON-serializable dictionary."""
        return {
            "stage_id": self.stage_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "records_produced": self.records_produced,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GeneratedFileRecord:
    """
    Immutable record of a generated report, ledger, or manifest file with SHA-256 integrity digest.
    """

    relative_path: str
    sha256: str
    size_bytes: int
    file_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.relative_path, str) or not self.relative_path.strip():
            raise ValueError("relative_path must be a non-empty string")
        if not isinstance(self.sha256, str) or len(self.sha256) != 64:
            raise ValueError(f"sha256 must be a 64-character hex string, got '{self.sha256}'")
        if not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        if not isinstance(self.file_type, str) or not self.file_type.strip():
            raise ValueError("file_type must be a non-empty string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "file_type": self.file_type,
        }


@dataclass(frozen=True)
class PipelineRunManifest:
    """
    Machine-readable run manifest certifying execution outcome, stage timings,
    input evidence baseline digests, and SHA-256 hashes of all generated output files.
    """

    run_id: str
    forensix_version: str
    started_at: str
    completed_at: str
    total_duration_seconds: float
    run_status: str
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    stages: Tuple[StageRecord, ...] = ()
    generated_files: Tuple[GeneratedFileRecord, ...] = ()
    evidence_digests: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.startswith("RUN-"):
            raise ValueError(f"run_id must start with 'RUN-', got '{self.run_id}'")
        status_val = self.run_status.value if isinstance(self.run_status, PipelineRunStatus) else str(self.run_status)
        if status_val not in ALL_RUN_STATUSES:
            raise ValueError(f"Invalid run_status: '{status_val}'. Expected one of {ALL_RUN_STATUSES}")
        object.__setattr__(self, "run_status", status_val)

        if not isinstance(self.stages, tuple):
            object.__setattr__(self, "stages", tuple(self.stages))
        for st in self.stages:
            if not isinstance(st, StageRecord):
                raise TypeError(f"stages elements must be StageRecord, got {type(st).__name__}")

        if not isinstance(self.generated_files, tuple):
            object.__setattr__(self, "generated_files", tuple(self.generated_files))
        for gf in self.generated_files:
            if not isinstance(gf, GeneratedFileRecord):
                raise TypeError(f"generated_files elements must be GeneratedFileRecord, got {type(gf).__name__}")

        if not isinstance(self.evidence_digests, tuple):
            object.__setattr__(self, "evidence_digests", _freeze_dict_to_tuples(self.evidence_digests))

    def to_dict(self) -> Dict[str, Any]:
        """Convert run manifest to a JSON-serializable dictionary."""
        return {
            "run_id": self.run_id,
            "forensix_version": self.forensix_version,
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "run_status": self.run_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_seconds": self.total_duration_seconds,
            "stages": [s.to_dict() for s in self.stages],
            "generated_files": [f.to_dict() for f in self.generated_files],
            "evidence_digests": dict(self.evidence_digests),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize run manifest to a deterministic JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
