"""
ForensiX - Automated Digital Forensics & Incident Triage Platform
V1 - Evidence Foundation
V2 - Host & System Artifacts
"""

__version__ = "1.0.0"

# V1 Core Exports
from forensix.hasher import compute_hashes
from forensix.evidence import EvidenceRecord, register_evidence, generate_evidence_id
from forensix.analyzer import (
    FileInfo,
    FileMetadata,
    HashResult,
    ForensicAnalysisResult,
    analyze_evidence,
    analyze_file_metadata,
    extract_file_info,
    extract_metadata,
)
from forensix.reporter import generate_json_report, DEFAULT_REPORTS_DIR
from forensix.main import main

# V2.1 Filesystem Artifact Collection Exports
from forensix.artifacts import (
    ArtifactCategory,
    ArtifactType,
    ArtifactStatus,
    ArtifactRecord,
    ArtifactCollectionResult,
    generate_artifact_id,
)
from forensix.identifier import identify_artifact, normalize_relative_path
from forensix.scanner import scan_evidence_directory

__all__ = [
    # V1
    "__version__",
    "compute_hashes",
    "EvidenceRecord",
    "register_evidence",
    "generate_evidence_id",
    "FileInfo",
    "FileMetadata",
    "HashResult",
    "ForensicAnalysisResult",
    "analyze_evidence",
    "analyze_file_metadata",
    "extract_file_info",
    "extract_metadata",
    "generate_json_report",
    "DEFAULT_REPORTS_DIR",
    "main",
    # V2.1
    "ArtifactCategory",
    "ArtifactType",
    "ArtifactStatus",
    "ArtifactRecord",
    "ArtifactCollectionResult",
    "generate_artifact_id",
    "identify_artifact",
    "normalize_relative_path",
    "scan_evidence_directory",
]
