"""
ForensiX - Automated Digital Forensics & Incident Triage Platform
V1 - Evidence Foundation
"""

__version__ = "0.1.0"

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

__all__ = [
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
]
