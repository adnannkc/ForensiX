"""
ForensiX - Automated Digital Forensics & Incident Triage Platform
V1 - Evidence Foundation
V2 - Host & System Artifacts
"""

__version__ = "2.0.1"

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
from forensix.main import main, build_triage_parser, triage_main, execute_triage_cli

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

# V2.2 Linux Log Analysis Exports
from forensix.log_models import (
    LogEvent,
    LogEventType,
    LogParseResult,
    generate_event_id,
)
from forensix.log_parser import (
    classify_log_message,
    iter_log_lines,
    parse_log_file,
    parse_log_line,
    parse_syslog_header,
    stream_log_events,
)

# V2.3 Authentication Activity Exports
from forensix.auth_models import (
    AuthEventType,
    AuthStatus,
    AuthenticationRecord,
    AuthenticationActivityResult,
    generate_auth_id,
)
from forensix.auth_analyzer import (
    extract_authentication_activity,
    log_event_to_auth_record,
    stream_authentication_activity,
)

# V2.4 Users & Privilege Information Exports
from forensix.account_models import (
    AccountCollectionResult,
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
    generate_group_id,
    generate_shadow_id,
    generate_ssh_key_id,
    generate_sudo_rule_id,
    generate_user_id,
)
from forensix.account_analyzer import (
    analyze_account_artifacts,
    parse_authorized_keys_file,
    parse_group_file,
    parse_passwd_file,
    parse_shadow_file,
    parse_sudoers_file,
    parse_sudoers_line,
    resolve_user_group_relationships,
)

# V2.5 Persistence Artifacts Exports
from forensix.persistence_models import (
    PersistenceCategory,
    PersistenceRecord,
    PersistenceCollectionResult,
    generate_persistence_id,
)
from forensix.persistence_analyzer import (
    analyze_persistence_artifacts,
    parse_anacron_file,
    parse_cron_file,
    parse_init_script_or_rc,
    parse_kernel_module_config,
    parse_ld_preload_file,
    parse_shell_startup_file,
    parse_systemd_unit_file,
    parse_xdg_autostart_file,
)

# V2.6 Unified Host Artifact Model Exports
from forensix.unified_models import (
    HostArtifact,
    HostArtifactCategory,
    HostArtifactCollection,
    SpecializedPayload,
    generate_host_artifact_id,
)
from forensix.unified_adapter import (
    artifact_record_to_host_artifact,
    auth_record_to_host_artifact,
    build_host_artifact_collection,
    group_record_to_host_artifact,
    log_event_to_host_artifact,
    persistence_record_to_host_artifact,
    shadow_record_to_host_artifact,
    ssh_key_to_host_artifact,
    sudo_rule_to_host_artifact,
    to_host_artifact,
    user_account_to_host_artifact,
)

# V2.7 Investigation Interface Exports
from forensix.investigation import (
    ArtifactQuery,
    InvestigationResultSet,
    HostArtifactInvestigator,
)

# V2.8 Reporting & Presentation Layer Exports
from forensix.audit import (
    AuditEvent,
    AuditEventType,
    create_audit_event,
    generate_audit_id,
)
from forensix.report_models import (
    ForensicReport,
    ReportFormat,
    ReportMetadata,
    generate_report_id,
)
from forensix.report_builder import build_forensic_report
from forensix.report_json import render_json_report, write_json_report
from forensix.report_csv import render_csv_report, write_csv_report
from forensix.report_html import render_html_report, write_html_report

# V2.9.1 Triage Orchestration Models Exports
from forensix.triage_models import (
    ALL_STAGE_STATUSES,
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageSummary,
    TriageTraceRecord,
    generate_triage_id,
)

# V2.9.2 / V2.9.3 Triage Orchestrator & Audit Exports
from forensix.triage_orchestrator import (
    EVENT_LIFECYCLE_ORDER,
    STAGE_DEPENDENCIES,
    STAGE_NAMES,
    TriageOrchestrator,
    sort_audit_events,
)

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
    # V2.2
    "LogEvent",
    "LogEventType",
    "LogParseResult",
    "generate_event_id",
    "classify_log_message",
    "iter_log_lines",
    "parse_log_file",
    "parse_log_line",
    "parse_syslog_header",
    "stream_log_events",
    # V2.3
    "AuthEventType",
    "AuthStatus",
    "AuthenticationRecord",
    "AuthenticationActivityResult",
    "generate_auth_id",
    "extract_authentication_activity",
    "log_event_to_auth_record",
    "stream_authentication_activity",
    # V2.4
    "AccountCollectionResult",
    "GroupRecord",
    "ShadowRecord",
    "SshKeyInfo",
    "SudoRule",
    "UserAccount",
    "generate_group_id",
    "generate_shadow_id",
    "generate_ssh_key_id",
    "generate_sudo_rule_id",
    "generate_user_id",
    "analyze_account_artifacts",
    "parse_authorized_keys_file",
    "parse_group_file",
    "parse_passwd_file",
    "parse_shadow_file",
    "parse_sudoers_file",
    "parse_sudoers_line",
    "resolve_user_group_relationships",
    # V2.5
    "PersistenceCategory",
    "PersistenceRecord",
    "PersistenceCollectionResult",
    "generate_persistence_id",
    "analyze_persistence_artifacts",
    "parse_anacron_file",
    "parse_cron_file",
    "parse_init_script_or_rc",
    "parse_kernel_module_config",
    "parse_ld_preload_file",
    "parse_shell_startup_file",
    "parse_systemd_unit_file",
    "parse_xdg_autostart_file",
    # V2.6
    "HostArtifact",
    "HostArtifactCategory",
    "HostArtifactCollection",
    "SpecializedPayload",
    "generate_host_artifact_id",
    "artifact_record_to_host_artifact",
    "auth_record_to_host_artifact",
    "build_host_artifact_collection",
    "group_record_to_host_artifact",
    "log_event_to_host_artifact",
    "persistence_record_to_host_artifact",
    "shadow_record_to_host_artifact",
    "ssh_key_to_host_artifact",
    "sudo_rule_to_host_artifact",
    "to_host_artifact",
    "user_account_to_host_artifact",
    # V2.7
    "ArtifactQuery",
    "InvestigationResultSet",
    "HostArtifactInvestigator",
    # V2.8
    "AuditEvent",
    "AuditEventType",
    "create_audit_event",
    "generate_audit_id",
    "ForensicReport",
    "ReportFormat",
    "ReportMetadata",
    "generate_report_id",
    "build_forensic_report",
    "render_json_report",
    "write_json_report",
    "render_csv_report",
    "write_csv_report",
    "render_html_report",
    "write_html_report",
    # V2.9.1 / V2.9.3
    "ALL_STAGE_STATUSES",
    "ALL_TRIAGE_STAGES",
    "TriageConfig",
    "TriageResult",
    "TriageStage",
    "TriageStageError",
    "TriageStageResult",
    "TriageStageStatus",
    "TriageSummary",
    "TriageTraceRecord",
    "generate_triage_id",
    # V2.9.2 / V2.9.3 / V2.9.5
    "STAGE_DEPENDENCIES",
    "STAGE_NAMES",
    "TriageOrchestrator",
    "EVENT_LIFECYCLE_ORDER",
    "sort_audit_events",
    "build_triage_parser",
    "triage_main",
    "execute_triage_cli",
]
