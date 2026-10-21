"""
ForensiX - Automated Digital Forensics & Incident Triage Platform
V1 - Evidence Foundation
V2 - Host & System Artifacts
"""

__version__ = "8.0.0"

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

# V3.1 Timeline Event Model Exports
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
    generate_timeline_id,
)

# V3.2 Timestamp Normalization Exports
from forensix.timestamp_normalizer import (
    NormalizedTimestamp,
    format_iso_timestamp,
    is_timezone_aware,
    normalize_bsd_timestamp,
    normalize_timestamp,
    parse_timestamp,
)

# V3.3 Artifact Adapters Exports
from forensix.artifact_adapters import (
    BaseArtifactAdapter,
    FilesystemAdapter,
    LogAdapter,
    AuthenticationAdapter,
    can_adapt_artifact,
    adapt_artifact,
    adapt_filesystem_artifact,
    adapt_log_artifact,
    adapt_auth_artifact,
    adapt_artifacts,
    compute_deterministic_artifact_id,
)

# V3.4 Timeline Reconstruction Exports
from forensix.timeline_reconstruction import (
    TimestampClass,
    classify_timestamp,
    timeline_sort_key,
    compute_event_fingerprint,
    ReconstructedTimeline,
    TimelineReconstructor,
    reconstruct_timeline,
    order_timeline_events,
)

# V3.5 Timeline Querying Exports
from forensix.timeline_query import (
    TimelineQuery,
    TimelineQueryResult,
    query_timeline,
)

# V3.6 Timeline Reporting Exports
from forensix.timeline_reporting import (
    TimelineReport,
    generate_timeline_report,
    render_timeline_json,
    render_timeline_html,
    write_timeline_json_report,
    write_timeline_html_report,
    serialize_timeline_event,
)

# V3.7 Timeline CLI Exports
from forensix.timeline_cli import (
    build_timeline_parser,
    execute_timeline_cli,
    timeline_main,
)

# V4.1 Correlation Model Exports
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
    create_correlation,
    generate_correlation_id,
)

# V4.2 Correlation Engine Exports
from forensix.correlation_engine import (
    DEFAULT_TIME_WINDOW_SECONDS,
    CorrelationConfig,
    CorrelationEngine,
    correlate_events,
    compute_timestamp_delta,
    extract_user_identity,
    extract_source_identity,
    extract_path_identity,
    extract_session_identity,
)

# V4.3 Rule Model Exports
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    Rule,
    RuleCollection,
    RuleCondition,
    compute_deterministic_rule_id,
    create_rule,
)

# V4.4 Detection Engine Exports
from forensix.detection_engine import (
    DetectionResult,
    DetectionResultCollection,
    DetectionEngine,
    evaluate_rule,
    evaluate_rules,
    compute_deterministic_detection_id,
    detection_sort_key,
    resolve_field_value,
    evaluate_condition_operator,
)

# V4.5 Initial Detection Rules Exports
from forensix.initial_rules import (
    DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
    RULE_NAME_SSH_AUTH_SUDO,
    RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
    RULE_NAME_ACCOUNT_PRIVILEGE,
    RULE_NAME_PERSISTENCE_FOLLOWUP,
    create_ssh_auth_sudo_rule,
    create_repeated_ssh_failure_success_rule,
    create_account_privilege_rule,
    create_persistence_followup_rule,
    create_initial_rules,
    get_initial_rules,
)

# V4.6 Correlation & Detection Reporting Exports
from forensix.correlation_reporting import (
    CorrelationReport,
    serialize_correlation,
    generate_correlation_report,
    render_correlation_json,
    write_correlation_json_report,
    render_correlation_html,
    write_correlation_html_report,
)
from forensix.detection_reporting import (
    DetectionReport,
    CorrelationDetectionReport,
    InvestigationReport,
    serialize_detection,
    generate_detection_report,
    render_detection_json,
    write_detection_json_report,
    render_detection_html,
    write_detection_html_report,
    generate_correlation_detection_report,
    generate_investigation_report,
    render_correlation_detection_json,
    write_correlation_detection_json_report,
    render_correlation_detection_html,
    write_correlation_detection_html_report,
)

# V4.7 CLI / Triage Integration Exports
from forensix.triage_cli import (
    build_investigation_parser,
    execute_investigation_cli,
    investigation_main,
    build_v4_triage_parser,
    execute_triage_v4_cli,
    triage_v4_main,
    build_pcap_parser,
    execute_pcap_cli,
    pcap_main,
)

# V5.1 Network Evidence Model Exports
from forensix.network_models import (
    FORENSIX_V5_NETWORK_NAMESPACE,
    NetworkEvidenceRecord,
    compute_deterministic_network_id,
    create_network_evidence_record,
)

# V5.2 PCAP Parser Exports
from forensix.network_pcap_parser import (
    PCAP_MAGIC_MICROSECONDS_BIG,
    PCAP_MAGIC_MICROSECONDS_LITTLE,
    PCAP_MAGIC_NANOSECONDS_BIG,
    PCAP_MAGIC_NANOSECONDS_LITTLE,
    PCAPNG_SECTION_HEADER_MAGIC,
    PcapError,
    PcapCorruptError,
    PcapTruncatedError,
    PcapUnsupportedError,
    PcapGlobalHeader,
    PcapParser,
    extract_transport_payload,
    parse_pcap,
    read_pcap,
    read_pcap_raw,
)

# V5.3 Network Event Extraction Exports
from forensix.network_events import (
    FORENSIX_V5_NETWORK_EVENT_NAMESPACE,
    NetworkEvent,
    NetworkEventExtractor,
    NetworkEventType,
    compute_deterministic_network_event_id,
    extract_network_event,
    extract_network_events,
)

# V5.4 Network Metadata Extraction Exports
from forensix.network_metadata import (
    FORENSIX_V5_NETWORK_METADATA_NAMESPACE,
    DnsAnswer,
    DnsMetadata,
    DnsQuestion,
    HttpMetadata,
    NetworkApplicationMetadata,
    NetworkMetadataExtractor,
    TlsMetadata,
    compute_deterministic_dns_id,
    compute_deterministic_http_id,
    compute_deterministic_tls_id,
    extract_application_metadata,
    extract_metadata_from_packet,
    extract_metadata_from_pcap,
    parse_dns_payload,
    parse_http_payload,
    parse_tls_payload,
)

# V5.5 Network-to-Timeline Integration Exports
from forensix.network_timeline import (
    NetworkTimelineAdapter,
    NetworkTimelineExtractor,
    adapt_network_artifact,
    adapt_network_event,
    adapt_network_metadata,
    adapt_network_record,
    extract_network_timeline_events,
    reconstruct_network_timeline,
)

# V5.6 Host-to-Network Correlation Exports
from forensix.network_correlation import (
    HostNetworkCorrelationConfig,
    HostNetworkCorrelator,
    correlate_host_network_events,
    extract_host_observed_ips,
    extract_host_ports,
    extract_network_ips,
    extract_network_ports,
    is_host_event,
    is_network_event,
    is_private_or_shared_ip,
    normalize_ip_address,
)

# V5.7 Network Detection Rules Exports
from forensix.network_rules import (
    DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS,
    RULE_NAME_DNS_QUERY_PATTERN,
    RULE_NAME_HTTP_REQUEST_PATTERN,
    RULE_NAME_TLS_SNI_PATTERN,
    RULE_NAME_PROTOCOL_PORT_PATTERN,
    RULE_NAME_HOST_NETWORK_CORRELATION,
    RULE_NET_01_DNS_OBSERVATION,
    RULE_NET_02_HTTP_OBSERVATION,
    RULE_NET_03_TLS_SNI_OBSERVATION,
    RULE_NET_04_SSH_PORT_OBSERVATION,
    RULE_NET_05_HOST_NETWORK_CORRELATION,
    NetworkRuleBuilder,
    create_canonical_network_rules,
    create_dns_query_rule,
    create_host_network_correlation_rule,
    create_http_request_rule,
    create_network_protocol_port_rule,
    create_tls_sni_rule,
)

# V6.1 Memory Evidence Foundation & Volatility Adapter Exports
from forensix.memory_models import (
    FORENSIX_V6_MEMORY_NAMESPACE,
    MEMORY_SCHEMA_VERSION,
    MemoryEvidenceRecord,
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    ModuleExtractionResult,
    ModuleRejectionRecord,
    NetworkExtractionResult,
    NetworkRejectionRecord,
    ProcessExtractionResult,
    ProcessRejectionRecord,
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_execution_id,
    compute_deterministic_memory_id,
    compute_deterministic_module_id,
    compute_deterministic_network_id,
    compute_deterministic_process_id,
    detect_memory_format,
    register_memory_evidence,
)
from forensix.memory_module import (
    extract_module_artifacts,
)
from forensix.memory_network import (
    extract_network_artifacts,
)
from forensix.memory_process import (
    extract_process_artifacts,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
    ReconstructedMemoryTimeline,
    adapt_module_artifact,
    adapt_module_extraction_result,
    adapt_network_artifact,
    adapt_network_extraction_result,
    adapt_process_artifact,
    adapt_process_extraction_result,
    classify_memory_event_timestamp,
    compute_deterministic_memory_event_id,
    compute_deterministic_v4_timeline_id,
    compute_memory_event_fingerprint,
    memory_timeline_sort_key,
    reconstruct_memory_timeline,
)
from forensix.memory_correlation import (
    MemoryCorrelation,
    MemoryCorrelationCollection,
    MemoryCorrelationConfidence,
    MemoryCorrelationConfig,
    MemoryCorrelationType,
    compute_deterministic_memory_correlation_id,
    correlate_memory_artifacts,
    memory_correlation_sort_key,
)
from forensix.volatility_adapter import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_VOLATILITY_CANDIDATES,
    VOLATILITY_BIN_ENV_VAR,
    VolatilityAdapter,
    VolatilityError,
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityNotFoundError,
    VolatilityOutputLimitExceededError,
    VolatilityParseError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
    build_sanitized_environment,
    execute_volatility_plugin,
    parse_volatility_json,
    resolve_volatility_binary,
    sanitize_cli_arguments,
    sanitize_diagnostic_snippet,
)
from forensix.memory_rules import (
    DEFAULT_MEMORY_RULE_TIME_WINDOW_SECONDS,
    RULE_MEM_01_PROCESS_NAME_OBSERVATION,
    RULE_MEM_02_LISTENING_PORT_OBSERVATION,
    RULE_MEM_03_PROCESS_SOCKET_CORRELATION,
    RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION,
    RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION,
    RULE_NAME_MEMORY_MODULE_DRIVER_PATH_PATTERN,
    RULE_NAME_MEMORY_NETWORK_PORT_PATTERN,
    RULE_NAME_MEMORY_PARENT_CHILD_CORRELATION,
    RULE_NAME_MEMORY_PROCESS_NAME_PATTERN,
    RULE_NAME_MEMORY_PROCESS_SOCKET_CORRELATION,
    MemoryRuleBuilder,
    create_canonical_memory_rules,
    create_memory_module_rule,
    create_memory_network_socket_rule,
    create_memory_parent_child_rule,
    create_memory_process_name_rule,
    create_memory_process_socket_correlation_rule,
)
from forensix.memory_triage import (
    MemoryTriageConfig,
    MemoryTriageResult,
    compute_deterministic_triage_id,
    run_memory_triage,
)
from forensix.memory_cli import (
    build_memory_parser,
    execute_memory_cli,
    memory_main,
)

# V7.1 Report Ingestion & Reader Exports
from forensix.report_reader import (
    DEFAULT_MAX_REPORT_SIZE_BYTES,
    CaseMetadataView,
    IngestedReport,
    ReportInvalidFileError,
    ReportNotFoundError,
    ReportParseError,
    ReportReaderError,
    ReportSchemaError,
    ReportSizeLimitError,
    ReportSummaryCounts,
    ReportType,
    detect_report_schema,
    freeze_payload,
    read_report,
    unfreeze_payload,
)
from forensix.dashboard_service import (
    ALLOWED_DASHBOARD_HOSTNAMES,
    ALLOWED_LOOPBACK_HOSTS,
    DEFAULT_DASHBOARD_HOST,
    DEFAULT_DASHBOARD_PORT,
    DEFAULT_PIVOT_MAX_RESULTS,
    DashboardReportRegistry,
    DashboardRequestHandler,
    DashboardServer,
    IDENTIFIER_KIND_CORRELATION_ID,
    IDENTIFIER_KIND_EVIDENCE_ID,
    IDENTIFIER_KIND_REPORT_ID,
    IDENTIFIER_KIND_SOURCE_ARTIFACT_ID,
    IDENTIFIER_KIND_SOURCE_ID,
    IDENTIFIER_KIND_UNIFIED_ID,
    MAX_PIVOT_RESULTS_LIMIT,
    PivotFieldType,
    PivotQueryResult,
    PivotReference,
    create_dashboard_server,
    extract_report_pivots,
    is_safe_report_id,
    is_valid_dashboard_host,
    normalize_pid,
    normalize_sha256,
    sanitize_skipped_reason,
)
from forensix.dashboard_ui import (
    STATIC_ASSETS,
    get_static_asset,
    load_static_assets,
)
from forensix.dashboard_cli import (
    build_dashboard_parser,
    dashboard_main,
    execute_dashboard_cli,
)

# V8.1 Chain of Custody Exports
from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    GENESIS_PREV_HASH,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    compute_canonical_event_json,
    compute_canonical_event_payload,
    compute_event_record_hash,
    generate_custody_event_id,
    is_valid_custody_event_id,
)

# V8.1 Manifest Models Exports
from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    HashAlgorithm,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    ManifestVerificationStatus,
    generate_manifest_id,
    is_valid_manifest_id,
    validate_relative_entry_path,
)

# V8.1 Advanced Report Models Exports
from forensix.advanced_report_models import (
    ADVANCED_REPORT_SCHEMA_VERSION,
    DEFAULT_ANALYTICAL_DISCLAIMER,
    AdvancedReport,
    AnalyticalLimitations,
    CustodySummary,
    EvidenceInventoryItem,
    FindingsSummary,
    generate_advanced_report_id,
    is_valid_advanced_report_id,
)

# V8.2 Manifest Integrity Verification Engine Exports
from forensix.manifest_verifier import (
    MANIFEST_VERIFICATION_NOTICE,
    ManifestEntryVerification,
    ManifestVerificationResult,
    verify_manifest,
)

# V8.3 Runtime Chain of Custody Ledger Exports
from forensix.custody_ledger import (
    CUSTODY_LEDGER_SCHEMA_VERSION,
    CustodyChainVerificationResult,
    CustodyLedger,
    compute_ledger_digest,
    generate_custody_ledger_id,
    is_valid_custody_ledger_id,
)

# V8.4 Advanced Forensic Report Builder Exports
from forensix.advanced_report_builder import (
    build_advanced_report,
    render_advanced_report_html,
    render_advanced_report_json,
    write_advanced_report_html,
    write_advanced_report_json,
)

# V8.5 Advanced Forensic Triage Orchestrator & CLI Exports
from forensix.advanced_orchestrator import (
    AdvancedTriageConfig,
    AdvancedTriageOrchestrator,
    AdvancedTriageResult,
    CustodyIntegrityError,
    run_advanced_triage,
)
from forensix.advanced_cli import (
    EXIT_CONFIG_ERROR,
    EXIT_CUSTODY_FAILURE,
    EXIT_FILESYSTEM_IO_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_DISCREPANCY,
    advanced_main,
    build_advanced_parser,
    execute_advanced_cli,
)

# V8.6 Forensic Manifest Generation Engine & CLI Exports
from forensix.manifest_generator import (
    ManifestGeneratorConfig,
    generate_manifest,
    save_manifest,
)
from forensix.manifest_cli import (
    build_manifest_parser,
    execute_manifest_cli,
    manifest_main,
)

# V8.7 Formal Custody Transfer Workflow & Audit-Trail Integrity Engine Exports
from forensix.custody_ledger import StaleLedgerError
from forensix.custody_transfer import (
    AuditFinding,
    CustodyAuditResult,
    CustodyTransferReceipt,
    CustodyTransferRecord,
    CustodyTransferStatus,
    audit_custody_ledger,
    generate_custody_receipt_id,
    generate_custody_transfer_id,
    generate_transfer_receipt,
    is_valid_custody_receipt_id,
    is_valid_custody_transfer_id,
    parse_transfer_from_event,
    record_transfer,
)
from forensix.custody_cli import (
    build_custody_parser,
    custody_main,
    execute_custody_cli,
)

# V9 Controlled Multi-Domain Investigation Pipeline Exports
from forensix.case_config import (
    ALL_DOMAINS,
    SUPPORTED_REPORT_FORMATS,
    CaseConfig,
    load_case_config_from_dict,
    load_case_config_from_file,
    validate_case_config,
)
from forensix.pipeline_models import (
    GeneratedFileRecord,
    PipelineRunManifest,
    PipelineRunStatus,
    PipelineStageId,
    StageRecord,
    StageStatus,
    generate_run_id,
)
from forensix.pipeline_engine import (
    EXIT_VERIFICATION_OR_PARTIAL,
    InvestigationPipeline,
    PipelineExecutionResult,
    run_pipeline,
)
from forensix.pipeline_cli import (
    build_pipeline_parser,
    execute_pipeline_cli,
    pipeline_main,
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
    # V3.1
    "TimelineCategory",
    "TimelineEvent",
    "create_timeline_event",
    "generate_timeline_id",
    # V3.2
    "NormalizedTimestamp",
    "format_iso_timestamp",
    "is_timezone_aware",
    "normalize_bsd_timestamp",
    "normalize_timestamp",
    "parse_timestamp",
    # V3.3
    "BaseArtifactAdapter",
    "FilesystemAdapter",
    "LogAdapter",
    "AuthenticationAdapter",
    "can_adapt_artifact",
    "adapt_artifact",
    "adapt_filesystem_artifact",
    "adapt_log_artifact",
    "adapt_auth_artifact",
    "adapt_artifacts",
    "compute_deterministic_artifact_id",
    # V3.4
    "TimestampClass",
    "classify_timestamp",
    "timeline_sort_key",
    "compute_event_fingerprint",
    "ReconstructedTimeline",
    "TimelineReconstructor",
    "reconstruct_timeline",
    "order_timeline_events",
    # V3.5
    "TimelineQuery",
    "TimelineQueryResult",
    "query_timeline",
    # V3.6
    "TimelineReport",
    "generate_timeline_report",
    "render_timeline_json",
    "render_timeline_html",
    "write_timeline_json_report",
    "write_timeline_html_report",
    "serialize_timeline_event",
    # V3.7
    "build_timeline_parser",
    "execute_timeline_cli",
    "timeline_main",
    # V4.1
    "Correlation",
    "CorrelationCollection",
    "CorrelationType",
    "RelationshipType",
    "compute_deterministic_correlation_id",
    "create_correlation",
    "generate_correlation_id",
    # V4.2
    "DEFAULT_TIME_WINDOW_SECONDS",
    "CorrelationConfig",
    "CorrelationEngine",
    "correlate_events",
    "compute_timestamp_delta",
    "extract_user_identity",
    "extract_source_identity",
    "extract_path_identity",
    "extract_session_identity",
    # V4.3
    "ConditionOperator",
    "DetectionRule",
    "Rule",
    "RuleCollection",
    "RuleCondition",
    "compute_deterministic_rule_id",
    "create_rule",
    # V4.4
    "DetectionResult",
    "DetectionResultCollection",
    "DetectionEngine",
    "evaluate_rule",
    "evaluate_rules",
    "compute_deterministic_detection_id",
    "detection_sort_key",
    "resolve_field_value",
    "evaluate_condition_operator",
    # V4.5
    "DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS",
    "RULE_NAME_SSH_AUTH_SUDO",
    "RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS",
    "RULE_NAME_ACCOUNT_PRIVILEGE",
    "RULE_NAME_PERSISTENCE_FOLLOWUP",
    "create_ssh_auth_sudo_rule",
    "create_repeated_ssh_failure_success_rule",
    "create_account_privilege_rule",
    "create_persistence_followup_rule",
    "create_initial_rules",
    "get_initial_rules",
    # V4.6
    "CorrelationReport",
    "serialize_correlation",
    "generate_correlation_report",
    "render_correlation_json",
    "write_correlation_json_report",
    "render_correlation_html",
    "write_correlation_html_report",
    "DetectionReport",
    "CorrelationDetectionReport",
    "InvestigationReport",
    "serialize_detection",
    "generate_detection_report",
    "render_detection_json",
    "write_detection_json_report",
    "render_detection_html",
    "write_detection_html_report",
    "generate_correlation_detection_report",
    "generate_investigation_report",
    "render_correlation_detection_json",
    "write_correlation_detection_json_report",
    "render_correlation_detection_html",
    "write_correlation_detection_html_report",
    # V4.7
    "build_investigation_parser",
    "execute_investigation_cli",
    "investigation_main",
    "build_v4_triage_parser",
    "execute_triage_v4_cli",
    "triage_v4_main",
    # V5.8
    "build_pcap_parser",
    "execute_pcap_cli",
    "pcap_main",
    # V5.1
    "FORENSIX_V5_NETWORK_NAMESPACE",
    "NetworkEvidenceRecord",
    "compute_deterministic_network_id",
    "create_network_evidence_record",
    # V5.2
    "PCAP_MAGIC_MICROSECONDS_BIG",
    "PCAP_MAGIC_MICROSECONDS_LITTLE",
    "PCAP_MAGIC_NANOSECONDS_BIG",
    "PCAP_MAGIC_NANOSECONDS_LITTLE",
    "PCAPNG_SECTION_HEADER_MAGIC",
    "PcapError",
    "PcapCorruptError",
    "PcapTruncatedError",
    "PcapUnsupportedError",
    "PcapGlobalHeader",
    "PcapParser",
    "extract_transport_payload",
    "parse_pcap",
    "read_pcap",
    "read_pcap_raw",
    # V5.3
    "FORENSIX_V5_NETWORK_EVENT_NAMESPACE",
    "NetworkEvent",
    "NetworkEventExtractor",
    "NetworkEventType",
    "compute_deterministic_network_event_id",
    "extract_network_event",
    "extract_network_events",
    # V5.4
    "FORENSIX_V5_NETWORK_METADATA_NAMESPACE",
    "DnsAnswer",
    "DnsMetadata",
    "DnsQuestion",
    "HttpMetadata",
    "NetworkApplicationMetadata",
    "NetworkMetadataExtractor",
    "TlsMetadata",
    "compute_deterministic_dns_id",
    "compute_deterministic_http_id",
    "compute_deterministic_tls_id",
    "extract_application_metadata",
    "extract_metadata_from_packet",
    "extract_metadata_from_pcap",
    "parse_dns_payload",
    "parse_http_payload",
    "parse_tls_payload",
    # V5.5
    "NetworkTimelineAdapter",
    "NetworkTimelineExtractor",
    "adapt_network_artifact",
    "adapt_network_event",
    "adapt_network_metadata",
    "adapt_network_record",
    "extract_network_timeline_events",
    "reconstruct_network_timeline",
    # V5.6
    "HostNetworkCorrelationConfig",
    "HostNetworkCorrelator",
    "correlate_host_network_events",
    "extract_host_observed_ips",
    "extract_host_ports",
    "extract_network_ips",
    "extract_network_ports",
    "is_host_event",
    "is_network_event",
    "is_private_or_shared_ip",
    "normalize_ip_address",
    # V5.7
    "DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS",
    "RULE_NAME_DNS_QUERY_PATTERN",
    "RULE_NAME_HTTP_REQUEST_PATTERN",
    "RULE_NAME_TLS_SNI_PATTERN",
    "RULE_NAME_PROTOCOL_PORT_PATTERN",
    "RULE_NAME_HOST_NETWORK_CORRELATION",
    "RULE_NET_01_DNS_OBSERVATION",
    "RULE_NET_02_HTTP_OBSERVATION",
    "RULE_NET_03_TLS_SNI_OBSERVATION",
    "RULE_NET_04_SSH_PORT_OBSERVATION",
    "RULE_NET_05_HOST_NETWORK_CORRELATION",
    "NetworkRuleBuilder",
    "create_canonical_network_rules",
    "create_dns_query_rule",
    "create_host_network_correlation_rule",
    "create_http_request_rule",
    "create_network_protocol_port_rule",
    "create_tls_sni_rule",
    # V6.1
    "FORENSIX_V6_MEMORY_NAMESPACE",
    "MEMORY_SCHEMA_VERSION",
    "MemoryEvidenceRecord",
    "VolatilityExecutionError",
    "VolatilityExecutionRecord",
    "VolatilityExecutionStatus",
    "compute_deterministic_execution_id",
    "compute_deterministic_memory_id",
    "detect_memory_format",
    "register_memory_evidence",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_VOLATILITY_CANDIDATES",
    "VOLATILITY_BIN_ENV_VAR",
    "VolatilityAdapter",
    "VolatilityError",
    "VolatilityExecutionFailureError",
    "VolatilityMissingSymbolsError",
    "VolatilityNotFoundError",
    "VolatilityOutputLimitExceededError",
    "VolatilityParseError",
    "VolatilityResult",
    "VolatilityTimeoutError",
    "VolatilityUnsupportedPluginError",
    "build_sanitized_environment",
    "execute_volatility_plugin",
    "parse_volatility_json",
    "resolve_volatility_binary",
    "sanitize_cli_arguments",
    "sanitize_diagnostic_snippet",
    # V6.2
    "MemoryProcessArtifact",
    "ProcessExtractionResult",
    "ProcessRejectionRecord",
    "compute_deterministic_process_id",
    "extract_process_artifacts",
    # V6.3
    "MemoryModuleArtifact",
    "ModuleExtractionResult",
    "ModuleRejectionRecord",
    "compute_deterministic_module_id",
    "extract_module_artifacts",
    # V6.4
    "MemoryNetworkArtifact",
    "NetworkExtractionResult",
    "NetworkRejectionRecord",
    "compute_deterministic_network_id",
    "extract_network_artifacts",
    # V6.5
    "MemoryTimelineCategory",
    "MemoryTimelineEvent",
    "ReconstructedMemoryTimeline",
    "adapt_module_artifact",
    "adapt_module_extraction_result",
    "adapt_network_artifact",
    "adapt_network_extraction_result",
    "adapt_process_artifact",
    "adapt_process_extraction_result",
    "classify_memory_event_timestamp",
    "compute_deterministic_memory_event_id",
    "compute_deterministic_v4_timeline_id",
    "compute_memory_event_fingerprint",
    "memory_timeline_sort_key",
    "reconstruct_memory_timeline",
    # V6.6
    "MemoryCorrelation",
    "MemoryCorrelationCollection",
    "MemoryCorrelationConfidence",
    "MemoryCorrelationConfig",
    "MemoryCorrelationType",
    "compute_deterministic_memory_correlation_id",
    "correlate_memory_artifacts",
    "memory_correlation_sort_key",
    # V6.7
    "DEFAULT_MEMORY_RULE_TIME_WINDOW_SECONDS",
    "RULE_NAME_MEMORY_PROCESS_NAME_PATTERN",
    "RULE_NAME_MEMORY_NETWORK_PORT_PATTERN",
    "RULE_NAME_MEMORY_PROCESS_SOCKET_CORRELATION",
    "RULE_NAME_MEMORY_MODULE_DRIVER_PATH_PATTERN",
    "RULE_NAME_MEMORY_PARENT_CHILD_CORRELATION",
    "RULE_MEM_01_PROCESS_NAME_OBSERVATION",
    "RULE_MEM_02_LISTENING_PORT_OBSERVATION",
    "RULE_MEM_03_PROCESS_SOCKET_CORRELATION",
    "RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION",
    "RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION",
    "MemoryRuleBuilder",
    "create_canonical_memory_rules",
    "create_memory_module_rule",
    "create_memory_network_socket_rule",
    "create_memory_parent_child_rule",
    "create_memory_process_name_rule",
    "create_memory_process_socket_correlation_rule",
    "MemoryTriageConfig",
    "MemoryTriageResult",
    "compute_deterministic_triage_id",
    "run_memory_triage",
    # V6.8
    "build_memory_parser",
    "execute_memory_cli",
    "memory_main",
    # V7.1
    "DEFAULT_MAX_REPORT_SIZE_BYTES",
    "CaseMetadataView",
    "IngestedReport",
    "ReportInvalidFileError",
    "ReportNotFoundError",
    "ReportParseError",
    "ReportReaderError",
    "ReportSchemaError",
    "ReportSizeLimitError",
    "ReportSummaryCounts",
    "ReportType",
    "detect_report_schema",
    "freeze_payload",
    "read_report",
    "unfreeze_payload",
    # V7.2
    "ALLOWED_DASHBOARD_HOSTNAMES",
    "ALLOWED_LOOPBACK_HOSTS",
    "DEFAULT_DASHBOARD_HOST",
    "DEFAULT_DASHBOARD_PORT",
    "DashboardReportRegistry",
    "DashboardRequestHandler",
    "DashboardServer",
    "create_dashboard_server",
    "is_safe_report_id",
    "is_valid_dashboard_host",
    "sanitize_skipped_reason",
    # V7.3
    "STATIC_ASSETS",
    "get_static_asset",
    "load_static_assets",
    # V7.4
    "DEFAULT_PIVOT_MAX_RESULTS",
    "IDENTIFIER_KIND_CORRELATION_ID",
    "IDENTIFIER_KIND_EVIDENCE_ID",
    "IDENTIFIER_KIND_REPORT_ID",
    "IDENTIFIER_KIND_SOURCE_ARTIFACT_ID",
    "IDENTIFIER_KIND_SOURCE_ID",
    "IDENTIFIER_KIND_UNIFIED_ID",
    "MAX_PIVOT_RESULTS_LIMIT",
    "PivotFieldType",
    "PivotQueryResult",
    "PivotReference",
    "extract_report_pivots",
    "normalize_pid",
    "normalize_sha256",
    # V7.5
    "build_dashboard_parser",
    "dashboard_main",
    "execute_dashboard_cli",
    # V8.1
    "CUSTODY_LIMITATIONS_DISCLAIMER",
    "GENESIS_PREV_HASH",
    "CustodyActionType",
    "CustodyActor",
    "CustodyEvent",
    "TimestampSource",
    "compute_canonical_event_json",
    "compute_canonical_event_payload",
    "compute_event_record_hash",
    "generate_custody_event_id",
    "is_valid_custody_event_id",
    "MANIFEST_SCHEMA_VERSION",
    "HashAlgorithm",
    "ManifestArtifactType",
    "ManifestEntry",
    "ManifestRecord",
    "ManifestVerificationStatus",
    "generate_manifest_id",
    "is_valid_manifest_id",
    "validate_relative_entry_path",
    "ADVANCED_REPORT_SCHEMA_VERSION",
    "DEFAULT_ANALYTICAL_DISCLAIMER",
    "AdvancedReport",
    "AnalyticalLimitations",
    "CustodySummary",
    "EvidenceInventoryItem",
    "FindingsSummary",
    "generate_advanced_report_id",
    "is_valid_advanced_report_id",
    # V8.2
    "MANIFEST_VERIFICATION_NOTICE",
    "ManifestEntryVerification",
    "ManifestVerificationResult",
    "verify_manifest",
    # V8.3
    "CUSTODY_LEDGER_SCHEMA_VERSION",
    "CustodyChainVerificationResult",
    "CustodyLedger",
    "compute_ledger_digest",
    "generate_custody_ledger_id",
    "is_valid_custody_ledger_id",
    # V8.4
    "build_advanced_report",
    "render_advanced_report_html",
    "render_advanced_report_json",
    "write_advanced_report_html",
    "write_advanced_report_json",
    # V8.5
    "AdvancedTriageConfig",
    "AdvancedTriageResult",
    "AdvancedTriageOrchestrator",
    "run_advanced_triage",
    "CustodyIntegrityError",
    "build_advanced_parser",
    "execute_advanced_cli",
    "advanced_main",
    "EXIT_SUCCESS",
    "EXIT_CONFIG_ERROR",
    "EXIT_VERIFICATION_DISCREPANCY",
    "EXIT_CUSTODY_FAILURE",
    "EXIT_FILESYSTEM_IO_ERROR",
    # V8.6
    "ManifestGeneratorConfig",
    "generate_manifest",
    "save_manifest",
    "build_manifest_parser",
    "execute_manifest_cli",
    "manifest_main",
    # V8.7
    "StaleLedgerError",
    "CustodyTransferStatus",
    "CustodyTransferRecord",
    "CustodyTransferReceipt",
    "CustodyAuditResult",
    "AuditFinding",
    "generate_custody_transfer_id",
    "is_valid_custody_transfer_id",
    "generate_custody_receipt_id",
    "is_valid_custody_receipt_id",
    "record_transfer",
    "generate_transfer_receipt",
    "audit_custody_ledger",
    "parse_transfer_from_event",
    "build_custody_parser",
    "execute_custody_cli",
    "custody_main",
    # V9
    "CaseConfig",
    "load_case_config_from_file",
    "load_case_config_from_dict",
    "validate_case_config",
    "ALL_DOMAINS",
    "SUPPORTED_REPORT_FORMATS",
    "PipelineStageId",
    "StageStatus",
    "PipelineRunStatus",
    "StageRecord",
    "GeneratedFileRecord",
    "PipelineRunManifest",
    "PipelineExecutionResult",
    "generate_run_id",
    "InvestigationPipeline",
    "run_pipeline",
    "EXIT_VERIFICATION_OR_PARTIAL",
    "build_pipeline_parser",
    "execute_pipeline_cli",
    "pipeline_main",
]

