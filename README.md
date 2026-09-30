# ForensiX

ForensiX is a lightweight, Linux-oriented automated digital forensics and incident triage platform built using only the Python standard library.

The goal of ForensiX is to automate and streamline the initial phases of digital forensic investigations—from raw evidence ingestion to multi-stage artifact collection, parsing, structured investigation queries, and multi-format reporting—while adhering strictly to fundamental forensic integrity and safety principles.

---

## Architecture Overview

ForensiX provides two primary operational modes:

1. **V1 Single-File Evidence Analysis**: Point-target cryptographic hashing, metadata extraction, and JSON reporting for individual files.
2. **V2 Automated Incident Triage**: Multi-stage, end-to-end triage orchestration across an entire Linux evidence directory, culminating in a unified host artifact model, investigation querying, multi-format reporting, and a tamper-evident audit trail.

### V2 Canonical Triage Pipeline

```text
Evidence Directory
       ↓
[ Stage 1 ] Evidence Validation
       ↓
[ Stage 2 ] Filesystem Artifact Collection
       ↓
[ Stage 3 ] Linux Log Parsing
       ↓
[ Stage 4 ] Authentication Activity Analysis
       ↓
[ Stage 5 ] User Account & Privilege Analysis
       ↓
[ Stage 6 ] Persistence Mechanism Analysis
       ↓
[ Stage 7 ] Unified Host Artifact Model (Canonical HostArtifact)
       ↓
[ Stage 8 ] Investigation & Query Interface (InvestigationResultSet)
       ↓
[ Stage 9 ] Multi-Format Reporting (JSON / CSV / HTML) + Audit Trail
       ↓
TriageResult
```

---

## Features

### V1 — Evidence Foundation
- **Evidence Registration**: Registers evidence targets, validates paths, and assigns a unique identifier (`EV-<UUIDv4>`) with UTC timestamps.
- **Filesystem Metadata Extraction**: Reads file size, POSIX permissions (octal format, e.g. `0644`), and ISO 8601 UTC timestamps (`mtime`, `atime`, `btime` when available).
- **Cryptographic Hashing**: Computes dual cryptographic digests (MD5 and SHA-256) in a single streaming pass using fixed 64 KB memory buffers.
- **Unified Forensic Analysis Result**: Binds all data into immutable dataclass structures (`ForensicAnalysisResult`).
- **JSON Reporting**: Generates structured, human-readable JSON reports formatted in UTF-8 into an isolated output directory.

### V2 — Host Artifact Triage & Automated Orchestration
- **Filesystem Artifact Collection (V2.1)**: Scans evidence targets for key forensic artifacts across `/etc`, `/var/log`, `/home`, etc., extracting metadata, computing SHA-256 hashes, and safely flagging unreadable files.
- **Linux Log Parsing (V2.2)**: Streaming parser for standard Linux syslog, `auth.log`, systemd journal exports, rotated logs (`.1`), and compressed logs (`.gz`). Defensive parsing guarantees that malformed lines never halt execution.
- **Authentication Analysis (V2.3)**: Extracts authentication attempts, SSH login methods, failed/successful credentials, sudo elevations, and session open/close events with source IP tracking.
- **Account & Privilege Analysis (V2.4)**: Parses `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers` & `/etc/sudoers.d/`, and user `~/.ssh/authorized_keys`. Identifies UID 0 non-root accounts, passwordless accounts, and group memberships.
- **Persistence Analysis (V2.5)**: Audits cron schedules (`/etc/crontab`, `/etc/cron.*`, user crontabs), systemd units (`/etc/systemd/system`, `/lib/systemd/system`), and shell startup scripts (`/etc/profile`, `/etc/profile.d/`, `~/.bashrc`).
- **Unified Host Model (V2.6)**: Normalizes all specialized records into a canonical, deeply immutable `HostArtifact` schema with unique IDs (`HOSTART-<UUIDv4>`), category tags, and provenance links.
- **Investigation & Query Interface (V2.7)**: High-performance in-memory query engine supporting filtering by category, time range, source path, search terms, and structured aggregations (`InvestigationResultSet`).
- **Multi-Format Reporting & Audit Trail (V2.8)**: Generates valid JSON, RFC 4180 CSV, and standalone HTML5 reports with embedded CSS and strict XSS escaping. Maintains a tamper-evident, append-only `AuditEvent` trail.
- **Automated End-to-End Orchestrator (V2.9)**: Manages stage execution with dependency cascades, failure isolation, partial execution handling, source traceability (`AUTH -> EVT -> ART`), CLI interface, safety controls, determinism, and idempotent execution.
- **Final Release & Validation (V2.10)**: Clean, reproducible release with 100% test pass rate across the full 434-test regression suite.

---

## Safety & Forensic Principles

ForensiX is designed to handle evidence with strict forensic discipline:

- **Strictly Read-Only Access**: All evidence files are opened strictly in binary read-only mode (`mode="rb"`).
- **Zero Evidence Modification**: ForensiX never writes, modifies, renames, moves, or deletes files inside the evidence directory.
- **Zero Evidence Execution**: ForensiX never executes binaries, scripts, or hooks found within evidence targets.
- **Zero Subprocess / Shell Invocations**: Analysis is performed entirely in-process using pure Python parsers; no external system commands (`os.system`, `subprocess`) are spawned.
- **Zero Network Activity**: Zero network sockets, HTTP requests, cloud telemetry, or external APIs are used. Analysis is 100% offline.
- **Output Directory Isolation**: Prohibits placing output reports inside or overlapping the evidence directory.
- **Deterministic & Idempotent**: Equivalent evidence inputs produce identical logical classifications and report structures; repeated runs produce zero memory leaks or artifact accumulation.

---

## Installation & Requirements

ForensiX is written in pure Python and requires only the **Python standard library**. No third-party dependencies are needed.

### Requirements
- **Python**: Version 3.9 or higher (fully compatible with Python 3.9 through 3.14).
- **Operating System**: Linux (Kali, Ubuntu, Debian, Fedora, Arch, etc.), macOS, or any POSIX-compliant environment.

### Setup
Clone the repository and install in editable mode:

```bash
git clone https://github.com/adnannkc/ForensiX.git
cd ForensiX
python3 -m pip install -e .
```

Verify the installation:

```bash
python3 -m forensix --version
```

Output:
```text
ForensiX 2.0.0
```

---

## Command-Line Usage

### 1. Automated Incident Triage (V2 Mode)

Execute end-to-end triage against an evidence directory containing collected host artifacts:

```bash
python3 -m forensix triage <evidence_directory> [OPTIONS]
```

#### Supported Options

| Option | Description |
| :--- | :--- |
| `evidence_directory` | Positional argument: path to the target evidence directory. |
| `--case-id CASE_ID` | Incident tracking identifier (e.g. `CASE-2026-001`). |
| `--case-name CASE_NAME` | Human-readable title for the investigation. |
| `--investigator NAME` | Name or identifier of the forensic investigator. |
| `-o`, `--output-dir DIR` | Destination directory for reports (default: `reports/`). |
| `--format {json,csv,html}` | Report presentation format(s) to generate (can be repeated). |
| `--skip-reports` | Execute triage and print terminal summary without writing report files to disk. |
| `--disable-stage STAGE` | Disable a specific triage stage from execution (can be repeated). |
| `-v`, `--version` | Display program version and exit. |
| `-h`, `--help` | Show command-line help message and exit. |

#### Example V2 Run

```bash
python3 -m forensix triage /mnt/evidence/host_01/ \
    --case-id CASE-2026-001 \
    --case-name "Linux Workstation Incident" \
    --investigator "Lead Analyst" \
    --output-dir ./investigation_reports \
    --format json \
    --format csv \
    --format html
```

#### Terminal Summary Example

```text
================================================================================
ForensiX Automated Incident Triage (v2.0.0)
================================================================================
Triage ID   : 8f4a1322-921c-4394-bb9e-473d09a2b53c
Case ID     : CASE-2026-001
Case Name   : Linux Workstation Incident
Investigator: Lead Analyst
Evidence    : /mnt/evidence/host_01
Status      : COMPLETED
Duration    : 0.12s
Artifacts   : 48

Stage Execution Summary:
  [✓ COMPLETED] Evidence Validation (records: 1)
  [✓ COMPLETED] Filesystem Artifact Collection (records: 14)
  [✓ COMPLETED] Linux Log Parsing (records: 18)
  [✓ COMPLETED] Authentication Activity Analysis (records: 10)
  [✓ COMPLETED] User Account & Privilege Analysis (records: 15)
  [✓ COMPLETED] Persistence Mechanism Analysis (records: 5)
  [✓ COMPLETED] Unified Host Artifact Model (records: 48)
  [✓ COMPLETED] Investigation Query Interface (records: 48)
  [✓ COMPLETED] Multi-Format Forensic Reporting (records: 3)

Generated Reports:
  JSON : /mnt/investigation_reports/report_8f4a1322-921c-4394-bb9e-473d09a2b53c.json
  CSV  : /mnt/investigation_reports/report_8f4a1322-921c-4394-bb9e-473d09a2b53c.csv
  HTML : /mnt/investigation_reports/report_8f4a1322-921c-4394-bb9e-473d09a2b53c.html
================================================================================
```

---

### 2. Single-File Analysis (V1 Compatibility Mode)

Analyze an individual evidence file for cryptographic integrity and file metadata:

```bash
python3 -m forensix <evidence_file> [-o OUTPUT_DIR]
```

Example:

```bash
python3 -m forensix /path/to/suspect_binary.bin -o ./reports
```

Output:
```text
==================================================
ForensiX Analysis Complete
==================================================
Evidence ID : EV-387d74e8-af84-4205-9199-76d03c3c9f32
File        : suspect_binary.bin
Size        : 4128 bytes
Type        : application/octet-stream
MD5         : c98d3632cfba9828d13b4c1001eeac37
SHA-256     : 4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754
Report      : reports/EV-387d74e8-af84-4205-9199-76d03c3c9f32.json
==================================================
```

---

## Report Formats

ForensiX generates three standalone, standardized report formats:

1. **JSON (`.json`)**:
   - Machine-parseable, structured representation containing report metadata, unified artifacts with specialized payloads, stage execution metrics, provenance trace records, and the full audit trail.
2. **CSV (`.csv`)**:
   - RFC 4180 compliant tabular export suitable for spreadsheet tools (Excel, LibreOffice) and timeline imports. Stable columns: `unified_id`, `category`, `source_id`, `source_path`, `timestamp`, `summary`.
3. **HTML (`.html`)**:
   - Standalone HTML5 document with embedded modern CSS. Includes zero external CDN links or remote fonts (safe for air-gapped viewing), escapes all evidence-controlled strings against XSS, and presents clear category breakdowns, stage results, and investigation findings.

---

## Project Structure

```text
ForensiX/
├── pyproject.toml              # Package configuration and build metadata (version 2.0.0)
├── README.md                   # Complete platform documentation
├── docs/                       # Architectural documentation and reviews
│   └── V1_REVIEW.md            # V1 implementation and scope review
├── evidence/                   # Working evidence directory (gitignored)
│   └── .gitkeep
├── reports/                    # Generated forensic reports directory (gitignored)
│   └── .gitkeep
├── src/
│   └── forensix/               # Core ForensiX package
│       ├── __init__.py         # Package entry and canonical exports
│       ├── __main__.py         # Module execution dispatcher ('python3 -m forensix')
│       ├── main.py             # CLI parser and workflow execution
│       ├── hasher.py           # Streaming MD5 and SHA-256 hashing engine
│       ├── analyzer.py         # File metadata and identification engine
│       ├── evidence.py         # Evidence registration and validation
│       ├── reporter.py         # V1 JSON report generator
│       ├── artifacts.py        # V2.1 filesystem artifact models
│       ├── identifier.py       # V2.1 file category identifier
│       ├── scanner.py          # V2.1 filesystem artifact scanner
│       ├── log_models.py       # V2.2 log event models
│       ├── log_parser.py       # V2.2 streaming syslog/auth parser
│       ├── auth_models.py      # V2.3 authentication activity models
│       ├── auth_analyzer.py    # V2.3 authentication activity analyzer
│       ├── account_models.py   # V2.4 account & privilege models
│       ├── account_analyzer.py # V2.4 user/group/shadow/sudo/ssh analyzer
│       ├── persistence_models.py  # V2.5 persistence models
│       ├── persistence_analyzer.py# V2.5 cron/systemd/profile analyzer
│       ├── host_artifact.py    # V2.6 canonical HostArtifact model
│       ├── unified_adapter.py  # V2.6 payload normalization adapters
│       ├── investigation.py    # V2.7 query engine and result sets
│       ├── audit.py            # V2.8 immutable audit trail
│       ├── report_models.py    # V2.8 forensic report models
│       ├── report_builder.py   # V2.8 report compilation engine
│       ├── report_json.py      # V2.8 JSON report serializer
│       ├── report_csv.py       # V2.8 CSV report serializer
│       ├── report_html.py      # V2.8 standalone HTML serializer
│       ├── triage_models.py    # V2.9 triage configuration and stage models
│       └── triage_orchestrator.py # V2.9 9-stage pipeline orchestrator
└── tests/                      # Comprehensive automated test suite (434 tests)
    ├── test_hasher.py
    ├── test_analyzer.py
    ├── test_evidence.py
    ├── test_unified_result.py
    ├── test_reporter.py
    ├── test_cli.py
    ├── test_end_to_end.py
    ├── test_artifacts.py
    ├── test_identifier.py
    ├── test_scanner.py
    ├── test_log_parser.py
    ├── test_auth_activity.py
    ├── test_account_analyzer.py
    ├── test_persistence_analyzer.py
    ├── test_unified_host_model.py
    ├── test_investigation.py
    ├── test_reporting.py
    ├── test_triage_models.py
    ├── test_triage_orchestrator.py
    ├── test_triage_traceability.py
    ├── test_triage_reporting.py
    ├── test_triage_cli.py
    ├── test_triage_safety.py
    ├── test_triage_determinism.py
    ├── test_triage_idempotency.py
    └── test_triage_final_validation.py
```

---

## Testing & Quality Assurance

ForensiX includes a comprehensive automated test suite executable via the standard library `unittest` runner or `pytest`:

```bash
# Standard library test runner
PYTHONPATH=src python3 -m unittest discover -s tests -v

# Pytest runner (if installed)
PYTHONPATH=src python3 -m pytest tests/ -v
```

### Validation Metrics
- **Test Methods**: 434
- **Subtests**: 72
- **Failures**: 0
- **Errors**: 0
- **Pass Rate**: 100%

### Test Coverage Highlights
- **Cryptographic Correctness**: NIST test vector validation, streaming chunk boundaries.
- **Defensive Parsing**: Resilient handling of malformed logs, missing shadow fields, corrupted crontabs, unreadable files.
- **Traceability Verification**: Complete provenance cross-referencing from source files to final reports (`AUTH -> EVT -> ART`).
- **Safety Auditing**: Monitored verification of zero file mutations, zero subprocess execution, zero network access, and output directory isolation.
- **Determinism & Idempotency**: Normalized multi-run comparisons ensuring identical classifications and zero memory leakage.
- **Failure Injection**: Testing all 9 stage failure cascades (Scenarios A through K) confirming proper isolation and `SKIPPED` downstream states.

---

## Scope & Limitations

To ensure transparency and maintain forensic rigor, the boundaries of ForensiX V2 are explicitly defined:

### Implemented in V2.0.0
- Linux evidence ingestion and registration
- Filesystem artifact discovery and metadata extraction
- Linux syslog and authentication activity parsing
- Account and privilege configuration analysis
- Cron, systemd, and shell persistence auditing
- Unified host artifact modeling with provenance tracking
- In-memory investigation querying and filtering
- Multi-format reporting (JSON, CSV, HTML) and tamper-evident audit logging
- Deterministic, safe, automated end-to-end triage orchestration

### Future / Not Implemented in V2.0.0
- **Malware Analysis / Classification**: ForensiX extracts and organizes host state; it does not classify binaries or declare malware infections.
- **YARA / Signature Scanning**: Rule-based pattern matching against files or memory.
- **Threat Intelligence**: External threat feeds, IP reputation checks, or CVE lookups.
- **Risk Scoring / Severity Ratings**: ForensiX reports factual software states without subjective risk scores.
- **Compromise Confirmation**: ForensiX does not declare a system "compromised"; conclusions remain the responsibility of the human investigator.
- **Attack-Chain Correlation**: Automated multi-stage attack reconstruction (e.g. MITRE ATT&CK mapping).
- **Network / PCAP Forensics**: Packet capture analysis and network flow reassembly.
- **Memory Forensics**: RAM dump analysis (e.g., Volatility integrations).
- **Web Dashboard / GUI / Cloud Services**: ForensiX operates strictly as a local CLI and library tool without running background servers or external cloud integrations.

---

## Development Roadmap

- [x] **V1 — Evidence Foundation (v1.0.0)**
  - Single-file hashing, metadata, registration, unified result, JSON reporting, CLI.
- [x] **V2 — Host Artifact Triage & Automated Orchestration (v2.0.0)**
  - [x] V2.1 — Filesystem artifact collection
  - [x] V2.2 — Linux log parsing
  - [x] V2.3 — Authentication activity analysis
  - [x] V2.4 — User account & privilege analysis
  - [x] V2.5 — Persistence mechanism analysis
  - [x] V2.6 — Unified HostArtifact model
  - [x] V2.7 — Investigation & query interface
  - [x] V2.8 — Multi-format reporting + audit trail
  - [x] V2.9 — Automated end-to-end triage orchestration
  - [x] V2.10 — Final validation, cleanup, and v2.0.0 release
- [ ] **V3 — Timeline Reconstruction & Temporal Sequencing (Planned)**
- [ ] **V4 — Event Correlation & Rule-Based Detection (Planned)**
- [ ] **V5 — Network & PCAP Forensics (Planned)**
- [ ] **V6 — Memory Dump Forensics (Planned)**
- [ ] **V7 — Investigation Web Dashboard & Interactive UI (Planned)**
- [ ] **V8 — Enterprise Integrations & Advanced Reporting (Planned)**
