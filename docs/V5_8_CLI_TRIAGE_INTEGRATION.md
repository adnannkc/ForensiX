# ForensiX V5.8 — CLI and Triage Integration

This document details the command-line interface (CLI) and triage workflow integration implemented in **ForensiX V5.8**, uniting classic PCAP network packet forensics (V5.1–V5.7) with existing ForensiX triage orchestration, timeline reconstruction, event correlation, detection rules, and structured reporting.

---

## 1. Overview and Architecture

ForensiX V5.8 establishes a unified, defensible triage workflow connecting network captures and host evidence through existing interfaces without creating parallel pipelines or secondary triage orchestrators.

```
                              [ Local Evidence ]
                                      |
                +---------------------+---------------------+
                |                                           |
         [ PCAP Capture ]                           [ Host Artifacts ]
                |                                           |
    PcapParser (Read-Only)                        TriageOrchestrator
                |                                           |
    NetworkTimelineExtractor                       adapt_artifacts
    (Packets + DNS/HTTP/TLS)                                |
                \                                           /
                 +---> reconstruct_timeline (V3) <---------+
                                      |
                            CorrelationEngine (V4)
                        (Temporal + Host-Network)
                                      |
                             DetectionEngine (V4)
                         (Host Rules + Network Rules)
                                      |
                     CorrelationDetectionReport (V4.6)
                                      |
                       +--------------+--------------+
                       |                             |
                [ JSON Report ]               [ HTML Report ]
```

### Core Design Principles
1. **Narrowest Useful Seam**: Extends existing `forensix investigate` / `forensix triage-v4` commands to recognize PCAP evidence directly while adding dedicated `forensix pcap` (alias `forensix network`) subcommands.
2. **Evidence Coexistence**: Supports PCAP-only investigation, host-only triage, and mixed host + network triage (`--pcap <file>` or auto-discovered `.pcap` files in evidence directories).
3. **No Fabricated Host Facts**: When analyzing a PCAP file alone, ForensiX never invokes host analyzers, never invents host logs, and never fabricates host identities or user accounts.
4. **Memory Safety & Streaming**: PCAP packets and metadata events are extracted incrementally via generator streams without buffering whole captures in memory.
5. **Defensible Forensic Immutability**: All evidence files are accessed strictly read-only; source hashes remain byte-for-byte identical before and after triage.

---

## 2. Command Line Interfaces

### A. Dedicated PCAP Analysis (`forensix pcap`)

```bash
python3 -m forensix pcap <pcap_file> [options]
# Alias:
python3 -m forensix network <pcap_file> [options]
```

#### Arguments
- `pcap_file` (positional, required): Path to local classic PCAP file.
- `-o`, `--output`, `--output-dir` (optional): Output destination path or directory for reports.
- `--format {html,json}` (optional): Presentation format (default: `html`).
- `--json` (flag): Shortcut for `--format json`.
- `--html` (flag): Shortcut for `--format html`.
- `--case-id` (optional): Case tracking identifier (e.g., `CASE-2026-NET01`).
- `--case-name` (optional): Human-readable case name.
- `--investigator` (optional): Handling forensic investigator name.
- `--matched-only` (flag): Report only matched detection rules.
- `--verbose` (flag): Display stage-by-stage execution progress.

### B. Extended Unified Investigation (`forensix investigate`)

```bash
python3 -m forensix investigate <evidence_path> [options]
```

- When `evidence_path` is a PCAP file: Executes PCAP-only incident triage and detection.
- When `evidence_path` is a directory:
  - Scans directory for host artifacts and any `.pcap` files.
  - Accepts optional `--pcap <path>` argument to attach an external capture.
  - Emits a unified investigation report correlating host logins with network flows.

---

## 3. End-to-End Processing Stages

Execution proceeds deterministically across six phases:

1. **Input Validation & Preflight Checks**:
   - Validates evidence path existence and read permissions.
   - For PCAP files, validates the 24-byte global header format, magic number, and supported data link types (`DLT_EN10MB`, `DLT_NULL`, `DLT_RAW`, `DLT_LINUX_SLL`).
   - Rejects unsupported PCAP-NG files, truncated files, or corrupt headers immediately with exit code 1.
2. **Host Evidence Analysis (Conditional)**:
   - For directory evidence: runs `TriageOrchestrator` to collect syslog, auth logs, shadow records, sudo rules, and cron persistence.
   - For PCAP-only evidence: skips host triage entirely, preserving clean provenance without mock host records.
3. **Network Streaming & Timeline Reconstruction**:
   - Streams packet observations (`NetworkEvent`) and application metadata (`DnsMetadata`, `HttpMetadata`, `TlsMetadata`) via `extract_network_timeline_events`.
   - Adapts records into canonical `TimelineEvent` objects under `TimelineCategory.NETWORK`.
   - Reconstructs and chronologically orders the unified timeline with factual deduplication.
4. **Multi-Domain Correlation**:
   - Evaluates temporal proximity across all events.
   - Where host authentication events and network events coexist, evaluates `CorrelationType.HOST_NETWORK` to link logins and network flows involving shared IP endpoints.
5. **Declarative Detection Rule Evaluation**:
   - Loads canonical V4 host initial rules (when host events exist) and V5 canonical network detection rules (when PCAP traffic exists).
   - Evaluates declarative rules (`RULE_NET_01` through `RULE_NET_05`) against timeline events and correlated relationships.
   - Generates deterministic detection results (`DET-<UUIDv5>`) linking to supporting event IDs.
6. **Structured Reporting & Summary**:
   - Generates deterministic `CorrelationDetectionReport` (`InvestigationReport`).
   - Persists machine-readable JSON and/or self-contained offline HTML reports.
   - Prints a factual terminal summary card with event, correlation, and detection counts.

---

## 4. Exit Code and Error Handling Conventions

| Exit Code | Condition | Behavior |
| :---: | :--- | :--- |
| **`0`** | Successful completion | Pipeline executed; report written. Matched detections do not alter exit code. |
| **`1`** | Forensic input or I/O error | Clean error message printed to `stderr` without Python tracebacks. Triggered by missing files, unreadable files, corrupt magic headers, unsupported PCAP-NG format, truncated captures, or invalid format arguments. |
| **`2`** | CLI syntax error | Raised by argument parser when required positional arguments are missing or invalid options are supplied. |

### Concrete Error Diagnostics
- **Non-existent evidence**: `Error: PCAP evidence file does not exist: '<path>'`
- **PCAP-NG capture**: `Error: Unsupported PCAP format: PCAP-NG format detected ... ForensiX V5 supports classic PCAP format`
- **Corrupt header**: `Error: Corrupt PCAP evidence: Invalid PCAP magic number ...`
- **Truncated capture**: `Error: Truncated PCAP capture: Truncated global header ...`
- **Permission failure**: `Error: Permission denied accessing PCAP evidence: ...`

---

## 5. Evidence Integrity and Provenance Guarantees

1. **Non-Destructive Read-Only Operation**:
   - Source capture files and directory artifacts are opened strictly in binary read mode (`"rb"`).
   - File SHA-256 digests remain byte-for-byte identical before, during, and after triage.
   - Report destinations inside the evidence directory are explicitly rejected to prevent collision or contamination.
2. **Deterministic Identifier Hierarchy**:
   - Network Evidence Records: `NET-<UUIDv5>` derived from frame number, source path, timestamp, and packet tuple.
   - Network Timeline Events: `source_event_id` preserves parent `NETEVT-<UUIDv5>` ID.
   - Host-Network Correlations: `CORR-<UUIDv5>` derived from relationship type and sorted event IDs.
   - Detections: `DET-<UUIDv5>` derived from rule ID, matched event IDs, and matched correlation IDs.
3. **No Execution or Network Calls**:
   - ForensiX never executes packet payloads and never initiates network sockets or outbound requests during analysis.

---

## 6. Example Usage

### A. Triage a Standalone PCAP Capture

```bash
# Analyze capture and generate a JSON report
python3 -m forensix pcap /evidence/incident_traffic.pcap \
  --case-id CASE-2026-001 \
  --case-name "External Ingress Analysis" \
  -o reports/network_triage.json \
  --format json
```

**Terminal Output:**
```
============================================================
ForensiX Incident Triage & Investigation (v4.0.0)
============================================================
Evidence Root           : /evidence/incident_traffic.pcap
Case ID                 : CASE-2026-001
Case Name               : External Ingress Analysis
Timeline Events         : 142
Correlations Identified : 18
Detection Results       : 5
Matched Detections      : 2
Rule Matches            :
  RULE-46cf828f-7cb2-5a49-9f37-d2503248c8b1: 1
  RULE-aaef9399-75d2-54dd-ac4f-a0342448b754: 1
Format                  : JSON
Report Path             : /home/adnan/ForensiX/reports/network_triage.json
------------------------------------------------------------
Status                  : SUCCESS
============================================================
```

### B. Mixed Host and Network Investigation

```bash
python3 -m forensix investigate /evidence/compromised_host/ \
  --pcap /evidence/network/perimeter.pcap \
  --case-id CASE-2026-MIXED \
  -o reports/investigation.html \
  --html
```

Produces an integrated HTML report featuring chronological host logins, DNS lookups, HTTP requests, and correlated `HOST_NETWORK` relationships connecting server logins to perimeter traffic.

---

## 7. Verification and Test Results

The V5.8 CLI and triage integration was validated using focused integration tests and full regression suites:

- **Focused V5.8 Suite**: `tests/test_v58_cli_triage.py` (15 passed)
- **V5 Network Suites**: `tests/test_network_*.py` (174 passed, 40 subtests passed)
- **CLI Regression Suites**: `tests/test_v47_cli_triage.py`, `tests/test_timeline_cli.py` (58 passed)
- **Full Test Suite**: `PYTHONPATH=src pytest -q`
  - **1,099 passed**
  - **238 subtests passed**
  - **0 failures, 0 regressions**
