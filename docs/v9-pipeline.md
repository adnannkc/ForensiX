# ForensiX V9 — Controlled Investigation Pipeline Architecture & Technical Specification

## 1. Executive Summary & Purpose

ForensiX V9 introduces the **Controlled Investigation Pipeline**, a production-grade orchestration layer built on top of the validated V1–V8 forensic engines. While previous versions provided isolated capabilities—host artifact collection (V2), timeline reconstruction (V3), correlation and detection (V4), PCAP network forensics (V5), memory triage (V6–V7), and Schema 8.0 chain-of-custody reporting (V8)—V9 unifies these domains into a single, deterministic, fail-safe investigation lifecycle.

A digital forensics investigation is governed by one immutable case configuration file (`case.json`) or equivalent command-line parameters. The pipeline runs each analytical stage in topological dependency order, enforces bitwise immutability of evidence inputs, guarantees output isolation, preserves cryptographically verifiable chain-of-custody tracking, and emits a standardized machine-readable run manifest (`pipeline_manifest.json`) alongside Schema 8.0 forensic reports.

---

## 2. Pipeline Architecture & Execution Flow

The investigation pipeline consists of 12 sequential stages executing in strict dependency order:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CONFIG_VALIDATION          Validate case metadata, paths, overlap guards │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. PREFLIGHT_VERIFICATION     Record SHA-256 baselines, verify manifest     │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. CUSTODY_INITIALIZATION     Initialize / resume Schema 8.0 custody ledger │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. HOST_ANALYSIS              V2.9 Triage (accounts, groups, logs, sudo)    │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. NETWORK_ANALYSIS           V5.3 PCAP streaming, flow & DNS extraction    │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. MEMORY_ANALYSIS            V6/V7 In-memory process, socket, module triage│
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. TIMELINE_RECONSTRUCTION    Cross-domain timeline normalization & dedupe  │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 8. CORRELATION                Host-Network & temporal pivot correlation     │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 9. DETECTION                  Canonical multi-domain detection rule engine  │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 10. REPORT_SYNTHESIS          Schema 8.0 Advanced Forensic Report (JSON/HTML│
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 11. CUSTODY_FINALIZATION      Record terminal hash, sign/finalize ledger    │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 12. RUN_MANIFEST              Emit machine-readable pipeline_manifest.json  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 12 Investigation Stages

| # | Stage ID (`PipelineStageId`) | Domain | Description & Contract |
|---|-----------------------------|--------|------------------------|
| 1 | `CONFIG_VALIDATION` | Core | Validates semantic correctness of `CaseConfig`, confirms existence of all declared evidence paths, and strictly forbids output directory overlap with any evidence tree. |
| 2 | `PREFLIGHT_VERIFICATION` | Forensics | Computes pre-execution SHA-256 hashes of discrete evidence files, checks output directory clobber guards, and optionally validates baseline evidence manifests (`verify_manifest`). |
| 3 | `CUSTODY_INITIALIZATION` | Custody | Instantiates a new cryptographically bound Schema 8.0 `CustodyLedger` or resumes an existing verified ledger; logs `EVIDENCE_RECEIVED` events for all evidence items with portable relative source paths. |
| 4 | `HOST_ANALYSIS` | Host | Executes `TriageOrchestrator` on the host root directory in binary read-only mode (`skip_reports=True`); adapts host artifacts to canonical `TimelineEvent`s. |
| 5 | `NETWORK_ANALYSIS` | Network | Streams packet headers and metadata from declared PCAP files using `PcapParser`; extracts application protocols (DNS, HTTP, TLS) and timeline events with pipeline wrapper source tagging. |
| 6 | `MEMORY_ANALYSIS` | Memory | Ingests memory artifact collections (processes, network connections, modules) via `load_memory_artifacts`; executes `run_memory_triage` and normalizes canonical timeline events. |
| 7 | `TIMELINE_RECONSTRUCTION` | Timeline | Combines raw events across all three domains into an ordered, deduplicated sequence via `reconstruct_timeline()`. |
| 8 | `CORRELATION` | Correlation | Executes temporal, identity, and host-network IP correlation across reconstructed events using `correlate_events()` and `correlate_host_network_events()`. |
| 9 | `DETECTION` | Detection | Evaluates declarative detection rules combining canonical host, network, and memory rule catalogs (`get_initial_rules()`, `create_canonical_network_rules()`, `create_canonical_memory_rules()`). |
| 10 | `REPORT_SYNTHESIS` | Reporting | Synthesizes an immutable Schema 8.0 `AdvancedReport` and writes requested formats (`report_<case>.json`, `report_<case>.html`) atomically. |
| 11 | `CUSTODY_FINALIZATION` | Custody | Appends `REPORT_GENERATED` event to custody ledger, records output SHA-256 digests, and persists the finalized custody ledger (`ledger_<case>.json`). |
| 12 | `RUN_MANIFEST` | Manifest | Compiles the comprehensive run record and writes `pipeline_manifest.json` into the output directory. |

---

## 4. Strict Forensic Guarantees

1. **Bitwise Evidence Immutability**:
   - Original evidence directories and files are accessed strictly in binary read-only mode (`"rb"`).
   - Pre-execution SHA-256 digests recorded during Stage 2 must remain bit-for-bit identical post-execution.
   - Verified by automated regression test `test_06_input_files_unchanged_after_run`.

2. **Output Isolation & Clobber Protection**:
   - The target output directory must never be identical to, or nested inside, any evidence directory.
   - If output files already exist and `overwrite` is `False`, the pipeline aborts cleanly in Stage 2 with exit code 4 (`EXIT_FILESYSTEM_IO_ERROR`), ensuring existing forensic reports are never silently clobbered.

3. **Fault Containment**:
   - Domain analysis failures (such as a corrupted PCAP or malformed memory artifact file) are caught and isolated within that stage.
   - The failing stage is marked `FAILED` or `PARTIAL`, an error is recorded in the manifest, and execution continues to downstream stages (timeline, reporting, custody).
   - If `fail_fast: true` is configured, execution halts immediately upon the first domain failure.

4. **Analytical Determinism & Per-Run Artifact Digests**:
   - **Input Fixture Determinism**: Input evidence fixtures (such as PCAPs, mock `/etc/passwd`, and logs) are generated deterministically and possess fixed, bitwise-reproducible cryptographic hashes.
   - **Per-Run Report & Ledger Digests**: Report (`.json`, `.html`) and custody ledger (`.json`) files include execution-specific metadata—such as `pipeline_run_id`, `report_id`, internal event/detection UUIDs, and generation timestamps. Consequently, output file SHA-256 hashes differ across independent runs.
   - **Analytical Invariance**: Given identical inputs and configuration, all forensic findings (event and record counts, detection names, rule evaluations, correlation graphs, and forensic explanations) are identical across runs.

---

## 5. Standard Exit Code Specification

The pipeline CLI conforms to the following exit code contract:

| Exit Code | Constant | Meaning |
|:---:|---|---|
| **0** | `EXIT_SUCCESS` | Complete success across all enabled stages; all evidence was verified and all reports were generated cleanly. |
| **1** | `EXIT_CONFIG_ERROR` | Semantic configuration error, missing required arguments, non-existent evidence paths, or output overlap violation. |
| **2** | `EXIT_VERIFICATION_OR_PARTIAL` | The run completed, but encountered either a **manifest verification discrepancy** (hash mismatch or missing baseline evidence) or **partial domain success** (one or more domain analysis stages recorded errors). |
| **3** | `EXIT_CUSTODY_FAILURE` | Cryptographic verification failed on an existing custody ledger, or ledger concurrency lock failed. |
| **4** | `EXIT_FILESYSTEM_IO_ERROR` | Output clobber collision (target files exist and `overwrite=False`), permission denied, or disk write failure. |

---

## 6. Run Record Specification (`pipeline_manifest.json`)

The run manifest is saved as strictly `pipeline_manifest.json` in the root of the output directory (with no case ID in the filename).

```json
{
  "run_id": "RUN-b69f5ceb-1a33-4ff7-bf0f-f21bf7c0c7b7",
  "forensix_version": "9.0.0",
  "started_at": "2026-10-21T06:18:58.123456+00:00",
  "completed_at": "2026-10-21T06:18:58.159678+00:00",
  "total_duration_seconds": 0.0362,
  "run_status": "SUCCESS",
  "case_id": "CASE-2026-SYNTHETIC-001",
  "case_name": "Synthetic Multi-Domain Forensic Investigation",
  "investigator": "Chief Digital Forensics Examiner",
  "stages": [
    {
      "stage_id": "config_validation",
      "status": "COMPLETED",
      "started_at": "2026-10-21T06:18:58.123500+00:00",
      "completed_at": "2026-10-21T06:18:58.123700+00:00",
      "duration_seconds": 0.0002,
      "records_produced": 3,
      "errors": [],
      "warnings": []
    }
  ],
  "generated_files": [
    {
      "relative_path": "report_CASE-2026-SYNTHETIC-001.json",
      "sha256": "47e79fede1f1c8f1a7201c648d600f819b76b66685cc0ec8e23ec07efbc5d3d6",
      "size_bytes": 9796,
      "file_type": "advanced_report_json"
    },
    {
      "relative_path": "report_CASE-2026-SYNTHETIC-001.html",
      "sha256": "842391502c65101b879449fa36e009634e6a02adec1ee64ad1ce92b74303b198",
      "size_bytes": 20316,
      "file_type": "advanced_report_html"
    },
    {
      "relative_path": "ledger_CASE-2026-SYNTHETIC-001.json",
      "sha256": "6bcd05ea5b09b774a27dcfba25136b3d14698d46b8ad51ea0d813d33d81231cd",
      "size_bytes": 4943,
      "file_type": "custody_ledger_json"
    }
  ],
  "evidence_digests": [
    ["memory_artifacts.json", "8f3b..."],
    ["traffic_incident.pcap", "4e7a..."]
  ]
}
```

---

## 7. Command-Line Interface (`forensix run`)

### 7.1 Running with Configuration File

```bash
forensix run --config examples/case-synthetic/case.json -o reports/ --overwrite
```

### 7.2 Running with Direct CLI Flags

```bash
forensix run \
  --case-id "CASE-2026-001" \
  --case-name "Incident Investigation" \
  --investigator "Lead Examiner" \
  --evidence-host-dir evidence/host/ \
  --evidence-pcap evidence/network/capture.pcap \
  --evidence-mem evidence/memory/artifacts.json \
  --output-dir reports/ \
  --overwrite
```

### 7.3 CLI Summary Display

Upon completion, `forensix run` prints a concise, formatted ASCII summary box:
```
==============================================================================
ForensiX V9 - Controlled Investigation Pipeline Execution Summary
==============================================================================
Case ID      : CASE-2026-SYNTHETIC-001
Case Name    : Synthetic Multi-Domain Forensic Investigation
Investigator : Chief Digital Forensics Examiner
Run ID       : RUN-b69f5ceb-1a33-4ff7-bf0f-f21bf7c0c7b7
Run Status   : SUCCESS
Duration     : 0.0396s
Version      : ForensiX 9.0.0
------------------------------------------------------------------------------
Stage Execution Summary:
  [01/12] CONFIG_VALIDATION ......... COMPLETED (0.0002s, 3 records)
  [02/12] PREFLIGHT_VERIFICATION .... COMPLETED (0.0002s, 2 records)
  [03/12] CUSTODY_INITIALIZATION .... COMPLETED (0.0033s, 3 records)
  [04/12] HOST_ANALYSIS ............. COMPLETED (0.0081s, 42 records)
  [05/12] NETWORK_ANALYSIS .......... COMPLETED (0.0014s, 6 records)
  [06/12] MEMORY_ANALYSIS ........... COMPLETED (0.0017s, 6 records)
  [07/12] TIMELINE_RECONSTRUCTION ... COMPLETED (0.0002s, 40 records)
  [08/12] CORRELATION ............... COMPLETED (0.0206s, 432 records)
  [09/12] DETECTION ................. COMPLETED (0.0011s, 7 records)
  [10/12] REPORT_SYNTHESIS .......... COMPLETED (0.0019s, 2 records)
  [11/12] CUSTODY_FINALIZATION ...... COMPLETED (0.0006s, 4 records)
  [12/12] RUN_MANIFEST .............. COMPLETED (0.0000s, 3 records)
------------------------------------------------------------------------------
Generated Artifacts & Cryptographic Digests:
  • report_CASE-2026-SYNTHETIC-001.json  (9.6 KB, advanced_report_json)
    SHA-256: 47e79fede1f1c8f1a7201c648d600f819b76b66685cc0ec8e23ec07efbc5d3d6
  • report_CASE-2026-SYNTHETIC-001.html  (19.8 KB, advanced_report_html)
    SHA-256: 842391502c65101b879449fa36e009634e6a02adec1ee64ad1ce92b74303b198
  • ledger_CASE-2026-SYNTHETIC-001.json  (4.8 KB, custody_ledger_json)
    SHA-256: 6bcd05ea5b09b774a27dcfba25136b3d14698d46b8ad51ea0d813d33d81231cd
==============================================================================
Final Exit Code : 0 (Status: SUCCESS)
==============================================================================
```

### 7.4 Sample Artifact Verification Note

> [!NOTE]
> The cryptographic digests shown above and stored in `docs/examples/case-synthetic/pipeline_manifest.json` represent the outputs of one specific reference execution run.
> 
> Because ForensiX embeds dynamic execution metadata into reports and ledgers (`pipeline_run_id`, `report_id`, internal event/detection UUIDs, and generation ISO timestamps), the output file SHA-256 hashes are per-run and will vary between independent invocations.
> 
> **How to verify sample reproducibility without relying on run-specific file hashes:**
> 1. **Record Counts**:
>    - Configuration records: `3`
>    - Preflight verification records: `2`
>    - Custody initialization records: `3`
>    - Host artifacts analyzed: `42`
>    - Network packets analyzed: `6`
>    - Memory artifacts analyzed: `6`
>    - Timeline events reconstructed: `40`
>    - Cross-domain correlations discovered: `432`
>    - Detections matched: `7`
>    - Custody finalization records: `4`
> 2. **Rule Evaluations & Detection Names**:
>    - `Baseline SSH Network Port Observation` (matched: `true`, 2 instances)
>    - `Repeated Failed SSH Attempts Followed by Successful SSH Login` (matched: `true`, 1 instance)
>    - `SSH Authentication Followed by Sudo` (matched: `true`, 3 instances)
>    - `Baseline Memory Process Name Observation (nc)` (matched: `true`, 1 instance)
> 3. **Input Integrity**:
>    - Evidence inputs (`traffic_incident.pcap`, `memory_artifacts.json`, `passwd`, `auth.log`) are generated deterministically and retain bit-for-bit identical hashes across all runs.
> 4. **Synthetic Case Timestamp Structure**:
>    - The synthetic sample intentionally mixes calendar years: network PCAP events and detections are dated `2025-10-21` and host authentication/sudo events are dated `2026-10-21`. The pipeline reads and processes each timestamp strictly as recorded; the mixed calendar years are an intentional property of the multi-source synthetic test data and do not represent a processing error.

