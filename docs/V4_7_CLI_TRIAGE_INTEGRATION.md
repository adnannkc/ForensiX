# ForensiX Milestone V4.7 — CLI / Triage Integration Specification

## 1. Purpose & Overview

Milestone **V4.7 (CLI / Triage Integration)** provides a unified, deterministic, and evidence-safe command-line orchestration layer that executes the end-to-end ForensiX forensic investigation pipeline. 

V4.7 connects all preceding platform layers into a cohesive workflow without manual orchestration:
1. **V1 / V2 Evidence & Host Analysis**: Artifact collection and parsing.
2. **V3 Timeline Reconstruction**: Chronological event ordering and deduplication.
3. **V4.2 Event Correlation**: Deterministic relationship discovery.
4. **V4.5 Initial Detection Rules**: Declarative forensic pattern definitions.
5. **V4.4 Detection Engine**: Deterministic rule evaluation against events and correlations.
6. **V4.6 Correlation & Detection Reporting**: Serialization into structured JSON and self-contained HTML investigation reports.

### Strict Forensic Philosophy
- **Factual Observations**: Detections represent observed rule patterns, NOT automated proof of compromise, malware verdict, attacker attribution, or intent.
- **Evidence Safety**: Original forensic evidence is treated as strictly read-only; no files are added, modified, renamed, executed, or deleted within the evidence directory.
- **Determinism**: Identical inputs produce identical derived analytical results without random IDs, environment-dependent timestamps, or unstable sort orders.
- **Offline Operation**: Operates fully offline without network access, cloud APIs, or external threat intelligence feeds.

---

## 2. Command Syntax & Entry Points

ForensiX provides direct integration via two equivalent command-line entry points:

### Dedicated Investigation Command
```bash
python3 -m forensix investigate <evidence_directory> [OPTIONS]
```

### Integrated Triage Command
```bash
python3 -m forensix triage <evidence_directory> --v4 [OPTIONS]
```
*(Also activated if `--matched-only` is provided to `forensix triage`).*

### Backward Compatibility
Existing commands remain fully supported and unmodified:
- **V1 Single File Analysis**: `python3 -m forensix <evidence_file> [-o output_dir]`
- **V2.9 Host Triage**: `python3 -m forensix triage <evidence_directory> [-o output_dir] [--format json|csv|html] [--disable-stage STAGE]`
- **V3 Timeline Analysis**: `python3 -m forensix timeline <evidence_directory> [FILTERS] [-o output] [--format html|json]`

---

## 3. Pipeline Architecture

V4.7 acts purely as an orchestration layer over verified existing platform modules:

```text
Evidence Directory
        ↓
Stage 1: Evidence / Host Analysis (V1/V2 TriageOrchestrator)
        ↓
Stage 2: Timeline Reconstruction (V3.3 adapt_artifacts + V3.4 reconstruct_timeline)
        ↓
Stage 3: Event Correlation (V4.2 CorrelationEngine)
        ↓
Stage 4: Rule Loading (V4.5 get_initial_rules)
        ↓
Stage 5: Rule Evaluation (V4.4 DetectionEngine)
        ↓
Stage 6: Investigation Reporting (V4.6 CorrelationDetectionReport)
        ↓
Terminal Summary & Structured Output (JSON / HTML)
```

### Stage Details

| Stage | Module | Functionality Reused |
|---|---|---|
| **1. Evidence Analysis** | `forensix.triage_orchestrator` | `TriageOrchestrator` runs read-only extraction (`skip_reports=True`, `collect_audit=False`). |
| **2. Timeline Reconstruction** | `forensix.artifact_adapters`, `forensix.timeline_reconstruction` | `adapt_artifacts` maps artifacts to `TimelineEvent`s; `reconstruct_timeline` orders and deduplicates chronologically. |
| **3. Event Correlation** | `forensix.correlation_engine` | `CorrelationEngine().correlate()` identifies deterministic relationships (`SAME_USER`, `SAME_SOURCE`, `SAME_PATH`, `TEMPORAL`, `AUTHENTICATION_PRIVILEGE`). |
| **4. Initial Rules** | `forensix.initial_rules` | `get_initial_rules()` loads the 4 canonical declarative detection rules. |
| **5. Detection Evaluation** | `forensix.detection_engine` | `DetectionEngine(rules=rules).evaluate()` evaluates timeline events and correlations against rule conditions. |
| **6. Investigation Reporting** | `forensix.detection_reporting` | `generate_correlation_detection_report`, `write_correlation_detection_json_report`, and `write_correlation_detection_html_report` serialize the integrated report. |

---

## 4. Supported Options

| Option | Type | Default | Description |
|---|---|---|---|
| `evidence_directory` | Positional (`str`) | *Required* | Path to the forensic evidence directory to analyze. |
| `--case-id` | `str` | `None` | Case tracking identifier (e.g. `CASE-2026-001`). |
| `--case-name` | `str` | `None` | Human-readable title or description for the investigation. |
| `--investigator` | `str` | `None` | Forensic examiner or investigator identification. |
| `-o`, `--output`, `--output-dir` | `Path` | `reports/` | Destination file path or directory for generated reports. |
| `--format` | `str` | `html` | Report format selection (`html` or `json`). |
| `--json` | Flag | `False` | Shortcut for `--format json`. |
| `--html` | Flag | `False` | Shortcut for `--format html`. |
| `--matched-only` | Flag | `False` | Filter report to only include rules with positive matches (`matched=True`). |
| `--verbose` | Flag | `False` | Display stage-by-stage progress information to standard output. |
| `-v`, `--version` | Action | — | Display ForensiX version string and exit. |
| `-h`, `--help` | Action | — | Display comprehensive help and exit. |

---

## 5. Output Handling & Directory Safety

1. **Evidence Protection**:
   The CLI verifies that the resolved output destination path is neither identical to nor a child of the evidence directory. Attempting to write into evidence results in an immediate execution halt with exit code `1`.
2. **Deterministic Output Naming**:
   When `--output` is unspecified or specifies a directory, the CLI deterministically names the report:
   ```text
   <output_directory>/<sanitized_case_id>_investigation.<format>
   ```
   If no case ID is provided, the prefix defaults to `triage_investigation.<format>`.
3. **Format Inference**:
   If an explicit file path is provided via `--output` without `--format`, the format is inferred from the file extension (`.json` $\rightarrow$ JSON, `.html` / `.htm` $\rightarrow$ HTML).

---

## 6. Exit Codes & Error Handling

ForensiX defines deterministic, standard CLI exit codes:

| Exit Code | Meaning | Examples |
|---|---|---|
| `0` | **Success** | Pipeline completed successfully (even if matched detections == 0 or > 0). |
| `1` | **Input / Execution Error** | Evidence path missing, path is a regular file, invalid format, output inside evidence, analysis failure. |
| `2` | **Syntax Error** | Missing required positional argument or unrecognized CLI flag (argparse default). |

### Error Message Conventions
- Errors are emitted directly to `stderr` with a clean `Error: <message>` prefix.
- Normal forensic usage does not expose Python stack traces.
- Detections and rule matches are **not** errors; a dataset with 0 detections or 10 detections both exit with code `0`.

---

## 7. Terminal Summary

Upon successful pipeline completion, the CLI prints a factual, concise terminal summary:

```text
============================================================
ForensiX Incident Triage & Investigation (v2.0.1)
============================================================
Evidence Root           : /path/to/evidence
Case ID                 : CASE-2026-001
Case Name               : Corporate Intrusion Triage
Investigator            : Lead Analyst
Timeline Events         : 42
Correlations Identified : 18
Detection Results       : 3
Matched Detections      : 1
Rule Matches            :
  RULE-1-SSH-AUTH-SUDO: 1
Format                  : HTML
Report Path             : /path/to/reports/CASE-2026-001_investigation.html
------------------------------------------------------------
Status                  : SUCCESS
============================================================
```

### Prohibited Speculative Phrasing
CLI messages and reports strictly refrain from:
- "Attack detected!"
- "Host compromised!"
- "Attacker identified!"
- "Intrusion confirmed!"

---

## 8. Synthetic E2E & Negative Workflows

### Mandatory Positive End-to-End Test
- **Dataset**: Synthetic authentication log with an SSH authentication event followed within 60 seconds by a privileged `sudo` execution by the same user.
- **Pipeline Execution**: Reconstructs timeline, discovers `AUTHENTICATION_PRIVILEGE` correlation, evaluates Rule 1 (`SSH Authentication Followed by Sudo`), and produces a matched detection.
- **Result**: Exit code `0`, `matched_detections >= 1`, report contains full provenance chain from Detection $\rightarrow$ Correlation $\rightarrow$ Supporting Events $\rightarrow$ Source Artifact.
- **Evidence Immutability**: All evidence file SHA-256 hashes are verified identical before and after execution.

### Mandatory Negative End-to-End Test
- **Dataset**: Synthetic benign activity log (e.g. single scheduled backup login, cron job) with zero rule trigger conditions.
- **Pipeline Execution**: Reconstructs timeline, discovers non-triggering correlations, evaluates detection rules, produces 0 matches.
- **Result**: Exit code `0`, `matched_detections == 0`, valid report generated, evidence untouched.

---

## 9. Verification & Regression Coverage

The V4.7 implementation is verified across 879 total test cases (36 dedicated V4.7 integration tests and 843 regression tests):
- Unit & E2E Tests: `tests/test_v47_cli_triage.py` (36 tests)
- V1 Evidence Foundation regression: `tests/test_cli.py`, `tests/test_evidence.py`
- V2 Host Forensics regression: `tests/test_triage_cli.py`, `tests/test_triage_orchestrator.py`
- V3 Timeline regression: `tests/test_timeline_cli.py`, `tests/test_timeline_reconstruction.py`
- V4.1 Correlation Model regression: `tests/test_correlation_models.py`
- V4.2 Correlation Engine regression: `tests/test_correlation_engine.py`
- V4.3 Rule Model regression: `tests/test_rule_models.py`
- V4.4 Detection Engine regression: `tests/test_detection_engine.py`
- V4.5 Initial Rules regression: `tests/test_initial_rules.py`
- V4.6 Reporting regression: `tests/test_correlation_detection_reporting.py`

---

## 10. Explicit Scope Boundary & Milestone V4.8 Hand-off

### Included in V4.7
- Pure CLI orchestration of V1–V4.6 pipeline.
- Safe output directory handling and evidence immutability checks.
- Structured JSON and self-contained HTML report generation.
- Factual terminal summaries and exit-code semantics.

### Excluded from V4.7 (Reserved for V4.8 or Later)
- Comprehensive final hardening and fuzz testing campaigns (Milestone V4.8).
- Web dashboards, REST APIs, or background daemon services.
- Real-time event streaming or network packet capture analysis.
- Live system artifact acquisition or write-back remediation.
