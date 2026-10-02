# ForensiX V3.7 — CLI Integration

## Purpose

The **Timeline CLI Integration** subsystem connects the complete ForensiX V3 timeline reconstruction, querying, and reporting pipeline to the command-line interface.

It allows forensic examiners and incident responders to:
1. Ingest evidence directories using the established ForensiX analysis workflow.
2. Adapt collected forensic records into immutable chronological `TimelineEvent` records (V3.3).
3. Reconstruct, order, and deduplicate events into a canonical timeline (V3.4).
4. Apply factual multi-criteria query filters (V3.5).
5. Generate structured JSON or self-contained HTML forensic timeline reports (V3.6).
6. Receive clear terminal execution status and deterministic report paths.

---

## Architectural Pipeline

The CLI acts purely as an orchestration layer, delegating forensic logic to existing V3 modules:

```text
Evidence Directory
        ↓
Existing Evidence Analysis (V2 Triage Orchestrator)
        ↓
Extracted Forensic Artifacts (HostArtifactCollection)
        ↓
V3.3 Artifact Adapters (Filesystem, Log, Auth)
        ↓
TimelineEvent Objects
        ↓
V3.4 Timeline Reconstruction (Order & Deduplication)
        ↓
V3.5 Timeline Querying (Optional Multi-Criteria AND Filters)
        ↓
V3.6 Timeline Reporting (Structured Model)
        ↓
JSON / HTML Reports on Disk
```

---

## Command Syntax

```bash
python3 -m forensix timeline <evidence_directory> [OPTIONS]
```

Or via direct module invocation:

```bash
python3 src/forensix/main.py timeline <evidence_directory> [OPTIONS]
```

---

## Supported Arguments & Options

### Positional Argument
* `evidence_directory`: Path to the directory containing evidence artifacts, logs, and files. Must be an existing directory.

### Metadata Options
* `--case-id <ID>`: Incident tracking identifier (e.g. `CASE-2026-001`).
* `--case-name <NAME>`: Human-readable title or description of the investigation.
* `--investigator <NAME>`: Name or identifier of the forensic investigator.

### Output Options
* `-o, --output <PATH>`: Explicit path for the generated report (e.g. `./reports/incident_timeline.html`).
* `--format <FORMAT>`: Output format (`html` or `json`). Defaults to `html`.

### Factual Query Filter Options (Logical AND)
All supplied filters are evaluated together using logical AND:

* `--start <TIMESTAMP>`: Earliest event timestamp (inclusive ISO 8601 string, e.g. `2026-09-30T09:00:00Z`).
* `--end <TIMESTAMP>`: Latest event timestamp (inclusive ISO 8601 string, e.g. `2026-09-30T17:00:00Z`).
* `--category <CATEGORY>`: Factual category filter. Valid choices: `FILESYSTEM`, `LOG`, `AUTHENTICATION`, `ACCOUNT`, `PERSISTENCE` (case-insensitive).
* `--event-type <TYPE>`: Exact match for event classification (e.g. `ssh_login`, `file_created`).
* `--source-path <PATH>`: Exact match for evidence source file path (e.g. `/var/log/auth.log`).
* `--source-artifact-id <ID>`: Filter events by parent forensic artifact tracking ID.
* `--source-event-id <ID>`: Filter events by underlying specialized event ID.
* `--text <SUBSTRING>`: Substring search across event descriptions, raw lines, and attributes.
* `--case-sensitive`: Enable case-sensitive text matching (default: case-insensitive).

---

## Usage Examples

### 1. Full Timeline Generation (HTML Default)
```bash
python3 -m forensix timeline ./evidence \
    --case-id CASE-2026-001 \
    --case-name "Server Compromise Triage" \
    --investigator "Examiner Alice"
```
Generates an interactive, dark-themed HTML report at `./reports/CASE-2026-001_timeline.html`.

### 2. Authentication Events Only (JSON Output)
```bash
python3 -m forensix timeline ./evidence \
    --category AUTHENTICATION \
    --format json \
    --output ./reports/auth_events.json
```
Filters events to authentication category only and writes a structured JSON report to `./reports/auth_events.json`.

### 3. Time Window Query with Combined Filters
```bash
python3 -m forensix timeline ./evidence \
    --start 2026-09-30T12:00:00Z \
    --end 2026-09-30T16:00:00Z \
    --event-type ssh_login \
    --source-path /var/log/auth.log \
    --format html \
    --output ./reports/ssh_window.html
```

### 4. Text Substring Search
```bash
python3 -m forensix timeline ./evidence \
    --text "sudoers" \
    --format json
```

---

## Error Handling & Exit Codes

The CLI validates all inputs cleanly without dumping Python stack traces on user errors:

* **Exit Code `0`**: Successful execution (even if a query matches zero events).
* **Exit Code `1`**: User input validation error, missing evidence path, unsupported format, or report writing failure.
* **Exit Code `2`**: Argument syntax error (handled by `argparse`).

### Common Validation Errors
* **Non-existent Evidence**:
  ```text
  Error: Evidence directory does not exist: './missing'
  ```
* **Invalid Category**:
  ```text
  Error: Invalid category: 'NETWORK'
  Valid categories:
    FILESYSTEM
    LOG
    AUTHENTICATION
    ACCOUNT
    PERSISTENCE
  ```
* **Unsupported Format**:
  ```text
  Error: Unsupported timeline format: 'pdf'. Supported formats: html, json
  ```
* **Invalid Timestamp Filter**:
  ```text
  Error: Invalid timeline filter: start timestamp cannot be greater than end timestamp
  ```

---

## Evidence Safety & Immutability

The timeline CLI operates in strict read-only mode:
* Original evidence files are never modified, renamed, or deleted.
* Evidence files are never executed as scripts or code.
* Generated reports are written exclusively to caller-specified paths or the dedicated `./reports/` directory. Attempting to target an output path inside the evidence directory is strictly rejected.
