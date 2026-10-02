# ForensiX V3.3 — Artifact Adapters

This document describes the **Artifact Adapter Layer (`artifact_adapters`)** introduced in **ForensiX V3.3 (Timeline Reconstruction)**.

---

## 1. Purpose

In digital forensics, evidence is gathered across diverse domains: filesystem metadata, system logs, authentication activity, user account records, and persistence configurations. In ForensiX V1 and V2, specialized analyzers and parsers produced domain-specific data structures (`ArtifactRecord`, `LogEvent`, `AuthenticationRecord`, `HostArtifact`, etc.).

To reconstruct chronological timelines (V3), ForensiX requires a standardized transformation layer that translates factual evidence structures into canonical V3.1 `TimelineEvent` records without modifying the source models or introducing speculative inferences.

**ForensiX V3.3 solves this by providing a clean, deterministic adapter layer:**
- Accepts supported forensic artifacts.
- Extracts factual observations and timestamps.
- Employs the V3.2 `timestamp_normalizer` to normalize timestamps deterministically.
- Returns immutable `TimelineEvent` records that retain full evidentiary provenance.

---

## 2. Architecture

The adapter layer implements the pipeline:

```text
Forensic Artifact (ArtifactRecord, LogEvent, AuthenticationRecord, HostArtifact)
       ↓
Artifact Adapter (FilesystemAdapter, LogAdapter, AuthenticationAdapter)
       ↓
Timestamp Normalization (timestamp_normalizer.parse_timestamp)
       ↓
TimelineEvent (V3.1 Immutable Model)
```

### Architectural Principles:
1. **Extraction and Translation, Not Interpretation**:
   Adapters extract observed facts (file timestamps, log lines, authentication events). They never determine whether an event is malicious, suspicious, an attack, or an incident.
2. **Never Fabricate Timestamps**:
   Events are emitted **only** when a factual timestamp is present in the evidence. If an optional timestamp is absent (e.g. file birth time `created = None`), no event is created for it.
3. **Strict Provenance Retention**:
   Every generated `TimelineEvent` preserves `source_path`, `source_line`, `source_artifact_id`, `source_event_id`, and `raw_data` to ensure a legally sound, verifiable evidentiary chain.
4. **Deterministic Output**:
   Given identical inputs, adapters always emit identical event contents and sequences.

---

## 3. Supported Adapters

ForensiX V3.3 implements the following adapters under `forensix.artifact_adapters`:

### 1. `FilesystemAdapter`
Adapts filesystem artifacts and metadata records into `TimelineEvent` observations.
- **Supported Inputs**:
  - `ArtifactRecord` (V2.1 filesystem artifact record)
  - `ForensicAnalysisResult` (V1 unified analysis result)
  - `FileMetadata` (V1 filesystem metadata record)
  - `HostArtifact` with category `filesystem` or wrapping an `ArtifactRecord`
  - Dictionaries containing filesystem metadata (`source_path` or `path`, along with timestamp fields)

### 2. `LogAdapter`
Adapts parsed Linux log records into `TimelineEvent` observations.
- **Supported Inputs**:
  - `LogEvent` (V2.2 parsed log event)
  - `HostArtifact` with category `log` or wrapping a `LogEvent`
  - Dictionaries containing log event fields (`source_path`, `event_type`, `raw_message`, etc.)

### 3. `AuthenticationAdapter`
Adapts structured authentication activity records into `TimelineEvent` observations.
- **Supported Inputs**:
  - `AuthenticationRecord` (V2.3 authentication activity record)
  - `HostArtifact` with category `authentication` or wrapping an `AuthenticationRecord`
  - Dictionaries containing authentication record fields (`auth_id`, `source_path`, `event_type`, etc.)

### 4. Polymorphic Dispatcher (`adapt_artifact` / `adapt_artifacts`)
- `can_adapt_artifact(artifact)`: Inspects artifact type and returns boolean support.
- `adapt_artifact(artifact)`: Automatically dispatches to the correct specialized adapter.
- `adapt_artifacts(artifacts, ignore_unsupported=False)`: Adapts a sequence of artifacts preserving input order without sorting or deduplication.

---

## 4. Event Mapping

Adapters map factual forensic timestamps to descriptive, non-speculative event types:

### Filesystem Event Mappings

| Source Timestamp Field | Generated `event_type` | Category | Description Pattern |
|---|---|---|---|
| `created` / `birthtime` / `crtime` | `file_created` | `FILESYSTEM` | `File created: <source_path>` |
| `modified` / `mtime` | `file_modified` | `FILESYSTEM` | `File modified: <source_path>` |
| `accessed` / `atime` | `file_accessed` | `FILESYSTEM` | `File accessed: <source_path>` |
| `ctime` / `metadata_changed` | `file_metadata_changed` | `FILESYSTEM` | `File metadata changed: <source_path>` |

When an artifact contains multiple factual timestamps (e.g. a file with `created`, `modified`, and `accessed`), separate events are emitted in canonical order:
1. `file_created`
2. `file_modified`
3. `file_accessed`
4. `file_metadata_changed`

Each event maintains the same source provenance (`source_path`, `source_artifact_id`, file attributes).

### Log Event Mappings

| Source Model Field | Generated `TimelineEvent` Property |
|---|---|
| `evt.event_type` | `event_type` (e.g. `ssh_login_success`, `session_open`, `sudo_command`, `generic_syslog`) |
| `evt.raw_message` | `description` |
| `evt.normalized_timestamp` / `evt.raw_timestamp` | `timestamp` (normalized datetime) and `raw_timestamp` (verbatim string) |
| `evt.source_path` | `source_path` |
| `evt.line_number` | `source_line` |
| `evt.source_artifact_id` | `source_artifact_id` |
| `evt.event_id` | `source_event_id` |
| `evt.raw_line` | `raw_data` |
| `evt.attributes` + `service`, `pid`, `hostname` | `attributes` |

### Authentication Event Mappings

| Source Model Field | Generated `TimelineEvent` Property |
|---|---|
| `auth.event_type` | `event_type` (e.g. `ssh_login_success`, `ssh_login_failure`, `session_open`, `sudo_command`) |
| `auth.raw_message` | `description` |
| `auth.normalized_timestamp` / `auth.raw_timestamp` | `timestamp` (normalized datetime) and `raw_timestamp` (verbatim string) |
| `auth.source_path` | `source_path` |
| `auth.line_number` | `source_line` |
| `auth.source_artifact_id` | `source_artifact_id` |
| `auth.auth_id` | `source_event_id` |
| `auth.raw_line` | `raw_data` |
| `auth.attributes` + `username`, `source_ip`, `status`, etc. | `attributes` |

---

## 5. Timestamp Normalization Integration

The adapter layer uses the V3.2 `timestamp_normalizer` module (`parse_timestamp`) exclusively:
- **No Redundant Timestamp Parsers**: Timestamp parsing logic is never re-implemented in adapters.
- **Timezone-Aware Timestamps**: Normalized deterministically to UTC (`datetime.timezone.utc`). The original representation is preserved in `raw_timestamp`.
  - Example: `"2026-09-30T14:30:00+05:30"` → `timestamp = 2026-09-30 09:00:00+00:00`, `raw_timestamp = "2026-09-30T14:30:00+05:30"`.
- **Timezone-Naive Timestamps**: Preserved strictly as naive (`tzinfo = None`). Never assumed to be local time or UTC.
  - Example: `"2026-09-30 14:30:00"` → `timestamp = 2026-09-30 14:30:00`, `raw_timestamp = "2026-09-30 14:30:00"`.
- **Incomplete / Yearless Timestamps**: For yearless BSD syslog lines without year, `timestamp` remains `None` without guessing a year, while `raw_timestamp` retains the raw evidence string.
- **Date-Only Timestamps**: Rejected with `ValueError` to prevent fabricating midnight.
- **Malformed Timestamps**: Rejected with `ValueError`.

---

## 6. Provenance Retention

Every adapted `TimelineEvent` retains full forensic traceability:
- `source_path`: Canonical path of the originating evidence file.
- `source_line`: Line number for line-based sources (logs, authentication), or `None` for file-level records.
- `source_artifact_id`: Parent artifact ID (`ART-...` or `EV-...`).
- `source_event_id`: Specialized record ID (`EVT-...` for logs, `AUTH-...` for authentication).
- `raw_data`: Complete unparsed raw line preserving verbatim evidence for line-based artifacts.
- `attributes`: Deeply immutable key-value pairs capturing factual attributes (permissions, file size, hashes, usernames, IP addresses, service names).

---

## 7. Artifact Provenance: V2 Run-Specific Artifact IDs vs. Deterministic V3 Timeline Provenance

### Distinction & Provenance Semantics
1. **V2 Run-Specific Artifact IDs (`ART-<UUIDv4>`)**:
   - In ForensiX V2, the filesystem scanner assigns each scanned artifact an ephemeral `artifact_id` generated via `generate_artifact_id()` (`ART-<UUIDv4>`).
   - This design tracks distinct scan sessions and runtime evidence collections within V2 triage reports.
   - V2 scanner behavior and `generate_artifact_id()` remain completely unchanged to preserve backwards compatibility with existing V2 tests, models, and serializations.

2. **Deterministic V3 Timeline Provenance (`ART-<UUIDv5>`)**:
   - ForensiX V3 timeline reconstruction requires full determinism across repeated, independent runs against identical evidence. Exposing V2's run-specific UUIDv4 directly in `TimelineEvent.source_artifact_id` introduces nondeterminism across runs.
   - In V3.3, `TimelineEvent.source_artifact_id` is computed deterministically via `compute_deterministic_artifact_id()` using RFC 4122 Version 5 UUID (SHA-1 name-based hashing) within the ForensiX V3 artifact namespace (`https://forensix.local/v3/artifact`).
   - The identity is derived strictly from immutable evidence facts available at the V3 boundary:
     - The normalized relative path within the evidence container (e.g. `var/log/auth.log` or `etc/passwd`), falling back to normalized `source_path`.
     - The cryptographic content digest (SHA-256) where available.
   - Identical facts across independent scans always produce the identical `source_artifact_id`.
   - Different evidence facts (different paths or modified file content) never collapse.

3. **Traceability Preservation**:
   - To preserve complete audit lineage without discarding V2 provenance, the original V2 scanner `artifact_id` is retained in `TimelineEvent.attributes` under the key `v2_artifact_id`.
   - In `adapt_artifacts()`, dependent log events (`LogEvent`) and authentication records (`AuthenticationRecord`) have their `source_artifact_id` resolved to the parent log file's deterministic V3 artifact ID, ensuring cross-subsystem provenance consistency.

---

## 8. Safety Boundaries

In strict compliance with milestone boundaries, **ForensiX V3.3 does NOT implement**:
- **Threat Detection or Risk Scoring**: No `risk_score`, `severity`, `threat_level`, or maliciousness assessments.
- **Attacker Intent Inference**: No speculative event types (e.g. `malware_executed`, `attack_detected`).
- **Timeline Reconstruction & Correlation**: Multi-source sorting, chronological alignment, event deduplication, and causality analysis belong to **V3.4**.
- **Timeline Querying & Filtering**: Search and windowing APIs belong to **V3.5**.
- **Timeline Reporting**: HTML, CSV, and JSON timeline reports belong to **V3.6**.
- **CLI Timeline Integration**: Timeline CLI commands belong to **V3.7**.

---

## 9. Future Work

Subsequent milestones in ForensiX V3 will consume the output of this adapter layer:
- **V3.4 (Timeline Reconstruction, Ordering & Deduplication)**: Consumes adapted `TimelineEvent` streams, resolves timestamp comparability, sorts events chronologically, and deduplicates multi-source representations.
- **V3.5 (Timeline Query & Filtering Engine)**: Provides querying across event types, timestamps, categories, and entities.
- **V3.6 (Timeline Reporting)**: Renders timeline views in triage reports.
- **V3.7 (CLI Integration)**: Exposes timeline workflows in the ForensiX CLI.
- **V3.8 (Determinism & Safety Verification)**: End-to-end verification across the entire V3 milestone suite.
