# ForensiX V3.1 — Timeline Event Model

This document describes the foundational **Timeline Event Model (`TimelineEvent`)** introduced in **ForensiX V3.1 (Timeline Reconstruction)**.

---

## 1. What `TimelineEvent` Represents

A `TimelineEvent` represents **one discrete, chronological forensic observation** extracted from evidence.

In digital forensics and incident response, an investigation revolves around answering:
1. **What happened?** (`description`, `event_type`)
2. **When did it happen?** (`timestamp`, `raw_timestamp`)
3. **What category of activity was it?** (`category`, `event_type`)
4. **Where was the observation recorded?** (`source_path`, `source_line`)
5. **Which V2 artifact or event produced it?** (`source_artifact_id`, `source_event_id`)
6. **What underlying evidence supports it?** (`raw_data`, `attributes`)

The `TimelineEvent` model captures these answers into a single, standardized, and immutable data structure.

---

## 2. Why `TimelineEvent` Exists

In ForensiX V2, specialized analyzers parsed individual evidence sources into domain-specific records:
- Filesystem artifacts (`ArtifactRecord`)
- Syslog and service log lines (`LogEvent`)
- Authentication records (`AuthenticationRecord`)
- User accounts, groups, shadow entries, sudo rules, and SSH keys (`UserAccount`, `GroupRecord`, etc.)
- Persistence configurations (`PersistenceRecord`)

While V2 unified these artifacts into `HostArtifact` for query and reporting, each source remained structured according to its original forensic domain.

ForensiX V3 introduces **Timeline Reconstruction**. To reconstruct an event timeline across disparate sources (e.g. correlating a user login in `/var/log/auth.log` with a file write in `/etc/cron.d/` and a password change in `/etc/shadow`), ForensiX requires a single canonical model focused on **chronological observation**.

---

## 3. How It Relates to V2 Models

`TimelineEvent` does not replace V2 models, nor does it duplicate raw file parsing. Instead, it follows a strict layered architecture:

```
Raw Evidence Files
       ↓
Specialized V2 Analyzers (LogParser, AuthAnalyzer, AccountAnalyzer, PersistenceAnalyzer)
       ↓
Structured V2 Models (LogEvent, AuthenticationRecord, UserAccount, PersistenceRecord, HostArtifact)
       ↓
TimelineEvent (V3.1 foundational model)
       ↓
Future Timeline Reconstruction Engine (V3.2+)
```

Key relationship points:
- **V2 models provide the forensic facts**: V2 analyzes raw logs and configuration files. V3 consumes these parsed models to generate timeline representations.
- **Traceability references**: A `TimelineEvent` points back to its originating V2 entities via identifiers rather than embedding large copies of V2 models:
  - `source_artifact_id`: points to the evidence file artifact (`ART-...`)
  - `source_event_id`: points to the specialized record (e.g. `AUTH-...`, `LOG-...`, `EVT-...`, `USER-...`, `PERSIST-...`)
- **Factual fidelity**: The raw timestamp string (`raw_timestamp`) and raw record line (`raw_data`) are preserved directly from V2 models to maintain an unassailable evidentiary chain.

---

## 4. Why Source IDs Are Preserved

In forensic science and legal proceedings, **chain of custody and audit provenance** are paramount.

- Every `TimelineEvent` receives its own unique identifier (`TIMELINE-<UUIDv4>`).
- However, the timeline event's ID **never overwrites or masks** the source artifact ID (`source_artifact_id`) or source event ID (`source_event_id`).
- When an examiner views an event on the timeline (e.g. `TIMELINE-8f23...`), they can trace it directly back to:
  1. The specialized record (e.g. `AUTH-3b1a...`),
  2. The parent evidence artifact (e.g. `ART-1a2b...`),
  3. The exact file path and line number (e.g. `/var/log/auth.log:42`),
  4. The cryptographic hashes and registration metadata of the physical evidence container.

If an event did not originate from a specialized source event or artifact, ForensiX records `None`—**no fake or speculative source IDs are ever fabricated**.

---

## 5. Why It Does Not Perform Correlation or Detection

`TimelineEvent` is an **observational data model**, not an analytical detector or correlation engine:

- **Separation of Facts from Conclusions**:
  - Forensics distinguishes between *what was observed* (e.g., "Accepted publickey for ubuntu") and *what an investigator concludes* (e.g., "Attack detected" or "Lateral movement").
  - `TimelineEvent` models strictly *what was observed*.
- **No speculative event types**:
  - Valid: `ssh_login_success`, `file_modified`, `user_account_entry`, `cron_job_scheduled`.
  - Disallowed: `attack_detected`, `compromise_confirmed`, `malware_executed`, `anomaly_detected`.
- **No risk or threat scores**:
  - The model does not include fields like `risk_score`, `severity`, `threat_level`, `is_malicious`, or `confidence`.
- **Event Correlation and Rule Detection belong to ForensiX V4**:
  - V3 focuses exclusively on chronological reconstruction.
  - V4 will later consume reconstructed timelines to perform rule-based detection, multi-source event correlation, and attack-path analysis.

---

## 6. What V3.1 Intentionally Does Not Implement

In accordance with strict milestone scoping, V3.1 implements **only the foundational event model**. It intentionally does **not** implement:

1. **Timestamp Normalization Engine**: V3.1 does not guess years for incomplete BSD syslog timestamps or perform complex multi-timezone shifting (scheduled for V3.2).
2. **V2-to-Timeline Adapters**: Translating V2 `HostArtifact`, `LogEvent`, `AuthenticationRecord`, etc., into `TimelineEvent` streams will occur in subsequent V3 milestones.
3. **Chronological Sorting & Merging Engine**: Sorting across heterogeneous sources and handling out-of-order events is deferred to the timeline engine milestone.
4. **Timeline Query Layer**: Filtering timelines by time windows, categories, or entities.
5. **Timeline Reporting Integration**: Adding timeline views to JSON, CSV, or HTML reports.
6. **CLI or Orchestrator Changes**: The 9-stage V2 triage pipeline remains completely unmodified.

---

## 7. Model Specification Summary

| Field | Type | Description |
|---|---|---|
| `event_id` | `str` | Unique identifier formatted as `TIMELINE-<UUIDv4>`. |
| `timestamp` | `Optional[datetime]` | Chronological timestamp as typed datetime, or `None` if unknown. |
| `raw_timestamp` | `Optional[str]` | Raw timestamp string exactly as observed in evidence (or `None`). |
| `category` | `TimelineCategory` | Broad source category: `FILESYSTEM`, `LOG`, `AUTHENTICATION`, `ACCOUNT`, `PERSISTENCE`. |
| `event_type` | `str` | Factual classification string representing the specific observation. |
| `description` | `str` | Human-readable factual summary of the observation. |
| `source_path` | `Optional[str]` | Canonical evidence-relative path where the observation occurred. |
| `source_line` | `Optional[int]` | 1-indexed source line number (`>= 1`, accessible also via `.line_number`). `0` is rejected. |
| `source_artifact_id` | `Optional[str]` | Traceable parent artifact ID (`ART-...`), or `None`. |
| `source_event_id` | `Optional[str]` | Traceable specialized event ID (`LOG-...`, `AUTH-...`, etc.), or `None`. |
| `raw_data` | `Optional[str]` | Raw unparsed evidence line or text (accessible also via `.raw_line`). |
| `attributes` | `Tuple[Tuple[str, Any], ...]` | Deeply immutable key-value pairs of auxiliary factual attributes. |

### Serialization (`to_dict()`)

`TimelineEvent.to_dict()` outputs a deterministic, JSON-serializable dictionary with sorted attribute keys, explicit `None` representations for omitted optional fields, and strict preservation of legitimate falsy attribute values (`False`, `0`, `""`, `[]`).
