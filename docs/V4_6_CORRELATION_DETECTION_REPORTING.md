# ForensiX Milestone V4.6 — Correlation & Detection Reporting Specification

**Status**: IMPLEMENTED & VERIFIED  
**Milestone**: V4.6 (Internal Development Milestone)  
**Package Version**: `2.0.1` (Unchanged per milestone constraints)  
**Evidence Integrity**: `evidence/.gitkeep` SHA-256 unchanged (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)

---

## 1. Purpose & Architectural Position

Milestone **V4.6** adds structured reporting and presentation capabilities over the objects produced by upstream pipeline layers:
- **V3**: Timeline Reconstruction (`TimelineEvent`, `ReconstructedTimeline`)
- **V4.1**: Correlation Models (`Correlation`, `CorrelationCollection`)
- **V4.2**: Correlation Engine (`CorrelationEngine`, `correlation_sort_key`)
- **V4.3**: Rule Model (`DetectionRule`, `RuleCollection`, `RuleCondition`)
- **V4.4**: Detection Engine (`DetectionEngine`, `DetectionResult`, `detection_sort_key`)
- **V4.5**: Initial Detection Rules (`create_initial_rules`, canonical rules 1–4)

```
Evidence (V1)
   ↓
Host/System Analysis (V2)
   ↓
Timeline Reconstruction (V3)
   ↓
Correlation Engine (V4.1 & V4.2)
   ↓
Detection Engine & Initial Rules (V4.3, V4.4, V4.5)
   ↓
REPORTING (V4.6) ← CURRENT MILESTONE
   ↓
CLI / Triage Integration (V4.7 - NOT STARTED)
   ↓
Final Hardening (V4.8 - NOT STARTED)
```

### Architectural Separation
- **V4.2** discovers correlations.
- **V4.4** evaluates rules and generates detection results.
- **V4.6** ONLY presents, serializes, and formats existing objects without modifying evidence, re-evaluating conditions, or creating new correlation/detection semantics.

---

## 2. Reused Architecture from V3

V4.6 adheres strictly to the existing reporting conventions established in `src/forensix/timeline_reporting.py`:
1. **Timestamp Normalization**: Uses `format_iso_timestamp(..., use_z=True)` for UTC timestamps (`Z` suffix) while maintaining naive timestamps faithfully.
2. **Deterministic Serialization**: Custom serializers (`serialize_correlation`, `serialize_detection`, `serialize_timeline_event`) enforce stable dictionary structures, explicit `None` handling, and sorted nested attributes.
3. **HTML Security & Formatting**: All dynamic evidence-controlled strings are escaped via `html.escape(..., quote=True)` through `esc()`.
4. **Self-Contained Offline HTML**: Zero CDN or external dependencies. Dark-themed responsive styles embedded inline.

---

## 3. Correlation Reporting (`forensix.correlation_reporting`)

Provides structured reporting for discovered relationships:
- **`CorrelationReport`**: Deeply immutable dataclass containing metadata, summary statistics (`relationship_counts`), and deterministically ordered `correlations` (sorted via `correlation_sort_key`).
- **`serialize_correlation(correlation)`**: Converts a `Correlation` instance to a deterministic JSON-safe dictionary preserving:
  - `correlation_id`
  - `relationship_type`
  - `event_ids`
  - `source_event_ids`
  - `source_artifact_ids`
  - `start_timestamp`, `end_timestamp`, `time_delta_seconds`
  - `description`
  - `attributes`
- **Renderers & Writers**:
  - `generate_correlation_report(correlations, ...)`
  - `render_correlation_json(correlations, ...)`
  - `write_correlation_json_report(correlations, output_path, ...)`
  - `render_correlation_html(correlations, ...)`
  - `write_correlation_html_report(correlations, output_path, ...)`

---

## 4. Detection & Investigation Reporting (`forensix.detection_reporting`)

Provides reporting for rule evaluation results and end-to-end investigation traceability:

### Detection Reporting
- **`DetectionReport`**: Immutable dataclass containing metadata, rule counts, total detections, matched detections count, and sorted `DetectionResult` objects (ordered via `detection_sort_key`).
- **`serialize_detection(detection, event_map=None, corr_map=None)`**: Converts `DetectionResult` into a deterministic dictionary. If `event_map` or `corr_map` are supplied, resolves complete underlying objects into `correlations` and `supporting_events`.
- **Renderers & Writers**:
  - `generate_detection_report(detections, ...)`
  - `render_detection_json(detections, ...)`
  - `write_detection_json_report(detections, output_path, ...)`
  - `render_detection_html(detections, ...)`
  - `write_detection_html_report(detections, output_path, ...)`

### Integrated Investigation View (`CorrelationDetectionReport` / `InvestigationReport`)
Enables an investigator to navigate the full provenance chain:
$$\text{Detection} \longrightarrow \text{Matched Correlation} \longrightarrow \text{Supporting Timeline Events} \longrightarrow \text{Source Log Line / Artifact}$$

- **`CorrelationDetectionReport`**: Aggregate report tying together detections, correlations, and timeline events.
- **`generate_correlation_detection_report(detections, correlations, timeline, ...)`**: Generates the unified investigation report with deterministic sorting across all three collections.
- **Renderers & Writers**:
  - `render_correlation_detection_json(...)`
  - `write_correlation_detection_json_report(...)`
  - `render_correlation_detection_html(...)`
  - `write_correlation_detection_html_report(...)`

---

## 5. Provenance Handling & Strict Factuality

### Provenance Chain
All reports preserve factual provenance without guessing or inferring missing links:
- `detection_id` $\rightarrow$ `matched_correlation_ids`
- `correlation_id` $\rightarrow$ `event_ids`
- `event_id` $\rightarrow$ `source_event_id`, `source_artifact_id`, `source_path`, `source_line`

### Strict Non-Speculative Language
In compliance with ForensiX forensic guidelines, all reporting language is strictly observational (`observed`, `matched`, `associated`, `followed by`). Prohibited speculative terms (`compromised`, `attacker`, `malicious`, `threat actor`, `breach`, `intrusion`) are completely forbidden from appearing in default explanations or generated reports.

---

## 6. Determinism & Immutability

1. **Ordering Determinism**:
   - Timeline events are sorted by `timeline_sort_key`.
   - Correlations are sorted by `correlation_sort_key`.
   - Detections are sorted by `detection_sort_key`.
2. **Byte-for-Byte Reproducibility**: Repeated generation on identical input objects produces identical JSON and HTML output.
3. **Deep Immutability**: All input objects (`TimelineEvent`, `Correlation`, `DetectionResult`, collections) remain unchanged throughout serialization and rendering.

---

## 7. Mandatory Synthetic Investigation Traceability

The synthetic scenario specified in the milestone requirements was evaluated and validated:
1. `10:00`: SSH successful login (`alice`, `10.0.0.10`, `/var/log/auth.log:210`)
2. `10:02`: Sudo command execution (`alice`, `10.0.0.10`, `/var/log/auth.log:245`)
3. `10:03`: Persistence modification (`alice`, `/var/spool/cron/crontabs/alice:1`)
4. `10:10`: Unrelated SSH event (`bob`, `192.168.1.50`, `/var/log/auth.log:300`)

### Verification Result
- **Rule 1** (`SSH Authentication Followed by Sudo`) successfully matched.
- The generated report traced from:
  $$\text{DET-991dd89d-dcb8-5095-8da2-3d480f6d3dad}$$
  $$\downarrow$$
  $$\text{CORR-6149525b-9e7f-55f4-a622-695a9d208a56 (AUTHENTICATION\_PRIVILEGE)}$$
  $$\downarrow$$
  $$\text{Event } \mathtt{TIMELINE-8cbb2a89...} \text{ (/var/log/auth.log, Line 210)}$$
  $$\text{Event } \mathtt{TIMELINE-90db1f64...} \text{ (/var/log/auth.log, Line 245)}$$

---

## 8. Verification & Test Metrics

- **Unit Test Suite**: `tests/test_correlation_detection_reporting.py` (30 comprehensive tests covering all 33+ mandatory scenarios).
- **Full Test Suite (`pytest -q`)**: 843 passed, 198 subtests passed.
- **Full Test Suite (`unittest discover`)**: 843 tests passed.
- **Evidence Integrity**: SHA-256 hash of `evidence/.gitkeep` verified unchanged.

---

## 9. Explicit Scope Boundaries

- **V4.6 implemented ONLY**: Reporting for correlations and detections.
- **NOT implemented**:
  - V4.7 (CLI / Triage Integration)
  - V4.8 (Final Testing & Hardening)
  - Dashboards, web servers, or REST APIs
  - Machine learning / heuristic threat scoring
  - Memory or network forensics
