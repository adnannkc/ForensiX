# ForensiX V3.2 — Timestamp Normalization

This document describes the **Timestamp Normalization Engine (`timestamp_normalizer`)** introduced in **ForensiX V3.2 (Timeline Reconstruction)**.

---

## 1. What Timestamp Normalization Means

Timestamp normalization is the deterministic process of interpreting valid forensic timestamp representations from heterogeneous sources and mapping them into a single canonical internal format (`datetime` object and standardized ISO 8601 string) while preserving the original raw string representation.

In digital forensics:
```text
Raw timestamp (e.g. "2026-09-30 14:30:00 +0530")
      ↓
Timestamp normalization (normalize_timestamp / parse_timestamp)
      ↓
Canonical representation (2026-09-30T09:00:00Z UTC datetime)
      ↓
TimelineEvent (timestamp + raw_timestamp)
```

---

## 2. Why Timestamp Normalization Is Needed

Forensic evidence collected from multi-source host environments contains timestamps in disparate formats, representations, and reference offsets:
- System logs may emit ISO 8601 strings (`2026-09-30T14:30:00Z`).
- Web servers or databases may emit space-separated strings (`2026-09-30 14:30:00+05:30`).
- Local application logs may emit timezone-naive strings (`2026-09-30 14:30:00`).
- Forensic tools may pass native Python `datetime` objects.

To reconstruct a truthful timeline across systems and timezones, events must be comparable along an unambiguous temporal axis. Without normalization:
- Events recorded in `+05:30` and `UTC` cannot be accurately sequenced.
- Chronological ordering would either produce incorrect sequences or fail entirely.
- Inconsistent parsing across modules could lead to non-deterministic investigation results.

ForensiX V3.2 provides a centralized, deterministic, and forensically sound module that bridges raw evidence timestamps and `TimelineEvent` records.

---

## 3. Supported Timestamp Formats

ForensiX V3.2 strictly parses formats that can be resolved deterministically without guessing or heuristics:

1. **ISO 8601 Datetime Strings**:
   - `2026-09-30T14:30:00Z`
   - `2026-09-30T14:30:00z`
   - `2026-09-30T14:30:00+05:30`
   - `2026-09-30T14:30:00-04:00`
   - `2026-09-30T14:30:00` (naive)
2. **Common Space-Separated Datetime Representations**:
   - `2026-09-30 14:30:00`
   - `2026-09-30 14:30:00+05:30`
   - `2026-09-30 14:30:00 +0530` / `2026-09-30 14:30:00 -0400`
   - `2026-09-30 14:30:00 UTC` / `2026-09-30 14:30:00 utc`
3. **Common Slash-Separated Datetimes**:
   - `2026/09/30 14:30:00`
4. **Sub-second Precision**:
   - Millisecond precision: `2026-09-30T14:30:00.123Z`
   - Microsecond precision: `2026-09-30T14:30:00.123456Z`
5. **Python `datetime` Objects**:
   - Timezone-aware `datetime` instances (e.g. `datetime(2026, 9, 30, 14, 30, tzinfo=...)`)
   - Timezone-naive `datetime` instances (e.g. `datetime(2026, 9, 30, 14, 30)`)

---

## 4. Timezone Handling: Aware vs Naive

A foundational forensic principle is: **Never fabricate timezones or infer missing information.**

### Timezone-Aware Timestamps
When an input explicitly specifies a timezone offset (e.g. `Z`, `+05:30`, `-04:00`, `UTC`):
- By default (`to_utc=True`), the normalizer deterministically converts the instant to UTC (`datetime.timezone.utc`).
- Example: `"2026-09-30 14:30:00 +0530"` becomes `2026-09-30 09:00:00+00:00`.
- The original raw representation is retained verbatim.
- If `to_utc=False` is requested, the original explicit offset is preserved.

### Timezone-Naive Timestamps
When an input does **not** specify a timezone offset (e.g. `"2026-09-30 14:30:00"`):
- The normalizer **DOES NOT** assume the local system timezone.
- The normalizer **DOES NOT** assume UTC.
- The resulting `datetime` object strictly has `tzinfo = None`.
- The absence of timezone information is explicitly maintained to prevent falsifying forensic evidence.

---

## 5. Precision Handling

Forensic log analysis requires preserving exact fractional second resolution:
- Microsecond and millisecond precisions are preserved intact up to Python's microsecond resolution.
- No arbitrary truncation or rounding is applied.
- `format_iso_timestamp()` preserves non-zero microsecond components (e.g. `2026-09-30T14:30:00.123456Z`).

---

## 6. Invalid and Ambiguous Input Handling

ForensiX fails safely and explicitly on invalid, incomplete, or ambiguous inputs:

1. **Date-Only Strings (Rejected)**:
   - Strings such as `"2026-09-30"` are explicitly rejected with a `ValueError`.
   - Normalizing a date without a time to midnight (`00:00:00`) fabricates an event time that did not occur.
2. **Yearless Timestamps (Rejected)**:
   - BSD syslog timestamps without years (e.g. `"Oct 1 14:30:00"`) cannot be parsed without external context.
   - Guessing the current year or host year violates determinism; hence they are rejected at this normalization layer.
3. **Invalid Calendar Dates & Times (Rejected)**:
   - `"2026-02-30"`, `"2026-13-01"`, `"2026-09-30 25:00:00"` raise `ValueError`.
4. **Malformed Offsets (Rejected)**:
   - Offsets such as `+25:00` or non-numeric offsets raise `ValueError`.
5. **Empty, Whitespace, None, or Invalid Types**:
   - `""`, `"   "`, `None` raise `ValueError` (or `TypeError` for non-string/non-datetime objects).

---

## 7. Preservation of Original Raw Timestamps

Forensic integrity requires that the original representation remains verifiable:
- `parse_timestamp()` returns a `NormalizedTimestamp` object containing both:
  - `normalized_datetime`: The canonical `datetime`.
  - `raw_timestamp`: The exact input string (or `.isoformat()` if input was a `datetime`).
  - `is_timezone_aware`: Boolean flag indicating if timezone information was present.
  - `original_tz_offset`: The original offset string (e.g. `"+05:30"`), if present.
- In `TimelineEvent`, the normalized datetime populates `timestamp`, while the raw string populates `raw_timestamp`.

---

## 8. What V3.2 Does NOT Do

To maintain strict modularity, V3.2 is confined solely to timestamp normalization:
- **NO Artifact Adapters**: Adapting specific V2 artifacts into timeline events belongs to V3.3.
- **NO Timeline Reconstruction**: Multi-source timeline building belongs to V3.4.
- **NO Event Ordering or Deduplication**: Sorting and deduplication belong to V3.4.
- **NO Timeline Querying or Filtering**: Query facilities belong to V3.5.
- **NO Timeline Reporting**: Timeline report generators belong to V3.6.
- **NO CLI Integration**: Timeline CLI commands belong to V3.7.
- **NO Forensic Interpretation**: No malware classification, threat detection, risk scoring, or compromise assessment.
