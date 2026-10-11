# ForensiX V5.9 — Reporting and Hardening

This document details the final development milestone of ForensiX V5: **Reporting Integration and Forensic Hardening**. It unites the network evidence models, PCAP parsing, protocol metadata extraction, timeline integration, correlation, detection rules, and CLI workflows into a defensible, factually neutral reporting system with comprehensive forensic hardening.

---

## 1. Overview and Architecture

ForensiX V5.9 completes the local V5 milestone cycle by integrating network evidence directly into the established V4 investigation reporting architecture (`CorrelationDetectionReport` / `InvestigationReport`) in both JSON and HTML formats.

Rather than introducing a parallel reporting engine or duplicative schemas, V5.9 extends the canonical reporting foundation:
- Schema: Preserves V4 report structure (schema v4.6) while safely accommodating network timeline events, correlations, and detection records.
- Provenance: Exposes packet frame numbers, wire-level record IDs, timestamps (with microsecond precision), endpoints, protocol dissections, and correlated host-network observations.
- Defensive Hardening: Enforces strict HTML escaping for untrusted network packet payloads and metadata, redacts sensitive HTTP credentials and authorization headers by default, bounds memory allocations, guarantees read-only evidence immutability, and isolates report output paths from evidence directories.

```
                           [ Local Evidence ]
                        (PCAP / Host Artifacts)
                                   |
                         Triage / Investigation
                                   |
                  +----------------+----------------+
                  |                                 |
         [ Timeline Events ]              [ Correlation & Detections ]
      (Host Logs + Network Packets)       (SAME_SRC, TEMPORAL, Rules)
                  |                                 |
                  +----------------+----------------+
                                   |
                     CorrelationDetectionReport (v4.6)
                 + limitations: Sequence[str]
                 + errors: Sequence[str]
                                   |
                 +-----------------+-----------------+
                 |                                   |
       render_correlation_json            render_correlation_html
       - Canonical schema v4.6            - Sanitized & HTML-escaped
       - Complete metadata & attrs        - Provenance (Frame: <N>)
       - Sensitive header redaction       - Diagnostics & limitations card
```

---

## 2. Reporting Integration and Reused Components

ForensiX V5.9 reuses existing reporting components in `src/forensix/detection_reporting.py`:

1. **`CorrelationDetectionReport`**:
   - Extended with optional `limitations: Tuple[str, ...]` and `errors: Tuple[str, ...]` fields (default empty tuples for backward compatibility).
   - Serialized in `to_dict()` and `to_json()` only when non-empty, preserving strict compatibility with existing V4 report consumers.

2. **JSON Investigation Reports (`render_correlation_detection_json`)**:
   - Serializes canonical `TimelineEvent` records with `category="network"` and full attribute dictionaries.
   - Preserves deterministic RFC 4122 UUIDv5 identifiers:
     - `source_event_id`: Identifies the underlying packet record (`NETREC-<uuid>`).
     - `attributes.metadata_id`: Identifies the protocol observation (`NETMD-DNS-<uuid>`, `NETMD-HTTP-<uuid>`, `NETMD-TLS-<uuid>`).
   - Retains transport protocol, source/destination IP addresses, source/destination ports, packet frame numbers, and extracted application metadata.

3. **HTML Investigation Reports (`render_correlation_detection_html`)**:
   - Detections Section: Renders matched detection cards with rule identifiers, severity, duration, and supporting timeline event tables.
   - Provenance Tracking: Renders packet frame numbers (`Frame: <N>`) for network events and log line numbers (`Line: <N>`) for host events.
   - Diagnostics Card: Displays a styled `Processing Limitations & Diagnostics` card when limitations or processing diagnostics are recorded.
   - Timeline Section: Chronologically lists timeline events with their event types, frame numbers, and descriptive summaries.

---

## 3. Network Evidence Fields in Reports

Network observations appear across timeline events, correlations, and detection results with the following supported fields:

| Field Name | Type | Description |
|---|---|---|
| `category` | `str` | Always `"network"` for PCAP observations. |
| `event_type` | `str` | Protocol event classification (e.g., `tcp_packet`, `udp_packet`, `network_dns_metadata`, `network_http_metadata`, `network_tls_metadata`). |
| `source_line` | `int` | Wire frame number (1-indexed packet sequence number in capture). |
| `source_path` | `str` | Normalized filesystem path to the source PCAP file. |
| `source_event_id` | `str` | Canonical packet record identifier (`NETREC-<UUIDv5>`). |
| `timestamp` / `raw_timestamp` | `str` | UTC ISO-8601 timestamp with microsecond precision and wire-level epoch string. |
| `attributes.src_ip` / `attributes.source_ip` | `str` | Source IPv4 or IPv6 address. |
| `attributes.dst_ip` / `attributes.destination_ip` | `str` | Destination IPv4 or IPv6 address. |
| `attributes.src_port` / `attributes.source_port` | `int` | Source TCP/UDP port number. |
| `attributes.dst_port` / `attributes.destination_port` | `int` | Destination TCP/UDP port number. |
| `attributes.transport_protocol` | `str` | Transport protocol (`"TCP"`, `"UDP"`, `"ICMP"`). |
| `attributes.dns` | `dict` | DNS metadata: `query_name`, `query_type`, `is_response`, `response_status`, `answers`. |
| `attributes.http` | `dict` | HTTP metadata: `method`, `target`, `host`, `status_code`, `reason_phrase`, redacted `headers`. |
| `attributes.tls` | `dict` | TLS metadata: `server_name` (SNI), `alpn_protocols`, `client_version`, `record_version`. |

---

## 4. Evidence Traceability and Forensic Neutrality

ForensiX enforces strict forensic neutrality and evidence traceability:

1. **Defensible Provenance**:
   - Every detection result links explicitly to `matched_correlation_ids` and `supporting_event_ids`.
   - Every correlation links explicitly to `event_ids`.
   - Every timeline event references its source evidence file (`source_path`), frame number (`source_line`), and evidence record identifier (`source_event_id`).

2. **No Speculation or Overclaiming**:
   - Rule matches are reported factually as pattern matches (e.g., `"MATCHED: rule NET-RULE-EXFIL-DNS"`), never as "confirmed malware" or "proven breaches."
   - Network flows are reported as wire observations; a TCP SYN without observed ACK is not described as a completed session.
   - IP addresses are not reported as verified machine or user identities unless supported by host logon artifacts.
   - Missing timestamps or packet metadata are not fabricated.

3. **Processing Limitations and Error Representation**:
   - Capture truncated flags, corrupted frames, and unsupported link-layer types are recorded as diagnostics.
   - Operational limitations (such as wire captures without TLS payload decryption) are explicitly reported in `limitations`.
   - Partial processing failures do not result in a false "clean / full success" report.

---

## 5. Forensic Hardening Measures Implemented

The following hardening measures have been implemented and verified across the pipeline:

1. **HTML Sanitization and XSS Prevention**:
   - All dynamic strings rendered into HTML reports (packet descriptions, URLs, query names, user agents, headers, error messages, and file paths) pass through strict HTML entity escaping (`html.escape(..., quote=True)`).
   - Malicious payloads containing `<script>`, `onerror=`, or injected tags are rendered harmlessly as escaped text.

2. **Sensitive Data Redaction by Default**:
   - Sensitive HTTP request and response headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `API-Key`) are automatically sanitized to `"[REDACTED]"` during application metadata extraction in `src/forensix/network_metadata.py`.
   - Raw packet payloads are never dumped in reports by default.

3. **Evidence Immutability and Write Protection**:
   - Source PCAP files are opened strictly in binary read-only mode (`"rb"`).
   - Evidence directory write isolation is verified: reports are never generated inside evidence source directories unless explicitly requested by the operator.
   - SHA-256 hashes of input evidence files remain unchanged before, during, and after triage execution.

4. **Streaming and Bounded Memory Execution**:
   - PCAP parsing uses chunked, bounded streaming via generator iterators (`iter_packets`, `iter_records`).
   - Frame allocation sizes are bounded by `DEFAULT_MAX_PACKET_SIZE = 262144` bytes (256 KiB) to prevent memory exhaustion from crafted large capture headers.
   - DNS name decompression depth is bounded by `MAX_DNS_POINTER_HOPS` (10 hops) to mitigate compression pointer loops.

5. **Robust Diagnostics for Corrupt Captures**:
   - Empty PCAP files (0 bytes), truncated headers (< 24 bytes), invalid magic numbers, and unsupported link-layer types raise explicit forensic diagnostics (`PcapCorruptError`, `PcapUnsupportedError`) with meaningful exit codes (exit code 2 for evidence errors).

6. **Deterministic Identifiers and Stable Sorting**:
   - RFC 4122 UUIDv5 hashing is used for all network records, metadata, and correlations.
   - Repeated analysis of the same capture produces identical event ordering, identical line/frame mapping, and identical correlation sets.

7. **Backward Compatibility**:
   - Existing V4 reports, host triage commands (`forensix triage-v4`, `forensix investigate`), and timeline reconstruction continue to function without modification.
   - Host-only investigations retain 100% of their schema and behavior.

---

## 6. Known Limitations and Unsupported Capabilities

In accordance with ForensiX forensic neutrality, capabilities not supported are documented explicitly:

- **PCAP-NG Format**: Only classic PCAP files (`0xa1b2c3d4`, `0xd4c3b2a1`, and nanosecond variants) are parsed. PCAP-NG (`0x0a0d0d0a`) is recognized and rejected with an informative `PcapUnsupportedError`.
- **Link-Layer Types**: BSD Loopback (`DLT_NULL`, 0), Ethernet (`DLT_EN10MB`, 1), Raw IP (`DLT_RAW`, 12), and Linux Cooked Capture v1 (`DLT_LINUX_SLL`, 113) are supported. Wireless 802.11 headers or other unlisted link-layer types are rejected.
- **TCP Stream Reassembly**: Analysis operates on individual packet frames and protocol payloads visible on the wire. Out-of-order segment reassembly across multiple packets is not performed.
- **TLS Decryption**: TLS ClientHello handshake metadata (SNI, ALPN, versions) is extracted passively. Encrypted application data records are not decrypted.

---

## 7. Verification and Test Suite

All 17 required V5.9 reporting and hardening verification tests were implemented in `tests/test_v59_reporting_hardening.py`:

| Test Case | Description | Result |
|---|---|---|
| `test_01_network_evidence_in_json_report` | Network evidence, frames, and metadata appear in JSON reports | PASSED |
| `test_02_network_evidence_in_html_report` | Network events, frames, and protocols appear in HTML reports | PASSED |
| `test_03_detections_and_correlations_linking` | Detections and correlations link to supporting events and artifacts | PASSED |
| `test_04_serialization_missing_and_optional_fields` | Correct serialization of missing and optional fields | PASSED |
| `test_05_timestamp_precision_limitations` | Microsecond timestamp precision and raw timestamp preservation | PASSED |
| `test_06_html_escaping_untrusted_strings` | HTML escaping prevents script injection from untrusted packet data | PASSED |
| `test_07_sensitive_payloads_not_exposed` | Sensitive HTTP authorization and cookie headers are redacted | PASSED |
| `test_08_malformed_and_unsupported_captures_diagnostics` | Clear diagnostics and exit codes on corrupted/unsupported captures | PASSED |
| `test_09_partial_pipeline_failures_represented_accurately` | Limitations and errors are represented in JSON and HTML reports | PASSED |
| `test_10_deterministic_report_ordering` | Repeated runs produce identical ordering, frame counts, and event IDs | PASSED |
| `test_11_duplicate_input_handling` | Duplicate packets retain distinct frame numbers and are not lost | PASSED |
| `test_12_evidence_integrity` | Evidence SHA-256 remains completely unchanged throughout processing | PASSED |
| `test_13_output_paths_not_polluting_evidence` | Output reports are never written inside source evidence directories | PASSED |
| `test_14_large_input_streaming_behavior` | Large PCAP files stream iteratively without memory exhaustion | PASSED |
| `test_15_backward_compatibility_v4_reports` | Existing V4 report schemas and loaders remain fully compatible | PASSED |
| `test_16_e2e_pcap_to_report` | Full PCAP-to-timeline-to-correlation-to-report pipeline execution | PASSED |
| `test_17_host_only_investigation_reporting_remains_functional` | Existing host-only triage and reporting remains intact | PASSED |

### Complete Test Suite Execution Results

- **V5.9 Focused Suite**: `17 passed`
- **Network & Reporting Suite**: `272 passed, 40 subtests passed`
- **Full Project Test Suite** (`PYTHONPATH=src pytest -q`): `1116 passed, 238 subtests passed, 0 failures`
