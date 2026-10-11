# ForensiX V5.5 — Network-to-Timeline Integration

This document describes the **Network-to-Timeline Integration** architecture, mapping rules, provenance model, and integration APIs implemented in **ForensiX V5.5**.

---

## 1. Overview and Purpose

ForensiX V5.5 integrates packet-level network observations (V5.3) and application-layer metadata (V5.4) into the unified ForensiX V3 timeline architecture (`TimelineEvent`, `reconstruct_timeline`, `query_timeline`, and `render_timeline_*`).

### Key Objectives
1. **Reuse Existing V3 Architecture**:
   - Reuses existing `TimelineEvent`, `TimelineCategory.NETWORK`, `reconstruct_timeline`, `query_timeline`, and timeline reporting without creating duplicate timeline engines or schema bifurcations.
2. **Provenance & Chronological Fidelity**:
   - Maps observed packet events and application metadata to `TimelineCategory.NETWORK`.
   - Preserves normalized and raw timestamps, source artifact references, packet frame numbers, canonical file paths, and deterministic IDs.
   - Preserves explicit relationships: application metadata timeline events record the parent `packet_event_id` in their attributes.
3. **Deterministic Identity & Deduplication**:
   - Preserves deterministic IDs from V5.3 (`NETEVT-<UUIDv5>`) and V5.4 (`NETMD-<UUIDv5>`).
   - Deduplicates identical repeated observations deterministically while maintaining distinct identities for distinct packet frames.
4. **Distinguishability**:
   - Maintains clear semantic separation between packet-level observations (`event_type="packet_observation"`, `tcp_connection_handshake`, etc.) and application-level metadata (`dns_query`, `dns_response`, `http_request`, `http_response`, `tls_client_hello`, etc.).
5. **Streaming & Incremental Processing**:
   - Supports streaming generator processing from raw PCAP files without buffering whole captures in memory.
6. **No Speculative Interpretation**:
   - Preserves observed facts without injecting security verdicts, risk scores, or speculative attack tags.

---

## 2. End-to-End Data Flow

The integrated forensic data pipeline flows as follows:

```
PCAP File / Evidence Stream
             ↓
[V5.2] Classic PCAP Parser (PcapParser.read_raw_records())
             ↓ (yields NetworkEvidenceRecord + raw frame bytes)
[V5.3] Network Event Extractor (extract_network_event())
   └── Produces: NetworkEvent (packet-level observation)
             ↓
[V5.4] Metadata Extractor (extract_metadata_from_packet())
   └── Produces: NetworkApplicationMetadata (DNS / HTTP / TLS facts)
             ↓
[V5.5] Network Timeline Adapter (src/forensix/network_timeline.py)
   ├── adapt_network_event()       ──> TimelineEvent (category=NETWORK)
   └── adapt_network_metadata()    ──> TimelineEvent (category=NETWORK, linked to packet event)
             ↓
[V3.4] Timeline Reconstruction (reconstruct_timeline())
   └── Deterministic chronological ordering (timestamp, tie-breaker order, event_id)
   └── Configurable deduplication preserving distinct frames
             ↓
[V3.5 / V3.6] Querying & Reporting
   ├── query_timeline()            (Filter by category='network', text, time windows)
   ├── render_timeline_json()      (Structured JSON with network metrics)
   └── render_timeline_html()      (Interactive HTML visualization)
```

---

## 3. Timeline Mapping Specification

### A. Packet Event Mapping (`adapt_network_event`)
- **Category**: `TimelineCategory.NETWORK` ("network")
- **Timestamp**: `event.timestamp` (normalized ISO 8601 UTC)
- **Raw Timestamp**: `event.raw_timestamp` (preserving microsecond/nanosecond fidelity)
- **Event Type**: `event.event_type.value` (e.g. `tcp_packet`, `udp_packet`, `icmp_packet`, `arp_packet`, `ip_fragment`, `generic_packet`)
- **Description**: Factual protocol description (e.g. `TCP 192.168.1.10:54321 -> 93.184.216.34:443 [SYN, ACK]`)
- **Source Path**: `event.source_path`
- **Source Artifact ID**: `event.source_artifact_id`
- **Source Line / Frame Number**: `event.frame_number`
- **Event ID**: `event.event_id` (`NETEVT-<UUIDv5>`)
- **Attributes**: Complete dictionary of observed network facts (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `mac_src`, `mac_dst`, `flags`, `packet_size`, `ip_version`, `is_fragment`, etc.).

### B. Application Metadata Mapping (`adapt_network_metadata`)
- **Category**: `TimelineCategory.NETWORK` ("network")
- **Timestamp**: `meta.timestamp` (normalized ISO 8601 UTC)
- **Raw Timestamp**: `meta.raw_timestamp`
- **Event Type**: Factual protocol event type:
  - DNS: `dns_query` (if query) or `dns_response` (if response)
  - HTTP: `http_request` (if request) or `http_response` (if response)
  - TLS: `tls_client_hello` (if ClientHello) or `tls_record` (other TLS record)
- **Description**: Protocol-specific factual summary:
  - DNS: `DNS Query A example.com` or `DNS Response NOERROR [1 answers]`
  - HTTP: `HTTP GET /index.html` or `HTTP 200 OK`
  - TLS: `TLS ClientHello sni=example.com` or `TLS Record ContentType=22`
- **Source Path**: `meta.source_path`
- **Source Artifact ID**: `meta.source_artifact_id`
- **Source Line / Frame Number**: `meta.frame_number`
- **Event ID**: `meta.metadata_id` (`NETMD-<UUIDv5>`)
- **Attributes**: Structured protocol attributes with `packet_event_id` cross-reference:
  - DNS: `query_name`, `query_type`, `response_status`, `answers`, etc.
  - HTTP: `method`, `target`, `host`, `user_agent`, `status_code`, etc.
  - TLS: `server_name`, `alpn_protocols`, `record_version`, etc.
  - Linking attribute: `packet_event_id` (contains the deterministic ID of the enclosing frame packet event).

---

## 4. Public Integration API

All primary integration entry points are located in `forensix.network_timeline` and exported at top-level `forensix`:

### 1. Functional Adapters
- `adapt_network_event(event: NetworkEvent) -> TimelineEvent`
  Converts an individual `NetworkEvent` into a `TimelineEvent`.
- `adapt_network_metadata(meta: NetworkApplicationMetadata, packet_event_id: Optional[str] = None) -> TimelineEvent`
  Converts an application metadata record into a `TimelineEvent`, recording optional `packet_event_id` in attributes.
- `adapt_network_record(record: NetworkEvidenceRecord, packet_bytes: Optional[bytes] = None) -> Tuple[TimelineEvent, ...]`
  Adapts a raw record and optional packet bytes into a tuple containing the packet `TimelineEvent` and, if supported metadata is present, the metadata `TimelineEvent`.
- `adapt_network_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]`
  Polymorphic dispatcher accepting `NetworkEvent`, `NetworkApplicationMetadata`, `DnsMetadata`, `HttpMetadata`, `TlsMetadata`, or `NetworkEvidenceRecord`.

### 2. Pipeline Orchestration & Streaming
- `extract_network_timeline_events(source: Union[str, Path, BinaryIO], source_artifact_id: Optional[str] = None) -> Iterator[TimelineEvent]`
  Generator that reads a PCAP stream or file frame-by-frame, extracting both packet events and metadata events in streaming order without loading the whole file into memory.
- `reconstruct_network_timeline(source: Union[str, Path, BinaryIO], source_artifact_id: Optional[str] = None, deduplicate: bool = True) -> ReconstructedTimeline`
  Convenience pipeline function that streams PCAP frames, adapts them to timeline events, and invokes `reconstruct_timeline` to produce a fully validated, chronologically sorted `ReconstructedTimeline`.

### 3. Object-Oriented Facade & Polymorphic Registration
- `NetworkTimelineAdapter`:
  Implements `BaseArtifactAdapter` (`can_adapt(artifact)` and `adapt(artifact)`).
  Registered in `forensix.artifact_adapters.can_adapt_artifact()` and `adapt_artifact()` so existing code calling `adapt_artifacts([fs_record, log_event, net_event])` automatically handles network artifacts.
- `NetworkTimelineExtractor`:
  Configurable extractor class wrapping event and metadata extraction and timeline adaptation.

---

## 5. Architectural Guarantees & Safeguards

1. **Deterministic Ordering**:
   Reconstruction applies the canonical V3 tie-breaker ordering:
   `(normalized_timestamp, original_order, event_id)`. Events without timestamps are sorted stably at the end without inventing chronological precision.
2. **Deterministic IDs & Frame Distinctness**:
   Different packet frames generate distinct UUIDv5 identifiers because frame numbers and captured facts differ.
   Exact duplicate records share identical UUIDv5 identifiers and are deduplicated cleanly when `deduplicate=True`.
3. **No Speculative Attack Verdicts**:
   All event types and descriptions represent directly observed protocol fields without hypothetical risk scoring or attack attribution.
4. **Backward Compatibility**:
   Existing V3 filesystem, log, and authentication adapters and V4 triage and correlation components continue to function identically with zero regression.

---

## 6. Verification and Test Coverage

The integration is verified by 24 focused integration tests in `tests/test_network_timeline.py`:
- Protocol mapping: TCP, UDP, ICMP, ICMPv6, ARP, IP fragment, DNS, HTTP, TLS.
- Timestamp handling: missing timestamps, raw timestamp microsecond/nanosecond preservation.
- Identity & Provenance: deterministic IDs, frame distinctness, parent-child linking.
- Query & Reporting: `query_timeline` filtering by network category and text, `render_timeline_json` and `render_timeline_html`.
- Polymorphic adaptation: `adapt_artifacts` handling mixed filesystem, log, and network items.
- End-to-end PCAP: Synthetic capture streamed through parsing, event extraction, metadata extraction, timeline adaptation, and reconstruction.

**Full Suite Results**: 1,049 passed, 238 subtests passed, 0 failures.
