# ForensiX V5.4 — DNS and HTTP/TLS Metadata Extraction

This document describes the **Application-Layer Metadata Extraction** architecture, models, and safety boundaries implemented in **ForensiX V5.4**.

---

## 1. Overview and Purpose

ForensiX V5.4 introduces bounded, read-only extraction of application-layer protocol metadata for **DNS**, **HTTP**, and **TLS** from observed network frames and transport payloads without active network connections, external DNS queries, TLS decryption, or speculative threat verdicts.

### Key Objectives
1. **Factual Protocol Observation**: Extract structured, parseable facts from application-layer payloads (e.g. DNS query names, response answers, HTTP methods, URIs, Host headers, and TLS ClientHello SNI/ALPN).
2. **Strict Forensic Safety**:
   - Prevent DNS compression pointer loops, excessive recursion, and buffer overflows.
   - Enforce bounded header scanning and maximum line length limits for cleartext HTTP.
   - Reject arbitrary payload retention: **HTTP request/response bodies are never stored or logged**.
   - Parse TLS record headers and ClientHello extensions safely without attempting decryption or claiming encrypted traffic was recovered.
   - Distinguish legacy advertised versions from negotiated versions (never claim a ClientHello proved the negotiated version).
3. **Deterministic Identity**: Generate reproducible `NETMD-<UUIDv5>` identifiers anchored to source packet facts within `FORENSIX_V5_NETWORK_METADATA_NAMESPACE`.
4. **Streaming & Incremental Processing**: Extract metadata directly from PCAP streams frame-by-frame without materializing entire captures or payloads in memory.
5. **Timeline Integration Seam**: Provide conversion to `TimelineEvent(category=TimelineCategory.NETWORK)`.

---

## 2. Architectural Extensions

To extract application-layer metadata, the existing pipeline was extended in a strictly backward-compatible manner:

```
Raw PCAP File
     ↓
PcapParser.read_raw_records() / read_pcap_raw() (V5.2 Extension)
     ↓ (yields NetworkEvidenceRecord + raw packet bytes)
extract_transport_payload() (V5.2 Extension)
     ↓ (extracts transport protocol, ports, and payload bytes)
extract_application_metadata() (V5.4)
     ├── parse_dns_payload()  ──> DnsMetadata
     ├── parse_http_payload() ──> HttpMetadata
     └── parse_tls_payload()  ──> TlsMetadata
     ↓
NetworkApplicationMetadata (V5.4 Unified Envelope)
     ↓
TimelineEvent (V3.1 Integration Seam)
```

No second PCAP parser was created. `PcapParser.read_records()` continues to yield `NetworkEvidenceRecord` without change, while `read_raw_records()` pairs each record with its raw captured bytes.

---

## 3. Supported Protocol Taxonomy and Fields

### A. DNS (`DnsMetadata`)
- **Fields Extracted**:
  - `transaction_id`: 16-bit transaction identifier.
  - `is_response`: Boolean QR flag.
  - `response_code`: Integer RCODE.
  - `response_status`: Canonical name (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, etc.).
  - `query_name`: Decompressed primary domain name.
  - `query_type`: Canonical type name (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`, etc.).
  - `query_class`: Canonical class name (`IN`, `CH`, `HS`, etc.).
  - `questions`: Sequence of `DnsQuestion` records.
  - `answers`: Sequence of `DnsAnswer` records with parsed IP addresses (`A`, `AAAA`), domain pointers (`CNAME`, `PTR`), text strings (`TXT`), and mail preferences (`MX`).
  - `flags`: Authoritative answer (`AA`), Truncation (`TC`), Recursion Desired (`RD`), Recursion Available (`RA`).
- **Safety Boundaries**:
  - Max domain name length: 255 bytes. Max label length: 63 bytes.
  - Max compression pointer hops: 16.
  - Pointer loop detection: Tracked via visited offsets set.
  - Header bounds: Max 50 questions, max 100 answers.
  - Non-DNS traffic rejection: Payloads with invalid opcodes, truncated questions, or malformed headers return `None`.

### B. HTTP (`HttpMetadata`)
- **Fields Extracted**:
  - `is_request`: Boolean flag.
  - `method`: Standard HTTP request method (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `CONNECT`, `TRACE`, `PATCH`).
  - `target`: Request URI / target path.
  - `http_version`: Protocol version string (`HTTP/1.1`, `HTTP/1.0`).
  - `status_code`: 3-digit response status code (100–599).
  - `reason_phrase`: Response status reason.
  - `host`: Host header value.
  - `user_agent`: User-Agent header value.
  - `content_type`: Content-Type header value.
  - `content_length`: Content-Length integer value.
  - `server`: Server header value.
  - `headers`: Full sequence of observed `(name, value)` header tuples.
- **Safety Boundaries**:
  - Max header scan block: 8,192 bytes.
  - Max header lines: 64.
  - Max line length: 4,096 bytes.
  - **Body Dropped**: Payloads after header block are discarded.
  - Fast rejection of TLS / binary traffic starting with `0x16 0x03`.

### C. TLS (`TlsMetadata`)
- **Fields Extracted**:
  - `content_type`: Integer content type (22 for Handshake, 20 ChangeCipherSpec, 21 Alert, 23 ApplicationData).
  - `handshake_type`: Handshake type (1 for ClientHello).
  - `is_client_hello`: Boolean flag.
  - `server_name`: Server Name Indication (SNI) hostname from extension `0x0000`.
  - `alpn_protocols`: Sequence of advertised ALPN protocols (e.g. `("h2", "http/1.1")`) from extension `0x0010`.
  - `record_version`: Record layer version string (`TLS 1.0`, `TLS 1.2`).
  - `client_version`: Advertised legacy version string in ClientHello.
  - `supported_versions`: Advertised version strings from extension `0x002B` (e.g. `TLS 1.3`, `TLS 1.2`).
- **Safety Boundaries**:
  - Validates record length and handshake length before reading.
  - Handles truncated ClientHello without `IndexError`.
  - **No Decryption**: Does not attempt decryption of ApplicationData.
  - **No Inferred Negotiation**: Never claims negotiated TLS version from a ClientHello.

---

## 4. Deterministic Identity Strategy

All metadata objects receive deterministic UUIDv5 identifiers:
- Namespace: `FORENSIX_V5_NETWORK_METADATA_NAMESPACE` (`4b55e378-da27-5674-88aa-37a5b3310087`), derived from `FORENSIX_V5_NETWORK_NAMESPACE`.
- Format:
  - DNS: `NETMD-DNS-<UUIDv5>`
  - HTTP: `NETMD-HTTP-<UUIDv5>`
  - TLS: `NETMD-TLS-<UUIDv5>`
- Canonical Seeds:
  - DNS: `{record_id}|dns|0x{transaction_id:04x}|{query_name}|frame:{frame_number}`
  - HTTP: `{record_id}|http|{method_or_status}|{target_or_host}|frame:{frame_number}`
  - TLS: `{record_id}|tls|{sni}|hs:{handshake_type}|frame:{frame_number}`

---

## 5. Public APIs

### Parsing Functions
- `parse_dns_payload(payload: bytes, ...) -> Optional[DnsMetadata]`
- `parse_http_payload(payload: bytes, ...) -> Optional[HttpMetadata]`
- `parse_tls_payload(payload: bytes, ...) -> Optional[TlsMetadata]`
- `extract_application_metadata(payload: bytes, ...) -> Optional[NetworkApplicationMetadata]`
- `extract_metadata_from_packet(record: NetworkEvidenceRecord, packet_bytes: bytes, link_type=1) -> Optional[NetworkApplicationMetadata]`
- `extract_metadata_from_pcap(source, ...) -> Iterator[NetworkApplicationMetadata]`

### OOP Extractor
```python
extractor = NetworkMetadataExtractor()
meta = extractor.extract_from_payload(payload, transport_protocol="UDP")
```

---

## 6. Limitations and Future Scope

1. **TCP Stream Reassembly**: V5.4 operates per packet. If an HTTP header block or TLS ClientHello is split across multiple TCP segments, only the segment containing the initial headers/extensions is parsed. Multi-packet TCP stream reassembly is deferred to V5.5.
2. **Encrypted Payloads**: Encrypted TLS ApplicationData is treated as opaque ciphertext; no decrypted HTTP or DNS is extracted from TLS sessions.
