# ForensiX V5.3 — Network Event Extraction

This document describes the **Network Event Extraction** architecture and models implemented in **ForensiX V5.3**.

---

## 1. Overview and Purpose

ForensiX V5.3 introduces the event extraction layer that consumes parsed network packet records (`NetworkEvidenceRecord` from V5.1/V5.2) and produces deterministic, structured, immutable network events (`NetworkEvent`).

Key objectives of V5.3:
1. **Factual Observation Extraction**: Translate raw packet captures and parsed network frames into standard, forensic network events without speculative interpretation or premature threat classification.
2. **Strict Determinism**: Ensure identical evidence records produce identical event IDs and serialized output across runs.
3. **Traceability and Provenance**: Maintain complete traceability to originating packet captures, source artifacts, and individual frame numbers.
4. **Timeline Integration Seam**: Provide seamless conversion (`to_timeline_event()`) to the established ForensiX `TimelineEvent` model under `TimelineCategory.NETWORK`.
5. **Streaming / Incremental Extraction**: Support memory-efficient, generator-based streaming extraction from packet streams and large PCAP files.

---

## 2. Architectural Layers

ForensiX V5 follows a strict layered network analysis pipeline:

```
Raw PCAP File
     ↓
PcapParser (V5.2)
     ↓
NetworkEvidenceRecord (V5.1 / V5.2)
     ↓
NetworkEventExtractor / extract_network_event (V5.3)
     ↓
NetworkEvent (V5.3) ──[to_timeline_event()]──> TimelineEvent (V3.1)
     ↓
[Future V5.4+ Application Protocol Parsing, V5.6 Correlation, V5.7 Detection]
```

V5.3 acts strictly as an observation extractor. It does not perform application protocol dissection (reserved for V5.4), protocol session/flow state reconstruction (reserved for V5.5), cross-artifact correlation (reserved for V5.6), or intrusion detection alerting (reserved for V5.7).

---

## 3. Supported Event Taxonomy

The event taxonomy in V5.3 is defined by `NetworkEventType`:

| Event Type | Identifier | Criteria |
| :--- | :--- | :--- |
| `TCP_PACKET` | `"network_tcp_packet"` | Packet has transport layer `TCP` or valid TCP metadata |
| `UDP_PACKET` | `"network_udp_packet"` | Packet has transport layer `UDP` |
| `ICMP_PACKET` | `"network_icmp_packet"` | Packet has network/transport protocol `ICMP` |
| `ICMPV6_PACKET` | `"network_icmpv6_packet"` | Packet has protocol `ICMPv6` |
| `ARP_PACKET` | `"network_arp_packet"` | Link or network protocol is `ARP` |
| `IP_FRAGMENT` | `"network_ip_fragment"` | Fragment offset > 0 or more-fragments flag set |
| `IPV4_PACKET` | `"network_ipv4_packet"` | Network protocol `IPv4` without transport layer |
| `IPV6_PACKET` | `"network_ipv6_packet"` | Network protocol `IPv6` without transport layer |
| `GENERIC_PACKET` | `"network_packet"` | Fallback observation when protocol is unparsed or raw |

### Anti-Speculation Policy

- **No Premature Connection Claims**: An observed TCP SYN or ACK is recorded as a packet observation, not as an established, successful connection.
- **No Inferred Application Metadata**: HTTP, DNS, or TLS traffic is not claimed unless explicitly parsed in appropriate layers.
- **No Speculative Labels**: Terms such as `"malicious"`, `"attack"`, `"c2"`, `"beacon"`, or `"compromised"` are strictly prohibited at the extraction layer.
- **Missing Data Preserved**: If source/destination ports, IP addresses, or flags are not present in the record, they remain `None` rather than being inferred or defaulted.

---

## 4. Deterministic Identity and Namespaces

### Deterministic Event IDs
Every `NetworkEvent` receives a deterministic ID formatted as:
`NETEVT-<UUIDv5>`

The UUIDv5 is derived using:
- **Namespace**: `FORENSIX_V5_NETWORK_EVENT_NAMESPACE` (`18c946f0-d5a8-5509-9b62-ce2d7bf37d11`), derived from the V5 network namespace `0c3e6022-f027-5d12-9c16-291771f2512a`.
- **Name Seed**: `{record_id}:{event_type}:{frame_number}`

This guarantees:
1. Processing the identical evidence record multiple times always yields identical event IDs.
2. Distinct frames with identical headers/payloads receive distinct IDs because `frame_number` or `record_id` differ.
3. Multiple event types extracted from a single record (if parameterized) remain uniquely keyed.

---

## 5. Timestamp Fidelity and Provenance

### Timestamp Handling
- `timestamp`: Stored as a UTC-aware `datetime` or `None`.
- `raw_timestamp`: Preserved verbatim as a string representation of the captured timestamp or nanosecond/microsecond resolution to avoid loss of forensic fidelity.
- All timestamp conversions adhere to ForensiX `normalize_to_utc` conventions.

### Provenance Attributes
Each `NetworkEvent` records:
- `packet_id`: Original `NetworkEvidenceRecord.record_id`.
- `frame_number`: Positive integer frame index from the PCAP capture.
- `source_path`: Absolute or relative path to the source evidence file.
- `source_artifact_id`: ForensiX artifact identifier (e.g., `ART-...`).
- `source_event_id`: Reference back to the packet record ID.

---

## 6. Public APIs

### `NetworkEvent`
An immutable, frozen dataclass representing the forensic network observation.
- Attributes: `event_id`, `event_type`, `description`, `timestamp`, `raw_timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `length`, `frame_number`, `source_path`, `source_artifact_id`, `packet_id`, `tcp_flags`, `attributes`.
- Methods:
  - `to_dict()`: Deterministic dictionary representation.
  - `to_json(indent=None)`: Valid JSON serialization.
  - `from_dict(d)`: Reconstructs a `NetworkEvent` from a serialized dictionary.
  - `to_timeline_event()`: Converts the observation into a canonical `TimelineEvent` with `TimelineCategory.NETWORK`.

### Extraction Functions and Classes
- `compute_deterministic_network_event_id(record, event_type, frame_number=None) -> str`
- `extract_network_event(record: NetworkEvidenceRecord) -> NetworkEvent`
- `extract_network_events(records: Iterable[NetworkEvidenceRecord]) -> Iterator[NetworkEvent]`
- `NetworkEventExtractor`: Object-oriented extraction class:
  - `extract(record) -> NetworkEvent`
  - `extract_many(records) -> Iterator[NetworkEvent]`
  - `extract_all(records) -> List[NetworkEvent]`
  - `extract_from_pcap(pcap_path, source_artifact_id=None) -> Iterator[NetworkEvent]`

---

## 7. Limitations and Forward Compatibility

1. **Protocol Depth**: V5.3 handles link, network, and transport protocol observations (Ethernet, IPv4, IPv6, ARP, ICMP, ICMPv6, TCP, UDP). Application-layer inspection (DNS, HTTP, TLS) is deferred to V5.4.
2. **Flow Reconstruction**: Extraction operates per-packet; bi-directional flow assembly is deferred to V5.5.
3. **Detection and Alerting**: All event descriptions are strictly descriptive; alert generation is handled in V5.7 detection rules.
