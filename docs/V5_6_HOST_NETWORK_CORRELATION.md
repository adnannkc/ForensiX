# ForensiX V5.6 — Host-to-Network Correlation

This document describes the **Host-to-Network Correlation** architecture, defensible matching dimensions, ambiguity handling model, and integration APIs implemented in **ForensiX V5.6**.

---

## 1. Overview and Purpose

ForensiX V5.6 bridges host-level forensic observations (logs, authentication records, filesystem modifications) and network-level observations (packets, frames, application metadata) within the unified ForensiX V3 timeline and V4 correlation architecture (`Correlation`, `CorrelationType.HOST_NETWORK`, `CorrelationEngine`).

### Key Objectives
1. **Reuse Existing V4 Correlation Architecture**:
   - Extends `CorrelationType` with `HOST_NETWORK` without altering existing relationship semantics.
   - Reuses `Correlation`, `CorrelationCollection`, `CorrelationEngine`, and `correlation_sort_key`.
   - Generates deterministic RFC 4122 UUIDv5 correlation IDs (`CORR-<UUIDv5>`).
2. **Defensible, Non-Speculative Correlation**:
   - Rejects assumption that an IP uniquely identifies a single machine (explicitly acknowledges NAT, proxies, DHCP reassignment, and shared multi-tenant infrastructure).
   - Rejects temporal proximity as sole evidence: every correlation requires an explicit observed anchor (IP, user, session, or port).
   - Never fabricates or guesses usernames, process IDs, hostnames, or endpoint mappings.
   - Never assigns security verdicts, hypothetical threat scores, or speculative attack tags.
3. **High-Performance Scalable Matching**:
   - Replaces naive $O(N_{host} \times N_{net})$ pairwise comparisons with index structures (`net_by_ip`, `net_by_user`, `net_by_session`).
4. **Provenance & Chronological Fidelity**:
   - Preserves source event IDs, source artifact IDs, line numbers, and frame numbers.
   - Preserves actual temporal intervals ($\Delta t$) and validates against configurable time windows.

---

## 2. Defensible Correlation Dimensions

A host timeline event ($E_{host}$) and a network timeline event ($E_{net}$) are correlated under `CorrelationType.HOST_NETWORK` when at least one explicit anchor matches and temporal constraints are satisfied:

| Dimension | Host Observation Evidence | Network Observation Evidence | Match Condition |
| :--- | :--- | :--- | :--- |
| **IP Match** (`ip_match`) | Observed remote peer IP (`source_ip`, `src_ip`, `client_ip`) | Packet/metadata `src_ip` or `dst_ip` | Exact IP string equality (canonical IPv4/IPv6) |
| **Host Endpoint Match** (`host_endpoint_ip_match`) | Known host IP (`known_host_ips` in config) | Packet/metadata `src_ip` or `dst_ip` | Endpoint traffic involving the host |
| **User Identity Match** (`user_match`) | Explicit user (`username`, `user`) | Explicit user (`username`, `user`) in application metadata | Comparable normalized string equality (`user_host.lower() == user_net.lower()`) |
| **Session Match** (`session_match`) | Explicit session (`session_id`, `session`) | Explicit session (`session_id`) | Exact session string equality |
| **Port Alignment** | Host client/service port (`source_port`, `port`) | Packet transport port (`src_port`, `dst_port`) | Verified port overlap recorded in `port_aligned=True` |

### Strict Conflict Invalidation Rules
1. **User Conflict**: If both host and network events contain explicit user identities and they differ (`user_host != user_net`), correlation is strictly rejected.
2. **Session Conflict**: If both host and network events contain explicit session identifiers and they differ, correlation is strictly rejected.
3. **Temporal Boundary**: If both events possess timestamps and $\Delta t > \text{time\_window\_seconds}$, correlation is strictly rejected.
4. **Missing Timestamps**: When `require_timestamps=True` (default), missing timestamps prevent correlation because chronological containment cannot be proven.

---

## 3. Explicit Ambiguity Handling

In digital forensics, IP address matching is prone to overinterpretation. ForensiX V5.6 explicitly documents limitations directly inside the `Correlation.attributes`:

1. **Private / Shared / Loopback Addresses**:
   - Addresses within RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 6598 CGNAT (`100.64.0.0/10`), loopback (`127.0.0.0/8`), or link-local (`169.254.0.0/16`) are classified via `is_private_or_shared_ip()`.
   - Recorded attribute: `is_private_or_shared_ip = True`.
   - Preserves warning note: *"Matched address is within a private, loopback, or reserved range; attribution may be ambiguous due to potential NAT, DHCP reassignment, or network overlapping."*
2. **Public / Routable Addresses**:
   - Preserves limitation note: *"IP match reflects observed addressing; does not guarantee unique machine identity if proxies, NAT gateways, or dynamic allocation are present."*
3. **Port Misalignment**:
   - If a host event records a specific port that does not match the observed packet port, `port_aligned = False` is recorded with an explanatory note.
4. **Multiplicity (Many-to-One / One-to-Many)**:
   - Multiple host events matching the same network observation (or vice-versa) generate distinct, deterministic correlations without collapsing distinct events.

---

## 4. Public API Reference

Primary integration entry points are located in `forensix.network_correlation` and exported at top-level `forensix`:

### Configuration
```python
@dataclass(frozen=True)
class HostNetworkCorrelationConfig:
    time_window_seconds: float = 300.0
    match_ip: bool = True
    match_user: bool = True
    match_session: bool = True
    match_port: bool = True
    known_host_ips: Tuple[str, ...] = ()
    require_timestamps: bool = True
    max_correlations: Optional[int] = None
```

### Core Engine & Functional Interface
- `correlate_host_network_events(timeline, config=None, ...) -> CorrelationCollection`:
  Correlates host and network events from a `ReconstructedTimeline` or event sequence.
- `HostNetworkCorrelator(config=None, ...)`:
  Object-oriented correlator class maintaining indexed lookup structures.
- `CorrelationEngine(relationship_types=[CorrelationType.HOST_NETWORK], ...)`:
  Unified V4 engine interface transparently evaluating host-to-network correlations.

### Utilities
- `is_host_event(event: TimelineEvent) -> bool`
- `is_network_event(event: TimelineEvent) -> bool`
- `normalize_ip_address(ip_val: Any) -> Optional[str]`
- `is_private_or_shared_ip(ip_val: Any) -> bool`
- `extract_host_observed_ips(event: TimelineEvent) -> Set[str]`
- `extract_network_ips(event: TimelineEvent) -> Tuple[Optional[str], Optional[str]]`
- `extract_host_ports(event: TimelineEvent) -> Set[int]`
- `extract_network_ports(event: TimelineEvent) -> Tuple[Optional[int], Optional[int]]`

---

## 5. Verification and Test Results

Tested across 20 focused unit and integration tests in `tests/test_network_correlation.py`:
- IP matching, known endpoint IP matching, port alignment.
- Time window boundaries, missing timestamps, naive/aware timestamps.
- Explicit ambiguity handling for RFC 1918 and CGNAT ranges.
- Matching and conflicting user identities.
- Matching and conflicting session identifiers.
- Many-to-one and one-to-many event relationships.
- Exact duplicate inputs deduplication.
- Deterministic RFC 4122 UUIDv5 correlation IDs and stable canonical sorting.
- Unified V4 `CorrelationEngine` integration.
- End-to-end synthetic PCAP + host logs timeline reconstruction and correlation.

**Full Regression Test Suite Results**: **1,069 passed, 238 subtests passed, 0 failures**.
