# ForensiX V5.7 — Network Detection Rules

This document describes the **declarative network detection rule architecture**, supported evidence fields, evaluation engine integration, and forensic neutrality guarantees implemented in **ForensiX V5.7**.

---

## 1. Overview and Purpose

ForensiX V5.7 implements declarative network detection capability fully integrated into the existing V4 detection architecture (`DetectionRule`, `RuleCondition`, `RuleCollection`, `DetectionEngine`, `DetectionResult`).

### Key Principles
1. **Reuse Existing V4 Architecture**:
   - Reuses the V4 declarative rule model and evaluation engine without introducing a parallel or secondary network-only rule engine.
   - Extends `ConditionOperator` with declarative string matching operators (`STARTS_WITH`, `ENDS_WITH`) alongside existing operators (`EQUALS`, `NOT_EQUALS`, `CONTAINS`, `IN`, `EXISTS`, `<`, `<=`, `>`, `>=`).
   - Evaluates both single-event network observations and multi-event/correlated relationships (`CorrelationType.HOST_NETWORK`).
2. **Defensible, Evidence-Based Detection**:
   - Matches genuine, substantiated network evidence fields (DNS query names & answers, HTTP host/target/method/status, TLS SNI & ALPN, transport protocol & port numbers).
   - Rejects speculative threat assertions: rules observe and record factual conditions, not unverified claims of malicious intent or compromise.
3. **Traceability and Provenance**:
   - Preserves source packet/record identifiers (`NETEVT-<UUIDv5>`), source artifact identifiers, frame numbers, source paths, and observed packet timestamps.
   - Generates deterministic RFC 4122 UUIDv5 detection identifiers (`DET-<UUIDv5>`).
4. **Safety and Determinism**:
   - Prohibits executable code, arbitrary expressions, dynamic callbacks, or `eval()`/`exec()` calls.
   - Safe against missing, malformed, or out-of-order evidence fields.
   - Output ordering and deduplication remain strictly deterministic.

---

## 2. Supported Evidence Fields and Condition Operators

Detection rules evaluate declarative conditions against `TimelineEvent` records under `TimelineCategory.NETWORK` and correlated `Correlation` entities:

| Evidence Domain | Field Name | Aliases / Sub-paths | Expected Type | Supported Operators | Example Match |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DNS** | `query_name` | `dns.query_name` | `str` | `EQUALS`, `ENDS_WITH`, `CONTAINS`, `STARTS_WITH` | Domain suffix `".internal.corp"` |
| **DNS** | `query_type` | `dns.query_type` | `str` | `EQUALS`, `IN` | Query record type `"A"`, `"TXT"` |
| **DNS** | `answers_data`| `dns.answers_data` | `List[str]` | `CONTAINS`, `EXISTS` | Resolved IP address `"192.0.2.1"` |
| **HTTP** | `host` | `http.host` | `str` | `EQUALS`, `ENDS_WITH`, `CONTAINS` | Host header `"api.partner.net"` |
| **HTTP** | `target` | `http.target` | `str` | `STARTS_WITH`, `EQUALS`, `CONTAINS` | Endpoint path `"/api/v1/auth"` |
| **HTTP** | `method` | `http.method` | `str` | `EQUALS`, `IN` | HTTP verb `"POST"`, `"GET"` |
| **HTTP** | `status_code` | `http.status_code` | `int` | `EQUALS`, `GREATER_EQUAL`, `IN` | Response code `200`, `500` |
| **TLS** | `server_name` | `sni`, `tls.server_name` | `str` | `EQUALS`, `ENDS_WITH`, `CONTAINS` | SNI hostname `"secure.gateway.org"` |
| **TLS** | `alpn_protocols` | `tls.alpn_protocols` | `List[str]` | `CONTAINS`, `EXISTS` | Negotiated protocol `"h2"` |
| **Transport** | `transport_protocol` | `protocol` | `str` | `EQUALS`, `IN` | Transport layer `"TCP"`, `"UDP"` |
| **Transport** | `dst_port` | `destination_port` | `int` | `EQUALS`, `IN`, `LESS_THAN`, `GREATER_THAN` | Port number `443`, `22` |
| **Transport** | `src_port` | `source_port` | `int` | `EQUALS`, `IN` | Ephemeral client port `53124` |
| **Network IP** | `dst_ip` | `destination_ip` | `str` | `EQUALS`, `IN` | Destination IPv4/IPv6 address |
| **Network IP** | `src_ip` | `source_ip` | `str` | `EQUALS`, `IN` | Source IPv4/IPv6 address |
| **Correlation** | `relationship_type` | `correlation.relationship_type` | `str` | `EQUALS`, `IN` | `"HOST_NETWORK"` |

---

## 3. How to Define and Evaluate Rules

### A. Factory Functions
ForensiX provides dedicated factory functions for standard network observation patterns:

```python
from forensix.network_rules import (
    create_dns_query_rule,
    create_http_request_rule,
    create_tls_sni_rule,
    create_network_protocol_port_rule,
    create_host_network_correlation_rule,
)
from forensix.rule_models import ConditionOperator

# 1. DNS Query Rule
dns_rule = create_dns_query_rule(
    domain_pattern="api.partner.org",
    operator=ConditionOperator.EQUALS,
    query_type="A",
)

# 2. HTTP Request Rule
http_rule = create_http_request_rule(
    host="service.local",
    target="/admin",
    target_operator=ConditionOperator.STARTS_WITH,
    method="POST",
)

# 3. TLS SNI Rule
tls_rule = create_tls_sni_rule(
    server_name="gateway.cloud.test",
    operator=ConditionOperator.EQUALS,
    alpn_protocol="h2",
)

# 4. Protocol & Port Rule
port_rule = create_network_protocol_port_rule(
    protocol="TCP",
    port=22,
    is_destination=True,
)

# 5. Host-to-Network Correlation Rule
corr_rule = create_host_network_correlation_rule(
    host_event_type="ssh_login_success",
    network_event_type="tcp_packet",
    time_window_seconds=300.0,
)
```

### B. Fluent Builder Pattern (`NetworkRuleBuilder`)
For custom or compound network detection rules:

```python
from forensix.network_rules import NetworkRuleBuilder
from forensix.rule_models import ConditionOperator
from forensix.timeline_models import TimelineCategory

rule = (
    NetworkRuleBuilder("DNS Query to Internal Database")
    .set_description("Observes DNS queries targeting internal database naming convention.")
    .set_detection_description("Observed DNS query for domain ending with '.db.internal'.")
    .match_category(TimelineCategory.NETWORK)
    .match_event_type("network_dns_metadata")
    .where("query_name", ConditionOperator.ENDS_WITH, ".db.internal")
    .where("query_type", ConditionOperator.EQUALS, "A")
    .set_time_window(60.0)
    .set_attribute("data_classification", "internal")
    .build()
)
```

### C. Rule Evaluation
Rules are evaluated using the standard `DetectionEngine`:

```python
from forensix.detection_engine import DetectionEngine

engine = DetectionEngine([dns_rule, http_rule, tls_rule, port_rule, corr_rule])
results = engine.evaluate(
    timeline=reconstructed_timeline.events,
    correlations=correlation_collection,
)

for detection in results:
    print(f"[{detection.rule_id}] {detection.rule_name} matched at {detection.start_timestamp}")
    print(f"Explanation: {detection.explanation}")
    print(f"Underlying events: {detection.matched_event_ids}")
```

---

## 4. Detection Output and Provenance

Every detection emitted by `DetectionEngine.evaluate()` is a canonical `DetectionResult` retaining full forensic provenance:

- **`detection_id`**: Deterministic RFC 4122 UUIDv5 identifier (`DET-<UUIDv5>`).
- **`rule_id` / `rule_name`**: Identity and human-readable name of the matched rule.
- **`matched`**: Always `True` for recorded detections.
- **`matched_event_ids`**: Tuple of timeline event identifiers (`TIMELINE-<UUIDv4>`) that satisfied the rule.
- **`matched_source_event_ids`**: Tuple of underlying evidence record IDs (e.g. `NETEVT-<UUIDv5>`).
- **`matched_source_artifact_ids`**: Tuple of source PCAP/artifact IDs (e.g. `ARTIFACT-<UUIDv4>`).
- **`matched_correlation_ids`**: Tuple of correlation IDs (e.g. `CORR-<UUIDv5>`) when triggered by a host-network correlation.
- **`start_timestamp` / `end_timestamp`**: Exact chronological boundaries of the observed evidence.
- **`time_delta_seconds`**: Elapsed interval ($\Delta t$) between correlated events (or `0.0` for single-event matches).
- **`explanation`**: Factual, explainable observation statement.

---

## 5. Forensic Neutrality and Safety Safeguards

### Observational Neutrality
- **No Inherent Compromise**: A rule match represents an observed factual condition (e.g., "DNS query for domain X observed", "HTTP request to path Y observed"). It is **not** proof of intrusion, malicious intent, or compromise.
- **Strict Prohibited Language**: ForensiX strictly rejects speculative attack assertions (`"confirmed attack"`, `"attacker confirmed"`, `"system compromised"`, `"malware confirmed"`, `"intrusion confirmed"`, `"attack confirmed"`, `"compromised system"`). Any rule attempting to use speculative language in names, descriptions, or explanations is rejected with a `ValueError`.
- **No Fabricated Evidence**: Missing timestamps, unobserved HTTP headers, or absent SNI fields are never fabricated. A rule condition on an absent field safely evaluates to non-match (or matches `EXISTS=False`).

### Execution Safety
- **No Dynamic Code Execution**: Rules are purely declarative data structures. No callbacks, dynamic expressions, or `eval()`/`exec()` calls exist.
- **Untrusted Input Handling**: PCAP frames and protocol metadata are treated as untrusted inputs. Malformed or unexpectedly typed fields evaluate safely without crashing the engine.
- **Deep Immutability**: All rules, conditions, and detection results are frozen immutable dataclasses.

---

## 6. Limitations and Unsupported Conditions

1. **Encrypted Payloads**: HTTP conditions cannot match inside encrypted TLS tunnels (unless decrypted prior to extraction). TLS matching is strictly limited to cleartext handshake metadata (SNI, ALPN, cipher suites, versions).
2. **Packet Fragmentation**: Transport port conditions cannot match on non-initial IP fragments lacking transport headers.
3. **Ambiguity of IP Addresses**: Matching an IP address does not prove machine identity due to NAT, proxies, and DHCP dynamic reassignment.
4. **Volume and Statistical Inferences**: ForensiX does not support speculative volume-based heuristics (e.g. "traffic anomaly" or "exfiltration threshold") as proof of maliciousness.

---

## 7. Public API Reference

The primary integration entry points are implemented in `forensix.network_rules` and exported at top-level `forensix`:

### Rule Factories
- `create_dns_query_rule(domain_pattern, *, operator=EQUALS, query_type=None, answer_data=None, ...)`
- `create_http_request_rule(*, host=None, target=None, method=None, status_code=None, ...)`
- `create_tls_sni_rule(server_name, *, operator=EQUALS, alpn_protocol=None, ...)`
- `create_network_protocol_port_rule(protocol, port, *, is_destination=True, ip_address=None, ...)`
- `create_host_network_correlation_rule(*, host_event_type=None, network_event_type=None, time_window_seconds=300.0, ...)`
- `create_canonical_network_rules() -> RuleCollection`

### Fluent Builder
- `NetworkRuleBuilder(name, description=None)`

### Canonical Constants
- `DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS: float = 300.0`
- `RULE_NAME_DNS_QUERY_PATTERN: str`
- `RULE_NAME_HTTP_REQUEST_PATTERN: str`
- `RULE_NAME_TLS_SNI_PATTERN: str`
- `RULE_NAME_PROTOCOL_PORT_PATTERN: str`
- `RULE_NAME_HOST_NETWORK_CORRELATION: str`
- `RULE_NET_01_DNS_OBSERVATION: str`
- `RULE_NET_02_HTTP_OBSERVATION: str`
- `RULE_NET_03_TLS_SNI_OBSERVATION: str`
- `RULE_NET_04_SSH_PORT_OBSERVATION: str`
- `RULE_NET_05_HOST_NETWORK_CORRELATION: str`

---

## 8. Verified Tests

The implementation was verified against the full project test suite:

- **Focused V5.7 Tests**: `tests/test_network_rules.py` (15 tests passed, 0 failures).
- **Network, Detection & Correlation Suites**: 346 tests passed, 76 subtests passed.
- **Full Project Regression Suite**: 1,084 tests passed, 238 subtests passed, 0 failures.
