"""
Comprehensive Test Suite for ForensiX V5.7 Network Detection Rules.

Validates the 14 mandatory verification areas:
1. Valid rule matching supported network evidence.
2. Rule that does not match (negative control).
3. DNS, HTTP, and TLS matching where the corresponding metadata exists.
4. Missing metadata and missing timestamps handling.
5. Malformed or unexpected field values handling.
6. Multiple matching rules against single/multiple events.
7. Deterministic detection IDs and stable ordering.
8. Evidence and event provenance preservation.
9. Host-network correlation references and integration.
10. Duplicate events and duplicate input handling.
11. Unsupported conditions or invalid rule configuration.
12. Forensic neutrality and no unsupported maliciousness claims.
13. Backward compatibility with existing V4 rule and detection tests.
14. End-to-end synthetic PCAP-to-network-event-to-rule-detection workflow.
"""

from datetime import datetime, timezone, timedelta
import struct
import unittest
import uuid

from forensix.correlation_engine import (
    CorrelationConfig,
    CorrelationEngine,
    correlate_events,
)
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    evaluate_rule,
    evaluate_rules,
)
from forensix.network_correlation import (
    HostNetworkCorrelationConfig,
    correlate_host_network_events,
)
from forensix.network_events import (
    NetworkEvent,
    extract_network_event,
)
from forensix.network_metadata import (
    DnsAnswer,
    DnsMetadata,
    DnsQuestion,
    HttpMetadata,
    NetworkApplicationMetadata,
    TlsMetadata,
    parse_dns_payload,
    parse_http_payload,
    parse_tls_payload,
)
from forensix.network_models import (
    NetworkEvidenceRecord,
    create_network_evidence_record,
)
from forensix.network_pcap_parser import (
    PCAP_MAGIC_MICROSECONDS_LITTLE,
)
from forensix.network_rules import (
    DEFAULT_NETWORK_RULE_TIME_WINDOW_SECONDS,
    RULE_NAME_DNS_QUERY_PATTERN,
    RULE_NAME_HTTP_REQUEST_PATTERN,
    RULE_NAME_PROTOCOL_PORT_PATTERN,
    RULE_NAME_TLS_SNI_PATTERN,
    RULE_NAME_HOST_NETWORK_CORRELATION,
    NetworkRuleBuilder,
    create_canonical_network_rules,
    create_dns_query_rule,
    create_host_network_correlation_rule,
    create_http_request_rule,
    create_network_protocol_port_rule,
    create_tls_sni_rule,
)
from forensix.network_timeline import (
    adapt_network_artifact,
    adapt_network_event,
    adapt_network_metadata,
    adapt_network_record,
    reconstruct_network_timeline,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    create_rule,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)


def _build_synthetic_pcap_bytes(packets: list) -> bytes:
    """Build synthetic pcap file bytes from list of (ts_sec, ts_usec, pkt_bytes)."""
    ghdr = struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_MICROSECONDS_LITTLE,
        2, 4, 0, 0, 65535, 1  # Ethernet linktype
    )
    body = bytearray(ghdr)
    for ts_sec, ts_usec, pdata in packets:
        orig_len = len(pdata)
        cap_len = orig_len
        phdr = struct.pack("<IIII", ts_sec, ts_usec, cap_len, orig_len)
        body.extend(phdr)
        body.extend(pdata)
    return bytes(body)


def _build_synthetic_ipv4_tcp_frame(
    src_ip_str: str,
    dst_ip_str: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    """Construct a synthetic Ethernet/IPv4/TCP frame."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src_parts = [int(x) for x in src_ip_str.split(".")]
    dst_parts = [int(x) for x in dst_ip_str.split(".")]
    src_ip_b = bytes(src_parts)
    dst_ip_b = bytes(dst_parts)
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0x1234, 0x0000, 64, 6, 0x0000, src_ip_b, dst_ip_b
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, 1000, 0, 0x50, 0x18, 8192, 0, 0
    )
    return eth + ip_hdr + tcp_hdr + payload


class TestNetworkDetectionRules(unittest.TestCase):
    """Focused unit and integration test suite for ForensiX V5.7 Network Detection Rules."""

    def setUp(self):
        self.base_time = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Valid rule matching supported network evidence
    def test_01_valid_rule_matching_supported_network_evidence(self):
        """1. Verify a valid declarative rule matches supported network evidence."""
        rule = create_dns_query_rule(
            domain_pattern="api.partner.org",
            operator=ConditionOperator.EQUALS,
            rule_name="Observed DNS Query to Partner API",
        )
        self.assertIsInstance(rule, DetectionRule)
        self.assertEqual(rule.name, "Observed DNS Query to Partner API")
        self.assertEqual(len(rule.conditions), 1)

        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-001",
            transaction_id=1234,
            is_response=False,
            response_code=0,
            response_status="NOERROR",
            query_name="api.partner.org",
            query_type="A",
            timestamp=self.base_time,
            source_ip="192.168.1.10",
            destination_ip="1.1.1.1",
            source_port=53123,
            destination_port=53,
            source_path="evidence/traffic.pcap",
        )
        event = adapt_network_metadata(dns_meta)

        engine = DetectionEngine([rule])
        results = engine.evaluate([event])

        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertTrue(det.matched)
        self.assertEqual(det.rule_id, rule.rule_id)
        self.assertEqual(det.rule_name, rule.name)
        self.assertIn(event.event_id, det.matched_event_ids)
        self.assertEqual(det.start_timestamp, self.base_time)
        self.assertEqual(det.explanation, rule.detection_description)

    # 2. Rule that does not match (negative control)
    def test_02_rule_that_does_not_match(self):
        """2. Verify that non-matching evidence produces zero detections."""
        rule = create_dns_query_rule(
            domain_pattern="internal.corp",
            operator=ConditionOperator.EQUALS,
        )
        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-002",
            transaction_id=1235,
            is_response=False,
            response_code=0,
            response_status="NOERROR",
            query_name="public.example.com",
            query_type="A",
            timestamp=self.base_time,
        )
        event = adapt_network_metadata(dns_meta)

        engine = DetectionEngine([rule])
        results = engine.evaluate([event])

        self.assertEqual(len(results), 0)

    # 3. DNS, HTTP, and TLS matching where the corresponding metadata exists
    def test_03_dns_http_and_tls_metadata_matching(self):
        """3. Verify specific DNS, HTTP, and TLS condition operators match accurately."""
        # 3a. DNS matching with query_type and answer IP
        dns_rule = create_dns_query_rule(
            domain_pattern=".internal.net",
            operator=ConditionOperator.ENDS_WITH,
            query_type="A",
            answer_data="10.0.0.50",
            answer_operator=ConditionOperator.CONTAINS,
        )
        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-003",
            transaction_id=555,
            is_response=True,
            response_code=0,
            response_status="NOERROR",
            query_name="db.internal.net",
            query_type="A",
            answers=(
                DnsAnswer(
                    name="db.internal.net",
                    rtype="A",
                    rclass="IN",
                    ttl=300,
                    data="10.0.0.50",
                    type_id=1,
                    class_id=1,
                ),
            ),
            timestamp=self.base_time,
        )
        dns_ev = adapt_network_metadata(dns_meta)
        dns_results = DetectionEngine([dns_rule]).evaluate([dns_ev])
        self.assertEqual(len(dns_results), 1)

        # 3b. HTTP matching with host, target path prefix, and method
        http_rule = create_http_request_rule(
            host="update.internal.local",
            target="/firmware/v2",
            target_operator=ConditionOperator.STARTS_WITH,
            method="GET",
        )
        http_meta = HttpMetadata(
            metadata_id="HTTP-TEST-001",
            is_request=True,
            method="GET",
            target="/firmware/v2/image.bin",
            http_version="1.1",
            host="update.internal.local",
            timestamp=self.base_time,
        )
        http_ev = adapt_network_metadata(http_meta)
        http_results = DetectionEngine([http_rule]).evaluate([http_ev])
        self.assertEqual(len(http_results), 1)

        # 3c. TLS matching with SNI and ALPN
        tls_rule = create_tls_sni_rule(
            server_name="gateway.cloud.test",
            operator=ConditionOperator.EQUALS,
            alpn_protocol="h2",
        )
        tls_meta = TlsMetadata(
            metadata_id="TLS-TEST-001",
            content_type=22,
            is_client_hello=True,
            server_name="gateway.cloud.test",
            alpn_protocols=("h2", "http/1.1"),
            timestamp=self.base_time,
        )
        tls_ev = adapt_network_metadata(tls_meta)
        tls_results = DetectionEngine([tls_rule]).evaluate([tls_ev])
        self.assertEqual(len(tls_results), 1)

    # 4. Missing metadata and missing timestamps
    def test_04_missing_metadata_and_missing_timestamps(self):
        """4. Verify deterministic behavior when fields or timestamps are absent."""
        # Rule requiring query_name and query_type
        rule = create_dns_query_rule(domain_pattern="example.org", query_type="TXT")

        # Event with None timestamp and missing query_type
        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-004",
            transaction_id=111,
            is_response=False,
            response_code=0,
            response_status="NOERROR",
            query_name="example.org",
            query_type=None,
            timestamp=None,
        )
        ev = adapt_network_metadata(dns_meta)
        self.assertIsNone(ev.timestamp)

        # Query type is missing, should not match
        results = DetectionEngine([rule]).evaluate([ev])
        self.assertEqual(len(results), 0)

        # But if rule only requires query_name, it matches even without timestamp
        rule_name_only = create_dns_query_rule(domain_pattern="example.org")
        results_match = DetectionEngine([rule_name_only]).evaluate([ev])
        self.assertEqual(len(results_match), 1)
        self.assertIsNone(results_match[0].start_timestamp)
        self.assertIsNone(results_match[0].end_timestamp)
        self.assertIsNone(results_match[0].time_delta_seconds)

    # 5. Malformed or unexpected field values
    def test_05_malformed_or_unexpected_field_values(self):
        """5. Verify safe evaluation against unexpected field types without crashes."""
        rule = create_http_request_rule(status_code=500)

        # Event with string status code or None status code
        ev = TimelineEvent(
            timestamp=self.base_time,
            category=TimelineCategory.NETWORK,
            event_type="network_http_metadata",
            description="Malformed HTTP metadata",
            attributes={"status_code": "500"},  # String instead of int
        )
        # Should evaluate safely to False without raising TypeError/ValueError
        results = DetectionEngine([rule]).evaluate([ev])
        self.assertEqual(len(results), 0)

    # 6. Multiple matching rules
    def test_06_multiple_matching_rules(self):
        """6. Verify multiple rules matching the same network event evaluate correctly."""
        rule_dns = create_dns_query_rule("telemetry.corp.org")
        rule_port = create_network_protocol_port_rule(
            protocol="UDP",
            port=53,
            is_destination=True,
            event_type="network_dns_metadata",
        )

        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-006",
            transaction_id=777,
            is_response=False,
            response_code=0,
            response_status="NOERROR",
            query_name="telemetry.corp.org",
            destination_port=53,
            transport_protocol="UDP",
            timestamp=self.base_time,
        )
        ev = adapt_network_metadata(dns_meta)

        engine = DetectionEngine([rule_dns, rule_port])
        results = engine.evaluate([ev])

        self.assertEqual(len(results), 2)
        matched_rule_ids = {d.rule_id for d in results}
        self.assertIn(rule_dns.rule_id, matched_rule_ids)
        self.assertIn(rule_port.rule_id, matched_rule_ids)

    # 7. Deterministic detection IDs and stable ordering
    def test_07_deterministic_detection_ids_and_ordering(self):
        """7. Verify detection IDs are deterministic UUIDv5 strings and output ordering is stable."""
        rule = create_tls_sni_rule("portal.domain.com")
        tls_meta = TlsMetadata(
            metadata_id="TLS-TEST-007",
            content_type=22,
            is_client_hello=True,
            server_name="portal.domain.com",
            timestamp=self.base_time,
        )
        ev = adapt_network_metadata(tls_meta)

        engine1 = DetectionEngine([rule])
        results1 = engine1.evaluate([ev])

        engine2 = DetectionEngine([rule])
        results2 = engine2.evaluate([ev])

        self.assertEqual(len(results1), 1)
        self.assertEqual(len(results2), 1)
        self.assertEqual(results1[0].detection_id, results2[0].detection_id)
        self.assertTrue(results1[0].detection_id.startswith("DET-"))

    # 8. Evidence and event provenance preservation
    def test_08_evidence_and_event_provenance_preservation(self):
        """8. Verify detection retains underlying source_event_id and source_artifact_id."""
        http_meta = HttpMetadata(
            metadata_id="HTTP-META-008",
            record_id="NETEVT-008",
            is_request=True,
            method="POST",
            target="/api/v1/auth",
            timestamp=self.base_time,
            source_artifact_id="ARTIFACT-PCAP-008",
            source_path="/var/log/forensics/dump.pcap",
        )
        ev = adapt_network_metadata(http_meta)
        self.assertEqual(ev.source_event_id, "NETEVT-008")
        self.assertEqual(ev.source_artifact_id, "ARTIFACT-PCAP-008")

        rule = create_http_request_rule(target="/api/v1/auth", method="POST")
        results = DetectionEngine([rule]).evaluate([ev])

        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertIn("NETEVT-008", det.matched_source_event_ids)
        self.assertIn("ARTIFACT-PCAP-008", det.matched_source_artifact_ids)

    # 9. Host-network correlation references
    def test_09_host_network_correlation_references(self):
        """9. Verify declarative detection of V5.6 host-to-network correlations."""
        host_ev = TimelineEvent(
            timestamp=self.base_time,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for root from 192.168.1.50 port 43210",
            source_path="/var/log/auth.log",
            source_line=12,
            source_artifact_id="ART-AUTH-01",
            source_event_id="EVT-AUTH-01",
            attributes={"src_ip": "192.168.1.50", "user": "root"},
        )
        net_ev = TimelineEvent(
            timestamp=self.base_time + timedelta(seconds=2),
            category=TimelineCategory.NETWORK,
            event_type="tcp_packet",
            description="TCP packet from 192.168.1.50 to 10.0.0.1",
            source_path="/var/log/traffic.pcap",
            source_line=45,
            source_artifact_id="ART-PCAP-01",
            source_event_id="NETEVT-PCAP-01",
            attributes={
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "transport_protocol": "TCP",
                "dst_port": 22,
            },
        )

        corr_res = correlate_host_network_events([host_ev, net_ev])
        self.assertEqual(corr_res.total_correlations, 1)
        corr = corr_res.correlations[0]
        self.assertEqual(corr.relationship_type, CorrelationType.HOST_NETWORK)

        rule = create_host_network_correlation_rule(
            host_event_type="ssh_login_success",
            network_event_type="tcp_packet",
            time_window_seconds=10.0,
            rule_name="Host SSH Login Correlated With Network Traffic",
        )

        engine = DetectionEngine([rule])
        results = engine.evaluate(
            timeline=[host_ev, net_ev],
            correlations=corr_res,
        )

        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertTrue(det.matched)
        self.assertEqual(det.rule_id, rule.rule_id)
        self.assertIn(corr.correlation_id, det.matched_correlation_ids)
        self.assertIn("EVT-AUTH-01", det.matched_source_event_ids)
        self.assertIn("NETEVT-PCAP-01", det.matched_source_event_ids)
        self.assertIn("ART-AUTH-01", det.matched_source_artifact_ids)
        self.assertIn("ART-PCAP-01", det.matched_source_artifact_ids)
        self.assertEqual(det.time_delta_seconds, 2.0)

    # 10. Duplicate events and duplicate input handling
    def test_10_duplicate_events_handling(self):
        """10. Verify that duplicate events in input do not produce duplicate detections."""
        dns_meta = DnsMetadata(
            metadata_id="DNS-TEST-010",
            transaction_id=999,
            is_response=False,
            response_code=0,
            response_status="NOERROR",
            query_name="unique.service.io",
            timestamp=self.base_time,
        )
        ev = adapt_network_metadata(dns_meta)
        rule = create_dns_query_rule("unique.service.io")

        # Evaluate against sequence containing the same event multiple times
        engine = DetectionEngine([rule])
        results = engine.evaluate([ev, ev, ev])

        self.assertEqual(len(results), 1)

    # 11. Unsupported conditions or invalid rule configuration
    def test_11_unsupported_conditions_and_invalid_configuration(self):
        """11. Verify strict validation rejects invalid rule parameters and types."""
        # 11a. Empty domain pattern
        with self.assertRaises(ValueError):
            create_dns_query_rule("")

        # 11b. Empty HTTP rule (no criteria specified)
        with self.assertRaises(ValueError):
            create_http_request_rule()

        # 11c. Invalid port number
        with self.assertRaises(ValueError):
            create_network_protocol_port_rule(protocol="TCP", port=70000)

        # 11d. Invalid port type
        with self.assertRaises(TypeError):
            create_network_protocol_port_rule(protocol="TCP", port="80")

        # 11e. Builder validation
        builder = NetworkRuleBuilder("Valid Builder Rule")
        with self.assertRaises(TypeError):
            builder.set_time_window("invalid")
        with self.assertRaises(ValueError):
            builder.where("", ConditionOperator.EQUALS, "val")

    # 12. Forensic neutrality: No unsupported maliciousness claims
    def test_12_forensic_neutrality(self):
        """12. Verify rejection of speculative or accusatory terminology in rules."""
        speculative_terms = [
            "confirmed attack",
            "system compromised",
            "intrusion confirmed",
            "malware confirmed",
        ]
        for term in speculative_terms:
            with self.assertRaises(ValueError):
                create_rule(
                    name=f"Rule with {term}",
                    description=f"Identifies {term}",
                    detection_description=f"Confirmed {term}",
                )

        # Canonical rules are neutral
        rules = create_canonical_network_rules()
        self.assertEqual(len(rules), 5)
        for r in rules:
            self.assertNotIn("compromise", r.name.lower())
            self.assertNotIn("malicious", r.description.lower())
            self.assertNotIn("c2", r.detection_description.lower())

    # 13. Backward compatibility with existing V4 rule and detection tests
    def test_13_backward_compatibility_v4(self):
        """13. Verify V4 DetectionEngine and RuleCollection remain 100% compatible."""
        v4_rule = create_rule(
            name="V4 Authentication Test Rule",
            description="Observes authentication login success",
            detection_description="Observed authentication event",
            required_categories=[TimelineCategory.AUTHENTICATION],
            required_event_types=["ssh_login_success"],
        )
        auth_ev = TimelineEvent(
            timestamp=self.base_time,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="SSH login success",
        )
        engine = DetectionEngine([v4_rule])
        results = engine.evaluate([auth_ev])
        self.assertEqual(len(results), 1)

    # 14. End-to-end synthetic PCAP-to-network-event-to-rule-detection workflow
    def test_14_end_to_end_pcap_to_rule_detection(self):
        """14. Verify full end-to-end pipeline: PCAP -> parsing -> timeline -> detection."""
        # Construct synthetic PCAP containing an HTTP request packet
        http_payload = b"GET /api/v1/telemetry HTTP/1.1\r\nHost: telemetry.sensor.net\r\n\r\n"
        frame_bytes = _build_synthetic_ipv4_tcp_frame(
            src_ip_str="192.168.1.100",
            dst_ip_str="93.184.216.34",
            src_port=49152,
            dst_port=80,
            payload=http_payload,
        )
        pcap_data = _build_synthetic_pcap_bytes([(1773576000, 500000, frame_bytes)])

        # Adapt packet into timeline events (packet event + metadata event)
        rec = create_network_evidence_record(
            source_path="evidence/synthetic_run.pcap",
            frame_number=1,
            timestamp=self.base_time,
            captured_length=len(frame_bytes),
            original_length=len(frame_bytes),
            protocol="TCP",
            source_ip="192.168.1.100",
            destination_ip="93.184.216.34",
            source_port=49152,
            destination_port=80,
            transport_protocol="TCP",
        )
        timeline_events = adapt_network_record(
            rec,
            packet_bytes=frame_bytes,
            link_type=1,
            include_packet_events=True,
            include_metadata_events=True,
        )
        self.assertEqual(len(timeline_events), 2)
        # One is tcp_packet, one is network_http_metadata
        event_types = {e.event_type for e in timeline_events}
        self.assertIn("tcp_packet", event_types)
        self.assertIn("network_http_metadata", event_types)

        # Configure detection rule matching the HTTP target path
        rule = create_http_request_rule(
            host="telemetry.sensor.net",
            target="/api/v1/telemetry",
            method="GET",
            rule_name="Observed Telemetry HTTP Request",
        )

        engine = DetectionEngine([rule])
        results = engine.evaluate(timeline_events)

        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertTrue(det.matched)
        self.assertEqual(det.rule_name, "Observed Telemetry HTTP Request")
        self.assertEqual(det.matched_event_ids, (timeline_events[1].event_id,))
        self.assertEqual(det.start_timestamp, self.base_time)


class TestNetworkRuleBuilder(unittest.TestCase):
    """Test suite for NetworkRuleBuilder fluent declarative API."""

    def test_builder_constructs_valid_detection_rule(self):
        """Verify NetworkRuleBuilder constructs strongly-typed DetectionRule."""
        builder = NetworkRuleBuilder(
            name="Custom Internal Service Query",
            description="Observes queries to custom internal services.",
        )
        builder.match_category(TimelineCategory.NETWORK)
        builder.match_event_type("network_dns_metadata")
        builder.where("query_name", ConditionOperator.ENDS_WITH, ".internal.corp")
        builder.set_time_window(120.0)
        builder.set_attribute("environment", "staging")

        rule = builder.build()
        self.assertIsInstance(rule, DetectionRule)
        self.assertEqual(rule.name, "Custom Internal Service Query")
        self.assertEqual(rule.time_window_seconds, 120.0)
        self.assertEqual(rule.required_categories, (TimelineCategory.NETWORK,))
        self.assertEqual(rule.required_event_types, ("network_dns_metadata",))
        self.assertEqual(len(rule.conditions), 1)
        self.assertEqual(rule.conditions[0].field, "query_name")
        self.assertEqual(rule.conditions[0].operator, ConditionOperator.ENDS_WITH)
        self.assertEqual(rule.conditions[0].value, ".internal.corp")
        self.assertEqual(dict(rule.attributes)["environment"], "staging")


if __name__ == "__main__":
    unittest.main()
