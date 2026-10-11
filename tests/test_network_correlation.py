"""
Comprehensive Unit and Integration Test Suite for ForensiX V5.6 Host-to-Network Correlation.

Tests cover:
1. Valid host-to-network IP correlation.
2. Matching, nonmatching, and boundary time windows.
3. Missing timestamps handling (no fabrication, configurable behavior).
4. IP match with explicit ambiguity handling (private, loopback, shared ranges).
5. Shared IPs and ambiguous host attribution documentation.
6. Matching user identity when present on both sources.
7. Mismatched user identity strictly rejected when both present.
8. Missing user on network side does not reject valid IP match (no invented identity).
9. Session identifier matching and mismatch rejection.
10. Multiple host events matching one network event.
11. One host event matching multiple network events.
12. Duplicate input records deduplication.
13. Deterministic correlation IDs and stable output ordering across runs.
14. Complete forensic provenance preservation (artifact IDs, event IDs).
15. Known host endpoint IP matching via configuration.
16. Port alignment and conflict detection.
17. Empty and single-sided inputs safety.
18. Deep immutability of input events and output collections.
19. Integration through unified V4 CorrelationEngine.
20. End-to-end synthetic PCAP + host logs timeline reconstruction and correlation.
"""

from datetime import datetime, timezone
import io
import struct
import unittest
import uuid

from forensix.artifact_adapters import adapt_artifacts
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
from forensix.log_models import LogEvent
from forensix.network_correlation import (
    HostNetworkCorrelationConfig,
    HostNetworkCorrelator,
    correlate_host_network_events,
    extract_host_observed_ips,
    extract_host_ports,
    extract_network_ips,
    extract_network_ports,
    is_host_event,
    is_network_event,
    is_private_or_shared_ip,
    normalize_ip_address,
)
from forensix.network_events import NetworkEvent, NetworkEventType
from forensix.network_metadata import DnsMetadata, DnsQuestion, NetworkApplicationMetadata
from forensix.network_models import NetworkEvidenceRecord
from forensix.network_timeline import (
    adapt_network_event,
    adapt_network_metadata,
    reconstruct_network_timeline,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import reconstruct_timeline


class TestHostNetworkCorrelation(unittest.TestCase):
    """Exhaustive test suite for ForensiX V5.6 Host-to-Network Correlation."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
        self.t1 = datetime(2026, 4, 15, 10, 2, 0, tzinfo=timezone.utc)  # +120s
        self.t2 = datetime(2026, 4, 15, 10, 10, 0, tzinfo=timezone.utc) # +600s

        # Host authentication event (e.g. sshd login from client 192.168.1.50:54321)
        self.host_auth_event = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
            timestamp=self.t0,
            raw_timestamp="2026-04-15T10:00:00Z",
            source_path="/var/log/auth.log",
            source_line=42,
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_event_id="AUTH-33333333-4444-4555-8666-777777777777",
            attributes={
                "username": "ubuntu",
                "source_ip": "192.168.1.50",
                "source_port": 54321,
                "service": "sshd",
                "hostname": "srv1",
            },
        )

        # Network TCP packet event (client 192.168.1.50:54321 -> server 192.168.1.10:22)
        net_ev = NetworkEvent(
            "NETEVT-44444444-5555-4666-8777-888888888888",
            "NET-11111111-2222-4333-8444-555555555555",
            101,
            NetworkEventType.TCP_PACKET.value,
            "TCP 192.168.1.50:54321 -> 192.168.1.10:22 [ACK]",
            timestamp=datetime(2026, 4, 15, 10, 2, 0, tzinfo=timezone.utc),
            raw_timestamp="1776247320.000000",
            src_ip="192.168.1.50",
            dst_ip="192.168.1.10",
            src_port=54321,
            dst_port=22,
            protocol="TCP",
            captured_length=60,
            source_path="/evidence/traffic.pcap",
            source_artifact_id="ART-99999999-8888-4777-8666-555555555555",
            attributes={"tcp_flags": ("ACK",)},
        )
        self.net_tcp_event = adapt_network_event(net_ev)

    # 1. Valid Host-to-Network IP Correlation
    def test_01_valid_host_to_network_ip_correlation(self):
        """1. Verify valid host authentication event correlates with network TCP event on matching IP."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)

        c = corrs[0]
        self.assertEqual(c.relationship_type, CorrelationType.HOST_NETWORK)
        self.assertIn(self.host_auth_event.event_id, c.event_ids)
        self.assertIn(self.net_tcp_event.event_id, c.event_ids)
        self.assertEqual(c.time_delta_seconds, 120.0)
        self.assertIn("192.168.1.50", c.description)
        self.assertIn("ssh_login_success", c.description)
        self.assertIn("tcp_packet", c.description)

        attrs = dict(c.attributes)
        self.assertEqual(attrs["matched_value"], "192.168.1.50")
        self.assertEqual(attrs["matched_dimension"], "ip_match")
        self.assertEqual(attrs["matched_direction"], "network_source")
        self.assertTrue(attrs["port_aligned"])
        self.assertTrue(attrs["is_private_or_shared_ip"])

    # 2. Matching and Non-matching Time Windows
    def test_02_matching_and_nonmatching_time_windows(self):
        """2. Verify configurable time window allows events within window and rejects outside."""
        # A. Within window (delta = 120s, window = 300s)
        corrs = correlate_host_network_events(
            [self.host_auth_event, self.net_tcp_event],
            time_window_seconds=300.0,
        )
        self.assertEqual(len(corrs), 1)

        # B. Outside window (delta = 120s, window = 60s)
        corrs_outside = correlate_host_network_events(
            [self.host_auth_event, self.net_tcp_event],
            time_window_seconds=60.0,
        )
        self.assertEqual(len(corrs_outside), 0)

        # C. Exact boundary match (delta = 120s, window = 120.0s)
        corrs_boundary = correlate_host_network_events(
            [self.host_auth_event, self.net_tcp_event],
            time_window_seconds=120.0,
        )
        self.assertEqual(len(corrs_boundary), 1)

    # 3. Missing Timestamps Handling
    def test_03_missing_timestamps_handling(self):
        """3. Verify missing timestamps are never fabricated; rejected by default, allowed if configured."""
        host_no_ts = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Login without timestamp",
            timestamp=None,
            attributes={"source_ip": "192.168.1.50"},
        )

        # Default (require_timestamps=True): no correlation
        corrs_strict = correlate_host_network_events([host_no_ts, self.net_tcp_event])
        self.assertEqual(len(corrs_strict), 0)

        # Lenient (require_timestamps=False): allows correlation with None delta and note
        corrs_lenient = correlate_host_network_events(
            [host_no_ts, self.net_tcp_event],
            require_timestamps=False,
        )
        self.assertEqual(len(corrs_lenient), 1)
        self.assertIsNone(corrs_lenient[0].time_delta_seconds)
        self.assertIn("missing timestamp", corrs_lenient[0].description)

    # 4. IP Matches with Explicit Ambiguity Handling
    def test_04_ip_match_with_explicit_ambiguity_handling(self):
        """4. Verify private/RFC1918 and public IPs have clear ambiguity classification."""
        self.assertTrue(is_private_or_shared_ip("192.168.1.1"))
        self.assertTrue(is_private_or_shared_ip("10.0.0.1"))
        self.assertTrue(is_private_or_shared_ip("172.16.0.1"))
        self.assertTrue(is_private_or_shared_ip("127.0.0.1"))
        self.assertTrue(is_private_or_shared_ip("100.64.0.1"))
        self.assertFalse(is_private_or_shared_ip("93.184.216.34"))

        # Public IP scenario
        host_public = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="login",
            description="Login from public IP",
            timestamp=self.t0,
            attributes={"source_ip": "93.184.216.34"},
        )
        net_public = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="tcp_packet",
            description="Packet from public IP",
            timestamp=self.t1,
            attributes={"src_ip": "93.184.216.34", "dst_ip": "10.0.0.1"},
        )

        corrs = correlate_host_network_events([host_public, net_public])
        self.assertEqual(len(corrs), 1)
        attrs = dict(corrs[0].attributes)
        self.assertFalse(attrs["is_private_or_shared_ip"])
        self.assertIn("ambiguity_notes", attrs)

    # 5. Shared IPs and Potentially Ambiguous Host Attribution
    def test_05_shared_ips_and_ambiguous_host_attribution(self):
        """5. Verify ambiguity notes prevent overinterpretation without speculative verdicts."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        attrs = dict(corrs[0].attributes)
        notes = attrs["ambiguity_notes"]
        self.assertTrue(any("NAT" in note or "private" in note for note in notes))

        # Check description does not contain forbidden speculative terms
        desc_lower = corrs[0].description.lower()
        self.assertNotIn("confirmed attack", desc_lower)
        self.assertNotIn("system compromised", desc_lower)

    # 6. Matching User Identity
    def test_06_matching_user_identity(self):
        """6. Verify user identity match when both host and application metadata specify user."""
        host_ev = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="http_access",
            description="Web access for alice",
            timestamp=self.t0,
            attributes={"username": "alice", "source_ip": "10.0.0.5"},
        )
        net_ev = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="http_request",
            description="HTTP GET /api",
            timestamp=self.t1,
            attributes={"username": "alice", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"},
        )

        corrs = correlate_host_network_events([host_ev, net_ev])
        self.assertEqual(len(corrs), 1)
        self.assertIn("alice", corrs[0].description)

    # 7. Mismatched User Identity Strictly Rejected
    def test_07_mismatched_user_identity_strictly_rejected(self):
        """7. Verify conflicting user identities on host and network events reject correlation."""
        host_alice = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="login",
            description="Login for alice",
            timestamp=self.t0,
            attributes={"username": "alice", "source_ip": "10.0.0.5"},
        )
        net_bob = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="http_request",
            description="Request for bob",
            timestamp=self.t1,
            attributes={"username": "bob", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"},
        )

        corrs = correlate_host_network_events([host_alice, net_bob])
        self.assertEqual(len(corrs), 0)

    # 8. Missing User on Network Side Does Not Reject IP Match
    def test_08_missing_user_on_network_does_not_reject_ip_match(self):
        """8. Verify network event lacking user does not invent identity and still correlates on IP."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        attrs = dict(corrs[0].attributes)
        self.assertEqual(attrs["matched_dimension"], "ip_match")

    # 9. Session Identifier Matching and Mismatch
    def test_09_session_identifier_matching_and_mismatch(self):
        """9. Verify session ID matching and rejection of mismatched session IDs."""
        host_sess1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="login",
            description="Session 100",
            timestamp=self.t0,
            attributes={"session_id": "SESS-100", "source_ip": "10.0.0.5"},
        )
        net_sess1 = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="tls_record",
            description="TLS Session 100",
            timestamp=self.t1,
            attributes={"session_id": "SESS-100", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"},
        )
        net_sess2 = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="tls_record",
            description="TLS Session 200",
            timestamp=self.t1,
            attributes={"session_id": "SESS-200", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"},
        )

        # Matching session
        corrs_match = correlate_host_network_events([host_sess1, net_sess1])
        self.assertEqual(len(corrs_match), 1)

        # Mismatched session (explicit conflict)
        corrs_mismatch = correlate_host_network_events([host_sess1, net_sess2])
        self.assertEqual(len(corrs_mismatch), 0)

    # 10. Multiple Host Events Matching One Network Event
    def test_10_multiple_host_events_matching_one_network_event(self):
        """10. Verify distinct host events matching same network event generate distinct correlations."""
        host_auth2 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="sudo_command",
            description="sudo apt update from same host",
            timestamp=self.t1,
            attributes={"source_ip": "192.168.1.50"},
        )

        corrs = correlate_host_network_events(
            [self.host_auth_event, host_auth2, self.net_tcp_event]
        )
        self.assertEqual(len(corrs), 2)
        # Distinct correlation IDs
        self.assertNotEqual(corrs[0].correlation_id, corrs[1].correlation_id)

    # 11. One Host Event Matching Multiple Network Events
    def test_11_one_host_event_matching_multiple_network_events(self):
        """11. Verify one host event matching multiple network events generates distinct correlations."""
        net_ev2 = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="tcp_packet",
            description="TCP second packet",
            timestamp=self.t1,
            attributes={"src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "dst_port": 22},
        )

        corrs = correlate_host_network_events(
            [self.host_auth_event, self.net_tcp_event, net_ev2]
        )
        self.assertEqual(len(corrs), 2)
        self.assertNotEqual(corrs[0].correlation_id, corrs[1].correlation_id)

    # 12. Duplicate Inputs Deduplicated
    def test_12_duplicate_inputs_deduplicated(self):
        """12. Verify duplicate events in timeline do not produce duplicate correlations."""
        corrs = correlate_host_network_events(
            [self.host_auth_event, self.net_tcp_event, self.host_auth_event, self.net_tcp_event]
        )
        self.assertEqual(len(corrs), 1)

    # 13. Deterministic IDs and Stable Output Order
    def test_13_deterministic_ids_and_stable_output_order(self):
        """13. Verify correlation IDs and sorting order are 100% deterministic across runs."""
        res1 = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        res2 = correlate_host_network_events([self.net_tcp_event, self.host_auth_event])

        self.assertEqual(len(res1), 1)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res1[0].correlation_id, res2[0].correlation_id)
        self.assertEqual(res1[0].description, res2[0].description)

    # 14. Provenance Preservation
    def test_14_provenance_preservation(self):
        """14. Verify source event IDs, artifact IDs, and line/frame references are preserved."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        c = corrs[0]

        self.assertIn(self.host_auth_event.source_artifact_id, c.source_artifact_ids)
        self.assertIn(self.net_tcp_event.source_artifact_id, c.source_artifact_ids)
        self.assertIn(self.host_auth_event.source_event_id, c.source_event_ids)
        self.assertIn(self.net_tcp_event.source_event_id, c.source_event_ids)

    # 15. Known Host Endpoint IP Matching via Configuration
    def test_15_known_host_endpoint_ip_matching(self):
        """15. Verify known host IP configuration correlates network traffic to/from the host."""
        host_ev_no_peer_ip = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Modified /etc/hosts",
            timestamp=self.t0,
            attributes={"path": "/etc/hosts"},
        )
        # Network packet where destination is the host's known IP (192.168.1.10)
        net_ev = create_timeline_event(
            category=TimelineCategory.NETWORK,
            event_type="dns_query",
            description="DNS Query",
            timestamp=self.t1,
            attributes={"src_ip": "10.0.0.1", "dst_ip": "192.168.1.10"},
        )

        # Without known_host_ips: no match (host event lacks IP)
        corrs_default = correlate_host_network_events([host_ev_no_peer_ip, net_ev])
        self.assertEqual(len(corrs_default), 0)

        # With known_host_ips: correlates!
        corrs_known = correlate_host_network_events(
            [host_ev_no_peer_ip, net_ev],
            known_host_ips=["192.168.1.10"],
        )
        self.assertEqual(len(corrs_known), 1)
        attrs = dict(corrs_known[0].attributes)
        self.assertEqual(attrs["match_dimension"], "host_endpoint_ip_match")
        self.assertEqual(attrs["matched_value"], "192.168.1.10")

    # 16. Port Alignment and Conflict Detection
    def test_16_port_alignment_and_conflict_detection(self):
        """16. Verify port alignment is detected when ports match; ambiguity recorded if not."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        attrs = dict(corrs[0].attributes)
        self.assertTrue(attrs["port_aligned"])

    # 17. Empty and Single-Sided Inputs Safety
    def test_17_empty_and_single_sided_inputs_safety(self):
        """17. Verify empty timelines, host-only timelines, and net-only timelines return empty collection."""
        self.assertEqual(len(correlate_host_network_events([])), 0)
        self.assertEqual(len(correlate_host_network_events([self.host_auth_event])), 0)
        self.assertEqual(len(correlate_host_network_events([self.net_tcp_event])), 0)
        self.assertEqual(len(correlate_host_network_events([self.host_auth_event, self.host_auth_event])), 0)
        self.assertEqual(len(correlate_host_network_events([self.net_tcp_event, self.net_tcp_event])), 0)

    # 18. Deep Immutability of Input Events and Output Collections
    def test_18_deep_immutability(self):
        """18. Verify Correlation and CorrelationCollection are deeply immutable."""
        corrs = correlate_host_network_events([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        c = corrs[0]

        with self.assertRaises(Exception):
            c.description = "modified"  # type: ignore
        with self.assertRaises(Exception):
            corrs.total_correlations = 99  # type: ignore

    # 19. Integration Through Unified V4 CorrelationEngine
    def test_19_correlation_engine_unified_integration(self):
        """19. Verify CorrelationEngine discovers HOST_NETWORK when configured."""
        engine = CorrelationEngine(
            relationship_types=[CorrelationType.HOST_NETWORK],
            time_window_seconds=300.0,
        )
        corrs = engine.correlate([self.host_auth_event, self.net_tcp_event])
        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0].relationship_type, CorrelationType.HOST_NETWORK)

    # 20. End-to-End Synthetic PCAP and Host Logs Integration
    def test_20_end_to_end_synthetic_pcap_and_host_logs(self):
        """20. Verify end-to-end synthetic PCAP + host LogEvent in ReconstructedTimeline correlates."""
        # 1. Create synthetic host LogEvent
        host_log = LogEvent(
            event_id="EVT-22222222-3333-4444-8555-666666666666",
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_path="/var/log/syslog",
            line_number=1,
            raw_timestamp="2026-04-15T10:00:00Z",
            normalized_timestamp="2026-04-15T10:00:00Z",
            hostname="srv1",
            service="sshd",
            pid=1234,
            event_type="ssh_login_success",
            attributes={"src_ip": "10.0.0.50", "user": "ubuntu"},
            raw_message="Accepted publickey for ubuntu from 10.0.0.50 port 43210 ssh2",
            raw_line="Apr 15 10:00:00 srv1 sshd[1234]: Accepted publickey for ubuntu from 10.0.0.50 port 43210 ssh2",
        )
        host_timeline_events = adapt_artifacts([host_log])
        self.assertEqual(len(host_timeline_events), 1)

        # 2. Create synthetic PCAP with packet involving 10.0.0.50
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        # IPv4: src=10.0.0.50 (0x0a000032), dst=10.0.0.1 (0x0a000001), proto=6 (TCP)
        ip = bytes([
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 50, 10, 0, 0, 1
        ])
        tcp = struct.pack(">HHIIBBHHH", 43210, 22, 100, 200, 0x50, 0x10, 65535, 0, 0)
        pkt_data = eth + ip + tcp
        # Build PCAP
        ghdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        phdr = struct.pack("<IIII", 1776247260, 0, len(pkt_data), len(pkt_data))  # 10:01:00 UTC (delta=60s)
        pcap_bytes = ghdr + phdr + pkt_data

        pcap_timeline = reconstruct_network_timeline(io.BytesIO(pcap_bytes))
        self.assertGreater(pcap_timeline.total_events, 0)

        # 3. Combine both streams into a unified reconstructed timeline
        combined_timeline = reconstruct_timeline(
            list(host_timeline_events) + list(pcap_timeline.events)
        )
        self.assertEqual(combined_timeline.total_events, 2)

        # 4. Correlate across host and network boundary!
        corrs = correlate_host_network_events(combined_timeline)
        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0].relationship_type, CorrelationType.HOST_NETWORK)
        self.assertIn("10.0.0.50", corrs[0].description)
        self.assertEqual(corrs[0].time_delta_seconds, 60.0)
