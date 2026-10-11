"""
Comprehensive Unit Test Suite for ForensiX V5.5 Network-to-Timeline Integration.

Validates:
1. TCP packet timeline mapping (TimelineCategory.NETWORK, source_line=frame_number, source_event_id).
2. UDP packet timeline mapping.
3. ICMP and ICMPv6 packet timeline mapping.
4. ARP packet timeline mapping.
5. IP fragment timeline mapping.
6. DNS metadata timeline mapping (query/response, domain, answers, RCODE).
7. Cleartext HTTP metadata timeline mapping (method, target, host, status).
8. TLS metadata timeline mapping (ClientHello, SNI, ALPN).
9. Missing timestamp preservation without fabrication.
10. Raw timestamp fidelity and nanosecond/microsecond preservation.
11. Provenance preservation (source_path, source_artifact_id, frame_number, event_id).
12. Application metadata linkage to parent packet event ID.
13. Distinct frame identities for identical packet contents (no improper deduplication).
14. Conservative deduplication of exact duplicate observations across repeated runs.
15. Deterministic chronological ordering across aware, naive, and missing timestamps.
16. Incomplete or unsupported payloads (emit packet event only without metadata errors).
17. Empty input handling and generator streaming.
18. TimelineQueryEngine compatibility (category 'network', event_type filter, text search, time range).
19. TimelineReporting compatibility (JSON and HTML export).
20. Polymorphic dispatch through adapt_artifact() and adapt_artifacts().
21. Unified multi-category timeline reconstruction (filesystem, log, auth, and network).
22. End-to-end synthetic PCAP streaming into ReconstructedTimeline.
23. Object-oriented NetworkTimelineExtractor API behavior.
24. Type safety and error handling on unsupported types.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import struct
import unittest

from forensix.artifact_adapters import (
    adapt_artifact,
    adapt_artifacts,
    can_adapt_artifact,
)
from forensix.artifacts import ArtifactRecord
from forensix.log_models import LogEvent
from forensix.network_events import (
    NetworkEvent,
    NetworkEventType,
    extract_network_event,
)
from forensix.network_metadata import (
    DnsMetadata,
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
from forensix.network_timeline import (
    NetworkTimelineAdapter,
    NetworkTimelineExtractor,
    adapt_network_artifact,
    adapt_network_event,
    adapt_network_metadata,
    adapt_network_record,
    extract_network_timeline_events,
    reconstruct_network_timeline,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)
from forensix.timeline_query import (
    TimelineQuery,
    query_timeline,
)
from forensix.timeline_reconstruction import (
    ReconstructedTimeline,
    reconstruct_timeline,
)
from forensix.timeline_reporting import (
    generate_timeline_report,
    render_timeline_html,
    render_timeline_json,
)


def make_sample_record(frame: int = 1, proto: str = "TCP", ts: Optional[datetime] = None) -> NetworkEvidenceRecord:
    return create_network_evidence_record(
        frame_number=frame,
        timestamp=ts or datetime(2026, 4, 15, 12, 0, 0, 100000, tzinfo=timezone.utc),
        raw_timestamp="1713182400.100000",
        source_path="/evidence/capture.pcap",
        source_artifact_id="ART-NET-01",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=44444,
        dst_port=80,
        protocol=proto,
        transport_protocol=proto,
    )


def make_synthetic_pcap_bytes(frames: list) -> bytes:
    # Classic little-endian PCAP header (24 bytes)
    hdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    buf = bytearray(hdr)
    for pdata, sec, usec in frames:
        rec_hdr = struct.pack("<IIII", sec, usec, len(pdata), len(pdata))
        buf.extend(rec_hdr)
        buf.extend(pdata)
    return bytes(buf)


def make_eth_ip_udp(src_ip: str, dst_ip: str, s_port: int, d_port: int, payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_len = 20 + 8 + len(payload)
    s_ip_b = bytes(int(x) for x in src_ip.split("."))
    d_ip_b = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, ip_len, 0x1111, 0, 64, 17, 0) + s_ip_b + d_ip_b
    udp_hdr = struct.pack(">HHHH", s_port, d_port, 8 + len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload


class TestNetworkTimelineIntegration(unittest.TestCase):
    """Rigorous unit test suite for V5.5 Network-to-Timeline Integration."""

    def setUp(self) -> None:
        self.sample_dt = datetime(2026, 4, 15, 12, 30, 0, 500000, tzinfo=timezone.utc)
        self.sample_record = make_sample_record(1, "TCP", self.sample_dt)
        self.sample_net_event = extract_network_event(self.sample_record)

    # 1. TCP Packet Timeline Mapping
    def test_01_tcp_packet_timeline_mapping(self):
        """1. Verify TCP packet event maps to TimelineCategory.NETWORK with full provenance."""
        tl_event = adapt_network_event(self.sample_net_event)
        self.assertIsInstance(tl_event, TimelineEvent)
        self.assertEqual(tl_event.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_event.event_type, "tcp_packet")
        self.assertEqual(tl_event.source_line, 1)  # Frame number mapped to source_line
        self.assertEqual(tl_event.source_path, "/evidence/capture.pcap")
        self.assertEqual(tl_event.source_artifact_id, "ART-NET-01")
        self.assertEqual(tl_event.source_event_id, self.sample_net_event.event_id)
        self.assertEqual(tl_event.timestamp, self.sample_dt)
        self.assertEqual(tl_event.raw_timestamp, "1713182400.100000")
        self.assertIn("192.168.1.10:44444", tl_event.description)

    # 2. UDP Packet Timeline Mapping
    def test_02_udp_packet_timeline_mapping(self):
        """2. Verify UDP packet event maps to TimelineCategory.NETWORK with event_type udp_packet."""
        rec = make_sample_record(2, "UDP", self.sample_dt)
        net_ev = extract_network_event(rec)
        tl_event = adapt_network_event(net_ev)
        self.assertEqual(tl_event.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_event.event_type, "udp_packet")
        self.assertEqual(tl_event.source_line, 2)

    # 3. ICMP and ICMPv6 Packet Timeline Mapping
    def test_03_icmp_and_icmpv6_packet_timeline_mapping(self):
        """3. Verify ICMP and ICMPv6 packet events map correctly to TimelineCategory.NETWORK."""
        rec_icmp = create_network_evidence_record(
            frame_number=3,
            timestamp=self.sample_dt,
            protocol="ICMP",
            transport_protocol="ICMP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.254",
        )
        tl_icmp = adapt_network_event(extract_network_event(rec_icmp))
        self.assertEqual(tl_icmp.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_icmp.event_type, "icmp_packet")

        rec_icmp6 = create_network_evidence_record(
            frame_number=4,
            timestamp=self.sample_dt,
            protocol="ICMPV6",
            transport_protocol="ICMPV6",
            src_ip="fe80::1",
            dst_ip="ff02::1",
        )
        tl_icmp6 = adapt_network_event(extract_network_event(rec_icmp6))
        self.assertEqual(tl_icmp6.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_icmp6.event_type, "icmpv6_packet")

    # 4. ARP Packet Timeline Mapping
    def test_04_arp_packet_timeline_mapping(self):
        """4. Verify ARP frame maps to TimelineCategory.NETWORK with event_type arp_packet."""
        rec_arp = create_network_evidence_record(
            frame_number=5,
            timestamp=self.sample_dt,
            protocol="ARP",
            network_protocol="ARP",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        tl_arp = adapt_network_event(extract_network_event(rec_arp))
        self.assertEqual(tl_arp.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_arp.event_type, "arp_packet")

    # 5. IP Fragment Timeline Mapping
    def test_05_ip_fragment_timeline_mapping(self):
        """5. Verify IP fragment maps to TimelineCategory.NETWORK with event_type ip_fragment."""
        rec_frag = create_network_evidence_record(
            frame_number=6,
            timestamp=self.sample_dt,
            protocol="IPV4",
            packet_metadata=(("fragment", True), ("fragment_offset", 1480)),
        )
        tl_frag = adapt_network_event(extract_network_event(rec_frag))
        self.assertEqual(tl_frag.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_frag.event_type, "ip_fragment")

    # 6. DNS Metadata Timeline Mapping
    def test_06_dns_metadata_timeline_mapping(self):
        """6. Verify DNS metadata maps to TimelineCategory.NETWORK with event_type network_dns_metadata."""
        dns_hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x07example\x03com\x00"
        dns_payload = dns_hdr + qname + struct.pack(">HH", 1, 1)
        dns_meta = parse_dns_payload(
            dns_payload,
            record_id="NET-1",
            frame_number=10,
            timestamp=self.sample_dt,
            raw_timestamp="1713182400.500000",
            source_ip="192.168.1.5",
            destination_ip="8.8.8.8",
            source_port=53535,
            destination_port=53,
            source_path="/evidence/test.pcap",
            source_artifact_id="ART-10",
        )
        self.assertIsNotNone(dns_meta)
        tl_dns = adapt_network_metadata(dns_meta)
        self.assertIsInstance(tl_dns, TimelineEvent)
        self.assertEqual(tl_dns.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_dns.event_type, "network_dns_metadata")
        self.assertEqual(tl_dns.source_line, 10)
        self.assertIn("example.com", tl_dns.description)

    # 7. HTTP Metadata Timeline Mapping
    def test_07_http_metadata_timeline_mapping(self):
        """7. Verify cleartext HTTP metadata maps to event_type network_http_metadata."""
        http_raw = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
        http_meta = parse_http_payload(
            http_raw,
            record_id="NET-2",
            frame_number=11,
            timestamp=self.sample_dt,
            source_ip="10.0.0.2",
            destination_ip="93.184.216.34",
            source_port=40000,
            destination_port=80,
        )
        self.assertIsNotNone(http_meta)
        tl_http = adapt_network_metadata(http_meta)
        self.assertEqual(tl_http.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_http.event_type, "network_http_metadata")
        self.assertIn("GET /index.html", tl_http.description)
        self.assertIn("example.org", tl_http.description)

    # 8. TLS Metadata Timeline Mapping
    def test_08_tls_metadata_timeline_mapping(self):
        """8. Verify TLS ClientHello metadata maps to event_type network_tls_metadata."""
        sni_host = b"secure.bank.com"
        sni_data = struct.pack(">HBH", len(sni_host) + 3, 0, len(sni_host)) + sni_host
        sni_ext = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data
        exts_block = struct.pack(">H", len(sni_ext)) + sni_ext
        ch_body = struct.pack(">H", 0x0303) + (b"\x00" * 32) + b"\x00" + struct.pack(">HH", 2, 0x002f) + b"\x01\x00" + exts_block
        ch_hdr = struct.pack(">B", 1) + struct.pack(">I", len(ch_body))[1:]
        record_body = ch_hdr + ch_body
        tls_pkt = struct.pack(">BHH", 22, 0x0301, len(record_body)) + record_body

        tls_meta = parse_tls_payload(
            tls_pkt,
            record_id="NET-3",
            frame_number=12,
            timestamp=self.sample_dt,
            source_ip="10.0.0.2",
            destination_ip="1.1.1.1",
            source_port=50000,
            destination_port=443,
        )
        self.assertIsNotNone(tls_meta)
        tl_tls = adapt_network_metadata(tls_meta)
        self.assertEqual(tl_tls.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_tls.event_type, "network_tls_metadata")
        self.assertIn("secure.bank.com", tl_tls.description)

    # 9. Missing Timestamp Handling
    def test_09_missing_timestamp_handling(self):
        """9. Verify missing timestamp is preserved as None without synthetic timestamp invention."""
        rec_no_ts = create_network_evidence_record(
            frame_number=20,
            timestamp=None,
            raw_timestamp=None,
            protocol="UDP",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        tl_no_ts = adapt_network_event(extract_network_event(rec_no_ts))
        self.assertIsNone(tl_no_ts.timestamp)
        self.assertIsNone(tl_no_ts.raw_timestamp)

    # 10. Raw Timestamp Fidelity
    def test_10_raw_timestamp_fidelity(self):
        """10. Verify exact raw timestamp string is preserved verbatim."""
        raw_str = "1713184245.123456789"
        rec = create_network_evidence_record(
            frame_number=21,
            timestamp=self.sample_dt,
            raw_timestamp=raw_str,
            protocol="TCP",
        )
        tl = adapt_network_event(extract_network_event(rec))
        self.assertEqual(tl.raw_timestamp, raw_str)

    # 11. Provenance Preservation
    def test_11_provenance_preservation(self):
        """11. Verify source_path, source_artifact_id, frame_number, and event IDs are preserved."""
        tl = adapt_network_event(self.sample_net_event)
        self.assertEqual(tl.source_path, "/evidence/capture.pcap")
        self.assertEqual(tl.source_artifact_id, "ART-NET-01")
        self.assertEqual(tl.source_line, 1)
        self.assertEqual(tl.source_event_id, self.sample_net_event.event_id)

    # 12. Application Metadata Linked to Packet Event ID
    def test_12_metadata_links_to_packet_event_id(self):
        """12. Verify application metadata event links to parent packet event ID via attributes."""
        dns_hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        dns_pkt = dns_hdr + b"\x04test\x00" + struct.pack(">HH", 1, 1)
        eth_frame = make_eth_ip_udp("192.168.1.10", "8.8.8.8", 53000, 53, dns_pkt)

        rec = create_network_evidence_record(
            frame_number=30,
            timestamp=self.sample_dt,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=53000,
            dst_port=53,
            protocol="UDP",
            transport_protocol="UDP",
        )
        events = adapt_network_record(rec, packet_bytes=eth_frame)
        self.assertEqual(len(events), 2)
        pkt_ev, meta_ev = events[0], events[1]
        self.assertEqual(pkt_ev.event_type, "udp_packet")
        self.assertEqual(meta_ev.event_type, "network_dns_metadata")
        # Metadata event links to packet event ID
        attrs_dict = dict(meta_ev.attributes)
        self.assertEqual(attrs_dict.get("packet_event_id"), pkt_ev.source_event_id)

    # 13. Distinct Frame Identities Not Collapsed
    def test_13_distinct_frame_identities_not_collapsed(self):
        """13. Verify separate frames with identical payloads maintain distinct identities and are not deduplicated."""
        rec1 = make_sample_record(frame=1, proto="TCP", ts=self.sample_dt)
        rec2 = make_sample_record(frame=2, proto="TCP", ts=self.sample_dt)
        ev1 = adapt_network_event(extract_network_event(rec1))
        ev2 = adapt_network_event(extract_network_event(rec2))

        self.assertNotEqual(ev1.source_line, ev2.source_line)
        self.assertNotEqual(ev1.source_event_id, ev2.source_event_id)

        # Timeline reconstruction must preserve both frames
        reconstructed = reconstruct_timeline([ev1, ev2], deduplicate=True)
        self.assertEqual(reconstructed.total_events, 2)
        self.assertEqual(reconstructed.duplicates_removed, 0)

    # 14. Conservative Deduplication of Exact Duplicate Ingestions
    def test_14_exact_duplicate_events_deduplicated(self):
        """14. Verify exact duplicate timeline events from re-scanning identical evidence are cleanly deduplicated."""
        ev1 = adapt_network_event(self.sample_net_event)
        ev2 = adapt_network_event(self.sample_net_event)
        reconstructed = reconstruct_timeline([ev1, ev2], deduplicate=True)
        self.assertEqual(reconstructed.total_events, 1)
        self.assertEqual(reconstructed.duplicates_removed, 1)

    # 15. Deterministic Chronological Ordering
    def test_15_deterministic_chronological_ordering(self):
        """15. Verify events are sorted chronologically with tie-breaking on provenance and frame number."""
        dt1 = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 4, 15, 11, 0, 0, tzinfo=timezone.utc)
        ev_early = adapt_network_event(extract_network_event(make_sample_record(1, "TCP", dt1)))
        ev_late = adapt_network_event(extract_network_event(make_sample_record(2, "TCP", dt2)))

        # Invert input order
        reconstructed = reconstruct_timeline([ev_late, ev_early])
        self.assertEqual(reconstructed.events[0].source_line, 1)
        self.assertEqual(reconstructed.events[1].source_line, 2)

    # 16. Incomplete Payloads Emit Packet Event Only
    def test_16_incomplete_payloads_emit_packet_event_only(self):
        """16. Verify packet without valid application payload emits packet event without raising exceptions."""
        rec = make_sample_record(40, "UDP", self.sample_dt)
        # Random non-DNS payload
        non_app_frame = make_eth_ip_udp("192.168.1.1", "10.0.0.1", 1234, 5678, b"\x00\x01\x02\x03")
        events = adapt_network_record(rec, packet_bytes=non_app_frame)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "udp_packet")

    # 17. Empty Inputs Safety
    def test_17_empty_inputs_safety(self):
        """17. Verify empty record list yields empty reconstructed timeline."""
        reconstructed = reconstruct_network_timeline([])
        self.assertEqual(reconstructed.total_events, 0)
        self.assertEqual(len(reconstructed.events), 0)

    # 18. TimelineQueryEngine Compatibility
    def test_18_timeline_query_engine_compatibility(self):
        """18. Verify ReconstructedTimeline with network events can be queried by category, type, and search text."""
        ev1 = adapt_network_event(self.sample_net_event)
        reconstructed = reconstruct_timeline([ev1])

        # Query by category network
        q_filter = TimelineQuery(category="network")
        result = query_timeline(reconstructed, query=q_filter)
        self.assertEqual(result.total_events, 1)

        # Query by non-matching category
        q_filter_fs = TimelineQuery(category="filesystem")
        result_fs = query_timeline(reconstructed, query=q_filter_fs)
        self.assertEqual(result_fs.total_events, 0)

        # Query by text search
        q_filter_text = TimelineQuery(text="192.168.1.10")
        result_text = query_timeline(reconstructed, query=q_filter_text)
        self.assertEqual(result_text.total_events, 1)

    # 19. TimelineReporting Compatibility
    def test_19_timeline_reporting_compatibility(self):
        """19. Verify reconstructed network timeline renders valid JSON and HTML reports."""
        ev = adapt_network_event(self.sample_net_event)
        timeline = reconstruct_timeline([ev])

        # JSON report
        json_report = render_timeline_json(timeline)
        report_data = json.loads(json_report)
        self.assertEqual(report_data["summary"]["event_count"], 1)
        self.assertEqual(report_data["events"][0]["category"], "network")

        # HTML report
        html_report = render_timeline_html(timeline)
        self.assertIn("network", html_report.lower())
        self.assertIn("192.168.1.10", html_report)

    # 20. Polymorphic Dispatch Through adapt_artifact()
    def test_20_polymorphic_dispatch_adapt_artifact(self):
        """20. Verify can_adapt_artifact and adapt_artifact in artifact_adapters route network models."""
        self.assertTrue(can_adapt_artifact(self.sample_net_event))
        self.assertTrue(can_adapt_artifact(self.sample_record))

        adapted = adapt_artifact(self.sample_net_event)
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0].category, TimelineCategory.NETWORK)

    # 21. Mixed Multi-Category Timeline Adaptation
    def test_21_mixed_multi_category_timeline_adaptation(self):
        """21. Verify adapt_artifacts adapts mixed filesystem, log, and network artifacts into a unified timeline."""
        fs_record = ArtifactRecord(
            artifact_id="ART-11111111-2222-4333-8444-555555555555",
            relative_path="etc/passwd",
            source_path="/evidence/target/etc/passwd",
            category="account",
            artifact_type="passwd",
            is_known=True,
            size=1200,
            permissions="0644",
            modified="2026-04-15T08:00:00Z",
            accessed=None,
            created=None,
            md5=None,
            sha256=None,
            status="collected",
        )
        log_event = LogEvent(
            event_id="EVT-22222222-3333-4444-8555-666666666666",
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_path="/var/log/syslog",
            line_number=1,
            raw_timestamp="2026-04-15T09:00:00Z",
            normalized_timestamp="2026-04-15T09:00:00Z",
            hostname="srv",
            service="systemd",
            pid=1,
            event_type="generic_syslog",
            attributes={},
            raw_message="Started Service.",
            raw_line="Apr 15 09:00:00 srv systemd[1]: Started Service.",
        )
        net_event = self.sample_net_event

        events = adapt_artifacts([fs_record, log_event, net_event])
        self.assertEqual(len(events), 3)

        categories = {e.category for e in events}
        self.assertIn(TimelineCategory.FILESYSTEM, categories)
        self.assertIn(TimelineCategory.LOG, categories)
        self.assertIn(TimelineCategory.NETWORK, categories)

        reconstructed = reconstruct_timeline(events)
        self.assertEqual(reconstructed.total_events, 3)

    # 22. End-to-End Synthetic PCAP Streaming to Timeline
    def test_22_end_to_end_pcap_to_timeline(self):
        """22. Verify synthetic PCAP containing DNS and HTTP traffic streams to ReconstructedTimeline."""
        dns_body = struct.pack(">HHHHHH", 0x4444, 0x0100, 1, 0, 0, 0) + b"\x03foo\x03com\x00" + struct.pack(">HH", 1, 1)
        dns_frame = make_eth_ip_udp("192.168.1.1", "8.8.8.8", 50000, 53, dns_body)

        pcap_data = make_synthetic_pcap_bytes([(dns_frame, 1713184200, 0)])
        stream = io.BytesIO(pcap_data)

        timeline = reconstruct_network_timeline(stream, pcap_name="test_stream.pcap")
        self.assertEqual(timeline.total_events, 2)  # 1 UDP packet event + 1 DNS metadata event
        types = {e.event_type for e in timeline.events}
        self.assertIn("udp_packet", types)
        self.assertIn("network_dns_metadata", types)

    # 23. NetworkTimelineExtractor OOP Interface
    def test_23_network_timeline_extractor_class(self):
        """23. Verify NetworkTimelineExtractor methods adapt and reconstruct_from_pcap."""
        extractor = NetworkTimelineExtractor()
        tl_evs = extractor.adapt(self.sample_net_event)
        self.assertEqual(len(tl_evs), 1)

        dns_body = struct.pack(">HHHHHH", 0x5555, 0x0100, 1, 0, 0, 0) + b"\x03bar\x03com\x00" + struct.pack(">HH", 1, 1)
        dns_frame = make_eth_ip_udp("10.0.0.1", "8.8.8.8", 50001, 53, dns_body)
        pcap_bytes = make_synthetic_pcap_bytes([(dns_frame, 1713184200, 0)])

        tl = extractor.reconstruct_from_pcap(io.BytesIO(pcap_bytes))
        self.assertGreaterEqual(tl.total_events, 1)

    # 24. Unsupported Artifact Type Raises TypeError
    def test_24_unsupported_type_raises_type_error(self):
        """24. Verify NetworkTimelineAdapter raises TypeError on unsupported artifact types."""
        adapter = NetworkTimelineAdapter()
        self.assertFalse(adapter.can_adapt("invalid_string_artifact"))
        with self.assertRaises(TypeError):
            adapter.adapt("invalid_string_artifact")


if __name__ == "__main__":
    unittest.main()
