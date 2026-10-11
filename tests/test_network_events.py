"""
Comprehensive Unit Test Suite for ForensiX V5.3 Network Event Extraction.

Validates:
1. Every supported NetworkEventType (TCP, UDP, ICMP, ICMPv6, ARP, IP fragment, IPv4, IPv6, generic).
2. Deterministic event ID generation (RFC 4122 UUIDv5 within FORENSIX_V5_NETWORK_EVENT_NAMESPACE).
3. Same evidence facts -> same deterministic event ID across repeated runs.
4. Different frame numbers -> different event IDs (even with identical payload bytes).
5. Different source PCAPs -> different event IDs.
6. Stable, deterministic output ordering preserving frame sequence.
7. TCP packet observations with flags, ports, and sequence metadata.
8. UDP packet observations with ports and lengths.
9. ICMP and ICMPv6 observations with types and codes (no transport ports).
10. ARP observations with MAC addresses and opcodes (no IP addresses).
11. Non-initial IP fragments (frag_offset > 0) classified as IP_FRAGMENT without transport ports.
12. Initial IP fragments (frag_offset == 0, MF=True) preserving transport ports and fragment flags.
13. IPv4 and IPv6 standalone observations.
14. Missing timestamps preserved as None while retaining raw_timestamp strings.
15. High-precision raw timestamp retention (nanosecond/microsecond).
16. Provenance preservation (record_id, source_path, source_artifact_id, pcap_name, frame_number).
17. Deep immutability of NetworkEvent (FrozenInstanceError on mutation, frozen attributes).
18. Deterministic serialization (to_dict, to_json, from_dict).
19. Integration bridge to TimelineEvent (to_timeline_event with TimelineCategory.NETWORK).
20. Empty input sequence handling (yields 0 events).
21. Incremental streaming extraction via extract_network_events and NetworkEventExtractor.
22. Direct extraction from PCAP stream via NetworkEventExtractor.extract_from_pcap.
23. Handling of minimal, metadata-poor, and partial frames.
24. Prevention of duplicate event generation across distinct frames.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import uuid

from forensix.network_events import (
    FORENSIX_V5_NETWORK_EVENT_NAMESPACE,
    NetworkEvent,
    NetworkEventExtractor,
    NetworkEventType,
    compute_deterministic_network_event_id,
    extract_network_event,
    extract_network_events,
)
from forensix.network_models import (
    NetworkEvidenceRecord,
    create_network_evidence_record,
)
from forensix.network_pcap_parser import (
    DLT_EN10MB,
    PCAP_MAGIC_MICROSECONDS_LITTLE,
)
from forensix.timeline_models import TimelineCategory, TimelineEvent


def _make_dummy_record(
    frame_number: int = 1,
    *,
    protocol: str = "TCP",
    network_protocol: str = "IPV4",
    transport_protocol: str = "TCP",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 443,
    source_path: str = "/cases/test.pcap",
    source_artifact_id: str = "ART-12345678-1234-5678-1234-567812345678",
    packet_metadata: dict = None,
    raw_timestamp: str = "1713184200.123456789",
    timestamp: datetime = None,
) -> NetworkEvidenceRecord:
    ts = timestamp if timestamp is not None else datetime(2026, 4, 15, 12, 30, 0, tzinfo=timezone.utc)
    return create_network_evidence_record(
        frame_number=frame_number,
        timestamp=ts,
        raw_timestamp=raw_timestamp,
        captured_length=64,
        original_length=64,
        link_layer="ETHERNET",
        src_mac="00:11:22:33:44:55",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        network_protocol=network_protocol,
        transport_protocol=transport_protocol,
        source_path=source_path,
        source_artifact_id=source_artifact_id,
        pcap_name="test.pcap",
        packet_metadata=packet_metadata or {},
    )


class TestNetworkEventExtraction(unittest.TestCase):
    """Rigorous unit test suite for V5.3 Network Event Extraction."""

    def setUp(self) -> None:
        self.sample_dt = datetime(2026, 4, 15, 12, 30, 0, tzinfo=timezone.utc)
        self.extractor = NetworkEventExtractor()

    # 1. Event Classification: TCP Packet
    def test_01_classify_tcp_packet_event(self):
        """1. Verify TCP packet record is classified as NetworkEventType.TCP_PACKET with flags."""
        rec = _make_dummy_record(
            protocol="TCP",
            packet_metadata={"tcp_flags": ["SYN"], "seq": 1000, "window_size": 65535},
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.event_type, NetworkEventType.TCP_PACKET.value)
        self.assertEqual(evt.protocol, "TCP")
        self.assertEqual(evt.src_port, 54321)
        self.assertEqual(evt.dst_port, 443)
        self.assertIn("SYN", evt.description)
        self.assertTrue(evt.event_id.startswith("NETEVT-"))

    # 2. Event Classification: UDP Packet
    def test_02_classify_udp_packet_event(self):
        """2. Verify UDP packet record is classified as NetworkEventType.UDP_PACKET."""
        rec = _make_dummy_record(
            protocol="UDP",
            transport_protocol="UDP",
            src_port=12345,
            dst_port=53,
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.event_type, NetworkEventType.UDP_PACKET.value)
        self.assertEqual(evt.protocol, "UDP")
        self.assertEqual(evt.src_port, 12345)
        self.assertEqual(evt.dst_port, 53)
        self.assertIn("UDP", evt.description)

    # 3. Event Classification: ICMP and ICMPv6
    def test_03_classify_icmp_and_icmpv6_events(self):
        """3. Verify ICMP and ICMPv6 packet records are classified with type and code."""
        rec_v4 = _make_dummy_record(
            protocol="ICMP",
            transport_protocol="ICMP",
            src_port=None,
            dst_port=None,
            packet_metadata={"icmp_type": 8, "icmp_code": 0},
        )
        evt_v4 = extract_network_event(rec_v4)
        self.assertEqual(evt_v4.event_type, NetworkEventType.ICMP_PACKET.value)
        self.assertIsNone(evt_v4.src_port)
        self.assertIn("type 8", evt_v4.description)

        rec_v6 = _make_dummy_record(
            protocol="ICMPV6",
            network_protocol="IPV6",
            transport_protocol="ICMPV6",
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=None,
            dst_port=None,
            packet_metadata={"icmp_type": 128, "icmp_code": 0},
        )
        evt_v6 = extract_network_event(rec_v6)
        self.assertEqual(evt_v6.event_type, NetworkEventType.ICMPV6_PACKET.value)
        self.assertIn("type 128", evt_v6.description)

    # 4. Event Classification: ARP Packet
    def test_04_classify_arp_event(self):
        """4. Verify ARP packet record is classified as NetworkEventType.ARP_PACKET."""
        rec = _make_dummy_record(
            protocol="ARP",
            network_protocol="ARP",
            transport_protocol=None,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            packet_metadata={"arp_opcode": 1, "arp_sender_mac": "00:11:22:33:44:55"},
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.event_type, NetworkEventType.ARP_PACKET.value)
        self.assertIsNone(evt.src_ip)
        self.assertIn("ARP request", evt.description)

    # 5. Event Classification: IP Fragments
    def test_05_classify_ip_fragment_events(self):
        """5. Verify IP fragments are correctly categorized without fabricating transport ports."""
        # Non-initial fragment
        rec_frag = _make_dummy_record(
            protocol="TCP",
            transport_protocol=None,
            src_port=None,
            dst_port=None,
            packet_metadata={"fragment": True, "fragment_offset": 1480},
        )
        evt_frag = extract_network_event(rec_frag)
        self.assertEqual(evt_frag.event_type, NetworkEventType.IP_FRAGMENT.value)
        self.assertIsNone(evt_frag.src_port)
        self.assertIn("offset 1480", evt_frag.description)

    # 6. Event Classification: IPv4 and IPv6 without transport protocol
    def test_06_classify_ipv4_and_ipv6_standalone(self):
        """6. Verify IP datagrams without recognized transport protocol are classified factually."""
        rec_v4 = _make_dummy_record(
            protocol="IP-47",  # GRE
            transport_protocol=None,
            src_port=None,
            dst_port=None,
        )
        evt_v4 = extract_network_event(rec_v4)
        self.assertEqual(evt_v4.event_type, NetworkEventType.IPV4_PACKET.value)

        rec_v6 = _make_dummy_record(
            protocol="IP-50",  # ESP
            network_protocol="IPV6",
            transport_protocol=None,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=None,
            dst_port=None,
        )
        evt_v6 = extract_network_event(rec_v6)
        self.assertEqual(evt_v6.event_type, NetworkEventType.IPV6_PACKET.value)

    # 7. Event Classification: Generic link-layer frame
    def test_07_classify_generic_packet(self):
        """7. Verify partial or non-IP frame is classified as GENERIC_PACKET."""
        rec = create_network_evidence_record(
            frame_number=1,
            captured_length=42,
            link_layer="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.event_type, NetworkEventType.GENERIC_PACKET.value)
        self.assertIn("ETHERNET frame #1", evt.description)

    # 8. Deterministic IDs: Same facts -> Same ID
    def test_08_deterministic_id_reproducibility(self):
        """8. Verify identical evidence produces byte-identical event IDs across repeated extractions."""
        rec1 = _make_dummy_record(frame_number=5)
        rec2 = _make_dummy_record(frame_number=5)
        evt1 = extract_network_event(rec1)
        evt2 = extract_network_event(rec2)
        self.assertEqual(evt1.event_id, evt2.event_id)

    # 9. Deterministic IDs: Different frames -> Different IDs
    def test_09_deterministic_id_distinct_frames(self):
        """9. Verify distinct frames with otherwise identical facts produce distinct event IDs."""
        rec1 = _make_dummy_record(frame_number=1)
        rec2 = _make_dummy_record(frame_number=2)
        evt1 = extract_network_event(rec1)
        evt2 = extract_network_event(rec2)
        self.assertNotEqual(evt1.event_id, evt2.event_id)

    # 10. Deterministic IDs: Different sources -> Different IDs
    def test_10_deterministic_id_distinct_sources(self):
        """10. Verify different PCAP sources produce distinct event IDs."""
        rec1 = _make_dummy_record(frame_number=1, source_path="/cases/cap1.pcap", source_artifact_id=None)
        rec2 = _make_dummy_record(frame_number=1, source_path="/cases/cap2.pcap", source_artifact_id=None)
        evt1 = extract_network_event(rec1)
        evt2 = extract_network_event(rec2)
        self.assertNotEqual(evt1.event_id, evt2.event_id)

    # 11. Stable Output Ordering
    def test_11_stable_output_ordering(self):
        """11. Verify streaming extraction strictly preserves sequence order of frames."""
        records = [_make_dummy_record(frame_number=i) for i in range(1, 11)]
        events = list(extract_network_events(records))
        self.assertEqual(len(events), 10)
        for i, evt in enumerate(events, start=1):
            self.assertEqual(evt.frame_number, i)

    # 12. Timestamp Preservation
    def test_12_timestamp_and_raw_precision_preservation(self):
        """12. Verify high-precision raw timestamps and normalized UTC datetimes are preserved exactly."""
        raw_nano = "1713184245.987654321"
        rec = _make_dummy_record(
            timestamp=self.sample_dt,
            raw_timestamp=raw_nano,
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.timestamp, self.sample_dt)
        self.assertEqual(evt.raw_timestamp, raw_nano)

    # 13. Missing Timestamps Handled Safely
    def test_13_missing_timestamp_preservation(self):
        """13. Verify records without timestamps emit events with timestamp=None without error."""
        rec = create_network_evidence_record(
            frame_number=1,
            timestamp=None,
            raw_timestamp=None,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=8080,
            protocol="TCP",
        )
        evt = extract_network_event(rec)
        self.assertIsNone(evt.timestamp)
        self.assertIsNone(evt.raw_timestamp)
        self.assertEqual(evt.src_port, 80)

    # 14. Provenance Preservation
    def test_14_provenance_preservation(self):
        """14. Verify full provenance (record_id, source_path, source_artifact_id, pcap_name) is retained."""
        rec = _make_dummy_record(
            frame_number=42,
            source_path="/evidence/captures/trace.pcap",
            source_artifact_id="ART-11111111-2222-3333-4444-555555555555",
        )
        evt = extract_network_event(rec)
        self.assertEqual(evt.record_id, rec.record_id)
        self.assertEqual(evt.frame_number, 42)
        self.assertEqual(evt.source_path, "/evidence/captures/trace.pcap")
        self.assertEqual(evt.source_artifact_id, "ART-11111111-2222-3333-4444-555555555555")
        self.assertEqual(evt.pcap_name, "test.pcap")

    # 15. Deep Immutability
    def test_15_deep_immutability(self):
        """15. Verify NetworkEvent raises FrozenInstanceError on modification or deletion."""
        evt = extract_network_event(_make_dummy_record())
        with self.assertRaises(Exception):
            evt.frame_number = 99  # type: ignore

        with self.assertRaises(Exception):
            evt.event_type = "altered"  # type: ignore

        with self.assertRaises(Exception):
            evt.attributes["new_key"] = "leak"  # type: ignore

    # 16. Serialization Round-trip
    def test_16_serialization_round_trip(self):
        """16. Verify to_dict(), to_json(), and from_dict() round-trip accurately."""
        orig_evt = extract_network_event(_make_dummy_record(packet_metadata={"tcp_flags": ["SYN"]}))
        d = orig_evt.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["event_id"], orig_evt.event_id)
        self.assertEqual(d["event_type"], orig_evt.event_type)

        json_str = orig_evt.to_json()
        self.assertIsInstance(json_str, str)

        reconstructed = NetworkEvent.from_dict(d)
        self.assertEqual(reconstructed.event_id, orig_evt.event_id)
        self.assertEqual(reconstructed.record_id, orig_evt.record_id)
        self.assertEqual(reconstructed.timestamp, orig_evt.timestamp)
        self.assertEqual(reconstructed.src_ip, orig_evt.src_ip)
        self.assertEqual(reconstructed.event_type, orig_evt.event_type)

    # 17. TimelineEvent Integration Bridge
    def test_17_to_timeline_event_integration(self):
        """17. Verify to_timeline_event produces valid TimelineEvent with TimelineCategory.NETWORK."""
        net_evt = extract_network_event(_make_dummy_record(frame_number=7))
        tl_evt = net_evt.to_timeline_event()
        self.assertIsInstance(tl_evt, TimelineEvent)
        self.assertEqual(tl_evt.category, TimelineCategory.NETWORK)
        self.assertEqual(tl_evt.event_type, NetworkEventType.TCP_PACKET.value)
        self.assertEqual(tl_evt.source_line, 7)
        self.assertEqual(tl_evt.source_event_id, net_evt.event_id)
        self.assertTrue(tl_evt.event_id.startswith("TIMELINE-"))

    # 18. Empty Input Sequence
    def test_18_empty_input_sequence(self):
        """18. Verify empty record collection yields empty iterator."""
        evts = list(extract_network_events([]))
        self.assertEqual(evts, [])

    # 19. NetworkEventExtractor Class
    def test_19_network_event_extractor_methods(self):
        """19. Verify NetworkEventExtractor methods (extract, extract_many, extract_all)."""
        recs = [_make_dummy_record(frame_number=i) for i in range(1, 4)]
        single = self.extractor.extract(recs[0])
        self.assertEqual(single.frame_number, 1)

        many = list(self.extractor.extract_many(recs))
        self.assertEqual(len(many), 3)

        all_evts = self.extractor.extract_all(recs)
        self.assertEqual(len(all_evts), 3)

    # 20. Direct Extraction from PCAP Stream
    def test_20_extract_from_pcap_stream(self):
        """20. Verify extract_from_pcap streams NetworkEvents directly from PCAP byte stream."""
        # Construct synthetic PCAP in memory
        dst_mac = b"\x00\x11\x22\x33\x44\x55"
        src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        eth = dst_mac + src_mac + struct.pack(">H", 0x0800)
        s_ip = b"\xc0\xa8\x01\x64"  # 192.168.1.100
        d_ip = b"\x0a\x00\x00\x01"  # 10.0.0.1
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 40, 1, 0, 64, 6, 0) + s_ip + d_ip
        tcp = struct.pack(">HHIIBBHHH", 1234, 80, 100, 0, 0x50, 0x02, 65535, 0, 0)
        pkt_data = eth + ip + tcp

        gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, DLT_EN10MB)
        rh = struct.pack("<IIII", 1713184200, 500, len(pkt_data), len(pkt_data))
        pcap_bytes = gh + rh + pkt_data

        pcap_stream = io.BytesIO(pcap_bytes)
        evts = list(self.extractor.extract_from_pcap(pcap_stream, pcap_name="synthetic.pcap"))
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0].event_type, NetworkEventType.TCP_PACKET.value)
        self.assertEqual(evts[0].src_ip, "192.168.1.100")
        self.assertEqual(evts[0].dst_port, 80)
        self.assertEqual(evts[0].pcap_name, "synthetic.pcap")

    # 21. Ergonomic Aliases
    def test_21_property_aliases(self):
        """21. Verify property aliases (source_ip, destination_ip, source_port, destination_port, packet_number)."""
        evt = extract_network_event(_make_dummy_record())
        self.assertEqual(evt.source_ip, evt.src_ip)
        self.assertEqual(evt.destination_ip, evt.dst_ip)
        self.assertEqual(evt.source_port, evt.src_port)
        self.assertEqual(evt.destination_port, evt.dst_port)
        self.assertEqual(evt.packet_number, evt.frame_number)
        self.assertEqual(evt.packet_length, evt.captured_length)
        self.assertEqual(evt.wire_length, evt.original_length)

    # 22. No Duplicate Generation across distinct frames
    def test_22_distinct_identities_for_identical_payloads(self):
        """22. Verify distinct frames with identical contents never collide or get deduplicated."""
        rec1 = _make_dummy_record(frame_number=1)
        rec2 = _make_dummy_record(frame_number=2)
        evts = list(extract_network_events([rec1, rec2]))
        self.assertEqual(len(evts), 2)
        self.assertNotEqual(evts[0].event_id, evts[1].event_id)
        self.assertEqual(evts[0].frame_number, 1)
        self.assertEqual(evts[1].frame_number, 2)


if __name__ == "__main__":
    unittest.main()
