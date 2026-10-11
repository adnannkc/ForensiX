"""
Comprehensive Unit Test Suite for ForensiX V5.1 Network Evidence Model.

Validates:
1. Valid NetworkEvidenceRecord construction (all fields explicitly supplied).
2. Required field validation (frame_number is mandatory, 1-indexed, positive integer).
3. Optional fields handling (None preserved without fabrication).
4. Missing network fields (valid non-IP traffic, partial packets without ports/IPs).
5. Timestamp handling (typed datetime, valid ISO string, POSIX epoch float/int, rejection of date-only/ambiguous).
6. Timestamp precision (microsecond preservation in datetime, raw nanosecond preservation in raw_timestamp).
7. Deterministic IDs (format NET-<UUIDv5>, RFC 4122 compliance, FORENSIX_V5_NETWORK_NAMESPACE).
8. Same facts -> Same ID (reproducibility across independent instances and executions).
9. Different frame -> Different ID (different frame numbers produce distinct IDs).
10. Immutability (modifications/deletions raise FrozenInstanceError).
11. Nested metadata immutability (deep freeze of dicts, lists, sets; no mutation leak).
12. Provenance preservation (traceability to PCAP path, artifact ID, frame number; no conflation with log line numbers).
13. Serialization (to_dict(), to_json(), from_dict() round-trip).
14. Deterministic serialization (sorted keys, stable structure, reproducible bytes).
15. Invalid values handling (invalid ports, lengths, IPs, protocols, conflicting fields).
16. TimelineCategory.NETWORK (presence in enum, compatibility with TimelineEvent).
17. Backward compatibility of existing timeline categories (FILESYSTEM, LOG, AUTHENTICATION, ACCOUNT, PERSISTENCE).
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest
import uuid

from forensix.network_models import (
    FORENSIX_V5_NETWORK_NAMESPACE,
    NetworkEvidenceRecord,
    compute_deterministic_network_id,
    create_network_evidence_record,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)


class TestNetworkEvidenceModel(unittest.TestCase):
    """Rigorous unit test suite for V5.1 Network Evidence Model."""

    def setUp(self) -> None:
        self.sample_dt = datetime(2026, 4, 15, 12, 30, 45, 123456, tzinfo=timezone.utc)
        self.sample_iso = "2026-04-15T12:30:45.123456+00:00"

    # 1. Valid NetworkEvidenceRecord creation
    def test_01_valid_network_evidence_record_all_fields(self):
        """1. Verify valid NetworkEvidenceRecord creation with all fields explicitly supplied."""
        record = NetworkEvidenceRecord(
            frame_number=1,
            timestamp=self.sample_dt,
            raw_timestamp="1713184245.123456789",
            captured_length=64,
            original_length=128,
            link_layer="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            network_protocol="IPv4",
            transport_protocol="TCP",
            source_path="/evidence/captures/traffic.pcap",
            source_artifact_id="ART-11111111-2222-5333-8444-555555555555",
            pcap_name="traffic.pcap",
            packet_metadata={"tcp_flags": ["SYN", "ACK"], "ttl": 64, "window_size": 65535},
        )
        self.assertTrue(record.record_id.startswith("NET-"))
        self.assertEqual(record.frame_number, 1)
        self.assertEqual(record.timestamp, self.sample_dt)
        self.assertEqual(record.raw_timestamp, "1713184245.123456789")
        self.assertEqual(record.captured_length, 64)
        self.assertEqual(record.original_length, 128)
        self.assertEqual(record.link_layer, "ETHERNET")
        self.assertEqual(record.src_mac, "00:11:22:33:44:55")
        self.assertEqual(record.dst_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(record.src_ip, "192.168.1.100")
        self.assertEqual(record.dst_ip, "10.0.0.1")
        self.assertEqual(record.src_port, 54321)
        self.assertEqual(record.dst_port, 443)
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.network_protocol, "IPV4")
        self.assertEqual(record.transport_protocol, "TCP")
        self.assertEqual(record.source_path, "/evidence/captures/traffic.pcap")
        self.assertEqual(record.source_artifact_id, "ART-11111111-2222-5333-8444-555555555555")
        self.assertEqual(record.pcap_name, "traffic.pcap")
        self.assertIsInstance(record.packet_metadata, tuple)

        # Check aliases
        self.assertEqual(record.source_ip, "192.168.1.100")
        self.assertEqual(record.destination_ip, "10.0.0.1")
        self.assertEqual(record.source_port, 54321)
        self.assertEqual(record.destination_port, 443)
        self.assertEqual(record.source_mac, "00:11:22:33:44:55")
        self.assertEqual(record.destination_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(record.packet_number, 1)
        self.assertEqual(record.packet_length, 64)
        self.assertEqual(record.wire_length, 128)
        self.assertEqual(record.attributes, record.packet_metadata)

    def test_02_create_network_evidence_record_factory(self):
        """2. Verify convenience factory create_network_evidence_record constructs identical instance."""
        record = create_network_evidence_record(
            frame_number=42,
            timestamp=self.sample_dt,
            src_ip="172.16.0.5",
            dst_ip="172.16.0.1",
            src_port=12345,
            dst_port=53,
            protocol="DNS",
        )
        self.assertTrue(record.record_id.startswith("NET-"))
        self.assertEqual(record.frame_number, 42)
        self.assertEqual(record.src_ip, "172.16.0.5")
        self.assertEqual(record.dst_ip, "172.16.0.1")
        self.assertEqual(record.src_port, 12345)
        self.assertEqual(record.dst_port, 53)
        self.assertEqual(record.protocol, "DNS")

    # 2. Required field validation
    def test_03_required_field_validation_frame_number(self):
        """3. Verify frame_number is strictly required, 1-indexed, and integer."""
        with self.assertRaises(TypeError):
            NetworkEvidenceRecord()  # type: ignore

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=None)  # type: ignore

        # Boolean is rejected
        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=True)  # type: ignore

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=False)  # type: ignore

        # Float / string rejected
        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=1.5)  # type: ignore

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number="1")  # type: ignore

        # Zero and negative values rejected
        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=0)

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=-1)

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=-999)

    # 3. Optional fields
    def test_04_optional_fields_preservation(self):
        """4. Verify minimal construction with only frame_number succeeds and preserves None values."""
        record = NetworkEvidenceRecord(frame_number=10)
        self.assertEqual(record.frame_number, 10)
        self.assertTrue(record.record_id.startswith("NET-"))
        self.assertIsNone(record.timestamp)
        self.assertIsNone(record.raw_timestamp)
        self.assertIsNone(record.captured_length)
        self.assertIsNone(record.original_length)
        self.assertIsNone(record.link_layer)
        self.assertIsNone(record.src_mac)
        self.assertIsNone(record.dst_mac)
        self.assertIsNone(record.src_ip)
        self.assertIsNone(record.dst_ip)
        self.assertIsNone(record.src_port)
        self.assertIsNone(record.dst_port)
        self.assertIsNone(record.protocol)
        self.assertIsNone(record.network_protocol)
        self.assertIsNone(record.transport_protocol)
        self.assertIsNone(record.source_path)
        self.assertIsNone(record.source_artifact_id)
        self.assertIsNone(record.pcap_name)
        self.assertEqual(record.packet_metadata, ())

    # 4. Missing network fields (non-IP or partial traffic)
    def test_05_missing_network_fields_non_ip_traffic(self):
        """5. Verify non-IP traffic (e.g. ARP or pure Ethernet frame) without IP or port fields succeeds."""
        record = NetworkEvidenceRecord(
            frame_number=1,
            link_layer="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
            protocol="ARP",
            captured_length=42,
            original_length=42,
        )
        self.assertEqual(record.protocol, "ARP")
        self.assertIsNone(record.src_ip)
        self.assertIsNone(record.dst_ip)
        self.assertIsNone(record.src_port)
        self.assertIsNone(record.dst_port)
        self.assertEqual(record.captured_length, 42)

    def test_06_missing_network_fields_icmp_traffic_no_ports(self):
        """6. Verify ICMP traffic with IP addresses but without transport ports succeeds."""
        record = NetworkEvidenceRecord(
            frame_number=2,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.254",
            protocol="ICMP",
            transport_protocol="ICMP",
        )
        self.assertEqual(record.src_ip, "192.168.1.1")
        self.assertEqual(record.dst_ip, "192.168.1.254")
        self.assertIsNone(record.src_port)
        self.assertIsNone(record.dst_port)
        self.assertEqual(record.protocol, "ICMP")

    # 5. Timestamp handling
    def test_07_timestamp_handling_typed_datetime(self):
        """7. Verify typed datetime is preserved exactly."""
        dt = datetime(2026, 5, 1, 10, 0, 0, 500000, tzinfo=timezone.utc)
        record = NetworkEvidenceRecord(frame_number=1, timestamp=dt)
        self.assertEqual(record.timestamp, dt)
        self.assertEqual(record.raw_timestamp, dt.isoformat())

    def test_08_timestamp_handling_iso_string(self):
        """8. Verify valid ISO 8601 string is normalized to typed datetime."""
        iso_str = "2026-05-01T10:00:00Z"
        record = NetworkEvidenceRecord(frame_number=1, timestamp=iso_str)
        self.assertIsInstance(record.timestamp, datetime)
        self.assertEqual(record.timestamp.year, 2026)
        self.assertEqual(record.timestamp.month, 5)
        self.assertEqual(record.raw_timestamp, iso_str)

    def test_09_timestamp_handling_numeric_epoch(self):
        """9. Verify numeric POSIX epoch (float/int) is converted to UTC datetime."""
        epoch = 1714557600.5
        record = NetworkEvidenceRecord(frame_number=1, timestamp=epoch)
        self.assertIsInstance(record.timestamp, datetime)
        self.assertEqual(record.timestamp, datetime.fromtimestamp(epoch, tz=timezone.utc))
        self.assertEqual(record.raw_timestamp, str(epoch))

    def test_10_timestamp_handling_rejects_date_only_and_ambiguous(self):
        """10. Verify date-only or ambiguous timestamps raise ValueError."""
        invalid_ts_list = [
            "2026-05-01",
            "yesterday",
            "Oct  1 12:00:00",
            "",
            "   ",
        ]
        for bad_ts in invalid_ts_list:
            with self.subTest(bad_ts=bad_ts):
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, timestamp=bad_ts)

    def test_11_timestamp_handling_rejects_invalid_types(self):
        """11. Verify invalid timestamp types raise TypeError or ValueError."""
        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=1, timestamp=True)  # type: ignore

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=1, timestamp=[])  # type: ignore

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, timestamp=-100)  # negative epoch

    # 6. Timestamp precision
    def test_12_timestamp_precision_microsecond_and_raw_nanosecond(self):
        """12. Verify microsecond precision in datetime and arbitrary nanosecond precision in raw_timestamp."""
        dt = datetime(2026, 4, 15, 12, 30, 45, 987654, tzinfo=timezone.utc)
        raw_nano = "1713184245.987654321"
        record = NetworkEvidenceRecord(
            frame_number=1,
            timestamp=dt,
            raw_timestamp=raw_nano,
        )
        self.assertEqual(record.timestamp.microsecond, 987654)
        self.assertEqual(record.raw_timestamp, raw_nano)

    # 7. Deterministic IDs
    def test_13_deterministic_id_format_and_namespace(self):
        """13. Verify record_id conforms to NET-<UUIDv5> and ForensiX V5 network namespace."""
        record = NetworkEvidenceRecord(frame_number=1, pcap_name="test.pcap")
        self.assertTrue(record.record_id.startswith("NET-"))
        uuid_str = record.record_id[len("NET-"):]
        parsed_uuid = uuid.UUID(uuid_str)
        self.assertEqual(parsed_uuid.version, 5)

        # Direct namespace verification
        expected_id = compute_deterministic_network_id(
            frame_number=1,
            pcap_name="test.pcap",
        )
        self.assertEqual(record.record_id, expected_id)

    # 8. Same facts -> Same ID
    def test_14_deterministic_id_same_facts_same_id(self):
        """14. Verify identical evidence facts produce the exact same ID across runs."""
        kwargs = {
            "frame_number": 5,
            "source_path": "/var/log/pcap/capture.pcap",
            "source_artifact_id": "ART-00000000-0000-5000-8000-000000000001",
            "raw_timestamp": "1713184200.000001",
            "src_ip": "10.1.1.1",
            "dst_ip": "10.1.1.2",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "TCP",
            "captured_length": 100,
            "original_length": 100,
        }
        r1 = NetworkEvidenceRecord(**kwargs)
        r2 = NetworkEvidenceRecord(**kwargs)
        self.assertEqual(r1.record_id, r2.record_id)

    # 9. Different frame -> Different ID
    def test_15_deterministic_id_different_frame_different_id(self):
        """15. Verify different frame numbers with otherwise identical facts produce different IDs."""
        r1 = NetworkEvidenceRecord(frame_number=1, pcap_name="traffic.pcap")
        r2 = NetworkEvidenceRecord(frame_number=2, pcap_name="traffic.pcap")
        self.assertNotEqual(r1.record_id, r2.record_id)

    def test_16_deterministic_id_different_source_different_id(self):
        """16. Verify different evidence sources produce different IDs."""
        r1 = NetworkEvidenceRecord(frame_number=1, source_path="/evidence/pcap1.pcap")
        r2 = NetworkEvidenceRecord(frame_number=1, source_path="/evidence/pcap2.pcap")
        self.assertNotEqual(r1.record_id, r2.record_id)

    def test_17_deterministic_id_different_facts_different_id(self):
        """17. Verify different network facts (e.g. port) produce different IDs."""
        r1 = NetworkEvidenceRecord(frame_number=1, src_port=80, protocol="TCP")
        r2 = NetworkEvidenceRecord(frame_number=1, src_port=443, protocol="TCP")
        self.assertNotEqual(r1.record_id, r2.record_id)

    # 10. Immutability
    def test_18_immutability_attribute_assignment_and_deletion(self):
        """18. Verify NetworkEvidenceRecord raises FrozenInstanceError on modification or deletion."""
        record = NetworkEvidenceRecord(frame_number=1, src_ip="192.168.1.1")
        with self.assertRaises(FrozenInstanceError):
            record.frame_number = 2  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            record.src_ip = "10.0.0.1"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            record.record_id = "NET-altered"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            del record.frame_number  # type: ignore

    # 11. Nested metadata immutability
    def test_19_nested_metadata_deep_immutability(self):
        """19. Verify nested metadata containers are deeply frozen and immutable."""
        meta_dict = {
            "flags": ["SYN", "ACK"],
            "options": {"mss": 1460, "wscale": 7},
            "subnets": {"internal", "dmz"},
        }
        record = NetworkEvidenceRecord(frame_number=1, packet_metadata=meta_dict)

        # Mutating original dictionary after construction must not affect record
        meta_dict["flags"].append("FIN")
        meta_dict["options"]["mss"] = 9999
        self.assertNotIn("FIN", record.packet_metadata)

        # Modifying record.packet_metadata container directly must fail
        with self.assertRaises((TypeError, AttributeError)):
            record.packet_metadata["new_key"] = "val"  # type: ignore

        # Modifying internal frozen dict must fail
        with self.assertRaises((TypeError, AttributeError)):
            record.packet_metadata[0] = ("mutated", "val")  # type: ignore

    # 12. Provenance preservation
    def test_20_provenance_preservation(self):
        """20. Verify source PCAP path, artifact ID, and frame number are strictly preserved."""
        pcap_path = Path("/cases/incident_01/dump.pcap")
        art_id = "ART-12345678-1234-5678-1234-567812345678"
        record = NetworkEvidenceRecord(
            frame_number=100,
            source_path=pcap_path,
            source_artifact_id=art_id,
        )
        self.assertEqual(record.source_path, str(pcap_path))
        self.assertEqual(record.source_artifact_id, art_id)
        self.assertEqual(record.pcap_name, "dump.pcap")
        self.assertEqual(record.frame_number, 100)

    # 13. Serialization
    def test_21_serialization_to_dict_and_to_json(self):
        """21. Verify to_dict() and to_json() produce accurate, JSON-serializable structures."""
        record = NetworkEvidenceRecord(
            frame_number=1,
            timestamp=self.sample_dt,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            packet_metadata={"tcp_seq": 1000},
        )
        d = record.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["frame_number"], 1)
        self.assertEqual(d["src_ip"], "192.168.1.1")
        self.assertEqual(d["packet_metadata"], {"tcp_seq": 1000})

        json_str = record.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["frame_number"], 1)
        self.assertEqual(parsed["src_ip"], "192.168.1.1")

    def test_22_serialization_round_trip_from_dict(self):
        """22. Verify from_dict() faithfully reconstructs identical NetworkEvidenceRecord."""
        orig = NetworkEvidenceRecord(
            frame_number=42,
            timestamp=self.sample_dt,
            captured_length=60,
            original_length=60,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=4444,
            dst_port=80,
            protocol="TCP",
            source_path="/tmp/test.pcap",
        )
        reconstructed = NetworkEvidenceRecord.from_dict(orig.to_dict())
        self.assertEqual(reconstructed.record_id, orig.record_id)
        self.assertEqual(reconstructed.frame_number, orig.frame_number)
        self.assertEqual(reconstructed.timestamp, orig.timestamp)
        self.assertEqual(reconstructed.src_ip, orig.src_ip)
        self.assertEqual(reconstructed.dst_port, orig.dst_port)

    # 14. Deterministic serialization
    def test_23_deterministic_serialization(self):
        """23. Verify serialization produces deterministic, sorted, byte-identical representations."""
        r1 = NetworkEvidenceRecord(
            frame_number=1,
            packet_metadata={"b": 2, "a": 1, "c": {"y": 20, "x": 10}},
        )
        r2 = NetworkEvidenceRecord(
            frame_number=1,
            packet_metadata={"a": 1, "c": {"x": 10, "y": 20}, "b": 2},
        )
        self.assertEqual(r1.to_json(), r2.to_json())

    # 15. Invalid values
    def test_24_invalid_ports(self):
        """24. Verify invalid port numbers raise ValueError or TypeError."""
        for bad_port in [-1, 65536, 100000]:
            with self.subTest(bad_port=bad_port):
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, src_port=bad_port)
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, dst_port=bad_port)

        for bad_type in [True, "80", 80.5, []]:
            with self.subTest(bad_type=bad_type):
                with self.assertRaises(TypeError):
                    NetworkEvidenceRecord(frame_number=1, src_port=bad_type)  # type: ignore

    def test_25_invalid_lengths(self):
        """25. Verify invalid lengths and conflicting captured > original lengths raise errors."""
        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, captured_length=-1)

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, original_length=-1)

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=1, captured_length=True)  # type: ignore

        # Conflicting lengths: captured cannot exceed original wire length
        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, captured_length=1500, original_length=100)

    def test_26_invalid_ip_addresses(self):
        """26. Verify malformed IP addresses raise ValueError; valid IPv4/IPv6 are accepted."""
        malformed_ips = [
            "999.999.999.999",
            "not-an-ip",
            "192.168.1.300",
            "2001:xyz::1",
            "",
            "   ",
        ]
        for bad_ip in malformed_ips:
            with self.subTest(bad_ip=bad_ip):
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, src_ip=bad_ip)
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, dst_ip=bad_ip)

        # Valid IPv4 and IPv6
        r_v4 = NetworkEvidenceRecord(frame_number=1, src_ip="192.168.1.1", dst_ip="10.0.0.1")
        self.assertEqual(r_v4.src_ip, "192.168.1.1")

        r_v6 = NetworkEvidenceRecord(frame_number=1, src_ip="2001:db8::1", dst_ip="::1")
        self.assertEqual(r_v6.src_ip, "2001:db8::1")

    def test_27_invalid_protocols(self):
        """27. Verify empty protocol raises ValueError and valid protocol normalizes to uppercase."""
        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, protocol="")

        with self.assertRaises(TypeError):
            NetworkEvidenceRecord(frame_number=1, protocol=123)  # type: ignore

        r = NetworkEvidenceRecord(frame_number=1, protocol="tcp", network_protocol="ipv4", transport_protocol="tcp")
        self.assertEqual(r.protocol, "TCP")
        self.assertEqual(r.network_protocol, "IPV4")
        self.assertEqual(r.transport_protocol, "TCP")

    def test_28_conflicting_alias_arguments(self):
        """28. Verify providing conflicting values for aliases raises ValueError."""
        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, src_ip="10.0.0.1", source_ip="10.0.0.2")

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, dst_port=80, destination_port=443)

        with self.assertRaises(ValueError):
            NetworkEvidenceRecord(frame_number=1, captured_length=10, packet_length=20)

        # Supplying identical values for aliases succeeds
        r = NetworkEvidenceRecord(frame_number=1, src_ip="10.0.0.1", source_ip="10.0.0.1")
        self.assertEqual(r.src_ip, "10.0.0.1")

    def test_29_rejection_of_speculative_security_terms(self):
        """29. Verify speculative security verdicts (malicious, C2, threat level) are rejected."""
        disallowed_fields = [
            "malicious",
            "attacker",
            "c2",
            "threat_level",
            "risk_score",
            "verdict",
            "compromised",
            "attack_detected",
        ]
        for term in disallowed_fields:
            with self.subTest(term=term):
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, packet_metadata={term: True})

                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, protocol=term)

    def test_30_custom_record_id_validation(self):
        """30. Verify custom record_id must conform to NET-<UUID> format."""
        valid_custom_id = f"NET-{uuid.uuid4()}"
        record = NetworkEvidenceRecord(frame_number=1, record_id=valid_custom_id)
        self.assertEqual(record.record_id, valid_custom_id)

        invalid_custom_ids = [
            "INVALID-1234",
            "NET-not-a-uuid",
            "NET-",
            "",
            "   ",
        ]
        for bad_id in invalid_custom_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ValueError):
                    NetworkEvidenceRecord(frame_number=1, record_id=bad_id)

    # 16. TimelineCategory.NETWORK
    def test_31_timeline_category_network_integration(self):
        """31. Verify TimelineCategory.NETWORK exists and integrates with TimelineEvent."""
        self.assertEqual(TimelineCategory.NETWORK.value, "network")
        self.assertIn("NETWORK", TimelineCategory.__members__)

        event = TimelineEvent(
            category=TimelineCategory.NETWORK,
            event_type="packet_observed",
            description="DNS query for example.com",
            timestamp=self.sample_dt,
            attributes={"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "proto": "UDP"},
        )
        self.assertEqual(event.category, TimelineCategory.NETWORK)
        self.assertEqual(event.event_type, "packet_observed")

        # Case-insensitive string parsing
        event_str = TimelineEvent(
            category="network",
            event_type="packet_observed",
            description="DNS query for example.com",
        )
        self.assertEqual(event_str.category, TimelineCategory.NETWORK)

        event_upper = TimelineEvent(
            category="NETWORK",
            event_type="packet_observed",
            description="DNS query for example.com",
        )
        self.assertEqual(event_upper.category, TimelineCategory.NETWORK)

    # 17. Backward compatibility of existing timeline categories
    def test_32_backward_compatibility_existing_timeline_categories(self):
        """32. Verify all foundational V1-V4 timeline categories continue to work exactly as before."""
        categories = [
            TimelineCategory.FILESYSTEM,
            TimelineCategory.LOG,
            TimelineCategory.AUTHENTICATION,
            TimelineCategory.ACCOUNT,
            TimelineCategory.PERSISTENCE,
        ]
        for cat in categories:
            with self.subTest(cat=cat):
                event = create_timeline_event(
                    category=cat,
                    event_type="test_observation",
                    description=f"Event for {cat.value}",
                )
                self.assertEqual(event.category, cat)


if __name__ == "__main__":
    unittest.main()
