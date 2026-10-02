"""
Focused Unit Test Suite for ForensiX V3.1 Timeline Event Model.

Covers:
1. Valid TimelineEvent construction (all fields, minimal fields, factory).
2. Timeline event ID format (TIMELINE-<UUIDv4>).
3. UUIDv4 uniqueness and format validation across generations.
4. Deep immutability (modifications/deletions raise FrozenInstanceError).
5. Timestamp storage (typed datetime preservation).
6. Optional timestamp handling (None preserved without fabrication).
7. Category validation (all supported categories, rejection of speculative/invalid ones).
8. Event type storage and non-empty string validation.
9. Source path preservation (str and Path).
10. Source artifact ID preservation (no fabrication).
11. Source event ID preservation (no fabrication).
12. Raw/source information preservation (raw_timestamp, raw_data, aliases).
13. to_dict() correctness and fidelity.
14. JSON serialization compatibility (round-trip with json.loads).
15. Deep immutability of nested structures (no mutable state leak).
16. Invalid required input handling (missing/malformed inputs).
17. Preservation of non-fabricated source IDs when absent.
18. Absence of detection, risk, severity, or correlation fields.
19. Deterministic serialization structure and key ordering.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest
import uuid

from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
    generate_timeline_id,
)


class TestTimelineEventModel(unittest.TestCase):
    """Rigorous unit tests for the V3.1 TimelineEvent foundational model."""

    def setUp(self) -> None:
        self.sample_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
        self.sample_event_id = f"TIMELINE-{self.sample_uuid}"
        self.sample_dt = datetime(2026, 3, 31, 14, 30, 0, tzinfo=timezone.utc)

    # 1. Valid TimelineEvent construction
    def test_01_valid_timeline_event_construction_all_fields(self):
        """1. Verify valid TimelineEvent construction with all fields explicitly supplied."""
        event = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
            source_path="/var/log/auth.log",
            source_line=42,
            source_artifact_id="ART-11111111-2222-4333-8444-555555555555",
            source_event_id="AUTH-66666666-7777-4888-8999-000000000000",
            raw_timestamp="Mar 31 14:30:00",
            raw_data="Mar 31 14:30:00 server sshd[1234]: Accepted publickey for ubuntu...",
            attributes={"user": "ubuntu", "src_ip": "192.168.1.50", "port": 54321},
        )
        self.assertEqual(event.event_id, self.sample_event_id)
        self.assertEqual(event.timestamp, self.sample_dt)
        self.assertEqual(event.category, TimelineCategory.AUTHENTICATION)
        self.assertEqual(event.event_type, "ssh_login_success")
        self.assertEqual(event.description, "Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2")
        self.assertEqual(event.source_path, "/var/log/auth.log")
        self.assertEqual(event.source_line, 42)
        self.assertEqual(event.line_number, 42)
        self.assertEqual(event.source_artifact_id, "ART-11111111-2222-4333-8444-555555555555")
        self.assertEqual(event.source_event_id, "AUTH-66666666-7777-4888-8999-000000000000")
        self.assertEqual(event.raw_timestamp, "Mar 31 14:30:00")
        self.assertEqual(event.raw_data, "Mar 31 14:30:00 server sshd[1234]: Accepted publickey for ubuntu...")
        self.assertEqual(event.raw_line, "Mar 31 14:30:00 server sshd[1234]: Accepted publickey for ubuntu...")
        self.assertIsInstance(event.attributes, tuple)

    def test_02_valid_timeline_event_construction_minimal_fields(self):
        """2. Verify valid TimelineEvent construction with only minimal required fields."""
        event = TimelineEvent(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="Discovered /etc/hosts file",
        )
        self.assertTrue(event.event_id.startswith("TIMELINE-"))
        self.assertIsNone(event.timestamp)
        self.assertEqual(event.category, TimelineCategory.FILESYSTEM)
        self.assertEqual(event.event_type, "file_created")
        self.assertEqual(event.description, "Discovered /etc/hosts file")
        self.assertIsNone(event.source_path)
        self.assertIsNone(event.source_line)
        self.assertIsNone(event.line_number)
        self.assertIsNone(event.source_artifact_id)
        self.assertIsNone(event.source_event_id)
        self.assertIsNone(event.raw_timestamp)
        self.assertIsNone(event.raw_data)
        self.assertIsNone(event.raw_line)
        self.assertEqual(event.attributes, ())

    def test_03_create_timeline_event_factory(self):
        """3. Verify convenience factory create_timeline_event constructs valid instance."""
        event = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="System reboot requested",
            timestamp=self.sample_dt,
            source_path="/var/log/syslog",
            source_line=100,
            attributes={"service": "systemd"},
        )
        self.assertTrue(event.event_id.startswith("TIMELINE-"))
        self.assertEqual(event.category, TimelineCategory.LOG)
        self.assertEqual(event.event_type, "generic_syslog")
        self.assertEqual(event.description, "System reboot requested")
        self.assertEqual(event.source_path, "/var/log/syslog")
        self.assertEqual(event.source_line, 100)

    # 2. Timeline event ID format
    def test_04_timeline_event_id_format(self):
        """4. Verify TimelineEvent ID format follows TIMELINE-<UUIDv4> strictly."""
        tid = generate_timeline_id()
        self.assertTrue(tid.startswith("TIMELINE-"))
        uuid_part = tid[len("TIMELINE-"):]
        parsed = uuid.UUID(uuid_part, version=4)
        self.assertEqual(str(parsed), uuid_part)
        self.assertEqual(parsed.version, 4)

    def test_05_explicit_invalid_timeline_event_id_rejected(self):
        """5. Verify invalid timeline event ID formats are rejected."""
        invalid_ids = [
            "INVALID-1234",
            "TIMELINE-not-a-uuid",
            "TIMELINE-6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # UUIDv1
            "",
            "   ",
        ]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ValueError):
                    TimelineEvent(
                        event_id=bad_id,
                        category=TimelineCategory.LOG,
                        event_type="test_event",
                        description="test description",
                    )

    # 3. UUIDv4 uniqueness/format
    def test_06_uuidv4_uniqueness(self):
        """6. Verify generated timeline IDs are strictly unique across 500 instances."""
        ids = {generate_timeline_id() for _ in range(500)}
        self.assertEqual(len(ids), 500)

    # 4. Immutability
    def test_07_immutability_attribute_assignment(self):
        """7. Verify TimelineEvent raises FrozenInstanceError when modifying attributes."""
        event = TimelineEvent(
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="Daily backup cron observed",
        )
        with self.assertRaises(FrozenInstanceError):
            event.description = "Altered description"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            event.event_id = "TIMELINE-altered"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            event.category = TimelineCategory.ACCOUNT  # type: ignore

    def test_08_immutability_attribute_deletion(self):
        """8. Verify TimelineEvent raises FrozenInstanceError when deleting attributes."""
        event = TimelineEvent(
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="Daily backup cron observed",
        )
        with self.assertRaises(FrozenInstanceError):
            del event.description  # type: ignore

    # 5. Timestamp storage
    def test_09_timestamp_storage_typed_datetime(self):
        """9. Verify typed datetime timestamp is stored without alteration."""
        dt = datetime(2026, 1, 15, 8, 30, 45, 123456, tzinfo=timezone.utc)
        event = TimelineEvent(
            timestamp=dt,
            category=TimelineCategory.LOG,
            event_type="system_boot",
            description="Kernel init",
        )
        self.assertIsInstance(event.timestamp, datetime)
        self.assertEqual(event.timestamp, dt)

    def test_10_timestamp_storage_from_valid_iso_string(self):
        """10. Verify valid ISO 8601 strings are converted to typed datetime."""
        iso_str = "2026-03-31T14:30:00+00:00"
        event = TimelineEvent(
            timestamp=iso_str,
            category=TimelineCategory.LOG,
            event_type="system_boot",
            description="Kernel init",
        )
        self.assertIsInstance(event.timestamp, datetime)
        self.assertEqual(event.timestamp.isoformat(), iso_str)

    # 6. Optional timestamp handling if supported
    def test_11_optional_timestamp_none_preservation(self):
        """11. Verify timestamp=None is preserved without inventing timestamps."""
        event = TimelineEvent(
            timestamp=None,
            category=TimelineCategory.ACCOUNT,
            event_type="user_account_entry",
            description="User root defined in /etc/passwd",
        )
        self.assertIsNone(event.timestamp)

    def test_12_ambiguous_incomplete_timestamp_rejected(self):
        """12. Verify ambiguous or incomplete timestamps (e.g. traditional BSD syslog) are rejected."""
        ambiguous_strings = [
            "Oct  1 12:00:00",
            "Mar 31 14:30:00",
            "yesterday at noon",
            "2026-99-99",
        ]
        for amb in ambiguous_strings:
            with self.subTest(amb=amb):
                with self.assertRaises(ValueError):
                    TimelineEvent(
                        timestamp=amb,
                        category=TimelineCategory.LOG,
                        event_type="test",
                        description="test",
                    )

    def test_13_invalid_timestamp_type_rejected(self):
        """13. Verify non-datetime, non-string timestamp types are rejected."""
        invalid_types = [1234567890, 123.45, [], {}, object()]
        for bad_val in invalid_types:
            with self.subTest(bad_val=bad_val):
                with self.assertRaises(TypeError):
                    TimelineEvent(
                        timestamp=bad_val,  # type: ignore
                        category=TimelineCategory.LOG,
                        event_type="test",
                        description="test",
                    )

    # 7. Category validation
    def test_14_category_validation_all_valid_categories(self):
        """14. Verify all broad V2-aligned categories are accepted."""
        valid_cats = [
            TimelineCategory.FILESYSTEM,
            TimelineCategory.LOG,
            TimelineCategory.AUTHENTICATION,
            TimelineCategory.ACCOUNT,
            TimelineCategory.PERSISTENCE,
        ]
        for cat in valid_cats:
            with self.subTest(cat=cat):
                event = TimelineEvent(
                    category=cat,
                    event_type="test_event",
                    description=f"Event for {cat.value}",
                )
                self.assertEqual(event.category, cat)

    def test_15_category_validation_case_insensitive_strings(self):
        """15. Verify category strings in mixed or upper case are validated and normalized."""
        test_cases = [
            ("FILESYSTEM", TimelineCategory.FILESYSTEM),
            ("filesystem", TimelineCategory.FILESYSTEM),
            ("Log", TimelineCategory.LOG),
            ("AUTHENTICATION", TimelineCategory.AUTHENTICATION),
            ("Account", TimelineCategory.ACCOUNT),
            ("PERSISTENCE", TimelineCategory.PERSISTENCE),
        ]
        for cat_str, expected_enum in test_cases:
            with self.subTest(cat_str=cat_str):
                event = TimelineEvent(
                    category=cat_str,
                    event_type="test_event",
                    description="test",
                )
                self.assertEqual(event.category, expected_enum)

    def test_16_category_validation_rejects_speculative_categories(self):
        """16. Verify speculative categories (PCAP, NETWORK, MEMORY, BROWSER, PROCESS) are rejected."""
        speculative = ["PCAP", "NETWORK", "MEMORY", "BROWSER", "PROCESS", "DNS", "CLOUD"]
        for spec in speculative:
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    TimelineEvent(
                        category=spec,
                        event_type="test",
                        description="test",
                    )

    def test_17_category_validation_invalid_type(self):
        """17. Verify non-string, non-enum category values raise TypeError."""
        for bad_cat in [None, 123, True, [], {}]:
            with self.subTest(bad_cat=bad_cat):
                with self.assertRaises((TypeError, ValueError)):
                    TimelineEvent(
                        category=bad_cat,  # type: ignore
                        event_type="test",
                        description="test",
                    )

    # 8. Event type storage
    def test_18_event_type_storage_and_validation(self):
        """18. Verify event_type is stored and empty/non-string values are rejected."""
        event = TimelineEvent(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_failure",
            description="Failed password for invalid user admin",
        )
        self.assertEqual(event.event_type, "ssh_login_failure")

        # Rejection of empty or invalid types
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="",
                description="test",
            )
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="   ",
                description="test",
            )
        with self.assertRaises(TypeError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type=123,  # type: ignore
                description="test",
            )

    def test_19_disallow_speculative_detection_event_types(self):
        """19. Verify speculative detection/conclusion event types are rejected."""
        disallowed = [
            "attack_detected",
            "compromise_confirmed",
            "malware_executed",
            "threat_detected",
            "incident_confirmed",
            "anomaly_detected",
        ]
        for dis in disallowed:
            with self.subTest(dis=dis):
                with self.assertRaises(ValueError):
                    TimelineEvent(
                        category=TimelineCategory.LOG,
                        event_type=dis,
                        description="Observation",
                    )

    # 9. Source path preservation
    def test_20_source_path_preservation(self):
        """20. Verify source path preservation for both str and Path instances."""
        event_str = TimelineEvent(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_stat",
            description="Stat /etc/shadow",
            source_path="/evidence/etc/shadow",
        )
        self.assertEqual(event_str.source_path, "/evidence/etc/shadow")

        event_path = TimelineEvent(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_stat",
            description="Stat /etc/shadow",
            source_path=Path("/evidence/etc/shadow"),
        )
        self.assertEqual(event_path.source_path, "/evidence/etc/shadow")

    def test_21_source_path_invalid_type_rejected(self):
        """21. Verify invalid source path types raise TypeError."""
        with self.assertRaises(TypeError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="test",
                description="test",
                source_path=12345,  # type: ignore
            )

    # 10. Source artifact ID preservation
    def test_22_source_artifact_id_preservation(self):
        """22. Verify source_artifact_id is preserved exactly without fabrication."""
        aid = "ART-7a18df7b-1234-4567-89ab-cdef01234567"
        event = TimelineEvent(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_analyzed",
            description="Analyzed artifact",
            source_artifact_id=aid,
        )
        self.assertEqual(event.source_artifact_id, aid)

    # 11. Source event ID preservation
    def test_23_source_event_id_preservation(self):
        """23. Verify source_event_id is preserved exactly across specialized IDs."""
        specialized_ids = [
            "LOG-1111-2222",
            "EVT-3333-4444",
            "AUTH-5555-6666",
            "USER-7777-8888",
            "PERSIST-9999-0000",
        ]
        for sid in specialized_ids:
            with self.subTest(sid=sid):
                event = TimelineEvent(
                    category=TimelineCategory.LOG,
                    event_type="log_entry",
                    description="Log entry",
                    source_event_id=sid,
                )
                self.assertEqual(event.source_event_id, sid)

    # 12. Raw/source information preservation
    def test_24_raw_source_information_preservation(self):
        """24. Verify raw_timestamp, raw_data, and line number aliases are preserved."""
        raw_ts = "Mar 31 14:30:00"
        raw_msg = "Mar 31 14:30:00 ubuntu sshd[100]: session opened"
        event = TimelineEvent(
            category=TimelineCategory.AUTHENTICATION,
            event_type="session_open",
            description="Session opened for root",
            raw_timestamp=raw_ts,
            raw_data=raw_msg,
            source_line=15,
        )
        self.assertEqual(event.raw_timestamp, raw_ts)
        self.assertEqual(event.raw_data, raw_msg)
        self.assertEqual(event.raw_line, raw_msg)
        self.assertEqual(event.source_line, 15)
        self.assertEqual(event.line_number, 15)

    def test_25_raw_line_and_line_number_constructor_aliases(self):
        """25. Verify constructor accepts line_number and raw_line aliases."""
        event = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="syslog_msg",
            description="Service restart",
            line_number=88,
            raw_line="Restarting cron service",
        )
        self.assertEqual(event.source_line, 88)
        self.assertEqual(event.line_number, 88)
        self.assertEqual(event.raw_data, "Restarting cron service")
        self.assertEqual(event.raw_line, "Restarting cron service")

    def test_26_conflicting_aliases_rejected(self):
        """26. Verify conflicting alias parameters raise ValueError."""
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="test",
                description="test",
                source_line=10,
                line_number=20,
            )
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="test",
                description="test",
                raw_data="foo",
                raw_line="bar",
            )

    # 13. to_dict() correctness
    def test_27_to_dict_correctness(self):
        """27. Verify to_dict() outputs exact dictionary matching the event model."""
        event = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Login success",
            source_path="/var/log/auth.log",
            source_line=55,
            source_artifact_id="ART-1111",
            source_event_id="AUTH-2222",
            raw_timestamp="Mar 31 14:30:00",
            raw_data="Raw line text",
            attributes={"client_ip": "10.0.0.1", "username": "admin"},
        )
        expected = {
            "event_id": self.sample_event_id,
            "timestamp": "2026-03-31T14:30:00+00:00",
            "raw_timestamp": "Mar 31 14:30:00",
            "category": "authentication",
            "event_type": "ssh_login_success",
            "description": "Login success",
            "source_path": "/var/log/auth.log",
            "source_line": 55,
            "source_artifact_id": "ART-1111",
            "source_event_id": "AUTH-2222",
            "raw_data": "Raw line text",
            "attributes": {"client_ip": "10.0.0.1", "username": "admin"},
        }
        actual = event.to_dict()
        self.assertEqual(actual, expected)

    def test_28_to_dict_with_none_values(self):
        """28. Verify to_dict() explicitly retains None for missing optional fields."""
        event = TimelineEvent(
            event_id=self.sample_event_id,
            category=TimelineCategory.ACCOUNT,
            event_type="user_added",
            description="User added to group",
        )
        d = event.to_dict()
        self.assertIsNone(d["timestamp"])
        self.assertIsNone(d["raw_timestamp"])
        self.assertIsNone(d["source_path"])
        self.assertIsNone(d["source_line"])
        self.assertIsNone(d["source_artifact_id"])
        self.assertIsNone(d["source_event_id"])
        self.assertIsNone(d["raw_data"])
        self.assertEqual(d["attributes"], {})

    # 14. JSON serialization compatibility
    def test_29_json_serialization_compatibility(self):
        """29. Verify JSON serialization round-trip via json.dumps and json.loads."""
        event = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.PERSISTENCE,
            event_type="systemd_unit_enabled",
            description="Enabled persistent unit",
            source_path="/etc/systemd/system/multi-user.target.wants/backdoor.service",
            source_line=1,
            source_artifact_id="ART-persist-1",
            source_event_id="PERSIST-svc-1",
            raw_timestamp="2026-03-31T14:30:00Z",
            raw_data="ExecStart=/opt/bin/agent",
            attributes={"unit": "backdoor.service", "scope": "system"},
        )
        dict_rep = event.to_dict()
        serialized = json.dumps(dict_rep)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized, dict_rep)

    # 15. No accidental mutable nested state
    def test_30_no_accidental_mutable_nested_state(self):
        """30. Verify attributes cannot be mutated after construction, and source mutations do not leak."""
        input_attrs = {"key": "initial_value", "nested": {"sub": 123}, "items": [1, 2, 3]}
        event = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="test_log",
            description="Test deep immutability",
            attributes=input_attrs,
        )
        # Attempting to mutate original input dictionary
        input_attrs["key"] = "mutated_value"
        input_attrs["nested"]["sub"] = 999
        input_attrs["items"].append(4)

        # TimelineEvent attributes must be untouched
        self.assertEqual(event.to_dict()["attributes"]["key"], "initial_value")
        self.assertEqual(event.to_dict()["attributes"]["nested"]["sub"], 123)
        self.assertEqual(event.to_dict()["attributes"]["items"], [1, 2, 3])

        # Attributes structure must be immutable tuple
        self.assertIsInstance(event.attributes, tuple)
        with self.assertRaises(TypeError):
            event.attributes[0] = ("new", "val")  # type: ignore

    # 16. Invalid required input handling
    def test_31_invalid_required_input_handling(self):
        """31. Verify missing required inputs raise TypeError / ValueError."""
        # Missing category
        with self.assertRaises(TypeError):
            TimelineEvent(event_type="ssh_login", description="desc")  # type: ignore

        # Missing event_type
        with self.assertRaises(TypeError):
            TimelineEvent(category=TimelineCategory.LOG, description="desc")  # type: ignore

        # Missing description
        with self.assertRaises(TypeError):
            TimelineEvent(category=TimelineCategory.LOG, event_type="ssh_login")  # type: ignore

        # Empty description
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="ssh_login",
                description="",
            )

        # Invalid source_line type
        with self.assertRaises(TypeError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="ssh_login",
                description="desc",
                source_line="not-an-int",  # type: ignore
            )

        # Negative or zero source_line (1-indexed)
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="ssh_login",
                description="desc",
                source_line=-5,
            )
        with self.assertRaises(ValueError):
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="ssh_login",
                description="desc",
                source_line=0,
            )

    # 17. No fabricated source IDs
    def test_32_no_fabricated_source_ids(self):
        """32. Verify source_artifact_id and source_event_id remain None when omitted."""
        event = TimelineEvent(
            category=TimelineCategory.ACCOUNT,
            event_type="account_discovery",
            description="Observed account entry",
        )
        self.assertIsNone(event.source_artifact_id)
        self.assertIsNone(event.source_event_id)
        d = event.to_dict()
        self.assertIsNone(d["source_artifact_id"])
        self.assertIsNone(d["source_event_id"])

    # 18. No detection/correlation fields being introduced
    def test_33_no_detection_or_correlation_fields_introduced(self):
        """33. Verify TimelineEvent has no detection, risk, severity, or correlation fields."""
        prohibited_terms = [
            "risk",
            "risk_score",
            "severity",
            "threat",
            "threat_level",
            "confidence",
            "correlation",
            "correlation_id",
            "cluster",
            "attack",
            "attack_stage",
            "compromise",
            "compromise_status",
            "malicious",
            "is_malicious",
            "verdict",
            "recommendation",
            "recommendations",
        ]
        # Inspect model class attributes
        class_dir = set(dir(TimelineEvent))
        for term in prohibited_terms:
            self.assertNotIn(term, class_dir, f"Disallowed field '{term}' found on TimelineEvent class")

        # Inspect instance attributes and dictionary representation
        event = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="auth_pam",
            description="PAM authentication completed",
        )
        dict_keys = set(event.to_dict().keys())
        for term in prohibited_terms:
            self.assertNotIn(term, dict_keys, f"Disallowed key '{term}' found in to_dict()")
            self.assertFalse(hasattr(event, term), f"Disallowed attribute '{term}' found on event instance")

    # 19. Deterministic serialization structure
    def test_34_deterministic_serialization_structure(self):
        """34. Verify to_dict() produces deterministic field ordering and identical byte output."""
        event1 = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="Cron job at /etc/cron.d/daily",
            source_path="/etc/cron.d/daily",
            source_line=12,
            source_artifact_id="ART-1234",
            source_event_id="PERSIST-5678",
            raw_timestamp="2026-03-31T14:30:00Z",
            raw_data="0 2 * * * /backup.sh",
            attributes={"user": "root", "schedule": "0 2 * * *"},
        )
        event2 = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="Cron job at /etc/cron.d/daily",
            source_path="/etc/cron.d/daily",
            source_line=12,
            source_artifact_id="ART-1234",
            source_event_id="PERSIST-5678",
            raw_timestamp="2026-03-31T14:30:00Z",
            raw_data="0 2 * * * /backup.sh",
            # Pass attributes in opposite order to test sorting determinism
            attributes={"schedule": "0 2 * * *", "user": "root"},
        )

        d1 = event1.to_dict()
        d2 = event2.to_dict()

        # Keys and values must match exactly in same order
        self.assertEqual(list(d1.keys()), list(d2.keys()))
        self.assertEqual(d1, d2)

        # JSON byte serialization must be identical
        json1 = json.dumps(d1)
        json2 = json.dumps(d2)
        self.assertEqual(json1, json2)

    def test_35_equality_and_hashability(self):
        """35. Verify TimelineEvent instances support value equality and hashing."""
        event1 = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.LOG,
            event_type="test",
            description="test description",
            attributes={"k": "v"},
        )
        event2 = TimelineEvent(
            event_id=self.sample_event_id,
            timestamp=self.sample_dt,
            category=TimelineCategory.LOG,
            event_type="test",
            description="test description",
            attributes={"k": "v"},
        )
        self.assertEqual(event1, event2)
        self.assertEqual(hash(event1), hash(event2))
        event_set = {event1, event2}
        self.assertEqual(len(event_set), 1)

    # Regression tests for V3.1 fixes
    def test_36_source_line_zero_rejected(self):
        """36. Verify source_line=0 is strictly rejected as source_line is 1-indexed."""
        with self.assertRaises(ValueError) as ctx:
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="test",
                description="test",
                source_line=0,
            )
        self.assertIn(">= 1", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            TimelineEvent(
                category=TimelineCategory.LOG,
                event_type="test",
                description="test",
                line_number=0,
            )
        self.assertIn(">= 1", str(ctx.exception))

    def test_37_unfreeze_to_dict_falsy_values_integrity(self):
        """37. Verify falsy attribute values (False, 0, '', []) round-trip without corruption."""
        test_cases = [
            {"enabled": False},
            {"count": 0},
            {"text": ""},
            {"items": []},
            {
                "enabled": False,
                "count": 0,
                "text": "",
                "items": [],
                "nested": {"active": False, "total": 0, "log": "", "subitems": []},
            },
        ]
        for payload in test_cases:
            with self.subTest(payload=payload):
                event = TimelineEvent(
                    category=TimelineCategory.LOG,
                    event_type="falsy_test",
                    description="Testing falsy value preservation",
                    attributes=payload,
                )
                actual_attrs = event.to_dict()["attributes"]
                self.assertEqual(actual_attrs, payload)
                # Verify exact types
                if "enabled" in payload:
                    self.assertIs(actual_attrs["enabled"], False)
                if "count" in payload:
                    self.assertIs(actual_attrs["count"], 0)
                    self.assertNotIsInstance(actual_attrs["count"], bool)
                if "text" in payload:
                    self.assertEqual(actual_attrs["text"], "")
                if "items" in payload:
                    self.assertEqual(actual_attrs["items"], [])


if __name__ == "__main__":
    unittest.main()
