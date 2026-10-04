"""
Focused Unit Test Suite for ForensiX V4.1 Correlation Model.

Covers:
1. Valid Correlation construction (all fields, minimal fields, factory).
2. Every supported relationship type (enum, uppercase string, lowercase string).
3. Invalid relationship types (unknown types, empty, malformed, non-string).
4. Required fields validation (missing relationship_type, event_ids, description).
5. Invalid event references (fewer than 2, empty collection, malformed UUIDs, duplicates).
6. TimelineEvent objects as input (auto-extraction of IDs, provenance, timestamps).
7. Provenance preservation (source_event_ids, source_artifact_ids).
8. Deep immutability (modifications raise FrozenInstanceError).
9. Deterministic correlation identity (RFC 4122 UUIDv5 reproducibility across runs).
10. Explicit correlation ID validation (CORR-<UUIDv4/v5>, rejection of invalid).
11. Serialization to_dict, JSON compatibility, and roundtrip via from_dict.
12. Falsy values preservation (0, 0.0, False, empty collections).
13. Temporal handling (aware, naive, awareness mismatch, delta calculation).
14. Speculative language rejection (prohibiting unverified attack/compromise claims).
15. CorrelationCollection functionality (aggregation, summary, immutability, to_dict).
16. Regression against V3 models (TimelineEvent and ReconstructedTimeline unaffected).
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
import unittest
import uuid

from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
    create_correlation,
    generate_correlation_id,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import ReconstructedTimeline


class TestCorrelationModel(unittest.TestCase):
    """Rigorous unit tests for the ForensiX V4.1 Correlation Model."""

    def setUp(self) -> None:
        self.uuid1 = "11111111-1111-4111-8111-111111111111"
        self.uuid2 = "22222222-2222-4222-8222-222222222222"
        self.uuid3 = "33333333-3333-4333-8333-333333333333"

        self.event_id_1 = f"TIMELINE-{self.uuid1}"
        self.event_id_2 = f"TIMELINE-{self.uuid2}"
        self.event_id_3 = f"TIMELINE-{self.uuid3}"

        self.dt1 = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
        self.dt2 = datetime(2026, 4, 1, 10, 2, 0, tzinfo=timezone.utc)

    # 1. Valid construction with all fields
    def test_01_valid_correlation_construction_all_fields(self):
        """Verify construction of Correlation with all fields explicitly provided."""
        custom_id = f"CORR-{self.uuid1}"
        corr = Correlation(
            correlation_id=custom_id,
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Successful SSH login followed by sudo command for user alice",
            source_event_ids=["AUTH-100", "AUTH-200"],
            source_artifact_ids=["ART-100"],
            start_timestamp=self.dt1,
            end_timestamp=self.dt2,
            time_delta_seconds=120.0,
            attributes={"user": "alice", "src_ip": "192.168.1.50"},
        )
        self.assertEqual(corr.correlation_id, custom_id)
        self.assertEqual(corr.relationship_type, CorrelationType.AUTHENTICATION_PRIVILEGE)
        self.assertEqual(corr.event_ids, (self.event_id_1, self.event_id_2))
        self.assertEqual(corr.timeline_event_ids, (self.event_id_1, self.event_id_2))
        self.assertEqual(corr.source_event_ids, ("AUTH-100", "AUTH-200"))
        self.assertEqual(corr.source_artifact_ids, ("ART-100",))
        self.assertEqual(corr.start_timestamp, self.dt1)
        self.assertEqual(corr.end_timestamp, self.dt2)
        self.assertEqual(corr.time_delta_seconds, 120.0)
        self.assertEqual(corr.delta_seconds, 120.0)
        self.assertEqual(
            corr.description,
            "Successful SSH login followed by sudo command for user alice",
        )
        self.assertEqual(corr.explanation, corr.description)
        self.assertIsInstance(corr.attributes, tuple)

    # 2. Valid construction with minimal fields
    def test_02_valid_correlation_minimal_fields(self):
        """Verify construction of Correlation with minimal required fields."""
        corr = Correlation(
            relationship_type=CorrelationType.SAME_USER,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Events associated with user bob",
        )
        self.assertTrue(corr.correlation_id.startswith("CORR-"))
        self.assertEqual(corr.relationship_type, CorrelationType.SAME_USER)
        self.assertEqual(corr.event_ids, (self.event_id_1, self.event_id_2))
        self.assertEqual(corr.source_event_ids, ())
        self.assertEqual(corr.source_artifact_ids, ())
        self.assertIsNone(corr.start_timestamp)
        self.assertIsNone(corr.end_timestamp)
        self.assertIsNone(corr.time_delta_seconds)
        self.assertEqual(corr.description, "Events associated with user bob")

    # 3. Factory function create_correlation
    def test_03_create_correlation_factory(self):
        """Verify create_correlation factory function operates identically to direct constructor."""
        corr = create_correlation(
            relationship_type="TEMPORAL",
            event_ids=[self.event_id_1, self.event_id_2],
            description="Temporal proximity between file creation and auth",
            time_delta_seconds=30.0,
        )
        self.assertEqual(corr.relationship_type, CorrelationType.TEMPORAL)
        self.assertEqual(corr.time_delta_seconds, 30.0)

    # 4. Every supported relationship type
    def test_04_every_supported_relationship_type(self):
        """Verify all 6 supported relationship types are accepted via Enum and string."""
        expected_types = [
            CorrelationType.TEMPORAL,
            CorrelationType.SAME_USER,
            CorrelationType.SAME_SOURCE,
            CorrelationType.SAME_PATH,
            CorrelationType.SAME_SESSION,
            CorrelationType.AUTHENTICATION_PRIVILEGE,
        ]
        self.assertIs(RelationshipType, CorrelationType)

        for rel in expected_types:
            with self.subTest(rel=rel):
                # 1. Via Enum directly
                c1 = Correlation(
                    relationship_type=rel,
                    event_ids=[self.event_id_1, self.event_id_2],
                    description=f"Testing relationship {rel.value}",
                )
                self.assertEqual(c1.relationship_type, rel)

                # 2. Via uppercase string
                c2 = Correlation(
                    relationship_type=rel.value,
                    event_ids=[self.event_id_1, self.event_id_2],
                    description=f"Testing relationship string {rel.value}",
                )
                self.assertEqual(c2.relationship_type, rel)

                # 3. Via lowercase string
                c3 = Correlation(
                    relationship_type=rel.value.lower(),
                    event_ids=[self.event_id_1, self.event_id_2],
                    description=f"Testing relationship lowercase {rel.value.lower()}",
                )
                self.assertEqual(c3.relationship_type, rel)

    # 5. Invalid relationship types
    def test_05_invalid_relationship_types(self):
        """Verify invalid or unapproved relationship types are strictly rejected."""
        bad_types = ["MALICIOUS_CHAIN", "UNKNOWN_REL", "", "   ", "lateral_movement"]
        for bad in bad_types:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Correlation(
                        relationship_type=bad,
                        event_ids=[self.event_id_1, self.event_id_2],
                        description="Test invalid type",
                    )

        with self.assertRaises(TypeError):
            Correlation(
                relationship_type=12345,  # type: ignore
                event_ids=[self.event_id_1, self.event_id_2],
                description="Test invalid type",
            )

    # 6. Required fields validation
    def test_06_required_fields_validation(self):
        """Verify missing required fields raise appropriate TypeErrors."""
        with self.assertRaises(TypeError):
            Correlation(event_ids=[self.event_id_1, self.event_id_2], description="Missing type")  # type: ignore
        with self.assertRaises(TypeError):
            Correlation(relationship_type=CorrelationType.TEMPORAL, description="Missing events")  # type: ignore
        with self.assertRaises(TypeError):
            Correlation(relationship_type=CorrelationType.TEMPORAL, event_ids=[self.event_id_1, self.event_id_2])  # type: ignore

    # 7. Invalid event references
    def test_07_invalid_event_references(self):
        """Verify invalid event reference inputs are strictly rejected."""
        # Empty collection
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[],
                description="Empty events",
            )

        # Fewer than 2 events
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1],
                description="Single event",
            )

        # Correlating an event with itself
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1, self.event_id_1],
                description="Self correlation",
            )

        # Non-string / non-event item in sequence
        with self.assertRaises(TypeError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1, 999],  # type: ignore
                description="Non-string event item",
            )

        # Malformed timeline event ID format
        bad_ids = [
            "NOT-TIMELINE-123",
            "TIMELINE-not-a-uuid",
            "TIMELINE-6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # UUIDv1
            "",
            "   ",
        ]
        for bad in bad_ids:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Correlation(
                        relationship_type=CorrelationType.TEMPORAL,
                        event_ids=[self.event_id_1, bad],
                        description="Malformed event id",
                    )

    # 8. TimelineEvent objects as input
    def test_08_timeline_event_objects_as_input(self):
        """Verify passing TimelineEvent instances directly auto-extracts IDs, provenance, and timestamps."""
        ev1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for ubuntu",
            timestamp=self.dt1,
            source_artifact_id="ART-11111111-1111-4111-8111-111111111111",
            source_event_id="AUTH-11111111-1111-4111-8111-111111111111",
        )
        ev2 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="COMMAND=/bin/cat /etc/shadow",
            timestamp=self.dt2,
            source_artifact_id="ART-11111111-1111-4111-8111-111111111111",
            source_event_id="AUTH-22222222-2222-4222-8222-222222222222",
        )

        corr = Correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[ev1, ev2],
            description="Observed authentication followed by privilege escalation",
        )
        self.assertEqual(corr.event_ids, (ev1.event_id, ev2.event_id))
        self.assertEqual(
            corr.source_event_ids,
            ("AUTH-11111111-1111-4111-8111-111111111111", "AUTH-22222222-2222-4222-8222-222222222222"),
        )
        # Deduplicated source artifact IDs
        self.assertEqual(corr.source_artifact_ids, ("ART-11111111-1111-4111-8111-111111111111",))
        self.assertEqual(corr.start_timestamp, self.dt1)
        self.assertEqual(corr.end_timestamp, self.dt2)
        self.assertEqual(corr.time_delta_seconds, 120.0)

    # 9. Provenance preservation
    def test_09_provenance_preservation(self):
        """Verify source_event_ids and source_artifact_ids preserve provenance faithfully."""
        corr = Correlation(
            relationship_type=CorrelationType.SAME_SOURCE,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Events from same host",
            source_event_ids=["EVT-1", "EVT-2", "EVT-1"],  # should deduplicate preserving order
            source_artifact_ids="ART-FILE-1",  # single string wrapped to tuple
        )
        self.assertEqual(corr.source_event_ids, ("EVT-1", "EVT-2"))
        self.assertEqual(corr.source_artifact_ids, ("ART-FILE-1",))

        # Rejection of invalid source IDs
        with self.assertRaises(TypeError):
            Correlation(
                relationship_type=CorrelationType.SAME_SOURCE,
                event_ids=[self.event_id_1, self.event_id_2],
                description="Test",
                source_event_ids=[123],  # type: ignore
            )
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.SAME_SOURCE,
                event_ids=[self.event_id_1, self.event_id_2],
                description="Test",
                source_event_ids=[""],
            )

    # 10. Deep immutability
    def test_10_deep_immutability(self):
        """Verify Correlation raises FrozenInstanceError when modifying any field."""
        corr = Correlation(
            relationship_type=CorrelationType.SAME_USER,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Events for user root",
            attributes={"key": "initial_value"},
        )
        with self.assertRaises(FrozenInstanceError):
            corr.description = "Altered description"  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            corr.event_ids = (self.event_id_1,)  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            corr.relationship_type = CorrelationType.TEMPORAL  # type: ignore

    # 11. Deterministic correlation identity
    def test_11_deterministic_correlation_identity(self):
        """Verify correlation IDs generated via UUIDv5 are 100% reproducible and order-independent."""
        # Same events and type -> identical ID
        c1 = Correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Test correlation run 1",
        )
        c2 = Correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.event_id_2, self.event_id_1],  # Reversed order
            description="Test correlation run 2 with different description",
        )
        self.assertEqual(c1.correlation_id, c2.correlation_id)

        # Direct function call produces identical ID
        computed_id = compute_deterministic_correlation_id(
            CorrelationType.AUTHENTICATION_PRIVILEGE,
            [self.event_id_1, self.event_id_2],
        )
        self.assertEqual(c1.correlation_id, computed_id)

        # Different relationship type produces different ID
        c3 = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Test different type",
        )
        self.assertNotEqual(c1.correlation_id, c3.correlation_id)

        # Discriminator changes ID predictably
        id_with_disc = compute_deterministic_correlation_id(
            CorrelationType.AUTHENTICATION_PRIVILEGE,
            [self.event_id_1, self.event_id_2],
            discriminator="user:alice",
        )
        self.assertNotEqual(c1.correlation_id, id_with_disc)

    # 12. Explicit correlation ID validation
    def test_12_explicit_correlation_id_validation(self):
        """Verify explicit correlation IDs are validated against CORR-<UUIDv4/v5>."""
        valid_v4 = generate_correlation_id()
        self.assertTrue(valid_v4.startswith("CORR-"))
        corr_v4 = Correlation(
            correlation_id=valid_v4,
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Explicit v4 ID",
        )
        self.assertEqual(corr_v4.correlation_id, valid_v4)

        bad_ids = [
            "TIMELINE-11111111-1111-4111-8111-111111111111",  # Wrong prefix
            "CORR-not-a-uuid",
            "CORR-6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # UUIDv1
            "",
            "   ",
        ]
        for bad in bad_ids:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Correlation(
                        correlation_id=bad,
                        relationship_type=CorrelationType.TEMPORAL,
                        event_ids=[self.event_id_1, self.event_id_2],
                        description="Bad correlation ID",
                    )

    # 13. Serialization and roundtrip
    def test_13_serialization_to_dict_and_roundtrip(self):
        """Verify to_dict produces valid JSON-serializable output and roundtrips via from_dict."""
        corr = Correlation(
            relationship_type=CorrelationType.SAME_PATH,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Modification of /etc/pam.d/common-auth",
            source_event_ids=["LOG-10", "LOG-20"],
            source_artifact_ids=["ART-PAM"],
            start_timestamp=self.dt1,
            end_timestamp=self.dt2,
            time_delta_seconds=120.0,
            attributes={"path": "/etc/pam.d/common-auth", "count": 2},
        )
        d = corr.to_dict()
        self.assertEqual(d["correlation_id"], corr.correlation_id)
        self.assertEqual(d["relationship_type"], "SAME_PATH")
        self.assertEqual(d["event_ids"], [self.event_id_1, self.event_id_2])
        self.assertEqual(d["source_event_ids"], ["LOG-10", "LOG-20"])
        self.assertEqual(d["source_artifact_ids"], ["ART-PAM"])
        self.assertEqual(d["start_timestamp"], self.dt1.isoformat())
        self.assertEqual(d["end_timestamp"], self.dt2.isoformat())
        self.assertEqual(d["time_delta_seconds"], 120.0)
        self.assertEqual(d["attributes"]["count"], 2)

        # JSON serialization
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["correlation_id"], corr.correlation_id)

        # Roundtrip via from_dict
        reconstructed = Correlation.from_dict(d)
        self.assertEqual(reconstructed.correlation_id, corr.correlation_id)
        self.assertEqual(reconstructed.relationship_type, corr.relationship_type)
        self.assertEqual(reconstructed.event_ids, corr.event_ids)
        self.assertEqual(reconstructed.source_event_ids, corr.source_event_ids)
        self.assertEqual(reconstructed.start_timestamp, corr.start_timestamp)
        self.assertEqual(reconstructed.end_timestamp, corr.end_timestamp)
        self.assertEqual(reconstructed.time_delta_seconds, corr.time_delta_seconds)

    # 14. Falsy values preservation
    def test_14_falsy_values_preservation(self):
        """Verify falsy scalar values (0, 0.0, False) and empty collections are not treated as None."""
        corr = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Simultaneous events",
            time_delta_seconds=0.0,  # 0.0 delta
            attributes={"flag": False, "attempts": 0, "empty_list": []},
        )
        self.assertIsNotNone(corr.time_delta_seconds)
        self.assertEqual(corr.time_delta_seconds, 0.0)

        d = corr.to_dict()
        self.assertEqual(d["time_delta_seconds"], 0.0)
        self.assertIs(d["attributes"]["flag"], False)
        self.assertEqual(d["attributes"]["attempts"], 0)
        self.assertEqual(d["attributes"]["empty_list"], [])

    # 15. Temporal handling
    def test_15_temporal_handling(self):
        """Verify aware, naive, and awareness-mismatch timestamp handling."""
        # 1. Aware timestamps compute delta
        c_aware = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Aware timestamps",
            start_timestamp=self.dt1,
            end_timestamp=self.dt2,
        )
        self.assertEqual(c_aware.time_delta_seconds, 120.0)

        # 2. Naive timestamps compute delta
        dt_naive1 = datetime(2026, 4, 1, 10, 0, 0)
        dt_naive2 = datetime(2026, 4, 1, 10, 5, 0)
        c_naive = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Naive timestamps",
            start_timestamp=dt_naive1,
            end_timestamp=dt_naive2,
        )
        self.assertEqual(c_naive.time_delta_seconds, 300.0)

        # 3. Awareness mismatch: aware vs naive does NOT raise TypeError and does NOT guess timezone
        c_mismatch = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Awareness mismatch",
            start_timestamp=self.dt1,  # Aware UTC
            end_timestamp=dt_naive2,   # Naive
        )
        self.assertIsNone(c_mismatch.time_delta_seconds)

        # 4. start > end raises ValueError
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1, self.event_id_2],
                description="Inverted timestamps",
                start_timestamp=self.dt2,
                end_timestamp=self.dt1,
            )

        # 5. Negative time_delta_seconds raises ValueError
        with self.assertRaises(ValueError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1, self.event_id_2],
                description="Negative delta",
                time_delta_seconds=-10.0,
            )

        # 6. Boolean passed as time_delta_seconds raises TypeError
        with self.assertRaises(TypeError):
            Correlation(
                relationship_type=CorrelationType.TEMPORAL,
                event_ids=[self.event_id_1, self.event_id_2],
                description="Bool delta",
                time_delta_seconds=True,  # type: ignore
            )

    # 16. Speculative language rejection
    def test_16_speculative_language_rejection(self):
        """Verify speculative or interpretive labels are rejected per forensic principles."""
        disallowed_phrases = [
            "This was a confirmed attack on the server",
            "Observed attacker confirmed in system",
            "Result indicates system compromised",
            "Malware confirmed running on host",
            "Severe intrusion confirmed by correlation",
        ]
        for phrase in disallowed_phrases:
            with self.subTest(phrase=phrase):
                with self.assertRaises(ValueError):
                    Correlation(
                        relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
                        event_ids=[self.event_id_1, self.event_id_2],
                        description=phrase,
                    )

    # 17. CorrelationCollection functionality
    def test_17_correlation_collection(self):
        """Verify CorrelationCollection aggregation, summary metrics, immutability, and indexing."""
        c1 = Correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.event_id_1, self.event_id_2],
            description="Auth followed by privilege",
        )
        c2 = Correlation(
            relationship_type=CorrelationType.SAME_USER,
            event_ids=[self.event_id_2, self.event_id_3],
            description="Same user activity",
        )
        c3 = Correlation(
            relationship_type=CorrelationType.AUTHENTICATION_PRIVILEGE,
            event_ids=[self.event_id_1, self.event_id_3],
            description="Second auth privilege",
        )

        col = CorrelationCollection([c1, c2, c3])
        self.assertEqual(len(col), 3)
        self.assertEqual(col.total_correlations, 3)
        self.assertEqual(col[0], c1)
        self.assertEqual(list(iter(col)), [c1, c2, c3])
        self.assertIn(c2, col)

        # Summary
        summary = col.summary
        self.assertEqual(summary["total_correlations"], 3)
        self.assertEqual(summary["relationship_counts"]["AUTHENTICATION_PRIVILEGE"], 2)
        self.assertEqual(summary["relationship_counts"]["SAME_USER"], 1)

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            col.total_correlations = 10  # type: ignore

        # to_dict serialization
        d = col.to_dict()
        self.assertEqual(len(d["correlations"]), 3)
        self.assertEqual(d["summary"]["total_correlations"], 3)
        json_output = json.dumps(d)
        self.assertIn("AUTHENTICATION_PRIVILEGE", json_output)

        # Reject non-Correlation items
        with self.assertRaises(TypeError):
            CorrelationCollection([c1, "not-a-correlation"])  # type: ignore

    # 18. Regression against V3 models
    def test_18_regression_against_v3_models(self):
        """Verify V3 models (TimelineEvent, ReconstructedTimeline) are completely untouched and unaffected."""
        ev1 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="Created /tmp/test.sh",
            timestamp=self.dt1,
        )
        ev2 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog_entry",
            description="Cron job started",
            timestamp=self.dt2,
        )

        # Create reconstructed timeline
        timeline = ReconstructedTimeline(
            events=(ev1, ev2),
            total_events=2,
            duplicates_removed=0,
            timestamp_class_counts=(("aware", 2),),
            category_counts=(("filesystem", 1), ("log", 1)),
        )
        self.assertEqual(len(timeline), 2)

        # Feed events into correlation
        corr = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[ev1, ev2],
            description="Temporal relation between file creation and cron",
        )
        self.assertEqual(corr.event_ids, (ev1.event_id, ev2.event_id))

        # Verify ev1 and ev2 dictionaries and properties remain identical
        ev1_dict = ev1.to_dict()
        self.assertEqual(ev1_dict["event_id"], ev1.event_id)
        self.assertEqual(ev1_dict["category"], "filesystem")


if __name__ == "__main__":
    unittest.main()
