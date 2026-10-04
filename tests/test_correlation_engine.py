"""
Focused Unit Test Suite for ForensiX V4.2 Correlation Engine.

Covers:
1. Empty timeline
2. Single event
3. Unrelated events
4. Temporal match
5. Temporal non-match
6. Exact time-window boundary (inside, exact, outside)
7. Same-user match
8. Same-user mismatch
9. Same-source match
10. Same-source mismatch
11. Same-path match
12. Same-path mismatch
13. Same-session match
14. Same-session mismatch
15. Authentication -> privilege match
16. Wrong authentication/privilege order
17. Wrong user (auth/privilege mismatch)
18. Outside time window (auth/privilege)
19. Missing attributes handling
20. Missing timestamps handling (no fabrication)
21. Aware timestamp behavior
22. Naive timestamp behavior
23. Aware/naive mismatch handling (no silent conversion)
24. Duplicate prevention
25. Multiple legitimate relationship types between same events
26. Provenance preservation
27. Input immutability
28. Output immutability
29. Deterministic repeated execution
30. Stable ordering
31. Serialization compatibility
32. V4.1 regression
33. V3 regression
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
import unittest

from forensix.correlation_engine import (
    CorrelationConfig,
    CorrelationEngine,
    correlate_events,
    compute_timestamp_delta,
    extract_user_identity,
    extract_source_identity,
    extract_path_identity,
    extract_session_identity,
)
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import ReconstructedTimeline


class TestCorrelationEngine(unittest.TestCase):
    """Rigorous unit tests for ForensiX V4.2 Correlation Engine."""

    def setUp(self) -> None:
        self.dt_base = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
        self.dt_plus_60 = datetime(2026, 4, 1, 10, 1, 0, tzinfo=timezone.utc)
        self.dt_plus_120 = datetime(2026, 4, 1, 10, 2, 0, tzinfo=timezone.utc)
        self.dt_plus_300 = datetime(2026, 4, 1, 10, 5, 0, tzinfo=timezone.utc)
        self.dt_plus_600 = datetime(2026, 4, 1, 10, 10, 0, tzinfo=timezone.utc)

        self.ev_auth_alice = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for alice from 192.168.1.100 port 45123 ssh2",
            timestamp=self.dt_base,
            source_path="/var/log/auth.log",
            source_line=10,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-001",
            attributes={
                "username": "alice",
                "source_ip": "192.168.1.100",
                "session_id": "sess-42",
            },
        )

        self.ev_sudo_alice = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            timestamp=self.dt_plus_120,
            source_path="/var/log/auth.log",
            source_line=25,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-002",
            attributes={
                "username": "alice",
                "source_ip": "192.168.1.100",
                "session_id": "sess-42",
                "command": "/bin/cat /etc/shadow",
                "path": "/etc/shadow",
            },
        )

        self.ev_file_shadow = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="File accessed: /etc/shadow",
            timestamp=self.dt_plus_120,
            source_path="/etc/shadow",
            source_artifact_id="ART-SHADOW",
            source_event_id=None,
            attributes={"path": "etc/shadow"},
        )

    # 1. Empty timeline
    def test_01_empty_timeline(self):
        """1. Verify empty timeline produces an empty CorrelationCollection."""
        engine = CorrelationEngine()
        result = engine.correlate([])
        self.assertIsInstance(result, CorrelationCollection)
        self.assertEqual(len(result), 0)
        self.assertEqual(result.total_correlations, 0)

    # 2. Single event
    def test_02_single_event(self):
        """2. Verify single event timeline produces an empty CorrelationCollection."""
        engine = CorrelationEngine()
        result = engine.correlate([self.ev_auth_alice])
        self.assertEqual(len(result), 0)

    # 3. Unrelated events
    def test_03_unrelated_events(self):
        """3. Verify completely unrelated events outside time window produce zero correlations."""
        ev_bob = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="app_log",
            description="Unrelated cron task for bob",
            timestamp=self.dt_plus_600,
            source_path="/var/log/syslog",
            attributes={"username": "bob", "source_ip": "10.0.0.99"},
        )
        engine = CorrelationEngine(time_window_seconds=60.0)
        result = engine.correlate([self.ev_auth_alice, ev_bob])
        self.assertEqual(len(result), 0)

    # 4. Temporal match
    def test_04_temporal_match(self):
        """4. Verify events within configured time window create a TEMPORAL correlation."""
        engine = CorrelationEngine(
            time_window_seconds=150.0,
            relationship_types=[CorrelationType.TEMPORAL],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        corr = result[0]
        self.assertEqual(corr.relationship_type, CorrelationType.TEMPORAL)
        self.assertEqual(corr.time_delta_seconds, 120.0)

    # 5. Temporal non-match
    def test_05_temporal_non_match(self):
        """5. Verify events outside configured time window do not create a TEMPORAL correlation."""
        engine = CorrelationEngine(
            time_window_seconds=60.0,
            relationship_types=[CorrelationType.TEMPORAL],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 0)

    # 6. Exact time-window boundary
    def test_06_exact_time_window_boundary(self):
        """6. Verify exact boundary (delta <= window): inside, exact, outside."""
        dt_boundary = self.dt_plus_300  # delta is exactly 300.0s from dt_base
        ev_boundary = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="cron_task",
            description="Scheduled task",
            timestamp=dt_boundary,
        )

        # Exact match (delta == 300.0s, window == 300.0s -> True)
        engine_exact = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.TEMPORAL],
        )
        res_exact = engine_exact.correlate([self.ev_auth_alice, ev_boundary])
        self.assertEqual(len(res_exact), 1)
        self.assertEqual(res_exact[0].time_delta_seconds, 300.0)

        # Just outside (window == 299.9s -> False)
        engine_outside = CorrelationEngine(
            time_window_seconds=299.9,
            relationship_types=[CorrelationType.TEMPORAL],
        )
        res_outside = engine_outside.correlate([self.ev_auth_alice, ev_boundary])
        self.assertEqual(len(res_outside), 0)

        # Just inside (window == 300.1s -> True)
        engine_inside = CorrelationEngine(
            time_window_seconds=300.1,
            relationship_types=[CorrelationType.TEMPORAL],
        )
        res_inside = engine_inside.correlate([self.ev_auth_alice, ev_boundary])
        self.assertEqual(len(res_inside), 1)

    # 7. Same-user match
    def test_07_same_user_match(self):
        """7. Verify SAME_USER correlation when both events explicitly share user identity."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.SAME_USER],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].relationship_type, CorrelationType.SAME_USER)
        self.assertIn("alice", result[0].description)

    # 8. Same-user mismatch
    def test_08_same_user_mismatch(self):
        """8. Verify SAME_USER does not match when users differ."""
        ev_bob = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="bob sudo",
            timestamp=self.dt_plus_60,
            attributes={"username": "bob"},
        )
        engine = CorrelationEngine(relationship_types=[CorrelationType.SAME_USER])
        result = engine.correlate([self.ev_auth_alice, ev_bob])
        self.assertEqual(len(result), 0)

    # 9. Same-source match
    def test_09_same_source_match(self):
        """9. Verify SAME_SOURCE correlation when events explicitly share source IP / host."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.SAME_SOURCE],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].relationship_type, CorrelationType.SAME_SOURCE)
        self.assertIn("192.168.1.100", result[0].description)

    # 10. Same-source mismatch
    def test_10_same_source_mismatch(self):
        """10. Verify SAME_SOURCE does not match when source identities differ."""
        ev_other_src = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="login from 10.0.0.1",
            timestamp=self.dt_plus_60,
            attributes={"source_ip": "10.0.0.1"},
        )
        engine = CorrelationEngine(relationship_types=[CorrelationType.SAME_SOURCE])
        result = engine.correlate([self.ev_auth_alice, ev_other_src])
        self.assertEqual(len(result), 0)

    # 11. Same-path match
    def test_11_same_path_match(self):
        """11. Verify SAME_PATH correlation when events reference the same normalized path."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.SAME_PATH],
        )
        result = engine.correlate([self.ev_sudo_alice, self.ev_file_shadow])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].relationship_type, CorrelationType.SAME_PATH)
        self.assertIn("etc/shadow", result[0].description)

    # 12. Same-path mismatch
    def test_12_same_path_mismatch(self):
        """12. Verify SAME_PATH does not match when paths differ."""
        ev_other_file = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="created /tmp/test.txt",
            timestamp=self.dt_plus_120,
            source_path="/tmp/test.txt",
            attributes={"path": "/tmp/test.txt"},
        )
        engine = CorrelationEngine(relationship_types=[CorrelationType.SAME_PATH])
        result = engine.correlate([self.ev_file_shadow, ev_other_file])
        self.assertEqual(len(result), 0)

    # 13. Same-session match
    def test_13_same_session_match(self):
        """13. Verify SAME_SESSION correlation when both events explicitly share session ID."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.SAME_SESSION],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].relationship_type, CorrelationType.SAME_SESSION)
        self.assertIn("sess-42", result[0].description)

    # 14. Same-session mismatch
    def test_14_same_session_mismatch(self):
        """14. Verify SAME_SESSION does not match when sessions differ."""
        ev_diff_sess = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="sudo session 99",
            timestamp=self.dt_plus_60,
            attributes={"session_id": "sess-99"},
        )
        engine = CorrelationEngine(relationship_types=[CorrelationType.SAME_SESSION])
        result = engine.correlate([self.ev_auth_alice, ev_diff_sess])
        self.assertEqual(len(result), 0)

    # 15. Authentication -> privilege match
    def test_15_auth_privilege_match(self):
        """15. Verify AUTHENTICATION_PRIVILEGE matches when auth is followed by privilege activity."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.AUTHENTICATION_PRIVILEGE],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        corr = result[0]
        self.assertEqual(corr.relationship_type, CorrelationType.AUTHENTICATION_PRIVILEGE)
        self.assertEqual(corr.event_ids, (self.ev_auth_alice.event_id, self.ev_sudo_alice.event_id))
        self.assertIn("alice", corr.description)
        self.assertEqual(corr.time_delta_seconds, 120.0)

    # 16. Wrong authentication/privilege order
    def test_16_wrong_auth_privilege_order(self):
        """16. Verify privilege activity occurring before authentication does NOT match."""
        # Swap order: sudo happens at 10:00, auth happens at 10:02
        ev_early_sudo = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="early sudo",
            timestamp=self.dt_base,
            attributes={"username": "alice"},
        )
        ev_late_auth = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="late auth",
            timestamp=self.dt_plus_120,
            attributes={"username": "alice"},
        )
        engine = CorrelationEngine(
            relationship_types=[CorrelationType.AUTHENTICATION_PRIVILEGE]
        )
        result = engine.correlate([ev_early_sudo, ev_late_auth])
        self.assertEqual(len(result), 0)

    # 17. Wrong user (auth/privilege mismatch)
    def test_17_wrong_user_auth_privilege(self):
        """17. Verify auth by alice followed by sudo by bob does NOT match AUTHENTICATION_PRIVILEGE."""
        ev_sudo_bob = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="bob sudo",
            timestamp=self.dt_plus_120,
            attributes={"username": "bob"},
        )
        engine = CorrelationEngine(
            relationship_types=[CorrelationType.AUTHENTICATION_PRIVILEGE]
        )
        result = engine.correlate([self.ev_auth_alice, ev_sudo_bob])
        self.assertEqual(len(result), 0)

    # 18. Outside time window (auth/privilege)
    def test_18_outside_time_window_auth_privilege(self):
        """18. Verify sudo occurring outside the configured window does not match."""
        ev_late_sudo = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="late sudo",
            timestamp=self.dt_plus_600,  # 600s later (window is 300s)
            attributes={"username": "alice"},
        )
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[CorrelationType.AUTHENTICATION_PRIVILEGE],
        )
        result = engine.correlate([self.ev_auth_alice, ev_late_sudo])
        self.assertEqual(len(result), 0)

    # 19. Missing attributes handling
    def test_19_missing_attributes_handling(self):
        """19. Verify events lacking specific attributes do not match respective types."""
        e1 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog",
            description="Event without user or source",
            timestamp=self.dt_base,
        )
        e2 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog",
            description="Second event without attributes",
            timestamp=self.dt_plus_60,
        )
        self.assertIsNone(extract_user_identity(e1))
        self.assertIsNone(extract_source_identity(e1))
        self.assertIsNone(extract_session_identity(e1))

        engine = CorrelationEngine(
            relationship_types=[
                CorrelationType.SAME_USER,
                CorrelationType.SAME_SOURCE,
                CorrelationType.SAME_SESSION,
            ]
        )
        result = engine.correlate([e1, e2])
        self.assertEqual(len(result), 0)

    # 20. Missing timestamps handling (no fabrication)
    def test_20_missing_timestamps_handling(self):
        """20. Verify events with missing timestamps do not match TEMPORAL (never fabricate timestamps)."""
        e1_no_ts = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog",
            description="Log without timestamp",
            timestamp=None,
        )
        e2_no_ts = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog",
            description="Second log without timestamp",
            timestamp=None,
        )
        delta = compute_timestamp_delta(e1_no_ts.timestamp, e2_no_ts.timestamp)
        self.assertIsNone(delta)

        engine = CorrelationEngine(relationship_types=[CorrelationType.TEMPORAL])
        result = engine.correlate([e1_no_ts, e2_no_ts])
        self.assertEqual(len(result), 0)

    # 21. Aware timestamp behavior
    def test_21_aware_timestamp_behavior(self):
        """21. Verify timezone-aware timestamps compare accurately across offsets."""
        # 10:00 UTC == 15:30 IST (+05:30)
        from datetime import timezone as dt_tz, timedelta
        ist = dt_tz(timedelta(hours=5, minutes=30))
        dt_ist = datetime(2026, 4, 1, 15, 30, 0, tzinfo=ist)

        delta = compute_timestamp_delta(self.dt_base, dt_ist)
        self.assertEqual(delta, 0.0)

    # 22. Naive timestamp behavior
    def test_22_naive_timestamp_behavior(self):
        """22. Verify timezone-naive timestamps compare accurately without guessing timezone."""
        dt_n1 = datetime(2026, 4, 1, 10, 0, 0)
        dt_n2 = datetime(2026, 4, 1, 10, 2, 0)
        delta = compute_timestamp_delta(dt_n1, dt_n2)
        self.assertEqual(delta, 120.0)

    # 23. Aware/naive mismatch handling (no silent conversion)
    def test_23_aware_naive_mismatch_handling(self):
        """23. Verify awareness mismatch returns None and prevents silent false matches."""
        dt_naive = datetime(2026, 4, 1, 10, 1, 0)
        delta = compute_timestamp_delta(self.dt_base, dt_naive)
        self.assertIsNone(delta)

        ev_naive = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="syslog",
            description="Naive event",
            timestamp=dt_naive,
        )
        engine = CorrelationEngine(relationship_types=[CorrelationType.TEMPORAL])
        result = engine.correlate([self.ev_auth_alice, ev_naive])
        self.assertEqual(len(result), 0)

    # 24. Duplicate prevention
    def test_24_duplicate_prevention(self):
        """24. Verify engine never produces duplicate correlations of same type for same pair."""
        engine = CorrelationEngine(
            relationship_types=[CorrelationType.SAME_USER]
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)

    # 25. Multiple legitimate relationship types between same events
    def test_25_multiple_legitimate_relationship_types(self):
        """25. Verify multiple distinct relationship types between same pair are all discovered."""
        engine = CorrelationEngine(
            time_window_seconds=300.0,
            relationship_types=[
                CorrelationType.TEMPORAL,
                CorrelationType.SAME_USER,
                CorrelationType.SAME_SOURCE,
                CorrelationType.SAME_SESSION,
                CorrelationType.AUTHENTICATION_PRIVILEGE,
            ],
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        # ev_auth_alice and ev_sudo_alice satisfy all 5 requested relationship types!
        types_discovered = {c.relationship_type for c in result}
        self.assertEqual(
            types_discovered,
            {
                CorrelationType.TEMPORAL,
                CorrelationType.SAME_USER,
                CorrelationType.SAME_SOURCE,
                CorrelationType.SAME_SESSION,
                CorrelationType.AUTHENTICATION_PRIVILEGE,
            },
        )
        self.assertEqual(len(result), 5)

    # 26. Provenance preservation
    def test_26_provenance_preservation(self):
        """26. Verify discovered correlations faithfully retain timeline IDs and source IDs."""
        engine = CorrelationEngine(
            relationship_types=[CorrelationType.AUTHENTICATION_PRIVILEGE]
        )
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(result), 1)
        corr = result[0]
        self.assertIn(self.ev_auth_alice.event_id, corr.event_ids)
        self.assertIn(self.ev_sudo_alice.event_id, corr.event_ids)
        self.assertEqual(corr.source_artifact_ids, ("ART-AUTH-LOG",))
        self.assertEqual(corr.source_event_ids, ("AUTH-001", "AUTH-002"))

    # 27. Input immutability
    def test_27_input_immutability(self):
        """27. Verify input TimelineEvents are untouched after correlation."""
        original_dict_1 = self.ev_auth_alice.to_dict()
        original_dict_2 = self.ev_sudo_alice.to_dict()

        engine = CorrelationEngine()
        engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])

        self.assertEqual(self.ev_auth_alice.to_dict(), original_dict_1)
        self.assertEqual(self.ev_sudo_alice.to_dict(), original_dict_2)

    # 28. Output immutability
    def test_28_output_immutability(self):
        """28. Verify CorrelationCollection and Correlation instances are immutable."""
        engine = CorrelationEngine()
        result = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertGreater(len(result), 0)

        with self.assertRaises(FrozenInstanceError):
            result.total_correlations = 999  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            result[0].description = "altered"  # type: ignore

    # 29. Deterministic repeated execution
    def test_29_deterministic_repeated_execution(self):
        """29. Verify running engine twice on identical input produces byte-identical output."""
        engine = CorrelationEngine()
        res1 = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice, self.ev_file_shadow])
        res2 = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice, self.ev_file_shadow])

        self.assertEqual(res1.to_dict(), res2.to_dict())
        self.assertEqual(len(res1), len(res2))
        for c1, c2 in zip(res1, res2):
            self.assertEqual(c1.correlation_id, c2.correlation_id)
            self.assertEqual(c1.relationship_type, c2.relationship_type)

    # 30. Stable ordering
    def test_30_stable_ordering(self):
        """30. Verify output correlations maintain stable chronological and category ordering."""
        engine = CorrelationEngine(time_window_seconds=300.0)
        res = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice, self.ev_file_shadow])
        corrs = list(res)
        # Check ordering is deterministic and non-empty
        self.assertGreater(len(corrs), 0)
        # Verify ordering is identical across separate runs
        res_check = engine.correlate([self.ev_auth_alice, self.ev_sudo_alice, self.ev_file_shadow])
        self.assertEqual([c.correlation_id for c in corrs], [c.correlation_id for c in res_check])

    # 31. Serialization compatibility
    def test_31_serialization_compatibility(self):
        """31. Verify correlation results serialize cleanly to JSON."""
        result = correlate_events([self.ev_auth_alice, self.ev_sudo_alice])
        d = result.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["summary"]["total_correlations"], len(result))

    # 32. V4.1 regression
    def test_32_v4_1_regression(self):
        """32. Verify direct V4.1 Correlation models and factory continue working as expected."""
        corr = Correlation(
            relationship_type=CorrelationType.TEMPORAL,
            event_ids=[self.ev_auth_alice.event_id, self.ev_sudo_alice.event_id],
            description="Direct v4.1 creation",
            time_delta_seconds=120.0,
        )
        self.assertTrue(corr.correlation_id.startswith("CORR-"))
        self.assertEqual(corr.relationship_type, CorrelationType.TEMPORAL)

    # 33. V3 regression
    def test_33_v3_regression(self):
        """33. Verify ReconstructedTimeline can be directly passed to CorrelationEngine."""
        timeline = ReconstructedTimeline(
            events=(self.ev_auth_alice, self.ev_sudo_alice),
            total_events=2,
            duplicates_removed=0,
            timestamp_class_counts=(("aware", 2),),
            category_counts=(("authentication", 2),),
        )
        result = correlate_events(timeline)
        self.assertGreater(len(result), 0)
        self.assertIsInstance(result, CorrelationCollection)


if __name__ == "__main__":
    unittest.main()
