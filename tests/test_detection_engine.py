"""
Focused Unit Test Suite for ForensiX V4.4 Detection Engine.

Covers the 39 mandatory verification scenarios:
1. Empty event set
2. Empty rule set
3. One event
4. Simple matching condition
5. Simple non-match
6. Every supported condition operator
7. Missing field
8. None value
9. Empty string
10. Zero value
11. False value
12. Multiple conditions
13. Required event type
14. Required category
15. Required relationship
16. Matching correlation
17. Missing required correlation
18. Time-window match
19. Time-window boundary
20. Outside time window
21. Aware timestamps
22. Naive timestamps
23. Aware/naive mismatch
24. Missing timestamp
25. Multiple legitimate matches
26. Duplicate prevention
27. Multiple rules
28. Deterministic DetectionResult IDs
29. Deterministic output ordering
30. DetectionResult immutability
31. Input immutability
32. Provenance preservation
33. Factual explanation
34. Speculative language protection
35. Serialization / round-trip
36. V4.3 regression
37. V4.2 regression
38. V4.1 regression
39. V3 regression
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, timedelta
import json
import unittest

from forensix.correlation_engine import (
    CorrelationConfig,
    CorrelationEngine,
    correlate_events,
)
from forensix.correlation_models import (
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
    create_correlation,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    compute_deterministic_detection_id,
    detection_sort_key,
    evaluate_condition_operator,
    evaluate_rule,
    evaluate_rules,
    resolve_field_value,
    _MISSING,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    Rule,
    RuleCollection,
    RuleCondition,
    compute_deterministic_rule_id,
    create_rule,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import (
    ReconstructedTimeline,
    reconstruct_timeline,
)


class TestDetectionEngine(unittest.TestCase):
    """Rigorous unit tests for ForensiX V4.4 Detection Engine."""

    def setUp(self) -> None:
        self.dt_base = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
        self.dt_plus_60 = datetime(2026, 4, 1, 10, 1, 0, tzinfo=timezone.utc)
        self.dt_plus_120 = datetime(2026, 4, 1, 10, 2, 0, tzinfo=timezone.utc)
        self.dt_plus_300 = datetime(2026, 4, 1, 10, 5, 0, tzinfo=timezone.utc)
        self.dt_plus_600 = datetime(2026, 4, 1, 10, 10, 0, tzinfo=timezone.utc)

        # Baseline events
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
                "login_count": 1,
                "is_admin": False,
                "null_field": None,
                "empty_field": "",
                "zero_field": 0,
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
                "target_user": "root",
            },
        )

        self.ev_file_shadow = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="File accessed: /etc/shadow",
            timestamp=self.dt_plus_120,
            source_path="/etc/shadow",
            source_artifact_id="ART-SHADOW",
            source_event_id="FS-001",
            attributes={"path": "/etc/shadow", "username": "alice"},
        )

        self.ev_bob = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted password for bob from 10.0.0.99",
            timestamp=self.dt_plus_600,
            source_path="/var/log/auth.log",
            source_line=50,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-003",
            attributes={"username": "bob", "source_ip": "10.0.0.99"},
        )

        # Baseline single-event rule
        self.rule_single_auth = create_rule(
            name="SSH Authentication by Alice",
            description="Detects successful SSH logins by alice.",
            detection_description="A successful SSH login by user alice was observed.",
            required_categories=[TimelineCategory.AUTHENTICATION],
            required_event_types=["ssh_login_success"],
            conditions=[
                RuleCondition(
                    field="username",
                    operator=ConditionOperator.EQUALS,
                    value="alice",
                )
            ],
        )

        # Baseline correlation-aware rule
        self.rule_auth_priv = create_rule(
            name="SSH Login Followed by Sudo",
            description="Correlated SSH authentication followed by privileged sudo command.",
            detection_description="An SSH login followed by privileged sudo execution was observed for the same identity.",
            required_categories=[TimelineCategory.AUTHENTICATION],
            required_relationships=[RelationshipType.AUTHENTICATION_PRIVILEGE],
            time_window_seconds=300.0,
            conditions=[
                RuleCondition(
                    field="username",
                    operator=ConditionOperator.EQUALS,
                    value="alice",
                )
            ],
        )

    # 1. Empty event set
    def test_01_empty_event_set(self):
        """1. Verify empty event set produces empty DetectionResultCollection."""
        engine = DetectionEngine(rules=[self.rule_single_auth])
        results = engine.evaluate(timeline=[])
        self.assertIsInstance(results, DetectionResultCollection)
        self.assertEqual(len(results), 0)
        self.assertEqual(results.total_detections, 0)

    # 2. Empty rule set
    def test_02_empty_rule_set(self):
        """2. Verify empty rule set produces empty DetectionResultCollection."""
        engine = DetectionEngine(rules=[])
        results = engine.evaluate(timeline=[self.ev_auth_alice])
        self.assertEqual(len(results), 0)

    # 3. One event
    def test_03_one_event_evaluation(self):
        """3. Verify evaluation against a single timeline event."""
        engine = DetectionEngine(rules=[self.rule_single_auth])
        results = engine.evaluate(timeline=[self.ev_auth_alice])
        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertEqual(det.rule_id, self.rule_single_auth.rule_id)
        self.assertEqual(det.matched_event_ids, (self.ev_auth_alice.event_id,))
        self.assertTrue(det.matched)

    # 4. Simple matching condition
    def test_04_simple_matching_condition(self):
        """4. Verify simple condition matching behaves correctly."""
        results = evaluate_rule(self.rule_single_auth, [self.ev_auth_alice])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].explanation, self.rule_single_auth.detection_description)

    # 5. Simple non-match
    def test_05_simple_non_match(self):
        """5. Verify non-matching event produces zero detections."""
        results = evaluate_rule(self.rule_single_auth, [self.ev_bob])
        self.assertEqual(len(results), 0)

    # 6. Every supported condition operator
    def test_06_every_supported_condition_operator(self):
        """6. Test all 9 ConditionOperators individually."""
        # EQUALS
        self.assertTrue(evaluate_condition_operator("test", ConditionOperator.EQUALS, "test"))
        self.assertFalse(evaluate_condition_operator("test", ConditionOperator.EQUALS, "other"))
        self.assertTrue(evaluate_condition_operator(10, ConditionOperator.EQUALS, 10.0))
        self.assertFalse(evaluate_condition_operator(True, ConditionOperator.EQUALS, 1))  # strict bool check

        # NOT_EQUALS
        self.assertTrue(evaluate_condition_operator("test", ConditionOperator.NOT_EQUALS, "other"))
        self.assertFalse(evaluate_condition_operator("test", ConditionOperator.NOT_EQUALS, "test"))
        self.assertTrue(evaluate_condition_operator(True, ConditionOperator.NOT_EQUALS, 1))

        # CONTAINS
        self.assertTrue(evaluate_condition_operator("hello world", ConditionOperator.CONTAINS, "world"))
        self.assertFalse(evaluate_condition_operator("hello world", ConditionOperator.CONTAINS, "xyz"))
        self.assertTrue(evaluate_condition_operator(["a", "b"], ConditionOperator.CONTAINS, "a"))
        self.assertFalse(evaluate_condition_operator(["a", "b"], ConditionOperator.CONTAINS, "c"))
        self.assertFalse(evaluate_condition_operator(None, ConditionOperator.CONTAINS, "a"))

        # IN
        self.assertTrue(evaluate_condition_operator("a", ConditionOperator.IN, ["a", "b", "c"]))
        self.assertFalse(evaluate_condition_operator("d", ConditionOperator.IN, ["a", "b", "c"]))
        self.assertTrue(evaluate_condition_operator("cat", ConditionOperator.IN, "catalog"))
        self.assertFalse(evaluate_condition_operator(None, ConditionOperator.IN, ["a"]))

        # GREATER_THAN
        self.assertTrue(evaluate_condition_operator(15, ConditionOperator.GREATER_THAN, 10))
        self.assertFalse(evaluate_condition_operator(10, ConditionOperator.GREATER_THAN, 10))
        self.assertFalse(evaluate_condition_operator(5, ConditionOperator.GREATER_THAN, 10))
        self.assertFalse(evaluate_condition_operator(True, ConditionOperator.GREATER_THAN, 0))

        # GREATER_EQUAL
        self.assertTrue(evaluate_condition_operator(10, ConditionOperator.GREATER_EQUAL, 10))
        self.assertTrue(evaluate_condition_operator(15, ConditionOperator.GREATER_EQUAL, 10))
        self.assertFalse(evaluate_condition_operator(5, ConditionOperator.GREATER_EQUAL, 10))

        # LESS_THAN
        self.assertTrue(evaluate_condition_operator(5, ConditionOperator.LESS_THAN, 10))
        self.assertFalse(evaluate_condition_operator(10, ConditionOperator.LESS_THAN, 10))

        # LESS_EQUAL
        self.assertTrue(evaluate_condition_operator(10, ConditionOperator.LESS_EQUAL, 10))
        self.assertTrue(evaluate_condition_operator(5, ConditionOperator.LESS_EQUAL, 10))
        self.assertFalse(evaluate_condition_operator(15, ConditionOperator.LESS_EQUAL, 10))

        # EXISTS
        self.assertTrue(evaluate_condition_operator("value", ConditionOperator.EXISTS, True))
        self.assertTrue(evaluate_condition_operator(0, ConditionOperator.EXISTS, True))
        self.assertTrue(evaluate_condition_operator(False, ConditionOperator.EXISTS, True))
        self.assertTrue(evaluate_condition_operator("", ConditionOperator.EXISTS, True))
        self.assertFalse(evaluate_condition_operator(None, ConditionOperator.EXISTS, True))
        self.assertFalse(evaluate_condition_operator(_MISSING, ConditionOperator.EXISTS, True))
        # EXISTS = False (checking absence)
        self.assertTrue(evaluate_condition_operator(None, ConditionOperator.EXISTS, False))
        self.assertTrue(evaluate_condition_operator(_MISSING, ConditionOperator.EXISTS, False))
        self.assertFalse(evaluate_condition_operator("value", ConditionOperator.EXISTS, False))

    # 7. Missing field
    def test_07_missing_field(self):
        """7. Verify missing field does not match and returns _MISSING."""
        val = resolve_field_value(self.ev_auth_alice, "nonexistent_field")
        self.assertIs(val, _MISSING)
        self.assertFalse(evaluate_condition_operator(val, ConditionOperator.EQUALS, "something"))

        # Rule requiring non-existent field
        rule_missing = create_rule(
            name="Requires Missing Field",
            description="Testing missing field handling.",
            detection_description="Observed missing field.",
            conditions=[
                RuleCondition(
                    field="nonexistent_field",
                    operator=ConditionOperator.EQUALS,
                    value="something",
                )
            ],
        )
        results = evaluate_rule(rule_missing, [self.ev_auth_alice])
        self.assertEqual(len(results), 0)

    # 8. None value
    def test_08_none_value_handling(self):
        """8. Verify explicit None attribute value is preserved and distinct from missing."""
        ev_none = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="login with None source_event_id",
            timestamp=self.dt_base,
            source_event_id=None,
            attributes={"username": "alice"},
        )
        val = resolve_field_value(ev_none, "source_event_id")
        self.assertIsNone(val)
        self.assertIsNot(val, _MISSING)

        rule_null = create_rule(
            name="Check Null Field",
            description="Checks if source_event_id exists.",
            detection_description="Checked null field.",
            conditions=[
                RuleCondition(
                    field="source_event_id",
                    operator=ConditionOperator.EXISTS,
                    value=False,
                )
            ],
        )
        results = evaluate_rule(rule_null, [ev_none])
        self.assertEqual(len(results), 1)

    # 9. Empty string
    def test_09_empty_string_handling(self):
        """9. Verify empty string is preserved and matches EQUALS ''."""
        val = resolve_field_value(self.ev_auth_alice, "empty_field")
        self.assertEqual(val, "")

        rule_empty = create_rule(
            name="Check Empty Field",
            description="Checks empty field.",
            detection_description="Checked empty field.",
            conditions=[
                RuleCondition(
                    field="empty_field",
                    operator=ConditionOperator.EQUALS,
                    value="",
                )
            ],
        )
        results = evaluate_rule(rule_empty, [self.ev_auth_alice])
        self.assertEqual(len(results), 1)

    # 10. Zero value
    def test_10_zero_value_handling(self):
        """10. Verify numeric 0 is preserved and not treated as falsy missing data."""
        val = resolve_field_value(self.ev_auth_alice, "zero_field")
        self.assertEqual(val, 0)
        self.assertIsNot(val, False)

        rule_zero = create_rule(
            name="Check Zero Field",
            description="Checks zero field.",
            detection_description="Checked zero field.",
            conditions=[
                RuleCondition(
                    field="zero_field",
                    operator=ConditionOperator.EQUALS,
                    value=0,
                )
            ],
        )
        results = evaluate_rule(rule_zero, [self.ev_auth_alice])
        self.assertEqual(len(results), 1)

    # 11. False value
    def test_11_false_value_handling(self):
        """11. Verify boolean False is preserved and does not match numeric 0 in EQUALS."""
        val = resolve_field_value(self.ev_auth_alice, "is_admin")
        self.assertIs(val, False)

        rule_false = create_rule(
            name="Check Admin False",
            description="Checks non-admin users.",
            detection_description="Observed non-admin login.",
            conditions=[
                RuleCondition(
                    field="is_admin",
                    operator=ConditionOperator.EQUALS,
                    value=False,
                )
            ],
        )
        results = evaluate_rule(rule_false, [self.ev_auth_alice])
        self.assertEqual(len(results), 1)

    # 12. Multiple conditions
    def test_12_multiple_conditions(self):
        """12. Verify multiple conditions are evaluated with logical AND."""
        rule_multi = create_rule(
            name="Multi Condition Alice",
            description="Checks username and login count.",
            detection_description="Observed multi-condition match for alice.",
            conditions=[
                RuleCondition(
                    field="username",
                    operator=ConditionOperator.EQUALS,
                    value="alice",
                ),
                RuleCondition(
                    field="login_count",
                    operator=ConditionOperator.GREATER_EQUAL,
                    value=1,
                ),
                RuleCondition(
                    field="is_admin",
                    operator=ConditionOperator.EQUALS,
                    value=False,
                ),
            ],
        )
        results = evaluate_rule(rule_multi, [self.ev_auth_alice])
        self.assertEqual(len(results), 1)

        # Fails if one condition is not satisfied
        rule_multi_fail = create_rule(
            name="Multi Condition Alice Fail",
            description="Checks username and login count.",
            detection_description="Will not match.",
            conditions=[
                RuleCondition(
                    field="username",
                    operator=ConditionOperator.EQUALS,
                    value="alice",
                ),
                RuleCondition(
                    field="login_count",
                    operator=ConditionOperator.GREATER_THAN,
                    value=10,  # Fails
                ),
            ],
        )
        results_fail = evaluate_rule(rule_multi_fail, [self.ev_auth_alice])
        self.assertEqual(len(results_fail), 0)

    # 13. Required event type
    def test_13_required_event_type(self):
        """13. Verify filtering by required_event_types."""
        rule = create_rule(
            name="Sudo Command Only",
            description="Requires sudo_command event type.",
            detection_description="Observed sudo command.",
            required_event_types=["sudo_command"],
        )
        # Auth event should not match
        res1 = evaluate_rule(rule, [self.ev_auth_alice])
        self.assertEqual(len(res1), 0)
        # Sudo event matches
        res2 = evaluate_rule(rule, [self.ev_sudo_alice])
        self.assertEqual(len(res2), 1)

    # 14. Required category
    def test_14_required_category(self):
        """14. Verify filtering by required_categories."""
        rule = create_rule(
            name="Filesystem Only",
            description="Requires filesystem category.",
            detection_description="Observed filesystem event.",
            required_categories=[TimelineCategory.FILESYSTEM],
        )
        # Auth events fail category check
        self.assertEqual(len(evaluate_rule(rule, [self.ev_auth_alice])), 0)
        # File event matches
        self.assertEqual(len(evaluate_rule(rule, [self.ev_file_shadow])), 1)

    # 15. Required relationship
    def test_15_required_relationship(self):
        """15. Verify required_relationships requires matching correlation."""
        # Correlation engine produces correlations including AUTHENTICATION_PRIVILEGE
        c_engine = CorrelationEngine()
        corrs = c_engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        auth_priv = [c for c in corrs if c.relationship_type == RelationshipType.AUTHENTICATION_PRIVILEGE]
        self.assertEqual(len(auth_priv), 1)

        results = evaluate_rule(
            self.rule_auth_priv,
            timeline=[self.ev_auth_alice, self.ev_sudo_alice],
            correlations=corrs,
        )
        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertEqual(det.matched_correlation_ids, (auth_priv[0].correlation_id,))
        self.assertEqual(set(det.matched_event_ids), {self.ev_auth_alice.event_id, self.ev_sudo_alice.event_id})

    # 16. Matching correlation
    def test_16_matching_correlation(self):
        """16. Verify matching correlation attributes and provenance propagation."""
        c_engine = CorrelationEngine()
        corrs = c_engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        results = evaluate_rule(
            self.rule_auth_priv,
            timeline=[self.ev_auth_alice, self.ev_sudo_alice],
            correlations=corrs,
        )
        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertIn("ART-AUTH-LOG", det.matched_source_artifact_ids)
        self.assertIn("AUTH-001", det.matched_source_event_ids)
        self.assertIn("AUTH-002", det.matched_source_event_ids)

    # 17. Missing required correlation
    def test_17_missing_required_correlation(self):
        """17. Verify rule requiring relationship produces 0 detections if correlations missing."""
        results = evaluate_rule(
            self.rule_auth_priv,
            timeline=[self.ev_auth_alice, self.ev_sudo_alice],
            correlations=[],  # No correlations provided
        )
        self.assertEqual(len(results), 0)

    # 18. Time-window match
    def test_18_time_window_match(self):
        """18. Verify events within configured time window match successfully."""
        # 120s delta within 300s window
        seq_rule = create_rule(
            name="SSH Auth then Sudo Sequence",
            description="Detects SSH auth followed by sudo within 300s.",
            detection_description="SSH authentication followed by sudo within window.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=300.0,
        )
        results = evaluate_rule(seq_rule, [self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].time_delta_seconds, 120.0)

    # 19. Time-window boundary
    def test_19_time_window_boundary(self):
        """19. Verify exact time window boundary is inclusive (delta <= window_seconds)."""
        seq_rule = create_rule(
            name="Exact Boundary Rule",
            description="Window equals exactly 120s.",
            detection_description="Boundary matched.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=120.0,
        )
        results = evaluate_rule(seq_rule, [self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].time_delta_seconds, 120.0)

    # 20. Outside time window
    def test_20_outside_time_window(self):
        """20. Verify events exceeding time window do not match."""
        seq_rule = create_rule(
            name="Narrow Window Rule",
            description="Window of 60s is smaller than 120s delta.",
            detection_description="Should not match.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=60.0,
        )
        results = evaluate_rule(seq_rule, [self.ev_auth_alice, self.ev_sudo_alice])
        self.assertEqual(len(results), 0)

    # 21. Aware timestamps
    def test_21_aware_timestamps(self):
        """21. Verify timezone-aware timestamps are compared accurately across offsets."""
        dt_est = datetime(2026, 4, 1, 5, 2, 0, tzinfo=timezone(timedelta(hours=-5)))  # Equivalent to 10:02 UTC
        ev_aware = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="sudo command in EST",
            timestamp=dt_est,
            attributes={"username": "alice"},
        )
        seq_rule = create_rule(
            name="Aware Sequence",
            description="Aware timestamps across offsets.",
            detection_description="Observed aware sequence.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=300.0,
        )
        results = evaluate_rule(seq_rule, [self.ev_auth_alice, ev_aware])
        self.assertEqual(len(results), 1)
        self.assertAlmostEqual(results[0].time_delta_seconds, 120.0, places=2)

    # 22. Naive timestamps
    def test_22_naive_timestamps(self):
        """22. Verify naive timestamps are compared directly."""
        dt_naive_1 = datetime(2026, 4, 1, 10, 0, 0)
        dt_naive_2 = datetime(2026, 4, 1, 10, 2, 0)
        ev_n1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="naive login",
            timestamp=dt_naive_1,
            attributes={"username": "alice"},
        )
        ev_n2 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="naive sudo",
            timestamp=dt_naive_2,
            attributes={"username": "alice"},
        )
        seq_rule = create_rule(
            name="Naive Sequence",
            description="Naive sequence test.",
            detection_description="Observed naive sequence.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=300.0,
        )
        results = evaluate_rule(seq_rule, [ev_n1, ev_n2])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].time_delta_seconds, 120.0)

    # 23. Aware/naive mismatch
    def test_23_aware_naive_mismatch(self):
        """23. Verify aware and naive timestamps mismatch does not silently assume a timezone."""
        dt_naive = datetime(2026, 4, 1, 10, 2, 0)
        ev_naive = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="naive sudo",
            timestamp=dt_naive,
            attributes={"username": "alice"},
        )
        seq_rule = create_rule(
            name="Mismatch Sequence",
            description="Aware vs naive mismatch.",
            detection_description="Should fail delta comparison.",
            required_event_types=["ssh_login_success", "sudo_command"],
            time_window_seconds=300.0,
        )
        results = evaluate_rule(seq_rule, [self.ev_auth_alice, ev_naive])
        # Delta cannot be computed reliably across aware/naive mismatch -> rejected
        self.assertEqual(len(results), 0)

    # 24. Missing timestamp
    def test_24_missing_timestamp(self):
        """24. Verify missing timestamps are handled cleanly without fabricating timestamps."""
        ev_no_ts = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="login without timestamp",
            timestamp=None,
            attributes={"username": "alice"},
        )
        results = evaluate_rule(self.rule_single_auth, [ev_no_ts])
        self.assertEqual(len(results), 1)
        det = results[0]
        self.assertIsNone(det.start_timestamp)
        self.assertIsNone(det.end_timestamp)
        self.assertIsNone(det.time_delta_seconds)

    # 25. Multiple legitimate matches
    def test_25_multiple_legitimate_matches(self):
        """25. Verify independent legitimate matches are all captured."""
        ev_auth_alice_2 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Second login by alice",
            timestamp=self.dt_plus_300,
            attributes={"username": "alice"},
        )
        results = evaluate_rule(self.rule_single_auth, [self.ev_auth_alice, ev_auth_alice_2])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].matched_event_ids, (self.ev_auth_alice.event_id,))
        self.assertEqual(results[1].matched_event_ids, (ev_auth_alice_2.event_id,))

    # 26. Duplicate prevention
    def test_26_duplicate_prevention(self):
        """26. Verify duplicate matches on the same event and rule are prevented."""
        engine = DetectionEngine(rules=[self.rule_single_auth])
        # Pass identical event twice
        results = engine.evaluate(timeline=[self.ev_auth_alice, self.ev_auth_alice])
        self.assertEqual(len(results), 1)

    # 27. Multiple rules
    def test_27_multiple_rules(self):
        """27. Verify multiple distinct rules can match the same or different events."""
        rule_any_ssh = create_rule(
            name="Any SSH Login",
            description="Matches any ssh_login_success.",
            detection_description="An SSH login occurred.",
            required_event_types=["ssh_login_success"],
        )
        engine = DetectionEngine(rules=[self.rule_single_auth, rule_any_ssh])
        results = engine.evaluate(timeline=[self.ev_auth_alice])
        # Both rules match ev_auth_alice
        self.assertEqual(len(results), 2)
        rule_ids = {r.rule_id for r in results}
        self.assertEqual(rule_ids, {self.rule_single_auth.rule_id, rule_any_ssh.rule_id})

    # 28. Deterministic DetectionResult IDs
    def test_28_deterministic_detection_ids(self):
        """28. Verify deterministic DetectionResult IDs across multiple engine executions."""
        engine1 = DetectionEngine(rules=[self.rule_single_auth])
        engine2 = DetectionEngine(rules=[self.rule_single_auth])

        res1 = engine1.evaluate(timeline=[self.ev_auth_alice])
        res2 = engine2.evaluate(timeline=[self.ev_auth_alice])

        self.assertEqual(res1[0].detection_id, res2[0].detection_id)
        self.assertTrue(res1[0].detection_id.startswith("DET-"))

    # 29. Deterministic output ordering
    def test_29_deterministic_output_ordering(self):
        """29. Verify output detections are ordered deterministically by timestamp, rule, event ID."""
        rule_any = create_rule(
            name="Any Auth",
            description="Matches all auth events.",
            detection_description="Auth event observed.",
            required_categories=[TimelineCategory.AUTHENTICATION],
        )
        timeline = [self.ev_bob, self.ev_sudo_alice, self.ev_auth_alice]
        results = evaluate_rule(rule_any, timeline)

        self.assertEqual(len(results), 3)
        # Should be sorted chronologically: ev_auth_alice (10:00) < ev_sudo_alice (10:02) < ev_bob (10:10)
        self.assertEqual(results[0].matched_event_ids, (self.ev_auth_alice.event_id,))
        self.assertEqual(results[1].matched_event_ids, (self.ev_sudo_alice.event_id,))
        self.assertEqual(results[2].matched_event_ids, (self.ev_bob.event_id,))

    # 30. DetectionResult immutability
    def test_30_detection_result_immutability(self):
        """30. Verify DetectionResult is deeply immutable and rejects field assignment."""
        results = evaluate_rule(self.rule_single_auth, [self.ev_auth_alice])
        det = results[0]

        with self.assertRaises(FrozenInstanceError):
            det.matched = False  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            det.explanation = "New explanation"  # type: ignore

    # 31. Input immutability
    def test_31_input_immutability(self):
        """31. Verify evaluation does not mutate timeline events, correlations, or rules."""
        orig_ev_dict = self.ev_auth_alice.to_dict()
        orig_rule_dict = self.rule_single_auth.to_dict()

        c_engine = CorrelationEngine()
        corrs = c_engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        orig_corr_dict = corrs[0].to_dict()

        # Execute evaluation
        evaluate_rule(self.rule_auth_priv, [self.ev_auth_alice, self.ev_sudo_alice], corrs)

        # Assert no mutations occurred
        self.assertEqual(self.ev_auth_alice.to_dict(), orig_ev_dict)
        self.assertEqual(self.rule_single_auth.to_dict(), orig_rule_dict)
        self.assertEqual(corrs[0].to_dict(), orig_corr_dict)

    # 32. Provenance preservation
    def test_32_provenance_preservation(self):
        """32. Verify comprehensive provenance attributes are stored on DetectionResult."""
        c_engine = CorrelationEngine()
        corrs = c_engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        results = evaluate_rule(
            self.rule_auth_priv,
            [self.ev_auth_alice, self.ev_sudo_alice],
            correlations=corrs,
        )
        det = results[0]
        self.assertEqual(det.rule_id, self.rule_auth_priv.rule_id)
        self.assertEqual(det.rule_name, self.rule_auth_priv.name)
        self.assertEqual(det.matched_correlation_ids, (corrs[0].correlation_id,))
        self.assertIn(self.ev_auth_alice.event_id, det.matched_event_ids)
        self.assertIn(self.ev_sudo_alice.event_id, det.matched_event_ids)
        self.assertIn("AUTH-001", det.matched_source_event_ids)
        self.assertIn("AUTH-002", det.matched_source_event_ids)
        self.assertIn("ART-AUTH-LOG", det.matched_source_artifact_ids)

    # 33. Factual explanation
    def test_33_factual_explanation(self):
        """33. Verify DetectionResult contains factual explanation."""
        results = evaluate_rule(self.rule_single_auth, [self.ev_auth_alice])
        self.assertEqual(results[0].explanation, "A successful SSH login by user alice was observed.")

    # 34. Speculative language protection
    def test_34_speculative_language_protection(self):
        """34. Verify speculative phrasing in explanations is rejected."""
        with self.assertRaises(ValueError) as ctx:
            DetectionResult(
                rule_id="RULE-01",
                rule_name="Compromise Test",
                matched_event_ids=["EV-01"],
                explanation="The system compromised completely by malicious threat actor.",
            )
        self.assertIn("disallowed", str(ctx.exception).lower())

    # 35. Serialization / round-trip
    def test_35_serialization_round_trip(self):
        """35. Verify DetectionResult and Collection to_dict and from_dict roundtrip."""
        results = evaluate_rule(self.rule_single_auth, [self.ev_auth_alice])
        det = results[0]

        d = det.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)

        reconstructed = DetectionResult.from_dict(parsed)
        self.assertEqual(reconstructed.detection_id, det.detection_id)
        self.assertEqual(reconstructed.rule_id, det.rule_id)
        self.assertEqual(reconstructed.matched_event_ids, det.matched_event_ids)
        self.assertEqual(reconstructed.start_timestamp, det.start_timestamp)

        # Collection to_dict
        coll_dict = results.to_dict()
        self.assertIn("summary", coll_dict)
        self.assertIn("results", coll_dict)
        self.assertEqual(coll_dict["summary"]["total_detections"], 1)

    # 36. V4.3 regression
    def test_36_v4_3_rule_models_regression(self):
        """36. Verify full compatibility with V4.3 rule models."""
        rule = create_rule(
            name="V4.3 Regression Rule",
            description="Testing rule model regression.",
            detection_description="Regression passed.",
            conditions=[
                RuleCondition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="ssh_login_success",
                )
            ],
        )
        self.assertIsInstance(rule, DetectionRule)
        self.assertTrue(rule.rule_id.startswith("RULE-"))

    # 37. V4.2 regression
    def test_37_v4_2_correlation_engine_regression(self):
        """37. Verify full compatibility with V4.2 correlation engine."""
        c_engine = CorrelationEngine(CorrelationConfig(time_window_seconds=600.0))
        corrs = c_engine.correlate([self.ev_auth_alice, self.ev_sudo_alice])
        self.assertIsInstance(corrs, CorrelationCollection)
        self.assertGreaterEqual(len(corrs), 1)

    # 38. V4.1 regression
    def test_38_v4_1_correlation_models_regression(self):
        """38. Verify full compatibility with V4.1 correlation models."""
        cid = compute_deterministic_correlation_id(
            CorrelationType.TEMPORAL,
            ["EV-1", "EV-2"],
        )
        self.assertTrue(cid.startswith("CORR-"))

    # 39. V3 regression
    def test_39_v3_timeline_regression(self):
        """39. Verify ReconstructedTimeline input passes seamlessly to DetectionEngine."""
        rt = reconstruct_timeline([self.ev_auth_alice, self.ev_sudo_alice])
        results = evaluate_rule(self.rule_single_auth, rt)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].matched_event_ids, (self.ev_auth_alice.event_id,))


if __name__ == "__main__":
    unittest.main()
