"""
Focused Unit Test Suite for ForensiX V4.5 Initial Detection Rules.

Covers the 26 mandatory verification scenarios:
1. Four rules are created
2. Rule IDs are deterministic
3. Rule IDs are unique
4. Rule names are non-empty
5. Rule descriptions are factual
6. Detection descriptions are factual
7. Correct event categories
8. Correct event types
9. Correct correlation relationships
10. Correct time windows
11. Rule conditions are valid
12. Rules are immutable
13. Rule collection is deterministic
14. Serialization works
15. Serialization round-trip works
16. No executable callbacks exist
17. No speculative language exists
18. V4.4 DetectionEngine can evaluate the rules
19. Matching synthetic scenarios produce detections (Scenarios A, B, C, D)
20. Non-matching scenarios produce no detections (negative controls)
21. Detection IDs remain deterministic
22. V4.3 regression
23. V4.4 regression
24. V4.2 regression
25. V4.1 regression
26. V3 regression
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
    DISALLOWED_SPECULATIVE_TERMS,
    Correlation,
    CorrelationCollection,
    CorrelationType,
    RelationshipType,
    compute_deterministic_correlation_id,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    evaluate_rule,
    evaluate_rules,
)
from forensix.initial_rules import (
    DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
    RULE_NAME_ACCOUNT_PRIVILEGE,
    RULE_NAME_PERSISTENCE_FOLLOWUP,
    RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
    RULE_NAME_SSH_AUTH_SUDO,
    create_account_privilege_rule,
    create_initial_rules,
    create_persistence_followup_rule,
    create_repeated_ssh_failure_success_rule,
    create_ssh_auth_sudo_rule,
    get_initial_rules,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    compute_deterministic_rule_id,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import ReconstructedTimeline, reconstruct_timeline


class TestInitialRules(unittest.TestCase):
    """Rigorous unit tests for ForensiX V4.5 Initial Detection Rules."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
        self.t_minus_5 = datetime(2026, 4, 1, 9, 55, 0, tzinfo=timezone.utc)
        self.t_minus_3 = datetime(2026, 4, 1, 9, 57, 0, tzinfo=timezone.utc)
        self.t_plus_2 = datetime(2026, 4, 1, 10, 2, 0, tzinfo=timezone.utc)
        self.t_plus_5 = datetime(2026, 4, 1, 10, 5, 0, tzinfo=timezone.utc)
        self.t_plus_10 = datetime(2026, 4, 1, 10, 10, 0, tzinfo=timezone.utc)

        # Base synthetic events
        self.ev_ssh_success = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for alice from 10.0.0.10 port 45123 ssh2",
            timestamp=self.t0,
            source_path="/var/log/auth.log",
            source_line=10,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-001",
            attributes={"username": "alice", "source_ip": "10.0.0.10", "session_id": "sess-1"},
        )

        self.ev_sudo = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
            timestamp=self.t_plus_2,
            source_path="/var/log/auth.log",
            source_line=25,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-002",
            attributes={
                "username": "alice",
                "source_ip": "10.0.0.10",
                "session_id": "sess-1",
                "command": "/bin/bash",
            },
        )

        self.ev_ssh_fail_1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_failure",
            description="Failed password for alice from 10.0.0.10 port 44100 ssh2",
            timestamp=self.t_minus_5,
            source_path="/var/log/auth.log",
            source_line=1,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-000A",
            attributes={"username": "alice", "source_ip": "10.0.0.10"},
        )

        self.ev_ssh_fail_2 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_failure",
            description="Failed password for alice from 10.0.0.10 port 44102 ssh2",
            timestamp=self.t_minus_3,
            source_path="/var/log/auth.log",
            source_line=5,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-000B",
            attributes={"username": "alice", "source_ip": "10.0.0.10"},
        )

        self.ev_account_add = create_timeline_event(
            category=TimelineCategory.ACCOUNT,
            event_type="user_added",
            description="new user: name=alice, UID=1001, GID=1001, home=/home/alice",
            timestamp=self.t0,
            source_path="/var/log/auth.log",
            source_line=8,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-000C",
            attributes={"username": "alice"},
        )

        self.ev_cron_persist = create_timeline_event(
            category=TimelineCategory.PERSISTENCE,
            event_type="cron_job_scheduled",
            description="Cron job entry added at /etc/cron.d/sync_service",
            timestamp=self.t_plus_5,
            source_path="/etc/cron.d/sync_service",
            source_line=1,
            source_artifact_id="ART-CRON",
            source_event_id="CRON-001",
            attributes={"command": "/opt/sync.sh", "schedule": "*/5 * * * *"},
        )

    # 1. Four rules are created
    def test_01_four_rules_created(self):
        """1. Verify create_initial_rules creates exactly four rules."""
        collection = create_initial_rules()
        self.assertIsInstance(collection, RuleCollection)
        self.assertEqual(len(collection), 4)
        self.assertEqual(collection.total_rules, 4)

        # Check singleton get_initial_rules()
        cached = get_initial_rules()
        self.assertEqual(len(cached), 4)

    # 2. Rule IDs are deterministic
    def test_02_rule_ids_deterministic(self):
        """2. Verify rule IDs are 100% deterministic across repeated factory calls."""
        c1 = create_initial_rules()
        c2 = create_initial_rules()
        for r1, r2 in zip(c1, c2):
            self.assertEqual(r1.rule_id, r2.rule_id)
            self.assertTrue(r1.rule_id.startswith("RULE-"))

    # 3. Rule IDs are unique
    def test_03_rule_ids_unique(self):
        """3. Verify all four initial rules have distinct unique IDs."""
        collection = create_initial_rules()
        rule_ids = [r.rule_id for r in collection]
        self.assertEqual(len(rule_ids), 4)
        self.assertEqual(len(set(rule_ids)), 4)

    # 4. Rule names are non-empty
    def test_04_rule_names_non_empty(self):
        """4. Verify rule names are non-empty and match canonical specifications."""
        collection = create_initial_rules()
        names = [r.name for r in collection]
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, names)
        self.assertIn(RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS, names)
        self.assertIn(RULE_NAME_ACCOUNT_PRIVILEGE, names)
        self.assertIn(RULE_NAME_PERSISTENCE_FOLLOWUP, names)
        for r in collection:
            self.assertTrue(len(r.name.strip()) > 0)

    # 5. Rule descriptions are factual
    def test_05_rule_descriptions_factual(self):
        """5. Verify rule descriptions are non-empty, factual, and informative."""
        collection = create_initial_rules()
        for r in collection:
            self.assertTrue(len(r.description.strip()) > 0)
            self.assertIn("Identifies", r.description)

    # 6. Detection descriptions are factual
    def test_06_detection_descriptions_factual(self):
        """6. Verify detection descriptions are non-empty and begin with observational phrasing."""
        collection = create_initial_rules()
        for r in collection:
            self.assertTrue(len(r.detection_description.strip()) > 0)
            self.assertTrue(r.detection_description.startswith("Observed"))

    # 7. Correct event categories
    def test_07_correct_event_categories(self):
        """7. Verify each rule specifies valid and expected TimelineCategory values."""
        r1 = create_ssh_auth_sudo_rule()
        self.assertEqual(r1.required_categories, (TimelineCategory.AUTHENTICATION,))

        r2 = create_repeated_ssh_failure_success_rule()
        self.assertEqual(r2.required_categories, (TimelineCategory.AUTHENTICATION,))

        r3 = create_account_privilege_rule()
        self.assertEqual(
            set(r3.required_categories),
            {TimelineCategory.ACCOUNT, TimelineCategory.AUTHENTICATION},
        )

        r4 = create_persistence_followup_rule()
        self.assertEqual(
            set(r4.required_categories),
            {TimelineCategory.AUTHENTICATION, TimelineCategory.PERSISTENCE},
        )

    # 8. Correct event types
    def test_08_correct_event_types(self):
        """8. Verify each rule specifies valid and expected event types."""
        r1 = create_ssh_auth_sudo_rule()
        self.assertEqual(r1.required_event_types, ("ssh_login_success", "sudo_command"))

        r2 = create_repeated_ssh_failure_success_rule()
        self.assertEqual(r2.required_event_types, ("ssh_login_failure", "ssh_login_success"))

        r3 = create_account_privilege_rule()
        self.assertEqual(r3.required_event_types, ("user_added", "sudo_command"))

        r4 = create_persistence_followup_rule()
        self.assertEqual(r4.required_event_types, ("sudo_command", "cron_job_scheduled"))

    # 9. Correct correlation relationships
    def test_09_correct_correlation_relationships(self):
        """9. Verify Rule 1 requires AUTHENTICATION_PRIVILEGE relationship."""
        r1 = create_ssh_auth_sudo_rule()
        self.assertEqual(r1.required_relationships, (RelationshipType.AUTHENTICATION_PRIVILEGE,))

        # Rules 2, 3, 4 evaluate declarative sequences without requiring pre-computed correlations
        r2 = create_repeated_ssh_failure_success_rule()
        self.assertEqual(r2.required_relationships, ())
        r3 = create_account_privilege_rule()
        self.assertEqual(r3.required_relationships, ())
        r4 = create_persistence_followup_rule()
        self.assertEqual(r4.required_relationships, ())

    # 10. Correct time windows
    def test_10_correct_time_windows(self):
        """10. Verify default time windows equal 300.0s and can be configured."""
        collection = create_initial_rules()
        for r in collection:
            self.assertEqual(r.time_window_seconds, DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS)
            self.assertEqual(r.time_window_seconds, 300.0)

        # Custom window parameter works
        custom_r1 = create_ssh_auth_sudo_rule(time_window_seconds=600.0)
        self.assertEqual(custom_r1.time_window_seconds, 600.0)

    # 11. Rule conditions are valid
    def test_11_rule_conditions_valid(self):
        """11. Verify all condition structures on rules are immutable tuples."""
        collection = create_initial_rules()
        for r in collection:
            self.assertIsInstance(r.conditions, tuple)

    # 12. Rules are immutable
    def test_12_rules_are_immutable(self):
        """12. Verify DetectionRule instances reject field assignment."""
        collection = create_initial_rules()
        r1 = collection[0]
        with self.assertRaises(FrozenInstanceError):
            r1.name = "Mutated Name"  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            r1.time_window_seconds = 999.0  # type: ignore

    # 13. Rule collection is deterministic
    def test_13_rule_collection_deterministic(self):
        """13. Verify collection ordering and indexing are deterministic."""
        c1 = create_initial_rules()
        c2 = create_initial_rules()
        for i in range(len(c1)):
            self.assertEqual(c1[i].rule_id, c2[i].rule_id)
            self.assertEqual(c1[i].name, c2[i].name)

    # 14. Serialization works
    def test_14_serialization_works(self):
        """14. Verify to_dict() produces valid serializable dictionaries."""
        collection = create_initial_rules()
        d = collection.to_dict()
        self.assertIn("summary", d)
        self.assertIn("rules", d)
        self.assertEqual(d["summary"]["total_rules"], 4)

        # JSON dumps verification
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    # 15. Serialization round-trip works
    def test_15_serialization_round_trip(self):
        """15. Verify DetectionRule and RuleCollection roundtrip via from_dict()."""
        collection = create_initial_rules()
        d = collection.to_dict()
        reconstructed_rules = [DetectionRule.from_dict(r) for r in d["rules"]]
        reconstructed = RuleCollection(reconstructed_rules)
        self.assertEqual(len(reconstructed), len(collection))
        for r_orig, r_reconst in zip(collection, reconstructed):
            self.assertEqual(r_orig.rule_id, r_reconst.rule_id)
            self.assertEqual(r_orig.name, r_reconst.name)
            self.assertEqual(r_orig.required_event_types, r_reconst.required_event_types)
            self.assertEqual(r_orig.required_categories, r_reconst.required_categories)
            self.assertEqual(r_orig.time_window_seconds, r_reconst.time_window_seconds)

    # 16. No executable callbacks exist
    def test_16_no_executable_callbacks(self):
        """16. Verify no executable callables exist inside any rule."""
        collection = create_initial_rules()
        for r in collection:
            for attr_name in ("name", "description", "detection_description", "conditions", "attributes"):
                val = getattr(r, attr_name)
                self.assertFalse(callable(val))
                if isinstance(val, (list, tuple)):
                    for item in val:
                        self.assertFalse(callable(item))

    # 17. No speculative language exists
    def test_17_no_speculative_language(self):
        """17. Verify no speculative terms exist in any rule field."""
        collection = create_initial_rules()
        for r in collection:
            for text_field in (r.name, r.description, r.detection_description):
                lower_text = text_field.lower()
                for disallowed in DISALLOWED_SPECULATIVE_TERMS:
                    self.assertNotIn(
                        disallowed,
                        lower_text,
                        f"Disallowed term '{disallowed}' found in {r.name}: '{text_field}'",
                    )

    # 18. V4.4 DetectionEngine can evaluate the rules
    def test_18_detection_engine_evaluation(self):
        """18. Verify V4.4 DetectionEngine evaluates initial rules seamlessly."""
        engine = DetectionEngine(rules=create_initial_rules())
        self.assertEqual(len(engine.rules), 4)

        # Empty timeline evaluation produces 0 detections
        results = engine.evaluate([])
        self.assertIsInstance(results, DetectionResultCollection)
        self.assertEqual(len(results), 0)

    # 19. Matching synthetic scenarios produce detections
    def test_19_matching_synthetic_scenarios(self):
        """19. Verify Scenarios A, B, C, and D produce matches on DetectionEngine."""
        # Scenario A: Successful SSH login followed by sudo
        corrs = CorrelationEngine().correlate([self.ev_ssh_success, self.ev_sudo])
        r1 = create_ssh_auth_sudo_rule()
        res_a = DetectionEngine(rules=[r1]).evaluate([self.ev_ssh_success, self.ev_sudo], correlations=corrs)
        self.assertEqual(len(res_a), 1)
        self.assertEqual(res_a[0].rule_name, RULE_NAME_SSH_AUTH_SUDO)
        self.assertEqual(res_a[0].matched_event_ids, (self.ev_ssh_success.event_id, self.ev_sudo.event_id))

        # Scenario B: Failed SSH attempts followed by successful SSH login
        r2 = create_repeated_ssh_failure_success_rule()
        res_b = DetectionEngine(rules=[r2]).evaluate([self.ev_ssh_fail_1, self.ev_ssh_fail_2, self.ev_ssh_success])
        self.assertGreaterEqual(len(res_b), 1)
        self.assertEqual(res_b[0].rule_name, RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS)

        # Scenario C: Account activity followed by privilege activity
        r3 = create_account_privilege_rule()
        res_c = DetectionEngine(rules=[r3]).evaluate([self.ev_account_add, self.ev_sudo])
        self.assertEqual(len(res_c), 1)
        self.assertEqual(res_c[0].rule_name, RULE_NAME_ACCOUNT_PRIVILEGE)
        self.assertEqual(res_c[0].matched_event_ids, (self.ev_account_add.event_id, self.ev_sudo.event_id))

        # Scenario D: Privilege activity followed by persistence modification
        r4 = create_persistence_followup_rule()
        res_d = DetectionEngine(rules=[r4]).evaluate([self.ev_sudo, self.ev_cron_persist])
        self.assertEqual(len(res_d), 1)
        self.assertEqual(res_d[0].rule_name, RULE_NAME_PERSISTENCE_FOLLOWUP)
        self.assertEqual(res_d[0].matched_event_ids, (self.ev_sudo.event_id, self.ev_cron_persist.event_id))

    # 20. Non-matching scenarios produce no detections
    def test_20_non_matching_scenarios(self):
        """20. Negative controls: wrong event types, missing correlations, or outside time windows fail."""
        # Negative 1: Missing correlation for Rule 1
        r1 = create_ssh_auth_sudo_rule()
        res_no_corr = DetectionEngine(rules=[r1]).evaluate([self.ev_ssh_success, self.ev_sudo], correlations=[])
        self.assertEqual(len(res_no_corr), 0)

        # Negative 2: Events outside time window (600s delta > 300s window)
        ev_sudo_late = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="Late sudo",
            timestamp=self.t_plus_10,
            attributes={"username": "alice"},
        )
        corrs_late = CorrelationEngine().correlate([self.ev_ssh_success, ev_sudo_late])
        res_late = DetectionEngine(rules=[r1]).evaluate([self.ev_ssh_success, ev_sudo_late], correlations=corrs_late)
        self.assertEqual(len(res_late), 0)

        # Negative 3: Wrong event type for Rule 3
        ev_unrelated = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="file created",
            timestamp=self.t0,
        )
        r3 = create_account_privilege_rule()
        res_wrong_type = DetectionEngine(rules=[r3]).evaluate([ev_unrelated, self.ev_sudo])
        self.assertEqual(len(res_wrong_type), 0)

    # 21. Detection IDs remain deterministic
    def test_21_detection_ids_deterministic(self):
        """21. Verify evaluation of initial rules produces identical DetectionResult IDs across runs."""
        corrs = CorrelationEngine().correlate([self.ev_ssh_success, self.ev_sudo])
        r1 = create_ssh_auth_sudo_rule()

        engine1 = DetectionEngine(rules=[r1])
        engine2 = DetectionEngine(rules=[r1])

        res1 = engine1.evaluate([self.ev_ssh_success, self.ev_sudo], correlations=corrs)
        res2 = engine2.evaluate([self.ev_ssh_success, self.ev_sudo], correlations=corrs)

        self.assertEqual(len(res1), 1)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res1[0].detection_id, res2[0].detection_id)

    # 22. V4.3 regression
    def test_22_v4_3_rule_models_regression(self):
        """22. Verify V4.3 rule models compatibility with initial rules."""
        rules = create_initial_rules()
        for r in rules:
            self.assertIsInstance(r, DetectionRule)
            self.assertTrue(r.rule_id.startswith("RULE-"))

    # 23. V4.4 regression
    def test_23_v4_4_detection_engine_regression(self):
        """23. Verify evaluate_rules and evaluate_rule work seamlessly with initial rules."""
        corrs = CorrelationEngine().correlate([self.ev_ssh_success, self.ev_sudo])
        r1 = create_ssh_auth_sudo_rule()

        res_single = evaluate_rule(r1, [self.ev_ssh_success, self.ev_sudo], correlations=corrs)
        self.assertEqual(len(res_single), 1)

        res_multi = evaluate_rules([self.ev_ssh_success, self.ev_sudo], [r1], correlations=corrs)
        self.assertEqual(len(res_multi), 1)

    # 24. V4.2 regression
    def test_24_v4_2_correlation_engine_regression(self):
        """24. Verify V4.2 correlation engine generates correlations consumed by initial rules."""
        c_engine = CorrelationEngine(CorrelationConfig(time_window_seconds=300.0))
        corrs = c_engine.correlate([self.ev_ssh_success, self.ev_sudo])
        auth_priv = [c for c in corrs if c.relationship_type == RelationshipType.AUTHENTICATION_PRIVILEGE]
        self.assertEqual(len(auth_priv), 1)

    # 25. V4.1 regression
    def test_25_v4_1_correlation_models_regression(self):
        """25. Verify V4.1 correlation models compatibility."""
        cid = compute_deterministic_correlation_id(
            CorrelationType.AUTHENTICATION_PRIVILEGE,
            [self.ev_ssh_success.event_id, self.ev_sudo.event_id],
        )
        self.assertTrue(cid.startswith("CORR-"))

    # 26. V3 regression
    def test_26_v3_timeline_regression(self):
        """26. Verify ReconstructedTimeline input passes into DetectionEngine with initial rules."""
        rt = reconstruct_timeline([self.ev_account_add, self.ev_sudo])
        r3 = create_account_privilege_rule()
        res = evaluate_rule(r3, rt)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].rule_name, RULE_NAME_ACCOUNT_PRIVILEGE)


if __name__ == "__main__":
    unittest.main()
