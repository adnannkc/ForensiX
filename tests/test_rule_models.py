"""
Focused Unit Test Suite for ForensiX V4.3 Rule Model.

Covers:
1. Valid minimal rule
2. Fully populated rule
3. Rule ID validation
4. Name validation
5. Description validation
6. Condition validation
7. Event type validation
8. Event category validation
9. Time-window validation
10. Detection description validation
11. Invalid rule rejection
12. Empty values handling
13. Invalid types handling
14. Unsupported values / speculative phrases rejection
15. Rule immutability
16. Nested condition immutability
17. Deterministic rule identity
18. Deterministic serialization
19. Serialization round-trip
20. Multiple conditions
21. Multiple event types
22. Multiple event categories
23. V4.1 compatibility/regression
24. V4.2 compatibility/regression
25. V3 regression
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.correlation_models import (
    Correlation,
    CorrelationType,
)
from forensix.correlation_engine import (
    CorrelationConfig,
    CorrelationEngine,
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


class TestRuleModel(unittest.TestCase):
    """Rigorous unit tests for ForensiX V4.3 Detection Rule Model."""

    # 1. Valid minimal rule
    def test_01_valid_minimal_rule(self):
        """1. Verify construction of a DetectionRule with minimal required fields."""
        rule = DetectionRule(
            name="Sudo Execution Rule",
            description="Rule tracking sudo command execution",
            detection_description="Observed sudo activity",
        )
        self.assertTrue(rule.rule_id.startswith("RULE-"))
        self.assertEqual(rule.name, "Sudo Execution Rule")
        self.assertEqual(rule.description, "Rule tracking sudo command execution")
        self.assertEqual(rule.detection_description, "Observed sudo activity")
        self.assertEqual(rule.required_categories, ())
        self.assertEqual(rule.required_event_types, ())
        self.assertEqual(rule.required_relationships, ())
        self.assertEqual(rule.conditions, ())
        self.assertIsNone(rule.time_window_seconds)

    # 2. Fully populated rule
    def test_02_fully_populated_rule(self):
        """2. Verify construction with all optional and explicit fields supplied."""
        cond1 = RuleCondition(
            field="username",
            operator=ConditionOperator.EQUALS,
            value="alice",
            description="User must be alice",
        )
        cond2 = RuleCondition(
            field="command",
            operator=ConditionOperator.CONTAINS,
            value="/etc/shadow",
            description="Command touches shadow",
        )

        rule = DetectionRule(
            rule_id="RULE-AUTH-SUDO-001",
            name="SSH Login Followed by Sudo",
            description="Observed SSH authentication followed by sudo activity",
            detection_description="SSH authentication was followed by sudo activity for user alice",
            required_categories=[TimelineCategory.AUTHENTICATION],
            required_event_types=["ssh_login_success", "sudo_command"],
            required_relationships=[CorrelationType.AUTHENTICATION_PRIVILEGE, CorrelationType.SAME_USER],
            conditions=[cond1, cond2],
            time_window_seconds=300.0,
            attributes={"mitre_id": "T1078", "author": "ForensiX Team"},
        )

        self.assertEqual(rule.rule_id, "RULE-AUTH-SUDO-001")
        self.assertEqual(rule.name, "SSH Login Followed by Sudo")
        self.assertEqual(rule.required_categories, (TimelineCategory.AUTHENTICATION,))
        self.assertEqual(rule.required_event_types, ("ssh_login_success", "sudo_command"))
        self.assertEqual(
            rule.required_relationships,
            (CorrelationType.AUTHENTICATION_PRIVILEGE, CorrelationType.SAME_USER),
        )
        self.assertEqual(len(rule.conditions), 2)
        self.assertEqual(rule.time_window_seconds, 300.0)
        self.assertIsInstance(rule.attributes, tuple)

    # 3. Rule ID validation
    def test_03_rule_id_validation(self):
        """3. Verify rule_id must start with 'RULE-' and have a non-empty suffix."""
        # Valid custom rule IDs
        r1 = DetectionRule(
            rule_id="RULE-CUSTOM-001",
            name="Custom Rule",
            description="Desc",
            detection_description="Det",
        )
        self.assertEqual(r1.rule_id, "RULE-CUSTOM-001")

        # Invalid prefixes or empty
        bad_ids = ["INVALID-001", "RULE-", "   ", "", "CORR-1234"]
        for bad in bad_ids:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    DetectionRule(
                        rule_id=bad,
                        name="Rule",
                        description="Desc",
                        detection_description="Det",
                    )

        with self.assertRaises(TypeError):
            DetectionRule(
                rule_id=12345,  # type: ignore
                name="Rule",
                description="Desc",
                detection_description="Det",
            )

    # 4. Name validation
    def test_04_name_validation(self):
        """4. Verify name must be a non-empty string."""
        with self.assertRaises(TypeError):
            DetectionRule(name=None, description="Desc", detection_description="Det")  # type: ignore
        with self.assertRaises(TypeError):
            DetectionRule(name=123, description="Desc", detection_description="Det")  # type: ignore
        with self.assertRaises(ValueError):
            DetectionRule(name="", description="Desc", detection_description="Det")
        with self.assertRaises(ValueError):
            DetectionRule(name="   ", description="Desc", detection_description="Det")

    # 5. Description validation
    def test_05_description_validation(self):
        """5. Verify description must be a non-empty string."""
        with self.assertRaises(TypeError):
            DetectionRule(name="Rule", description=None, detection_description="Det")  # type: ignore
        with self.assertRaises(ValueError):
            DetectionRule(name="Rule", description="", detection_description="Det")
        with self.assertRaises(ValueError):
            DetectionRule(name="Rule", description="   ", detection_description="Det")

    # 6. Condition validation
    def test_06_condition_validation(self):
        """6. Verify RuleCondition validation on field, operator, value, and description."""
        # Valid condition
        cond = RuleCondition("status", "==", "SUCCESS", "Checks status")
        self.assertEqual(cond.field, "status")
        self.assertEqual(cond.operator, ConditionOperator.EQUALS)
        self.assertEqual(cond.value, "SUCCESS")

        # Field validation
        with self.assertRaises(TypeError):
            RuleCondition(None, "==")  # type: ignore
        with self.assertRaises(ValueError):
            RuleCondition("", "==")

        # Operator validation
        with self.assertRaises(ValueError):
            RuleCondition("status", "INVALID_OP")
        with self.assertRaises(TypeError):
            RuleCondition("status", 123)  # type: ignore

        # Prohibit executable code / callables
        with self.assertRaises(TypeError):
            RuleCondition("status", "==", lambda x: x)  # type: ignore
        with self.assertRaises(ValueError):
            RuleCondition("status", "==", "eval('malicious')")

    # 7. Event type validation
    def test_07_event_type_validation(self):
        """7. Verify required_event_types validation and rejection of speculative types."""
        # Valid event types
        rule = DetectionRule(
            name="Rule",
            description="Desc",
            detection_description="Det",
            required_event_types=["ssh_login_success", "sudo_command"],
        )
        self.assertEqual(rule.required_event_types, ("ssh_login_success", "sudo_command"))

        # Rejection of speculative event types
        with self.assertRaises(ValueError):
            DetectionRule(
                name="Rule",
                description="Desc",
                detection_description="Det",
                required_event_types=["attack_detected"],
            )

        # Rejection of empty strings or non-strings
        with self.assertRaises(ValueError):
            DetectionRule(
                name="Rule",
                description="Desc",
                detection_description="Det",
                required_event_types=[""],
            )
        with self.assertRaises(TypeError):
            DetectionRule(
                name="Rule",
                description="Desc",
                detection_description="Det",
                required_event_types=[123],  # type: ignore
            )

    # 8. Event category validation
    def test_08_event_category_validation(self):
        """8. Verify required_categories accepts TimelineCategory enums and strings."""
        rule = DetectionRule(
            name="Rule",
            description="Desc",
            detection_description="Det",
            required_categories=[TimelineCategory.AUTHENTICATION, "filesystem"],
        )
        self.assertEqual(
            rule.required_categories,
            (TimelineCategory.AUTHENTICATION, TimelineCategory.FILESYSTEM),
        )

        with self.assertRaises(ValueError):
            DetectionRule(
                name="Rule",
                description="Desc",
                detection_description="Det",
                required_categories=["unknown_cat"],
            )
        with self.assertRaises(TypeError):
            DetectionRule(
                name="Rule",
                description="Desc",
                detection_description="Det",
                required_categories=[999],  # type: ignore
            )

    # 9. Time-window validation
    def test_09_time_window_validation(self):
        """9. Verify time_window_seconds accepts non-negative floats/ints and rejects negative/bool."""
        # Valid float and int
        r1 = DetectionRule(
            name="R1", description="D", detection_description="DD", time_window_seconds=120.0
        )
        self.assertEqual(r1.time_window_seconds, 120.0)

        # 0.0 is valid
        r0 = DetectionRule(
            name="R0", description="D", detection_description="DD", time_window_seconds=0.0
        )
        self.assertEqual(r0.time_window_seconds, 0.0)

        # Negative
        with self.assertRaises(ValueError):
            DetectionRule(
                name="R", description="D", detection_description="DD", time_window_seconds=-10.0
            )

        # Boolean
        with self.assertRaises(TypeError):
            DetectionRule(
                name="R", description="D", detection_description="DD", time_window_seconds=True  # type: ignore
            )

    # 10. Detection description validation
    def test_10_detection_description_validation(self):
        """10. Verify detection_description must be a non-empty string."""
        with self.assertRaises(TypeError):
            DetectionRule(name="R", description="D", detection_description=None)  # type: ignore
        with self.assertRaises(ValueError):
            DetectionRule(name="R", description="D", detection_description="")
        with self.assertRaises(ValueError):
            DetectionRule(name="R", description="D", detection_description="   ")

    # 11. Invalid rule rejection
    def test_11_invalid_rule_rejection(self):
        """11. Verify missing required positional arguments raise TypeError."""
        with self.assertRaises(TypeError):
            DetectionRule()  # type: ignore
        with self.assertRaises(TypeError):
            DetectionRule(name="R")  # type: ignore
        with self.assertRaises(TypeError):
            DetectionRule(name="R", description="D")  # type: ignore

    # 12. Empty values handling
    def test_12_empty_values_handling(self):
        """12. Verify whitespace-only arguments raise ValueError."""
        with self.assertRaises(ValueError):
            DetectionRule(name="   ", description="D", detection_description="DD")
        with self.assertRaises(ValueError):
            DetectionRule(name="R", description="   ", detection_description="DD")
        with self.assertRaises(ValueError):
            DetectionRule(name="R", description="D", detection_description="   ")

    # 13. Invalid types handling
    def test_13_invalid_types_handling(self):
        """13. Verify non-string types for text fields raise TypeError."""
        with self.assertRaises(TypeError):
            DetectionRule(name=["List"], description="D", detection_description="DD")  # type: ignore
        with self.assertRaises(TypeError):
            DetectionRule(name="R", description={"dict": 1}, detection_description="DD")  # type: ignore
        with self.assertRaises(TypeError):
            DetectionRule(name="R", description="D", detection_description=123)  # type: ignore

    # 14. Speculative language rejection
    def test_14_speculative_language_rejection(self):
        """14. Verify speculative or interpretive labels raise ValueError in rule definitions."""
        disallowed = [
            "confirmed attack",
            "attacker confirmed",
            "system compromised",
            "malware confirmed",
            "intrusion confirmed",
        ]
        for term in disallowed:
            with self.subTest(term=term):
                with self.assertRaises(ValueError):
                    DetectionRule(
                        name=f"Rule for {term}",
                        description="Desc",
                        detection_description="Det",
                    )
                with self.assertRaises(ValueError):
                    DetectionRule(
                        name="Rule",
                        description=f"Description claiming {term}",
                        detection_description="Det",
                    )
                with self.assertRaises(ValueError):
                    DetectionRule(
                        name="Rule",
                        description="Desc",
                        detection_description=f"Detection claiming {term}",
                    )

    # 15. Rule immutability
    def test_15_rule_immutability(self):
        """15. Verify DetectionRule raises FrozenInstanceError when modifying attributes."""
        rule = DetectionRule(name="R", description="D", detection_description="DD")
        with self.assertRaises(FrozenInstanceError):
            rule.name = "Altered Name"  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            rule.description = "Altered Desc"  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            rule.time_window_seconds = 60.0  # type: ignore

    # 16. Nested condition immutability
    def test_16_nested_condition_immutability(self):
        """16. Verify RuleCondition raises FrozenInstanceError when modifying attributes."""
        cond = RuleCondition("username", "==", ["alice", "bob"])
        with self.assertRaises(FrozenInstanceError):
            cond.field = "other"  # type: ignore
        with self.assertRaises(FrozenInstanceError):
            cond.value = "eve"  # type: ignore
        # Collection value is frozen into a tuple
        self.assertIsInstance(cond.value, tuple)

    # 17. Deterministic rule identity
    def test_17_deterministic_rule_identity(self):
        """17. Verify rule IDs generated via UUIDv5 are 100% reproducible across calls."""
        r1 = DetectionRule(
            name="SSH Auth Followed by Sudo",
            description="D",
            detection_description="DD",
            required_event_types=["ssh_login_success", "sudo_command"],
        )
        r2 = DetectionRule(
            name="SSH Auth Followed by Sudo",
            description="Different description does not change canonical name/types",
            detection_description="Different det description",
            required_event_types=["sudo_command", "ssh_login_success"],  # reversed order
        )
        self.assertEqual(r1.rule_id, r2.rule_id)

        # Calling compute_deterministic_rule_id directly
        direct_id = compute_deterministic_rule_id(
            "SSH Auth Followed by Sudo",
            ["ssh_login_success", "sudo_command"],
        )
        self.assertEqual(r1.rule_id, direct_id)

    # 18. Deterministic serialization
    def test_18_deterministic_serialization(self):
        """18. Verify to_dict produces a deterministic JSON-serializable dictionary."""
        cond = RuleCondition("user", "==", "alice")
        rule = DetectionRule(
            rule_id="RULE-TEST-001",
            name="Rule Name",
            description="Desc",
            detection_description="Det Desc",
            required_categories=[TimelineCategory.AUTHENTICATION],
            required_event_types=["login"],
            required_relationships=[CorrelationType.SAME_USER],
            conditions=[cond],
            time_window_seconds=120.0,
            attributes={"tag": "auth"},
        )
        d = rule.to_dict()
        self.assertEqual(d["rule_id"], "RULE-TEST-001")
        self.assertEqual(d["required_categories"], ["authentication"])
        self.assertEqual(d["required_event_types"], ["login"])
        self.assertEqual(d["required_relationships"], ["SAME_USER"])
        self.assertEqual(len(d["conditions"]), 1)
        self.assertEqual(d["time_window_seconds"], 120.0)

        # JSON dumps test
        json_str = json.dumps(d)
        self.assertIn("RULE-TEST-001", json_str)

    # 19. Serialization round-trip
    def test_19_serialization_roundtrip(self):
        """19. Verify roundtrip from_dict reconstructs an identical DetectionRule."""
        cond = RuleCondition("user", "in", ["alice", "bob"])
        rule = DetectionRule(
            rule_id="RULE-ROUNDTRIP-001",
            name="Roundtrip Rule",
            description="Testing roundtrip",
            detection_description="Det description",
            required_categories=[TimelineCategory.LOG, TimelineCategory.AUTHENTICATION],
            required_event_types=["syslog", "auth"],
            required_relationships=[CorrelationType.TEMPORAL],
            conditions=[cond],
            time_window_seconds=240.0,
            attributes={"level": 1},
        )
        d = rule.to_dict()
        reconstructed = DetectionRule.from_dict(d)

        self.assertEqual(reconstructed.rule_id, rule.rule_id)
        self.assertEqual(reconstructed.name, rule.name)
        self.assertEqual(reconstructed.description, rule.description)
        self.assertEqual(reconstructed.detection_description, rule.detection_description)
        self.assertEqual(reconstructed.required_categories, rule.required_categories)
        self.assertEqual(reconstructed.required_event_types, rule.required_event_types)
        self.assertEqual(reconstructed.required_relationships, rule.required_relationships)
        self.assertEqual(len(reconstructed.conditions), len(rule.conditions))
        self.assertEqual(reconstructed.time_window_seconds, rule.time_window_seconds)

    # 20. Multiple conditions
    def test_20_multiple_conditions(self):
        """20. Verify rule supports chaining multiple conditions."""
        conds = [
            RuleCondition("user", "==", "alice"),
            RuleCondition("source_ip", "!=", "127.0.0.1"),
            RuleCondition("port", ">", 1024),
        ]
        rule = DetectionRule(
            name="Multi Condition Rule",
            description="D",
            detection_description="DD",
            conditions=conds,
        )
        self.assertEqual(len(rule.conditions), 3)

    # 21. Multiple event types
    def test_21_multiple_event_types(self):
        """21. Verify rule preserves sequence of required event types."""
        types = ["ssh_login_success", "sudo_command", "file_accessed"]
        rule = DetectionRule(
            name="Multi Event Type Rule",
            description="D",
            detection_description="DD",
            required_event_types=types,
        )
        self.assertEqual(rule.required_event_types, tuple(types))

    # 22. Multiple event categories
    def test_22_multiple_event_categories(self):
        """22. Verify rule preserves sequence of required event categories."""
        cats = [TimelineCategory.AUTHENTICATION, TimelineCategory.FILESYSTEM]
        rule = DetectionRule(
            name="Multi Category Rule",
            description="D",
            detection_description="DD",
            required_categories=cats,
        )
        self.assertEqual(rule.required_categories, tuple(cats))

    # 23. V4.1 compatibility and regression
    def test_23_v4_1_compatibility_and_regression(self):
        """23. Verify Rule model seamlessly accepts CorrelationType from V4.1."""
        rule = create_rule(
            name="Correlation Linked Rule",
            description="D",
            detection_description="DD",
            required_relationships=[CorrelationType.AUTHENTICATION_PRIVILEGE],
        )
        self.assertEqual(
            rule.required_relationships,
            (CorrelationType.AUTHENTICATION_PRIVILEGE,),
        )

    # 24. V4.2 compatibility and regression
    def test_24_v4_2_compatibility_and_regression(self):
        """24. Verify CorrelationConfig and CorrelationEngine continue operating cleanly."""
        config = CorrelationConfig(time_window_seconds=180.0)
        self.assertEqual(config.time_window_seconds, 180.0)

    # 25. V3 regression
    def test_25_v3_regression(self):
        """25. Verify TimelineEvent and TimelineCategory continue operating cleanly."""
        ev = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="SSH login",
        )
        self.assertEqual(ev.category, TimelineCategory.AUTHENTICATION)

    # 26. RuleCollection functionality
    def test_26_rule_collection_functionality(self):
        """26. Verify RuleCollection aggregation, indexing, iteration, and summary."""
        r1 = DetectionRule(rule_id="RULE-1", name="R1", description="D", detection_description="DD")
        r2 = DetectionRule(rule_id="RULE-2", name="R2", description="D", detection_description="DD")

        collection = RuleCollection([r1, r2])
        self.assertEqual(len(collection), 2)
        self.assertEqual(collection.total_rules, 2)
        self.assertEqual(collection[0], r1)
        self.assertIn(r1, collection)
        self.assertIn("RULE-1", collection)
        self.assertEqual(collection.get_rule("RULE-2"), r2)
        self.assertIsNone(collection.get_rule("RULE-NONEXISTENT"))

        # Summary and to_dict
        summary = collection.summary
        self.assertEqual(summary["total_rules"], 2)
        self.assertEqual(summary["rule_ids"], ["RULE-1", "RULE-2"])

        d = collection.to_dict()
        self.assertEqual(len(d["rules"]), 2)

        # Duplicate rule_id in collection raises ValueError
        with self.assertRaises(ValueError):
            RuleCollection([r1, r1])

        # Non-rule item raises TypeError
        with self.assertRaises(TypeError):
            RuleCollection([r1, "not-a-rule"])  # type: ignore


if __name__ == "__main__":
    unittest.main()
