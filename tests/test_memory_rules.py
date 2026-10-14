"""
Comprehensive Unit Test Suite for ForensiX V6.7 Memory Detection Rules.

Validates:
1. Declarative rule construction, validation, and immutability.
2. Deterministic rule IDs and repeatable canonical rule collections.
3. Positive and negative detection matching across memory event types.
4. Correct required event types, categories, and correlation relationships.
5. Handling of missing, null, or malformed artifact fields.
6. Direct versus contextual correlation confidence filtering.
7. Filtering by specific memory_relationship_type.
8. Rejection of unsupported speculative assertion language.
9. Fluent MemoryRuleBuilder operations.
10. Neutral, factual, and explainable forensic language.
"""

from datetime import datetime, timezone
import unittest

from forensix.correlation_models import Correlation, CorrelationType
from forensix.detection_engine import DetectionEngine, DetectionResultCollection
from forensix.memory_rules import (
    DEFAULT_MEMORY_RULE_TIME_WINDOW_SECONDS,
    RULE_MEM_01_PROCESS_NAME_OBSERVATION,
    RULE_MEM_02_LISTENING_PORT_OBSERVATION,
    RULE_MEM_03_PROCESS_SOCKET_CORRELATION,
    RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION,
    RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION,
    RULE_NAME_MEMORY_MODULE_DRIVER_PATH_PATTERN,
    RULE_NAME_MEMORY_NETWORK_PORT_PATTERN,
    RULE_NAME_MEMORY_PARENT_CHILD_CORRELATION,
    RULE_NAME_MEMORY_PROCESS_NAME_PATTERN,
    RULE_NAME_MEMORY_PROCESS_SOCKET_CORRELATION,
    MemoryRuleBuilder,
    create_canonical_memory_rules,
    create_memory_module_rule,
    create_memory_network_socket_rule,
    create_memory_parent_child_rule,
    create_memory_process_name_rule,
    create_memory_process_socket_correlation_rule,
)
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
)
from forensix.timeline_models import TimelineCategory, TimelineEvent


class TestMemoryRulesConstruction(unittest.TestCase):
    """Test deterministic rule construction, validation, and immutability."""

    def test_canonical_rules_collection(self) -> None:
        """Verify the 5 canonical baseline memory detection rules."""
        rules = create_canonical_memory_rules()
        self.assertIsInstance(rules, RuleCollection)
        self.assertEqual(len(rules), 5)

        pattern_ids = [r.attributes.get("pattern_id") if isinstance(r.attributes, dict) else dict(r.attributes).get("pattern_id") for r in rules]
        self.assertIn(RULE_MEM_01_PROCESS_NAME_OBSERVATION, pattern_ids)
        self.assertIn(RULE_MEM_02_LISTENING_PORT_OBSERVATION, pattern_ids)
        self.assertIn(RULE_MEM_03_PROCESS_SOCKET_CORRELATION, pattern_ids)
        self.assertIn(RULE_MEM_04_MODULE_DRIVER_PATH_OBSERVATION, pattern_ids)
        self.assertIn(RULE_MEM_05_PARENT_CHILD_PROCESS_CORRELATION, pattern_ids)

    def test_deterministic_rule_ids(self) -> None:
        """Verify identical factory calls produce identical deterministic rule IDs."""
        r1 = create_memory_process_name_rule("nc")
        r2 = create_memory_process_name_rule("nc")
        self.assertEqual(r1.rule_id, r2.rule_id)
        self.assertTrue(r1.rule_id.startswith("RULE-"))

    def test_rule_immutability(self) -> None:
        """Verify DetectionRule fields cannot be mutated."""
        rule = create_memory_process_name_rule("test_proc")
        with self.assertRaises((AttributeError, TypeError)):
            rule.name = "Mutated Name"  # type: ignore

    def test_rejection_of_speculative_language(self) -> None:
        """Verify speculative conclusion terms are strictly rejected."""
        speculative_phrases = [
            "confirmed attack in memory",
            "malware confirmed on host",
            "system compromised via rootkit",
            "intrusion confirmed by memory scan",
        ]
        for phrase in speculative_phrases:
            with self.subTest(phrase=phrase):
                with self.assertRaises(ValueError):
                    create_memory_process_name_rule("bash", description=phrase)

    def test_rejection_of_invalid_inputs(self) -> None:
        """Verify parameter validation on factory functions."""
        with self.assertRaises(ValueError):
            create_memory_process_name_rule("")

        with self.assertRaises(ValueError):
            create_memory_network_socket_rule(state=None)  # No conditions specified

        with self.assertRaises(ValueError):
            create_memory_network_socket_rule(local_port=70000)  # Invalid port

        with self.assertRaises(ValueError):
            create_memory_module_rule()  # No conditions specified

    def test_fluent_builder(self) -> None:
        """Verify MemoryRuleBuilder constructs valid DetectionRules."""
        rule = (
            MemoryRuleBuilder("Custom Memory Rule", "Factual observation description")
            .detection_description("Observed custom memory event")
            .with_category(TimelineCategory.LOG)
            .with_event_type("memory_process_created")
            .where("process_name", ConditionOperator.EQUALS, "gdb")
            .set_time_window(120.0)
            .set_attribute("custom_key", "custom_val")
            .build()
        )
        self.assertIsInstance(rule, DetectionRule)
        self.assertEqual(rule.name, "Custom Memory Rule")
        self.assertEqual(rule.time_window_seconds, 120.0)
        attrs = dict(rule.attributes)
        self.assertEqual(attrs.get("custom_key"), "custom_val")


class TestMemoryProcessRules(unittest.TestCase):
    """Test process-name observation detection rules."""

    def setUp(self) -> None:
        self.rule = create_memory_process_name_rule("nc", operator=ConditionOperator.EQUALS)
        self.engine = DetectionEngine([self.rule])

    def test_positive_match_created_event(self) -> None:
        """Verify positive detection for process named 'nc' on memory_process_created."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            timestamp=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.LOG,
            event_type="memory_process_created",
            description="Memory process created: nc (PID 1234)",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-00000000-0000-5000-8000-000000000001",
            attributes={"process_name": "nc", "pid": 1234},
        )
        results = self.engine.evaluate([event])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)
        self.assertIn("MEMPROC-00000000-0000-5000-8000-000000000001", results[0].matched_source_artifact_ids)

    def test_positive_match_observed_unanchored_event(self) -> None:
        """Verify positive detection on unanchored memory_process_observed event."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000002",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_observed",
            description="Memory process observed: nc (PID 1234)",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-00000000-0000-5000-8000-000000000001",
            attributes={"process_name": "nc", "pid": 1234},
        )
        results = self.engine.evaluate([event])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)

    def test_negative_control_non_matching_name(self) -> None:
        """Verify benign/non-matching process name produces no detection."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000003",
            timestamp=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.LOG,
            event_type="memory_process_created",
            description="Memory process created: sshd (PID 999)",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-00000000-0000-5000-8000-000000000002",
            attributes={"process_name": "sshd", "pid": 999},
        )
        results = self.engine.evaluate([event])
        self.assertEqual(len(results), 0)

    def test_missing_process_name_field(self) -> None:
        """Verify event missing process_name field does not raise error and does not match."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000004",
            timestamp=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.LOG,
            event_type="memory_process_created",
            description="Corrupt event",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"pid": 1234},  # Missing process_name
        )
        results = self.engine.evaluate([event])
        self.assertEqual(len(results), 0)

    def test_configurable_pattern_contains(self) -> None:
        """Verify configurable substring matching using CONTAINS operator."""
        rule = create_memory_process_name_rule("sh", operator=ConditionOperator.CONTAINS)
        engine = DetectionEngine([rule])

        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000005",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_created",
            description="Process bash",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"process_name": "bash"},
        )
        results = engine.evaluate([event])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)


class TestMemoryNetworkSocketRules(unittest.TestCase):
    """Test memory network socket observation detection rules."""

    def setUp(self) -> None:
        self.rule = create_memory_network_socket_rule(
            local_port=4444,
            state="LISTEN",
            protocol="TCP",
        )
        self.engine = DetectionEngine([self.rule])

    def test_positive_match_listening_port(self) -> None:
        """Verify positive detection for TCP socket listening on port 4444."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000010",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Memory socket: TCP 0.0.0.0:4444 (LISTEN)",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMNET-00000000-0000-5000-8000-000000000001",
            attributes={
                "protocol": "TCP",
                "state": "LISTEN",
                "local_port": 4444,
                "local_address": "0.0.0.0",
                "pid": 5555,
            },
        )
        results = self.engine.evaluate([event])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)
        self.assertIn("MEMNET-00000000-0000-5000-8000-000000000001", results[0].matched_source_artifact_ids)

    def test_negative_control_wrong_port_or_state(self) -> None:
        """Verify socket on different port or non-LISTEN state produces no detection."""
        # Case A: Wrong port (80)
        ev_port = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000011",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Port 80",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"protocol": "TCP", "state": "LISTEN", "local_port": 80},
        )
        self.assertEqual(len(self.engine.evaluate([ev_port])), 0)

        # Case B: Wrong state (ESTABLISHED)
        ev_state = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000012",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Port 4444 Established",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"protocol": "TCP", "state": "ESTABLISHED", "local_port": 4444},
        )
        self.assertEqual(len(self.engine.evaluate([ev_state])), 0)

    def test_missing_or_none_socket_fields(self) -> None:
        """Verify socket missing local_port or state evaluates cleanly without error."""
        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000013",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Incomplete socket",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"protocol": "TCP", "state": None, "local_port": None},
        )
        self.assertEqual(len(self.engine.evaluate([event])), 0)


class TestMemoryModuleRules(unittest.TestCase):
    """Test kernel module and driver path review indicator rules."""

    def test_positive_match_driver_path(self) -> None:
        """Verify positive detection when module path contains '/tmp'."""
        rule = create_memory_module_rule(path_pattern="/tmp", path_operator=ConditionOperator.CONTAINS)
        engine = DetectionEngine([rule])

        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000020",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_module_observed",
            description="Module in /tmp",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMMOD-00000000-0000-5000-8000-000000000001",
            attributes={
                "module_name": "test_rootkit",
                "driver_path": "/tmp/test_rootkit.ko",
                "size_bytes": 2048,
            },
        )
        results = engine.evaluate([event])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)

    def test_negative_control_standard_path(self) -> None:
        """Verify standard kernel module path does not trigger review indicator."""
        rule = create_memory_module_rule(path_pattern="/tmp", path_operator=ConditionOperator.CONTAINS)
        engine = DetectionEngine([rule])

        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000021",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_module_observed",
            description="Standard module",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={
                "module_name": "ext4",
                "driver_path": "/lib/modules/6.8.0/kernel/fs/ext4/ext4.ko",
            },
        )
        results = engine.evaluate([event])
        self.assertEqual(len(results), 0)

    def test_missing_driver_path_none(self) -> None:
        """Verify module with driver_path=None evaluates safely without exception."""
        rule = create_memory_module_rule(path_pattern="/tmp", path_operator=ConditionOperator.CONTAINS)
        engine = DetectionEngine([rule])

        event = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000022",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_module_observed",
            description="Module without path",
            source_path="memory:MEM-test",
            source_line=1,
            attributes={"module_name": "vboxguest", "driver_path": None},
        )
        results = engine.evaluate([event])
        self.assertEqual(len(results), 0)


class TestMemoryCorrelationRules(unittest.TestCase):
    """Test correlation-based memory detection rules."""

    def test_process_network_socket_correlation(self) -> None:
        """Verify detection on PROCESS_NETWORK_SOCKET correlation."""
        rule = create_memory_process_socket_correlation_rule(require_direct_confidence=True)
        engine = DetectionEngine([rule])

        # Underlying events
        ev_proc = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000030",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_observed",
            description="Process",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-00000000-0000-5000-8000-000000000001",
            attributes={"pid": 1234, "process_name": "nc"},
        )
        ev_sock = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000031",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Socket",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMNET-00000000-0000-5000-8000-000000000001",
            attributes={"pid": 1234, "local_port": 4444},
        )

        # Correlation matching HOST_NETWORK
        corr = Correlation(
            correlation_id="CORR-00000000-0000-4000-8000-000000000001",
            relationship_type=CorrelationType.HOST_NETWORK,
            event_ids=(ev_proc.event_id, ev_sock.event_id),
            source_artifact_ids=(ev_proc.source_artifact_id, ev_sock.source_artifact_id),
            description="Process to socket link",
            attributes={
                "memory_relationship_type": "PROCESS_NETWORK_SOCKET",
                "confidence": "DIRECT",
                "evidence_id": "MEM-00000000-0000-5000-8000-000000000001",
            },
        )

        results = engine.evaluate(timeline=[ev_proc, ev_sock], correlations=[corr])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)
        self.assertIn("MEMPROC-00000000-0000-5000-8000-000000000001", results[0].matched_source_artifact_ids)
        self.assertIn("MEMNET-00000000-0000-5000-8000-000000000001", results[0].matched_source_artifact_ids)

    def test_process_network_socket_wrong_confidence(self) -> None:
        """Verify correlation with CONTEXTUAL confidence does not match when DIRECT is required."""
        rule = create_memory_process_socket_correlation_rule(require_direct_confidence=True)
        engine = DetectionEngine([rule])

        ev1 = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000032",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_observed",
            description="Process 1",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-1",
        )
        ev2 = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000033",
            timestamp=None,
            category=TimelineCategory.NETWORK,
            event_type="memory_network_socket_observed",
            description="Socket 2",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMNET-2",
        )
        corr = Correlation(
            correlation_id="CORR-00000000-0000-4000-8000-000000000002",
            relationship_type=CorrelationType.HOST_NETWORK,
            event_ids=(ev1.event_id, ev2.event_id),
            description="Contextual process socket link",
            attributes={
                "memory_relationship_type": "PROCESS_NETWORK_SOCKET",
                "confidence": "CONTEXTUAL",  # Not DIRECT
            },
        )
        results = engine.evaluate(timeline=[ev1, ev2], correlations=[corr])
        self.assertEqual(len(results), 0)

    def test_parent_child_process_correlation(self) -> None:
        """Verify detection on PARENT_CHILD_PROCESS correlation."""
        rule = create_memory_parent_child_rule(
            parent_process_name="nginx",
            child_process_name="sh",
            require_direct_confidence=True,
        )
        engine = DetectionEngine([rule])

        ev_parent = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000040",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_observed",
            description="Parent",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-PARENT",
            attributes={"process_name": "nginx", "pid": 800},
        )
        ev_child = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000041",
            timestamp=None,
            category=TimelineCategory.LOG,
            event_type="memory_process_observed",
            description="Child",
            source_path="memory:MEM-test",
            source_line=1,
            source_artifact_id="MEMPROC-CHILD",
            attributes={"process_name": "sh", "pid": 801, "ppid": 800},
        )

        corr = Correlation(
            correlation_id="CORR-00000000-0000-4000-8000-000000000003",
            relationship_type=CorrelationType.SAME_SOURCE,
            event_ids=(ev_parent.event_id, ev_child.event_id),
            source_artifact_ids=("MEMPROC-PARENT", "MEMPROC-CHILD"),
            description="Parent-child process link",
            attributes={
                "memory_relationship_type": "PARENT_CHILD_PROCESS",
                "confidence": "DIRECT",
                "supporting_fields": {"parent_name": "nginx", "child_name": "sh"},
            },
        )

        results = engine.evaluate(timeline=[ev_parent, ev_child], correlations=[corr])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)
        self.assertIn("MEMPROC-PARENT", results[0].matched_source_artifact_ids)
        self.assertIn("MEMPROC-CHILD", results[0].matched_source_artifact_ids)


if __name__ == "__main__":
    unittest.main()
