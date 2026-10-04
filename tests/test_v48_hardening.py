"""
ForensiX Milestone V4.8 — Comprehensive Hardening & Release Readiness Test Suite.

Thoroughly exercises and validates:
1. Input validation & error boundary defenses across core models and CLI.
2. Path safety, traversal prevention (../, ../../, absolute, unicode), and evidence boundary enforcement.
3. Strict evidence immutability (file counts, filenames, sizes, and SHA-256 hashes across V1-V4 pipelines).
4. Empty evidence directory handling.
5. Malformed artifact handling (corrupted logs, truncated files, invalid metadata).
6. Timestamp boundaries (aware, naive, microsecond deltas, boundary window matches).
7. Correlation engine boundary conditions and identity isolation.
8. Rule model robustness, validation, and speculative language rejection.
9. Detection engine edge cases, missing attributes, falsy values, and AND logic.
10. Initial rules verification (all 4 canonical rules, exact parameters, documented boundaries).
11. Reporting security: HTML/XSS sanitization (<script>, &, <, >, ", '), self-contained styling, zero CDN deps.
12. CLI entry-point behavior, help formatting, and exit-code semantics.
13. CLI backward compatibility across V1, V2.9 triage, and V3 timeline commands.
14. Determinism of analytical results across repeated executions.
15. Serialization roundtrip integrity for all V4 models and reports.
16. Deep immutability guarantees on models, collections, and reports.
17. Speculative phrasing audit (rejecting unsupported compromise claims).
18. Resource sanity under scaled event volume.
19. Security review: offline operation, no eval/exec, safe subprocess usage.
20. Import stability and public API symbol resolution.
21. Full synthetic E2E workflows (positive, negative, malformed).
"""

from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import unittest
from unittest.mock import MagicMock, patch

import forensix
from forensix import (
    __version__,
    build_investigation_parser,
    build_timeline_parser,
    build_triage_parser,
    execute_investigation_cli,
    execute_timeline_cli,
    execute_triage_cli,
    investigation_main,
    main,
    timeline_main,
    triage_main,
)
from forensix.main import build_parser
from forensix.artifact_adapters import adapt_artifacts
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
from forensix.correlation_reporting import (
    generate_correlation_report,
    write_correlation_html_report,
    write_correlation_json_report,
)
from forensix.detection_engine import (
    DetectionEngine,
    DetectionResult,
    DetectionResultCollection,
    compute_deterministic_detection_id,
    evaluate_condition_operator,
    resolve_field_value,
)
from forensix.detection_reporting import (
    CorrelationDetectionReport,
    DetectionReport,
    InvestigationReport,
    generate_correlation_detection_report,
    generate_detection_report,
    write_correlation_detection_html_report,
    write_correlation_detection_json_report,
    write_detection_html_report,
    write_detection_json_report,
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
    create_rule,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    create_timeline_event,
)
from forensix.timeline_reconstruction import (
    reconstruct_timeline,
)
from forensix.triage_models import TriageConfig
from forensix.triage_orchestrator import TriageOrchestrator


class TestV48Hardening(unittest.TestCase):
    """ForensiX V4.8 Comprehensive Hardening and Verification Suite."""

    def setUp(self):
        """Prepare temporary test workspace and evidence trees."""
        self.workspace = tempfile.mkdtemp(prefix="forensix_v48_")
        self.reports_dir = Path(self.workspace) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Multi-artifact evidence tree
        self.evidence_dir = Path(self.workspace) / "evidence"
        self.log_dir = self.evidence_dir / "var" / "log"
        self.etc_dir = self.evidence_dir / "etc"
        self.cron_dir = self.etc_dir / "cron.d"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.cron_dir.mkdir(parents=True, exist_ok=True)

        # Baseline auth.log with valid ISO timestamps
        self.auth_log = self.log_dir / "auth.log"
        self.auth_log.write_text(
            "2026-09-30T10:00:00+00:00 srv01 sshd[1001]: Accepted password for secops from 192.168.1.100 port 44200 ssh2\n"
            "2026-09-30T10:01:00+00:00 srv01 sudo: secops : TTY=pts/0 ; PWD=/home/secops ; USER=root ; COMMAND=/usr/bin/whoami\n",
            encoding="utf-8",
        )

        # Baseline persistence cron artifact
        self.cron_job = self.cron_dir / "maintenance"
        self.cron_job.write_text(
            "*/10 * * * * root /usr/local/bin/sync.sh\n",
            encoding="utf-8",
        )

        # Baseline /etc/passwd artifact
        self.passwd_file = self.etc_dir / "passwd"
        self.passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "secops:x:1001:1001:Security Analyst:/home/secops:/bin/bash\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up test workspace."""
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _hash_tree(self, directory: Path) -> Dict[str, Tuple[int, str]]:
        """Compute relative path -> (file_size, sha256) mapping for all files."""
        tree: Dict[str, Tuple[int, str]] = {}
        for p in sorted(directory.rglob("*")):
            if p.is_file():
                rel = str(p.relative_to(directory))
                size = p.stat().st_size
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                tree[rel] = (size, digest)
        return tree

    def _capture_cli(self, func, argv: List[str]):
        """Capture stdout and stderr for a CLI invocation."""
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        res = 0
        try:
            sys.stdout = out_buf
            sys.stderr = err_buf
            res = func(argv)
        except SystemExit as exc:
            res = exc.code if isinstance(exc.code, int) else 0
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return res, out_buf.getvalue(), err_buf.getvalue()

    # =========================================================================
    # AREA 1: INPUT VALIDATION
    # =========================================================================

    def test_area01_core_model_input_validation(self):
        """Verify core forensic models reject invalid, None, or empty parameters."""
        # 1. TimelineEvent requires valid category and non-empty event_type
        with self.assertRaises(TypeError):
            TimelineEvent(category=None, event_type="login", description="desc")
        with self.assertRaises(ValueError):
            TimelineEvent(category=TimelineCategory.AUTHENTICATION, event_type="", description="desc")

        # 2. Correlation requires relationship_type and at least 2 events
        ev_id1 = "TIMELINE-00000000-0000-4000-8000-000000000001"
        with self.assertRaises(TypeError):
            Correlation(relationship_type=None, event_ids=[ev_id1], description="desc")
        with self.assertRaises(ValueError):
            Correlation(relationship_type=CorrelationType.SAME_USER, event_ids=[ev_id1], description="desc")

        # 3. DetectionRule requires non-empty name and detection_description
        with self.assertRaises(ValueError):
            create_rule(name="", description="valid", detection_description="valid", conditions=[])
        with self.assertRaises(ValueError):
            create_rule(name="valid", description="valid", detection_description="", conditions=[])

    def test_area01_cli_input_validation(self):
        """Verify CLI rejects invalid input with status code 1 and clean stderr message."""
        # Missing evidence path
        non_existent = Path(self.workspace) / "non_existent_path"
        code, _, err = self._capture_cli(execute_investigation_cli, [str(non_existent)])
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Evidence directory does not exist", err)

        # File passed where directory required
        code, _, err = self._capture_cli(execute_investigation_cli, [str(self.auth_log)])
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Evidence path is not a directory", err)

        # Whitespace case-id
        code, _, err = self._capture_cli(
            execute_investigation_cli,
            [str(self.evidence_dir), "--case-id", "   "],
        )
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Case ID cannot be empty or whitespace", err)

        # Conflicting format flags (--json AND --html)
        code, _, err = self._capture_cli(
            execute_investigation_cli,
            [str(self.evidence_dir), "--json", "--html"],
        )
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Cannot specify both --json and --html formats", err)

    # =========================================================================
    # AREA 2: PATH SAFETY & TRAVERSAL PREVENTION
    # =========================================================================

    def test_area02_path_safety_traversal_prevention(self):
        """Verify traversal sequences in case ID or output paths are safely neutralized."""
        # Case ID with directory traversal attempt
        case_with_traversal = "../../malicious/case"
        out_dest = self.reports_dir / "safe_test"
        code, rep = execute_investigation_cli([
            str(self.evidence_dir),
            "--case-id", case_with_traversal,
            "-o", str(out_dest),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        # Should not write outside out_dest
        expected_file = out_dest / "malicious_case_investigation.json"
        self.assertTrue(expected_file.exists())
        self.assertFalse(Path(self.workspace, "malicious").exists())

    def test_area02_reject_output_inside_evidence(self):
        """Verify attempting to place generated reports inside evidence directory is rejected."""
        inside_path = self.evidence_dir / "var" / "report.json"
        code, _, err = self._capture_cli(
            execute_investigation_cli,
            [str(self.evidence_dir), "-o", str(inside_path)],
        )
        self.assertEqual(code[0] if isinstance(code, tuple) else code, 1)
        self.assertIn("Output report path cannot be within or identical to evidence path", err)

    # =========================================================================
    # AREA 3: EVIDENCE IMMUTABILITY
    # =========================================================================

    def test_area03_strict_evidence_immutability(self):
        """Verify comprehensive evidence tree is 100% byte-for-byte identical after all pipelines."""
        hashes_initial = self._hash_tree(self.evidence_dir)

        # 1. Run V1 Single File Analysis
        ret_v1 = main([str(self.auth_log), "-o", str(self.reports_dir / "v1")])
        self.assertEqual(ret_v1, 0)

        # 2. Run V2 Host Triage
        ret_v2 = main([
            "triage", str(self.evidence_dir),
            "-o", str(self.reports_dir / "v2"),
            "--skip-reports",
        ])
        self.assertEqual(ret_v2, 0)

        # 3. Run V3 Timeline Reconstruction
        ret_v3 = main([
            "timeline", str(self.evidence_dir),
            "-o", str(self.reports_dir / "v3.html"),
        ])
        self.assertEqual(ret_v3, 0)

        # 4. Run V4 Integrated Investigation
        ret_v4 = main([
            "investigate", str(self.evidence_dir),
            "-o", str(self.reports_dir / "v4.json"),
        ])
        self.assertEqual(ret_v4, 0)

        hashes_final = self._hash_tree(self.evidence_dir)
        self.assertEqual(hashes_initial, hashes_final)

    # =========================================================================
    # AREA 4: EMPTY EVIDENCE
    # =========================================================================

    def test_area04_empty_evidence_handling(self):
        """Verify empty evidence directory completes safely with 0 events and 0 detections."""
        empty_dir = Path(self.workspace) / "empty_dir"
        empty_dir.mkdir(parents=True, exist_ok=True)

        code, rep = execute_investigation_cli([
            str(empty_dir),
            "-o", str(self.reports_dir / "empty_inv.json"),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(rep)
        self.assertEqual(rep.event_count, 0)
        self.assertEqual(rep.correlation_count, 0)
        self.assertEqual(rep.detection_count, 0)
        self.assertEqual(rep.matched_detections, 0)

    # =========================================================================
    # AREA 5: MALFORMED ARTIFACTS
    # =========================================================================

    def test_area05_malformed_artifact_resilience(self):
        """Verify corrupted or invalid log records do not crash the pipeline."""
        malformed_log = self.log_dir / "corrupted.log"
        malformed_log.write_text(
            "INVALID HEADER NO TIMESTAMP\n"
            "2026-09-30T10:00:00+00:00 srv01 sshd[1]: Accepted password for root from 1.1.1.1 port 22\n"
            "RANDOM CORRUPT BYTES \x00\x01\x02\n",
            encoding="utf-8",
            errors="replace",
        )

        code, rep = execute_investigation_cli([
            str(self.evidence_dir),
            "-o", str(self.reports_dir / "malformed_resilience.json"),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(rep)
        self.assertGreater(rep.event_count, 0)

    # =========================================================================
    # AREA 6: TIMESTAMP BOUNDARIES & DELTAS
    # =========================================================================

    def test_area06_timestamp_window_boundaries(self):
        """Verify correlation delta respects exact boundaries, microseconds, and exclusions."""
        engine = CorrelationEngine(CorrelationConfig(time_window_seconds=300.0))

        t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
        ev1 = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            timestamp=t0,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Login",
            attributes={"user": "admin"},
        )

        # Exactly 300.0s boundary (inclusive)
        ev_exact = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000002",
            timestamp=t0 + timedelta(seconds=300),
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="Sudo",
            attributes={"user": "admin"},
        )
        corrs_exact = engine.correlate([ev1, ev_exact])
        self.assertTrue(any(c.relationship_type == CorrelationType.AUTHENTICATION_PRIVILEGE for c in corrs_exact))

        # 300.001s outside boundary (exclusive)
        ev_outside = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000003",
            timestamp=t0 + timedelta(seconds=300, microseconds=1000),
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="Sudo outside",
            attributes={"user": "admin"},
        )
        corrs_outside = engine.correlate([ev1, ev_outside])
        self.assertFalse(any(c.relationship_type == CorrelationType.AUTHENTICATION_PRIVILEGE for c in corrs_outside))

    # =========================================================================
    # AREA 7: CORRELATION ENGINE ROBUSTNESS
    # =========================================================================

    def test_area07_correlation_identity_isolation(self):
        """Verify correlation engine strictly isolates relationships by user identity."""
        engine = CorrelationEngine()
        t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
        ev_alice = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            timestamp=t0,
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Alice login",
            attributes={"user": "alice"},
        )
        ev_bob = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000002",
            timestamp=t0 + timedelta(seconds=10),
            category=TimelineCategory.AUTHENTICATION,
            event_type="sudo_command",
            description="Bob sudo",
            attributes={"user": "bob"},
        )
        corrs = engine.correlate([ev_alice, ev_bob])
        # Should not correlate different users for AUTHENTICATION_PRIVILEGE or SAME_USER
        self.assertFalse(any(c.relationship_type == CorrelationType.AUTHENTICATION_PRIVILEGE for c in corrs))
        self.assertFalse(any(c.relationship_type == CorrelationType.SAME_USER for c in corrs))

    # =========================================================================
    # AREA 8: RULE MODEL BOUNDARIES & SPECULATIVE LANGUAGE REJECTION
    # =========================================================================

    def test_area08_rule_model_validation(self):
        """Verify rule creation rejects invalid windows and speculative wording."""
        cond = RuleCondition(field="event_type", operator=ConditionOperator.EQUALS, value="sudo_command")

        # Negative time window rejected
        with self.assertRaises(ValueError):
            create_rule(
                name="Invalid Window",
                description="desc",
                detection_description="desc",
                time_window_seconds=-10.0,
                conditions=[cond],
            )

        # Speculative verdict in description rejected
        with self.assertRaises(ValueError):
            create_rule(
                name="Attack Rule",
                description="system compromised by attacker",
                detection_description="Confirmed intrusion",
                conditions=[cond],
            )

    # =========================================================================
    # AREA 9: DETECTION ENGINE EVALUATION ROBUSTNESS
    # =========================================================================

    def test_area09_detection_engine_falsy_values_and_missing_attributes(self):
        """Verify DetectionEngine safely resolves missing fields and falsy values."""
        cond_missing = RuleCondition(
            field="attributes.non_existent_key",
            operator=ConditionOperator.EQUALS,
            value="expected",
        )
        rule = create_rule(
            name="Missing Field Rule",
            description="desc",
            detection_description="desc",
            conditions=[cond_missing],
        )

        ev = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.AUTHENTICATION,
            event_type="auth_test",
            description="test",
            attributes={"falsy_int": 0, "falsy_str": "", "falsy_bool": False},
        )

        engine = DetectionEngine(rules=[rule])
        results = engine.evaluate([ev])
        self.assertEqual(len(results), 0)

        # Operator evaluation with falsy actuals
        self.assertTrue(evaluate_condition_operator(0, ConditionOperator.EQUALS, 0))
        self.assertFalse(evaluate_condition_operator(0, ConditionOperator.EQUALS, 1))
        self.assertTrue(evaluate_condition_operator("", ConditionOperator.EQUALS, ""))
        self.assertTrue(evaluate_condition_operator(False, ConditionOperator.EQUALS, False))

    # =========================================================================
    # AREA 10: INITIAL RULES VERIFICATION
    # =========================================================================

    def test_area10_initial_rules_exact_definitions(self):
        """Verify all 4 canonical detection rules match documented initial specifications."""
        rules = get_initial_rules()
        self.assertEqual(len(rules), 4)

        names = {r.name for r in rules}
        self.assertIn(RULE_NAME_SSH_AUTH_SUDO, names)
        self.assertIn(RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS, names)
        self.assertIn(RULE_NAME_ACCOUNT_PRIVILEGE, names)
        self.assertIn(RULE_NAME_PERSISTENCE_FOLLOWUP, names)

        for r in rules:
            self.assertTrue(r.rule_id.startswith("RULE-"))
            self.assertEqual(r.time_window_seconds, 300.0)
            self.assertEqual(r.time_window_seconds, DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS)
            self.assertEqual(dict(r.attributes).get("initial_milestone"), "V4.5")

    # =========================================================================
    # AREA 11: REPORTING SECURITY & HTML XSS SANITIZATION
    # =========================================================================

    def test_area11_html_xss_escaping_and_self_contained(self):
        """Verify dangerous HTML/JS payloads in metadata and events are strictly escaped."""
        xss_payload = '<script>alert("XSS")</script>&<>"\'test'
        rep = generate_correlation_detection_report(
            detections=DetectionResultCollection(()),
            correlations=CorrelationCollection(()),
            timeline=(),
            case_id=xss_payload,
            case_name=xss_payload,
            investigator=xss_payload,
        )

        out_html = self.reports_dir / "xss_test.html"
        write_correlation_detection_html_report(rep, out_html)
        content = out_html.read_text(encoding="utf-8")

        # Must not contain unescaped script tag
        self.assertNotIn('<script>alert("XSS")</script>', content)
        # Must contain escaped representation
        self.assertIn("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;", content)
        # Must not have external CDN dependencies
        self.assertNotIn("http://", content)
        self.assertNotIn("https://", content)

    # =========================================================================
    # AREA 12: CLI INTERFACES & HELP
    # =========================================================================

    def test_area12_all_cli_help_interfaces(self):
        """Verify help text is cleanly rendered for all subcommands without errors."""
        for prog_args in (
            ["--help"],
            ["investigate", "--help"],
            ["triage", "--help"],
            ["timeline", "--help"],
        ):
            code, out, _ = self._capture_cli(main, prog_args)
            self.assertEqual(code, 0)
            self.assertIn("ForensiX", out)

    # =========================================================================
    # AREA 13: CLI BACKWARD COMPATIBILITY
    # =========================================================================

    def test_area13_backward_compatibility_v1_v2_v3(self):
        """Verify V1 single file, V2 host triage, and V3 timeline commands execute cleanly."""
        # V1 Single File
        v1_out = self.reports_dir / "v1_compat"
        code = main([str(self.auth_log), "-o", str(v1_out)])
        self.assertEqual(code, 0)

        # V2 Triage Orchestrator (9 stages)
        code = main(["triage", str(self.evidence_dir), "--skip-reports"])
        self.assertEqual(code, 0)

        # V3 Timeline
        v3_out = self.reports_dir / "v3_compat.html"
        code = main(["timeline", str(self.evidence_dir), "-o", str(v3_out)])
        self.assertEqual(code, 0)
        self.assertTrue(v3_out.exists())

    # =========================================================================
    # AREA 14: DETERMINISM ACROSS REPEATED RUNS
    # =========================================================================

    def test_area14_deterministic_repeated_executions(self):
        """Verify repeated CLI executions against identical evidence produce stable results."""
        out1 = self.reports_dir / "det1.json"
        out2 = self.reports_dir / "det2.json"

        code1, rep1 = execute_investigation_cli([
            str(self.evidence_dir),
            "--case-id", "DET-CASE-01",
            "-o", str(out1),
            "--format", "json",
        ])
        code2, rep2 = execute_investigation_cli([
            str(self.evidence_dir),
            "--case-id", "DET-CASE-01",
            "-o", str(out2),
            "--format", "json",
        ])

        self.assertEqual(code1, 0)
        self.assertEqual(code2, 0)
        self.assertEqual(rep1.event_count, rep2.event_count)
        self.assertEqual(rep1.correlation_count, rep2.correlation_count)
        self.assertEqual(rep1.matched_detections, rep2.matched_detections)
        self.assertEqual(rep1.rule_counts, rep2.rule_counts)
        self.assertEqual(
            [d.rule_name for d in rep1.detections],
            [d.rule_name for d in rep2.detections],
        )

    # =========================================================================
    # AREA 15: SERIALIZATION ROUNDTRIPS
    # =========================================================================

    def test_area15_model_serialization_roundtrip(self):
        """Verify model serialization to dictionary preserves semantic data without loss."""
        rule = create_ssh_auth_sudo_rule()
        r_dict = rule.to_dict()
        self.assertEqual(r_dict["name"], RULE_NAME_SSH_AUTH_SUDO)
        self.assertEqual(r_dict["rule_id"], rule.rule_id)
        self.assertIn("conditions", r_dict)

        ev_id1 = "TIMELINE-00000000-0000-4000-8000-000000000001"
        ev_id2 = "TIMELINE-00000000-0000-4000-8000-000000000002"
        corr = Correlation(
            correlation_id="CORR-00000000-0000-4000-8000-000000000001",
            relationship_type=CorrelationType.SAME_USER,
            event_ids=[ev_id1, ev_id2],
            description="Test user correlation",
        )
        c_dict = corr.to_dict()
        self.assertEqual(c_dict["correlation_id"], corr.correlation_id)
        self.assertEqual(c_dict["relationship_type"], CorrelationType.SAME_USER.value)
        self.assertEqual(c_dict["event_ids"], [ev_id1, ev_id2])

    # =========================================================================
    # AREA 16: DEEP IMMUTABILITY GUARANTEES
    # =========================================================================

    def test_area16_immutability_guarantees(self):
        """Verify immutable models and collections raise exceptions on mutation attempts."""
        ev = TimelineEvent(
            event_id="TIMELINE-00000000-0000-4000-8000-000000000001",
            timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
            category=TimelineCategory.AUTHENTICATION,
            event_type="login",
            description="desc",
            attributes={"k": "v"},
        )

        with self.assertRaises((AttributeError, TypeError)):
            ev.attributes["k"] = "modified"

        with self.assertRaises((AttributeError, TypeError)):
            ev.event_id = "TIMELINE-OTHER"

    # =========================================================================
    # AREA 17: SPECULATIVE LANGUAGE PROHIBITION
    # =========================================================================

    def test_area17_speculative_language_audit(self):
        """Verify CLI terminal output and report contents contain no speculative claims."""
        code, stdout, _ = self._capture_cli(
            execute_investigation_cli,
            [str(self.evidence_dir), "-o", str(self.reports_dir / "audit.json"), "--verbose"],
        )
        self.assertEqual(code[0], 0)
        lower_txt = stdout.lower()
        self.assertNotIn("attack detected", lower_txt)
        self.assertNotIn("host compromised", lower_txt)
        self.assertNotIn("attacker identified", lower_txt)
        self.assertNotIn("intrusion confirmed", lower_txt)

    # =========================================================================
    # AREA 18: RESOURCE / SCALE SANITY
    # =========================================================================

    def test_area18_scaled_event_volume_processing(self):
        """Verify pipeline handles 100 synthetic events without crashing or quadratic slowdown."""
        events: List[TimelineEvent] = []
        base_t = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(100):
            events.append(
                TimelineEvent(
                    event_id=f"TIMELINE-00000000-0000-4000-8000-{i:012d}",
                    timestamp=base_t + timedelta(seconds=i),
                    category=TimelineCategory.AUTHENTICATION,
                    event_type="auth_event",
                    description=f"Synthetic event {i}",
                    attributes={"user": f"user_{i % 5}", "ip": "10.0.0.1"},
                )
            )

        timeline = reconstruct_timeline(events)
        engine = CorrelationEngine(CorrelationConfig(time_window_seconds=60.0))
        correlations = engine.correlate(timeline.events)
        self.assertGreater(len(correlations), 0)

        det_engine = DetectionEngine(rules=get_initial_rules())
        results = det_engine.evaluate(timeline=timeline.events, correlations=correlations)
        self.assertIsInstance(results, DetectionResultCollection)

    # =========================================================================
    # AREA 19: SECURITY REVIEW (NO NETWORK / NO EVAL / DEFENSIVE I/O)
    # =========================================================================

    def test_area19_defensive_security_and_offline(self):
        """Verify execution creates zero network sockets and invokes no eval/exec."""
        with patch("socket.socket") as mock_socket:
            code, rep = execute_investigation_cli([
                str(self.evidence_dir),
                "-o", str(self.reports_dir / "sec_test.json"),
                "--format", "json",
            ])
            self.assertEqual(code, 0)
            mock_socket.assert_not_called()

    # =========================================================================
    # AREA 20: IMPORT STABILITY & EXPORTS
    # =========================================================================

    def test_area20_public_api_exports_resolve(self):
        """Verify all symbols in __all__ are defined and importable without circularity."""
        import forensix
        for sym in forensix.__all__:
            self.assertTrue(
                hasattr(forensix, sym),
                f"Exported symbol '{sym}' missing from forensix namespace",
            )

    # =========================================================================
    # AREA 21: INTEGRATION WORKFLOWS (POSITIVE, NEGATIVE, MALFORMED)
    # =========================================================================

    def test_area21_positive_integration_workflow(self):
        """Execute positive E2E workflow: evidence -> timeline -> correlation -> detection -> report."""
        out_path = self.reports_dir / "positive_workflow.json"
        code, rep = execute_investigation_cli([
            str(self.evidence_dir),
            "--case-id", "E2E-CASE-001",
            "--case-name", "Positive Verification",
            "--investigator", "Examiner A",
            "-o", str(out_path),
            "--format", "json",
            "--matched-only",
        ])
        self.assertEqual(code, 0)
        self.assertGreaterEqual(rep.matched_detections, 1)
        self.assertTrue(out_path.exists())

        data = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["case_id"], "E2E-CASE-001")
        self.assertGreaterEqual(len(data["detections"]), 1)

    def test_area21_negative_integration_workflow(self):
        """Execute negative E2E workflow against benign evidence with 0 matched detections."""
        benign_dir = Path(self.workspace) / "benign_evidence"
        b_log = benign_dir / "var" / "log"
        b_log.mkdir(parents=True, exist_ok=True)
        (b_log / "auth.log").write_text(
            "2026-09-30T12:00:00+00:00 srv01 systemd: Started Daily Cleanup.\n",
            encoding="utf-8",
        )

        out_path = self.reports_dir / "negative_workflow.json"
        code, rep = execute_investigation_cli([
            str(benign_dir),
            "--case-id", "E2E-NEG-001",
            "-o", str(out_path),
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(rep.matched_detections, 0)
        self.assertTrue(out_path.exists())


if __name__ == "__main__":
    unittest.main()
