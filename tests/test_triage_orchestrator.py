"""
Unit tests for ForensiX Triage Stage Execution & Failure Handling (V2.9.2).

Verifies:
1. Default stage ordering
2. Successful stage execution
3. Stage result creation
4. Disabled stage -> SKIPPED
5. Stage failure -> FAILED
6. Structured error propagation
7. Partial result handling
8. Dependency enforcement
9. Dependent stage skipped after required dependency failure
10. Independent stage continues after unrelated failure
11. Output propagation between stages
12. No fabricated stage output
13. Deterministic execution order
14. Final TriageResult construction
15. Source/evidence immutability
16. Zero subprocess execution
17. Zero network access
18. Empty/invalid configuration handling
19. Unexpected exception handling
20. Regression against V2.9.1 models
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.request

from forensix.audit import AuditEventType
from forensix.investigation import HostArtifactInvestigator, InvestigationResultSet
from forensix.report_models import ForensicReport
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
)
from forensix.triage_orchestrator import (
    STAGE_DEPENDENCIES,
    STAGE_NAMES,
    StageExecutionContext,
    TriageOrchestrator,
)
from forensix.unified_models import HostArtifactCollection


class TestTriageOrchestrator(unittest.TestCase):
    """Test suite for V2.9.2 triage stage execution, dependencies, and failure handling."""

    def setUp(self):
        """Create a mock Linux host evidence root for testing."""
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_test_evidence_")
        self.evidence_dir = Path(self.temp_dir) / "evidence"
        self.output_dir = Path(self.temp_dir) / "reports"

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup standard mock evidence layout: /etc, /var/log, /home, /root
        (self.evidence_dir / "etc").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "var" / "log").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "root" / ".ssh").mkdir(parents=True, exist_ok=True)

        # /etc/passwd
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "analyst:x:1001:1001:Lead Analyst:/home/analyst:/bin/bash\n"
        )
        (self.evidence_dir / "etc" / "passwd").write_text(passwd_content, encoding="utf-8")

        # /etc/group
        group_content = (
            "root:x:0:\n"
            "sudo:x:27:analyst\n"
            "analyst:x:1001:\n"
        )
        (self.evidence_dir / "etc" / "group").write_text(group_content, encoding="utf-8")

        # /etc/shadow
        shadow_content = (
            "root:*:19000:0:99999:7:::\n"
            "analyst:*:19000:0:99999:7:::\n"
        )
        (self.evidence_dir / "etc" / "shadow").write_text(shadow_content, encoding="utf-8")

        # /etc/crontab
        crontab_content = (
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        )
        (self.evidence_dir / "etc" / "crontab").write_text(crontab_content, encoding="utf-8")

        # /var/log/auth.log
        auth_log_content = (
            "Sep 30 14:00:01 forensic-host sshd[1234]: Accepted password for analyst from 192.168.1.50 port 54321 ssh2\n"
            "Sep 30 14:05:00 forensic-host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        )
        (self.evidence_dir / "var" / "log" / "auth.log").write_text(auth_log_content, encoding="utf-8")

    def tearDown(self):
        """Clean up temporary test artifacts."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_default_stage_ordering(self):
        """1. Verify TriageOrchestrator maintains exact approved stage order."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        expected_stages = list(ALL_TRIAGE_STAGES)
        actual_stages = [res.stage_id for res in result.stage_results]
        self.assertEqual(actual_stages, expected_stages)

    def test_02_successful_stage_execution(self):
        """2. Verify successful end-to-end execution across all enabled stages."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-EXEC-01",
            output_dir=str(self.output_dir),
            report_formats=("json", "csv"),
        )
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        self.assertTrue(result.summary.is_success)
        self.assertEqual(result.summary.stages_failed, 0)
        self.assertGreater(result.summary.stages_completed, 0)
        self.assertIsNotNone(result.artifacts)
        self.assertIsNotNone(result.investigator)
        self.assertIsNotNone(result.report)
        self.assertGreater(len(result.report_files), 0)

    def test_03_stage_result_creation(self):
        """3. Verify stage result creation with valid timing, counts, and metadata."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        for st in result.stage_results:
            self.assertIn(st.stage_id, ALL_TRIAGE_STAGES)
            self.assertIn(st.status, (TriageStageStatus.COMPLETED.value, TriageStageStatus.PARTIAL.value))
            self.assertIsNotNone(st.started_at)
            self.assertIsNotNone(st.completed_at)
            self.assertGreaterEqual(st.duration_seconds, 0.0)
            self.assertGreaterEqual(st.records_produced, 0)
            self.assertIsInstance(st.metadata, tuple)

    def test_04_disabled_stage_skipped(self):
        """4. Verify disabled stage results in explicit SKIPPED status."""
        # Enable all stages EXCEPT persistence_analysis
        enabled = tuple(s for s in ALL_TRIAGE_STAGES if s != TriageStage.PERSISTENCE_ANALYSIS.value)
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), enabled_stages=enabled)
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        persistence_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.PERSISTENCE_ANALYSIS.value
        )
        self.assertEqual(persistence_res.status, TriageStageStatus.SKIPPED.value)
        self.assertIn("disabled by configuration", persistence_res.warnings[0].lower())

    def test_05_stage_failure_failed(self):
        """5. Verify a failed stage produces FAILED status and does not crash the orchestrator."""
        non_existent_path = str(Path(self.temp_dir) / "does_not_exist_evidence")
        cfg = TriageConfig(evidence_path=non_existent_path)
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        ev_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.EVIDENCE_VALIDATION.value
        )
        self.assertEqual(ev_res.status, TriageStageStatus.FAILED.value)
        self.assertFalse(result.summary.is_success)
        self.assertEqual(result.summary.stages_failed, 1)
        self.assertEqual(len(ev_res.errors), 1)

    def test_06_structured_error_propagation(self):
        """6. Verify structured error information is recorded cleanly in TriageStageError."""
        non_existent_path = str(Path(self.temp_dir) / "does_not_exist_evidence")
        cfg = TriageConfig(evidence_path=non_existent_path)
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        ev_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.EVIDENCE_VALIDATION.value
        )
        err = ev_res.errors[0]
        self.assertEqual(err.stage_id, TriageStage.EVIDENCE_VALIDATION.value)
        self.assertEqual(err.error_type, "FileNotFoundError")
        self.assertIn("does not exist", err.error_message)
        d = err.to_dict()
        self.assertEqual(d["error_type"], "FileNotFoundError")

    def test_07_partial_result_handling(self):
        """7. Verify partial results when one specialized stage fails but others succeed."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def failing_persistence(ctx: StageExecutionContext) -> TriageStageResult:
            raise RuntimeError("Simulated failure in persistence parser")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.PERSISTENCE_ANALYSIS.value: failing_persistence},
        )
        result = orchestrator.run()

        # Persistence stage failed
        pers_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.PERSISTENCE_ANALYSIS.value
        )
        self.assertEqual(pers_res.status, TriageStageStatus.FAILED.value)

        # Unified host model completed with PARTIAL status
        unified_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.UNIFIED_HOST_MODEL.value
        )
        self.assertEqual(unified_res.status, TriageStageStatus.PARTIAL.value)
        self.assertTrue(any("partial" in w.lower() for w in unified_res.warnings))
        self.assertIsNotNone(result.artifacts)

    def test_08_dependency_enforcement(self):
        """8. Verify dependency rules are strictly defined and accessible."""
        self.assertEqual(STAGE_DEPENDENCIES[TriageStage.EVIDENCE_VALIDATION.value], ())
        self.assertEqual(
            STAGE_DEPENDENCIES[TriageStage.FILESYSTEM_COLLECTION.value],
            (TriageStage.EVIDENCE_VALIDATION.value,),
        )
        self.assertEqual(
            STAGE_DEPENDENCIES[TriageStage.AUTHENTICATION_ANALYSIS.value],
            (TriageStage.LOG_PARSING.value,),
        )
        self.assertEqual(
            STAGE_DEPENDENCIES[TriageStage.INVESTIGATION.value],
            (TriageStage.UNIFIED_HOST_MODEL.value,),
        )

    def test_09_dependent_stage_skipped_after_required_dependency_failure(self):
        """9. Verify dependent stage is skipped when a required dependency fails."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def failing_log_parsing(ctx: StageExecutionContext) -> TriageStageResult:
            raise IOError("Unreadable log partition")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.LOG_PARSING.value: failing_log_parsing},
        )
        result = orchestrator.run()

        log_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.LOG_PARSING.value
        )
        auth_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.AUTHENTICATION_ANALYSIS.value
        )

        self.assertEqual(log_res.status, TriageStageStatus.FAILED.value)
        # Auth analysis depends strictly on log_parsing -> must be SKIPPED
        self.assertEqual(auth_res.status, TriageStageStatus.SKIPPED.value)
        self.assertTrue(any("required predecessor 'log_parsing'" in w for w in auth_res.warnings))

    def test_10_independent_stage_continues_after_unrelated_failure(self):
        """10. Verify independent stage continues running after an unrelated failure."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def failing_log_parsing(ctx: StageExecutionContext) -> TriageStageResult:
            raise IOError("Simulated log failure")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.LOG_PARSING.value: failing_log_parsing},
        )
        result = orchestrator.run()

        # Account analysis depends only on evidence_validation, not log_parsing
        acct_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.ACCOUNT_ANALYSIS.value
        )
        pers_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.PERSISTENCE_ANALYSIS.value
        )

        self.assertEqual(acct_res.status, TriageStageStatus.COMPLETED.value)
        self.assertEqual(pers_res.status, TriageStageStatus.COMPLETED.value)

    def test_11_output_propagation_between_stages(self):
        """11. Verify intermediate outputs propagate faithfully to dependent stages."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        self.assertIsNotNone(result.artifacts)
        self.assertGreater(result.artifacts.total_artifacts, 0)
        self.assertIsNotNone(result.investigator)
        self.assertIsNotNone(result.investigation_result)
        self.assertEqual(
            result.investigation_result.total_matches,
            result.artifacts.total_artifacts,
        )

    def test_12_no_fabricated_stage_output(self):
        """12. Verify no fabricated output when a specialized category has no evidence."""
        # Evidence with no SSH keys or cron files
        empty_dir = Path(self.temp_dir) / "empty_evidence"
        empty_dir.mkdir(parents=True, exist_ok=True)

        cfg = TriageConfig(evidence_path=str(empty_dir))
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        # No artifacts fabricated
        if result.artifacts:
            self.assertEqual(result.artifacts.total_artifacts, 0)

    def test_13_deterministic_execution_order(self):
        """13. Verify deterministic execution order across repeated runs."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        order1 = [r.stage_id for r in res1.stage_results]
        order2 = [r.stage_id for r in res2.stage_results]
        self.assertEqual(order1, order2)
        self.assertEqual(order1, list(ALL_TRIAGE_STAGES))

    def test_14_final_triage_result_construction(self):
        """14. Verify final TriageResult aggregate contains all required metrics."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-FINAL-01",
            case_name="Final Validation Run",
            investigator="Forensic Examiner",
        )
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        self.assertTrue(result.triage_id.startswith("TRIAGE-"))
        self.assertEqual(result.summary.case_id, "CASE-FINAL-01")
        self.assertEqual(result.summary.case_name, "Final Validation Run")
        self.assertEqual(result.summary.investigator, "Forensic Examiner")
        self.assertEqual(len(result.stage_results), 9)

    def test_15_source_evidence_immutability(self):
        """15. Verify evidence directory files are not modified during triage execution."""
        passwd_file = self.evidence_dir / "etc" / "passwd"
        pre_mtime = passwd_file.stat().st_mtime_ns
        pre_hash = hashlib.sha256(passwd_file.read_bytes()).hexdigest()

        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)
        _ = orchestrator.run()

        post_mtime = passwd_file.stat().st_mtime_ns
        post_hash = hashlib.sha256(passwd_file.read_bytes()).hexdigest()

        self.assertEqual(pre_mtime, post_mtime)
        self.assertEqual(pre_hash, post_hash)

    def test_16_zero_subprocess_execution(self):
        """16. Verify zero subprocesses are spawned during triage execution."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)

        with patch("subprocess.Popen") as mock_popen, patch("os.system") as mock_system:
            _ = orchestrator.run()
            mock_popen.assert_not_called()
            mock_system.assert_not_called()

    def test_17_zero_network_access(self):
        """17. Verify zero network calls are attempted during triage execution."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)

        with patch("socket.socket") as mock_socket, patch("urllib.request.urlopen") as mock_urlopen:
            _ = orchestrator.run()
            mock_socket.assert_not_called()
            mock_urlopen.assert_not_called()

    def test_18_empty_invalid_configuration_handling(self):
        """18. Verify strict rejection of invalid or malformed configurations."""
        with self.assertRaises(TypeError):
            TriageOrchestrator(config="not_a_triage_config")  # type: ignore

        with self.assertRaises(ValueError):
            TriageOrchestrator(config=TriageConfig(evidence_path=str(self.evidence_dir)), extra_kw="bad")

    def test_19_unexpected_exception_handling(self):
        """19. Verify unexpected handler exceptions are safely caught and isolated."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def exploding_handler(ctx: StageExecutionContext) -> TriageStageResult:
            raise ArithmeticError("Unexpected division by zero in mock stage")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.PERSISTENCE_ANALYSIS.value: exploding_handler},
        )
        result = orchestrator.run()

        pers_res = next(
            r for r in result.stage_results if r.stage_id == TriageStage.PERSISTENCE_ANALYSIS.value
        )
        self.assertEqual(pers_res.status, TriageStageStatus.FAILED.value)
        self.assertEqual(pers_res.errors[0].error_type, "ArithmeticError")
        self.assertIn("division by zero", pers_res.errors[0].error_message)
        self.assertFalse(result.summary.is_success)

    def test_20_regression_against_v291_models(self):
        """20. Verify produced TriageResult is deeply immutable and JSON serializable."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="REGRESS-2026",
            output_dir=str(self.output_dir),
        )
        orchestrator = TriageOrchestrator(cfg)
        result = orchestrator.run()

        # Immutability checks
        with self.assertRaises(Exception):
            result.stage_results = ()  # type: ignore
        with self.assertRaises(Exception):
            result.triage_id = "MUTATED"  # type: ignore

        # JSON serialization check
        res_dict = result.to_dict()
        serialized = json.dumps(res_dict, indent=2)
        self.assertIsInstance(serialized, str)

        parsed = json.loads(serialized)
        self.assertEqual(parsed["summary"]["case_id"], "REGRESS-2026")
        self.assertEqual(len(parsed["stage_results"]), 9)


if __name__ == "__main__":
    unittest.main()
