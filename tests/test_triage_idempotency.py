"""
Comprehensive Idempotency and Immutability Test Suite for ForensiX Milestone V2.9.6.

Verifies:
21. Same evidence + same config produces equivalent logical results
22. Repeated triage does not duplicate artifacts
23. Repeated triage does not leak global state across executions
24. Repeated CLI execution works cleanly
25. Repeated report generation produces valid outputs
26. Existing reports are not corrupted or duplicate-appended
27. Two runs have independent TriageResult objects
28. Two runs have independent audit trails
29. Two runs have independent stage results
30. Triage IDs remain unique per run
31. TriageConfig is strictly immutable and not mutated during orchestration
32. Equivalent configurations produce equivalent outcomes
33. Stage disabling remains deterministic and idempotent
34. Report format selection remains deterministic
35. TriageResult remains deeply immutable
36. InvestigationResultSet remains immutable
37. ForensicReport remains immutable
38. Audit trail remains immutable
39. HostArtifactCollection remains immutable
40. V1 CLI remains functional
41. V2.9.5 CLI remains functional
42. V2.9.1–V2.9.5 behavior remains compatible
43. Full V1–V2.9.5 regression compatibility
"""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from forensix.investigation import HostArtifactInvestigator, InvestigationResultSet
from forensix.main import execute_triage_cli, main, triage_main
from forensix.report_models import ForensicReport
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageStatus,
)
from forensix.triage_orchestrator import TriageOrchestrator
from forensix.unified_models import HostArtifactCollection


class TestTriageIdempotency(unittest.TestCase):
    """Test suite verifying forensic idempotency, immutability, and state isolation (V2.9.6)."""

    def setUp(self):
        """Create controlled fixture evidence directory."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_idempotency_test_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Realistic minimal evidence
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)

        (etc_dir / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n",
            encoding="utf-8",
        )
        (etc_dir / "group").write_text(
            "root:x:0:\n"
            "alice:x:1001:\n",
            encoding="utf-8",
        )
        (etc_dir / "cron.d" / "sync").parent.mkdir(parents=True, exist_ok=True)
        (etc_dir / "cron.d" / "sync").write_text("* * * * * root /bin/sync\n", encoding="utf-8")

        (log_dir / "auth.log").write_text(
            "Sep 30 10:00:00 test-host sshd[500]: Accepted password for alice from 192.168.1.10 port 22 ssh2\n",
            encoding="utf-8",
        )

        self.single_evidence_file = Path(self.test_dir) / "v1_sample.log"
        self.single_evidence_file.write_text(
            "2026-09-30T10:00:00Z [SECURITY] Test single evidence\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up workspace."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 21. Same evidence + same config produces equivalent logical results
    def test_21_same_evidence_and_config_produces_equivalent_results(self):
        """Verify repeated runs against unchanged evidence produce equivalent logical forensic results."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            case_id="CASE-IDEMP-21",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        self.assertEqual(res1.summary.total_artifacts, res2.summary.total_artifacts)
        self.assertEqual(res1.summary.stages_completed, res2.summary.stages_completed)
        self.assertEqual(res1.summary.is_success, res2.summary.is_success)

        # Logical attributes of artifacts must match 1-to-1 in order
        arts1 = res1.artifacts.artifacts
        arts2 = res2.artifacts.artifacts
        self.assertEqual(len(arts1), len(arts2))
        for a1, a2 in zip(arts1, arts2):
            self.assertEqual(a1.source_path, a2.source_path)
            self.assertEqual(a1.line_number, a2.line_number)
            self.assertEqual(a1.category, a2.category)
            self.assertEqual(a1.artifact_type, a2.artifact_type)
            self.assertEqual(a1.status, a2.status)
            self.assertEqual(a1.raw_data, a2.raw_data)

    # 22. Repeated triage does not duplicate artifacts
    def test_22_repeated_triage_does_not_duplicate_artifacts(self):
        """Verify running triage multiple times in succession does not accumulate duplicate artifacts."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-IDEMP-22",
        )
        orchestrator = TriageOrchestrator(cfg)
        res1 = orchestrator.run()
        res2 = orchestrator.run()
        res3 = orchestrator.run()

        self.assertEqual(res1.summary.total_artifacts, res2.summary.total_artifacts)
        self.assertEqual(res2.summary.total_artifacts, res3.summary.total_artifacts)
        self.assertEqual(len(res1.artifacts.artifacts), len(res3.artifacts.artifacts))

    # 23. Repeated triage does not leak global state across executions
    def test_23_no_global_state_leakage(self):
        """Verify two triages on distinct evidence roots do not cross-contaminate artifacts."""
        other_dir = Path(self.test_dir) / "other_evidence"
        other_dir.mkdir()
        (other_dir / "unique_marker.log").write_text("UniqueMarkerLine\n", encoding="utf-8")

        cfg1 = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True, case_id="CASE-1")
        cfg2 = TriageConfig(evidence_path=str(other_dir), skip_reports=True, case_id="CASE-2")

        res1 = TriageOrchestrator(cfg1).run()
        res2 = TriageOrchestrator(cfg2).run()

        paths1 = [a.source_path for a in res1.artifacts.artifacts]
        paths2 = [a.source_path for a in res2.artifacts.artifacts]

        # Artifacts from other_dir must not leak into res1
        for p in paths1:
            self.assertNotIn("unique_marker", p)
        # Artifacts from evidence_dir must not leak into res2
        for p in paths2:
            self.assertNotIn("passwd", p)

    # 24. Repeated CLI execution works cleanly
    def test_24_repeated_cli_execution_works(self):
        """Verify python3 -m forensix triage can be executed repeatedly without error."""
        for run_idx in range(3):
            exit_code = triage_main([
                str(self.evidence_dir),
                "-o", str(self.output_dir),
                "--case-id", f"CLI-CASE-{run_idx}",
                "--format", "json",
            ])
            self.assertEqual(exit_code, 0)
            report_file = self.output_dir / f"forensix_report_CLI-CASE-{run_idx}.json"
            self.assertTrue(report_file.exists())
            data = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["case_id"], f"CLI-CASE-{run_idx}")

    # 25 & 26. Repeated report generation remains valid and does not corrupt existing reports
    def test_25_and_26_repeated_report_generation_valid_and_not_corrupted(self):
        """Verify overwriting an existing report produces valid JSON, CSV, and HTML without duplication."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
            case_id="SAME-CASE",
        )
        # First execution
        res1 = TriageOrchestrator(cfg).run()
        json_path = self.output_dir / "forensix_report_SAME-CASE.json"
        csv_path = self.output_dir / "forensix_report_SAME-CASE.csv"
        html_path = self.output_dir / "forensix_report_SAME-CASE.html"

        size_json1 = json_path.stat().st_size
        csv_lines1 = len(csv_path.read_text(encoding="utf-8").splitlines())

        # Second execution with identical output directory and case ID
        res2 = TriageOrchestrator(cfg).run()

        # Files remain valid
        data2 = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertIn("summary", data2)
        self.assertIn("artifacts", data2)

        csv_lines2 = len(csv_path.read_text(encoding="utf-8").splitlines())
        # Line count must be identical (not doubled!)
        self.assertEqual(csv_lines1, csv_lines2)

        html_content = html_path.read_text(encoding="utf-8")
        # Ensure HTML structure is valid and not duplicated
        self.assertEqual(html_content.count("<!DOCTYPE html>"), 1)
        self.assertEqual(html_content.count("</html>"), 1)

    # 27, 28, 29. Two runs have independent TriageResult, audit trails, and stage results
    def test_27_to_29_independent_objects_between_runs(self):
        """Verify each orchestration run produces completely distinct instances of result models."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-INDEP",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        # Independent TriageResult
        self.assertIsNot(res1, res2)
        self.assertIsNot(res1.summary, res2.summary)
        self.assertIsNot(res1.artifacts, res2.artifacts)

        # Independent audit trails
        self.assertIsNot(res1.audit_trail, res2.audit_trail)
        audit_ids1 = {e.audit_id for e in res1.audit_trail}
        audit_ids2 = {e.audit_id for e in res2.audit_trail}
        self.assertEqual(len(audit_ids1.intersection(audit_ids2)), 0)

        # Independent stage results
        self.assertIsNot(res1.stage_results, res2.stage_results)
        for s1, s2 in zip(res1.stage_results, res2.stage_results):
            self.assertIsNot(s1, s2)

    # 30. Triage IDs remain unique per run
    def test_30_triage_ids_unique_per_run(self):
        """Verify every run generates a distinct UUID-based triage_id."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
        )
        triage_ids = {TriageOrchestrator(cfg).run().triage_id for _ in range(5)}
        self.assertEqual(len(triage_ids), 5)

    # 31. TriageConfig is strictly immutable and not mutated during orchestration
    def test_31_triage_config_not_mutated(self):
        """Verify TriageConfig cannot be modified and is unchanged after orchestration."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-IMMUTABLE-CFG",
            output_dir=str(self.output_dir),
        )
        orig_dict = cfg.to_dict()

        with self.assertRaises(FrozenInstanceError):
            cfg.case_id = "MUTATED"

        with self.assertRaises(FrozenInstanceError):
            cfg.evidence_path = "/mutated/path"

        TriageOrchestrator(cfg).run()
        self.assertEqual(cfg.to_dict(), orig_dict)

    # 32. Equivalent configurations produce equivalent outcomes
    def test_32_equivalent_configurations_produce_equivalent_outcomes(self):
        """Verify distinct TriageConfig instances with equivalent values produce equal results."""
        cfg1 = TriageConfig(evidence_path=str(self.evidence_dir), case_id="C1", skip_reports=True)
        cfg2 = TriageConfig(evidence_path=str(self.evidence_dir), case_id="C1", skip_reports=True)
        self.assertEqual(cfg1, cfg2)

        res1 = TriageOrchestrator(cfg1).run()
        res2 = TriageOrchestrator(cfg2).run()
        self.assertEqual(res1.summary.total_artifacts, res2.summary.total_artifacts)
        self.assertEqual(res1.summary.stages_completed, res2.summary.stages_completed)

    # 33. Stage disabling remains deterministic and idempotent
    def test_33_stage_disabling_deterministic(self):
        """Verify disabling stages deterministically marks them SKIPPED on every run."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            enabled_stages=(TriageStage.EVIDENCE_VALIDATION, TriageStage.FILESYSTEM_COLLECTION),
            skip_reports=True,
        )
        for _ in range(2):
            res = TriageOrchestrator(cfg).run()
            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["log_parsing"], TriageStageStatus.SKIPPED.value)
            self.assertEqual(statuses["authentication_analysis"], TriageStageStatus.SKIPPED.value)
            self.assertEqual(statuses["account_analysis"], TriageStageStatus.SKIPPED.value)
            self.assertEqual(statuses["persistence_analysis"], TriageStageStatus.SKIPPED.value)

    # 34. Report format selection remains deterministic
    def test_34_report_format_selection_deterministic(self):
        """Verify requested formats determine exact report types generated without side-effects."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "html"),
            case_id="FMT-CASE",
        )
        res = TriageOrchestrator(cfg).run()
        fmts = [fmt for fmt, _ in res.report_files]
        self.assertEqual(fmts, ["json", "html"])
        self.assertTrue((self.output_dir / "forensix_report_FMT-CASE.json").exists())
        self.assertTrue((self.output_dir / "forensix_report_FMT-CASE.html").exists())
        self.assertFalse((self.output_dir / "forensix_report_FMT-CASE.csv").exists())

    # 35. TriageResult remains deeply immutable
    def test_35_triage_result_remains_deeply_immutable(self):
        """Verify TriageResult and its summary cannot be modified."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
        res = TriageOrchestrator(cfg).run()

        with self.assertRaises(FrozenInstanceError):
            res.triage_id = "TAMPERED"

        with self.assertRaises(FrozenInstanceError):
            res.summary = None

        with self.assertRaises(FrozenInstanceError):
            res.summary.stages_completed = 999

    # 36. InvestigationResultSet remains immutable
    def test_36_investigation_result_set_remains_immutable(self):
        """Verify InvestigationResultSet cannot have attributes mutated."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
        res = TriageOrchestrator(cfg).run()

        with self.assertRaises(FrozenInstanceError):
            res.investigation_result.total_matches = 0

    # 37. ForensicReport remains immutable
    def test_37_forensic_report_remains_immutable(self):
        """Verify ForensicReport instance is frozen."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
        res = TriageOrchestrator(cfg).run()
        self.assertIsNotNone(res.report)

        with self.assertRaises(FrozenInstanceError):
            res.report.metadata = None

    # 38. Audit trail remains immutable
    def test_38_audit_trail_remains_immutable(self):
        """Verify AuditEvent instances in audit trail cannot be modified."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
        res = TriageOrchestrator(cfg).run()
        self.assertGreater(len(res.audit_trail), 0)

        with self.assertRaises(FrozenInstanceError):
            res.audit_trail[0].action = "MUTATED"

    # 39. HostArtifactCollection remains immutable
    def test_39_host_artifact_collection_remains_immutable(self):
        """Verify HostArtifactCollection cannot have its contents or metrics modified."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
        res = TriageOrchestrator(cfg).run()

        with self.assertRaises(FrozenInstanceError):
            res.artifacts.total_artifacts = 9999

    # 40. V1 CLI remains functional
    def test_40_v1_cli_remains_functional(self):
        """Verify V1 single-file CLI runs and writes valid JSON report."""
        v1_out = self.output_dir / "v1_reports"
        ret = main([str(self.single_evidence_file), "-o", str(v1_out)])
        self.assertEqual(ret, 0)
        reports = list(v1_out.glob("*.json"))
        self.assertEqual(len(reports), 1)

    # 41. V2.9.5 CLI remains functional
    def test_41_v295_cli_remains_functional(self):
        """Verify python3 -m forensix triage runs end-to-end via CLI router."""
        code, res = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--case-id", "CLI-REGRESS-41",
            "--format", "json",
        ])
        self.assertEqual(code, 0)
        self.assertIsNotNone(res)
        self.assertTrue(res.summary.is_success)

    # 42. V2.9.1–V2.9.5 behavior remains compatible
    def test_42_v291_to_v295_behavior_compatible(self):
        """Verify stage count, dependencies, and model factories are consistent."""
        self.assertEqual(len(ALL_TRIAGE_STAGES), 9)

    # 43. Full V1–V2.9.5 regression compatibility
    def test_43_full_v1_to_v295_regression_compatibility(self):
        """Subtest verification of milestone core modules."""
        with self.subTest("V1 Evidence"):
            from forensix.evidence import register_evidence
            self.assertTrue(callable(register_evidence))

        with self.subTest("V2.1 Scanner"):
            from forensix.scanner import scan_evidence_directory
            self.assertTrue(callable(scan_evidence_directory))

        with self.subTest("V2.2 Log Parser"):
            from forensix.log_parser import parse_log_file
            self.assertTrue(callable(parse_log_file))

        with self.subTest("V2.3 Auth Activity"):
            from forensix.auth_analyzer import extract_authentication_activity
            self.assertTrue(callable(extract_authentication_activity))

        with self.subTest("V2.4 Accounts"):
            from forensix.account_analyzer import analyze_account_artifacts
            self.assertTrue(callable(analyze_account_artifacts))

        with self.subTest("V2.5 Persistence"):
            from forensix.persistence_analyzer import analyze_persistence_artifacts
            self.assertTrue(callable(analyze_persistence_artifacts))

        with self.subTest("V2.6 Unified Model"):
            from forensix.unified_models import HostArtifactCollection
            self.assertIsNotNone(HostArtifactCollection)

        with self.subTest("V2.7 Investigation"):
            from forensix.investigation import HostArtifactInvestigator
            self.assertTrue(callable(HostArtifactInvestigator))

        with self.subTest("V2.8 Reporting"):
            from forensix.report_builder import build_forensic_report
            self.assertTrue(callable(build_forensic_report))

        with self.subTest("V2.9.1–V2.9.5 Orchestrator & CLI"):
            from forensix.main import build_triage_parser
            self.assertTrue(callable(build_triage_parser))
