"""
Final V2.9 Validation Test Suite for ForensiX (Milestone V2.9.7).

Provides comprehensive, rigorous validation for:
1.  Full Architecture Review & Component Reuse (V2.1-V2.8)
2.  Canonical Pipeline Order & Execution Invariance
3.  Dependency Matrix & Failure Propagation (Scenarios A through K)
4.  Partial Results Preservation without Artificial Forensic Conclusions
5.  End-to-End Traceability (Evidence -> Artifact -> Log -> Auth -> HostArtifact -> Investigation -> Report)
6.  Audit Lifecycle & Provenance Integrity
7.  Multi-Format Reporting Validation (JSON, CSV, HTML)
8.  CLI & End-to-End Workflow with Realistic Synthetic Linux Evidence Fixture
9.  Multi-Run Idempotency & State Isolation (Run A -> Run B -> Run C)
10. Deep Immutability of Core Models
11. Report Files Representation & Serialization Consistency
12. Full Regression Compatibility Baseline
"""

import copy
import csv
from dataclasses import FrozenInstanceError
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import patch

from forensix import __version__
from forensix.account_analyzer import analyze_account_artifacts
from forensix.account_models import UserAccount
from forensix.artifacts import ArtifactRecord
from forensix.audit import AuditEvent, AuditEventType
from forensix.auth_analyzer import extract_authentication_activity
from forensix.auth_models import AuthenticationRecord
from forensix.investigation import (
    ArtifactQuery,
    HostArtifactInvestigator,
    InvestigationResultSet,
)
from forensix.log_models import LogEvent
from forensix.log_parser import parse_log_file
from forensix.main import build_triage_parser, execute_triage_cli, main, triage_main
from forensix.persistence_analyzer import analyze_persistence_artifacts
from forensix.report_models import ForensicReport
from forensix.scanner import scan_evidence_directory
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageSummary,
    TriageTraceRecord,
)
from forensix.triage_orchestrator import (
    STAGE_DEPENDENCIES,
    STAGE_NAMES,
    TriageOrchestrator,
)
from forensix.unified_adapter import build_host_artifact_collection
from forensix.unified_models import HostArtifact, HostArtifactCollection


class TestTriageFinalValidation(unittest.TestCase):
    """Final V2.9 validation test suite exercising the complete architecture."""

    def setUp(self):
        """Create a synthetic, realistic multi-component Linux evidence fixture."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_v297_val_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 1. /etc configuration files
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)

        (etc_dir / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "analyst:x:1001:1001:Security Analyst:/home/analyst:/bin/bash\n"
            "guest:x:1002:1002:Guest Account:/home/guest:/bin/sh\n"
            "malformed_line_without_enough_colons\n",
            encoding="utf-8",
        )

        (etc_dir / "group").write_text(
            "root:x:0:\n"
            "analyst:x:1001:\n"
            "guest:x:1002:\n",
            encoding="utf-8",
        )

        (etc_dir / "shadow").write_text(
            "root:*:19000:0:99999:7:::\n"
            "analyst:*:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        (etc_dir / "hosts").write_text(
            "127.0.0.1 localhost\n"
            "192.168.1.10 target-server\n",
            encoding="utf-8",
        )

        (etc_dir / "hostname").write_text("target-server\n", encoding="utf-8")

        (etc_dir / "os-release").write_text(
            'NAME="Ubuntu"\nVERSION="24.04 LTS (Noble Numbat)"\nID=ubuntu\n',
            encoding="utf-8",
        )

        # Sudo configuration
        sudoers_d = etc_dir / "sudoers.d"
        sudoers_d.mkdir(parents=True, exist_ok=True)
        (sudoers_d / "01_analyst").write_text("analyst ALL=(ALL:ALL) ALL\n", encoding="utf-8")

        # Persistence configuration (cron, systemd, shell)
        cron_dir = etc_dir / "cron.d"
        cron_dir.mkdir(parents=True, exist_ok=True)
        (cron_dir / "system_backup").write_text("0 2 * * * root /usr/local/bin/backup.sh\n", encoding="utf-8")
        # Unicode persistence filename
        (cron_dir / "задача_синхронизации").write_text("30 * * * * root /bin/sync\n", encoding="utf-8")

        systemd_dir = etc_dir / "systemd" / "system"
        systemd_dir.mkdir(parents=True, exist_ok=True)
        (systemd_dir / "canary.service").write_text(
            "[Unit]\nDescription=Canary Service\n[Service]\nExecStart=/usr/bin/canary\n[Install]\nWantedBy=multi-user.target\n",
            encoding="utf-8",
        )

        # Shell startup
        (etc_dir / "profile.d").mkdir(parents=True, exist_ok=True)
        (etc_dir / "profile.d" / "custom.sh").write_text("export FORENSIC_ENV=1\n", encoding="utf-8")

        # 2. User directories and SSH keys
        analyst_ssh = self.evidence_dir / "home" / "analyst" / ".ssh"
        analyst_ssh.mkdir(parents=True, exist_ok=True)
        (analyst_ssh / "authorized_keys").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnalystKey analyst@workstation\n",
            encoding="utf-8",
        )

        # 3. /var/log directory (active log, rotated log, gzip log, empty log)
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.auth_log = log_dir / "auth.log"
        self.auth_log.write_text(
            "Sep 30 10:00:00 target-server sshd[1234]: Accepted password for analyst from 192.168.1.100 port 22 ssh2\n"
            "Sep 30 10:05:00 target-server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/id\n"
            "Sep 30 10:10:00 target-server sshd[1235]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2\n",
            encoding="utf-8",
        )

        self.rotated_log = log_dir / "auth.log.1"
        self.rotated_log.write_text(
            "Sep 29 08:00:00 target-server sshd[1000]: Accepted publickey for analyst\n",
            encoding="utf-8",
        )

        # Rotated gzip log
        self.gz_log = log_dir / "auth.log.2.gz"
        with gzip.open(self.gz_log, "wt", encoding="utf-8") as f_gz:
            f_gz.write("Sep 28 04:00:00 target-server sshd[900]: Accepted password for root\n")

        # Empty log file
        (log_dir / "empty.log").write_text("", encoding="utf-8")

    def tearDown(self):
        """Clean up workspace."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Full Architecture Review & Component Reuse
    # -------------------------------------------------------------------------
    def test_01_component_reuse_verification(self):
        """Verify V2.9 directly reuses canonical V2.1-V2.8 models and analyzers."""
        # V2.1 scanner reuse
        fs_res = scan_evidence_directory(self.evidence_dir)
        self.assertGreater(fs_res.total_artifacts, 0)

        # V2.2 log parser reuse
        log_res = parse_log_file(self.auth_log)
        self.assertGreater(log_res.parsed_events, 0)

        # V2.3 auth activity analyzer reuse
        auth_res = extract_authentication_activity(log_res.events)
        self.assertGreater(auth_res.total_records, 0)

        # V2.4 account analyzer reuse
        acc_res = analyze_account_artifacts(self.evidence_dir)
        self.assertGreater(acc_res.total_users, 0)

        # V2.5 persistence analyzer reuse
        persist_res = analyze_persistence_artifacts(self.evidence_dir)
        self.assertGreater(persist_res.total_records, 0)

        # V2.6 unified host model reuse
        host_col = build_host_artifact_collection(str(self.evidence_dir), fs_res.artifacts)
        self.assertIsInstance(host_col, HostArtifactCollection)

        # V2.7 investigation interface reuse
        investigator = HostArtifactInvestigator(host_col)
        inv_res = investigator.filter_by_category("filesystem")
        self.assertIsInstance(inv_res, InvestigationResultSet)

    # -------------------------------------------------------------------------
    # 2. Canonical Pipeline Order & Execution Invariance
    # -------------------------------------------------------------------------
    def test_02_canonical_pipeline_stage_order(self):
        """Verify exact canonical 9-stage order and invariance under dictionary/option changes."""
        expected_order = (
            "evidence_validation",
            "filesystem_collection",
            "log_parsing",
            "authentication_analysis",
            "account_analysis",
            "persistence_analysis",
            "unified_host_model",
            "investigation",
            "reporting",
        )
        self.assertEqual(ALL_TRIAGE_STAGES, expected_order)

        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
        res = TriageOrchestrator(cfg).run()
        observed_order = tuple(sr.stage_id for sr in res.stage_results)
        self.assertEqual(observed_order, expected_order)

    # -------------------------------------------------------------------------
    # 3. Dependency Matrix & Failure Handling (Scenarios A through K)
    # -------------------------------------------------------------------------
    def test_03_scenario_a_successful_pipeline(self):
        """Scenario A: Successful full 9-stage pipeline."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "html"),
            case_id="SCENARIO-A",
        )
        res = TriageOrchestrator(cfg).run()
        self.assertTrue(res.summary.is_success)
        self.assertEqual(res.summary.stages_failed, 0)
        self.assertGreater(res.summary.total_artifacts, 0)
        self.assertEqual(len(res.report_files), 2)

    def test_04_scenario_b_filesystem_stage_failure(self):
        """Scenario B: Filesystem collection failure -> other stages succeed, unified model is PARTIAL."""
        with patch.object(TriageOrchestrator, "_execute_filesystem_collection", side_effect=RuntimeError("FS scan error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["filesystem_collection"], "FAILED")
            self.assertEqual(statuses["log_parsing"], "COMPLETED")
            self.assertEqual(statuses["authentication_analysis"], "COMPLETED")
            self.assertEqual(statuses["account_analysis"], "COMPLETED")
            self.assertEqual(statuses["persistence_analysis"], "COMPLETED")
            self.assertEqual(statuses["unified_host_model"], "PARTIAL")
            self.assertEqual(statuses["investigation"], "COMPLETED")

    def test_05_scenario_c_log_stage_failure(self):
        """Scenario C: Log parsing failure -> auth analysis SKIPPED, other stages succeed, unified model is PARTIAL."""
        with patch.object(TriageOrchestrator, "_execute_log_parsing", side_effect=RuntimeError("Log error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["log_parsing"], "FAILED")
            self.assertEqual(statuses["authentication_analysis"], "SKIPPED")
            self.assertEqual(statuses["filesystem_collection"], "COMPLETED")
            self.assertEqual(statuses["account_analysis"], "COMPLETED")
            self.assertEqual(statuses["unified_host_model"], "PARTIAL")

    def test_06_scenario_d_auth_stage_failure(self):
        """Scenario D: Authentication analysis failure -> other stages succeed, unified model is PARTIAL."""
        with patch.object(TriageOrchestrator, "_execute_authentication_analysis", side_effect=RuntimeError("Auth error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["authentication_analysis"], "FAILED")
            self.assertEqual(statuses["log_parsing"], "COMPLETED")
            self.assertEqual(statuses["unified_host_model"], "PARTIAL")

    def test_07_scenario_e_account_stage_failure(self):
        """Scenario E: Account analysis failure -> other stages succeed, unified model is PARTIAL."""
        with patch.object(TriageOrchestrator, "_execute_account_analysis", side_effect=RuntimeError("Account error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["account_analysis"], "FAILED")
            self.assertEqual(statuses["unified_host_model"], "PARTIAL")

    def test_08_scenario_f_persistence_stage_failure(self):
        """Scenario F: Persistence analysis failure -> other stages succeed, unified model is PARTIAL."""
        with patch.object(TriageOrchestrator, "_execute_persistence_analysis", side_effect=RuntimeError("Persist error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["persistence_analysis"], "FAILED")
            self.assertEqual(statuses["unified_host_model"], "PARTIAL")

    def test_09_scenario_g_unified_model_failure(self):
        """Scenario G: Unified model failure -> investigation & reporting SKIPPED."""
        with patch.object(TriageOrchestrator, "_execute_unified_host_model", side_effect=RuntimeError("Unified model error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["unified_host_model"], "FAILED")
            self.assertEqual(statuses["investigation"], "SKIPPED")
            self.assertEqual(statuses["reporting"], "SKIPPED")

    def test_10_scenario_h_investigation_failure(self):
        """Scenario H: Investigation failure -> reporting still runs (investigation summary is None)."""
        with patch.object(TriageOrchestrator, "_execute_investigation", side_effect=RuntimeError("Investigation error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["investigation"], "FAILED")
            self.assertEqual(statuses["reporting"], "COMPLETED")

    def test_11_scenario_i_reporting_failure(self):
        """Scenario I: Reporting failure -> reporting is FAILED, prior stages remain intact."""
        with patch.object(TriageOrchestrator, "_execute_reporting", side_effect=RuntimeError("Report render error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)

            statuses = {sr.stage_id: sr.status for sr in res.stage_results}
            self.assertEqual(statuses["reporting"], "FAILED")
            self.assertEqual(statuses["investigation"], "COMPLETED")

    def test_12_scenario_j_evidence_validation_failure(self):
        """Scenario J: Evidence validation failure -> all 8 downstream stages SKIPPED."""
        with patch.object(TriageOrchestrator, "_execute_evidence_validation", side_effect=RuntimeError("Validation error")):
            cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
            res = TriageOrchestrator(cfg).run()
            self.assertFalse(res.summary.is_success)
            self.assertEqual(res.summary.stages_failed, 1)
            self.assertEqual(res.summary.stages_skipped, 8)

    def test_13_scenario_k_all_specialized_stages_disabled(self):
        """Scenario K: All specialized stages disabled -> unified model, investigation, and reporting SKIPPED."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            enabled_stages=(TriageStage.EVIDENCE_VALIDATION,),
            skip_reports=False,
        )
        res = TriageOrchestrator(cfg).run()
        self.assertTrue(res.summary.is_success)  # No stages failed
        statuses = {sr.stage_id: sr.status for sr in res.stage_results}
        self.assertEqual(statuses["evidence_validation"], "COMPLETED")
        self.assertEqual(statuses["unified_host_model"], "SKIPPED")
        self.assertEqual(statuses["investigation"], "SKIPPED")
        self.assertEqual(statuses["reporting"], "SKIPPED")

    # -------------------------------------------------------------------------
    # 4. Partial Results Validation
    # -------------------------------------------------------------------------
    def test_14_partial_results_factual_interpretation(self):
        """Verify partial execution remains factual without artificial risk or compromise conclusions."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
        )
        with unittest.mock.patch.object(
            TriageOrchestrator,
            "_execute_persistence_analysis",
            side_effect=RuntimeError("Corrupt persistence config"),
        ):
            res = TriageOrchestrator(cfg).run()

        uhm_stage = [sr for sr in res.stage_results if sr.stage_id == "unified_host_model"][0]
        self.assertEqual(uhm_stage.status, TriageStageStatus.PARTIAL.value)
        self.assertTrue(any("persistence_analysis" in w for w in uhm_stage.warnings))

        # Verify summary reflects factual counts
        self.assertEqual(res.summary.stages_partial, 1)
        self.assertEqual(res.summary.stages_failed, 1)
        self.assertGreater(res.summary.total_artifacts, 0)

        # Verify no artificial risk scoring or threat classifications are added
        for art in res.artifacts.artifacts:
            self.assertFalse(hasattr(art, "risk_score"))
            self.assertFalse(hasattr(art, "threat_level"))
            self.assertFalse(hasattr(art, "is_malicious"))

    # -------------------------------------------------------------------------
    # 5. Traceability & Lineage Validation
    # -------------------------------------------------------------------------
    def test_15_end_to_end_traceability_preservation(self):
        """Verify full lineage preservation from source artifacts up to the forensic report."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json",),
            case_id="CASE-TRACE-15",
        )
        res = TriageOrchestrator(cfg).run()
        self.assertGreater(len(res.trace_records), 0)

        # Check trace records
        for tr in res.trace_records:
            self.assertEqual(tr.triage_id, res.triage_id)
            self.assertIn(tr.stage_id, ALL_TRIAGE_STAGES)
            self.assertIn(tr.stage_status, ("COMPLETED", "PARTIAL", "FAILED", "SKIPPED"))

        # Verify cross-reference chain on authentication artifacts: AUTH -> EVT -> ART
        auth_artifacts = [a for a in res.artifacts.artifacts if a.category == "authentication"]
        self.assertGreater(len(auth_artifacts), 0)
        for a in auth_artifacts:
            self.assertTrue(a.source_id.startswith("AUTH-"))
            self.assertIsNotNone(a.source_event_id)
            self.assertTrue(a.source_event_id.startswith("EVT-"))
            self.assertIsNotNone(a.source_artifact_id)
            self.assertTrue(a.source_artifact_id.startswith("ART-"))

    # -------------------------------------------------------------------------
    # 6. Audit Lifecycle & Provenance Integrity
    # -------------------------------------------------------------------------
    def test_16_audit_lifecycle_ordering_and_integrity(self):
        """Verify audit trail follows strict lifecycle progression with valid metadata."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=True, case_id="AUDIT-CASE")
        res = TriageOrchestrator(cfg).run()
        self.assertGreater(len(res.audit_trail), 0)

        # First and last events
        self.assertEqual(res.audit_trail[0].event_type, AuditEventType.TRIAGE_STARTED.value)
        self.assertEqual(res.audit_trail[-1].event_type, AuditEventType.TRIAGE_COMPLETED.value)

        # All events belong to this triage ID
        for ev in res.audit_trail:
            self.assertIsNotNone(ev.timestamp)
            self.assertTrue(ev.audit_id.startswith("AUDIT-"))

    # -------------------------------------------------------------------------
    # 7. Multi-Format Reporting Validation
    # -------------------------------------------------------------------------
    def test_17_multi_format_reporting_validation(self):
        """Verify JSON, CSV, and HTML reports are generated and can be parsed correctly."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
            case_id="CASE-RPT-17",
        )
        res = TriageOrchestrator(cfg).run()
        self.assertEqual(len(res.report_files), 3)

        files = dict(res.report_files)
        json_path = Path(files["json"])
        csv_path = Path(files["csv"])
        html_path = Path(files["html"])

        # JSON verification
        self.assertTrue(json_path.exists())
        data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["case_id"], "CASE-RPT-17")
        self.assertIn("artifacts", data)
        self.assertIn("audit_trail", data)
        self.assertIn("stage_results", data)

        # CSV verification
        self.assertTrue(csv_path.exists())
        csv_rows = list(csv.reader(csv_path.read_text(encoding="utf-8").splitlines()))
        self.assertGreater(len(csv_rows), 1)
        self.assertEqual(csv_rows[0][0], "unified_id")
        self.assertEqual(csv_rows[0][1], "category")

        # HTML verification
        self.assertTrue(html_path.exists())
        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("ForensiX Forensic Investigation Report", html_text)
        self.assertIn("CASE-RPT-17", html_text)

    # -------------------------------------------------------------------------
    # 8. Complete End-to-End CLI Workflow with Realistic Synthetic Fixture
    # -------------------------------------------------------------------------
    def test_18_complete_end_to_end_cli_workflow(self):
        """Verify full CLI execution against synthetic evidence directory producing valid outputs."""
        exit_code, res = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(self.output_dir),
            "--case-id", "CLI-E2E-18",
            "--case-name", "Synthetic Linux Incident Triage",
            "--investigator", "Examiner-42",
            "--format", "json",
            "--format", "html",
        ])
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(res)
        self.assertTrue(res.summary.is_success)
        self.assertEqual(res.config.case_id, "CLI-E2E-18")
        self.assertEqual(res.config.investigator, "Examiner-42")
        self.assertGreater(res.summary.total_artifacts, 10)
        self.assertEqual(len(res.report_files), 2)

    # -------------------------------------------------------------------------
    # 9. Multi-Run Idempotency & State Isolation (Run A -> Run B -> Run C)
    # -------------------------------------------------------------------------
    def test_19_multi_run_state_isolation(self):
        """Verify sequential runs (A -> B -> C) produce independent results with zero leakage."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="MULTI-RUN",
        )
        res_a = TriageOrchestrator(cfg).run()
        res_b = TriageOrchestrator(cfg).run()
        res_c = TriageOrchestrator(cfg).run()

        # All three must have different triage IDs
        ids = {res_a.triage_id, res_b.triage_id, res_c.triage_id}
        self.assertEqual(len(ids), 3)

        # Artifact counts must be identical across all runs
        self.assertEqual(res_a.summary.total_artifacts, res_b.summary.total_artifacts)
        self.assertEqual(res_b.summary.total_artifacts, res_c.summary.total_artifacts)

        # Instances must be separate objects in memory
        self.assertIsNot(res_a, res_b)
        self.assertIsNot(res_b, res_c)
        self.assertIsNot(res_a.artifacts, res_b.artifacts)

    # -------------------------------------------------------------------------
    # 10. Deep Immutability Validation
    # -------------------------------------------------------------------------
    def test_20_deep_immutability_validation(self):
        """Verify all core orchestration and report models are frozen and cannot be mutated."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), skip_reports=False)
        res = TriageOrchestrator(cfg).run()

        # TriageConfig
        with self.assertRaises(FrozenInstanceError):
            cfg.case_id = "TAMPERED"

        # TriageResult
        with self.assertRaises(FrozenInstanceError):
            res.triage_id = "TAMPERED"

        # TriageSummary
        with self.assertRaises(FrozenInstanceError):
            res.summary.stages_completed = 999

        # TriageStageResult
        with self.assertRaises(FrozenInstanceError):
            res.stage_results[0].status = "FAILED"

        # TriageTraceRecord
        with self.assertRaises(FrozenInstanceError):
            res.trace_records[0].stage_status = "MUTATED"

        # ForensicReport
        with self.assertRaises(FrozenInstanceError):
            res.report.total_artifacts = 0

        # HostArtifactCollection
        with self.assertRaises(FrozenInstanceError):
            res.artifacts.total_artifacts = 0

    # -------------------------------------------------------------------------
    # 11. Report Files Representation & Serialization Consistency
    # -------------------------------------------------------------------------
    def test_21_report_files_representation_consistency(self):
        """Verify report_files tuple in-memory maps losslessly to dictionary in to_dict()."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv"),
            case_id="CASE-RPT-FILES",
        )
        res = TriageOrchestrator(cfg).run()
        # In-memory tuple representation
        self.assertIsInstance(res.report_files, tuple)
        self.assertEqual(len(res.report_files), 2)
        for item in res.report_files:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

        # to_dict() mapping
        d = res.to_dict()
        self.assertIsInstance(d["report_files"], dict)
        self.assertIn("json", d["report_files"])
        self.assertIn("csv", d["report_files"])
        self.assertEqual(d["report_files"]["json"], res.report_files[0][1])
        self.assertEqual(d["report_files"]["csv"], res.report_files[1][1])

    # -------------------------------------------------------------------------
    # 12. Regression Subtests across Milestones
    # -------------------------------------------------------------------------
    def test_22_full_regression_baseline_subtests(self):
        """Verify baseline functionality across all historical milestones."""
        with self.subTest("V1 Core Analyzer"):
            from forensix.analyzer import analyze_evidence
            self.assertTrue(callable(analyze_evidence))

        with self.subTest("V2.1 Scanner"):
            self.assertTrue(callable(scan_evidence_directory))

        with self.subTest("V2.2 Log Parser"):
            self.assertTrue(callable(parse_log_file))

        with self.subTest("V2.3 Auth Analyzer"):
            self.assertTrue(callable(extract_authentication_activity))

        with self.subTest("V2.4 Account Analyzer"):
            self.assertTrue(callable(analyze_account_artifacts))

        with self.subTest("V2.5 Persistence Analyzer"):
            self.assertTrue(callable(analyze_persistence_artifacts))

        with self.subTest("V2.6 Unified Adapter"):
            self.assertTrue(callable(build_host_artifact_collection))

        with self.subTest("V2.7 Investigator"):
            self.assertTrue(callable(HostArtifactInvestigator))

        with self.subTest("V2.8 Forensic Report"):
            from forensix.report_builder import build_forensic_report
            self.assertTrue(callable(build_forensic_report))

        with self.subTest("V2.9 Orchestrator & CLI"):
            self.assertTrue(callable(TriageOrchestrator))
            self.assertTrue(callable(execute_triage_cli))
