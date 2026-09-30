"""
Unit tests for ForensiX Traceability & Audit Integration (V2.9.3).

Verifies:
1. TRIAGE_STARTED audit event
2. STAGE_STARTED audit event
3. STAGE_COMPLETED audit event
4. STAGE_PARTIAL audit event
5. STAGE_FAILED audit event
6. STAGE_SKIPPED audit event
7. TRIAGE_COMPLETED audit event
8. Correct triage_id propagation
9. Correct stage propagation
10. Correct source_artifact_id propagation
11. Correct source_event_id propagation
12. Correct unified_id propagation
13. Correct source_path propagation
14. Stage error remains linked to its stage
15. Warning remains linked to its stage
16. Audit lifecycle ordering
17. Deterministic ordering when timestamps tie
18. Deep immutability
19. JSON serialization
20. Existing V2.9.2 behavior remains compatible
21. No evidence mutation
22. No subprocess execution
23. No network activity
24. Full regression V1-V2.9.2 compatibility
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

from forensix.audit import AuditEvent, AuditEventType, create_audit_event
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageTraceRecord,
)
from forensix.triage_orchestrator import (
    EVENT_LIFECYCLE_ORDER,
    StageExecutionContext,
    TriageOrchestrator,
    sort_audit_events,
)


class TestTriageTraceability(unittest.TestCase):
    """Test suite for V2.9.3 Traceability & Audit Integration."""

    def setUp(self):
        """Set up standard temporary evidence fixtures for testing."""
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_trace_test_")
        self.evidence_dir = Path(self.temp_dir) / "evidence"
        self.output_dir = Path(self.temp_dir) / "reports"

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # /etc layout
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)

        (etc_dir / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "analyst:x:1001:1001:Security Analyst:/home/analyst:/bin/bash\n",
            encoding="utf-8",
        )
        (etc_dir / "group").write_text(
            "root:x:0:\n"
            "sudo:x:27:analyst\n"
            "analyst:x:1001:\n",
            encoding="utf-8",
        )
        (etc_dir / "shadow").write_text(
            "root:*:19000:0:99999:7:::\n"
            "analyst:*:19000:0:99999:7:::\n",
            encoding="utf-8",
        )
        (etc_dir / "crontab").write_text(
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
            encoding="utf-8",
        )

        # /var/log layout
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "auth.log").write_text(
            "Sep 30 14:00:01 forensic-host sshd[1234]: Accepted password for analyst from 192.168.1.50 port 54321 ssh2\n"
            "Sep 30 14:05:00 forensic-host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up temporary test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_triage_start_audit_event(self):
        """1. Verify TRIAGE_STARTED audit event is emitted at pipeline start."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-TRACE-01",
            case_name="Traceability Investigation",
            investigator="Lead Analyst",
        )
        result = TriageOrchestrator(cfg).run()

        start_ev = next((e for e in result.audit_trail if e.event_type == AuditEventType.TRIAGE_STARTED.value), None)
        self.assertIsNotNone(start_ev)
        self.assertEqual(start_ev.related_id, result.triage_id)
        self.assertEqual(start_ev.actor, "Lead Analyst")
        meta = dict(start_ev.metadata)
        self.assertEqual(meta["case_id"], "CASE-TRACE-01")
        self.assertEqual(meta["case_name"], "Traceability Investigation")
        self.assertEqual(meta["triage_id"], result.triage_id)

    def test_02_stage_start_audit_event(self):
        """2. Verify STAGE_STARTED audit event is emitted for executed stages."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        stage_start_events = [e for e in result.audit_trail if e.event_type == AuditEventType.STAGE_STARTED.value]
        # At least evidence_validation, filesystem_collection, etc. should emit STAGE_STARTED
        self.assertGreater(len(stage_start_events), 0)
        stages_started = {dict(e.metadata)["stage_id"] for e in stage_start_events}
        self.assertIn(TriageStage.EVIDENCE_VALIDATION.value, stages_started)
        self.assertIn(TriageStage.FILESYSTEM_COLLECTION.value, stages_started)

    def test_03_stage_completed_audit_event(self):
        """3. Verify STAGE_COMPLETED audit event is emitted with records produced."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        completed_events = [e for e in result.audit_trail if e.event_type == AuditEventType.STAGE_COMPLETED.value]
        self.assertGreater(len(completed_events), 0)
        for ev in completed_events:
            meta = dict(ev.metadata)
            self.assertIn("records_produced", meta)
            self.assertIn("stage_id", meta)
            self.assertEqual(meta["status"], "COMPLETED")

    def test_04_stage_partial_audit_event(self):
        """4. Verify STAGE_PARTIAL audit event is emitted with warnings and record counts."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def partial_handler(ctx: StageExecutionContext) -> TriageStageResult:
            return TriageStageResult(
                stage_id=TriageStage.LOG_PARSING.value,
                stage_name="Log Parsing",
                status=TriageStageStatus.PARTIAL,
                records_produced=5,
                warnings=("2 unparseable lines detected",),
            )

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.LOG_PARSING.value: partial_handler},
        )
        result = orchestrator.run()

        partial_ev = next(
            (e for e in result.audit_trail if e.event_type == AuditEventType.STAGE_PARTIAL.value),
            None,
        )
        self.assertIsNotNone(partial_ev)
        meta = dict(partial_ev.metadata)
        self.assertEqual(meta["stage_id"], TriageStage.LOG_PARSING.value)
        self.assertEqual(meta["status"], "PARTIAL")
        self.assertEqual(meta["records_produced"], 5)
        self.assertIn("2 unparseable lines detected", meta["warnings"])

    def test_05_stage_failed_audit_event(self):
        """5. Verify STAGE_FAILED audit event is emitted with factual error information."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def failing_handler(ctx: StageExecutionContext) -> TriageStageResult:
            raise PermissionError("Access denied to secure partition")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.ACCOUNT_ANALYSIS.value: failing_handler},
        )
        result = orchestrator.run()

        failed_ev = next(
            (e for e in result.audit_trail if e.event_type == AuditEventType.STAGE_FAILED.value),
            None,
        )
        self.assertIsNotNone(failed_ev)
        meta = dict(failed_ev.metadata)
        self.assertEqual(meta["stage_id"], TriageStage.ACCOUNT_ANALYSIS.value)
        self.assertEqual(meta["error_type"], "PermissionError")
        self.assertIn("Access denied", meta["error_message"])

    def test_06_stage_skipped_audit_event(self):
        """6. Verify STAGE_SKIPPED audit event is emitted with factual skip reason."""
        # Disable reporting
        enabled = tuple(s for s in ALL_TRIAGE_STAGES if s != TriageStage.REPORTING.value)
        cfg = TriageConfig(evidence_path=str(self.evidence_dir), enabled_stages=enabled)
        result = TriageOrchestrator(cfg).run()

        skipped_ev = next(
            (e for e in result.audit_trail if e.event_type == AuditEventType.STAGE_SKIPPED.value),
            None,
        )
        self.assertIsNotNone(skipped_ev)
        meta = dict(skipped_ev.metadata)
        self.assertEqual(meta["stage_id"], TriageStage.REPORTING.value)
        self.assertIn("disabled by configuration", meta["reason"].lower())

    def test_07_triage_completed_audit_event(self):
        """7. Verify TRIAGE_COMPLETED audit event is emitted with summary counts."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        completed_ev = next(
            (e for e in result.audit_trail if e.event_type == AuditEventType.TRIAGE_COMPLETED.value),
            None,
        )
        self.assertIsNotNone(completed_ev)
        meta = dict(completed_ev.metadata)
        self.assertEqual(meta["triage_id"], result.triage_id)
        self.assertTrue(meta["is_success"])
        self.assertEqual(meta["stages_failed"], 0)
        self.assertIn("stages_completed", meta)

    def test_08_triage_id_propagation(self):
        """8. Verify triage_id propagates consistently across result, trace records, and audit events."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        tid = result.triage_id
        self.assertTrue(tid.startswith("TRIAGE-"))

        # Trace records
        self.assertEqual(len(result.trace_records), 9)
        for tr in result.trace_records:
            self.assertEqual(tr.triage_id, tid)

        # Audit events
        for ev in result.audit_trail:
            self.assertEqual(ev.related_id, tid)

    def test_09_stage_propagation(self):
        """9. Verify stage identifiers propagate faithfully to trace records and audit events."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        trace_stages = [tr.stage_id for tr in result.trace_records]
        self.assertEqual(trace_stages, list(ALL_TRIAGE_STAGES))

    def test_10_source_artifact_id_propagation(self):
        """10. Verify source_artifact_id propagates to unified model and investigation trace records."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        fs_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.FILESYSTEM_COLLECTION.value)
        unified_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.UNIFIED_HOST_MODEL.value)

        self.assertGreater(len(fs_trace.source_artifact_ids), 0)
        for art_id in fs_trace.source_artifact_ids:
            self.assertIn(art_id, unified_trace.source_artifact_ids)

    def test_11_source_event_id_propagation(self):
        """11. Verify source_event_id propagates from log parsing to auth analysis and unified model."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        log_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.LOG_PARSING.value)
        auth_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.AUTHENTICATION_ANALYSIS.value)
        unified_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.UNIFIED_HOST_MODEL.value)

        self.assertGreater(len(log_trace.source_event_ids), 0)
        for evt_id in auth_trace.source_event_ids:
            self.assertIn(evt_id, log_trace.source_event_ids)
            self.assertIn(evt_id, unified_trace.source_event_ids)

    def test_12_unified_id_propagation(self):
        """12. Verify unified_id propagates from unified model to investigation and reporting traces."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        unified_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.UNIFIED_HOST_MODEL.value)
        invest_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.INVESTIGATION.value)
        report_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.REPORTING.value)

        self.assertGreater(len(unified_trace.unified_artifact_ids), 0)
        self.assertEqual(unified_trace.unified_artifact_ids, invest_trace.input_identifiers)
        self.assertEqual(invest_trace.unified_artifact_ids, report_trace.input_identifiers)

    def test_13_source_path_propagation(self):
        """13. Verify exact canonical source_paths propagate faithfully through trace records."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        fs_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.FILESYSTEM_COLLECTION.value)
        unified_trace = next(tr for tr in result.trace_records if tr.stage_id == TriageStage.UNIFIED_HOST_MODEL.value)

        expected_passwd = str(self.evidence_dir / "etc" / "passwd")
        self.assertIn(expected_passwd, fs_trace.source_paths)
        self.assertIn(expected_passwd, unified_trace.source_paths)

    def test_14_stage_error_linked_to_stage(self):
        """14. Verify stage errors remain linked to the failing stage in both results and audit events."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def failing_handler(ctx: StageExecutionContext) -> TriageStageResult:
            raise ValueError("Corrupted shadow file header")

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.ACCOUNT_ANALYSIS.value: failing_handler},
        )
        result = orchestrator.run()

        acct_res = next(r for r in result.stage_results if r.stage_id == TriageStage.ACCOUNT_ANALYSIS.value)
        self.assertEqual(len(acct_res.errors), 1)
        self.assertEqual(acct_res.errors[0].stage_id, TriageStage.ACCOUNT_ANALYSIS.value)
        self.assertEqual(acct_res.errors[0].error_type, "ValueError")

        acct_audit = next(
            e for e in result.audit_trail
            if e.event_type == AuditEventType.STAGE_FAILED.value and dict(e.metadata).get("stage_id") == TriageStage.ACCOUNT_ANALYSIS.value
        )
        self.assertEqual(dict(acct_audit.metadata)["error_type"], "ValueError")

    def test_15_warning_linked_to_stage(self):
        """15. Verify warnings remain attached to their stage and preserved in audit events."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))

        def warning_handler(ctx: StageExecutionContext) -> TriageStageResult:
            return TriageStageResult(
                stage_id=TriageStage.PERSISTENCE_ANALYSIS.value,
                stage_name="Persistence Analysis",
                status=TriageStageStatus.PARTIAL,
                records_produced=1,
                warnings=("Malformed cron line: syntax error at token @invalid",),
            )

        orchestrator = TriageOrchestrator(
            cfg,
            custom_handlers={TriageStage.PERSISTENCE_ANALYSIS.value: warning_handler},
        )
        result = orchestrator.run()

        pers_res = next(r for r in result.stage_results if r.stage_id == TriageStage.PERSISTENCE_ANALYSIS.value)
        self.assertEqual(len(pers_res.warnings), 1)
        self.assertIn("@invalid", pers_res.warnings[0])

        pers_audit = next(
            e for e in result.audit_trail
            if e.event_type == AuditEventType.STAGE_PARTIAL.value and dict(e.metadata).get("stage_id") == TriageStage.PERSISTENCE_ANALYSIS.value
        )
        self.assertIn("@invalid", dict(pers_audit.metadata)["warnings"][0])

    def test_16_audit_lifecycle_ordering(self):
        """16. Verify audit trail follows proper lifecycle order from start to finish."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        types = [e.event_type for e in result.audit_trail]
        # First event is TRIAGE_STARTED
        self.assertEqual(types[0], AuditEventType.TRIAGE_STARTED.value)
        # Last event is TRIAGE_COMPLETED
        self.assertEqual(types[-1], AuditEventType.TRIAGE_COMPLETED.value)

        # Stage lifecycle: STAGE_STARTED appears before STAGE_COMPLETED for a given stage
        ev_start_idx = types.index(AuditEventType.STAGE_STARTED.value)
        ev_comp_idx = types.index(AuditEventType.STAGE_COMPLETED.value)
        self.assertLess(ev_start_idx, ev_comp_idx)

    def test_17_deterministic_ordering_timestamps_tie(self):
        """17. Verify sort_audit_events breaks timestamp ties deterministically using lifecycle order."""
        fixed_ts = "2026-09-30T12:00:00Z"
        ev_completed = create_audit_event(
            event_type=AuditEventType.TRIAGE_COMPLETED,
            description="Triage finished",
            timestamp=fixed_ts,
        )
        ev_started = create_audit_event(
            event_type=AuditEventType.TRIAGE_STARTED,
            description="Triage started",
            timestamp=fixed_ts,
        )
        ev_stage_start = create_audit_event(
            event_type=AuditEventType.STAGE_STARTED,
            description="Stage started",
            timestamp=fixed_ts,
        )
        ev_stage_comp = create_audit_event(
            event_type=AuditEventType.STAGE_COMPLETED,
            description="Stage completed",
            timestamp=fixed_ts,
        )

        # Pass in reverse order
        shuffled = [ev_completed, ev_stage_comp, ev_stage_start, ev_started]
        sorted_evs = sort_audit_events(shuffled)

        sorted_types = [e.event_type for e in sorted_evs]
        expected_types = [
            AuditEventType.TRIAGE_STARTED.value,
            AuditEventType.STAGE_STARTED.value,
            AuditEventType.STAGE_COMPLETED.value,
            AuditEventType.TRIAGE_COMPLETED.value,
        ]
        self.assertEqual(sorted_types, expected_types)

    def test_18_deep_immutability(self):
        """18. Verify deep immutability of TriageTraceRecord and TriageResult.trace_records."""
        rec = TriageTraceRecord(
            triage_id="TRIAGE-test",
            stage_id="log_parsing",
            stage_status="COMPLETED",
            input_identifiers=("input1",),
            output_identifiers=("out1", "out2"),
            source_artifact_ids=("art1",),
        )
        # Frozen dataclass rejects attribute assignment
        with self.assertRaises(Exception):
            rec.stage_status = "FAILED"  # type: ignore

        # Collections are immutable tuples
        self.assertIsInstance(rec.input_identifiers, tuple)
        self.assertIsInstance(rec.output_identifiers, tuple)
        self.assertIsInstance(rec.source_artifact_ids, tuple)

        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()
        with self.assertRaises(Exception):
            result.trace_records = ()  # type: ignore

    def test_19_json_serialization(self):
        """19. Verify full JSON serializability of TriageResult with trace records and audit events."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="TRACE-JSON-01",
        )
        result = TriageOrchestrator(cfg).run()

        d = result.to_dict()
        self.assertIn("trace_records", d)
        self.assertEqual(len(d["trace_records"]), 9)
        self.assertIn("audit_trail", d)
        self.assertGreater(len(d["audit_trail"]), 0)

        serialized = json.dumps(d, indent=2)
        self.assertIsInstance(serialized, str)

        parsed = json.loads(serialized)
        self.assertEqual(parsed["triage_id"], result.triage_id)
        self.assertEqual(len(parsed["trace_records"]), 9)

    def test_20_existing_v292_behavior_compatible(self):
        """20. Verify existing V2.9.2 orchestrator behavior remains 100% compatible."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="COMPAT-01",
            output_dir=str(self.output_dir),
            report_formats=("json", "csv"),
        )
        result = TriageOrchestrator(cfg).run()

        self.assertTrue(result.summary.is_success)
        self.assertEqual(len(result.stage_results), 9)
        self.assertIsNotNone(result.artifacts)
        self.assertIsNotNone(result.investigator)
        self.assertIsNotNone(result.report)
        self.assertEqual(len(result.report_files), 2)

    def test_21_no_evidence_mutation(self):
        """21. Verify evidence files remain completely unmodified."""
        passwd = self.evidence_dir / "etc" / "passwd"
        auth_log = self.evidence_dir / "var" / "log" / "auth.log"

        pre_passwd_hash = hashlib.sha256(passwd.read_bytes()).hexdigest()
        pre_passwd_mtime = passwd.stat().st_mtime_ns
        pre_auth_hash = hashlib.sha256(auth_log.read_bytes()).hexdigest()
        pre_auth_mtime = auth_log.stat().st_mtime_ns

        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        _ = TriageOrchestrator(cfg).run()

        self.assertEqual(pre_passwd_hash, hashlib.sha256(passwd.read_bytes()).hexdigest())
        self.assertEqual(pre_passwd_mtime, passwd.stat().st_mtime_ns)
        self.assertEqual(pre_auth_hash, hashlib.sha256(auth_log.read_bytes()).hexdigest())
        self.assertEqual(pre_auth_mtime, auth_log.stat().st_mtime_ns)

    def test_22_no_subprocess_execution(self):
        """22. Verify zero subprocess execution during audit & trace orchestration."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)

        with patch("subprocess.Popen") as mock_popen, patch("os.system") as mock_system:
            _ = orchestrator.run()
            mock_popen.assert_not_called()
            mock_system.assert_not_called()

    def test_23_no_network_activity(self):
        """23. Verify zero network activity during audit & trace orchestration."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        orchestrator = TriageOrchestrator(cfg)

        with patch("socket.socket") as mock_socket, patch("urllib.request.urlopen") as mock_urlopen:
            _ = orchestrator.run()
            mock_socket.assert_not_called()
            mock_urlopen.assert_not_called()

    def test_24_full_regression_v1_v292(self):
        """24. Verify full regression compatibility across V1-V2.9.2 models."""
        cfg = TriageConfig(evidence_path=str(self.evidence_dir))
        result = TriageOrchestrator(cfg).run()

        # Validate that HostArtifactCollection, HostArtifactInvestigator, and ForensicReport are standard
        self.assertGreater(result.artifacts.total_artifacts, 0)
        self.assertGreater(result.investigation_result.total_matches, 0)
        self.assertEqual(result.report.total_artifacts, result.artifacts.total_artifacts)


if __name__ == "__main__":
    unittest.main()
