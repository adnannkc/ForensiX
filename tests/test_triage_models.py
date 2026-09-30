"""
Unit tests for ForensiX Triage Orchestration Models (V2.9.1).

Verifies:
- TriageStage and TriageStageStatus enumerations
- TriageConfig construction, defaults, validation, and deep immutability
- TriageStageError structured error representation
- TriageStageResult construction, validation, and status handling
- TriageSummary overview metrics
- TriageResult aggregate container and integration with canonical V2 models
- Deep immutability and protection of nested structures
- Deterministic JSON-serializable to_dict() output
- Source-object immutability
"""

import json
from pathlib import Path
import unittest

from forensix.artifacts import ArtifactRecord
from forensix.audit import AuditEventType, create_audit_event
from forensix.investigation import HostArtifactInvestigator
from forensix.report_builder import build_forensic_report
from forensix.report_models import ForensicReport, ReportFormat
from forensix.triage_models import (
    ALL_STAGE_STATUSES,
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageError,
    TriageStageResult,
    TriageStageStatus,
    TriageSummary,
    generate_triage_id,
)
from forensix.unified_adapter import build_host_artifact_collection, to_host_artifact
from forensix.unified_models import HostArtifactCollection


class TestTriageModels(unittest.TestCase):
    """Test suite for V2.9.1 core triage models and orchestration data structures."""

    def setUp(self):
        """Set up representative canonical V2 models for integration testing."""
        self.sample_art = ArtifactRecord(
            artifact_id="ART-1111",
            relative_path="etc/passwd",
            source_path="/evidence/etc/passwd",
            category="account",
            artifact_type="passwd",
            is_known=True,
            size=1024,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-30T10:00:00Z",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="collected",
        )
        self.host_collection = build_host_artifact_collection(
            evidence_root="/evidence",
            records=[self.sample_art],
            collected_at="2026-09-30T10:00:00Z",
        )
        self.investigator = HostArtifactInvestigator(self.host_collection)
        self.forensic_report = build_forensic_report(
            source=self.host_collection,
            case_id="CASE-101",
            case_name="Automated Triage Test",
            investigator="Lead Analyst",
        )

    def test_01_triage_stage_enumeration(self):
        """1. Verify TriageStage covers all approved pipeline stages."""
        expected_stages = {
            "evidence_validation",
            "filesystem_collection",
            "log_parsing",
            "authentication_analysis",
            "account_analysis",
            "persistence_analysis",
            "unified_host_model",
            "investigation",
            "reporting",
        }
        actual_stages = {s.value for s in TriageStage}
        self.assertEqual(actual_stages, expected_stages)
        self.assertEqual(len(ALL_TRIAGE_STAGES), 9)

    def test_02_triage_stage_status_enumeration(self):
        """2. Verify TriageStageStatus contains exactly the 6 required execution states."""
        expected_statuses = {
            "NOT_STARTED",
            "RUNNING",
            "COMPLETED",
            "PARTIAL",
            "FAILED",
            "SKIPPED",
        }
        actual_statuses = {s.value for s in TriageStageStatus}
        self.assertEqual(actual_statuses, expected_statuses)
        self.assertEqual(len(ALL_STAGE_STATUSES), 6)

    def test_03_triage_config_construction(self):
        """3. Verify TriageConfig construction with explicit parameters."""
        cfg = TriageConfig(
            evidence_path="/mnt/evidence_image",
            case_id="CASE-001",
            case_name="Security Incident",
            investigator="Adnan",
            output_dir="/mnt/reports",
            enabled_stages=(TriageStage.FILESYSTEM_COLLECTION.value, TriageStage.ACCOUNT_ANALYSIS.value),
            report_formats=("json", "html"),
            skip_reports=False,
            collect_audit=True,
        )
        self.assertEqual(cfg.evidence_path, "/mnt/evidence_image")
        self.assertEqual(cfg.case_id, "CASE-001")
        self.assertEqual(cfg.case_name, "Security Incident")
        self.assertEqual(cfg.investigator, "Adnan")
        self.assertEqual(cfg.output_dir, "/mnt/reports")
        self.assertEqual(len(cfg.enabled_stages), 2)
        self.assertEqual(cfg.report_formats, ("json", "html"))
        self.assertFalse(cfg.skip_reports)
        self.assertTrue(cfg.collect_audit)

    def test_04_triage_config_defaults(self):
        """4. Verify TriageConfig default values."""
        cfg = TriageConfig(evidence_path="/evidence")
        self.assertEqual(cfg.evidence_path, "/evidence")
        self.assertIsNone(cfg.case_id)
        self.assertIsNone(cfg.case_name)
        self.assertIsNone(cfg.investigator)
        self.assertIsNone(cfg.output_dir)
        self.assertEqual(cfg.enabled_stages, ALL_TRIAGE_STAGES)
        self.assertEqual(cfg.report_formats, ("json", "csv", "html"))
        self.assertFalse(cfg.skip_reports)
        self.assertTrue(cfg.collect_audit)

    def test_05_triage_config_immutability(self):
        """5. Verify TriageConfig rejects attribute mutation and stores immutable tuples."""
        cfg = TriageConfig(evidence_path="/evidence")
        with self.assertRaises(Exception):
            cfg.evidence_path = "/new_path"  # type: ignore
        with self.assertRaises(Exception):
            cfg.skip_reports = True  # type: ignore
        self.assertIsInstance(cfg.enabled_stages, tuple)
        self.assertIsInstance(cfg.report_formats, tuple)

    def test_06_triage_stage_result_construction(self):
        """6. Verify TriageStageResult construction with valid fields."""
        res = TriageStageResult(
            stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
            stage_name="Filesystem Artifact Collection",
            status=TriageStageStatus.COMPLETED,
            started_at="2026-09-30T10:00:00Z",
            completed_at="2026-09-30T10:00:02Z",
            duration_seconds=2.0,
            records_produced=150,
            warnings=("1 broken symlink quarantined",),
            metadata=(("scanner", "ArtifactScanner"),),
        )
        self.assertEqual(res.stage_id, "filesystem_collection")
        self.assertEqual(res.status, "COMPLETED")
        self.assertEqual(res.records_produced, 150)
        self.assertEqual(len(res.warnings), 1)

    def test_07_triage_stage_result_status_handling(self):
        """7. Verify TriageStageResult status handling and invalid status rejection."""
        res = TriageStageResult(
            stage_id="test",
            stage_name="Test",
            status=TriageStageStatus.FAILED,
        )
        self.assertEqual(res.status, "FAILED")

        # Invalid status raises ValueError
        with self.assertRaises(ValueError):
            TriageStageResult(
                stage_id="test",
                stage_name="Test",
                status="INVALID_STATUS",
            )

    def test_08_structured_error_representation(self):
        """8. Verify structured error representation with TriageStageError."""
        err = TriageStageError(
            stage_id=TriageStage.LOG_PARSING.value,
            error_type="UnreadableFileError",
            error_message="Log file var/log/auth.log could not be opened (Permission denied)",
            details=(("path", "var/log/auth.log"), ("errno", 13)),
        )
        self.assertEqual(err.stage_id, "log_parsing")
        self.assertEqual(err.error_type, "UnreadableFileError")
        self.assertIn("Permission denied", err.error_message)
        self.assertIsInstance(err.details, tuple)

        d = err.to_dict()
        self.assertEqual(d["details"]["errno"], 13)
        self.assertEqual(d["error_type"], "UnreadableFileError")

    def test_09_triage_result_construction(self):
        """9. Verify TriageResult aggregate container construction."""
        cfg = TriageConfig(evidence_path="/evidence", case_id="CASE-001")
        summary = TriageSummary(
            case_id="CASE-001",
            case_name=None,
            investigator=None,
            evidence_root="/evidence",
            started_at="2026-09-30T10:00:00Z",
            completed_at="2026-09-30T10:00:02Z",
            total_duration_seconds=2.0,
            total_artifacts=1,
            stages_completed=9,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        stage_res = TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name="Evidence Validation",
            status=TriageStageStatus.COMPLETED,
            records_produced=1,
        )
        audit_ev = create_audit_event(
            event_type=AuditEventType.EVIDENCE_REGISTERED,
            description="Evidence root validated",
        )

        triage_res = TriageResult(
            triage_id=generate_triage_id(),
            config=cfg,
            summary=summary,
            stage_results=(stage_res,),
            artifacts=self.host_collection,
            investigator=self.investigator,
            report=self.forensic_report,
            report_files=(("json", "/reports/report.json"),),
            audit_trail=(audit_ev,),
        )

        self.assertTrue(triage_res.triage_id.startswith("TRIAGE-"))
        self.assertEqual(len(triage_res.stage_results), 1)
        self.assertIs(triage_res.artifacts, self.host_collection)
        self.assertIs(triage_res.investigator, self.investigator)
        self.assertIs(triage_res.report, self.forensic_report)

    def test_10_nested_stage_results(self):
        """10. Verify nested stage results within TriageResult."""
        cfg = TriageConfig(evidence_path="/evidence")
        summary = TriageSummary(
            case_id=None,
            case_name=None,
            investigator=None,
            evidence_root="/evidence",
            started_at=None,
            completed_at=None,
            total_duration_seconds=None,
            total_artifacts=0,
            stages_completed=1,
            stages_partial=1,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        stage1 = TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name="Evidence Validation",
            status=TriageStageStatus.COMPLETED,
        )
        stage2 = TriageStageResult(
            stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
            stage_name="Filesystem Collection",
            status=TriageStageStatus.PARTIAL,
            errors=(
                TriageStageError(
                    stage_id=TriageStage.FILESYSTEM_COLLECTION.value,
                    error_type="PermissionError",
                    error_message="Access denied to /evidence/etc/shadow",
                ),
            ),
        )

        triage_res = TriageResult(
            triage_id=generate_triage_id(),
            config=cfg,
            summary=summary,
            stage_results=(stage1, stage2),
        )

        self.assertEqual(len(triage_res.stage_results), 2)
        self.assertEqual(triage_res.stage_results[0].stage_id, "evidence_validation")
        self.assertEqual(triage_res.stage_results[1].stage_id, "filesystem_collection")
        self.assertEqual(len(triage_res.stage_results[1].errors), 1)

    def test_11_deep_immutability(self):
        """11. Verify deep immutability across all triage models and nested structures."""
        cfg = TriageConfig(evidence_path="/evidence")
        summary = TriageSummary(
            case_id=None,
            case_name=None,
            investigator=None,
            evidence_root="/evidence",
            started_at=None,
            completed_at=None,
            total_duration_seconds=None,
            total_artifacts=0,
            stages_completed=0,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        stage = TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name="Evidence Validation",
            status=TriageStageStatus.COMPLETED,
            metadata=(("key", "val"),),
        )
        triage_res = TriageResult(
            triage_id="TRIAGE-immutable",
            config=cfg,
            summary=summary,
            stage_results=(stage,),
        )

        with self.assertRaises(Exception):
            triage_res.triage_id = "NEW_ID"  # type: ignore
        with self.assertRaises(Exception):
            triage_res.stage_results = ()  # type: ignore
        with self.assertRaises(Exception):
            stage.status = TriageStageStatus.FAILED  # type: ignore
        with self.assertRaises(Exception):
            cfg.evidence_path = "/new"  # type: ignore

        # Ensure nested structures are tuples, not mutable lists or dicts
        self.assertIsInstance(triage_res.stage_results, tuple)
        self.assertIsInstance(stage.metadata, tuple)
        self.assertIsInstance(stage.errors, tuple)
        self.assertIsInstance(stage.warnings, tuple)

    def test_12_deterministic_serialization(self):
        """12. Verify deterministic serialization across repeated to_dict() calls."""
        cfg = TriageConfig(evidence_path="/evidence", case_id="CASE-2026")
        summary = TriageSummary(
            case_id="CASE-2026",
            case_name="Test Case",
            investigator="Analyst",
            evidence_root="/evidence",
            started_at="2026-09-30T10:00:00Z",
            completed_at="2026-09-30T10:00:02Z",
            total_duration_seconds=2.0,
            total_artifacts=1,
            stages_completed=1,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        stage = TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name="Evidence Validation",
            status=TriageStageStatus.COMPLETED,
            metadata=(("k1", "v1"),),
        )
        triage_res = TriageResult(
            triage_id="TRIAGE-fixed-uuid",
            config=cfg,
            summary=summary,
            stage_results=(stage,),
            artifacts=self.host_collection,
            report_files=(("json", "/reports/CASE-2026.json"),),
        )

        d1 = triage_res.to_dict()
        d2 = triage_res.to_dict()
        self.assertEqual(d1, d2)
        self.assertEqual(json.dumps(d1, sort_keys=True), json.dumps(d2, sort_keys=True))

    def test_13_json_compatibility(self):
        """13. Verify JSON compatibility of serialized triage models."""
        cfg = TriageConfig(evidence_path="/evidence", case_id="CASE-2026")
        summary = TriageSummary(
            case_id="CASE-2026",
            case_name="Test Case",
            investigator="Analyst",
            evidence_root="/evidence",
            started_at="2026-09-30T10:00:00Z",
            completed_at="2026-09-30T10:00:02Z",
            total_duration_seconds=2.0,
            total_artifacts=1,
            stages_completed=1,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        stage = TriageStageResult(
            stage_id=TriageStage.EVIDENCE_VALIDATION.value,
            stage_name="Evidence Validation",
            status=TriageStageStatus.COMPLETED,
            metadata=(("k1", "v1"),),
        )
        triage_res = TriageResult(
            triage_id="TRIAGE-fixed-uuid",
            config=cfg,
            summary=summary,
            stage_results=(stage,),
            artifacts=self.host_collection,
            report_files=(("json", "/reports/CASE-2026.json"),),
        )

        serialized = json.dumps(triage_res.to_dict())
        self.assertIsInstance(serialized, str)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["triage_id"], "TRIAGE-fixed-uuid")
        self.assertEqual(parsed["summary"]["case_id"], "CASE-2026")
        self.assertEqual(parsed["stage_results"][0]["metadata"]["k1"], "v1")

    def test_14_empty_and_optional_fields_handling(self):
        """14. Verify TriageResult handles None values for optional components cleanly."""
        cfg = TriageConfig(evidence_path="/evidence")
        summary = TriageSummary(
            case_id=None,
            case_name=None,
            investigator=None,
            evidence_root="/evidence",
            started_at=None,
            completed_at=None,
            total_duration_seconds=None,
            total_artifacts=0,
            stages_completed=0,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=False,
        )
        triage_res = TriageResult(
            triage_id="TRIAGE-empty",
            config=cfg,
            summary=summary,
            stage_results=(),
            artifacts=None,
            investigator=None,
            report=None,
            report_files=(),
            audit_trail=(),
        )
        d = triage_res.to_dict()
        self.assertIsNone(d["artifacts_summary"])
        self.assertIsNone(d["report_summary"])
        self.assertEqual(d["stage_results"], [])
        self.assertEqual(d["report_files"], {})

    def test_15_traceability_fields(self):
        """15. Verify stage results preserve explicit stage_id and errors for traceability."""
        stage = TriageStageResult(
            stage_id=TriageStage.PERSISTENCE_ANALYSIS.value,
            stage_name="Persistence Analysis",
            status=TriageStageStatus.PARTIAL,
            records_produced=10,
            warnings=("Malformed line in /etc/crontab: line 5",),
            metadata=(("analyzer", "persistence_analyzer"),),
        )
        self.assertEqual(stage.stage_id, "persistence_analysis")
        self.assertIn("line 5", stage.warnings[0])
        self.assertEqual(dict(stage.metadata)["analyzer"], "persistence_analyzer")

    def test_16_source_object_immutability(self):
        """16. Verify passing canonical V2 models into TriageResult leaves them unmodified."""
        pre_summary = self.host_collection.summary
        pre_art_count = len(self.host_collection.artifacts)

        cfg = TriageConfig(evidence_path="/evidence")
        summary = TriageSummary(
            case_id=None,
            case_name=None,
            investigator=None,
            evidence_root="/evidence",
            started_at=None,
            completed_at=None,
            total_duration_seconds=None,
            total_artifacts=1,
            stages_completed=1,
            stages_partial=0,
            stages_failed=0,
            stages_skipped=0,
            is_success=True,
        )
        _ = TriageResult(
            triage_id="TRIAGE-immutability",
            config=cfg,
            summary=summary,
            stage_results=(),
            artifacts=self.host_collection,
            investigator=self.investigator,
            report=self.forensic_report,
        )

        self.assertEqual(self.host_collection.summary, pre_summary)
        self.assertEqual(len(self.host_collection.artifacts), pre_art_count)

    def test_17_invalid_input_validation(self):
        """17. Verify strict TypeError and ValueError validation on bad model inputs."""
        # Non-string evidence path
        with self.assertRaises(TypeError):
            TriageConfig(evidence_path=123)  # type: ignore

        # Empty evidence path
        with self.assertRaises(ValueError):
            TriageConfig(evidence_path="   ")

        # Invalid stage name in enabled_stages
        with self.assertRaises(ValueError):
            TriageConfig(evidence_path="/evidence", enabled_stages=("invalid_stage_name",))

        # Invalid report format
        with self.assertRaises(ValueError):
            TriageConfig(evidence_path="/evidence", report_formats=("pdf",))

        # Negative records_produced in TriageStageResult
        with self.assertRaises(ValueError):
            TriageStageResult(
                stage_id="test",
                stage_name="Test",
                status="COMPLETED",
                records_produced=-1,
            )

        # Non-integer records_produced in TriageStageResult
        with self.assertRaises(TypeError):
            TriageStageResult(
                stage_id="test",
                stage_name="Test",
                status="COMPLETED",
                records_produced="ten",  # type: ignore
            )

        # Invalid stage error type in errors tuple
        with self.assertRaises(TypeError):
            TriageStageResult(
                stage_id="test",
                stage_name="Test",
                status="FAILED",
                errors=("string_error_not_allowed",),  # type: ignore
            )

    def test_18_deterministic_ordering(self):
        """18. Verify deterministic ordering in to_dict() outputs."""
        cfg = TriageConfig(
            evidence_path="/evidence",
            enabled_stages=(TriageStage.REPORTING.value, TriageStage.ACCOUNT_ANALYSIS.value),
        )
        d1 = cfg.to_dict()
        d2 = cfg.to_dict()
        self.assertEqual(list(d1.keys()), list(d2.keys()))
        self.assertEqual(d1["enabled_stages"], d2["enabled_stages"])


if __name__ == "__main__":
    unittest.main()
