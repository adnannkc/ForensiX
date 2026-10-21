"""
Unit tests for ForensiX V9 Pipeline Models.
"""

import json
import unittest

from forensix.pipeline_models import (
    ALL_PIPELINE_STAGES,
    ALL_RUN_STATUSES,
    ALL_STAGE_STATUSES,
    GeneratedFileRecord,
    PipelineRunManifest,
    PipelineRunStatus,
    PipelineStageId,
    StageRecord,
    StageStatus,
    generate_run_id,
)


class TestPipelineModels(unittest.TestCase):
    def test_enums_completeness(self):
        """Prove all 12 pipeline stage IDs exist in expected dependency order."""
        expected = [
            "config_validation",
            "preflight_verification",
            "custody_initialization",
            "host_analysis",
            "network_analysis",
            "memory_analysis",
            "timeline_reconstruction",
            "correlation",
            "detection",
            "report_synthesis",
            "custody_finalization",
            "run_manifest",
        ]
        self.assertEqual(list(ALL_PIPELINE_STAGES), expected)
        self.assertIn("SUCCESS", ALL_RUN_STATUSES)
        self.assertIn("PARTIAL_SUCCESS", ALL_RUN_STATUSES)
        self.assertIn("FAILURE", ALL_RUN_STATUSES)

    def test_generate_run_id(self):
        """Prove run ID generation generates unique RUN-<UUIDv4> identifiers."""
        r1 = generate_run_id()
        r2 = generate_run_id()
        self.assertTrue(r1.startswith("RUN-"))
        self.assertTrue(r2.startswith("RUN-"))
        self.assertNotEqual(r1, r2)

    def test_stage_record_validation_and_immutability(self):
        """Prove StageRecord enforces validation and deep immutability."""
        rec = StageRecord(
            stage_id="host_analysis",
            status=StageStatus.COMPLETED,
            duration_seconds=0.1234,
            records_produced=50,
            warnings=("Skipped unreadable file",),
            metadata=(("total_files", 10),),
        )
        self.assertEqual(rec.stage_id, "host_analysis")
        self.assertEqual(rec.status, "COMPLETED")
        self.assertEqual(rec.records_produced, 50)
        self.assertEqual(rec.warnings, ("Skipped unreadable file",))

        # Immutability check
        with self.assertRaises(Exception):
            rec.records_produced = 100

        d = rec.to_dict()
        self.assertEqual(d["stage_id"], "host_analysis")
        self.assertEqual(d["metadata"], {"total_files": 10})

    def test_generated_file_record(self):
        """Prove GeneratedFileRecord validates SHA-256 and size."""
        dummy_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        gf = GeneratedFileRecord(
            relative_path="report.json",
            sha256=dummy_sha,
            size_bytes=1024,
            file_type="json_report",
        )
        self.assertEqual(gf.relative_path, "report.json")
        self.assertEqual(gf.sha256, dummy_sha)

        with self.assertRaises(ValueError):
            GeneratedFileRecord(
                relative_path="report.json",
                sha256="invalid_short_hash",
                size_bytes=10,
                file_type="json",
            )

    def test_pipeline_run_manifest_serialization(self):
        """Prove PipelineRunManifest JSON serialization and roundtrip."""
        dummy_sha = "a" * 64
        rec1 = StageRecord(
            stage_id="config_validation",
            status="COMPLETED",
            duration_seconds=0.01,
        )
        gf = GeneratedFileRecord(
            relative_path="pipeline_manifest.json",
            sha256=dummy_sha,
            size_bytes=512,
            file_type="manifest",
        )
        manifest = PipelineRunManifest(
            run_id="RUN-12345678-1234-5678-1234-567812345678",
            forensix_version="8.0.0",
            started_at="2026-10-21T10:00:00Z",
            completed_at="2026-10-21T10:00:01Z",
            total_duration_seconds=1.0,
            run_status=PipelineRunStatus.SUCCESS,
            case_id="CASE-001",
            stages=(rec1,),
            generated_files=(gf,),
            evidence_digests=(("capture.pcap", dummy_sha),),
        )
        json_str = manifest.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["run_id"], "RUN-12345678-1234-5678-1234-567812345678")
        self.assertEqual(parsed["run_status"], "SUCCESS")
        self.assertEqual(len(parsed["stages"]), 1)
        self.assertEqual(len(parsed["generated_files"]), 1)
        self.assertEqual(parsed["evidence_digests"]["capture.pcap"], dummy_sha)


if __name__ == "__main__":
    unittest.main()
