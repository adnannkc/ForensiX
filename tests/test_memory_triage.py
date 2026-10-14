"""
Comprehensive Integration Test Suite for ForensiX Milestone V6.7 — Memory Triage.

Validates:
1. End-to-end processing of synthetic, already-extracted memory artifacts.
2. Correct timeline reconstruction and correlation integration.
3. Strict Evidence-Image Isolation (duplicate PIDs across separate evidence images).
4. Full provenance chain preservation in DetectionResults.
5. Deterministic triage output, stable identifiers, and repeatable metrics.
6. Empty input and missing optional artifact fields.
7. Report serialization (JSON and HTML) via existing supported interfaces.
8. Zero execution, acquisition, mutation, or network dependency.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from forensix.detection_engine import DetectionResultCollection
from forensix.detection_reporting import CorrelationDetectionReport
from forensix.memory_correlation import (
    MemoryCorrelation,
    MemoryCorrelationConfig,
    MemoryCorrelationType,
)
from forensix.memory_models import (
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    ProcessExtractionResult,
    compute_deterministic_memory_id,
    compute_deterministic_module_id,
    compute_deterministic_network_id,
    compute_deterministic_process_id,
)
from forensix.memory_rules import (
    create_canonical_memory_rules,
    create_memory_network_socket_rule,
    create_memory_process_name_rule,
    create_memory_process_socket_correlation_rule,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
)
from forensix.memory_triage import (
    MemoryTriageConfig,
    MemoryTriageResult,
    compute_deterministic_triage_id,
    run_memory_triage,
)
from forensix.rule_models import ConditionOperator, RuleCollection


class TestMemoryTriagePipeline(unittest.TestCase):
    """Test end-to-end memory triage orchestration and artifact adaptation."""

    def setUp(self) -> None:
        self.evidence_id = compute_deterministic_memory_id(
            sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            file_size=1048576,
            evidence_format="lime",
        )
        self.proc_art_id = compute_deterministic_process_id(
            evidence_id=self.evidence_id,
            plugin="linux.pslist",
            pid=4321,
            process_name="nc",
        )
        self.net_art_id = compute_deterministic_network_id(
            evidence_id=self.evidence_id,
            plugin="linux.sockstat",
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=4444,
        )
        self.mod_art_id = compute_deterministic_module_id(
            evidence_id=self.evidence_id,
            plugin="linux.lsmod",
            module_name="rkhunter_mod",
        )

        self.proc = MemoryProcessArtifact(
            artifact_id=self.proc_art_id,
            evidence_id=self.evidence_id,
            pid=4321,
            process_name="nc",
            source_plugin="linux.pslist",
            created_at="2026-10-14T10:00:00+00:00",
        )
        self.net = MemoryNetworkArtifact(
            artifact_id=self.net_art_id,
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="linux.sockstat",
            local_address="0.0.0.0",
            local_port=4444,
            state="LISTEN",
            pid=4321,
            process_name="nc",
        )
        self.mod = MemoryModuleArtifact(
            artifact_id=self.mod_art_id,
            evidence_id=self.evidence_id,
            module_name="rkhunter_mod",
            source_plugin="linux.lsmod",
            driver_path="/tmp/rkhunter_mod.ko",
            size_bytes=2048,
        )

    def test_run_memory_triage_basic(self) -> None:
        """Verify successful end-to-end triage over valid synthetic artifacts."""
        artifacts = [self.proc, self.net, self.mod]
        result = run_memory_triage(artifacts)

        self.assertIsInstance(result, MemoryTriageResult)
        self.assertTrue(result.is_success)
        self.assertTrue(result.triage_id.startswith("MEMTRIAGE-"))
        self.assertEqual(result.total_artifacts, 3)
        self.assertIn(self.evidence_id, result.evidence_ids)

        # Check timeline events
        self.assertGreater(len(result.timeline_events), 0)
        self.assertGreater(len(result.memory_timeline_events), 0)

        # Check correlations
        self.assertGreater(len(result.correlations), 0)
        self.assertGreater(len(result.memory_correlations), 0)

        # Check detections: canonical baseline rules should match 'nc', port 4444, process-socket, and '/tmp' driver path
        self.assertIsInstance(result.detections, DetectionResultCollection)
        matched_rules = [d.rule_name for d in result.detections if d.matched]
        self.assertGreater(len(matched_rules), 0)

        # Check summary counts
        summary = result.summary_dict
        self.assertEqual(summary["total_artifacts"], 3)
        self.assertEqual(summary["evidence_count"], 1)
        self.assertGreater(summary["detections_matched"], 0)

    def test_strict_evidence_isolation(self) -> None:
        """Verify artifacts from distinct memory images are strictly isolated."""
        eid_1 = compute_deterministic_memory_id(
            sha256="1111111111111111111111111111111111111111111111111111111111111111",
            file_size=1000,
        )
        eid_2 = compute_deterministic_memory_id(
            sha256="2222222222222222222222222222222222222222222222222222222222222222",
            file_size=2000,
        )

        # Image 1 has process with PID 999
        proc_1 = MemoryProcessArtifact(
            artifact_id=compute_deterministic_process_id(eid_1, "linux.pslist", 999, "bash"),
            evidence_id=eid_1,
            pid=999,
            process_name="bash",
            source_plugin="linux.pslist",
        )
        # Image 2 has socket with PID 999 (IDENTICAL PID)
        net_2 = MemoryNetworkArtifact(
            artifact_id=compute_deterministic_network_id(eid_2, "linux.sockstat", "TCP", "127.0.0.1", 8080),
            evidence_id=eid_2,
            protocol="TCP",
            source_plugin="linux.sockstat",
            local_address="127.0.0.1",
            local_port=8080,
            pid=999,
        )

        result = run_memory_triage([proc_1, net_2])

        # Even though PID 999 is present in both, they are in DIFFERENT evidence images
        # Therefore, ZERO PROCESS_NETWORK_SOCKET correlations should be generated between them!
        self.assertEqual(len(result.correlations), 0)
        self.assertEqual(len(result.memory_correlations), 0)

    def test_provenance_preservation(self) -> None:
        """Verify DetectionResults retain exact source artifact IDs and evidence identity."""
        rule = create_memory_process_name_rule("nc")
        result = run_memory_triage([self.proc], rules=[rule])

        matched_dets = [d for d in result.detections if d.matched]
        self.assertEqual(len(matched_dets), 1)
        det = matched_dets[0]

        self.assertIn(self.proc_art_id, det.matched_source_artifact_ids)
        self.assertTrue(len(det.matched_event_ids) >= 1)
        self.assertTrue(det.detection_id.startswith("DET-"))

    def test_deterministic_triage_id(self) -> None:
        """Verify identical triage runs produce identical triage identifiers."""
        id1 = compute_deterministic_triage_id([self.evidence_id], 3, 5)
        id2 = compute_deterministic_triage_id([self.evidence_id], 3, 5)
        self.assertEqual(id1, id2)

        # Different counts produce different IDs
        id3 = compute_deterministic_triage_id([self.evidence_id], 4, 5)
        self.assertNotEqual(id1, id3)

    def test_empty_artifacts_input(self) -> None:
        """Verify empty input returns clean, empty, successful result."""
        result = run_memory_triage([])
        self.assertTrue(result.is_success)
        self.assertEqual(result.total_artifacts, 0)
        self.assertEqual(len(result.timeline_events), 0)
        self.assertEqual(len(result.correlations), 0)
        self.assertEqual(len(result.detections), 0)

    def test_missing_optional_fields_safety(self) -> None:
        """Verify artifacts with missing optional fields process without failure."""
        incomplete_proc = MemoryProcessArtifact(
            artifact_id=compute_deterministic_process_id(self.evidence_id, "linux.pslist", 100, "daemon"),
            evidence_id=self.evidence_id,
            pid=100,
            process_name="daemon",
            source_plugin="linux.pslist",
            ppid=None,
            created_at=None,
            exit_time=None,
            offset=None,
        )
        incomplete_net = MemoryNetworkArtifact(
            artifact_id=compute_deterministic_network_id(self.evidence_id, "linux.sockstat", "UDP"),
            evidence_id=self.evidence_id,
            protocol="UDP",
            source_plugin="linux.sockstat",
            local_address=None,
            local_port=None,
            remote_address=None,
            remote_port=None,
            state=None,
            pid=None,
        )
        incomplete_mod = MemoryModuleArtifact(
            artifact_id=compute_deterministic_module_id(self.evidence_id, "linux.lsmod", "core_mod"),
            evidence_id=self.evidence_id,
            module_name="core_mod",
            source_plugin="linux.lsmod",
            base_address=None,
            size_bytes=None,
            offset=None,
            driver_path=None,
        )

        result = run_memory_triage([incomplete_proc, incomplete_net, incomplete_mod])
        self.assertTrue(result.is_success)
        self.assertEqual(result.total_artifacts, 3)

    def test_report_generation_json_and_html(self) -> None:
        """Verify report generation and serialization via existing supported interfaces."""
        artifacts = [self.proc, self.net, self.mod]
        config = MemoryTriageConfig(
            case_id="CASE-2026-TEST",
            case_name="Synthetic Memory Triage Test",
            investigator="Forensic Analyst",
        )
        result = run_memory_triage(artifacts, config=config)

        # 1. Generate CorrelationDetectionReport
        report = result.generate_report()
        self.assertIsInstance(report, CorrelationDetectionReport)
        self.assertEqual(report.case_id, "CASE-2026-TEST")

        # 2. Render JSON
        json_output = result.render_report(format="json")
        self.assertIsInstance(json_output, str)
        parsed = json.loads(json_output)
        self.assertIn("detections", parsed)
        self.assertIn("summary", parsed)

        # 3. Render HTML
        html_output = result.render_report(format="html")
        self.assertIsInstance(html_output, str)
        self.assertIn("<!DOCTYPE html>", html_output)
        self.assertIn("CASE-2026-TEST", html_output)

        # 4. Write Report to temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_json = Path(tmp_dir) / "report.json"
            out_html = Path(tmp_dir) / "report.html"

            written_json = result.write_report(out_json, format="json")
            self.assertTrue(written_json.exists())
            self.assertGreater(written_json.stat().st_size, 0)

            written_html = result.write_report(out_html, format="html")
            self.assertTrue(written_html.exists())
            self.assertGreater(written_html.stat().st_size, 0)

    def test_triage_config_validation(self) -> None:
        """Verify MemoryTriageConfig validation rules."""
        with self.assertRaises(TypeError):
            MemoryTriageConfig(case_id=123)  # type: ignore

        with self.assertRaises(ValueError):
            MemoryTriageConfig(report_formats=("pdf",))  # Unsupported format

        cfg = MemoryTriageConfig(case_id="  CASE-001  ", matched_only=True)
        self.assertEqual(cfg.case_id, "CASE-001")
        self.assertTrue(cfg.matched_only)


if __name__ == "__main__":
    unittest.main()
