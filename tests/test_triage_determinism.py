"""
Comprehensive Determinism Test Suite for ForensiX Milestone V2.9.6.

Verifies:
11. Stable HostArtifact ordering
12. Stable investigation query ordering
13. Stable JSON report logical content
14. Stable CSV report logical content
15. Stable HTML report logical content
16. Stable canonical stage ordering
17. Stable trace records ordering
18. Stable audit event ordering
19. Stable summary metrics
20. Stable failure and skipped dependency behavior
21. Input sequence independence (shuffled/reversed inputs)
22. Configuration determinism (identical config -> identical output)
"""

import copy
import csv
import json
from pathlib import Path
import random
import shutil
import tempfile
from typing import Any, Dict, List
import unittest
from unittest.mock import patch

from forensix.investigation import (
    ArtifactQuery,
    HostArtifactInvestigator,
    InvestigationResultSet,
)
from forensix.report_csv import render_csv_report
from forensix.report_html import render_html_report
from forensix.report_json import render_json_report
from forensix.triage_models import (
    ALL_TRIAGE_STAGES,
    TriageConfig,
    TriageResult,
    TriageStage,
    TriageStageStatus,
)
from forensix.triage_orchestrator import TriageOrchestrator
from forensix.unified_adapter import build_host_artifact_collection, to_host_artifact


class TestTriageDeterminism(unittest.TestCase):
    """Test suite verifying forensic determinism across ForensiX V2 components (V2.9.6)."""

    def setUp(self):
        """Create controlled fixture evidence directory."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_determinism_test_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup standard artifacts
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)

        (etc_dir / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
            "bob:x:1002:1002:Bob:/home/bob:/bin/sh\n",
            encoding="utf-8",
        )
        (etc_dir / "group").write_text(
            "root:x:0:\n"
            "alice:x:1001:\n"
            "bob:x:1002:\n",
            encoding="utf-8",
        )
        cron_dir = etc_dir / "cron.d"
        cron_dir.mkdir(parents=True, exist_ok=True)
        (cron_dir / "daily_sync").write_text("0 0 * * * root /bin/sync\n", encoding="utf-8")

        (log_dir / "auth.log").write_text(
            "Sep 30 10:00:00 test-host sshd[100]: Accepted password for root from 192.168.1.1 port 22 ssh2\n"
            "Sep 30 10:05:00 test-host sshd[101]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2\n",
            encoding="utf-8",
        )

    def tearDown(self):
        """Clean up workspace."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _normalize_json_report(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize intentionally run-specific fields (triage_id, timestamps, report_id, generated IDs) for deterministic comparison."""
        d = copy.deepcopy(json_data)
        if "metadata" in d:
            d["metadata"]["report_id"] = "NORMALIZED"
            d["metadata"]["triage_id"] = "NORMALIZED"
            d["metadata"]["generated_at"] = "NORMALIZED"
            d["metadata"]["created_at"] = "NORMALIZED"
        if "summary" in d:
            d["summary"]["triage_id"] = "NORMALIZED"
            d["summary"]["started_at"] = "NORMALIZED"
            d["summary"]["completed_at"] = "NORMALIZED"
            d["summary"]["total_duration_seconds"] = 0.0
        if "artifacts" in d:
            for art in d["artifacts"]:
                art["unified_id"] = "NORMALIZED"
                art["source_id"] = "NORMALIZED"
                art["source_event_id"] = "NORMALIZED" if art.get("source_event_id") else None
                art["source_artifact_id"] = "NORMALIZED" if art.get("source_artifact_id") else None
                if isinstance(art.get("specialized_payload"), dict):
                    sp = art["specialized_payload"]
                    for k in list(sp.keys()):
                        if "id" in k or "timestamp" in k or "time" in k or "collected_at" in k:
                            sp[k] = "NORMALIZED"
        if "audit_trail" in d:
            for ev in d["audit_trail"]:
                ev["audit_id"] = "NORMALIZED"
                ev["timestamp"] = "NORMALIZED"
                ev["related_id"] = "NORMALIZED"
                if "metadata" in ev:
                    ev["metadata"] = {}
        if "stage_results" in d:
            for st in d["stage_results"]:
                st["started_at"] = "NORMALIZED"
                st["completed_at"] = "NORMALIZED"
                st["duration_seconds"] = 0.0
        if "trace_records" in d:
            for tr in d["trace_records"]:
                tr["triage_id"] = "NORMALIZED"
                tr["timestamp"] = "NORMALIZED"
                tr["unified_artifact_ids"] = []
                tr["input_identifiers"] = ["NORMALIZED"] * len(tr.get("input_identifiers", []))
                tr["output_identifiers"] = ["NORMALIZED"] * len(tr.get("output_identifiers", []))
                tr["source_artifact_ids"] = ["NORMALIZED"] * len(tr.get("source_artifact_ids", []))
                tr["source_event_ids"] = ["NORMALIZED"] * len(tr.get("source_event_ids", []))
        return d

    # 11. Stable HostArtifact ordering
    def test_11_stable_host_artifact_ordering(self):
        """Verify HostArtifactCollection orders artifacts deterministically regardless of input order."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-DET-11",
        )
        result = TriageOrchestrator(cfg).run()
        artifacts = list(result.artifacts.artifacts)
        self.assertGreater(len(artifacts), 0)

        # Shuffle artifacts and re-build collection
        shuffled = list(artifacts)
        random.seed(42)
        random.shuffle(shuffled)

        collection1 = build_host_artifact_collection(
            evidence_root=str(self.evidence_dir),
            records=[a.specialized_payload for a in artifacts],
            collected_at="2026-09-30T00:00:00Z",
        )
        collection2 = build_host_artifact_collection(
            evidence_root=str(self.evidence_dir),
            records=[a.specialized_payload for a in shuffled],
            collected_at="2026-09-30T00:00:00Z",
        )

        keys1 = [(a.source_path, a.line_number, a.category, a.source_id) for a in collection1.artifacts]
        keys2 = [(a.source_path, a.line_number, a.category, a.source_id) for a in collection2.artifacts]
        self.assertEqual(keys1, keys2)
        self.assertEqual(collection1.category_counts, collection2.category_counts)
        self.assertEqual(collection1.status_counts, collection2.status_counts)

    # 12. Stable investigation ordering
    def test_12_stable_investigation_ordering(self):
        """Verify HostArtifactInvestigator produces identically ordered results for identical queries."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-DET-12",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        inv1 = HostArtifactInvestigator(res1.artifacts)
        inv2 = HostArtifactInvestigator(res2.artifacts)

        # Query by category
        q1 = inv1.query(category="authentication")
        q2 = inv2.query(category="authentication")

        self.assertEqual(q1.total_matches, q2.total_matches)
        keys_q1 = [(a.source_path, a.line_number, a.category, a.artifact_type, a.status, a.raw_data) for a in q1.artifacts]
        keys_q2 = [(a.source_path, a.line_number, a.category, a.artifact_type, a.status, a.raw_data) for a in q2.artifacts]
        self.assertEqual(keys_q1, keys_q2)
        self.assertEqual(q1.category_breakdown, q2.category_breakdown)
        self.assertEqual(q1.status_breakdown, q2.status_breakdown)

        # Query by text search
        s1 = inv1.search_text("root")
        s2 = inv2.search_text("root")
        self.assertEqual(s1.total_matches, s2.total_matches)
        keys_s1 = [(a.source_path, a.line_number, a.category, a.artifact_type, a.status, a.raw_data) for a in s1.artifacts]
        keys_s2 = [(a.source_path, a.line_number, a.category, a.artifact_type, a.status, a.raw_data) for a in s2.artifacts]
        self.assertEqual(keys_s1, keys_s2)

    # 13. Stable JSON logical content
    def test_13_stable_json_logical_content(self):
        """Verify two independent triage runs on the same evidence produce identical normalized JSON reports."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json",),
            case_id="CASE-DET-13",
        )
        res1 = TriageOrchestrator(cfg).run()
        json_path1 = Path(res1.report_files[0][1])
        data1 = json.loads(json_path1.read_text(encoding="utf-8"))

        res2 = TriageOrchestrator(cfg).run()
        json_path2 = Path(res2.report_files[0][1])
        data2 = json.loads(json_path2.read_text(encoding="utf-8"))

        norm1 = self._normalize_json_report(data1)
        norm2 = self._normalize_json_report(data2)
        self.assertEqual(norm1, norm2)

    # 14. Stable CSV logical content
    def test_14_stable_csv_logical_content(self):
        """Verify two runs produce equivalent CSV row ordering and columns, ignoring run-specific generated IDs."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("csv",),
            case_id="CASE-DET-14",
        )
        res1 = TriageOrchestrator(cfg).run()
        rows1 = list(csv.reader(Path(res1.report_files[0][1]).read_text(encoding="utf-8").splitlines()))

        res2 = TriageOrchestrator(cfg).run()
        rows2 = list(csv.reader(Path(res2.report_files[0][1]).read_text(encoding="utf-8").splitlines()))

        self.assertEqual(len(rows1), len(rows2))
        self.assertEqual(rows1[0], rows2[0])  # Headers match exactly

        # Compare factual content across data rows: category, artifact_type, source_path, line_number, status, raw_data
        for r1, r2 in zip(rows1[1:], rows2[1:]):
            core1 = [r1[1], r1[2], r1[6], r1[7], r1[8], r1[9]]
            core2 = [r2[1], r2[2], r2[6], r2[7], r2[8], r2[9]]
            self.assertEqual(core1, core2)

    # 15. Stable HTML logical content
    def test_15_stable_html_logical_content(self):
        """Verify HTML reports have identical sections in exact numerical order across runs."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("html",),
            case_id="CASE-DET-15",
        )
        res1 = TriageOrchestrator(cfg).run()
        html1 = Path(res1.report_files[0][1]).read_text(encoding="utf-8")

        res2 = TriageOrchestrator(cfg).run()
        html2 = Path(res2.report_files[0][1]).read_text(encoding="utf-8")

        # Canonical numbered sections must appear in exact numerical order
        sections = [
            "1. Case Information",
            "2. Investigation Summary",
            "3. Artifact Statistics",
            "4. Artifacts",
            "5. Source / Lineage Information",
            "6. Audit Information",
            "7. Pipeline Execution & Traceability",
        ]
        last_pos1, last_pos2 = -1, -1
        for sec in sections:
            pos1 = html1.find(sec)
            pos2 = html2.find(sec)
            self.assertGreater(pos1, last_pos1, f"Section {sec} out of order in HTML run 1")
            self.assertGreater(pos2, last_pos2, f"Section {sec} out of order in HTML run 2")
            last_pos1, last_pos2 = pos1, pos2

    # 16. Stable stage ordering
    def test_16_stable_stage_ordering(self):
        """Verify stage execution order strictly adheres to canonical 9 stages in all runs."""
        for run_idx in range(3):
            cfg = TriageConfig(
                evidence_path=str(self.evidence_dir),
                skip_reports=True,
                case_id=f"CASE-DET-16-{run_idx}",
            )
            result = TriageOrchestrator(cfg).run()
            observed = tuple(sr.stage_id for sr in result.stage_results)
            self.assertEqual(observed, ALL_TRIAGE_STAGES)

    # 17. Stable trace ordering
    def test_17_stable_trace_ordering(self):
        """Verify trace records match canonical stage progression in every run."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-DET-17",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        traces1 = [tr.stage_id for tr in res1.trace_records]
        traces2 = [tr.stage_id for tr in res2.trace_records]
        self.assertEqual(traces1, traces2)
        self.assertEqual(traces1, list(ALL_TRIAGE_STAGES))

    # 18. Stable audit event ordering
    def test_18_stable_audit_event_ordering(self):
        """Verify audit events follow deterministic lifecycle order across runs."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-DET-18",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        ev_types1 = [e.event_type for e in res1.audit_trail]
        ev_types2 = [e.event_type for e in res2.audit_trail]
        self.assertEqual(ev_types1, ev_types2)
        self.assertEqual(ev_types1[0], "TRIAGE_STARTED")
        self.assertEqual(ev_types1[-1], "TRIAGE_COMPLETED")

    # 19. Stable metrics
    def test_19_stable_metrics(self):
        """Verify summary metrics (artifact counts, stage counts, success state) are identical across repeated runs."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
            case_id="CASE-DET-19",
        )
        res1 = TriageOrchestrator(cfg).run()
        res2 = TriageOrchestrator(cfg).run()

        s1, s2 = res1.summary, res2.summary
        self.assertEqual(s1.total_artifacts, s2.total_artifacts)
        self.assertEqual(s1.stages_completed, s2.stages_completed)
        self.assertEqual(s1.stages_partial, s2.stages_partial)
        self.assertEqual(s1.stages_failed, s2.stages_failed)
        self.assertEqual(s1.stages_skipped, s2.stages_skipped)
        self.assertEqual(s1.is_success, s2.is_success)

    # 20. Stable failure behavior
    def test_20_stable_failure_behavior(self):
        """Verify that a controlled failure produces identical stage statuses and skipped dependencies across runs."""
        for _ in range(2):
            with patch.object(
                TriageOrchestrator,
                "_execute_log_parsing",
                side_effect=RuntimeError("Forced log parsing failure"),
            ):
                cfg = TriageConfig(
                    evidence_path=str(self.evidence_dir),
                    skip_reports=True,
                    case_id="CASE-DET-20",
                )
                res = TriageOrchestrator(cfg).run()
                self.assertFalse(res.summary.is_success)
                self.assertEqual(res.summary.stages_failed, 1)

                statuses = {sr.stage_id: sr.status for sr in res.stage_results}
                self.assertEqual(statuses["log_parsing"], TriageStageStatus.FAILED.value)
                # Dependent stage authentication_analysis must be skipped deterministically
                self.assertEqual(statuses["authentication_analysis"], TriageStageStatus.SKIPPED.value)


    # 21. Input sequence independence
    def test_21_input_sequence_independence(self):
        """Verify that passing inputs in reverse order produces identical canonical HostArtifactCollection."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            skip_reports=True,
        )
        res = TriageOrchestrator(cfg).run()
        orig_records = [a.specialized_payload for a in res.artifacts.artifacts]
        rev_records = list(reversed(orig_records))

        col1 = build_host_artifact_collection(str(self.evidence_dir), orig_records, collected_at="2026-09-30T00:00:00Z")
        col2 = build_host_artifact_collection(str(self.evidence_dir), rev_records, collected_at="2026-09-30T00:00:00Z")

        keys1 = [(a.source_path, a.line_number, a.source_id) for a in col1.artifacts]
        keys2 = [(a.source_path, a.line_number, a.source_id) for a in col2.artifacts]
        self.assertEqual(keys1, keys2)

    # 22. Configuration determinism
    def test_22_configuration_determinism(self):
        """Verify identical configuration produces identical stage selection and outputs."""
        cfg1 = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-CFG",
            enabled_stages=(TriageStage.EVIDENCE_VALIDATION, TriageStage.FILESYSTEM_COLLECTION),
            skip_reports=True,
        )
        cfg2 = TriageConfig(
            evidence_path=str(self.evidence_dir),
            case_id="CASE-CFG",
            enabled_stages=(TriageStage.EVIDENCE_VALIDATION, TriageStage.FILESYSTEM_COLLECTION),
            skip_reports=True,
        )
        self.assertEqual(cfg1, cfg2)
        res1 = TriageOrchestrator(cfg1).run()
        res2 = TriageOrchestrator(cfg2).run()
        self.assertEqual(res1.summary.stages_completed, res2.summary.stages_completed)
        self.assertEqual(res1.summary.stages_skipped, res2.summary.stages_skipped)
