"""
Unit tests for ForensiX Schema 8.0 Advanced Forensic Report Builder (V8.4).

Verifies:
- Deterministic report construction, schema validation, and deep immutability.
- Accurate integration of manifest verification results (matches, mismatches, missing files).
- Accurate integration of runtime custody ledgers (verified, unverified, tampered).
- Deterministic canonical JSON serialization.
- Secure, air-gapped HTML rendering with 100% strict escaping against hostile XSS inputs.
- Filesystem safety: no-clobber atomic writes, evidence-root overlap rejection, and evidence immutability.
"""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import tempfile
import unittest

from forensix import __version__
from forensix.advanced_report_builder import (
    build_advanced_report,
    render_advanced_report_html,
    render_advanced_report_json,
    write_advanced_report_html,
    write_advanced_report_json,
)
from forensix.advanced_report_models import (
    ADVANCED_REPORT_SCHEMA_VERSION,
    DEFAULT_ANALYTICAL_DISCLAIMER,
    AdvancedReport,
    AnalyticalLimitations,
    CustodySummary,
    EvidenceInventoryItem,
    FindingsSummary,
    is_valid_advanced_report_id,
)
from forensix.custody_ledger import (
    CustodyLedger,
    generate_custody_ledger_id,
)
from forensix.custody_models import (
    CUSTODY_LIMITATIONS_DISCLAIMER,
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
    generate_custody_event_id,
)
from forensix.investigation import HostArtifactInvestigator, InvestigationResultSet
from forensix.manifest_models import (
    HashAlgorithm,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    generate_manifest_id,
)
from forensix.manifest_verifier import (
    MANIFEST_VERIFICATION_NOTICE,
    verify_manifest,
)
from forensix.unified_models import HostArtifact, HostArtifactCategory


class TestAdvancedReportBuilder(unittest.TestCase):
    """Test suite for ForensiX Advanced Forensic Report Builder."""

    def setUp(self):
        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_sha256_alt = "1111111111111111111111111111111111111111111111111111111111111111"
        self.sample_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        self.case_meta = {
            "case_id": "CASE-2026-001",
            "case_name": "Project Aegis Investigation",
            "investigator": "Forensic Lead J. Doe",
            "evidence_root": "/var/evidence/case_001",
        }
        self.actor = CustodyActor(declared_identity="Forensic Analyst", role="Examiner")

    # =========================================================================
    # 1. Report Construction & Schema Validation Tests
    # =========================================================================

    def test_minimal_report_construction(self):
        """Verify report construction with minimal case metadata."""
        report = build_advanced_report(
            case_metadata=self.case_meta,
            created_at="2026-10-20T12:00:00Z",
        )
        self.assertIsInstance(report, AdvancedReport)
        self.assertEqual(report.report_schema, ADVANCED_REPORT_SCHEMA_VERSION)
        self.assertTrue(is_valid_advanced_report_id(report.report_id))
        self.assertEqual(report.created_at, "2026-10-20T12:00:00Z")
        self.assertEqual(report.forensix_version, __version__)
        self.assertEqual(report.case_metadata["case_id"], "CASE-2026-001")
        self.assertEqual(len(report.evidence_inventory), 0)
        self.assertEqual(report.findings_summary.total_host_artifacts, 0)
        self.assertIsNone(report.custody_summary)
        self.assertIn("Evidence inventory was not provided.", report.limitations.omissions)

    def test_deep_immutability_enforcement(self):
        """Ensure caller-owned objects cannot mutate the built report."""
        mutable_meta = {"case_id": "CASE-001", "nested": {"key": "original"}}
        report = build_advanced_report(case_metadata=mutable_meta)

        # Mutate the source dictionary
        mutable_meta["case_id"] = "MUTATED"
        mutable_meta["nested"]["key"] = "MUTATED"

        # Report state must remain pristine
        self.assertEqual(report.case_metadata["case_id"], "CASE-001")
        self.assertEqual(report.case_metadata["nested"]["key"], "original")

        # Report fields must reject reassignment
        with self.assertRaises(FrozenInstanceError):
            report.case_metadata = {"new": "dict"}  # type: ignore

    def test_explicit_report_id_validation(self):
        """Verify custom report ID acceptance or rejection."""
        custom_id = "REP8-a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
        report = build_advanced_report(
            case_metadata=self.case_meta,
            report_id=custom_id,
        )
        self.assertEqual(report.report_id, custom_id)

        # Invalid ID formats must be rejected
        with self.assertRaises(ValueError):
            build_advanced_report(case_metadata=self.case_meta, report_id="INVALID-ID")
        with self.assertRaises(ValueError):
            build_advanced_report(case_metadata=self.case_meta, report_id="REP8-not-a-valid-uuid")

    # =========================================================================
    # 2. Evidence Inventory & Manifest Integration Tests
    # =========================================================================

    def test_manifest_synthesis_without_verification(self):
        """Synthesize evidence inventory directly from a ManifestRecord."""
        entry1 = ManifestEntry(
            relative_path="var/log/syslog",
            size_bytes=1024,
            hashes={"sha256": self.sample_sha256},
            evidence_id="EV-001",
        )
        entry2 = ManifestEntry(
            relative_path="etc/passwd",
            size_bytes=512,
            hashes={"sha256": self.sample_sha256_alt},
        )
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry1, entry2],
        )

        report = build_advanced_report(
            case_metadata=self.case_meta,
            manifest=manifest,
        )
        self.assertEqual(len(report.evidence_inventory), 2)
        inv_by_path = {item.relative_path: item for item in report.evidence_inventory}
        item1 = inv_by_path["var/log/syslog"]
        self.assertEqual(item1.evidence_id, "EV-001")
        self.assertEqual(item1.relative_path, "var/log/syslog")
        self.assertEqual(item1.size_bytes, 1024)
        self.assertIsNone(item1.verification_status)

        item2 = inv_by_path["etc/passwd"]
        self.assertEqual(item2.evidence_id, "EV-etc/passwd")
        self.assertEqual(item2.relative_path, "etc/passwd")

    def test_manifest_synthesis_with_verification_results(self):
        """Synthesize inventory and map verification statuses (MATCH, MISMATCH, MISSING)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            file1 = temp_path / "clean.log"
            file1.write_bytes(b"")  # Hash is empty SHA-256

            file2 = temp_path / "tampered.log"
            file2.write_bytes(b"tampered content")  # Hash differs from empty SHA-256

            # Missing file3 will not be created on disk

            entry1 = ManifestEntry(
                relative_path="clean.log",
                size_bytes=0,
                hashes={"sha256": self.sample_sha256},
            )
            entry2 = ManifestEntry(
                relative_path="tampered.log",
                size_bytes=10,
                hashes={"sha256": self.sample_sha256},
            )
            entry3 = ManifestEntry(
                relative_path="missing.log",
                size_bytes=100,
                hashes={"sha256": self.sample_sha256},
            )
            manifest = ManifestRecord(
                manifest_id=generate_manifest_id(),
                manifest_version="8.0",
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[entry1, entry2, entry3],
            )

            # Perform manifest verification using V8.2 engine
            verif_result = verify_manifest(manifest=manifest, base_dir=temp_path)

            # Build report using manifest + verification
            report = build_advanced_report(
                case_metadata=self.case_meta,
                manifest=manifest,
                manifest_verification=verif_result,
            )

            inv_by_path = {item.relative_path: item for item in report.evidence_inventory}
            self.assertEqual(inv_by_path["clean.log"].verification_status, "VERIFIED")
            self.assertEqual(inv_by_path["tampered.log"].verification_status, "MISMATCH")
            self.assertEqual(inv_by_path["missing.log"].verification_status, "FILE_MISSING")

            # Warnings must honestly report discrepancies
            warning_text = " ".join(report.limitations.warnings)
            self.assertIn("hash mismatch(es) detected", warning_text)
            self.assertIn("evidence file(s) recorded in manifest are missing", warning_text)

    def test_conflicting_manifest_ids_rejected(self):
        """Reject manifest and manifest_verification with differing manifest_id values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            id1 = generate_manifest_id()
            id2 = generate_manifest_id()
            manifest1 = ManifestRecord(
                manifest_id=id1,
                manifest_version="8.0",
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[],
            )
            manifest2 = ManifestRecord(
                manifest_id=id2,
                manifest_version="8.0",
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[],
            )
            verif2 = verify_manifest(manifest=manifest2, base_dir=temp_dir)

            with self.assertRaises(ValueError) as ctx:
                build_advanced_report(
                    case_metadata=self.case_meta,
                    manifest=manifest1,
                    manifest_verification=verif2,
                )
            self.assertIn("Conflicting manifest_id", str(ctx.exception))

    def test_manifest_case_id_matching_accepted(self):
        """Manifest with matching case_id is accepted."""
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_id="CASE-2026-001",
            entries=[],
        )
        report = build_advanced_report(
            case_metadata=self.case_meta,  # Has "CASE-2026-001"
            manifest=manifest,
        )
        self.assertEqual(report.case_metadata["case_id"], "CASE-2026-001")

    def test_manifest_case_id_conflict_raises_value_error(self):
        """Manifest with conflicting case_id raises ValueError."""
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_id="CASE-CONFLICT-999",
            entries=[],
        )
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata=self.case_meta,  # Has "CASE-2026-001"
                manifest=manifest,
            )
        self.assertIn("Conflicting case_id", str(ctx.exception))

    def test_manifest_case_id_absent_preserves_behavior(self):
        """Manifest with absent/None case_id or case_metadata without case_id succeeds."""
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_id=None,
            entries=[],
        )
        # 1. Manifest case_id is None, case_metadata has case_id
        report1 = build_advanced_report(
            case_metadata=self.case_meta,
            manifest=manifest,
        )
        self.assertEqual(report1.case_metadata["case_id"], "CASE-2026-001")

        # 2. Both absent
        report2 = build_advanced_report(
            case_metadata={},
            manifest=manifest,
        )
        self.assertEqual(len(report2.evidence_inventory), 0)

    def test_manifest_and_custody_case_id_conflict_raises_value_error(self):
        """Conflict between manifest.case_id and custody_ledger.case_id raises ValueError."""
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_id="CASE-ALPHA",
            entries=[],
        )
        ledger = CustodyLedger(case_id="CASE-BETA")
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata={},
                manifest=manifest,
                custody_ledger=ledger,
            )
        self.assertIn("Conflicting case_id", str(ctx.exception))

    def test_simultaneous_inventory_and_manifest_raises_value_error(self):
        """Supplying both evidence_inventory and manifest raises ValueError."""
        item = EvidenceInventoryItem(
            evidence_id="EV-1",
            relative_path="file.txt",
            size_bytes=10,
            hashes={"sha256": self.sample_sha256},
            registration_timestamp="2026-10-20T10:00:00Z",
        )
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata=self.case_meta,
                evidence_inventory=[item],
                manifest=manifest,
            )
        self.assertIn("Conflicting inventory sources", str(ctx.exception))

    def test_empty_inventory_and_manifest_raises_value_error(self):
        """Supplying explicit empty evidence_inventory with manifest raises ValueError."""
        manifest = ManifestRecord(
            manifest_id=generate_manifest_id(),
            manifest_version="8.0",
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[],
        )
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata=self.case_meta,
                evidence_inventory=[],
                manifest=manifest,
            )
        self.assertIn("Conflicting inventory sources", str(ctx.exception))

    # =========================================================================
    # 3. Chain of Custody Integration Tests
    # =========================================================================

    def test_custody_integration_verified(self):
        """Integrate a verified runtime custody ledger."""
        ledger = CustodyLedger(
            case_id="CASE-2026-001",
            description="Custody ledger",
        )
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-001",
            actor=self.actor,
            notes="Acquired disk image",
        )

        report = build_advanced_report(
            case_metadata=self.case_meta,
            custody_ledger=ledger,
        )
        self.assertIsNotNone(report.custody_summary)
        summary = report.custody_summary
        self.assertEqual(summary.ledger_id, ledger.ledger_id)
        self.assertEqual(summary.total_events, 1)
        self.assertEqual(summary.chain_integrity, "VERIFIED")
        self.assertEqual(summary.terminal_hash, ledger.terminal_hash)
        self.assertIn(CUSTODY_LIMITATIONS_DISCLAIMER, report.limitations.evidentiary_disclaimer)

    def test_empty_custody_ledger_semantics(self):
        """Empty ledger preserves 0 events and UNVERIFIED status with honest warning."""
        ledger = CustodyLedger(
            case_id="CASE-2026-001",
        )
        report = build_advanced_report(
            case_metadata=self.case_meta,
            custody_ledger=ledger,
        )
        self.assertIsNotNone(report.custody_summary)
        summary = report.custody_summary
        self.assertEqual(summary.total_events, 0)
        self.assertEqual(summary.chain_integrity, "UNVERIFIED")
        self.assertIn(
            "Chain-of-custody ledger contains 0 events; custody chain status is UNVERIFIED.",
            report.limitations.warnings,
        )

    def test_tampered_custody_chain_preservation(self):
        """Tampered custody ledger preserves TAMPERED status and critical warning."""
        ledger = CustodyLedger(
            case_id="CASE-2026-001",
        )
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id="EV-001",
            actor=self.actor,
        )

        broken_ev = CustodyEvent(
            event_id=generate_custody_event_id(),
            sequence_number=1,
            timestamp="2026-10-20T10:30:00Z",
            timestamp_source=TimestampSource.HOST_SYSTEM_CLOCK,
            action_type=CustodyActionType.EVIDENCE_REGISTERED,
            evidence_id="EV-001",
            actor=self.actor,
            prev_event_hash="0" * 63 + "1",
        )
        ledger._events.append(broken_ev)

        report = build_advanced_report(
            case_metadata=self.case_meta,
            custody_ledger=ledger,
        )
        self.assertIsNotNone(report.custody_summary)
        self.assertEqual(report.custody_summary.chain_integrity, "TAMPERED")
        warning_text = " ".join(report.limitations.warnings)
        self.assertIn("CRITICAL WARNING: Chain-of-custody verification failed with status TAMPERED", warning_text)

    def test_conflicting_case_ids_rejected(self):
        """Reject conflict between case_metadata['case_id'] and custody_ledger.case_id."""
        ledger = CustodyLedger(
            case_id="CASE-DIFFERENT-999",
        )
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata=self.case_meta,  # Has "CASE-2026-001"
                custody_ledger=ledger,
            )
        self.assertIn("Conflicting case_id", str(ctx.exception))

    # =========================================================================
    # 4. Investigation & Findings Synthesis Tests
    # =========================================================================

    def test_findings_from_investigation_result_set(self):
        """Extract artifact counts from an InvestigationResultSet."""
        from forensix.artifacts import ArtifactRecord
        from forensix.unified_adapter import to_host_artifact

        rec1 = ArtifactRecord(
            artifact_id="ART-001",
            relative_path="var/log/syslog",
            source_path="/var/log/syslog",
            category="log",
            artifact_type="syslog",
            is_known=True,
            size=1024,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-30T10:00:00Z",
            md5=self.sample_md5,
            sha256=self.sample_sha256,
            status="collected",
        )
        rec2 = ArtifactRecord(
            artifact_id="ART-002",
            relative_path="var/log/auth.log",
            source_path="/var/log/auth.log",
            category="log",
            artifact_type="auth_log",
            is_known=True,
            size=2048,
            permissions="0644",
            modified="2026-09-30T10:00:00Z",
            accessed="2026-09-30T10:00:00Z",
            created="2026-09-30T10:00:00Z",
            md5=self.sample_md5,
            sha256=self.sample_sha256,
            status="collected",
        )
        art1 = to_host_artifact(rec1)
        art2 = to_host_artifact(rec2)
        investigator = HostArtifactInvestigator([art1, art2])
        query_result = investigator.filter_by_status("collected")

        report = build_advanced_report(
            case_metadata=self.case_meta,
            investigation_results=query_result,
        )
        self.assertEqual(report.findings_summary.total_host_artifacts, 2)

    def test_explicit_findings_summary_rejection_of_booleans(self):
        """FindingsSummary must strictly reject boolean values for integer counters."""
        with self.assertRaises(TypeError):
            FindingsSummary(total_host_artifacts=True)  # type: ignore

    # =========================================================================
    # 5. Deterministic JSON Serialization Tests
    # =========================================================================

    def test_json_serialization_determinism(self):
        """Repeated JSON serialization of identical data produces identical bytes."""
        fixed_time = "2026-10-20T12:00:00Z"
        fixed_id = "REP8-11111111-2222-4333-8444-555555555555"
        report1 = build_advanced_report(
            case_metadata=self.case_meta,
            report_id=fixed_id,
            created_at=fixed_time,
        )
        report2 = build_advanced_report(
            case_metadata=self.case_meta,
            report_id=fixed_id,
            created_at=fixed_time,
        )
        json1 = render_advanced_report_json(report1)
        json2 = render_advanced_report_json(report2)
        self.assertEqual(json1, json2)

    def test_json_roundtrip_fidelity(self):
        """Verify report deserialization produces valid JSON data matching original."""
        report = build_advanced_report(case_metadata=self.case_meta)
        rendered = render_advanced_report_json(report)
        parsed = json.loads(rendered)
        self.assertEqual(parsed["report_schema"], "8.0")
        self.assertEqual(parsed["report_id"], report.report_id)
        self.assertEqual(parsed["case_metadata"]["case_id"], "CASE-2026-001")

    # =========================================================================
    # 6. HTML Rendering & XSS Security Tests
    # =========================================================================

    def test_html_rendering_structure(self):
        """Verify HTML report includes all 6 Schema 8.0 sections."""
        report = build_advanced_report(case_metadata=self.case_meta)
        html_out = render_advanced_report_html(report)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("Case Information", html_out)
        self.assertIn("Chain of Custody Summary", html_out)
        self.assertIn("Evidence Inventory", html_out)
        self.assertIn("Analytical Findings Summary", html_out)
        self.assertIn("Analytical Limitations &amp; Evidentiary Disclaimers", html_out)
        self.assertNotIn("http://", html_out)
        self.assertNotIn("https://", html_out)

    def test_html_strict_escaping_against_xss(self):
        """Hostile strings in metadata, paths, or notes must be escaped strictly."""
        hostile_meta = {
            "case_id": "<script>alert('xss')</script>",
            "investigator": '"><img src=x onerror=alert(1)>',
            "case_name": "Normal & 'Quotes' <and> Symbols",
        }
        report = build_advanced_report(case_metadata=hostile_meta)
        html_out = render_advanced_report_html(report)

        # Raw executable tags must never appear in HTML
        self.assertNotIn("<script>alert('xss')</script>", html_out)
        self.assertNotIn("<img src=x onerror=alert(1)>", html_out)

        # Escaped versions must appear
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_out)
        self.assertIn("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", html_out)
        self.assertIn("Normal &amp; &#x27;Quotes&#x27; &lt;and&gt; Symbols", html_out)

    # =========================================================================
    # 7. Filesystem & Evidence Safety Tests
    # =========================================================================

    def test_refuse_overwrite_by_default(self):
        """Writing report raises FileExistsError if destination exists and overwrite=False."""
        report = build_advanced_report(case_metadata=self.case_meta)
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "report.json"
            out_file.write_text("existing content", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                write_advanced_report_json(report, out_file, overwrite=False)

            # Assert original content was not clobbered
            self.assertEqual(out_file.read_text(encoding="utf-8"), "existing content")

    def test_successful_atomic_overwrite(self):
        """Writing report replaces destination when overwrite=True."""
        report = build_advanced_report(case_metadata=self.case_meta)
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "report.json"
            out_file.write_text("existing content", encoding="utf-8")

            written_path = write_advanced_report_json(report, out_file, overwrite=True)
            self.assertEqual(written_path, out_file.resolve())
            new_content = out_file.read_text(encoding="utf-8")
            self.assertIn("report_schema", new_content)

    def test_rejection_of_output_inside_evidence_root(self):
        """Never write reports inside or overlapping evidence directory."""
        with tempfile.TemporaryDirectory() as ev_dir:
            ev_path = Path(ev_dir)
            report = build_advanced_report(
                case_metadata={"case_id": "C-1", "evidence_root": str(ev_path)}
            )

            # Destination inside evidence directory
            target_inside = ev_path / "subfolder" / "report.json"
            with self.assertRaises(ValueError) as ctx:
                write_advanced_report_json(report, target_inside, evidence_root=ev_path)
            self.assertIn("overlaps or is located inside evidence root", str(ctx.exception))

            # Direct destination matching evidence directory itself
            with self.assertRaises(ValueError):
                write_advanced_report_html(report, ev_path, evidence_root=ev_path)

            # Even with overwrite=True, evidence directory write MUST be refused
            with self.assertRaises(ValueError):
                write_advanced_report_json(report, target_inside, overwrite=True, evidence_root=ev_path)

    def test_evidence_bytes_and_mtime_remain_unmodified(self):
        """Verify evidence files are strictly unmodified during report generation and writing."""
        with tempfile.TemporaryDirectory() as ev_dir, tempfile.TemporaryDirectory() as report_dir:
            ev_path = Path(ev_dir)
            test_file = ev_path / "disk.img"
            test_file.write_bytes(b"FORENSIC_RAW_BYTES_1234567890")
            initial_stat = test_file.stat()
            initial_bytes = test_file.read_bytes()

            report = build_advanced_report(
                case_metadata={"case_id": "C-1", "evidence_root": str(ev_path)}
            )
            out_report = Path(report_dir) / "report.html"
            write_advanced_report_html(report, out_report, evidence_root=ev_path)

            # Ensure report was written
            self.assertTrue(out_report.exists())

            # Verify evidence file unchanged in content, size, and modification time
            current_stat = test_file.stat()
            self.assertEqual(test_file.read_bytes(), initial_bytes)
            self.assertEqual(current_stat.st_mtime_ns, initial_stat.st_mtime_ns)
            self.assertEqual(current_stat.st_size, initial_stat.st_size)

    def test_direct_evidence_inventory_acceptance(self):
        """Build report from pre-constructed sequence of EvidenceInventoryItem instances."""
        item = EvidenceInventoryItem(
            evidence_id="EV-DIRECT-01",
            relative_path="opt/data.db",
            size_bytes=4096,
            hashes={"sha256": self.sample_sha256},
            registration_timestamp="2026-10-20T08:00:00Z",
            verification_status="VERIFIED",
        )
        report = build_advanced_report(
            case_metadata=self.case_meta,
            evidence_inventory=[item],
        )
        self.assertEqual(len(report.evidence_inventory), 1)
        self.assertEqual(report.evidence_inventory[0].evidence_id, "EV-DIRECT-01")

    def test_direct_custody_summary_acceptance(self):
        """Build report from pre-constructed CustodySummary without raw ledger."""
        summary = CustodySummary(
            ledger_id="COCLEDGER-550e8400-e29b-41d4-a716-446655440000",
            total_events=5,
            terminal_hash=self.sample_sha256,
            chain_integrity="VERIFIED",
        )
        report = build_advanced_report(
            case_metadata=self.case_meta,
            custody_summary=summary,
        )
        self.assertIsNotNone(report.custody_summary)
        self.assertEqual(report.custody_summary.ledger_id, "COCLEDGER-550e8400-e29b-41d4-a716-446655440000")

    def test_conflicting_custody_summary_and_ledger(self):
        """Reject when caller provides both custody_ledger and custody_summary with different IDs."""
        ledger = CustodyLedger(case_id="CASE-2026-001")
        summary = CustodySummary(
            ledger_id="COCLEDGER-550e8400-e29b-41d4-a716-446655449999",
            total_events=1,
            terminal_hash=self.sample_sha256,
            chain_integrity="VERIFIED",
        )
        with self.assertRaises(ValueError) as ctx:
            build_advanced_report(
                case_metadata=self.case_meta,
                custody_ledger=ledger,
                custody_summary=summary,
            )
        self.assertIn("Conflicting custody identifiers", str(ctx.exception))

    def test_details_deep_immutability(self):
        """Verify report details mapping is deeply frozen against caller mutation."""
        mutable_details = {"key": "val", "nested": {"list": [1, 2, 3]}}
        report = build_advanced_report(
            case_metadata=self.case_meta,
            details=mutable_details,
        )
        mutable_details["key"] = "MUTATED"
        mutable_details["nested"]["list"].append(4)

        self.assertEqual(report.details["key"], "val")
        self.assertEqual(list(report.details["nested"]["list"]), [1, 2, 3])

    def test_invalid_case_metadata_type_raises(self):
        """Reject non-Mapping case_metadata."""
        with self.assertRaises(TypeError):
            build_advanced_report(case_metadata=["not", "a", "mapping"])  # type: ignore

    def test_destination_is_directory_raises(self):
        """Reject destination path that is an existing directory."""
        report = build_advanced_report(case_metadata=self.case_meta)
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            with self.assertRaises(IsADirectoryError):
                write_advanced_report_json(report, dir_path)

    def test_symlink_inside_evidence_root_rejection(self):
        """Reject destination path that traverses a symlink into evidence root."""
        with tempfile.TemporaryDirectory() as ev_dir, tempfile.TemporaryDirectory() as outside_dir:
            ev_path = Path(ev_dir)
            outside_path = Path(outside_dir)

            # Create symlink outside that points inside evidence directory
            symlink_to_ev = outside_path / "link_to_evidence"
            try:
                symlink_to_ev.symlink_to(ev_path, target_is_directory=True)
            except OSError:
                self.skipTest("Symlinks not supported on this platform/filesystem")

            report = build_advanced_report(case_metadata=self.case_meta)
            target = symlink_to_ev / "forbidden_report.json"

            with self.assertRaises(ValueError) as ctx:
                write_advanced_report_json(report, target, evidence_root=ev_path)
            self.assertIn("overlaps or is located inside evidence root", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
