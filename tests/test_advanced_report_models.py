"""
Unit tests for ForensiX Advanced Report Models (advanced_report_models.py).
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.advanced_report_models import (
    ADVANCED_REPORT_SCHEMA_VERSION,
    DEFAULT_ANALYTICAL_DISCLAIMER,
    AdvancedReport,
    AnalyticalLimitations,
    CustodySummary,
    EvidenceInventoryItem,
    FindingsSummary,
    generate_advanced_report_id,
    is_valid_advanced_report_id,
)


class TestAdvancedReportModels(unittest.TestCase):
    """Test suite for Schema 8.0 Advanced Forensic Report and sub-models."""

    def setUp(self):
        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_md5 = "d41d8cd98f00b204e9800998ecf8427e"

    def test_schema_version_constant(self):
        """Ensure ADVANCED_REPORT_SCHEMA_VERSION is 8.0."""
        self.assertEqual(ADVANCED_REPORT_SCHEMA_VERSION, "8.0")

    def test_generate_and_validate_advanced_report_id(self):
        """Verify REP8-<UUIDv4> canonical format."""
        rid = generate_advanced_report_id()
        self.assertTrue(is_valid_advanced_report_id(rid))
        self.assertTrue(rid.startswith("REP8-"))
        self.assertEqual(len(rid), 5 + 36)

        # Invalid cases
        self.assertFalse(is_valid_advanced_report_id("REP8-not-a-uuid"))
        self.assertFalse(is_valid_advanced_report_id("INVALID-550e8400-e29b-41d4-a716-446655440000"))
        self.assertFalse(is_valid_advanced_report_id(rid.upper()))
        self.assertFalse(is_valid_advanced_report_id(123))

    def test_evidence_inventory_item_validation(self):
        """Verify EvidenceInventoryItem validation and immutability."""
        item = EvidenceInventoryItem(
            evidence_id="EV-100",
            relative_path="var/log/auth.log",
            size_bytes=2048,
            hashes={"sha256": self.sample_sha256, "md5": self.sample_md5},
            registration_timestamp="2026-10-20T08:00:00Z",
            verification_status="MATCH",
        )
        self.assertEqual(item.evidence_id, "EV-100")
        self.assertEqual(item.relative_path, "var/log/auth.log")
        self.assertEqual(item.size_bytes, 2048)
        self.assertEqual(item.verification_status, "MATCH")

        # Frozen check
        with self.assertRaises(FrozenInstanceError):
            item.size_bytes = 4096

        # Reject booleans
        with self.assertRaises(TypeError):
            EvidenceInventoryItem(
                evidence_id="EV-100",
                relative_path="var/log/auth.log",
                size_bytes=False,
                hashes={"sha256": self.sample_sha256},
                registration_timestamp="2026-10-20T08:00:00Z",
            )

        # Reject path traversal
        with self.assertRaises(ValueError):
            EvidenceInventoryItem(
                evidence_id="EV-100",
                relative_path="../../etc/shadow",
                size_bytes=100,
                hashes={"sha256": self.sample_sha256},
                registration_timestamp="2026-10-20T08:00:00Z",
            )

        # Reject empty hash collections
        with self.assertRaises(ValueError) as ctx_empty:
            EvidenceInventoryItem(
                evidence_id="EV-100",
                relative_path="var/log/auth.log",
                size_bytes=100,
                hashes={},
                registration_timestamp="2026-10-20T08:00:00Z",
            )
        self.assertIn("EvidenceInventoryItem must contain at least one valid cryptographic hash", str(ctx_empty.exception))

        with self.assertRaises(ValueError):
            EvidenceInventoryItem(
                evidence_id="EV-100",
                relative_path="var/log/auth.log",
                size_bytes=100,
                hashes=(),
                registration_timestamp="2026-10-20T08:00:00Z",
            )

    def test_findings_summary_validation(self):
        """Verify FindingsSummary integer counters and boolean rejection."""
        summary = FindingsSummary(
            total_host_artifacts=10,
            total_timeline_events=25,
            total_correlations=2,
            total_rule_evaluations=5,
            matched_detections=1,
        )
        d = summary.to_dict()
        self.assertEqual(d["total_host_artifacts"], 10)
        self.assertEqual(d["matched_detections"], 1)

        # Reject boolean
        with self.assertRaises(TypeError):
            FindingsSummary(total_host_artifacts=True)

        # Reject negative
        with self.assertRaises(ValueError):
            FindingsSummary(total_timeline_events=-1)

    def test_custody_summary_validation(self):
        """Verify CustodySummary terminal hash, event counts, and chain integrity enum."""
        summary = CustodySummary(
            ledger_id="COC-LEDGER-01",
            total_events=3,
            terminal_hash=self.sample_sha256,
            chain_integrity="VERIFIED",
        )
        self.assertEqual(summary.ledger_id, "COC-LEDGER-01")
        self.assertEqual(summary.total_events, 3)
        self.assertEqual(summary.terminal_hash, self.sample_sha256)
        self.assertEqual(summary.chain_integrity, "VERIFIED")

        # Reject boolean event count
        with self.assertRaises(TypeError):
            CustodySummary(
                ledger_id="COC-01",
                total_events=False,
                terminal_hash=self.sample_sha256,
            )

        # Reject invalid terminal hash
        with self.assertRaises(ValueError):
            CustodySummary(
                ledger_id="COC-01",
                total_events=1,
                terminal_hash="bad_hash",
            )

        # Reject invalid chain integrity status
        with self.assertRaises(ValueError):
            CustodySummary(
                ledger_id="COC-01",
                total_events=1,
                terminal_hash=self.sample_sha256,
                chain_integrity="INVALID_STATUS",
            )

    def test_analytical_limitations_defaults(self):
        """Verify AnalyticalLimitations default disclaimer and tuple freezing."""
        limitations = AnalyticalLimitations(
            warnings=["File unreadable", "Permissions denied"],
            omissions=["Memory triage omitted"],
        )
        self.assertEqual(len(limitations.warnings), 2)
        self.assertEqual(len(limitations.omissions), 1)
        self.assertEqual(limitations.evidentiary_disclaimer, DEFAULT_ANALYTICAL_DISCLAIMER)

        d = limitations.to_dict()
        self.assertIsInstance(d["warnings"], list)
        self.assertEqual(d["warnings"], ["File unreadable", "Permissions denied"])

    def test_advanced_report_full_construction_and_immutability(self):
        """Verify complete Schema 8.0 AdvancedReport construction and deep immutability."""
        rid = generate_advanced_report_id()
        item = EvidenceInventoryItem(
            evidence_id="EV-100",
            relative_path="var/log/auth.log",
            size_bytes=512,
            hashes={"sha256": self.sample_sha256},
            registration_timestamp="2026-10-20T08:00:00Z",
        )
        findings = FindingsSummary(total_host_artifacts=5)
        custody = CustodySummary(
            ledger_id="COC-01",
            total_events=1,
            terminal_hash=self.sample_sha256,
            chain_integrity="VERIFIED",
        )
        limitations = AnalyticalLimitations()

        mutable_meta = {"case_id": "CASE-2026-001", "nested": {"analyst": "Jane"}}
        mutable_details = {"stage": "Stage 9", "extra": [1, 2, 3]}

        report = AdvancedReport(
            report_schema=ADVANCED_REPORT_SCHEMA_VERSION,
            report_id=rid,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_metadata=mutable_meta,
            evidence_inventory=[item],
            findings_summary=findings,
            custody_summary=custody,
            limitations=limitations,
            details=mutable_details,
        )

        # Mutate caller dictionaries
        mutable_meta["case_id"] = "MUTATED"
        mutable_details["stage"] = "MUTATED"

        # Verify report values remain frozen and intact
        self.assertEqual(report.case_metadata["case_id"], "CASE-2026-001")
        self.assertEqual(report.details["stage"], "Stage 9")

        # Verify frozen instance errors on report
        with self.assertRaises(FrozenInstanceError):
            report.report_id = "REP8-new"

    def test_advanced_report_rejects_wrong_schema(self):
        """AdvancedReport must strictly require report_schema == '8.0'."""
        rid = generate_advanced_report_id()
        with self.assertRaises(ValueError):
            AdvancedReport(
                report_schema="7.0",
                report_id=rid,
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                case_metadata={},
                evidence_inventory=[],
                findings_summary=FindingsSummary(),
                limitations=AnalyticalLimitations(),
            )

    def test_advanced_report_to_dict_round_trip(self):
        """Verify to_dict produces a pure, valid JSON-serializable dictionary."""
        rid = generate_advanced_report_id()
        report = AdvancedReport(
            report_schema=ADVANCED_REPORT_SCHEMA_VERSION,
            report_id=rid,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_metadata={"case_id": "CASE-42", "investigator": "Analyst"},
            evidence_inventory=[],
            findings_summary=FindingsSummary(total_host_artifacts=12),
            limitations=AnalyticalLimitations(),
            custody_summary=None,
            details={"artifacts_count": 12},
        )
        d = report.to_dict()
        self.assertEqual(d["report_schema"], "8.0")
        self.assertEqual(d["report_id"], rid)
        self.assertEqual(d["case_metadata"]["case_id"], "CASE-42")
        self.assertNotIn("custody_summary", d)
        self.assertEqual(d["details"], {"artifacts_count": 12})

        # Ensure json.dumps serializes cleanly without TypeError
        serialized = json.dumps(d)
        self.assertIn(rid, serialized)
        self.assertIn('"report_schema": "8.0"', serialized)


    def test_public_package_exports_and_version(self):
        """Verify forensix package exports all V8.1 symbols and maintains 8.0.0 version."""
        import forensix

        self.assertEqual(forensix.__version__, "8.0.0")

        v81_symbols = [
            "CUSTODY_LIMITATIONS_DISCLAIMER",
            "GENESIS_PREV_HASH",
            "CustodyActionType",
            "CustodyActor",
            "CustodyEvent",
            "TimestampSource",
            "compute_canonical_event_json",
            "compute_canonical_event_payload",
            "compute_event_record_hash",
            "generate_custody_event_id",
            "is_valid_custody_event_id",
            "MANIFEST_SCHEMA_VERSION",
            "HashAlgorithm",
            "ManifestArtifactType",
            "ManifestEntry",
            "ManifestRecord",
            "ManifestVerificationStatus",
            "generate_manifest_id",
            "is_valid_manifest_id",
            "validate_relative_entry_path",
            "ADVANCED_REPORT_SCHEMA_VERSION",
            "DEFAULT_ANALYTICAL_DISCLAIMER",
            "AdvancedReport",
            "AnalyticalLimitations",
            "CustodySummary",
            "EvidenceInventoryItem",
            "FindingsSummary",
            "generate_advanced_report_id",
            "is_valid_advanced_report_id",
        ]
        for sym in v81_symbols:
            self.assertTrue(
                hasattr(forensix, sym),
                f"V8.1 symbol '{sym}' missing from top-level forensix namespace",
            )
            self.assertIn(sym, forensix.__all__)


if __name__ == "__main__":
    unittest.main()
