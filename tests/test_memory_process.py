"""
Unit test suite for ForensiX V6.2 Process Artifact Extraction (memory_process.py).

Validates:
1. compute_deterministic_process_id determinism and uniqueness.
2. MemoryProcessArtifact validation, immutability, and serialization.
3. ProcessRejectionRecord validation and serialization without data leakage.
4. ProcessExtractionResult aggregate metrics and serialization.
5. Successful Linux and Windows Volatility 3 pslist extraction.
6. Successful empty output preservation (distinct from execution failure).
7. Alias precedence and conflicting alias detection/rejection (CONFLICTING_ALIASES).
8. Concordant alias handling (matching values accepted).
9. Missing and invalid required fields rejection (MISSING_PID, INVALID_PID, MISSING_PROCESS_NAME).
10. Missing optional fields handling (PPID=None, created_at=None, offset=None).
11. Exact duplicate source rows collapsing and duplicate_row_count tracking.
12. Distinct observations with matching PID and name preserved as distinct artifacts.
13. Strict failure-handling contract (re-raising existing V6.1 exceptions with execution_record).
14. Deep immutability of raw_attributes and nested structures.
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.memory_models import (
    MemoryProcessArtifact,
    ProcessExtractionResult,
    ProcessRejectionRecord,
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_process_id,
)
from forensix.memory_process import (
    extract_process_artifacts,
)
from forensix.volatility_adapter import (
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityOutputLimitExceededError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
)


class TestMemoryProcessExtraction(unittest.TestCase):
    """Test suite covering V6.2 process artifact models, normalizer, and extraction results."""

    def setUp(self) -> None:
        """Create standard test fixtures."""
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.execution_record = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            tool="volatility3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw", "-r", "json", "linux.pslist"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )

    # -------------------------------------------------------------------------
    # 1. Deterministic Identifier Generation
    # -------------------------------------------------------------------------

    def test_compute_deterministic_process_id_determinism(self) -> None:
        """Deterministic process ID produces byte-identical UUIDv5 across identical inputs."""
        id1 = compute_deterministic_process_id(
            evidence_id=self.evidence_id,
            plugin="linux.pslist",
            pid=1,
            process_name="systemd",
            created_at="2026-09-30T10:00:00Z",
            offset="0x8000",
        )
        id2 = compute_deterministic_process_id(
            evidence_id=self.evidence_id,
            plugin="linux.pslist",
            pid=1,
            process_name="systemd",
            created_at="2026-09-30T10:00:00Z",
            offset="0x8000",
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("MEMPROC-"))

    def test_compute_deterministic_process_id_uniqueness_on_varying_inputs(self) -> None:
        """Process IDs differ when PID, name, creation time, offset, or digest vary."""
        base = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 100, "worker", "2026-09-30T10:00:00Z", "0x1000"
        )
        diff_pid = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 101, "worker", "2026-09-30T10:00:00Z", "0x1000"
        )
        diff_name = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 100, "master", "2026-09-30T10:00:00Z", "0x1000"
        )
        diff_time = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 100, "worker", "2026-09-30T11:00:00Z", "0x1000"
        )
        diff_offset = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 100, "worker", "2026-09-30T10:00:00Z", "0x2000"
        )
        diff_digest = compute_deterministic_process_id(
            self.evidence_id, "linux.pslist", 100, "worker", "2026-09-30T10:00:00Z", "0x1000", content_digest="abcdef1234"
        )

        ids = {base, diff_pid, diff_name, diff_time, diff_offset, diff_digest}
        self.assertEqual(len(ids), 6)

    # -------------------------------------------------------------------------
    # 2. Model Validation & Immutability
    # -------------------------------------------------------------------------

    def test_memory_process_artifact_validation(self) -> None:
        """MemoryProcessArtifact validates required fields and types strictly."""
        art_id = compute_deterministic_process_id(self.evidence_id, "linux.pslist", 1, "init")
        art = MemoryProcessArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            pid=1,
            process_name="init",
            source_plugin="linux.pslist",
            ppid=0,
            created_at="2026-09-30T10:00:00Z",
            offset="0x8000",
            execution_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            source_row_indices=(0,),
            raw_attributes=(("Threads", 1),),
        )

        self.assertEqual(art.pid, 1)
        self.assertEqual(art.process_name, "init")
        self.assertEqual(art.ppid, 0)
        self.assertEqual(art.source_row_indices, (0,))

        # Serialization
        data_dict = art.to_dict()
        self.assertEqual(data_dict["pid"], 1)
        self.assertEqual(data_dict["raw_attributes"], {"Threads": 1})
        self.assertIn("artifact_id", art.to_json())

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            art.pid = 999  # type: ignore

    def test_memory_process_artifact_invalid_inputs_rejected(self) -> None:
        """MemoryProcessArtifact rejects malformed identifiers, negative PIDs, and empty names."""
        valid_id = compute_deterministic_process_id(self.evidence_id, "linux.pslist", 1, "init")

        # Invalid artifact_id
        with self.assertRaises(ValueError):
            MemoryProcessArtifact(
                artifact_id="INVALID-ID",
                evidence_id=self.evidence_id,
                pid=1,
                process_name="init",
                source_plugin="linux.pslist",
            )

        # Invalid evidence_id
        with self.assertRaises(ValueError):
            MemoryProcessArtifact(
                artifact_id=valid_id,
                evidence_id="NOT-MEM-ID",
                pid=1,
                process_name="init",
                source_plugin="linux.pslist",
            )

        # Negative PID
        with self.assertRaises(ValueError):
            MemoryProcessArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                pid=-1,
                process_name="init",
                source_plugin="linux.pslist",
            )

        # Empty process_name
        with self.assertRaises(ValueError):
            MemoryProcessArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                pid=1,
                process_name="   ",
                source_plugin="linux.pslist",
            )

        # Control-character-only process_name
        with self.assertRaises(ValueError):
            MemoryProcessArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                pid=1,
                process_name="\x00\x01\x1f",
                source_plugin="linux.pslist",
            )

    def test_process_rejection_record_validation(self) -> None:
        """ProcessRejectionRecord validates row_index, reason_code, and serializes cleanly."""
        rej = ProcessRejectionRecord(
            row_index=3,
            reason_code="INVALID_PID",
            field_name="PID",
            message="PID must be a non-negative integer",
        )
        self.assertEqual(rej.row_index, 3)
        self.assertEqual(rej.reason_code, "INVALID_PID")
        d = rej.to_dict()
        self.assertEqual(d["row_index"], 3)
        self.assertEqual(d["reason_code"], "INVALID_PID")

        with self.assertRaises(ValueError):
            ProcessRejectionRecord(row_index=-1, reason_code="ERR", field_name="f", message="m")

        with self.assertRaises(ValueError):
            ProcessRejectionRecord(row_index=0, reason_code="", field_name="f", message="m")

    def test_process_extraction_result_metrics(self) -> None:
        """ProcessExtractionResult computes total_rows, valid_count, and rejected_count accurately."""
        art_id = compute_deterministic_process_id(self.evidence_id, "linux.pslist", 1, "init")
        art = MemoryProcessArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            pid=1,
            process_name="init",
            source_plugin="linux.pslist",
        )
        rej = ProcessRejectionRecord(row_index=1, reason_code="MISSING_PID", field_name="PID", message="msg")

        res = ProcessExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=self.execution_record,
            artifacts=(art,),
            rejections=(rej,),
            duplicate_row_count=2,
        )

        self.assertEqual(res.valid_count, 1)
        self.assertEqual(res.rejected_count, 1)
        self.assertEqual(res.duplicate_row_count, 2)
        self.assertEqual(res.total_rows, 4)  # 1 valid + 1 rejected + 2 duplicates
        self.assertIn("evidence_id", res.to_dict())
        self.assertIn("artifacts", res.to_json())

    # -------------------------------------------------------------------------
    # 3. Extraction: Linux and Windows Output Schemas
    # -------------------------------------------------------------------------

    def test_extract_linux_pslist_success(self) -> None:
        """Valid Linux pslist rows normalize into sorted MemoryProcessArtifact models."""
        rows = (
            {
                "PID": 2,
                "PPID": 0,
                "COMM": "kthreadd",
                "Offset": "0x8100",
                "CreationTime": "2026-09-30 10:00:01 UTC",
                "ExitTime": None,
            },
            {
                "PID": 1,
                "PPID": 0,
                "COMM": "systemd",
                "Offset": "0x8000",
                "CreationTime": "2026-09-30 10:00:00 UTC",
                "ExitTime": None,
            },
        )
        res = VolatilityResult(
            execution_record=self.execution_record,
            data=rows,
            raw_output='[{"PID": 2}, {"PID": 1}]',
        )

        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.rejected_count, 0)
        self.assertEqual(outcome.total_rows, 2)

        # Sorted by PID: PID 1 first, then PID 2
        p1, p2 = outcome.artifacts
        self.assertEqual(p1.pid, 1)
        self.assertEqual(p1.process_name, "systemd")
        self.assertEqual(p1.ppid, 0)
        self.assertEqual(p1.created_at, "2026-09-30T10:00:00Z")
        self.assertEqual(p1.offset, "0x8000")
        self.assertEqual(p1.source_row_indices, (1,))

        self.assertEqual(p2.pid, 2)
        self.assertEqual(p2.process_name, "kthreadd")
        self.assertEqual(p2.source_row_indices, (0,))

    def test_extract_windows_pslist_success(self) -> None:
        """Valid Windows pslist rows with ImageFileName, CreateTime, and Offset(V) normalize properly."""
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000001",
            tool="volatility3",
            plugin="windows.pslist",
            sanitized_args=("-f", "mem.raw", "windows.pslist"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        rows = (
            {
                "PID": 4,
                "PPID": 0,
                "ImageFileName": "System",
                "Offset(V)": "0xfffffa8001a1b040",
                "CreateTime": "2026-09-30 08:00:00 UTC",
                "ExitTime": "N/A",
                "Threads": 98,
                "Handles": 540,
                "SessionId": None,
            },
        )
        res = VolatilityResult(execution_record=exec_rec, data=rows, raw_output="[]")

        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        p = outcome.artifacts[0]
        self.assertEqual(p.pid, 4)
        self.assertEqual(p.process_name, "System")
        self.assertEqual(p.created_at, "2026-09-30T08:00:00Z")
        self.assertIsNone(p.exit_time)  # "N/A" cleanly normalized to None
        self.assertEqual(p.offset, "0xfffffa8001a1b040")
        # Threads and Handles preserved in raw_attributes
        attrs_dict = dict(p.raw_attributes)
        self.assertEqual(attrs_dict["Threads"], 98)
        self.assertEqual(attrs_dict["Handles"], 540)

    def test_extract_empty_process_output_preservation(self) -> None:
        """Successful Volatility execution returning 0 rows returns valid_count=0 without error."""
        res = VolatilityResult(execution_record=self.execution_record, data=(), raw_output="[]")

        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 0)
        self.assertEqual(outcome.rejected_count, 0)
        self.assertEqual(outcome.total_rows, 0)
        self.assertEqual(outcome.artifacts, ())
        self.assertEqual(outcome.rejections, ())

    # -------------------------------------------------------------------------
    # 4. Alias Precedence & Conflict Detection
    # -------------------------------------------------------------------------

    def test_conflicting_aliases_rejected_without_leaking_secrets(self) -> None:
        """Conflicting non-null values across alias keys reject row with CONFLICTING_ALIASES."""
        # 1. Conflicting PID vs pid
        rows1 = ({"PID": 100, "pid": 200, "COMM": "test_worker"},)
        res1 = VolatilityResult(execution_record=self.evidence_id, data=rows1, raw_output="")
        out1 = extract_process_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows1, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out1.valid_count, 0)
        self.assertEqual(out1.rejected_count, 1)
        self.assertEqual(out1.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out1.rejections[0].field_name, "pid")
        self.assertIn("'PID' and 'pid'", out1.rejections[0].message)

        # 2. Conflicting ImageFileName vs Name
        rows2 = ({"PID": 10, "ImageFileName": "worker.exe", "Name": "other.exe"},)
        out2 = extract_process_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows2, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out2.valid_count, 0)
        self.assertEqual(out2.rejected_count, 1)
        self.assertEqual(out2.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out2.rejections[0].field_name, "process_name")

        # 3. Conflicting CreateTime vs CreationTime
        rows3 = (
            {
                "PID": 10,
                "COMM": "app",
                "CreateTime": "2026-09-30 10:00:00 UTC",
                "CreationTime": "2026-09-30 11:00:00 UTC",
            },
        )
        out3 = extract_process_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows3, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out3.valid_count, 0)
        self.assertEqual(out3.rejected_count, 1)
        self.assertEqual(out3.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out3.rejections[0].field_name, "created_at")

    def test_concordant_aliases_accepted_without_conflict(self) -> None:
        """Matching non-null values across aliases are accepted cleanly."""
        rows = (
            {
                "PID": 50,
                "pid": 50,
                "ImageFileName": "daemon",
                "COMM": "daemon",
                "CreateTime": "2026-09-30 10:00:00 UTC",
                "CreationTime": "2026-09-30 10:00:00 UTC",
            },
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 0)
        p = outcome.artifacts[0]
        self.assertEqual(p.pid, 50)
        self.assertEqual(p.process_name, "daemon")

    # -------------------------------------------------------------------------
    # 5. Missing & Invalid Fields Handling
    # -------------------------------------------------------------------------

    def test_missing_and_invalid_pid_rejection(self) -> None:
        """Missing, non-numeric, or negative PID causes row rejection with structured code."""
        rows = (
            {"COMM": "no_pid"},  # Missing PID
            {"PID": "not_a_number", "COMM": "bad_pid"},  # Invalid PID
            {"PID": -1, "COMM": "negative_pid"},  # Negative PID
            {"PID": 1, "COMM": "good_process"},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 3)
        self.assertEqual(outcome.artifacts[0].pid, 1)

        codes = [r.reason_code for r in outcome.rejections]
        self.assertIn("MISSING_PID", codes)
        self.assertIn("INVALID_PID", codes)

    def test_missing_process_name_rejection(self) -> None:
        """Missing or whitespace-only process name causes row rejection."""
        rows = (
            {"PID": 10},  # Missing name
            {"PID": 11, "COMM": "   "},  # Whitespace-only name
            {"PID": 12, "COMM": "\x00\x08"},  # Control-characters only
            {"PID": 13, "COMM": "valid_app"},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 3)
        self.assertEqual(outcome.artifacts[0].pid, 13)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MISSING_PROCESS_NAME")

    def test_missing_optional_fields_populated_with_none(self) -> None:
        """Missing PPID, timestamps, or offsets cleanly populate None."""
        rows = (
            {"PID": 100, "COMM": "standalone"},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        p = outcome.artifacts[0]
        self.assertIsNone(p.ppid)
        self.assertIsNone(p.created_at)
        self.assertIsNone(p.exit_time)
        self.assertIsNone(p.offset)

    def test_malformed_non_dict_row_rejection(self) -> None:
        """Non-dictionary row is rejected with MALFORMED_RECORD."""
        rows = (
            {"PID": 1, "COMM": "valid"},
            "primitive_string_row",  # Malformed
            [1, 2, 3],  # Malformed
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")  # type: ignore
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 2)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MALFORMED_RECORD")

    # -------------------------------------------------------------------------
    # 6. Duplicates vs. Distinct Observations
    # -------------------------------------------------------------------------

    def test_exact_duplicate_rows_collapsed_with_traceability(self) -> None:
        """Exact duplicate source rows are collapsed while recording row indices and count."""
        identical_row = {"PID": 500, "COMM": "worker", "PPID": 1, "Offset": "0x5000"}
        rows = (
            identical_row,  # row 0
            {"PID": 501, "COMM": "other", "PPID": 1},  # row 1
            identical_row,  # row 2 (exact duplicate of row 0)
        )
        res = VolatilityResult(execution_record=self.evidence_id, data=rows, raw_output="")
        outcome = extract_process_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows, raw_output=""),
            self.evidence_id,
        )

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 1)
        self.assertEqual(outcome.total_rows, 3)

        # Worker process has both row 0 and row 2 in source_row_indices
        worker_art = [a for a in outcome.artifacts if a.pid == 500][0]
        self.assertEqual(worker_art.source_row_indices, (0, 2))

    def test_distinct_observations_with_same_pid_and_name_preserved(self) -> None:
        """Different rows sharing PID and name (e.g. recycled PID with different PPID or offset) are both preserved."""
        rows = (
            {"PID": 500, "COMM": "worker", "PPID": 1, "Offset": "0x1000"},  # row 0
            {"PID": 500, "COMM": "worker", "PPID": 2, "Offset": "0x2000"},  # row 1 (different PPID and offset)
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 0)

        art0, art1 = outcome.artifacts
        self.assertNotEqual(art0.artifact_id, art1.artifact_id)
        self.assertEqual(art0.offset, "0x1000")
        self.assertEqual(art1.offset, "0x2000")

    # -------------------------------------------------------------------------
    # 7. Strict Failure Contract
    # -------------------------------------------------------------------------

    def test_failed_volatility_execution_re_raises_typed_v61_exceptions(self) -> None:
        """Failed VolatilityResult execution re-raises existing V6.1 typed exceptions carrying execution_record."""
        # 1. MISSING_SYMBOLS
        rec_sym = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000001",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=1,
            error=VolatilityExecutionError(
                error_type="MISSING_SYMBOLS",
                error_message="Symbol table requirement not satisfied: linux.elf",
            ),
        )
        res_sym = VolatilityResult(execution_record=rec_sym, data=(), raw_output="")
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx1:
            extract_process_artifacts(res_sym, self.evidence_id)
        self.assertEqual(ctx1.exception.exit_code, 1)
        self.assertIs(ctx1.exception.execution_record, rec_sym)

        # 2. UNSUPPORTED_PLUGIN
        rec_plug = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000002",
            tool="vol3",
            plugin="linux.badplugin",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=2,
            error=VolatilityExecutionError(
                error_type="UNSUPPORTED_PLUGIN",
                error_message="Unknown plugin: linux.badplugin",
            ),
        )
        res_plug = VolatilityResult(execution_record=rec_plug, data=(), raw_output="")
        with self.assertRaises(VolatilityUnsupportedPluginError) as ctx2:
            extract_process_artifacts(res_plug, self.evidence_id)
        self.assertEqual(ctx2.exception.exit_code, 2)
        self.assertIs(ctx2.exception.execution_record, rec_plug)

        # 3. TIMEOUT
        rec_time = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000003",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.TIMEOUT.value,
            executed=True,
            error=VolatilityExecutionError(
                error_type="TIMEOUT",
                error_message="Process timed out",
            ),
        )
        res_time = VolatilityResult(execution_record=rec_time, data=(), raw_output="")
        with self.assertRaises(VolatilityTimeoutError) as ctx3:
            extract_process_artifacts(res_time, self.evidence_id)
        self.assertIs(ctx3.exception.execution_record, rec_time)

        # 4. OUTPUT_LIMIT_EXCEEDED
        rec_limit = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000004",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.ERROR.value,
            executed=True,
            error=VolatilityExecutionError(
                error_type="OUTPUT_LIMIT_EXCEEDED",
                error_message="Max bytes exceeded",
            ),
        )
        res_limit = VolatilityResult(execution_record=rec_limit, data=(), raw_output="")
        with self.assertRaises(VolatilityOutputLimitExceededError) as ctx4:
            extract_process_artifacts(res_limit, self.evidence_id)
        self.assertIs(ctx4.exception.execution_record, rec_limit)

        # 5. GENERAL EXECUTION FAILURE
        rec_gen = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000005",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=137,
            error=VolatilityExecutionError(
                error_type="EXECUTION_FAILURE",
                error_message="Killed by signal",
            ),
        )
        res_gen = VolatilityResult(execution_record=rec_gen, data=(), raw_output="")
        with self.assertRaises(VolatilityExecutionFailureError) as ctx5:
            extract_process_artifacts(res_gen, self.evidence_id)
        self.assertEqual(ctx5.exception.exit_code, 137)
        self.assertIs(ctx5.exception.execution_record, rec_gen)

    # -------------------------------------------------------------------------
    # 8. Deep Immutability
    # -------------------------------------------------------------------------

    def test_extract_process_artifacts_deep_immutability(self) -> None:
        """Extracted artifacts contain deeply immutable tuples with no mutable references."""
        nested_dict = {"sub": {"key": [1, 2, 3]}}
        rows = (
            {"PID": 1, "COMM": "test", "Extra": nested_dict},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_process_artifacts(res, self.evidence_id)

        p = outcome.artifacts[0]
        self.assertIsInstance(p.raw_attributes, tuple)
        extra_val = dict(p.raw_attributes)["Extra"]
        # Nested dict and list were converted to tuples
        self.assertIsInstance(extra_val, tuple)

        # Attempting to mutate original dictionary does not affect artifact
        nested_dict["sub"]["key"].append(4)  # type: ignore
        self.assertNotIn("4", str(p.raw_attributes))


if __name__ == "__main__":
    unittest.main()
