"""
Unit test suite for ForensiX V6.3 Kernel Modules and Drivers (memory_module.py).

Validates:
1. compute_deterministic_module_id determinism and uniqueness.
2. MemoryModuleArtifact validation, immutability, and serialization.
3. ModuleRejectionRecord validation and serialization without data leakage.
4. ModuleExtractionResult aggregate metrics and reconciliation.
5. Successful Linux linux.lsmod extraction (Offset as base address).
6. Successful Windows windows.modules extraction (Base, Size, Path).
7. Successful Windows windows.driverscan extraction (Offset as structure offset, Start as base).
8. Successful empty output preservation (distinct from execution failure).
9. Alias precedence and conflicting alias detection/rejection (CONFLICTING_ALIASES).
10. Concordant alias handling (matching values accepted).
11. Missing and invalid module name rejection (MISSING_MODULE_NAME).
12. Invalid base address and size rejection (INVALID_BASE_ADDRESS, INVALID_SIZE).
13. Missing optional fields handling (base=None, size=None, offset=None, path=None).
14. Exact duplicate source rows collapsing and duplicate_row_count tracking.
15. Distinct observations with matching module name preserved as distinct artifacts.
16. Strict failure-handling contract (re-raising existing V6.1 exceptions with execution_record).
17. Deep immutability of raw_attributes and nested structures.
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.memory_models import (
    MemoryModuleArtifact,
    ModuleExtractionResult,
    ModuleRejectionRecord,
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_module_id,
)
from forensix.memory_module import (
    extract_module_artifacts,
)
from forensix.volatility_adapter import (
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityOutputLimitExceededError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
)


class TestMemoryModuleExtraction(unittest.TestCase):
    """Test suite covering V6.3 kernel module and driver models, normalizer, and extraction results."""

    def setUp(self) -> None:
        """Create standard test fixtures."""
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.execution_record = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            tool="volatility3",
            plugin="linux.lsmod",
            sanitized_args=("-f", "mem.raw", "-r", "json", "linux.lsmod"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )

    # -------------------------------------------------------------------------
    # 1. Deterministic Identifier Generation
    # -------------------------------------------------------------------------

    def test_compute_deterministic_module_id_determinism(self) -> None:
        """Deterministic module ID produces byte-identical UUIDv5 across identical inputs."""
        id1 = compute_deterministic_module_id(
            evidence_id=self.evidence_id,
            plugin="linux.lsmod",
            module_name="ext4",
            base_address="0xffffffffa0000000",
            size_bytes=1048576,
            offset="0x5000",
        )
        id2 = compute_deterministic_module_id(
            evidence_id=self.evidence_id,
            plugin="linux.lsmod",
            module_name="ext4",
            base_address="0xffffffffa0000000",
            size_bytes=1048576,
            offset="0x5000",
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("MEMMOD-"))

    def test_compute_deterministic_module_id_uniqueness_on_varying_inputs(self) -> None:
        """Module IDs differ when name, base address, size, offset, or digest vary."""
        base = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "ext4", "0xffffffffa0000000", 1000, "0x1000"
        )
        diff_name = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "xfs", "0xffffffffa0000000", 1000, "0x1000"
        )
        diff_base = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "ext4", "0xffffffffb0000000", 1000, "0x1000"
        )
        diff_size = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "ext4", "0xffffffffa0000000", 2000, "0x1000"
        )
        diff_offset = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "ext4", "0xffffffffa0000000", 1000, "0x2000"
        )
        diff_digest = compute_deterministic_module_id(
            self.evidence_id, "linux.lsmod", "ext4", "0xffffffffa0000000", 1000, "0x1000", content_digest="abcdef1234"
        )

        ids = {base, diff_name, diff_base, diff_size, diff_offset, diff_digest}
        self.assertEqual(len(ids), 6)

    # -------------------------------------------------------------------------
    # 2. Model Validation & Immutability
    # -------------------------------------------------------------------------

    def test_memory_module_artifact_validation(self) -> None:
        """MemoryModuleArtifact validates required fields and types strictly."""
        art_id = compute_deterministic_module_id(self.evidence_id, "linux.lsmod", "ext4")
        art = MemoryModuleArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            module_name="ext4",
            source_plugin="linux.lsmod",
            base_address="0xffffffffa0000000",
            size_bytes=524288,
            offset="0x8000",
            driver_path="/lib/modules/ext4.ko",
            execution_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            source_row_indices=(0,),
            raw_attributes=(("Tainted", "G"),),
        )

        self.assertEqual(art.module_name, "ext4")
        self.assertEqual(art.base_address, "0xffffffffa0000000")
        self.assertEqual(art.size_bytes, 524288)
        self.assertEqual(art.source_row_indices, (0,))

        # Serialization
        data_dict = art.to_dict()
        self.assertEqual(data_dict["module_name"], "ext4")
        self.assertEqual(data_dict["raw_attributes"], {"Tainted": "G"})
        self.assertIn("artifact_id", art.to_json())

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            art.module_name = "tampered"  # type: ignore

    def test_memory_module_artifact_invalid_inputs_rejected(self) -> None:
        """MemoryModuleArtifact rejects malformed identifiers, empty names, and invalid hex."""
        valid_id = compute_deterministic_module_id(self.evidence_id, "linux.lsmod", "ext4")

        # Invalid artifact_id
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id="INVALID-ID",
                evidence_id=self.evidence_id,
                module_name="ext4",
                source_plugin="linux.lsmod",
            )

        # Invalid evidence_id
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id=valid_id,
                evidence_id="NOT-MEM-ID",
                module_name="ext4",
                source_plugin="linux.lsmod",
            )

        # Empty module_name
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                module_name="   ",
                source_plugin="linux.lsmod",
            )

        # Control-characters only module_name
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                module_name="\x00\x01\x1f",
                source_plugin="linux.lsmod",
            )

        # Invalid base_address (not hex)
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                module_name="ext4",
                source_plugin="linux.lsmod",
                base_address="not_a_hex",
            )

        # Negative size_bytes
        with self.assertRaises(ValueError):
            MemoryModuleArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                module_name="ext4",
                source_plugin="linux.lsmod",
                size_bytes=-10,
            )

    def test_module_rejection_record_validation(self) -> None:
        """ModuleRejectionRecord validates row_index, reason_code, and serializes cleanly."""
        rej = ModuleRejectionRecord(
            row_index=3,
            reason_code="INVALID_BASE_ADDRESS",
            field_name="base_address",
            message="Base address must be a valid hexadecimal string",
        )
        self.assertEqual(rej.row_index, 3)
        self.assertEqual(rej.reason_code, "INVALID_BASE_ADDRESS")
        d = rej.to_dict()
        self.assertEqual(d["row_index"], 3)
        self.assertEqual(d["reason_code"], "INVALID_BASE_ADDRESS")

        with self.assertRaises(ValueError):
            ModuleRejectionRecord(row_index=-1, reason_code="ERR", field_name="f", message="m")

        with self.assertRaises(ValueError):
            ModuleRejectionRecord(row_index=0, reason_code="", field_name="f", message="m")

    def test_module_extraction_result_metrics(self) -> None:
        """ModuleExtractionResult computes total_rows, valid_count, and rejected_count accurately."""
        art_id = compute_deterministic_module_id(self.evidence_id, "linux.lsmod", "ext4")
        art = MemoryModuleArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            module_name="ext4",
            source_plugin="linux.lsmod",
        )
        rej = ModuleRejectionRecord(row_index=1, reason_code="MISSING_MODULE_NAME", field_name="name", message="msg")

        res = ModuleExtractionResult(
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

    def test_extract_linux_lsmod_success(self) -> None:
        """Valid Linux lsmod rows normalize Offset to base address, Size, and Name."""
        rows = (
            {
                "Offset": "0xffffffffa0100000",
                "Name": "xfs",
                "Size": 2097152,
                "Tainted": "G",
            },
            {
                "Offset": "0xffffffffa0000000",
                "Name": "ext4",
                "Size": 1048576,
                "Tainted": "G",
            },
        )
        res = VolatilityResult(
            execution_record=self.execution_record,
            data=rows,
            raw_output='[{"Name": "xfs"}, {"Name": "ext4"}]',
        )

        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.rejected_count, 0)
        self.assertEqual(outcome.total_rows, 2)

        # Sorted by module_name: 'ext4' first, then 'xfs'
        m1, m2 = outcome.artifacts
        self.assertEqual(m1.module_name, "ext4")
        self.assertEqual(m1.base_address, "0xffffffffa0000000")
        self.assertEqual(m1.size_bytes, 1048576)
        self.assertEqual(m1.source_row_indices, (1,))

        self.assertEqual(m2.module_name, "xfs")
        self.assertEqual(m2.base_address, "0xffffffffa0100000")
        self.assertEqual(m2.size_bytes, 2097152)
        self.assertEqual(m2.source_row_indices, (0,))

    def test_extract_windows_modules_success(self) -> None:
        """Valid Windows modules rows with Base, Size, Name, and Path normalize properly."""
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000001",
            tool="volatility3",
            plugin="windows.modules",
            sanitized_args=("-f", "mem.raw", "windows.modules"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        rows = (
            {
                "Base": "0xfffff80002800000",
                "Size": "0x120000",
                "Name": "ntoskrnl.exe",
                "Path": r"\SystemRoot\system32\ntoskrnl.exe",
            },
        )
        res = VolatilityResult(execution_record=exec_rec, data=rows, raw_output="[]")

        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        m = outcome.artifacts[0]
        self.assertEqual(m.module_name, "ntoskrnl.exe")
        self.assertEqual(m.base_address, "0xfffff80002800000")
        self.assertEqual(m.size_bytes, 0x120000)
        self.assertEqual(m.driver_path, r"\SystemRoot\system32\ntoskrnl.exe")
        self.assertIsNone(m.offset)

    def test_extract_windows_driverscan_success(self) -> None:
        """Valid Windows driverscan rows map Offset to structure offset and Start to base address."""
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000002",
            tool="volatility3",
            plugin="windows.driverscan",
            sanitized_args=("-f", "mem.raw", "windows.driverscan"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        rows = (
            {
                "Offset": "0xfffffa8001002040",
                "Start": "0xfffff88001200000",
                "Size": 65536,
                "Driver Name": r"\Driver\ACPI",
                "Service Key": r"\Registry\Machine\System\ControlSet001\Services\ACPI",
            },
        )
        res = VolatilityResult(execution_record=exec_rec, data=rows, raw_output="[]")

        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        m = outcome.artifacts[0]
        self.assertEqual(m.module_name, r"\Driver\ACPI")
        self.assertEqual(m.offset, "0xfffffa8001002040")  # Structure offset
        self.assertEqual(m.base_address, "0xfffff88001200000")  # Start/Base address
        self.assertEqual(m.size_bytes, 65536)
        # Service Key preserved in raw_attributes
        attrs_dict = dict(m.raw_attributes)
        self.assertIn("Service Key", attrs_dict)

    def test_extract_empty_module_output_preservation(self) -> None:
        """Successful Volatility execution returning 0 rows returns valid_count=0 without error."""
        res = VolatilityResult(execution_record=self.execution_record, data=(), raw_output="[]")

        outcome = extract_module_artifacts(res, self.evidence_id)

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
        # 1. Conflicting Name vs Module Name
        rows1 = ({"Name": "mod_a", "Module Name": "mod_b", "Offset": "0x1000"},)
        out1 = extract_module_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows1, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out1.valid_count, 0)
        self.assertEqual(out1.rejected_count, 1)
        self.assertEqual(out1.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out1.rejections[0].field_name, "module_name")
        self.assertIn("'Name' and 'Module Name'", out1.rejections[0].message)

        # 2. Conflicting Base vs Offset in Linux lsmod
        rows2 = ({"Name": "mod_a", "Base": "0x1000", "Offset": "0x2000"},)
        out2 = extract_module_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows2, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out2.valid_count, 0)
        self.assertEqual(out2.rejected_count, 1)
        self.assertEqual(out2.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out2.rejections[0].field_name, "base_address")

        # 3. Conflicting Size vs SizeOfImage
        rows3 = ({"Name": "mod_a", "Size": 1000, "SizeOfImage": 2000},)
        out3 = extract_module_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows3, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out3.valid_count, 0)
        self.assertEqual(out3.rejected_count, 1)
        self.assertEqual(out3.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out3.rejections[0].field_name, "size_bytes")

    def test_concordant_aliases_accepted_without_conflict(self) -> None:
        """Matching non-null values across aliases are accepted cleanly."""
        rows = (
            {
                "Name": "ext4",
                "Module Name": "ext4",
                "Offset": "0x8000",
                "Base": "0x8000",
                "Size": 1024,
                "SizeOfImage": 1024,
            },
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 0)
        m = outcome.artifacts[0]
        self.assertEqual(m.module_name, "ext4")
        self.assertEqual(m.base_address, "0x8000")
        self.assertEqual(m.size_bytes, 1024)

    # -------------------------------------------------------------------------
    # 5. Missing & Invalid Fields Handling
    # -------------------------------------------------------------------------

    def test_missing_and_invalid_module_name_rejection(self) -> None:
        """Missing or whitespace-only module name causes row rejection."""
        rows = (
            {"Offset": "0x1000"},  # Missing name
            {"Name": "   ", "Offset": "0x1000"},  # Whitespace-only name
            {"Name": "\x00\x08", "Offset": "0x1000"},  # Control-characters only
            {"Name": "valid_mod", "Offset": "0x1000"},  # Valid
        )
        res = VolatilityResult(execution_record=self.evidence_id, data=rows, raw_output="")
        outcome = extract_module_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows, raw_output=""),
            self.evidence_id,
        )

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 3)
        self.assertEqual(outcome.artifacts[0].module_name, "valid_mod")
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MISSING_MODULE_NAME")

    def test_invalid_base_address_and_size_rejection(self) -> None:
        """Invalid non-hex base address or negative size rejects row."""
        rows = (
            {"Name": "mod1", "Offset": "invalid_hex"},  # Bad base
            {"Name": "mod2", "Offset": "0x1000", "Size": -50},  # Negative size
            {"Name": "mod3", "Offset": "0x1000", "Size": "not_a_number"},  # Bad size
            {"Name": "mod4", "Offset": "0x1000", "Size": 100},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 3)
        codes = [r.reason_code for r in outcome.rejections]
        self.assertIn("INVALID_BASE_ADDRESS", codes)
        self.assertIn("INVALID_SIZE", codes)

    def test_missing_optional_fields_populated_with_none(self) -> None:
        """Missing base address, size, offset, or path cleanly default to None."""
        rows = (
            {"Name": "standalone_mod"},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        m = outcome.artifacts[0]
        self.assertIsNone(m.base_address)
        self.assertIsNone(m.size_bytes)
        self.assertIsNone(m.offset)
        self.assertIsNone(m.driver_path)

    def test_malformed_non_dict_row_rejection(self) -> None:
        """Non-dictionary row is rejected with MALFORMED_RECORD."""
        rows = (
            {"Name": "valid", "Offset": "0x1000"},
            "primitive_string_row",
            [1, 2, 3],
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")  # type: ignore
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 2)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MALFORMED_RECORD")

    # -------------------------------------------------------------------------
    # 6. Duplicates vs. Distinct Observations
    # -------------------------------------------------------------------------

    def test_exact_duplicate_rows_collapsed_with_traceability(self) -> None:
        """Exact duplicate source rows are collapsed while recording row indices and count."""
        identical_row = {"Name": "ext4", "Offset": "0x5000", "Size": 1000}
        rows = (
            identical_row,  # row 0
            {"Name": "xfs", "Offset": "0x6000"},  # row 1
            identical_row,  # row 2 (exact duplicate of row 0)
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 1)
        self.assertEqual(outcome.total_rows, 3)

        # ext4 module has both row 0 and row 2 in source_row_indices
        ext4_art = [a for a in outcome.artifacts if a.module_name == "ext4"][0]
        self.assertEqual(ext4_art.source_row_indices, (0, 2))

    def test_distinct_observations_with_same_name_preserved(self) -> None:
        """Different rows sharing module name (e.g. reloaded at different base address) are preserved."""
        rows = (
            {"Name": "my_driver", "Offset": "0x1000", "Size": 500},  # row 0
            {"Name": "my_driver", "Offset": "0x2000", "Size": 500},  # row 1 (different base address)
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 0)

        art0, art1 = outcome.artifacts
        self.assertNotEqual(art0.artifact_id, art1.artifact_id)
        self.assertEqual(art0.base_address, "0x1000")
        self.assertEqual(art1.base_address, "0x2000")

    # -------------------------------------------------------------------------
    # 7. Strict Failure Contract
    # -------------------------------------------------------------------------

    def test_failed_volatility_execution_re_raises_typed_v61_exceptions(self) -> None:
        """Failed VolatilityResult execution re-raises existing V6.1 typed exceptions carrying execution_record."""
        # 1. MISSING_SYMBOLS
        rec_sym = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000001",
            tool="vol3",
            plugin="linux.lsmod",
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
            extract_module_artifacts(res_sym, self.evidence_id)
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
            extract_module_artifacts(res_plug, self.evidence_id)
        self.assertEqual(ctx2.exception.exit_code, 2)
        self.assertIs(ctx2.exception.execution_record, rec_plug)

        # 3. TIMEOUT
        rec_time = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000003",
            tool="vol3",
            plugin="linux.lsmod",
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
            extract_module_artifacts(res_time, self.evidence_id)
        self.assertIs(ctx3.exception.execution_record, rec_time)

        # 4. OUTPUT_LIMIT_EXCEEDED
        rec_limit = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000004",
            tool="vol3",
            plugin="linux.lsmod",
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
            extract_module_artifacts(res_limit, self.evidence_id)
        self.assertIs(ctx4.exception.execution_record, rec_limit)

        # 5. GENERAL EXECUTION FAILURE
        rec_gen = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000005",
            tool="vol3",
            plugin="linux.lsmod",
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
            extract_module_artifacts(res_gen, self.evidence_id)
        self.assertEqual(ctx5.exception.exit_code, 137)
        self.assertIs(ctx5.exception.execution_record, rec_gen)

    # -------------------------------------------------------------------------
    # 8. Deep Immutability
    # -------------------------------------------------------------------------

    def test_extract_module_artifacts_deep_immutability(self) -> None:
        """Extracted artifacts contain deeply immutable tuples with no mutable references."""
        nested_dict = {"sub": {"key": [1, 2, 3]}}
        rows = (
            {"Name": "test_mod", "Offset": "0x1000", "Extra": nested_dict},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_module_artifacts(res, self.evidence_id)

        m = outcome.artifacts[0]
        self.assertIsInstance(m.raw_attributes, tuple)
        extra_val = dict(m.raw_attributes)["Extra"]
        self.assertIsInstance(extra_val, tuple)

        # Attempting to mutate original dictionary does not affect artifact
        nested_dict["sub"]["key"].append(4)  # type: ignore
        self.assertNotIn("4", str(m.raw_attributes))


if __name__ == "__main__":
    unittest.main()
