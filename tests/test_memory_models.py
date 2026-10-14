"""
Unit test suite for ForensiX V6.1 Memory Evidence Models (memory_models.py).

Validates:
1. Deterministic UUIDv5 identity (RFC 4122 compliance, FORENSIX_V6_MEMORY_NAMESPACE).
2. Stability of identity inputs (path/time changes do not alter ID; content changes do).
3. MemoryEvidenceRecord strict validation, immutability, and frozen attributes.
4. MemoryEvidenceRecord dictionary and JSON serialization round-trips.
5. Chunked streaming hashing of synthetic evidence files without full RAM load.
6. Non-modification of original evidence during registration.
7. Reliable memory format detection (LiME, crash dump, ELF core, raw).
8. VolatilityExecutionRecord validation, immutability, and serialization round-trips.
9. VolatilityExecutionError structured error handling and details freezing.
10. Execution ID determinism and provenance separation (executed vs attempted).
"""

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from forensix.memory_models import (
    FORENSIX_V6_MEMORY_NAMESPACE,
    MEMORY_SCHEMA_VERSION,
    MemoryEvidenceRecord,
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_execution_id,
    compute_deterministic_memory_id,
    detect_memory_format,
    register_memory_evidence,
)


class TestMemoryModels(unittest.TestCase):
    """Test suite for ForensiX V6.1 Memory Evidence Models."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_size = 1048576  # 1 MB

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Deterministic UUIDv5 Identity
    # -------------------------------------------------------------------------

    def test_deterministic_uuidv5_identity_consistency(self):
        """Identical evidence facts produce byte-identical deterministic MEM-<UUIDv5> IDs."""
        id1 = compute_deterministic_memory_id(self.sample_sha256, self.sample_size, "lime")
        id2 = compute_deterministic_memory_id(self.sample_sha256, self.sample_size, "lime")
        self.assertEqual(id1, id2)

        # Validate format
        self.assertTrue(id1.startswith("MEM-"))
        suffix = id1[len("MEM-"):]
        parsed_uuid = uuid.UUID(suffix)
        self.assertEqual(parsed_uuid.version, 5)

    def test_identity_independent_of_volatile_inputs(self):
        """Evidence ID is strictly determined by content hash and size, not path or time."""
        file1 = self.temp_dir_path / "hostA_dump.raw"
        file2 = self.temp_dir_path / "hostB_renamed.raw"
        content = b"Synthetic RAM dump block 0123456789ABCDEF" * 1000
        file1.write_bytes(content)
        file2.write_bytes(content)

        rec1 = register_memory_evidence(file1)
        rec2 = register_memory_evidence(file2)

        # Different paths, but identical evidence contents
        self.assertNotEqual(rec1.file_path, rec2.file_path)
        self.assertEqual(rec1.sha256, rec2.sha256)
        self.assertEqual(rec1.size_bytes, rec2.size_bytes)
        # Therefore, deterministic IDs MUST be identical!
        self.assertEqual(rec1.evidence_id, rec2.evidence_id)

    def test_different_contents_produce_different_ids(self):
        """Different cryptographic hashes or sizes yield distinct deterministic IDs."""
        id1 = compute_deterministic_memory_id(self.sample_sha256, 100, "raw")
        id2 = compute_deterministic_memory_id(self.sample_sha256, 200, "raw")
        other_sha = "a" * 64
        id3 = compute_deterministic_memory_id(other_sha, 100, "raw")

        self.assertNotEqual(id1, id2)
        self.assertNotEqual(id1, id3)
        self.assertNotEqual(id2, id3)

    # -------------------------------------------------------------------------
    # 2. MemoryEvidenceRecord Validation & Immutability
    # -------------------------------------------------------------------------

    def test_record_immutability(self):
        """MemoryEvidenceRecord is frozen; attribute modification raises FrozenInstanceError."""
        rec = MemoryEvidenceRecord(
            evidence_id=compute_deterministic_memory_id(self.sample_sha256, self.sample_size),
            file_path=str(self.temp_dir_path / "dump.raw"),
            size_bytes=self.sample_size,
            sha256=self.sample_sha256,
        )

        with self.assertRaises(FrozenInstanceError):
            rec.size_bytes = 200  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            rec.sha256 = "invalid"  # type: ignore

    def test_record_validation_invalid_fields(self):
        """Strict validation enforces positive size, 64-char hex sha256, and valid UUID prefix."""
        valid_id = compute_deterministic_memory_id(self.sample_sha256, 10)
        valid_path = str(self.temp_dir_path / "dump.raw")

        # Invalid negative size
        with self.assertRaises(ValueError):
            MemoryEvidenceRecord(
                evidence_id=valid_id,
                file_path=valid_path,
                size_bytes=-1,
                sha256=self.sample_sha256,
            )

        # Invalid sha256 (not 64 characters)
        with self.assertRaises(ValueError):
            MemoryEvidenceRecord(
                evidence_id=valid_id,
                file_path=valid_path,
                size_bytes=10,
                sha256="tooshort",
            )

        # Invalid sha256 (non-hex characters)
        with self.assertRaises(ValueError):
            MemoryEvidenceRecord(
                evidence_id=valid_id,
                file_path=valid_path,
                size_bytes=10,
                sha256="z" * 64,
            )

        # Invalid evidence_id prefix
        with self.assertRaises(ValueError):
            MemoryEvidenceRecord(
                evidence_id="INVALID-1234",
                file_path=valid_path,
                size_bytes=10,
                sha256=self.sample_sha256,
            )

    # -------------------------------------------------------------------------
    # 3. Serialization Round Trips
    # -------------------------------------------------------------------------

    def test_serialization_round_trip(self):
        """to_dict / from_dict and to_json / from_json preserve complete fidelity."""
        rec = MemoryEvidenceRecord(
            evidence_id=compute_deterministic_memory_id(self.sample_sha256, self.sample_size, "lime"),
            file_path=str(self.temp_dir_path / "dump.lime"),
            size_bytes=self.sample_size,
            sha256=self.sample_sha256,
            format="lime",
            schema_version=MEMORY_SCHEMA_VERSION,
        )

        # Dict round-trip
        rec_dict = rec.to_dict()
        self.assertIsInstance(rec_dict, dict)
        self.assertEqual(rec_dict["evidence_id"], rec.evidence_id)
        self.assertEqual(rec_dict["format"], "lime")
        self.assertEqual(rec_dict["schema_version"], MEMORY_SCHEMA_VERSION)

        restored_from_dict = MemoryEvidenceRecord.from_dict(rec_dict)
        self.assertEqual(rec, restored_from_dict)

        # JSON round-trip
        json_str = rec.to_json(indent=2)
        self.assertIsInstance(json_str, str)
        restored_from_json = MemoryEvidenceRecord.from_json(json_str)
        self.assertEqual(rec, restored_from_json)

    # -------------------------------------------------------------------------
    # 4. Chunked Hashing of Synthetic File
    # -------------------------------------------------------------------------

    def test_chunked_hashing_synthetic_evidence(self):
        """Verify chunked streaming hashing on synthetic file without RAM overload."""
        evidence_file = self.temp_dir_path / "synthetic_memory.raw"
        # Create a 256 KB file with predictable repeating binary content
        chunk = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 1024  # 16 KB
        full_content = chunk * 16  # 256 KB
        evidence_file.write_bytes(full_content)

        expected_sha256 = hashlib.sha256(full_content).hexdigest()
        expected_size = len(full_content)

        mtime_before = evidence_file.stat().st_mtime_ns

        # Register with small 4 KB chunk size to test multi-chunk streaming
        record = register_memory_evidence(evidence_file, chunk_size=4096)

        self.assertEqual(record.sha256, expected_sha256)
        self.assertEqual(record.size_bytes, expected_size)
        self.assertEqual(record.file_path, str(evidence_file.resolve()))

        # Forensic Integrity: Original evidence was NOT modified
        mtime_after = evidence_file.stat().st_mtime_ns
        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(evidence_file.read_bytes(), full_content)

    def test_register_memory_evidence_errors(self):
        """register_memory_evidence fails cleanly on missing files or directories."""
        missing = self.temp_dir_path / "does_not_exist.raw"
        with self.assertRaises(FileNotFoundError):
            register_memory_evidence(missing)

        with self.assertRaises(IsADirectoryError):
            register_memory_evidence(self.temp_dir_path)

    # -------------------------------------------------------------------------
    # 5. Format Detection
    # -------------------------------------------------------------------------

    def test_format_detection_magic_headers(self):
        """detect_memory_format correctly identifies LiME, crash dumps, and ELF cores via headers."""
        # LiME format (little-endian and big-endian)
        lime_file = self.temp_dir_path / "mem.lime"
        lime_file.write_bytes(b"LiME\x01\x00\x00\x00" + b"\x00" * 100)
        self.assertEqual(detect_memory_format(lime_file), "lime")

        lime_be_file = self.temp_dir_path / "mem_be.lime"
        lime_be_file.write_bytes(b"EMiL\x00\x00\x00\x01" + b"\x00" * 100)
        self.assertEqual(detect_memory_format(lime_be_file), "lime")

        # Windows Crash Dump (PAGEDUMP, PAGE, DU64)
        dmp_file = self.temp_dir_path / "memory.dmp"
        dmp_file.write_bytes(b"PAGEDUMP" + b"\x00" * 100)
        self.assertEqual(detect_memory_format(dmp_file), "crash_dump")

        page_file = self.temp_dir_path / "memory_page.dmp"
        page_file.write_bytes(b"PAGE" + b"\x00" * 100)
        self.assertEqual(detect_memory_format(page_file), "crash_dump")

        du64_file = self.temp_dir_path / "memory_64.dmp"
        du64_file.write_bytes(b"DU64" + b"\x00" * 100)
        self.assertEqual(detect_memory_format(du64_file), "crash_dump")

        # ELF core (ELFCLASS64, little-endian, ET_CORE = 4)
        elf_file = self.temp_dir_path / "core.dump"
        elf_file.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(elf_file), "elf_core")

    def test_format_detection_elf_headers(self):
        """detect_memory_format validates ELF class, byte order, and requires e_type == ET_CORE."""
        # 1. Supported classes and byte orders with ET_CORE (4)
        # 64-bit Little-Endian ET_CORE
        core_64_le = self.temp_dir_path / "core_64_le.elf"
        core_64_le.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(core_64_le), "elf_core")

        # 32-bit Little-Endian ET_CORE
        core_32_le = self.temp_dir_path / "core_32_le.elf"
        core_32_le.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(core_32_le), "elf_core")

        # 64-bit Big-Endian ET_CORE
        core_64_be = self.temp_dir_path / "core_64_be.elf"
        core_64_be.write_bytes(b"\x7fELF\x02\x02\x01" + b"\x00" * 9 + b"\x00\x04" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(core_64_be), "elf_core")

        # 32-bit Big-Endian ET_CORE
        core_32_be = self.temp_dir_path / "core_32_be.elf"
        core_32_be.write_bytes(b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + b"\x00\x04" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(core_32_be), "elf_core")

        # 2. Non-core ELF types must return None (ET_EXEC = 2, ET_DYN = 3, ET_REL = 1)
        exec_elf = self.temp_dir_path / "exec.elf"
        exec_elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(exec_elf))

        dyn_elf = self.temp_dir_path / "dyn.so"
        dyn_elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x03\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(dyn_elf))

        rel_elf = self.temp_dir_path / "rel.o"
        rel_elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x01\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(rel_elf))

        # 3. Truncated ELF headers (< 18 bytes) must return None
        trunc1 = self.temp_dir_path / "trunc1.elf"
        trunc1.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        self.assertIsNone(detect_memory_format(trunc1))

        trunc2 = self.temp_dir_path / "trunc2.elf"
        trunc2.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04")  # 17 bytes
        self.assertIsNone(detect_memory_format(trunc2))

        # 4. Malformed / unsupported class (EI_CLASS not 1 or 2)
        bad_class = self.temp_dir_path / "bad_class.elf"
        bad_class.write_bytes(b"\x7fELF\x03\x01\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(bad_class))

        # 5. Malformed / unsupported byte order (EI_DATA not 1 or 2)
        bad_endian = self.temp_dir_path / "bad_endian.elf"
        bad_endian.write_bytes(b"\x7fELF\x02\x00\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(bad_endian))

    def test_format_detection_empty_and_short_files(self):
        """detect_memory_format returns None for empty and 1-to-3 byte files."""
        # Empty file (0 bytes)
        empty_file = self.temp_dir_path / "empty.raw"
        empty_file.write_bytes(b"")
        self.assertIsNone(detect_memory_format(empty_file))

        # 1-byte file
        one_byte = self.temp_dir_path / "one_byte.lime"
        one_byte.write_bytes(b"L")
        self.assertIsNone(detect_memory_format(one_byte))

        # 2-byte file
        two_bytes = self.temp_dir_path / "two_bytes.dmp"
        two_bytes.write_bytes(b"PA")
        self.assertIsNone(detect_memory_format(two_bytes))

        # 3-byte file
        three_bytes = self.temp_dir_path / "three_bytes.raw"
        three_bytes.write_bytes(b"\x7fEL")
        self.assertIsNone(detect_memory_format(three_bytes))

    def test_format_detection_conflicting_extension_and_content(self):
        """Header content overrides extension; extension alone never establishes format."""
        # LiME extension but verified ELF core header -> detected as elf_core
        conflict1 = self.temp_dir_path / "fake.lime"
        conflict1.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04\x00" + b"\x00" * 16)
        self.assertEqual(detect_memory_format(conflict1), "elf_core")

        # LiME extension but ELF executable header (ET_EXEC) -> detected as None
        conflict_exec = self.temp_dir_path / "fake_exec.lime"
        conflict_exec.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00" + b"\x00" * 16)
        self.assertIsNone(detect_memory_format(conflict_exec))

        # DMP extension but LiME header -> detected as lime
        conflict2 = self.temp_dir_path / "fake.dmp"
        conflict2.write_bytes(b"LiME\x01\x00\x00\x00" + b"\x00" * 32)
        self.assertEqual(detect_memory_format(conflict2), "lime")

        # RAW extension but crash dump header -> detected as crash_dump
        conflict3 = self.temp_dir_path / "fake.raw"
        conflict3.write_bytes(b"PAGEDUMP" + b"\x00" * 32)
        self.assertEqual(detect_memory_format(conflict3), "crash_dump")

    def test_format_detection_invalid_lime_signatures(self):
        """Invalid or corrupt LiME magic signatures return None."""
        invalid_lime1 = self.temp_dir_path / "bad_lime1.lime"
        invalid_lime1.write_bytes(b"LIME\x01\x00\x00\x00" + b"\x00" * 32)  # All uppercase
        self.assertIsNone(detect_memory_format(invalid_lime1))

        invalid_lime2 = self.temp_dir_path / "bad_lime2.lime"
        invalid_lime2.write_bytes(b"lime\x01\x00\x00\x00" + b"\x00" * 32)  # All lowercase
        self.assertIsNone(detect_memory_format(invalid_lime2))

        invalid_lime3 = self.temp_dir_path / "bad_lime3.lime"
        invalid_lime3.write_bytes(b"LiM\x00\x01\x00\x00\x00" + b"\x00" * 32)  # Truncated magic
        self.assertIsNone(detect_memory_format(invalid_lime3))

    def test_format_detection_unknown_data_returns_none(self):
        """Unknown or unverified data returns None regardless of filename extension."""
        for ext in (".raw", ".lime", ".dmp", ".img", ".bin", ".dd", ".dump"):
            f = self.temp_dir_path / f"unknown{ext}"
            f.write_bytes(b"\xaa\xbb\xcc\xdd" * 32)
            self.assertIsNone(
                detect_memory_format(f),
                f"Expected None for unknown content with extension {ext}",
            )

    # -------------------------------------------------------------------------
    # 6. VolatilityExecutionRecord & Execution Error
    # -------------------------------------------------------------------------

    def test_volatility_execution_record_immutability_and_roundtrip(self):
        """VolatilityExecutionRecord is frozen, validates fields, and roundtrips correctly."""
        err = VolatilityExecutionError(
            error_type="MISSING_SYMBOLS",
            error_message="Symbol table requirement unsatisfied",
            details=(("banner", "Linux 5.15.0"),),
        )

        exec_id = compute_deterministic_execution_id(
            tool="volatility3",
            plugin="linux.pslist",
            sanitized_args=("-f mem.raw", "-r json", "linux.pslist"),
            input_evidence_hash=self.sample_sha256,
        )

        rec = VolatilityExecutionRecord(
            record_id=exec_id,
            tool="volatility3",
            tool_version="2.4.0",
            plugin="linux.pslist",
            sanitized_args=("-f mem.raw", "-r json", "linux.pslist"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            started_at="2026-10-12T12:00:00+00:00",
            completed_at="2026-10-12T12:00:05+00:00",
            duration_seconds=5.0,
            exit_code=1,
            error=err,
            input_evidence_hash=self.sample_sha256,
            output_hashes=(("stdout", "abc123hash"),),
        )

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            rec.status = "SUCCESS"  # type: ignore

        # Dict round-trip
        d = rec.to_dict()
        self.assertEqual(d["tool"], "volatility3")
        self.assertEqual(d["executed"], True)
        self.assertEqual(d["error"]["error_type"], "MISSING_SYMBOLS")

        restored = VolatilityExecutionRecord.from_dict(d)
        self.assertEqual(rec, restored)

        # JSON round-trip
        j_str = rec.to_json()
        restored_j = VolatilityExecutionRecord.from_json(j_str)
        self.assertEqual(rec, restored_j)

    def test_execution_provenance_distinguishes_attempted_vs_executed(self):
        """Record clearly distinguishes unspawned attempts from executed processes."""
        unexecuted_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-1111",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=(),
            status=VolatilityExecutionStatus.ERROR.value,
            executed=False,
            exit_code=None,
        )
        self.assertFalse(unexecuted_rec.executed)
        self.assertIsNone(unexecuted_rec.exit_code)

        executed_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-2222",
            tool="vol3",
            plugin="linux.pslist",
            sanitized_args=(),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        self.assertTrue(executed_rec.executed)
        self.assertEqual(executed_rec.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
