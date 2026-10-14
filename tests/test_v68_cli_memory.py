"""
Comprehensive Test Suite for ForensiX Milestone V6.8 — Artifact-Based Memory CLI.

Validates:
1. CLI help (`memory --help`) displays usage, arguments, and options.
2. Router dispatch in `main.py` handles both `memory` and `mem` subcommands.
3. Missing evidence path rejection (exit code 1).
4. Empty or whitespace-only case ID rejection (exit code 1).
5. Conflicting output format flags (`--json` and `--html`) rejection (exit code 1).
6. Unsafe report destination rejection (cannot overwrite input or write inside evidence dir) (exit code 1).
7. Rejection of raw memory images (.raw, .lime, .dmp) with clear diagnostic (exit code 1).
8. Malformed JSON and unsupported artifact schema diagnostics (exit code 1).
9. Successful memory triage over synthetic artifact JSON file (exit code 0).
10. JSON report generation conforming to CorrelationDetectionReport schema.
11. HTML report generation with self-contained presentation.
12. Directory-based artifact ingestion (multiple JSON artifact files).
13. Empty directory / no JSON files diagnostic (exit code 1).
14. Matched-only report filtering (`--matched-only`).
15. Case metadata propagation (`--case-id`, `--case-name`, `--investigator`).
16. Strict evidence immutability (cryptographic hash verified before and after).
17. Argparse syntax errors return standard exit code 2.
18. Verbose output provides stage progress information.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Dict, List
import unittest
from unittest.mock import patch

from forensix import __version__
from forensix.detection_reporting import CorrelationDetectionReport
from forensix.main import main
from forensix.memory_cli import (
    build_memory_parser,
    execute_memory_cli,
    load_memory_artifacts,
    memory_main,
)
from forensix.memory_models import (
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    compute_deterministic_memory_id,
    compute_deterministic_module_id,
    compute_deterministic_network_id,
    compute_deterministic_process_id,
)


class TestMemoryCLISuite(unittest.TestCase):
    """Test suite for ForensiX Milestone V6.8 Memory Forensics CLI."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="forensix_test_v68_")
        self.evidence_dir = Path(self.temp_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = Path(self.temp_dir) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.evidence_id = compute_deterministic_memory_id(
            sha256="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            file_size=2097152,
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

        self.proc_dict: Dict[str, Any] = {
            "artifact_id": self.proc_art_id,
            "evidence_id": self.evidence_id,
            "pid": 4321,
            "ppid": 1,
            "process_name": "nc",
            "source_plugin": "linux.pslist",
            "created_at": "2026-10-14T10:00:00+00:00",
            "source_row_indices": [0],
            "raw_attributes": {"command_line": "nc -lvnp 4444"},
        }
        self.net_dict: Dict[str, Any] = {
            "artifact_id": self.net_art_id,
            "evidence_id": self.evidence_id,
            "protocol": "TCP",
            "source_plugin": "linux.sockstat",
            "local_address": "0.0.0.0",
            "local_port": 4444,
            "state": "LISTEN",
            "pid": 4321,
            "process_name": "nc",
            "source_row_indices": [1],
            "raw_attributes": {},
        }
        self.mod_dict: Dict[str, Any] = {
            "artifact_id": self.mod_art_id,
            "evidence_id": self.evidence_id,
            "module_name": "rkhunter_mod",
            "source_plugin": "linux.lsmod",
            "driver_path": "/tmp/rkhunter_mod.ko",
            "size_bytes": 4096,
            "source_row_indices": [2],
            "raw_attributes": {},
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_artifact_file(self, filename: str, artifacts: List[Dict[str, Any]]) -> Path:
        """Write a synthetic artifact JSON file inside the evidence directory."""
        target = self.evidence_dir / filename
        with open(target, "w", encoding="utf-8") as f:
            json.dump(artifacts, f, indent=2)
        return target

    # 1. CLI Help and Parser
    def test_01_memory_help(self) -> None:
        """Verify memory --help displays valid usage and options."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
            exit_code = memory_main(["--help"])

        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("ForensiX", output)
        self.assertIn("memory", output)
        self.assertIn("--case-id", output)
        self.assertIn("--format", output)
        self.assertIn("--matched-only", output)

    # 2. Router Dispatch in main.py
    def test_02_router_dispatch(self) -> None:
        """Verify main() routes 'memory' and 'mem' subcommands."""
        for cmd in ("memory", "mem"):
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
                exit_code = main([cmd, "--help"])
            self.assertEqual(exit_code, 0)
            self.assertIn("ForensiX", stdout_buf.getvalue())

    # 3. Missing Evidence Path
    def test_03_missing_evidence_path(self) -> None:
        """Verify non-existent evidence path returns exit code 1."""
        non_existent = str(self.evidence_dir / "does_not_exist.json")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([non_existent])
        self.assertEqual(exit_code, 1)
        self.assertIn("Evidence path does not exist", stderr_buf.getvalue())

    # 4. Empty Case ID Validation
    def test_04_empty_case_id(self) -> None:
        """Verify empty or whitespace-only case ID returns exit code 1."""
        art_path = self._write_artifact_file("artifacts.json", [self.proc_dict])
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(art_path), "--case-id", "   "])
        self.assertEqual(exit_code, 1)
        self.assertIn("Case ID cannot be empty or whitespace", stderr_buf.getvalue())

    # 5. Conflicting Format Flags
    def test_05_conflicting_format_flags(self) -> None:
        """Verify specifying both --json and --html returns exit code 1."""
        art_path = self._write_artifact_file("artifacts.json", [self.proc_dict])
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(art_path), "--json", "--html"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Cannot specify both --json and --html", stderr_buf.getvalue())

    # 6. Unsafe Report Destinations
    def test_06_unsafe_report_destination(self) -> None:
        """Verify report cannot overwrite input evidence file or enter evidence directory."""
        art_path = self._write_artifact_file("artifacts.json", [self.proc_dict])

        # Attempt to overwrite the input file itself
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(art_path), "-o", str(art_path)])
        self.assertEqual(exit_code, 1)
        self.assertIn("cannot be identical to evidence path", stderr_buf.getvalue())

        # Attempt to write into directory evidence
        stderr_buf = io.StringIO()
        unsafe_dest = self.evidence_dir / "report.html"
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(self.evidence_dir), "-o", str(unsafe_dest)])
        self.assertEqual(exit_code, 1)
        self.assertIn("cannot be within evidence directory", stderr_buf.getvalue())

    # 7. Raw Memory Image Rejection
    def test_07_raw_memory_image_rejection(self) -> None:
        """Verify raw image files (.raw, .lime, .dmp) are rejected with clear diagnostics."""
        for ext in (".raw", ".lime", ".dmp", ".vmem"):
            raw_file = self.evidence_dir / f"sample{ext}"
            raw_file.write_bytes(b"\x00" * 1024)

            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = memory_main([str(raw_file)])
            self.assertEqual(exit_code, 1)
            err_msg = stderr_buf.getvalue()
            self.assertIn("Raw memory image", err_msg)
            self.assertIn("not supported in artifact-based memory triage", err_msg)

    # 8. Malformed Input Diagnostics
    def test_08_malformed_json_and_schema(self) -> None:
        """Verify malformed JSON or unsupported artifact schemas produce exit code 1."""
        # 1. Invalid JSON syntax
        bad_json = self.evidence_dir / "corrupt.json"
        bad_json.write_text("{this is not valid json}", encoding="utf-8")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(bad_json)])
        self.assertEqual(exit_code, 1)
        self.assertIn("Malformed JSON", stderr_buf.getvalue())

        # 2. Unsupported schema (missing artifact_id)
        bad_schema = self.evidence_dir / "bad_schema.json"
        with open(bad_schema, "w", encoding="utf-8") as f:
            json.dump([{"some_unknown_key": "some_value"}], f)
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(bad_schema)])
        self.assertEqual(exit_code, 1)
        self.assertIn("Unsupported or unrecognized memory artifact schema", stderr_buf.getvalue())

    # 9. Successful Triage over Single Artifact JSON File
    def test_09_successful_triage_single_file(self) -> None:
        """Verify successful end-to-end memory triage generating HTML report."""
        art_path = self._write_artifact_file(
            "artifacts.json",
            [self.proc_dict, self.net_dict, self.mod_dict],
        )
        out_report = self.reports_dir / "test_report.html"

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code, report = execute_memory_cli([
                str(art_path),
                "--case-id", "CASE-2026-MEM01",
                "--case-name", "Memory Investigation Test",
                "--investigator", "Agent 007",
                "-o", str(out_report),
                "--html",
            ])

        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertTrue(out_report.exists())
        self.assertGreater(out_report.stat().st_size, 0)

        # Check terminal output
        stdout_val = stdout_buf.getvalue()
        self.assertIn("ForensiX Memory Forensics Triage", stdout_val)
        self.assertIn("Artifacts Analyzed      : 3", stdout_val)
        self.assertIn("Status                  : SUCCESS", stdout_val)

        # Verify HTML report content
        html_content = out_report.read_text(encoding="utf-8")
        self.assertIn("CASE-2026-MEM01", html_content)
        self.assertIn("Memory Investigation Test", html_content)

    # 10. JSON Report Generation
    def test_10_successful_triage_json_report(self) -> None:
        """Verify JSON report generation conforming to CorrelationDetectionReport schema."""
        art_path = self._write_artifact_file(
            "artifacts.json",
            [self.proc_dict, self.net_dict, self.mod_dict],
        )
        out_report = self.reports_dir / "test_report.json"

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code, report = execute_memory_cli([
                str(art_path),
                "--case-id", "CASE-JSON-01",
                "-o", str(out_report),
                "--json",
            ])

        self.assertEqual(exit_code, 0)
        self.assertTrue(out_report.exists())

        with open(out_report, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["metadata"]["case_id"], "CASE-JSON-01")
        self.assertIn("detections", data)
        self.assertIn("timeline_events", data)
        self.assertIn("correlations", data)
        self.assertGreater(len(data["detections"]), 0)

    # 11. Directory-Based Artifact Ingestion
    def test_11_directory_artifact_ingestion(self) -> None:
        """Verify memory triage across a directory of multiple JSON artifact files."""
        # Split into separate files
        self._write_artifact_file("procs.json", [self.proc_dict])
        self._write_artifact_file("net.json", [self.net_dict])
        self._write_artifact_file("mod.json", [self.mod_dict])

        out_report = self.reports_dir / "dir_report.html"

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code, report = execute_memory_cli([
                str(self.evidence_dir),
                "-o", str(out_report),
            ])

        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        stdout_val = stdout_buf.getvalue()
        self.assertIn("Artifacts Analyzed      : 3", stdout_val)
        self.assertTrue(out_report.exists())

    # 12. Empty Directory Error
    def test_12_empty_artifact_directory(self) -> None:
        """Verify directory with no JSON files returns exit code 1."""
        empty_dir = Path(self.temp_dir) / "empty_dir"
        empty_dir.mkdir(parents=True, exist_ok=True)

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main([str(empty_dir)])
        self.assertEqual(exit_code, 1)
        self.assertIn("contains no JSON memory artifact files", stderr_buf.getvalue())

    # 13. Matched-Only Reporting
    def test_13_matched_only_reporting(self) -> None:
        """Verify --matched-only filters non-matching detection rules."""
        art_path = self._write_artifact_file(
            "artifacts.json",
            [self.proc_dict, self.net_dict, self.mod_dict],
        )
        out_report = self.reports_dir / "matched_only.json"

        exit_code, report = execute_memory_cli([
            str(art_path),
            "-o", str(out_report),
            "--json",
            "--matched-only",
        ])

        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        with open(out_report, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Every detection in the report must have matched=True
        for det in data["detections"]:
            self.assertTrue(det["matched"])

    # 14. Case Metadata Propagation
    def test_14_metadata_propagation(self) -> None:
        """Verify case metadata is properly propagated to the report."""
        art_path = self._write_artifact_file("artifacts.json", [self.proc_dict])
        out_report = self.reports_dir / "meta_report.json"

        exit_code, report = execute_memory_cli([
            str(art_path),
            "--case-id", "INCIDENT-9999",
            "--case-name", "Operation Memory Scan",
            "--investigator", "Investigator Holmes",
            "-o", str(out_report),
            "--json",
        ])

        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(report)
        self.assertEqual(report.case_id, "INCIDENT-9999")
        self.assertEqual(report.case_name, "Operation Memory Scan")
        self.assertEqual(report.investigator, "Investigator Holmes")

    # 15. Evidence Immutability
    def test_15_evidence_immutability(self) -> None:
        """Verify evidence files are strictly unmodified during triage."""
        art_path = self._write_artifact_file(
            "artifacts.json",
            [self.proc_dict, self.net_dict, self.mod_dict],
        )

        def get_sha256(p: Path) -> str:
            return hashlib.sha256(p.read_bytes()).hexdigest()

        hash_before = get_sha256(art_path)
        out_report = self.reports_dir / "immutability_report.html"

        exit_code, _ = execute_memory_cli([
            str(art_path),
            "-o", str(out_report),
        ])

        self.assertEqual(exit_code, 0)
        hash_after = get_sha256(art_path)
        self.assertEqual(hash_before, hash_after)

    # 16. Argparse Syntax Errors
    def test_16_argparse_syntax_errors(self) -> None:
        """Verify invalid flags return exit code 2."""
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = memory_main(["--unrecognized-argument-xyz"])
        self.assertEqual(exit_code, 2)

    # 17. Verbose Execution Information
    def test_17_verbose_execution(self) -> None:
        """Verify --verbose displays stage-by-stage progress information."""
        art_path = self._write_artifact_file("artifacts.json", [self.proc_dict])
        out_report = self.reports_dir / "verbose_report.html"

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code, _ = execute_memory_cli([
                str(art_path),
                "-o", str(out_report),
                "--verbose",
            ])

        self.assertEqual(exit_code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("[1/3] Loading Memory Artifacts...", output)
        self.assertIn("[2/3] Executing Memory Triage Pipeline...", output)
        self.assertIn("[3/3] Generating Memory Triage Report...", output)


if __name__ == "__main__":
    unittest.main()
