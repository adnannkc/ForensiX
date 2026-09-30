"""
End-to-End Integration Tests for ForensiX V1 Pipeline (Milestone 7).

Validates the complete execution path from input evidence file through the CLI,
registration, identification, metadata extraction, cryptographic hashing,
ForensicAnalysisResult construction, and JSON report generation.
"""

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class TestEndToEndPipeline(unittest.TestCase):
    """Comprehensive end-to-end test suite for ForensiX V1 CLI workflow."""

    def setUp(self):
        """Set up temporary working directories for test evidence and reports."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

        self.evidence_dir = self.test_dir_path / "evidence_pool"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.reports_dir = self.test_dir_path / "reports_pool"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Base environment with src directory on PYTHONPATH
        self.env = dict(os.environ, PYTHONPATH="src")

    def tearDown(self):
        """Clean up temporary directories, restoring permissions if needed."""
        # Ensure any read-only files created in tests can be removed
        for root, dirs, files in os.walk(self.test_dir_path):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    os.chmod(fpath, 0o644)
                except OSError:
                    pass
        self.test_dir.cleanup()

    def _run_cli(self, *args) -> subprocess.CompletedProcess:
        """Helper to invoke python3 -m forensix via subprocess."""
        cmd = [sys.executable, "-m", "forensix", *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=self.env,
        )

    def _get_latest_report(self) -> Path:
        """Retrieve the most recently created JSON report in reports_dir."""
        reports = list(self.reports_dir.glob("*.json"))
        self.assertGreater(len(reports), 0, "No report files found in reports directory")
        reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return reports[0]

    def test_scenario_a_normal_text_evidence(self):
        """Scenario A: Complete pipeline run against standard text evidence."""
        content = b"2026-09-29T22:00:00Z [AUTH] User root authenticated via SSH\n"
        sample_file = self.evidence_dir / "auth_incident.log"
        sample_file.write_bytes(content)

        # Independent test-side hash calculation
        expected_md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        proc = self._run_cli(str(sample_file), "-o", str(self.reports_dir))

        # 1. Process exit status
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")

        # 2. Terminal output checks
        self.assertIn("ForensiX Analysis Complete", proc.stdout)
        self.assertIn("Evidence ID : EV-", proc.stdout)
        self.assertIn(f"File        : {sample_file.name}", proc.stdout)
        self.assertIn(f"Size        : {len(content)} bytes", proc.stdout)
        self.assertIn(f"MD5         : {expected_md5}", proc.stdout)
        self.assertIn(f"SHA-256     : {expected_sha256}", proc.stdout)

        # 3. Report file existence and structure
        report_path = self._get_latest_report()
        self.assertTrue(report_path.exists())

        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report_data["file"]["filename"], "auth_incident.log")
        self.assertEqual(report_data["file"]["size"], len(content))
        self.assertEqual(report_data["hashes"]["md5"], expected_md5)
        self.assertEqual(report_data["hashes"]["sha256"], expected_sha256)
        self.assertEqual(report_data["evidence"]["original_path"], str(sample_file.resolve()))

    def test_scenario_b_empty_evidence(self):
        """Scenario B: Pipeline handles zero-byte evidence without crashing."""
        empty_file = self.evidence_dir / "zero_byte.raw"
        empty_file.write_bytes(b"")

        expected_md5 = hashlib.md5(b"", usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(b"").hexdigest()

        proc = self._run_cli(str(empty_file), "-o", str(self.reports_dir))

        self.assertEqual(proc.returncode, 0, f"CLI crashed on empty file: {proc.stderr}")
        self.assertIn("Size        : 0 bytes", proc.stdout)
        self.assertIn(f"MD5         : {expected_md5}", proc.stdout)
        self.assertIn(f"SHA-256     : {expected_sha256}", proc.stdout)

        report_data = json.loads(self._get_latest_report().read_text(encoding="utf-8"))
        self.assertEqual(report_data["file"]["size"], 0)
        self.assertEqual(report_data["hashes"]["sha256"], expected_sha256)

    def test_scenario_c_binary_evidence(self):
        """Scenario C: Binary evidence bytes are not corrupted and hashes match independently."""
        # 128 KB deterministic pseudo-random binary payload
        binary_data = bytes((x * 37) % 256 for x in range(128 * 1024))
        bin_file = self.evidence_dir / "memory_sector.bin"
        bin_file.write_bytes(binary_data)

        expected_md5 = hashlib.md5(binary_data, usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()

        proc = self._run_cli(str(bin_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0)

        # Verify content was not modified
        self.assertEqual(bin_file.read_bytes(), binary_data)

        report_data = json.loads(self._get_latest_report().read_text(encoding="utf-8"))
        self.assertEqual(report_data["hashes"]["md5"], expected_md5)
        self.assertEqual(report_data["hashes"]["sha256"], expected_sha256)
        self.assertEqual(report_data["file"]["size"], len(binary_data))

    def test_scenario_d_non_ascii_filename(self):
        """Scenario D: Unicode and non-ASCII filenames are supported cleanly."""
        content = b"Non-ASCII evidence testing payload"
        unicode_name = "évidence_triage_测试_2026.dat"
        unicode_file = self.evidence_dir / unicode_name
        unicode_file.write_bytes(content)

        proc = self._run_cli(str(unicode_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0, f"Failed on Unicode filename: {proc.stderr}")

        report_data = json.loads(self._get_latest_report().read_text(encoding="utf-8"))
        self.assertEqual(report_data["file"]["filename"], unicode_name)
        self.assertEqual(report_data["file"]["size"], len(content))

    def test_scenario_e_deep_nested_path(self):
        """Scenario E: Evidence located in deeply nested subdirectories is processed correctly."""
        deep_dir = self.evidence_dir / "case_2026" / "vol_1" / "partition_2" / "logs"
        deep_dir.mkdir(parents=True, exist_ok=True)

        deep_file = deep_dir / "firewall_drop.log"
        content = b"DROP TCP 10.0.0.5 -> 192.168.1.1:445\n"
        deep_file.write_bytes(content)

        proc = self._run_cli(str(deep_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0)

        report_data = json.loads(self._get_latest_report().read_text(encoding="utf-8"))
        self.assertEqual(report_data["evidence"]["original_path"], str(deep_file.resolve()))
        self.assertEqual(report_data["file"]["filename"], "firewall_drop.log")

    def test_scenario_f_missing_evidence(self):
        """Scenario F: Non-existent path returns non-zero status and creates no report."""
        initial_reports = list(self.reports_dir.glob("*.json"))
        missing_target = self.evidence_dir / "ghost_file.raw"

        proc = self._run_cli(str(missing_target), "-o", str(self.reports_dir))

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Error: Evidence file does not exist", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

        # Assert no report was created
        current_reports = list(self.reports_dir.glob("*.json"))
        self.assertEqual(len(initial_reports), len(current_reports))

    def test_scenario_g_directory_target(self):
        """Scenario G: Passing a directory returns non-zero status and creates no report."""
        initial_reports = list(self.reports_dir.glob("*.json"))
        sub_folder = self.evidence_dir / "target_folder"
        sub_folder.mkdir(parents=True, exist_ok=True)

        proc = self._run_cli(str(sub_folder), "-o", str(self.reports_dir))

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("target is a directory", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

        # Assert no report was created
        current_reports = list(self.reports_dir.glob("*.json"))
        self.assertEqual(len(initial_reports), len(current_reports))

    def test_scenario_h_read_only_evidence(self):
        """Scenario H: Read-only evidence is analyzed without modification or permission failure."""
        ro_file = self.evidence_dir / "readonly_evidence.bin"
        content = b"Read-only forensic evidence block"
        ro_file.write_bytes(content)
        os.chmod(ro_file, 0o444)  # Read-only (r--r--r--)

        expected_sha256 = hashlib.sha256(content).hexdigest()

        proc = self._run_cli(str(ro_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0, f"Failed on read-only file: {proc.stderr}")

        report_data = json.loads(self._get_latest_report().read_text(encoding="utf-8"))
        self.assertEqual(report_data["hashes"]["sha256"], expected_sha256)
        self.assertEqual(report_data["metadata"]["permissions"], "0444")

    def test_scenario_i_evidence_immutability(self):
        """Scenario I: Comprehensive bitstream and metadata immutability verification."""
        test_file = self.evidence_dir / "immutability_sample.img"
        test_bytes = b"Evidence bitstream verification across full CLI lifecycle\n" * 50
        test_file.write_bytes(test_bytes)
        os.chmod(test_file, 0o640)

        # Record pre-execution state
        pre_content = test_file.read_bytes()
        pre_md5 = hashlib.md5(pre_content, usedforsecurity=False).hexdigest()
        pre_sha256 = hashlib.sha256(pre_content).hexdigest()
        pre_stat = test_file.stat()

        # Run complete CLI
        proc = self._run_cli(str(test_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0)

        # Record post-execution state
        post_content = test_file.read_bytes()
        post_md5 = hashlib.md5(post_content, usedforsecurity=False).hexdigest()
        post_sha256 = hashlib.sha256(post_content).hexdigest()
        post_stat = test_file.stat()

        # Verify exact matches
        self.assertEqual(pre_content, post_content, "Evidence content bytes were modified!")
        self.assertEqual(pre_md5, post_md5, "MD5 digest changed after CLI execution!")
        self.assertEqual(pre_sha256, post_sha256, "SHA-256 digest changed after CLI execution!")
        self.assertEqual(pre_stat.st_size, post_stat.st_size, "File size changed!")
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime, "Modification time changed!")
        self.assertEqual(pre_stat.st_mode, post_stat.st_mode, "File permissions changed!")

    def test_report_isolation(self):
        """Verify reports are stored in reports_dir and never beside evidence."""
        sample_file = self.evidence_dir / "isolated_evidence.txt"
        sample_file.write_bytes(b"isolated evidence check")

        # Snapshot evidence directory
        pre_evidence_files = set(self.evidence_dir.iterdir())

        proc = self._run_cli(str(sample_file), "-o", str(self.reports_dir))
        self.assertEqual(proc.returncode, 0)

        # 1. No new files created in evidence directory
        post_evidence_files = set(self.evidence_dir.iterdir())
        self.assertEqual(pre_evidence_files, post_evidence_files)

        # 2. Report is placed in reports_dir only
        report = self._get_latest_report()
        self.assertEqual(report.parent, self.reports_dir.resolve())
        self.assertTrue(report.name.startswith("EV-"))

        # 3. Evidence is not copied into reports directory
        self.assertFalse((self.reports_dir / "isolated_evidence.txt").exists())

    def test_repeated_execution_consistency(self):
        """Verify repeated runs against the same evidence produce consistent hashes and separate reports."""
        repeat_file = self.evidence_dir / "repeat_run.log"
        content = b"Repeated forensic execution analysis\n"
        repeat_file.write_bytes(content)

        expected_sha256 = hashlib.sha256(content).hexdigest()

        # Run 1
        proc1 = self._run_cli(str(repeat_file), "-o", str(self.reports_dir))
        self.assertEqual(proc1.returncode, 0)
        report1 = self._get_latest_report()
        data1 = json.loads(report1.read_text(encoding="utf-8"))

        # Run 2
        proc2 = self._run_cli(str(repeat_file), "-o", str(self.reports_dir))
        self.assertEqual(proc2.returncode, 0)
        report2 = self._get_latest_report()
        data2 = json.loads(report2.read_text(encoding="utf-8"))

        # Both runs produce different report files (distinct evidence IDs)
        self.assertNotEqual(report1.name, report2.name)
        self.assertNotEqual(data1["evidence"]["evidence_id"], data2["evidence"]["evidence_id"])

        # Both reports verify identical content hashes
        self.assertEqual(data1["hashes"]["sha256"], expected_sha256)
        self.assertEqual(data2["hashes"]["sha256"], expected_sha256)
        self.assertEqual(data1["hashes"]["sha256"], data2["hashes"]["sha256"])

        # Evidence file remains unaltered
        self.assertEqual(repeat_file.read_bytes(), content)

    def test_cli_help_flag(self):
        """Verify --help flag exits with code 0 and provides clear guidance."""
        proc = self._run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ForensiX - Automated Digital Forensics", proc.stdout)
        self.assertIn("evidence_file", proc.stdout)
        self.assertIn("--output-dir", proc.stdout)


if __name__ == "__main__":
    unittest.main()
