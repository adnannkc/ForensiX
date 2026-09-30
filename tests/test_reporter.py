"""
Unit tests for ForensiX JSON reporting module (reporter.py).
"""

import json
from pathlib import Path
import tempfile
import unittest

from forensix.analyzer import analyze_evidence
from forensix.hasher import compute_hashes
from forensix.reporter import generate_json_report, sanitize_filename


class TestReporter(unittest.TestCase):
    """Test suite for generate_json_report in src/forensix/reporter.py."""

    def setUp(self):
        """Create temporary workspace for evidence and reports."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

        # Create a sample evidence file
        self.evidence_file = self.test_dir_path / "syslog_sample.log"
        self.sample_content = b"Oct 12 10:14:00 server sshd[1234]: Accepted publickey for admin\n"
        self.evidence_file.write_bytes(self.sample_content)

        # Output directory for reports
        self.reports_dir = self.test_dir_path / "reports_output"

    def tearDown(self):
        """Clean up temporary directory."""
        self.test_dir.cleanup()

    def test_successful_json_report_generation(self):
        """Test generating report successfully and verifying file existence."""
        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        self.assertTrue(report_path.exists())
        self.assertEqual(report_path.suffix, ".json")
        self.assertTrue(report_path.name.startswith("EV-"))

    def test_reports_directory_creation_when_missing(self):
        """Test that missing reports directory is automatically created."""
        nested_dir = self.test_dir_path / "deeply" / "nested" / "reports"
        self.assertFalse(nested_dir.exists())

        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=nested_dir)

        self.assertTrue(nested_dir.exists())
        self.assertTrue(report_path.exists())

    def test_valid_json_and_expected_structure(self):
        """Test report contains valid, parseable JSON with all top-level sections."""
        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        raw_text = report_path.read_text(encoding="utf-8")
        parsed = json.loads(raw_text)

        # Expected top-level keys
        self.assertIn("evidence", parsed)
        self.assertIn("file", parsed)
        self.assertIn("metadata", parsed)
        self.assertIn("hashes", parsed)

    def test_preserved_evidence_information(self):
        """Test that evidence registration info is preserved accurately in report."""
        custom_id = "EV-REPORT-TEST-1234"
        analysis = analyze_evidence(self.evidence_file, evidence_id=custom_id)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        evidence = parsed["evidence"]

        self.assertEqual(evidence["evidence_id"], custom_id)
        self.assertEqual(evidence["original_path"], str(self.evidence_file.resolve()))
        self.assertEqual(evidence["registered_at"], analysis.evidence.registered_at)

    def test_preserved_file_and_metadata_information(self):
        """Test that file info and filesystem metadata are preserved."""
        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        file_sec = parsed["file"]
        meta_sec = parsed["metadata"]

        self.assertEqual(file_sec["filename"], "syslog_sample.log")
        self.assertEqual(file_sec["size"], len(self.sample_content))
        self.assertEqual(file_sec["extension"], ".log")

        self.assertEqual(meta_sec["permissions"], analysis.metadata.permissions)
        self.assertEqual(meta_sec["modified"], analysis.metadata.modified)
        self.assertEqual(meta_sec["accessed"], analysis.metadata.accessed)
        self.assertEqual(meta_sec["created"], analysis.metadata.created)

    def test_preserved_hashes(self):
        """Test that MD5 and SHA-256 hashes are preserved accurately."""
        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        hashes = parsed["hashes"]

        self.assertEqual(hashes["md5"], analysis.hashes.md5)
        self.assertEqual(hashes["sha256"], analysis.hashes.sha256)

    def test_human_readable_indentation(self):
        """Test that report is formatted with newlines and standard indentation."""
        analysis = analyze_evidence(self.evidence_file)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir, indent=4)

        raw_text = report_path.read_text(encoding="utf-8")
        # Check that multiple indented lines are present
        lines = raw_text.splitlines()
        self.assertGreater(len(lines), 15)
        self.assertTrue(lines[1].startswith("    \"evidence\": {"))

    def test_safe_deterministic_filename(self):
        """Test that unsafe evidence IDs or filenames are properly sanitized."""
        custom_id = "EV-2026/../../../evil:name"
        analysis = analyze_evidence(self.evidence_file, evidence_id=custom_id)
        report_path = generate_json_report(analysis, output_dir=self.reports_dir)

        # Path must remain strictly within reports_dir
        self.assertEqual(report_path.parent, self.reports_dir.resolve())
        # Slashes and colons must be sanitized
        self.assertNotIn("/", report_path.name.replace(".json", ""))
        self.assertNotIn(":", report_path.name)

    def test_original_evidence_remains_unchanged(self):
        """Test that generating a report does not touch the original evidence."""
        hashes_pre = compute_hashes(self.evidence_file)
        stat_pre = self.evidence_file.stat()

        analysis = analyze_evidence(self.evidence_file)
        _ = generate_json_report(analysis, output_dir=self.reports_dir)

        hashes_post = compute_hashes(self.evidence_file)
        stat_post = self.evidence_file.stat()

        self.assertEqual(hashes_pre["sha256"], hashes_post["sha256"])
        self.assertEqual(stat_pre.st_size, stat_post.st_size)
        self.assertEqual(stat_pre.st_mtime, stat_post.st_mtime)

    def test_incomplete_result_raises_valueerror(self):
        """Test passing an invalid/incomplete dict raises ValueError."""
        incomplete_data = {"evidence": {}, "file": {}}
        with self.assertRaises(ValueError):
            generate_json_report(incomplete_data, output_dir=self.reports_dir)

    def test_sanitize_filename_helper(self):
        """Test filename sanitization utility."""
        self.assertEqual(sanitize_filename("valid-name_123"), "valid-name_123")
        self.assertEqual(sanitize_filename("../../etc/passwd"), "etc_passwd")
        self.assertEqual(sanitize_filename("evil|pipe&cmd"), "evil_pipe_cmd")


if __name__ == "__main__":
    unittest.main()
