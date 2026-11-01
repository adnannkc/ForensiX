"""
Integration and CLI tests for investigator notes commands (forensix.notes_cli).
"""

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from forensix.hasher import compute_hashes
from forensix.notes_cli import run_note_cli


class TestNotesCLI(unittest.TestCase):
    """Test suite for forensix note CLI subcommands."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.results_dir = self.temp_path / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.case_id = "CASE-2026-TEST-001"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_note_add_then_list(self):
        """Add one note, list it, and verify the note text appears in stdout."""
        stdout_capture = io.StringIO()
        code_add = run_note_cli(
            [
                "add",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
                "--author",
                "Lead Examiner",
                "--target",
                "case",
                "--text",
                "Initial note for test case.",
            ],
            stdout=stdout_capture,
        )
        self.assertEqual(code_add, 0)

        list_out = io.StringIO()
        code_list = run_note_cli(
            [
                "list",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
            ],
            stdout=list_out,
        )
        self.assertEqual(code_list, 0)
        output_text = list_out.getvalue()
        self.assertIn("Initial note for test case.", output_text)
        self.assertIn("Lead Examiner", output_text)
        self.assertIn("NOTE-", output_text)

    def test_note_list_target_filter(self):
        """Filtering by target returns only matching notes."""
        # Add two notes with different targets
        run_note_cli(
            [
                "add",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
                "--author",
                "Examiner 1",
                "--target",
                "case",
                "--text",
                "General case note text.",
            ]
        )
        run_note_cli(
            [
                "add",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
                "--author",
                "Examiner 2",
                "--target",
                "evidence:network.pcap",
                "--text",
                "Network capture observation.",
            ]
        )

        # Filter by evidence:network.pcap
        filtered_out = io.StringIO()
        code = run_note_cli(
            [
                "list",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
                "--target",
                "evidence:network.pcap",
            ],
            stdout=filtered_out,
        )
        self.assertEqual(code, 0)
        val = filtered_out.getvalue()
        self.assertIn("Network capture observation.", val)
        self.assertNotIn("General case note text.", val)

    def test_note_commands_preserve_evidence_and_results_integrity(self):
        """Hash every file in evidence, reports, ledger, and manifest before and after note operations; assert unchanged."""
        # Copy synthetic case evidence and run pipeline to establish baseline output
        sample_case = Path("examples/case-synthetic/case.json")
        out_dir = self.temp_path / "synthetic_run"
        
        # Execute pipeline to generate baseline artifacts
        cmd = [
            sys.executable,
            "-m",
            "forensix",
            "case",
            "--config",
            str(sample_case),
            "-o",
            str(out_dir),
            "--overwrite",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env={"PYTHONPATH": "src"})
        self.assertEqual(proc.returncode, 0)

        # Record pre-hashes for evidence and generated artifacts
        def get_all_target_hashes():
            digests = {}
            # Evidence directory files
            for p in Path("examples/case-synthetic").rglob("*"):
                if p.is_file():
                    digests[f"evidence:{p.resolve()}"] = hashlib.sha256(p.read_bytes()).hexdigest()
            # Pipeline generated files
            for p in out_dir.iterdir():
                if p.is_file() and not p.name.startswith("notes_"):
                    digests[f"output:{p.name}"] = hashlib.sha256(p.read_bytes()).hexdigest()
            return digests

        pre_digests = get_all_target_hashes()

        # Run note add and note list
        run_note_cli(
            [
                "add",
                "--case-id",
                "CASE-2026-SYNTHETIC-001",
                "-o",
                str(out_dir),
                "--author",
                "Chief Digital Forensics Examiner",
                "--target",
                "case",
                "--text",
                "Investigator note testing integrity boundary.",
            ]
        )
        list_buf = io.StringIO()
        run_note_cli(
            [
                "list",
                "--case-id",
                "CASE-2026-SYNTHETIC-001",
                "-o",
                str(out_dir),
            ],
            stdout=list_buf,
        )

        post_digests = get_all_target_hashes()

        # Assert every single digest is identical
        self.assertEqual(pre_digests, post_digests)

    def test_note_add_refuses_missing_author(self):
        """Exit code is non-zero and a clear error is reported when author is missing or empty."""
        err_capture = io.StringIO()
        code = run_note_cli(
            [
                "add",
                "--case-id",
                self.case_id,
                "-o",
                str(self.results_dir),
                "--author",
                "",
                "--target",
                "case",
                "--text",
                "Some text",
            ],
            stderr=err_capture,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("author", err_capture.getvalue().lower())

    def test_notes_never_enter_ledger_or_report(self):
        """After adding a note and rerunning the sample case, grep reports and ledger for note text; zero hits."""
        unique_secret_note = "UNIQUE_INVESTIGATOR_SECRET_MARKER_98765"
        out_dir = self.temp_path / "leak_check_run"
        sample_case = Path("examples/case-synthetic/case.json")

        # 1. Run pipeline
        subprocess.run(
            [sys.executable, "-m", "forensix", "case", "--config", str(sample_case), "-o", str(out_dir), "--overwrite"],
            check=True,
            env={"PYTHONPATH": "src"},
        )

        # 2. Add note
        run_note_cli(
            [
                "add",
                "--case-id",
                "CASE-2026-SYNTHETIC-001",
                "-o",
                str(out_dir),
                "--author",
                "Examiner Secret",
                "--target",
                "case",
                "--text",
                unique_secret_note,
            ]
        )

        # 3. Rerun pipeline
        subprocess.run(
            [sys.executable, "-m", "forensix", "case", "--config", str(sample_case), "-o", str(out_dir), "--overwrite"],
            check=True,
            env={"PYTHONPATH": "src"},
        )

        # 4. Check all output files (except notes_*.json) for the secret marker
        for f in out_dir.iterdir():
            if f.is_file() and not f.name.startswith("notes_"):
                content = f.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn(
                    unique_secret_note,
                    content,
                    f"Found investigator note text leaked into pipeline output file: {f.name}",
                )


if __name__ == "__main__":
    unittest.main()
