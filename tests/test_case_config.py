"""
Unit tests for ForensiX V9 CaseConfig.
"""

import json
from pathlib import Path
import tempfile
import unittest

from forensix.case_config import (
    CaseConfig,
    load_case_config_from_dict,
    load_case_config_from_file,
    validate_case_config,
)


class TestCaseConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        # Create dummy evidence directory and files
        self.host_dir = self.base_path / "host_ev"
        self.host_dir.mkdir(parents=True, exist_ok=True)
        (self.host_dir / "test.txt").write_text("sample")

        self.pcap_file = self.base_path / "test.pcap"
        self.pcap_file.write_bytes(b"\x00" * 24)

        self.mem_file = self.base_path / "mem.json"
        self.mem_file.write_text("[]")

        self.out_dir = self.base_path / "output_reports"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_config_instantiation(self):
        """Prove CaseConfig constructs cleanly with valid attributes."""
        cfg = CaseConfig(
            case_id="CASE-2026-X",
            case_name="Test Investigation",
            evidence_host_dir=self.host_dir,
            evidence_pcap_files=(self.pcap_file,),
            evidence_mem_files=(self.mem_file,),
            output_dir=self.out_dir,
        )
        self.assertEqual(cfg.case_id, "CASE-2026-X")
        self.assertTrue(cfg.has_evidence)
        self.assertEqual(len(cfg.all_evidence_paths), 3)
        validate_case_config(cfg)

    def test_missing_evidence_rejection(self):
        """Prove CaseConfig validation fails when no evidence inputs are declared."""
        cfg = CaseConfig(
            case_id="CASE-EMPTY",
            output_dir=self.out_dir,
        )
        self.assertFalse(cfg.has_evidence)
        with self.assertRaises(ValueError) as ctx:
            validate_case_config(cfg)
        self.assertIn("declare at least one evidence input", str(ctx.exception))

    def test_output_overlap_rejection(self):
        """Prove CaseConfig validation rejects output_dir overlapping host evidence dir."""
        inside_out = self.host_dir / "nested_reports"
        cfg = CaseConfig(
            evidence_host_dir=self.host_dir,
            output_dir=inside_out,
        )
        with self.assertRaises(ValueError) as ctx:
            validate_case_config(cfg)
        self.assertIn("Forensic safety violation", str(ctx.exception))

    def test_load_from_json_file_relative_paths(self):
        """Prove load_case_config_from_file resolves relative paths against config file directory."""
        config_path = self.base_path / "case.json"
        config_data = {
            "case_id": "REL-CASE-01",
            "case_name": "Relative Path Test",
            "evidence_host_dir": "host_ev",
            "evidence_pcap_files": ["test.pcap"],
            "evidence_mem_files": ["mem.json"],
            "output_dir": "output_reports",
            "report_formats": ["html", "json"],
            "overwrite": True,
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        cfg = load_case_config_from_file(config_path)
        self.assertEqual(cfg.case_id, "REL-CASE-01")
        self.assertEqual(cfg.evidence_host_dir, self.host_dir.resolve())
        self.assertEqual(cfg.evidence_pcap_files, (self.pcap_file.resolve(),))
        self.assertEqual(cfg.evidence_mem_files, (self.mem_file.resolve(),))
        self.assertEqual(cfg.output_dir, self.out_dir.resolve())
        self.assertTrue(cfg.overwrite)
        validate_case_config(cfg)

    def test_nonexistent_evidence_path_rejection(self):
        """Prove validation fails fast when configured path does not exist."""
        ghost_path = self.base_path / "ghost_host_dir"
        cfg = CaseConfig(
            evidence_host_dir=ghost_path,
            output_dir=self.out_dir,
        )
        with self.assertRaises(FileNotFoundError):
            validate_case_config(cfg)


if __name__ == "__main__":
    unittest.main()
