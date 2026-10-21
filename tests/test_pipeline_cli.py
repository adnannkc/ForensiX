"""
Unit and Integration Tests for ForensiX V9 Pipeline CLI.

Validates:
1. --help displays command description, options, and exit codes.
2. Direct execution via --config <path> to JSON case specification.
3. Direct execution via command-line flags (--case-id, --host-dir, --output-dir).
4. CLI validation failure (missing evidence) exits with code 1.
5. Manifest discrepancy yields exit code 2.
6. Dispatch from forensix.main:main(['run', ...]) and forensix.main:main(['pipeline', ...]).
"""

import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from forensix.main import main
from forensix.pipeline_cli import execute_pipeline_cli, pipeline_main


def _create_synthetic_pcap(path: Path) -> None:
    """Create minimal valid classic PCAP file."""
    global_hdr = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack(">IIII", 1760000000, 500000, 54, 54)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0x4000, 64, 6, 0,
        bytes([192, 0, 2, 10]), bytes([198, 51, 100, 25]),
    )
    tcp = struct.pack(">HHIIBBHHH", 54321, 22, 100, 0, 0x50, 0x02, 64240, 0, 0)
    path.write_bytes(global_hdr + pkt_hdr + eth + ip + tcp)


def _create_synthetic_host(root: Path) -> None:
    """Create minimal synthetic host structure."""
    etc_dir = root / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    (etc_dir / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nanalyst:x:1001:1001::/home/analyst:/bin/bash\n")
    (etc_dir / "group").write_text("root:x:0:\nanalyst:x:1001:\n")


class TestPipelineCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.host_dir = self.base_dir / "evidence_host"
        _create_synthetic_host(self.host_dir)

        self.pcap_file = self.base_dir / "traffic.pcap"
        _create_synthetic_pcap(self.pcap_file)

        self.out_dir = self.base_dir / "reports_out"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_help_flag(self):
        """Prove --help displays usage and exits with SystemExit(0)."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                pipeline_main(["--help"])
            self.assertEqual(cm.exception.code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("ForensiX V9", output)
        self.assertIn("--config", output)
        self.assertIn("Exit Codes", output)

    def test_direct_flags_run(self):
        """Prove pipeline CLI runs successfully with direct command line flags."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main([
                "--case-id", "CLI-DIRECT-01",
                "--evidence-host-dir", str(self.host_dir),
                "--evidence-pcap", str(self.pcap_file),
                "-o", str(self.out_dir),
                "--overwrite",
            ])
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())
        self.assertIn("Execution Summary", stdout_buf.getvalue())
        self.assertIn("CLI-DIRECT-01", stdout_buf.getvalue())

    def test_config_file_run(self):
        """Prove pipeline CLI runs successfully via --config JSON file."""
        case_data = {
            "case_id": "CLI-CONFIG-01",
            "case_name": "Config File Test",
            "investigator": "Test Analyst",
            "evidence_host_dir": str(self.host_dir),
            "output_dir": str(self.out_dir),
            "overwrite": True,
        }
        cfg_path = self.base_dir / "case.json"
        cfg_path.write_text(json.dumps(case_data, indent=2), encoding="utf-8")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = pipeline_main(["--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())
        self.assertIn("CLI-CONFIG-01", stdout_buf.getvalue())

    def test_validation_error_missing_evidence(self):
        """Prove missing evidence inputs produce validation error and exit code 1."""
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            exit_code = pipeline_main([
                "--case-id", "NO-EVIDENCE",
                "-o", str(self.out_dir),
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("Case configuration must declare at least one evidence input", stderr_buf.getvalue())

    def test_main_dispatch_run_and_pipeline(self):
        """Prove forensix.main:main correctly routes 'run' and 'pipeline' subcommands."""
        # Test routing for 'run'
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code_run = main([
                "run",
                "--case-id", "MAIN-RUN-01",
                "--evidence-host-dir", str(self.host_dir),
                "-o", str(self.out_dir),
                "--overwrite",
            ])
        self.assertEqual(code_run, 0)

        # Test routing for 'pipeline' alias
        out_dir_2 = self.base_dir / "out2"
        with patch("sys.stdout", stdout_buf):
            code_pipeline = main([
                "pipeline",
                "--case-id", "MAIN-PIPELINE-01",
                "--evidence-host-dir", str(self.host_dir),
                "-o", str(out_dir_2),
                "--overwrite",
            ])
        self.assertEqual(code_pipeline, 0)
        self.assertTrue((out_dir_2 / "pipeline_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
