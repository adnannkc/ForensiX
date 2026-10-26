"""
Unit and Integration Tests for ForensiX Case CLI (forensix case).

Validates:
1. --help lists all pipeline arguments plus --serve, -p/--port, and --host.
2. forensix.main:main dispatches 'case' subcommand cleanly.
3. case without --serve returns pipeline exit code (exit 0 on synthetic case).
4. case with --serve calls execute_dashboard_cli with resolved config.output_dir.
5. Exit 1 (config/validation error) skips dashboard invocation.
6. Exit 3 and Exit 4 skip dashboard invocation.
7. Exit 2 serves dashboard with required warning banner and preserves exit 2.
8. Non-loopback host (e.g. 0.0.0.0) is rejected, prints error, and returns pipeline exit code.
9. Dashboard registry ingests run folder without error, indexing reports and skipping ledger/manifest.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from forensix.case_cli import build_case_parser, case_main, execute_case_cli
from forensix.dashboard_service import DashboardReportRegistry
from forensix.main import main
from forensix.pipeline_engine import PipelineExecutionResult
from forensix.pipeline_models import (
    PipelineRunManifest,
    PipelineRunStatus,
)


class TestCaseCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.synth_case_config = Path("examples/case-synthetic/case.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_case_help_lists_serve_port_host(self):
        """Verify --help displays case description, options, and specifically --serve, --port, and --host."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                case_main(["--help"])
            self.assertEqual(cm.exception.code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("forensix case", output)
        self.assertIn("--serve", output)
        self.assertIn("--port", output)
        self.assertIn("-p", output)
        self.assertIn("--host", output)
        self.assertIn("--config", output)

    def test_main_routes_case(self):
        """Verify forensix.main:main correctly routes 'case' subcommand."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            with self.assertRaises(SystemExit) as cm:
                main(["case", "--help"])
            self.assertEqual(cm.exception.code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("forensix case", output)
        self.assertIn("--serve", output)

    def test_case_without_serve_returns_pipeline_code(self):
        """Verify case without --serve runs pipeline to completion and returns exit code 0."""
        out_dir = self.base_dir / "reports_no_serve"
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = case_main([
                "--config", str(self.synth_case_config),
                "-o", str(out_dir),
                "--overwrite",
            ])
        self.assertEqual(exit_code, 0)
        self.assertTrue((out_dir / "pipeline_manifest.json").exists())
        self.assertIn("Execution Summary", stdout_buf.getvalue())
        self.assertIn("CASE-2026-SYNTHETIC-001", stdout_buf.getvalue())

    def test_case_with_serve_calls_dashboard_on_resolved_output_dir(self):
        """Verify case with --serve calls dashboard targeting resolved output directory."""
        custom_out = self.base_dir / "custom_reports_dir"
        with patch("forensix.case_cli.execute_dashboard_cli", return_value=(0, None)) as mock_dash:
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                exit_code = execute_case_cli([
                    "--config", str(self.synth_case_config),
                    "-o", str(custom_out),
                    "--overwrite",
                    "--serve",
                    "-p", "9876",
                    "--host", "127.0.0.1",
                ], block=False)
            self.assertEqual(exit_code, 0)
            mock_dash.assert_called_once()
            dash_args = mock_dash.call_args[0][0]
            self.assertEqual(dash_args[0], str(custom_out))
            self.assertIn("--port", dash_args)
            self.assertEqual(dash_args[dash_args.index("--port") + 1], "9876")
            self.assertIn("--host", dash_args)
            self.assertEqual(dash_args[dash_args.index("--host") + 1], "127.0.0.1")

    def test_exit1_skips_serve(self):
        """Verify pipeline exit 1 (config/validation error) skips dashboard invocation."""
        with patch("forensix.case_cli.execute_dashboard_cli") as mock_dash:
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = execute_case_cli([
                    "--config", str(self.base_dir / "nonexistent.json"),
                    "--serve",
                ], block=False)
            self.assertEqual(exit_code, 1)
            mock_dash.assert_not_called()

    def test_exit3_and_exit4_skip_serve(self):
        """Verify pipeline exit 3 (custody failure) and exit 4 (I/O error) skip dashboard invocation."""
        dummy_manifest = PipelineRunManifest(
            run_id="RUN-TEST-FAILURE",
            forensix_version="9.0.0",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_duration_seconds=0.1,
            run_status=PipelineRunStatus.FAILURE.value,
        )

        for code in (3, 4):
            mock_result = PipelineExecutionResult(
                run_manifest=dummy_manifest,
                exit_code=code,
            )
            with patch("forensix.case_cli.run_pipeline", return_value=mock_result), \
                 patch("forensix.case_cli.execute_dashboard_cli") as mock_dash:
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    ret = execute_case_cli([
                        "--config", str(self.synth_case_config),
                        "-o", str(self.base_dir / f"out_{code}"),
                        "--overwrite",
                        "--serve",
                    ], block=False)
                self.assertEqual(ret, code)
                mock_dash.assert_not_called()

    def test_exit2_serves_with_banner(self):
        """Verify pipeline exit 2 (partial/verification discrepancy) prints required warning banner and invokes dashboard."""
        dummy_manifest = PipelineRunManifest(
            run_id="RUN-TEST-PARTIAL",
            forensix_version="9.0.0",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_duration_seconds=0.1,
            run_status=PipelineRunStatus.PARTIAL_SUCCESS.value,
        )
        mock_result = PipelineExecutionResult(
            run_manifest=dummy_manifest,
            exit_code=2,
        )

        with patch("forensix.case_cli.run_pipeline", return_value=mock_result), \
             patch("forensix.case_cli.execute_dashboard_cli", return_value=(0, None)) as mock_dash:
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                ret = execute_case_cli([
                    "--config", str(self.synth_case_config),
                    "-o", str(self.base_dir / "out_exit2"),
                    "--overwrite",
                    "--serve",
                ], block=False)
            self.assertEqual(ret, 2)
            mock_dash.assert_called_once()
            stdout_val = stdout_buf.getvalue()
            expected_banner = "Run finished with exit 2: partial results or manifest discrepancy. Read the run summary before relying on these findings."
            self.assertIn(expected_banner, stdout_val)

    def test_non_loopback_host_rejected(self):
        """Verify non-loopback host (e.g. 0.0.0.0) is rejected early, prints error, and returns 1."""
        out_dir = self.base_dir / "reports_bad_host"
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
            ret = execute_case_cli([
                "--config", str(self.synth_case_config),
                "-o", str(out_dir),
                "--overwrite",
                "--serve",
                "--host", "0.0.0.0",
            ], block=False)
        self.assertEqual(ret, 1)
        stderr_val = stderr_buf.getvalue()
        self.assertIn("ForensiX dashboard can only bind to loopback", stderr_val)
        self.assertIn("0.0.0.0", stderr_val)

    def test_case_bad_host_fails_before_run(self):
        """Verify --serve --host 0.0.0.0 returns 1, and run_pipeline is not called."""
        out_dir = self.base_dir / "reports_bad_host_early"
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf), patch("forensix.case_cli.run_pipeline") as mock_run:
            ret = execute_case_cli([
                "--config", str(self.synth_case_config),
                "-o", str(out_dir),
                "--overwrite",
                "--serve",
                "--host", "0.0.0.0",
            ], block=False)
        self.assertEqual(ret, 1)
        mock_run.assert_not_called()
        stderr_val = stderr_buf.getvalue()
        self.assertIn("ForensiX dashboard can only bind to loopback", stderr_val)
        self.assertIn("0.0.0.0", stderr_val)

    def test_dashboard_ingests_run_folder_without_error(self):
        """Verify dashboard registry ingests pipeline run output folder cleanly, indexing reports and skipping ledger and manifest."""
        out_dir = self.base_dir / "reports_ingest"
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = case_main([
                "--config", str(self.synth_case_config),
                "-o", str(out_dir),
                "--overwrite",
            ])
        self.assertEqual(exit_code, 0)

        registry = DashboardReportRegistry()
        # Ingest directory without raising any exceptions
        registry.register_directory(out_dir, recursive=False)

        # Custody ledger and manifest are recorded as skipped files with a reason
        skipped_filenames = [item["filename"] for item in registry.skipped_reports]
        self.assertTrue(any("ledger" in fn for fn in skipped_filenames))
        self.assertTrue(any("pipeline_manifest" in fn for fn in skipped_filenames))
        for item in registry.skipped_reports:
            self.assertTrue(len(str(item["reason"])) > 0)


if __name__ == "__main__":
    unittest.main()
