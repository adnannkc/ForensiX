"""
Unit test suite for ForensiX V6.1 Volatility Subprocess Adapter (volatility_adapter.py).

Validates:
1. Missing executable handling (clean VolatilityNotFoundError, unexecuted provenance).
2. Explicit executable override and precedence (explicit > FORENSIX_VOLATILITY_BIN > PATH).
3. Candidate resolution in PATH (vol3, volatility3, vol).
4. Safe environment handling and HOME directory preservation:
   - Preserves valid, existing HOME directory.
   - Omits HOME when unset (does not fall back to /tmp).
   - Omits HOME when set to non-existent or relative paths.
5. Exact argument list recording and redaction:
   - Full command constructed first.
   - Recorded arguments match actual invocation tokens (including -s, --offline, plugin args).
   - Sensitive flags (--password, etc.) redacted in provenance without altering real execution.
6. Bounded output policy enforcement:
   - Validates max_output_bytes configuration.
   - Actively bounds output reading; terminates process when output exceeds byte limit.
   - Preserves legitimate output within configured limits.
7. Timeout handling and timeout provenance recording.
8. Non-zero exit code classification (general failure, missing symbols, unsupported plugins).
   - Unrecognized argument errors are not misclassified as unsupported plugins.
9. JSON parsing contracts (valid list of rows, valid table dict with rows).
10. Legitimate empty result preservation (valid JSON with zero rows []).
11. Malformed JSON and unexpected schema rejection.
12. Diagnostic snippet truncation and sanitization.
13. Strict isolation: no network calls, no requirement for installed Volatility package.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from forensix.memory_models import (
    VolatilityExecutionStatus,
)
from forensix.volatility_adapter import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    VOLATILITY_BIN_ENV_VAR,
    VolatilityAdapter,
    VolatilityError,
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityNotFoundError,
    VolatilityOutputLimitExceededError,
    VolatilityParseError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
    _classify_execution_failure,
    _run_subprocess_bounded,
    build_sanitized_environment,
    execute_volatility_plugin,
    parse_volatility_json,
    resolve_volatility_binary,
    sanitize_cli_arguments,
    sanitize_diagnostic_snippet,
    redact_sensitive_text,
)


class TestVolatilityAdapter(unittest.TestCase):
    """Test suite for VolatilityAdapter and associated utilities."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        # Create a synthetic memory image file
        self.synthetic_mem = self.temp_dir_path / "test_memory.raw"
        self.synthetic_mem.write_bytes(b"\x00\x01\x02\x03" * 1024)

        # Create a synthetic fake executable script
        self.fake_vol_bin = self.temp_dir_path / "fake_vol3"
        self.fake_vol_bin.write_text("#!/bin/sh\necho '[]'\n")
        self.fake_vol_bin.chmod(0o755)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Executable Resolution & Precedence
    # -------------------------------------------------------------------------

    def test_missing_executable_raises_not_found(self):
        """When no binary is specified, env is empty, and PATH has no candidates, fail cleanly."""
        with patch("shutil.which", return_value=None), patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(VolatilityNotFoundError) as ctx:
                resolve_volatility_binary()
            self.assertIn("Volatility executable not found", str(ctx.exception))

    def test_run_plugin_missing_executable_captures_unexecuted_provenance(self):
        """When executable is not found, adapter records executed=False and status=ERROR."""
        adapter = VolatilityAdapter(vol_bin="/nonexistent/path/vol3")
        with self.assertRaises(VolatilityNotFoundError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        rec = ctx.exception.execution_record
        self.assertIsNotNone(rec)
        self.assertFalse(rec.executed)
        self.assertEqual(rec.status, VolatilityExecutionStatus.ERROR.value)
        self.assertIsNone(rec.exit_code)
        self.assertEqual(rec.error.error_type, "EXECUTABLE_NOT_FOUND")

    def test_explicit_override_precedence(self):
        """Explicit path override takes precedence over FORENSIX_VOLATILITY_BIN and PATH."""
        env_fake = self.temp_dir_path / "env_vol"
        env_fake.write_text("#!/bin/sh\n")
        env_fake.chmod(0o755)

        with patch.dict("os.environ", {VOLATILITY_BIN_ENV_VAR: str(env_fake)}), \
             patch("shutil.which", return_value="/usr/bin/vol3"):
            resolved = resolve_volatility_binary(explicit_path=self.fake_vol_bin)
            self.assertEqual(resolved, self.fake_vol_bin.resolve())

    def test_env_var_precedence_over_path(self):
        """FORENSIX_VOLATILITY_BIN takes precedence over candidates found in PATH."""
        env_fake = self.temp_dir_path / "env_vol"
        env_fake.write_text("#!/bin/sh\n")
        env_fake.chmod(0o755)

        with patch.dict("os.environ", {VOLATILITY_BIN_ENV_VAR: str(env_fake)}), \
             patch("shutil.which", return_value="/usr/bin/vol3"):
            resolved = resolve_volatility_binary(explicit_path=None)
            self.assertEqual(resolved, env_fake.resolve())

    def test_candidate_resolution_order_in_path(self):
        """Candidates in PATH are resolved in candidate order ('vol3', 'volatility3')."""
        def fake_which(cmd: str):
            if cmd == "vol3":
                return str(self.fake_vol_bin)
            return None

        with patch.dict("os.environ", {}, clear=True), patch("shutil.which", side_effect=fake_which):
            resolved = resolve_volatility_binary()
            self.assertEqual(resolved, self.fake_vol_bin.resolve())

    def test_ambiguous_vol_binary_not_automatically_selected(self):
        """An ambiguous 'vol' executable in PATH is NOT selected automatically."""
        fake_vol2 = self.temp_dir_path / "vol"
        fake_vol2.write_text("#!/bin/sh\n")
        fake_vol2.chmod(0o755)

        def fake_which(cmd: str):
            if cmd == "vol":
                return str(fake_vol2)
            return None

        with patch.dict("os.environ", {}, clear=True), patch("shutil.which", side_effect=fake_which):
            with self.assertRaises(VolatilityNotFoundError) as ctx:
                resolve_volatility_binary()
            self.assertIn("Volatility executable not found", str(ctx.exception))

    def test_custom_executable_vol_preserved_when_explicitly_configured(self):
        """Explicit programmatic override or environment variable targeting 'vol' is preserved."""
        fake_vol = self.temp_dir_path / "vol"
        fake_vol.write_text("#!/bin/sh\n")
        fake_vol.chmod(0o755)

        # 1. Explicit path parameter
        resolved = resolve_volatility_binary(explicit_path=fake_vol)
        self.assertEqual(resolved, fake_vol.resolve())

        # 2. Environment variable
        with patch.dict("os.environ", {VOLATILITY_BIN_ENV_VAR: str(fake_vol)}):
            resolved_env = resolve_volatility_binary()
            self.assertEqual(resolved_env, fake_vol.resolve())

    def test_non_executable_or_directory_rejected(self):
        """Directory or non-executable file as explicit path is rejected."""
        not_exec = self.temp_dir_path / "not_exec.txt"
        not_exec.write_text("plain file")
        not_exec.chmod(0o644)

        with self.assertRaises(VolatilityNotFoundError):
            resolve_volatility_binary(explicit_path=not_exec)

        with self.assertRaises(VolatilityNotFoundError):
            resolve_volatility_binary(explicit_path=self.temp_dir_path)

    # -------------------------------------------------------------------------
    # 2. Controlled Environment & HOME Preservation (Fix A)
    # -------------------------------------------------------------------------

    def test_home_preserved_when_set_and_valid(self):
        """When HOME is set to an existing absolute directory, it is preserved in environment."""
        valid_home = self.temp_dir_path / "user_home"
        valid_home.mkdir()

        with patch.dict("os.environ", {"HOME": str(valid_home), "API_KEY": "secret"}, clear=True):
            env = build_sanitized_environment()
            self.assertEqual(env["HOME"], str(valid_home.resolve()))
            self.assertIn("PATH", env)
            self.assertIn("LANG", env)
            # Secrets strictly excluded
            self.assertNotIn("API_KEY", env)

    def test_home_omitted_when_unset(self):
        """When HOME is unset, it is omitted and does NOT fall back to /tmp."""
        with patch.dict("os.environ", {}, clear=True):
            env = build_sanitized_environment()
            self.assertNotIn("HOME", env)

    def test_home_omitted_when_invalid(self):
        """When HOME is relative or points to a non-existent directory, it is omitted."""
        # Non-existent directory
        with patch.dict("os.environ", {"HOME": "/nonexistent/fake/dir/xyz"}, clear=True):
            env = build_sanitized_environment()
            self.assertNotIn("HOME", env)

        # Relative path
        with patch.dict("os.environ", {"HOME": "relative/path"}, clear=True):
            env = build_sanitized_environment()
            self.assertNotIn("HOME", env)

    # -------------------------------------------------------------------------
    # 3. Exact Argument List Recording & Redaction (Fix B)
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_recorded_arguments_match_actual_invocation_with_redaction(self, mock_run: MagicMock):
        """Recorded arguments in execution record match actual invocation after redaction."""
        mock_run.return_value = (0, b"[]", b"")

        sym_dir = self.temp_dir_path / "symbols"
        sym_dir.mkdir()

        adapter = VolatilityAdapter(
            vol_bin=self.fake_vol_bin,
            symbol_dir=sym_dir,
            offline=True,
        )

        result = adapter.run_plugin(
            self.synthetic_mem,
            "linux.pslist.PsList",
            plugin_args=["--password", "secret123", "--pid", "100"],
        )

        self.assertGreaterEqual(mock_run.call_count, 1)
        cmd = mock_run.call_args_list[-1][1]["cmd"]

        # 1. Verify actual command line passed to subprocess contains all real values unredacted
        self.assertEqual(cmd[0], str(self.fake_vol_bin.resolve()))
        self.assertIn("-f", cmd)
        self.assertIn(str(self.synthetic_mem.resolve()), cmd)
        self.assertIn("-r", cmd)
        self.assertIn("json", cmd)
        self.assertIn("-s", cmd)
        self.assertIn(str(sym_dir.resolve()), cmd)
        self.assertIn("--offline", cmd)
        self.assertIn("linux.pslist.PsList", cmd)
        self.assertIn("--password", cmd)
        self.assertIn("secret123", cmd)  # Real secret passed to process
        self.assertIn("--pid", cmd)
        self.assertIn("100", cmd)

        # 2. Verify recorded sanitized_args matches cmd[1:] with secrets redacted
        rec = result.execution_record
        expected_sanitized = (
            "-f",
            str(self.synthetic_mem.resolve()),
            "-r",
            "json",
            "-s",
            str(sym_dir.resolve()),
            "--offline",
            "linux.pslist.PsList",
            "--password",
            "[REDACTED]",
            "--pid",
            "100",
        )
        self.assertEqual(rec.sanitized_args, expected_sanitized)

    def test_plugin_name_injection_prevention(self):
        """Plugin names with shell characters or spaces are rejected."""
        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)

        malicious_plugins = [
            "linux.pslist; cat /etc/passwd",
            "linux.pslist | grep root",
            "linux.pslist && echo evil",
            "plugin $(whoami)",
            "plugin`id`",
            "",
            "   ",
        ]
        for bad_plugin in malicious_plugins:
            with self.assertRaises(ValueError):
                adapter.run_plugin(self.synthetic_mem, bad_plugin)

    def test_argument_redaction_rule_coverage(self):
        """Sensitive argument flags and key=val pairs are redacted across formats and naming variants."""
        secrets = [
            "SecretPassSeparate",
            "SecretPassInline",
            "ApiKeySeparateHyphen",
            "ApiKeyInlineHyphen",
            "ApiKeySeparateUnder",
            "ApiKeyInlineUnder",
            "AccessTokenSeparate",
            "AccessTokenInline",
            "ClientSecretSeparate",
            "ClientSecretInline",
            "SecretKeySeparate",
            "AuthTokenSeparate",
            "KeyValSeparate",
            "TokenValInline",
        ]

        args = [
            "-f", "mem.raw",
            # Separate forms
            "--password", "SecretPassSeparate",
            "--api-key", "ApiKeySeparateHyphen",
            "--api_key", "ApiKeySeparateUnder",
            "--access-token", "AccessTokenSeparate",
            "--client-secret", "ClientSecretSeparate",
            "--secret-key", "SecretKeySeparate",
            "--auth-token", "AuthTokenSeparate",
            "--key", "KeyValSeparate",
            # Inline forms
            "--password=SecretPassInline",
            "--api-key=ApiKeyInlineHyphen",
            "--api_key=ApiKeyInlineUnder",
            "--access-token=AccessTokenInline",
            "--client-secret=ClientSecretInline",
            "--token=TokenValInline",
            # Non-sensitive arguments that must remain unredacted
            "--keyboard", "us",
            "--key-file", "/etc/ssl/key.pem",
            "--primary-key=id",
            "--sort-key", "pid",
            "--keyring", "default",
            "--token-type=bearer",
            "--normal", "value",
        ]
        sanitized = sanitize_cli_arguments(args)

        # 1. Assert none of the secret strings appear in sanitized output
        for secret in secrets:
            self.assertNotIn(secret, sanitized, f"Secret '{secret}' was not redacted!")

        # 2. Assert redacted markers are present
        self.assertIn("[REDACTED]", sanitized)
        self.assertIn("--password=[REDACTED]", sanitized)
        self.assertIn("--api-key=[REDACTED]", sanitized)
        self.assertIn("--api_key=[REDACTED]", sanitized)
        self.assertIn("--access-token=[REDACTED]", sanitized)
        self.assertIn("--client-secret=[REDACTED]", sanitized)
        self.assertIn("--token=[REDACTED]", sanitized)

        # 3. Assert ordinary arguments are preserved untouched
        self.assertIn("-f", sanitized)
        self.assertIn("mem.raw", sanitized)
        self.assertIn("--keyboard", sanitized)
        self.assertIn("us", sanitized)
        self.assertIn("--key-file", sanitized)
        self.assertIn("/etc/ssl/key.pem", sanitized)
        self.assertIn("--primary-key=id", sanitized)
        self.assertIn("--sort-key", sanitized)
        self.assertIn("pid", sanitized)
        self.assertIn("--keyring", sanitized)
        self.assertIn("default", sanitized)
        self.assertIn("--token-type=bearer", sanitized)
        self.assertIn("--normal", sanitized)
        self.assertIn("value", sanitized)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_actual_subprocess_arguments_remain_unredacted_while_provenance_redacted(self, mock_run: MagicMock):
        """Subprocess command contains real arguments unredacted, while provenance record is redacted."""
        mock_run.return_value = (0, b"[]", b"")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        result = adapter.run_plugin(
            self.synthetic_mem,
            "linux.pslist",
            plugin_args=[
                "--password", "RealSecretPass1",
                "--api-key=RealSecretApiKey2",
                "--client-secret", "RealClientSecret3",
                "--access-token=RealAccessToken4",
                "--keyboard", "us",
                "--sort-key", "pid",
            ],
        )

        # 1. Actual subprocess cmd retains unredacted values
        actual_cmd = mock_run.call_args[1]["cmd"]
        self.assertIn("RealSecretPass1", actual_cmd)
        self.assertIn("--api-key=RealSecretApiKey2", actual_cmd)
        self.assertIn("RealClientSecret3", actual_cmd)
        self.assertIn("--access-token=RealAccessToken4", actual_cmd)
        self.assertIn("--keyboard", actual_cmd)
        self.assertIn("us", actual_cmd)
        self.assertIn("--sort-key", actual_cmd)
        self.assertIn("pid", actual_cmd)

        # 2. Recorded provenance in execution_record has secrets redacted
        sanitized = result.execution_record.sanitized_args
        self.assertNotIn("RealSecretPass1", sanitized)
        self.assertNotIn("RealSecretApiKey2", sanitized)
        self.assertNotIn("RealClientSecret3", sanitized)
        self.assertNotIn("RealAccessToken4", sanitized)
        self.assertIn("--password", sanitized)
        self.assertIn("[REDACTED]", sanitized)
        self.assertIn("--api-key=[REDACTED]", sanitized)
        self.assertIn("--client-secret", sanitized)
        self.assertIn("--access-token=[REDACTED]", sanitized)
        # Non-sensitive arguments preserved
        self.assertIn("--keyboard", sanitized)
        self.assertIn("us", sanitized)
        self.assertIn("--sort-key", sanitized)
        self.assertIn("pid", sanitized)

    def test_argument_redaction_edge_cases_and_missing_values(self):
        """Harden against missing values, consecutive options, and dash-prefixed credential values."""
        # 1. Sensitive flag followed immediately by another long option (missing value)
        res1 = sanitize_cli_arguments(["--password", "--offline"])
        self.assertEqual(res1, ("--password", "--offline"))

        # 2. Sensitive flag at the end of the argument list (missing value)
        res2 = sanitize_cli_arguments(["--api-key"])
        self.assertEqual(res2, ("--api-key",))

        # 3. Sensitive flag followed by an unrelated option and ordinary value
        res3 = sanitize_cli_arguments(["--client-secret", "--some-option", "ordinary-value"])
        self.assertEqual(res3, ("--client-secret", "--some-option", "ordinary-value"))

        # 4. Legitimate credential value that begins with '-' (single dash)
        secret_dash1 = "-SecretBeginningWithDash"
        res4 = sanitize_cli_arguments(["--password", secret_dash1])
        self.assertEqual(res4, ("--password", "[REDACTED]"))
        self.assertNotIn(secret_dash1, res4)

        # 5. Dash-prefixed credential followed by an unrelated option
        secret_dash2 = "-p@ss-with-dash"
        res5 = sanitize_cli_arguments(["--password", secret_dash2, "--offline"])
        self.assertEqual(res5, ("--password", "[REDACTED]", "--offline"))
        self.assertNotIn(secret_dash2, res5)

        # 6. Multiple dash-prefixed credentials across different flags
        secret_key1 = "-123456"
        secret_key2 = "-MySecretKey"
        res6 = sanitize_cli_arguments(["--api-key", secret_key1, "--client-secret", secret_key2])
        self.assertEqual(res6, ("--api-key", "[REDACTED]", "--client-secret", "[REDACTED]"))
        self.assertNotIn(secret_key1, res6)
        self.assertNotIn(secret_key2, res6)

        # 7. Sensitive flag followed by a known short option flag (-f)
        res7 = sanitize_cli_arguments(["--password", "-f", "mem.raw"])
        self.assertEqual(res7, ("--password", "-f", "mem.raw"))

        # 8. Consecutive sensitive flags where the first is missing a value
        secret_val = "validSecret123"
        res8 = sanitize_cli_arguments(["--password", "--api-key", secret_val])
        self.assertEqual(res8, ("--password", "--api-key", "[REDACTED]"))
        self.assertNotIn(secret_val, res8)

        # 9. Inline assignment containing a dash-prefixed credential value
        secret_inline = "-DashSecretInline"
        res9 = sanitize_cli_arguments([f"--password={secret_inline}"])
        self.assertEqual(res9, ("--password=[REDACTED]",))
        self.assertNotIn(secret_inline, res9)

    # -------------------------------------------------------------------------
    # Working Directory Hardening (Finding 1)
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_run_plugin_default_cwd_is_not_evidence_directory(self, mock_run: MagicMock):
        """Default subprocess cwd must be tempfile.gettempdir(), never the evidence directory."""
        mock_run.return_value = (0, b"[]", b"")

        # Put synthetic memory in an isolated directory
        evidence_dir = self.temp_dir_path / "evidence_vault"
        evidence_dir.mkdir()
        mem_file = evidence_dir / "target_ram.raw"
        mem_file.write_bytes(b"\x00" * 1024)

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        adapter.run_plugin(mem_file, "linux.pslist")

        self.assertGreaterEqual(mock_run.call_count, 1)
        actual_cwd = mock_run.call_args[1]["cwd"]

        # Assert actual_cwd is NOT the evidence directory
        self.assertNotEqual(actual_cwd, str(evidence_dir.resolve()))
        self.assertNotEqual(actual_cwd, str(evidence_dir))
        # Assert actual_cwd is tempfile.gettempdir()
        self.assertEqual(actual_cwd, tempfile.gettempdir())

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_run_plugin_custom_cwd_honored(self, mock_run: MagicMock):
        """When an explicit cwd is passed to VolatilityAdapter, it is used instead of tempdir."""
        mock_run.return_value = (0, b"[]", b"")
        custom_cwd = self.temp_dir_path / "controlled_working_dir"
        custom_cwd.mkdir()

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin, cwd=custom_cwd)
        adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        self.assertGreaterEqual(mock_run.call_count, 1)
        actual_cwd = mock_run.call_args[1]["cwd"]
        self.assertEqual(actual_cwd, str(custom_cwd.resolve()))

    def test_invalid_cwd_rejected(self):
        """Non-existent or non-directory cwd raises ValueError."""
        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, cwd="/nonexistent/dir/path")
        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, cwd=self.synthetic_mem)

    # -------------------------------------------------------------------------
    # 4. Bounded Output Policy Enforcement (Fix C)
    # -------------------------------------------------------------------------

    def test_max_output_bytes_validation(self):
        """max_output_bytes must be a positive integer."""
        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, max_output_bytes=-10)

        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, max_output_bytes=0)

        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, max_output_bytes="100MB")  # type: ignore

        with self.assertRaises(ValueError):
            VolatilityAdapter(vol_bin=self.fake_vol_bin, max_output_bytes=True)  # type: ignore

    def test_real_subprocess_bounded_output_kills_process_on_overflow(self):
        """_run_subprocess_bounded terminates process immediately when output exceeds limit."""
        # Use python to generate 200 KB of data while limit is set to 4 KB
        cmd = [
            "python3",
            "-c",
            "import sys, time; sys.stdout.write('A' * 200000); sys.stdout.flush(); time.sleep(5)",
        ]
        with self.assertRaises(VolatilityOutputLimitExceededError):
            _run_subprocess_bounded(
                cmd=cmd,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                cwd=self.temp_dir.name,
                timeout=5.0,
                max_output_bytes=4096,  # 4 KB limit
            )

    def test_real_subprocess_cumulative_output_limit_across_both_streams(self):
        """Neither stdout nor stderr alone exceeds limit, but combined sum triggers immediate kill."""
        # Limit is 4000 bytes.
        # stdout writes 2500 bytes (< 4000).
        # stderr writes 2500 bytes (< 4000).
        # Total combined = 5000 bytes (> 4000).
        cmd = [
            "python3",
            "-c",
            "import sys, time; "
            "sys.stdout.write('O' * 2500); sys.stdout.flush(); "
            "sys.stderr.write('E' * 2500); sys.stderr.flush(); "
            "time.sleep(5)",
        ]
        with self.assertRaises(VolatilityOutputLimitExceededError) as ctx:
            _run_subprocess_bounded(
                cmd=cmd,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                cwd=self.temp_dir.name,
                timeout=5.0,
                max_output_bytes=4000,
            )
        self.assertIn("combined output exceeded maximum allowed limit", str(ctx.exception))

    def test_real_subprocess_output_within_limit_succeeds(self):
        """Output under cumulative limit is read cleanly without error."""
        cmd = [
            "python3",
            "-c",
            "import sys; sys.stdout.write('hello'); sys.stderr.write('world')",
        ]
        code, out, err = _run_subprocess_bounded(
            cmd=cmd,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            cwd=self.temp_dir.name,
            timeout=5.0,
            max_output_bytes=4000,
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, b"hello")
        self.assertEqual(err, b"world")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_run_plugin_records_output_limit_exceeded_provenance(self, mock_run: MagicMock):
        """Output limit violation captures ERROR status and OUTPUT_LIMIT_EXCEEDED provenance."""
        mock_run.side_effect = VolatilityOutputLimitExceededError("Output exceeded limit of 1024 bytes")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin, max_output_bytes=1024)

        with self.assertRaises(VolatilityOutputLimitExceededError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        rec = ctx.exception.execution_record
        self.assertIsNotNone(rec)
        self.assertTrue(rec.executed)
        self.assertEqual(rec.status, VolatilityExecutionStatus.ERROR.value)
        self.assertEqual(rec.error.error_type, "OUTPUT_LIMIT_EXCEEDED")

    # -------------------------------------------------------------------------
    # 5. Timeout Handling
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_timeout_handling(self, mock_run: MagicMock):
        """Timeout raises VolatilityTimeoutError and creates execution record with status=TIMEOUT."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["vol3"], timeout=2.0)

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin, timeout=2.0)

        with self.assertRaises(VolatilityTimeoutError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        rec = ctx.exception.execution_record
        self.assertIsNotNone(rec)
        self.assertTrue(rec.executed)
        self.assertEqual(rec.status, VolatilityExecutionStatus.TIMEOUT.value)
        self.assertIsNone(rec.exit_code)
        self.assertEqual(rec.error.error_type, "TIMEOUT")

    # -------------------------------------------------------------------------
    # 6. Non-Zero Exit & Error Classification
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_non_zero_exit_general_failure(self, mock_run: MagicMock):
        """Non-zero exit without specific signatures raises VolatilityExecutionFailureError."""
        mock_run.return_value = (1, b"", b"Internal core memory fault occurred")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityExecutionFailureError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        self.assertEqual(ctx.exception.exit_code, 1)
        rec = ctx.exception.execution_record
        self.assertEqual(rec.status, VolatilityExecutionStatus.FAILED.value)
        self.assertEqual(rec.exit_code, 1)
        self.assertEqual(rec.error.error_type, "EXECUTION_FAILURE")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_missing_symbols_classification(self, mock_run: MagicMock):
        """Stderr mentioning unsatisfied symbol table requirements raises VolatilityMissingSymbolsError."""
        stderr_msg = b"Volatility 3 framework error: Symbol table requirement not satisfied: linux.elf.symbols"
        mock_run.return_value = (1, b"", stderr_msg)

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        rec = ctx.exception.execution_record
        self.assertEqual(rec.status, VolatilityExecutionStatus.FAILED.value)
        self.assertEqual(rec.error.error_type, "MISSING_SYMBOLS")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_unsupported_plugin_classification(self, mock_run: MagicMock):
        """Stderr indicating an unknown plugin raises VolatilityUnsupportedPluginError."""
        mock_run.return_value = (2, b"", b"Error: Plugin not found: linux.nonexistent")
        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityUnsupportedPluginError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.nonexistent")

        rec = ctx.exception.execution_record
        self.assertEqual(rec.error.error_type, "UNSUPPORTED_PLUGIN")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_unrecognized_argument_not_misclassified_as_unsupported_plugin(self, mock_run: MagicMock):
        """Unrecognized CLI arguments are classified as EXECUTION_FAILURE, not UNSUPPORTED_PLUGIN."""
        mock_run.return_value = (2, b"", b"vol.py: error: unrecognized arguments: --pidd 100")
        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)

        with self.assertRaises(VolatilityExecutionFailureError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        # Must not be VolatilityUnsupportedPluginError
        self.assertNotIsInstance(ctx.exception, VolatilityUnsupportedPluginError)
        rec = ctx.exception.execution_record
        self.assertEqual(rec.error.error_type, "EXECUTION_FAILURE")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_non_zero_exit_general_failure_redacts_diagnostic_secrets_in_stderr_and_stdout(self, mock_run: MagicMock):
        """Non-zero exit containing secrets in stderr/stdout redacts them across all error reporting surfaces."""
        secrets = ["SuperSecret123", "ApiSecret456", "BareSecret789"]
        stderr_output = (
            b"vol.py: error: execution failed with --password=SuperSecret123\n"
            b"Traceback (most recent call last):\n"
            b"  File 'vol.py', line 42, in run\n"
            b"    connect(user='admin', password='BareSecret789')\n"
        )
        stdout_output = b"Diagnostic debug: --api-key ApiSecret456\n"
        mock_run.return_value = (1, stdout_output, stderr_output)

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityExecutionFailureError) as ctx:
            adapter.run_plugin(
                self.synthetic_mem,
                "linux.pslist",
                plugin_args=["--password", "SuperSecret123", "--api-key", "ApiSecret456"],
            )

        exc = ctx.exception
        rec = exc.execution_record
        self.assertIsNotNone(rec)
        self.assertEqual(rec.status, VolatilityExecutionStatus.FAILED.value)
        self.assertEqual(rec.error.error_type, "EXECUTION_FAILURE")

        # 1. Unredacted arguments passed to real subprocess invocation
        actual_cmd = mock_run.call_args[1]["cmd"]
        self.assertIn("SuperSecret123", actual_cmd)
        self.assertIn("ApiSecret456", actual_cmd)

        # 2. Assert each secret is absent from all 4 required surfaces
        for secret in secrets:
            self.assertNotIn(secret, rec.error.error_message, f"Secret '{secret}' leaked in error_message!")
            self.assertNotIn(secret, str(exc), f"Secret '{secret}' leaked in str(exception)!")
            self.assertNotIn(secret, exc.stderr_snippet, f"Secret '{secret}' leaked in stderr_snippet!")
            self.assertNotIn(secret, rec.to_json(), f"Secret '{secret}' leaked in to_json()!")

        # 3. Assert redaction markers and non-sensitive diagnostic context are preserved
        self.assertIn("[REDACTED]", rec.error.error_message)
        self.assertIn("[REDACTED]", str(exc))
        self.assertIn("[REDACTED]", exc.stderr_snippet)
        self.assertIn("[REDACTED]", rec.to_json())
        self.assertIn("Volatility execution failed with exit code 1", rec.error.error_message)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_non_zero_exit_recognized_failure_missing_symbols_redacts_secrets(self, mock_run: MagicMock):
        """Recognized MISSING_SYMBOLS failure redacts credentials while preserving classification and error context."""
        secrets = ["SuperSecret123", "ApiSecret456", "BareSecret789"]
        stderr_output = (
            b"Volatility 3 framework error: Symbol table requirement not satisfied: linux.elf.symbols\n"
            b"Invocation context: --password=SuperSecret123 --api-key ApiSecret456 password='BareSecret789'\n"
        )
        mock_run.return_value = (1, b"", stderr_output)

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        exc = ctx.exception
        rec = exc.execution_record
        self.assertIsNotNone(rec)
        self.assertEqual(rec.error.error_type, "MISSING_SYMBOLS")

        # Assert each secret is absent from all 4 required surfaces
        for secret in secrets:
            self.assertNotIn(secret, rec.error.error_message, f"Secret '{secret}' leaked in error_message!")
            self.assertNotIn(secret, str(exc), f"Secret '{secret}' leaked in str(exception)!")
            self.assertNotIn(secret, exc.stderr_snippet, f"Secret '{secret}' leaked in stderr_snippet!")
            self.assertNotIn(secret, rec.to_json(), f"Secret '{secret}' leaked in to_json()!")

        # Preserves symbol table diagnostic context and classification
        self.assertIn("Symbol table requirement not satisfied", rec.error.error_message)
        self.assertIn("linux.elf.symbols", rec.error.error_message)
        self.assertIn("[REDACTED]", rec.error.error_message)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_non_zero_exit_recognized_failure_unsupported_plugin_redacts_stdout_secrets(self, mock_run: MagicMock):
        """Recognized UNSUPPORTED_PLUGIN failure emitted on stdout redacts credentials across all surfaces."""
        secrets = ["SuperSecret123", "ApiSecret456", "BareSecret789"]
        stdout_output = (
            b"vol.py: error: unrecognized plugin 'linux.malicious'\n"
            b"Supplied arguments: --password=SuperSecret123 --api-key ApiSecret456 password='BareSecret789'\n"
        )
        mock_run.return_value = (2, stdout_output, b"")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityUnsupportedPluginError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        exc = ctx.exception
        rec = exc.execution_record
        self.assertIsNotNone(rec)
        self.assertEqual(rec.error.error_type, "UNSUPPORTED_PLUGIN")

        # Assert each secret is absent from all 4 required surfaces
        for secret in secrets:
            self.assertNotIn(secret, rec.error.error_message, f"Secret '{secret}' leaked in error_message!")
            self.assertNotIn(secret, str(exc), f"Secret '{secret}' leaked in str(exception)!")
            self.assertNotIn(secret, exc.stderr_snippet, f"Secret '{secret}' leaked in stderr_snippet!")
            self.assertNotIn(secret, rec.to_json(), f"Secret '{secret}' leaked in to_json()!")

        # Preserves plugin diagnostic context and classification
        self.assertIn("unrecognized plugin", rec.error.error_message)
        self.assertIn("[REDACTED]", rec.error.error_message)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_diagnostic_source_selection_missing_symbol_stdout_with_whitespace_stderr(self, mock_run: MagicMock):
        """Missing-symbol failure in stdout is selected when stderr contains only whitespace."""
        stdout_text = "Volatility 3 framework error: Symbol table requirement not satisfied: linux.elf.symbols --password=SuperSecret123"
        stderr_text = "   \n\t  "
        mock_run.return_value = (1, stdout_text.encode("utf-8"), stderr_text.encode("utf-8"))

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        exc = ctx.exception
        rec = exc.execution_record
        self.assertEqual(rec.error.error_type, "MISSING_SYMBOLS")
        # Diagnostic source must be stdout
        self.assertIn("Symbol table requirement not satisfied: linux.elf.symbols", rec.error.error_message)
        self.assertIn("Symbol table requirement not satisfied: linux.elf.symbols", exc.stderr_snippet)
        # Secret must be redacted
        self.assertNotIn("SuperSecret123", rec.error.error_message)
        self.assertNotIn("SuperSecret123", str(exc))
        self.assertNotIn("SuperSecret123", exc.stderr_snippet)
        self.assertNotIn("SuperSecret123", rec.to_json())
        self.assertIn("[REDACTED]", rec.error.error_message)

        # Also verify direct unit classification
        exc_cls, err_type, err_msg = _classify_execution_failure(1, stdout_text, stderr_text)
        self.assertIs(exc_cls, VolatilityMissingSymbolsError)
        self.assertEqual(err_type, "MISSING_SYMBOLS")
        self.assertIn("Symbol table requirement not satisfied: linux.elf.symbols", err_msg)
        self.assertNotIn("SuperSecret123", err_msg)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_diagnostic_source_selection_unsupported_plugin_stdout_with_unrelated_stderr(self, mock_run: MagicMock):
        """Unsupported-plugin failure in stdout is selected even when stderr has unrelated non-empty text."""
        stdout_text = "vol.py: error: unrecognized plugin 'linux.pslist_fake' --api-key ApiSecret456"
        stderr_text = "Unrelated warning: cache directory not found on host system\n"
        mock_run.return_value = (2, stdout_text.encode("utf-8"), stderr_text.encode("utf-8"))

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityUnsupportedPluginError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist_fake")

        exc = ctx.exception
        rec = exc.execution_record
        self.assertEqual(rec.error.error_type, "UNSUPPORTED_PLUGIN")
        # Diagnostic source must be stdout, not the unrelated stderr
        self.assertIn("unrecognized plugin 'linux.pslist_fake'", rec.error.error_message)
        self.assertIn("unrecognized plugin 'linux.pslist_fake'", str(exc))
        self.assertNotIn("Unrelated warning: cache directory not found", rec.error.error_message)
        self.assertNotIn("Unrelated warning: cache directory not found", str(exc))
        # Secret must be redacted
        self.assertNotIn("ApiSecret456", rec.error.error_message)
        self.assertNotIn("ApiSecret456", str(exc))
        self.assertNotIn("ApiSecret456", exc.stderr_snippet)
        self.assertNotIn("ApiSecret456", rec.to_json())
        self.assertIn("[REDACTED]", rec.error.error_message)

        # Also verify direct unit classification
        exc_cls, err_type, err_msg = _classify_execution_failure(2, stdout_text, stderr_text)
        self.assertIs(exc_cls, VolatilityUnsupportedPluginError)
        self.assertEqual(err_type, "UNSUPPORTED_PLUGIN")
        self.assertIn("unrecognized plugin 'linux.pslist_fake'", err_msg)
        self.assertNotIn("Unrelated warning", err_msg)
        self.assertNotIn("ApiSecret456", err_msg)

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_diagnostic_source_selection_recognized_signature_stderr_with_unrelated_stdout(self, mock_run: MagicMock):
        """Recognized failure signature in stderr is selected when stdout contains unrelated output."""
        stdout_text = "Volatility 3 Framework 2.4.0 banner\nUnrelated table output header\n"
        stderr_text = "Volatility 3 framework error: Symbol table requirement not satisfied: windows.kernel.symbols\npassword='BareSecret789'\n"
        mock_run.return_value = (1, stdout_text.encode("utf-8"), stderr_text.encode("utf-8"))

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx:
            adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        exc = ctx.exception
        rec = exc.execution_record
        self.assertEqual(rec.error.error_type, "MISSING_SYMBOLS")
        # Diagnostic source must be stderr because the recognized pattern is in stderr
        self.assertIn("Symbol table requirement not satisfied: windows.kernel.symbols", rec.error.error_message)
        self.assertIn("Symbol table requirement not satisfied: windows.kernel.symbols", exc.stderr_snippet)
        self.assertNotIn("Volatility 3 Framework 2.4.0 banner", rec.error.error_message)
        self.assertNotIn("Volatility 3 Framework 2.4.0 banner", exc.stderr_snippet)
        # Secret must be redacted
        self.assertNotIn("BareSecret789", rec.error.error_message)
        self.assertNotIn("BareSecret789", str(exc))
        self.assertNotIn("BareSecret789", exc.stderr_snippet)
        self.assertNotIn("BareSecret789", rec.to_json())
        self.assertIn("[REDACTED]", rec.error.error_message)

        # Also verify direct unit classification
        exc_cls, err_type, err_msg = _classify_execution_failure(1, stdout_text, stderr_text)
        self.assertIs(exc_cls, VolatilityMissingSymbolsError)
        self.assertEqual(err_type, "MISSING_SYMBOLS")
        self.assertIn("Symbol table requirement not satisfied: windows.kernel.symbols", err_msg)
        self.assertNotIn("Volatility 3 Framework 2.4.0 banner", err_msg)
        self.assertNotIn("BareSecret789", err_msg)

    # -------------------------------------------------------------------------
    # 7. Output Parsing & JSON Schema Contracts
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_successful_execution_and_parsing(self, mock_run: MagicMock):
        """Valid JSON list of row dictionaries parses into VolatilityResult."""
        json_output = b"""[
            {"PID": 1, "PPID": 0, "ImageFileName": "systemd", "Offset": "0x8000"},
            {"PID": 2, "PPID": 0, "ImageFileName": "kthreadd", "Offset": "0x8100"}
        ]"""
        mock_run.return_value = (0, json_output, b"")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        result = adapter.run_plugin(self.synthetic_mem, "linux.pslist")

        self.assertIsInstance(result, VolatilityResult)
        self.assertEqual(len(result.data), 2)
        self.assertEqual(result.data[0]["PID"], 1)
        self.assertEqual(result.data[0]["ImageFileName"], "systemd")
        self.assertEqual(result.data[1]["PID"], 2)

        # Provenance verification
        rec = result.execution_record
        self.assertEqual(rec.status, VolatilityExecutionStatus.SUCCESS.value)
        self.assertTrue(rec.executed)
        self.assertEqual(rec.exit_code, 0)
        self.assertIsNone(rec.error)
        self.assertEqual(len(rec.output_hashes), 1)
        self.assertEqual(rec.output_hashes[0][0], "stdout")

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_valid_json_with_zero_rows_preserved(self, mock_run: MagicMock):
        """Empty result '[]' is preserved as a legitimate zero-row success."""
        mock_run.return_value = (0, b"[]", b"")

        adapter = VolatilityAdapter(vol_bin=self.fake_vol_bin)
        result = adapter.run_plugin(self.synthetic_mem, "linux.malfind")

        self.assertEqual(result.data, ())
        self.assertEqual(result.execution_record.status, VolatilityExecutionStatus.SUCCESS.value)

    def test_parse_volatility_json_table_dict_format(self):
        """Volatility output with top-level 'rows' or 'data' is supported."""
        table_output = '{"rows": [{"PID": 10, "Name": "bash"}, {"PID": 20, "Name": "python"}]}'
        parsed = parse_volatility_json(table_output)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["Name"], "bash")

    def test_malformed_json_raises_parse_error(self):
        """Malformed JSON raises VolatilityParseError and is never converted to empty list."""
        with self.assertRaises(VolatilityParseError):
            parse_volatility_json("Not valid JSON at all")

        with self.assertRaises(VolatilityParseError):
            parse_volatility_json("")

        with self.assertRaises(VolatilityParseError):
            parse_volatility_json("   \n  \t ")

    def test_unexpected_json_schema_raises_parse_error(self):
        """Lists of non-dictionaries or primitives raise VolatilityParseError."""
        # List of integers
        with self.assertRaises(VolatilityParseError):
            parse_volatility_json("[1, 2, 3]")

        # Primitive string
        with self.assertRaises(VolatilityParseError):
            parse_volatility_json('"hello world"')

        # Dict without rows or data
        with self.assertRaises(VolatilityParseError):
            parse_volatility_json('{"key": "value"}')

    # -------------------------------------------------------------------------
    # 8. Diagnostic Truncation & Redaction
    # -------------------------------------------------------------------------

    def test_diagnostic_snippet_truncation(self):
        """Long error text is safely truncated and control characters stripped."""
        long_text = "ERROR_HEADER: " + ("A" * 1000)
        snippet = sanitize_diagnostic_snippet(long_text, max_length=100)
        self.assertLessEqual(len(snippet), 130)
        self.assertTrue(snippet.endswith("... [TRUNCATED]"))

    def test_diagnostic_snippet_redaction_sensitive_flags_and_values(self):
        """Diagnostics from stderr/stdout redact sensitive flags and credential values."""
        secrets = [
            "SecretPass123",
            "SuperApiKey456",
            "UnderApiKey789",
            "ClientSecretVal",
            "AccessTokenVal",
            "SingleQuotedToken",
            "DoubleQuotedPass",
            "BarePasswordVal",
        ]

        diagnostic_text = (
            "vol: error: unrecognized option '--password=SecretPass123'\n"
            "Failed option --api-key SuperApiKey456 and --api_key=UnderApiKey789\n"
            "Options --client-secret ClientSecretVal and --access-token=AccessTokenVal failed\n"
            "Flag error: --token 'SingleQuotedToken' and --key=\"DoubleQuotedPass\"\n"
            "Traceback detail: password='BarePasswordVal'\n"
            "Context: failed while reading --key-file /etc/certs/key.pem and --sort-key pid"
        )

        cleaned = sanitize_diagnostic_snippet(diagnostic_text)

        # 1. Assert NONE of the secret values appear anywhere in the sanitized output
        for secret in secrets:
            self.assertNotIn(secret, cleaned, f"Secret '{secret}' was not redacted from diagnostic snippet!")

        # 2. Assert redaction markers are present in appropriate forms
        self.assertIn("--password=[REDACTED]", cleaned)
        self.assertIn("--api-key [REDACTED]", cleaned)
        self.assertIn("--api_key=[REDACTED]", cleaned)
        self.assertIn("--client-secret [REDACTED]", cleaned)
        self.assertIn("--access-token=[REDACTED]", cleaned)
        self.assertIn("--token [REDACTED]", cleaned)
        self.assertIn("--key=[REDACTED]", cleaned)
        self.assertIn("password=[REDACTED]", cleaned)

        # 3. Assert non-sensitive context and arguments remain intact
        self.assertIn("--key-file /etc/certs/key.pem", cleaned)
        self.assertIn("--sort-key pid", cleaned)
        self.assertIn("vol: error:", cleaned)

    # -------------------------------------------------------------------------
    # 9. Convenience Wrapper
    # -------------------------------------------------------------------------

    @patch.object(VolatilityAdapter, "_run_subprocess")
    def test_execute_volatility_plugin_wrapper(self, mock_run: MagicMock):
        """execute_volatility_plugin wrapper functions identically to adapter instance."""
        mock_run.return_value = (0, b'[{"PID": 42}]', b"")
        res = execute_volatility_plugin(
            memory_path=self.synthetic_mem,
            plugin="linux.pslist",
            vol_bin=self.fake_vol_bin,
        )
        self.assertEqual(len(res.data), 1)
        self.assertEqual(res.data[0]["PID"], 42)


if __name__ == "__main__":
    unittest.main()
