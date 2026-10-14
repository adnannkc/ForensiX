"""
Hardened Volatility 3 Subprocess Adapter for ForensiX (V6.1).

Provides safe, deterministic subprocess execution and output parsing for Volatility 3
memory forensics without invoking shells, leaking memory contents, or compromising forensic integrity.

Core Principles:
1. Hardened Subprocess Execution: Uses argument lists and shell=False strictly. Never invokes shells
   or interpolates input into shell commands.
2. Controlled Environment: Cleanses process environment to avoid leaking credentials or sensitive tokens,
   while safely preserving the user's HOME directory when valid.
3. Executable Precedence: Resolves binary via (1) programmatic override, (2) FORENSIX_VOLATILITY_BIN,
   (3) candidate search in PATH (vol3, volatility3).
4. Bounded Output Streaming: Actively limits captured stdout/stderr without buffering unbounded streams
   into memory before size checks. Immediately terminates child processes exceeding configured byte limits.
5. Accurate Provenance: Generates sanitized argument provenance matching the exact invoked argument list
   (including symbols and offline flags), redacting secrets without altering process execution.
6. Strict Parsing & Schema Validation: Validates top-level JSON structure and row types. Preserves
   legitimate empty results while rejecting malformed or truncated outputs.
7. Structured Diagnostics: Distinguishes missing executables, timeouts, output limits, missing symbols,
   and unsupported plugins as distinct structured failures. Truncates and sanitizes error snippets.
8. Offline Operation: Supports explicit symbol directories; never accesses the network or auto-downloads symbols.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union

from forensix.memory_models import (
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_execution_id,
)

# Configuration defaults
DEFAULT_TIMEOUT_SECONDS: float = 300.0
DEFAULT_MAX_OUTPUT_BYTES: int = 100 * 1024 * 1024  # 100 MiB bounded buffer limit
DEFAULT_VOLATILITY_CANDIDATES: Tuple[str, ...] = ("vol3", "volatility3")
VOLATILITY_BIN_ENV_VAR: str = "FORENSIX_VOLATILITY_BIN"
MAX_DIAGNOSTIC_SNIPPET_LENGTH: int = 500

# Plugin name regex: restricts to alphanumeric, dots, and underscores (e.g. 'linux.pslist.PsList')
_PLUGIN_NAME_REGEX: re.Pattern = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$")

# Recognized sensitive credential flag names pattern (case-insensitive)
# Includes hyphenated and underscored variants: password, api-key, access-token, client-secret, etc.
_SENSITIVE_FLAG_NAMES_PATTERN: str = (
    r"(?:password|passwd|secret|client[-_]secret|token|access[-_]token|auth[-_]token|"
    r"api[-_]token|session[-_]token|api[-_]key|apikey|secret[-_]key|private[-_]key|key)"
)

# Regex matching recognized sensitive CLI flags (e.g. '--password', '-api-key', '--client_secret')
_SENSITIVE_FLAG_REGEX: re.Pattern = re.compile(
    rf"^--?{_SENSITIVE_FLAG_NAMES_PATTERN}$",
    re.IGNORECASE,
)

# Backward-compatible tuple of sensitive argument patterns
_SENSITIVE_ARG_PATTERNS: Tuple[re.Pattern, ...] = (_SENSITIVE_FLAG_REGEX,)

# Patterns for redacting sensitive values from diagnostic error snippets and output text
_SENSITIVE_DIAGNOSTIC_PATTERNS: Tuple[re.Pattern, ...] = (
    # 1. Dashed flags with =, whitespace, or colon (e.g. '--password Secret', '--api-key=Secret', '--key: Secret')
    # Bounded by (?<![\w-]) and (?![\w-]) so substrings like '--sort-key' or '--key-file' are not misidentified as '--key'.
    re.compile(
        rf"(?<![\w-])(--?{_SENSITIVE_FLAG_NAMES_PATTERN})(?![\w-])(\s*[:=]\s*|\s+)([^\s,;'\"]+|'[^']*'|\"[^\"]*\")",
        re.IGNORECASE,
    ),
    # 2. Bare unambiguous credential assignments in error messages (e.g. "password='Secret'", "api_key: Secret")
    # Note: Excludes generic single-word 'key', 'secret', or 'token' to avoid redacting dictionary keys or normal text.
    re.compile(
        r"(?<![\w-])(\b(?:password|passwd|client[-_]secret|access[-_]token|auth[-_]token|"
        r"api[-_]token|session[-_]token|api[-_]key|apikey|secret[-_]key|private[-_]key)"
        r"(?![\w-]))(\s*[:=]\s*)([^\s,;'\"]+|'[^']*'|\"[^\"]*\")",
        re.IGNORECASE,
    ),
)

# Known symbol failure signatures in Volatility output
_SYMBOL_FAILURE_PATTERNS: Tuple[str, ...] = (
    "symbol table requirement not satisfied",
    "unsatisfied requirement",
    "symbols could not be found",
    "no suitable symbol table found",
    "symboltablerequirement",
    "missing symbols",
    "symbol directory",
)

# Known unsupported plugin signatures in Volatility output
_UNSUPPORTED_PLUGIN_PATTERNS: Tuple[str, ...] = (
    "plugin not found",
    "unknown plugin",
    "no such plugin",
    "unrecognized plugin",
    "invalid choice:",
)


class VolatilityError(Exception):
    """
    Base exception for all Volatility adapter failures.

    Attributes:
        message: Human-readable error description.
        execution_record: Associated VolatilityExecutionRecord capturing execution provenance.
    """

    def __init__(
        self,
        message: str,
        execution_record: Optional[VolatilityExecutionRecord] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.execution_record = execution_record


class VolatilityNotFoundError(VolatilityError):
    """Raised when the Volatility executable cannot be found or is not executable."""


class VolatilityTimeoutError(VolatilityError):
    """Raised when Volatility execution exceeds the configured timeout threshold."""


class VolatilityOutputLimitExceededError(VolatilityError):
    """Raised when Volatility process output exceeds the configured maximum byte limit."""


class VolatilityExecutionFailureError(VolatilityError):
    """
    Raised when Volatility exits with a non-zero exit status.

    Attributes:
        exit_code: Process return code.
        stderr_snippet: Truncated, sanitized diagnostic error snippet.
    """

    def __init__(
        self,
        message: str,
        exit_code: int,
        execution_record: Optional[VolatilityExecutionRecord] = None,
        stderr_snippet: Optional[str] = None,
    ) -> None:
        super().__init__(message, execution_record=execution_record)
        self.exit_code = exit_code
        self.stderr_snippet = stderr_snippet


class VolatilityMissingSymbolsError(VolatilityExecutionFailureError):
    """Raised when Volatility fails due to missing symbols or unsatisfied symbol table requirements."""


class VolatilityUnsupportedPluginError(VolatilityExecutionFailureError):
    """Raised when a requested Volatility plugin is unknown, unsupported, or unavailable."""


class VolatilityParseError(VolatilityError):
    """Raised when Volatility stdout cannot be parsed as valid JSON or violates expected schema."""


@dataclass(frozen=True)
class VolatilityResult:
    """
    Immutable representation of a completed Volatility plugin execution.

    Forensic Note:
        A successful process exit and parsed result records software execution provenance,
        not a guarantee that forensic conclusions are correct.

    Attributes:
        execution_record: Deeply immutable provenance record for the execution.
        data: Immutable tuple of parsed dictionary rows/records.
        raw_output: Captured raw stdout text for cryptographic integrity verification.
    """

    execution_record: VolatilityExecutionRecord
    data: Tuple[Dict[str, Any], ...]
    raw_output: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result outcome to a JSON-serializable dictionary."""
        return {
            "execution_record": self.execution_record.to_dict(),
            "data": [dict(row) for row in self.data],
            "row_count": len(self.data),
        }


def build_sanitized_environment() -> Dict[str, str]:
    """
    Construct a controlled, restricted environment dictionary for child processes.

    Strict Boundaries:
    - Retains standard PATH and UTF-8 locale settings.
    - Preserves current user's HOME only when explicitly set to a valid, existing directory.
      Does NOT blindly fall back to '/tmp' to prevent shared/unexpected cache use.
    - Strictly excludes all other environment variables, API tokens, and credentials.

    Returns:
        Dict[str, str]: Sanitized environment map.
    """
    env: Dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    home_val = os.environ.get("HOME")
    if home_val and os.path.isabs(home_val) and os.path.isdir(home_val):
        env["HOME"] = home_val

    return env


def _is_cli_option(token: str) -> bool:
    """
    Determine whether a token represents a command-line option flag rather than a value.

    Recognized option patterns:
    - Long options: Starts with '--' and contains an option name (e.g. '--offline', '--some-option').
    - Option delimiter: Exactly '--'.
    - Short option flags: Single '-' followed by a single ASCII letter (e.g. '-f', '-r', '-s', '-h').
    - Recognized sensitive CLI flags: Matches _SENSITIVE_FLAG_REGEX (e.g. '--password', '-api-key').

    Values that begin with '-' but do not conform to option flag syntax
    (e.g. '-SecretValue', '-12345', '-P@ssw0rd', '-token_abc') are NOT treated as options,
    allowing legitimate dash-prefixed credential values to be properly redacted.
    """
    if not token:
        return False
    if token == "--":
        return True
    if token.startswith("--") and len(token) > 2 and token[2] != "-":
        return True
    if _SENSITIVE_FLAG_REGEX.match(token):
        return True
    if len(token) == 2 and token[0] == "-" and token[1].isalpha():
        return True
    return False


def sanitize_cli_arguments(args: Sequence[str]) -> Tuple[str, ...]:
    """
    Sanitize command-line arguments by redacting potential secrets or credentials.

    Redacts sensitive values for both separate argument forms (e.g. ['--password', 'secret'])
    and inline assignment forms (e.g. ['--password=secret', '--api-key=token']).
    Preserves argument order and non-sensitive options.
    Does not modify the original argument list.

    Edge-case handling for separate sensitive flags:
    - If a subsequent token exists and represents a value (even if it begins with '-'),
      it is consumed and redacted as '[REDACTED]'.
    - If the sensitive flag is missing its value (e.g. at the end of args, or followed
      immediately by an option flag such as '--offline' or '--some-option'), the sensitive
      flag is preserved without consuming the following option.

    Args:
        args: Raw sequence of command-line argument strings.

    Returns:
        Tuple[str, ...]: Sanitized argument tuple suitable for execution provenance logging.
    """
    sanitized: List[str] = []
    i = 0
    n = len(args)

    while i < n:
        arg_str = str(args[i])

        # 1. Inline assignment form (e.g. '--password=secret' or '--api-key=token')
        if "=" in arg_str:
            key, val = arg_str.split("=", 1)
            if _SENSITIVE_FLAG_REGEX.match(key):
                sanitized.append(f"{key}=[REDACTED]")
                i += 1
                continue

        # 2. Separate sensitive flag form (e.g. '--password', 'secret')
        if _SENSITIVE_FLAG_REGEX.match(arg_str):
            sanitized.append(arg_str)
            if i + 1 < n:
                next_token = str(args[i + 1])
                if not _is_cli_option(next_token):
                    # next_token is a credential value (even if it begins with '-')
                    sanitized.append("[REDACTED]")
                    i += 2
                    continue
            # Missing value (either at end of args or followed by another option)
            i += 1
            continue

        # 3. Non-sensitive argument or option
        sanitized.append(arg_str)
        i += 1

    return tuple(sanitized)


def redact_sensitive_text(text: str) -> str:
    """
    Redact recognized sensitive credential patterns from diagnostic text or error output.

    Replaces credential values with '[REDACTED]' while preserving option flags,
    error messages, and non-sensitive diagnostic context.

    Args:
        text: Input diagnostic text.

    Returns:
        str: Sanitized text with sensitive values redacted.
    """
    if not text:
        return ""
    result = text
    for pat in _SENSITIVE_DIAGNOSTIC_PATTERNS:
        result = pat.sub(r"\g<1>\g<2>[REDACTED]", result)
    return result


def sanitize_diagnostic_snippet(
    text: str,
    max_length: int = MAX_DIAGNOSTIC_SNIPPET_LENGTH,
) -> str:
    """
    Sanitize and truncate error output to prevent leaking raw memory contents or passwords.

    Strips binary control characters and redacts recognized credentials before
    applying length bounds.

    Args:
        text: Raw output or error text.
        max_length: Maximum permitted length before truncation.

    Returns:
        str: Truncated and cleaned diagnostic message string with credentials redacted.
    """
    if not text:
        return ""
    # Strip binary control characters except newlines/tabs
    clean = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\xff]", " ", text).strip()
    clean = redact_sensitive_text(clean)
    if len(clean) > max_length:
        clean = clean[:max_length] + " ... [TRUNCATED]"
    return clean


def resolve_volatility_binary(
    explicit_path: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Resolve the Volatility executable using documented precedence rules.

    Precedence:
    1. Explicit programmatic override (`explicit_path`)
    2. Environment variable `FORENSIX_VOLATILITY_BIN`
    3. Candidate search in system PATH ('vol3', 'volatility3')

    Returns:
        Path: Resolved, validated Path to the executable binary.

    Raises:
        VolatilityNotFoundError: If no candidate is found or the candidate is not executable.
    """
    # 1. Explicit programmatic override
    if explicit_path is not None:
        raw_str = str(explicit_path).strip()
        if not raw_str:
            raise VolatilityNotFoundError("Explicit Volatility binary path is empty")
        candidate = Path(raw_str).resolve()
        if not candidate.exists():
            which_p = shutil.which(raw_str)
            if which_p:
                candidate = Path(which_p).resolve()
        if not candidate.exists():
            raise VolatilityNotFoundError(f"Explicit Volatility executable not found: {candidate}")
        if candidate.is_dir():
            raise VolatilityNotFoundError(f"Explicit Volatility executable path is a directory: {candidate}")
        if not os.access(candidate, os.X_OK):
            raise VolatilityNotFoundError(f"Explicit Volatility executable is not executable: {candidate}")
        return candidate

    # 2. Environment variable FORENSIX_VOLATILITY_BIN
    env_override = os.environ.get(VOLATILITY_BIN_ENV_VAR)
    if env_override and env_override.strip():
        candidate_env = Path(env_override.strip()).resolve()
        if not candidate_env.exists():
            raise VolatilityNotFoundError(
                f"Volatility binary from {VOLATILITY_BIN_ENV_VAR} not found: {candidate_env}"
            )
        if candidate_env.is_dir():
            raise VolatilityNotFoundError(
                f"Volatility binary from {VOLATILITY_BIN_ENV_VAR} is a directory: {candidate_env}"
            )
        if not os.access(candidate_env, os.X_OK):
            raise VolatilityNotFoundError(
                f"Volatility binary from {VOLATILITY_BIN_ENV_VAR} is not executable: {candidate_env}"
            )
        return candidate_env

    # 3. Candidate search in system PATH
    for candidate_name in DEFAULT_VOLATILITY_CANDIDATES:
        which_path = shutil.which(candidate_name)
        if which_path:
            p = Path(which_path).resolve()
            if p.exists() and os.access(p, os.X_OK):
                return p

    searched = [f"explicit: {explicit_path}", f"env: {VOLATILITY_BIN_ENV_VAR}"] + list(DEFAULT_VOLATILITY_CANDIDATES)
    raise VolatilityNotFoundError(
        f"Volatility executable not found in PATH or environment. Searched candidates: {searched}"
    )


def _run_subprocess_bounded(
    cmd: Sequence[str],
    env: Dict[str, str],
    cwd: str,
    timeout: float,
    max_output_bytes: int,
) -> Tuple[int, bytes, bytes]:
    """
    Execute a subprocess with strict enforcement of timeout and maximum output byte limits.

    Never buffers unbounded output into memory: immediately terminates the child process
    if captured stdout or stderr exceeds max_output_bytes during reading.

    Returns:
        Tuple of (returncode, stdout_bytes, stderr_bytes)

    Raises:
        subprocess.TimeoutExpired: If execution time exceeds timeout.
        VolatilityOutputLimitExceededError: If output byte limit is exceeded.
        OSError: If process spawning fails.
    """
    proc = subprocess.Popen(
        list(cmd),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
    )

    if proc.stdout is not None:
        os.set_blocking(proc.stdout.fileno(), False)
    if proc.stderr is not None:
        os.set_blocking(proc.stderr.fileno(), False)

    sel = selectors.DefaultSelector()
    if proc.stdout is not None:
        sel.register(proc.stdout, selectors.EVENT_READ, data="stdout")
    if proc.stderr is not None:
        sel.register(proc.stderr, selectors.EVENT_READ, data="stderr")

    stdout_chunks: List[bytes] = []
    stderr_chunks: List[bytes] = []
    total_bytes_read = 0
    exceeded_limit = False

    start_time = time.monotonic()

    try:
        while sel.get_map():
            elapsed = time.monotonic() - start_time
            remaining = timeout - elapsed
            if remaining <= 0:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(cmd=list(cmd), timeout=timeout)

            events = sel.select(timeout=min(remaining, 0.5))
            for key, _ in events:
                stream = key.fileobj
                stream_name = key.data
                try:
                    chunk = stream.read(65536)
                except (BlockingIOError, OSError):
                    continue

                if not chunk:
                    sel.unregister(stream)
                    continue

                if stream_name == "stdout":
                    stdout_chunks.append(chunk)
                else:
                    stderr_chunks.append(chunk)

                total_bytes_read += len(chunk)
                if total_bytes_read > max_output_bytes:
                    exceeded_limit = True
                    break

            if exceeded_limit:
                proc.kill()
                proc.wait()
                raise VolatilityOutputLimitExceededError(
                    f"Volatility process combined output exceeded maximum allowed limit of {max_output_bytes} bytes."
                )

        proc.wait(timeout=max(1.0, timeout - (time.monotonic() - start_time)))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        for key in list(sel.get_map().values()):
            try:
                sel.unregister(key.fileobj)
            except Exception:
                pass
        sel.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    return (proc.returncode, b"".join(stdout_chunks), b"".join(stderr_chunks))


def parse_volatility_json(stdout_content: str) -> List[Dict[str, Any]]:
    """
    Parse and validate Volatility JSON output contract.

    Contract Rules:
    - Must be valid JSON.
    - Top-level structure must be an array of records (mappings) or a dictionary containing a 'rows' array.
    - Legitimate empty results (e.g. `[]`) are preserved as empty lists without error.
    - Non-empty records must be dictionary mappings with string keys.
    - Non-JSON text or primitive JSON types raise VolatilityParseError.

    Args:
        stdout_content: Raw stdout text produced by Volatility.

    Returns:
        List[Dict[str, Any]]: Validated list of result row dictionaries.

    Raises:
        VolatilityParseError: If output is malformed, not JSON, or violates schema.
    """
    stripped = stdout_content.strip()
    if not stripped:
        raise VolatilityParseError("Volatility produced empty stdout; expected JSON array")

    parsed: Any = None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        # Volatility might output logging lines before the JSON array. Attempt to extract the JSON array.
        start_idx = stripped.find("[")
        end_idx = stripped.rfind("]")
        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            snippet = stripped[start_idx : end_idx + 1]
            try:
                parsed = json.loads(snippet)
            except json.JSONDecodeError as err:
                raise VolatilityParseError(f"Malformed JSON output from Volatility: {err}") from err
        else:
            raise VolatilityParseError(
                "Malformed JSON output from Volatility: stdout does not contain valid JSON"
            )

    # Validate top-level structure
    if isinstance(parsed, list):
        rows: List[Dict[str, Any]] = []
        for idx, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise VolatilityParseError(
                    f"Unexpected JSON schema: list element at index {idx} must be a dictionary, got {type(item).__name__}"
                )
            rows.append(item)
        return rows
    elif isinstance(parsed, dict):
        # Support Volatility rendering format with top-level 'rows' or 'data'
        if "rows" in parsed and isinstance(parsed["rows"], list):
            rows = []
            for idx, item in enumerate(parsed["rows"]):
                if not isinstance(item, dict):
                    raise VolatilityParseError(
                        f"Unexpected JSON schema: 'rows' element at index {idx} must be a dictionary, got {type(item).__name__}"
                    )
                rows.append(item)
            return rows
        elif "data" in parsed and isinstance(parsed["data"], list):
            rows = []
            for idx, item in enumerate(parsed["data"]):
                if not isinstance(item, dict):
                    raise VolatilityParseError(
                        f"Unexpected JSON schema: 'data' element at index {idx} must be a dictionary, got {type(item).__name__}"
                    )
                rows.append(item)
            return rows
        else:
            raise VolatilityParseError(
                "Unexpected JSON schema: dictionary missing expected 'rows' or 'data' list"
            )
    else:
        raise VolatilityParseError(
            f"Unexpected JSON schema: expected JSON array of rows, got {type(parsed).__name__}"
        )


def _classify_execution_failure(
    returncode: int,
    stdout_text: str,
    stderr_text: str,
) -> Tuple[Type[VolatilityExecutionFailureError], str, str]:
    """
    Classify a non-zero exit from Volatility into a specific structured failure type.

    Returns:
        Tuple of (ExceptionClass, error_type_string, diagnostic_message)
    """
    combined_lower = f"{stderr_text}\n{stdout_text}".lower()
    stderr_lower = stderr_text.lower()
    stdout_lower = stdout_text.lower()

    def _select_diag_source(matched_pat: Optional[str] = None) -> str:
        if matched_pat:
            # 1. If a recognized failure pattern matches stdout but does not match stderr, select stdout.
            if matched_pat in stdout_lower and matched_pat not in stderr_lower:
                return stdout_text
            # 2. If the pattern matches stderr, select stderr.
            if matched_pat in stderr_lower:
                return stderr_text
        # 3. If neither stream matches the recognized pattern, prefer non-empty stderr, otherwise stdout.
        return stderr_text if stderr_text.strip() else stdout_text

    # 1. Missing symbols detection
    for pat in _SYMBOL_FAILURE_PATTERNS:
        if pat in combined_lower:
            snippet = sanitize_diagnostic_snippet(_select_diag_source(pat))
            msg = f"Volatility failed due to missing symbol tables or unsatisfied requirements: {snippet}"
            return VolatilityMissingSymbolsError, "MISSING_SYMBOLS", msg

    # 2. Unsupported plugin detection
    for pat in _UNSUPPORTED_PLUGIN_PATTERNS:
        if pat in combined_lower:
            snippet = sanitize_diagnostic_snippet(_select_diag_source(pat))
            msg = f"Volatility plugin is unknown or unsupported: {snippet}"
            return VolatilityUnsupportedPluginError, "UNSUPPORTED_PLUGIN", msg

    # 3. General non-zero exit
    snippet = sanitize_diagnostic_snippet(_select_diag_source())
    msg = f"Volatility execution failed with exit code {returncode}: {snippet}"
    return VolatilityExecutionFailureError, "EXECUTION_FAILURE", msg


class VolatilityAdapter:
    """
    Hardened subprocess adapter for Volatility 3 memory forensics.

    Guarantees:
    - Never invokes a shell (shell=False).
    - Actively bounds output reading to prevent memory exhaustion.
    - Validates paths and plugin parameters against injection.
    - Cleanses environment while preserving valid user HOME.
    - Structured error reporting with deep execution provenance.
    """

    def __init__(
        self,
        vol_bin: Optional[Union[str, Path]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        symbol_dir: Optional[Union[str, Path]] = None,
        offline: bool = True,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        cwd: Optional[Union[str, Path]] = None,
    ) -> None:
        """
        Initialize the VolatilityAdapter.

        Args:
            vol_bin: Optional explicit path to the Volatility executable.
            timeout: Subprocess timeout in seconds (default 300.0).
            symbol_dir: Optional path to an offline symbols directory.
            offline: If True, operates in offline mode without symbol downloads.
            max_output_bytes: Maximum allowed stdout/stderr buffer size in bytes (default 100 MiB).
            cwd: Optional controlled working directory for subprocess execution (defaults to temp directory).

        Raises:
            ValueError: If timeout, max_output_bytes, symbol_dir, or cwd is invalid.
        """
        self._vol_bin_override = vol_bin
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError(f"timeout must be a positive number, got {timeout}")
        self.timeout = float(timeout)

        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
            raise ValueError(f"max_output_bytes must be a positive integer, got {max_output_bytes}")
        self.max_output_bytes = max_output_bytes

        if symbol_dir is not None:
            sym_path = Path(symbol_dir).resolve()
            if not sym_path.exists() or not sym_path.is_dir():
                raise ValueError(f"symbol_dir must point to an existing directory: {symbol_dir}")
            self.symbol_dir: Optional[Path] = sym_path
        else:
            self.symbol_dir = None

        if cwd is not None:
            sym_cwd = Path(cwd).resolve()
            if not sym_cwd.exists() or not sym_cwd.is_dir():
                raise ValueError(f"cwd must point to an existing directory: {cwd}")
            self.cwd: Optional[Path] = sym_cwd
        else:
            self.cwd = None

        self.offline = bool(offline)
        self._tool_version: Optional[str] = None

    def resolve_binary(self) -> Path:
        """Resolve the Volatility binary according to documented precedence."""
        return resolve_volatility_binary(self._vol_bin_override)

    def _run_subprocess(
        self,
        cmd: Sequence[str],
        env: Dict[str, str],
        cwd: str,
        timeout: float,
        max_output_bytes: int,
    ) -> Tuple[int, bytes, bytes]:
        """Internal subprocess dispatcher to facilitate testing and bounded execution."""
        return _run_subprocess_bounded(
            cmd=cmd,
            env=env,
            cwd=cwd,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
        )

    def get_version(self) -> Optional[str]:
        """
        Safely query the Volatility executable version.

        Returns:
            Optional[str]: Detected version string, or None if query fails.
        """
        if self._tool_version is not None:
            return self._tool_version

        try:
            bin_path = self.resolve_binary()
        except VolatilityNotFoundError:
            return None

        safe_env = build_sanitized_environment()
        try:
            retcode, out_bytes, _ = self._run_subprocess(
                cmd=[str(bin_path), "--version"],
                env=safe_env,
                cwd=tempfile.gettempdir(),
                timeout=10.0,
                max_output_bytes=65536,
            )
            if retcode == 0 and out_bytes:
                out = out_bytes.decode("utf-8", errors="replace").strip()
                if out:
                    self._tool_version = out.splitlines()[0]
                    return self._tool_version
        except (subprocess.SubprocessError, OSError, VolatilityError):
            pass
        return None

    def run_plugin(
        self,
        memory_path: Union[str, Path],
        plugin: str,
        plugin_args: Optional[Sequence[str]] = None,
        timeout: Optional[float] = None,
        symbol_dir: Optional[Union[str, Path]] = None,
        max_output_bytes: Optional[int] = None,
        input_evidence_hash: Optional[str] = None,
    ) -> VolatilityResult:
        """
        Execute a Volatility plugin on a memory evidence file safely.

        Args:
            memory_path: Filesystem path to the target memory image.
            plugin: Volatility plugin identifier (e.g. 'linux.pslist').
            plugin_args: Optional additional plugin arguments.
            timeout: Optional per-execution timeout override.
            symbol_dir: Optional per-execution symbol directory override.
            max_output_bytes: Optional per-execution output buffer byte limit.
            input_evidence_hash: Optional SHA-256 hash of the input evidence for provenance.

        Returns:
            VolatilityResult: Immutable result containing parsed records and execution record.

        Raises:
            VolatilityNotFoundError: If executable cannot be resolved.
            VolatilityTimeoutError: If execution exceeds timeout.
            VolatilityOutputLimitExceededError: If output exceeds max_output_bytes.
            VolatilityMissingSymbolsError: If symbol table requirements are unsatisfied.
            VolatilityUnsupportedPluginError: If plugin is unknown or unsupported.
            VolatilityExecutionFailureError: If Volatility exits with a non-zero code.
            VolatilityParseError: If output JSON is invalid or violates schema.
            ValueError: If plugin name, limits, or paths are invalid.
        """
        # 1. Validate memory_path
        target_mem = Path(memory_path).resolve()
        if not target_mem.exists():
            raise FileNotFoundError(f"Memory image does not exist: {target_mem}")
        if not target_mem.is_file():
            raise ValueError(f"Memory image path is not a regular file: {target_mem}")

        # 2. Validate plugin
        if not isinstance(plugin, str) or not plugin.strip():
            raise ValueError("plugin must be a non-empty string")
        clean_plugin = plugin.strip()
        if not _PLUGIN_NAME_REGEX.match(clean_plugin):
            raise ValueError(
                f"Invalid plugin name: '{plugin}'. Must consist of alphanumeric characters, dots, and underscores."
            )

        # 3. Validate timeout
        effective_timeout = self.timeout
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
                raise ValueError(f"timeout must be a positive number, got {timeout}")
            effective_timeout = float(timeout)

        # 4. Validate max_output_bytes
        effective_max_output = self.max_output_bytes
        if max_output_bytes is not None:
            if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
                raise ValueError(f"max_output_bytes must be a positive integer, got {max_output_bytes}")
            effective_max_output = max_output_bytes

        # 5. Validate symbol_dir
        effective_sym_dir = self.symbol_dir
        if symbol_dir is not None:
            sym_p = Path(symbol_dir).resolve()
            if not sym_p.exists() or not sym_p.is_dir():
                raise ValueError(f"symbol_dir must point to an existing directory: {symbol_dir}")
            effective_sym_dir = sym_p

        raw_plugin_args = [str(a) for a in plugin_args] if plugin_args else []

        # 6. Resolve executable binary
        try:
            bin_path = self.resolve_binary()
        except VolatilityNotFoundError as err:
            # Build attempted command arguments for accurate provenance
            attempted_args: List[str] = [
                "-f",
                str(target_mem),
                "-r",
                "json",
            ]
            if effective_sym_dir:
                attempted_args.extend(["-s", str(effective_sym_dir)])
            if self.offline:
                attempted_args.append("--offline")
            attempted_args.append(clean_plugin)
            attempted_args.extend(raw_plugin_args)
            sanitized_attempted = sanitize_cli_arguments(attempted_args)

            tool_name = Path(str(self._vol_bin_override)).name if self._vol_bin_override else "volatility3"
            exec_rec = VolatilityExecutionRecord(
                record_id=compute_deterministic_execution_id(tool_name, clean_plugin, sanitized_attempted, input_evidence_hash),
                tool=tool_name,
                plugin=clean_plugin,
                sanitized_args=sanitized_attempted,
                status=VolatilityExecutionStatus.ERROR.value,
                executed=False,
                error=VolatilityExecutionError(
                    error_type="EXECUTABLE_NOT_FOUND",
                    error_message=str(err),
                ),
                input_evidence_hash=input_evidence_hash,
            )
            raise VolatilityNotFoundError(str(err), execution_record=exec_rec) from err

        tool_version = self.get_version()

        # 7. Construct complete command line first
        cmd: List[str] = [
            str(bin_path),
            "-f",
            str(target_mem),
            "-r",
            "json",
        ]

        if effective_sym_dir:
            cmd.extend(["-s", str(effective_sym_dir)])

        if self.offline:
            cmd.append("--offline")

        cmd.append(clean_plugin)
        cmd.extend(raw_plugin_args)

        # 8. Record actual arguments with sensitive redaction
        # cmd[0] is the binary (stored in record.tool); cmd[1:] are the exact invoked arguments
        sanitized_args = sanitize_cli_arguments(cmd[1:])

        # 9. Prepare controlled environment
        safe_env = build_sanitized_environment()

        # Neutral working directory: fallback to tempfile.gettempdir() by default.
        # Never uses the evidence file's parent directory as default cwd.
        cwd = str(self.cwd) if self.cwd is not None else tempfile.gettempdir()

        # 10. Execute with bounded output and timing
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        try:
            returncode, stdout_bytes, stderr_bytes = self._run_subprocess(
                cmd=cmd,
                env=safe_env,
                cwd=cwd,
                timeout=effective_timeout,
                max_output_bytes=effective_max_output,
            )
        except subprocess.TimeoutExpired as err:
            duration = round(time.monotonic() - t0, 6)
            completed_at = datetime.now(timezone.utc).isoformat()
            exec_rec = VolatilityExecutionRecord(
                record_id=compute_deterministic_execution_id(bin_path.name, clean_plugin, sanitized_args, input_evidence_hash),
                tool=bin_path.name,
                tool_version=tool_version,
                plugin=clean_plugin,
                sanitized_args=sanitized_args,
                status=VolatilityExecutionStatus.TIMEOUT.value,
                executed=True,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                exit_code=None,
                error=VolatilityExecutionError(
                    error_type="TIMEOUT",
                    error_message=f"Process timed out after {effective_timeout}s",
                    details=(("timeout_seconds", effective_timeout),),
                ),
                input_evidence_hash=input_evidence_hash,
            )
            raise VolatilityTimeoutError(
                f"Volatility execution timed out after {effective_timeout}s for plugin '{clean_plugin}'",
                execution_record=exec_rec,
            ) from err
        except VolatilityOutputLimitExceededError as err:
            duration = round(time.monotonic() - t0, 6)
            completed_at = datetime.now(timezone.utc).isoformat()
            exec_rec = VolatilityExecutionRecord(
                record_id=compute_deterministic_execution_id(bin_path.name, clean_plugin, sanitized_args, input_evidence_hash),
                tool=bin_path.name,
                tool_version=tool_version,
                plugin=clean_plugin,
                sanitized_args=sanitized_args,
                status=VolatilityExecutionStatus.ERROR.value,
                executed=True,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                exit_code=None,
                error=VolatilityExecutionError(
                    error_type="OUTPUT_LIMIT_EXCEEDED",
                    error_message=str(err),
                    details=(("max_output_bytes", effective_max_output),),
                ),
                input_evidence_hash=input_evidence_hash,
            )
            raise VolatilityOutputLimitExceededError(str(err), execution_record=exec_rec) from err

        duration = round(time.monotonic() - t0, 6)
        completed_at = datetime.now(timezone.utc).isoformat()

        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")

        # Hash stdout output artifact
        stdout_hash = hashlib.sha256(stdout_bytes).hexdigest()
        output_hashes = (("stdout", stdout_hash),)

        # 11. Handle non-zero exit status
        if returncode != 0:
            exc_cls, err_type, err_msg = _classify_execution_failure(
                returncode, stdout_str, stderr_str
            )
            exec_rec = VolatilityExecutionRecord(
                record_id=compute_deterministic_execution_id(bin_path.name, clean_plugin, sanitized_args, input_evidence_hash),
                tool=bin_path.name,
                tool_version=tool_version,
                plugin=clean_plugin,
                sanitized_args=sanitized_args,
                status=VolatilityExecutionStatus.FAILED.value,
                executed=True,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                exit_code=returncode,
                error=VolatilityExecutionError(
                    error_type=err_type,
                    error_message=err_msg,
                    details=(("exit_code", returncode),),
                ),
                input_evidence_hash=input_evidence_hash,
                output_hashes=output_hashes,
            )
            raise exc_cls(
                err_msg,
                exit_code=returncode,
                execution_record=exec_rec,
                stderr_snippet=sanitize_diagnostic_snippet(stderr_str if stderr_str.strip() else stdout_str),
            )

        # 12. Parse JSON output
        try:
            parsed_rows = parse_volatility_json(stdout_str)
        except VolatilityParseError as err:
            exec_rec = VolatilityExecutionRecord(
                record_id=compute_deterministic_execution_id(bin_path.name, clean_plugin, sanitized_args, input_evidence_hash),
                tool=bin_path.name,
                tool_version=tool_version,
                plugin=clean_plugin,
                sanitized_args=sanitized_args,
                status=VolatilityExecutionStatus.ERROR.value,
                executed=True,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                exit_code=returncode,
                error=VolatilityExecutionError(
                    error_type="OUTPUT_PARSE_ERROR",
                    error_message=str(err),
                ),
                input_evidence_hash=input_evidence_hash,
                output_hashes=output_hashes,
            )
            raise VolatilityParseError(str(err), execution_record=exec_rec) from err

        # 13. Build successful execution record and result
        exec_rec = VolatilityExecutionRecord(
            record_id=compute_deterministic_execution_id(bin_path.name, clean_plugin, sanitized_args, input_evidence_hash),
            tool=bin_path.name,
            tool_version=tool_version,
            plugin=clean_plugin,
            sanitized_args=sanitized_args,
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            exit_code=0,
            error=None,
            input_evidence_hash=input_evidence_hash,
            output_hashes=output_hashes,
        )

        return VolatilityResult(
            execution_record=exec_rec,
            data=tuple(parsed_rows),
            raw_output=stdout_str,
        )


def execute_volatility_plugin(
    memory_path: Union[str, Path],
    plugin: str,
    vol_bin: Optional[Union[str, Path]] = None,
    plugin_args: Optional[Sequence[str]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    symbol_dir: Optional[Union[str, Path]] = None,
    offline: bool = True,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    input_evidence_hash: Optional[str] = None,
    cwd: Optional[Union[str, Path]] = None,
) -> VolatilityResult:
    """
    Convenience wrapper to instantiate VolatilityAdapter and execute a plugin.

    Args:
        memory_path: Path to the target memory image.
        plugin: Name of the Volatility plugin (e.g. 'linux.pslist').
        vol_bin: Optional path override for the Volatility executable.
        plugin_args: Optional additional plugin arguments.
        timeout: Execution timeout in seconds.
        symbol_dir: Optional offline symbols directory.
        offline: If True, operates in offline mode.
        max_output_bytes: Maximum allowed output buffer size in bytes.
        input_evidence_hash: Optional input evidence hash for provenance.
        cwd: Optional controlled working directory for subprocess execution.

    Returns:
        VolatilityResult: Execution outcome with parsed rows and provenance.
    """
    adapter = VolatilityAdapter(
        vol_bin=vol_bin,
        timeout=timeout,
        symbol_dir=symbol_dir,
        offline=offline,
        max_output_bytes=max_output_bytes,
        cwd=cwd,
    )
    return adapter.run_plugin(
        memory_path=memory_path,
        plugin=plugin,
        plugin_args=plugin_args,
        input_evidence_hash=input_evidence_hash,
    )
