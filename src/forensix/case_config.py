"""
ForensiX V9 - Investigation Case Configuration.

Provides strongly typed, validated, and deeply immutable configuration specifications
for multi-domain investigation pipeline runs.

Supports declarative loading from JSON files with relative path resolution and strict
forensic safety boundary enforcement (output isolation, evidence existence verification).
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

SUPPORTED_REPORT_FORMATS: Tuple[str, ...] = ("json", "html")
ALL_DOMAINS: Tuple[str, ...] = ("host", "network", "memory", "timeline", "correlation", "detection")


@dataclass(frozen=True)
class CaseConfig:
    """
    Immutable specification of an investigation case and its evidence inputs.

    Attributes:
        case_id: Incident tracking identifier (e.g. 'CASE-2026-001').
        case_name: Human-readable incident title.
        investigator: Primary investigator or forensic analyst name.
        actor_role: Role designation of the active custodian (default: 'Forensic Analyst').
        actor_org: Organization or forensic laboratory name.
        evidence_host_dir: Path to directory containing host artifacts (or None).
        evidence_pcap_files: Paths to PCAP capture files.
        evidence_mem_files: Paths to memory artifact JSON files or directories.
        manifest_path: Path to baseline evidence manifest JSON (or None).
        custody_ledger_path: Path to existing custody ledger JSON to resume (or None).
        output_dir: Destination directory for all generated reports and ledgers.
        report_formats: Formats to generate ('json', 'html').
        enabled_domains: Domains to include in analysis ('host', 'network', 'memory', etc.).
        log_year: Explicit calendar year for yearless BSD syslog timestamps.
        allow_symlinks: If True, symlinks in evidence trees are followed.
        overwrite: If True, atomically replace existing files in output_dir.
        fail_fast: If True, halt on first domain failure rather than attempting remaining domains.
    """

    case_id: Optional[str] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    actor_role: str = "Forensic Analyst"
    actor_org: Optional[str] = None
    evidence_host_dir: Optional[Path] = None
    evidence_pcap_files: Tuple[Path, ...] = ()
    evidence_mem_files: Tuple[Path, ...] = ()
    manifest_path: Optional[Path] = None
    custody_ledger_path: Optional[Path] = None
    output_dir: Path = Path("reports")
    report_formats: Tuple[str, ...] = ("json", "html")
    enabled_domains: Tuple[str, ...] = ALL_DOMAINS
    log_year: Optional[int] = None
    allow_symlinks: bool = False
    overwrite: bool = False
    fail_fast: bool = False

    def __post_init__(self) -> None:
        if self.case_id is not None:
            if not isinstance(self.case_id, str):
                raise TypeError(f"case_id must be str or None, got {type(self.case_id).__name__}")
            clean_id = self.case_id.strip() or None
            object.__setattr__(self, "case_id", clean_id)

        if self.case_name is not None:
            if not isinstance(self.case_name, str):
                raise TypeError(f"case_name must be str or None, got {type(self.case_name).__name__}")
            clean_name = self.case_name.strip() or None
            object.__setattr__(self, "case_name", clean_name)

        if self.investigator is not None:
            if not isinstance(self.investigator, str):
                raise TypeError(f"investigator must be str or None, got {type(self.investigator).__name__}")
            clean_inv = self.investigator.strip() or None
            object.__setattr__(self, "investigator", clean_inv)

        if not isinstance(self.actor_role, str) or not self.actor_role.strip():
            raise ValueError("actor_role must be a non-empty string")

        if self.evidence_host_dir is not None:
            if not isinstance(self.evidence_host_dir, (str, Path)):
                raise TypeError("evidence_host_dir must be Path, str, or None")
            object.__setattr__(self, "evidence_host_dir", Path(self.evidence_host_dir).resolve())

        # Freeze pcap files tuple
        clean_pcaps: List[Path] = []
        if isinstance(self.evidence_pcap_files, (list, tuple)):
            for p in self.evidence_pcap_files:
                if not isinstance(p, (str, Path)):
                    raise TypeError("evidence_pcap_files items must be Path or str")
                clean_pcaps.append(Path(p).resolve())
        else:
            raise TypeError("evidence_pcap_files must be a sequence of Paths")
        object.__setattr__(self, "evidence_pcap_files", tuple(clean_pcaps))

        # Freeze mem files tuple
        clean_mems: List[Path] = []
        if isinstance(self.evidence_mem_files, (list, tuple)):
            for p in self.evidence_mem_files:
                if not isinstance(p, (str, Path)):
                    raise TypeError("evidence_mem_files items must be Path or str")
                clean_mems.append(Path(p).resolve())
        else:
            raise TypeError("evidence_mem_files must be a sequence of Paths")
        object.__setattr__(self, "evidence_mem_files", tuple(clean_mems))

        if self.manifest_path is not None:
            object.__setattr__(self, "manifest_path", Path(self.manifest_path).resolve())

        if self.custody_ledger_path is not None:
            object.__setattr__(self, "custody_ledger_path", Path(self.custody_ledger_path).resolve())

        object.__setattr__(self, "output_dir", Path(self.output_dir).resolve())

        # Formats validation
        clean_fmts: List[str] = []
        for fmt in self.report_formats:
            val = str(fmt).strip().lower()
            if val not in SUPPORTED_REPORT_FORMATS:
                raise ValueError(f"Unsupported report format: '{val}'. Expected one of {SUPPORTED_REPORT_FORMATS}")
            clean_fmts.append(val)
        object.__setattr__(self, "report_formats", tuple(clean_fmts))

        # Domains validation
        clean_doms: List[str] = []
        for d in self.enabled_domains:
            val = str(d).strip().lower()
            if val not in ALL_DOMAINS:
                raise ValueError(f"Unknown domain: '{val}'. Expected one of {ALL_DOMAINS}")
            clean_doms.append(val)
        object.__setattr__(self, "enabled_domains", tuple(clean_doms))

        if self.log_year is not None:
            if not isinstance(self.log_year, int) or isinstance(self.log_year, bool):
                raise TypeError("log_year must be an integer")
            if self.log_year < 1970 or self.log_year > 2100:
                raise ValueError(f"log_year must be between 1970 and 2100, got {self.log_year}")

    @property
    def has_evidence(self) -> bool:
        """True if at least one evidence input (host, PCAP, or memory) is configured."""
        return bool(self.evidence_host_dir or self.evidence_pcap_files or self.evidence_mem_files)

    @property
    def all_evidence_paths(self) -> Tuple[Path, ...]:
        """Tuple of all configured evidence file/directory paths."""
        paths: List[Path] = []
        if self.evidence_host_dir:
            paths.append(self.evidence_host_dir)
        paths.extend(self.evidence_pcap_files)
        paths.extend(self.evidence_mem_files)
        return tuple(paths)


def validate_case_config(config: CaseConfig) -> None:
    """
    Validate case configuration for existence of evidence and forensic boundary safety.

    Raises:
        ValueError: If no evidence is configured, or if output_dir collides with evidence.
        FileNotFoundError: If configured evidence paths do not exist.
        NotADirectoryError: If evidence_host_dir is not a directory.
    """
    if not isinstance(config, CaseConfig):
        raise TypeError(f"config must be CaseConfig, got {type(config).__name__}")

    if not config.has_evidence:
        raise ValueError(
            "Case configuration must declare at least one evidence input "
            "('evidence_host_dir', 'evidence_pcap_files', or 'evidence_mem_files')"
        )

    out_dir = config.output_dir.resolve()

    # 1. Validate evidence_host_dir
    if config.evidence_host_dir is not None:
        p = config.evidence_host_dir.resolve()
        if not p.exists():
            raise FileNotFoundError(f"Configured host evidence directory does not exist: '{p}'")
        if not p.is_dir():
            raise NotADirectoryError(f"Host evidence path is not a directory: '{p}'")
        if out_dir == p or out_dir.is_relative_to(p):
            raise ValueError(
                f"Forensic safety violation: output directory '{out_dir}' "
                f"overlaps or is inside host evidence directory '{p}'"
            )

    # 2. Validate evidence_pcap_files
    for pcap in config.evidence_pcap_files:
        p = pcap.resolve()
        if not p.exists():
            raise FileNotFoundError(f"Configured PCAP evidence file does not exist: '{p}'")
        if not p.is_file():
            raise ValueError(f"Configured PCAP path is not a regular file: '{p}'")
        if out_dir == p.parent or out_dir.is_relative_to(p.parent):
            if p.parent == out_dir:
                raise ValueError(
                    f"Forensic safety violation: output directory '{out_dir}' "
                    f"is the same directory containing PCAP evidence '{p.name}'"
                )

    # 3. Validate evidence_mem_files
    for mem in config.evidence_mem_files:
        p = mem.resolve()
        if not p.exists():
            raise FileNotFoundError(f"Configured memory evidence path does not exist: '{p}'")
        if p.is_file() and p.suffix.lower() != ".json":
            # Guard against passing raw memory images to the pipeline
            from forensix.memory_cli import RAW_IMAGE_EXTENSIONS
            if p.suffix.lower() in RAW_IMAGE_EXTENSIONS:
                raise ValueError(
                    f"Raw memory image '{p.name}' is not supported directly in V9 pipeline. "
                    "Pre-extracted JSON memory artifacts are required."
                )

    # 4. Validate manifest if provided
    if config.manifest_path is not None:
        p = config.manifest_path.resolve()
        if not p.exists():
            raise FileNotFoundError(f"Configured manifest baseline file does not exist: '{p}'")
        if not p.is_file():
            raise ValueError(f"Manifest path is not a regular file: '{p}'")

    # 5. Validate custody ledger if resuming
    if config.custody_ledger_path is not None:
        p = config.custody_ledger_path.resolve()
        if not p.exists():
            raise FileNotFoundError(f"Configured custody ledger file to resume does not exist: '{p}'")
        if not p.is_file():
            raise ValueError(f"Custody ledger path is not a regular file: '{p}'")


def load_case_config_from_dict(
    data: Dict[str, Any],
    base_dir: Optional[Union[str, Path]] = None,
) -> CaseConfig:
    """
    Reconstruct a CaseConfig from a dictionary, resolving relative paths against base_dir.
    """
    if not isinstance(data, dict):
        raise TypeError(f"data must be a dictionary, got {type(data).__name__}")

    bdir = Path(base_dir).resolve() if base_dir is not None else Path.cwd()

    def resolve_path(p: Optional[str]) -> Optional[Path]:
        if not p:
            return None
        raw = Path(p)
        return raw if raw.is_absolute() else (bdir / raw).resolve()

    def resolve_path_list(plist: Optional[Sequence[str]]) -> Tuple[Path, ...]:
        if not plist:
            return ()
        resolved = []
        for p in plist:
            raw = Path(p)
            resolved.append(raw if raw.is_absolute() else (bdir / raw).resolve())
        return tuple(resolved)

    host_dir = resolve_path(data.get("evidence_host_dir"))
    pcap_files = resolve_path_list(data.get("evidence_pcap_files", ()))
    mem_files = resolve_path_list(data.get("evidence_mem_files", ()))
    manifest_p = resolve_path(data.get("manifest_path"))
    ledger_p = resolve_path(data.get("custody_ledger_path"))
    out_dir = resolve_path(data.get("output_dir", "reports")) or Path("reports").resolve()

    return CaseConfig(
        case_id=data.get("case_id"),
        case_name=data.get("case_name"),
        investigator=data.get("investigator"),
        actor_role=data.get("actor_role", "Forensic Analyst"),
        actor_org=data.get("actor_org"),
        evidence_host_dir=host_dir,
        evidence_pcap_files=pcap_files,
        evidence_mem_files=mem_files,
        manifest_path=manifest_p,
        custody_ledger_path=ledger_p,
        output_dir=out_dir,
        report_formats=tuple(data.get("report_formats", ("json", "html"))),
        enabled_domains=tuple(data.get("enabled_domains", ALL_DOMAINS)),
        log_year=data.get("log_year"),
        allow_symlinks=bool(data.get("allow_symlinks", False)),
        overwrite=bool(data.get("overwrite", False)),
        fail_fast=bool(data.get("fail_fast", False)),
    )


def load_case_config_from_file(path: Union[str, Path]) -> CaseConfig:
    """
    Parse a JSON case configuration file and return a validated CaseConfig.
    Relative paths in the JSON file are resolved relative to the file's parent directory.
    """
    cfg_path = Path(path).resolve()
    if not cfg_path.exists():
        raise FileNotFoundError(f"Case configuration file not found: '{cfg_path}'")
    if not cfg_path.is_file():
        raise ValueError(f"Case configuration path is not a file: '{cfg_path}'")

    with open(cfg_path, "r", encoding="utf-8") as f:
        try:
            content = json.load(f)
        except json.JSONDecodeError as err:
            raise ValueError(f"Malformed JSON in case configuration file '{cfg_path.name}': {err}") from err

    if not isinstance(content, dict):
        raise ValueError("Case configuration file must contain a JSON object")

    return load_case_config_from_dict(content, base_dir=cfg_path.parent)
