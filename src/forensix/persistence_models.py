"""
Forensic Persistence Models for ForensiX (V2.5 Persistence Artifacts).

Provides strongly typed, deeply immutable dataclasses representing observed
persistence-capable configurations (systemd, cron, shell startup, desktop autostart,
dynamic loader, kernel modules) while separating observed facts from derived data.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple
import uuid


class PersistenceCategory(str, Enum):
    """Categorization of persistence-capable Linux configuration artifacts."""

    SYSTEMD = "systemd"
    CRON = "cron"
    ANACRON = "anacron"
    INIT_SCRIPT = "init_script"
    SHELL_STARTUP = "shell_startup"
    XDG_AUTOSTART = "xdg_autostart"
    DYNAMIC_LOADER = "dynamic_loader"
    KERNEL_MODULE = "kernel_module"
    OTHER = "other"


def generate_persistence_id() -> str:
    """Generate a unique tracking identifier for a persistence record (PERSIST-<UUIDv4>)."""
    return f"PERSIST-{uuid.uuid4()}"


@dataclass(frozen=True)
class PersistenceRecord:
    """
    Immutable representation of an observed persistence-capable configuration entry.

    Forensic notes on raw_line:
        raw_line is the decoded line as read by the parser using errors="replace".
        Valid UTF-8 preserves original text; invalid UTF-8 bytes are replaced by \\ufffd.

    Attributes:
        persistence_id: Unique tracking identifier formatted as PERSIST-<UUIDv4>.
        source_artifact_id: Optional tracking ID of the parent artifact.
        source_path: Canonical filesystem path in evidence.
        line_number: 1-indexed line number where applicable (or None for file-level).
        category: PersistenceCategory value string.
        mechanism: Specific mechanism (e.g. 'systemd_service', 'systemd_timer',
                   'systemd_enablement_symlink', 'crontab', 'cron_env', 'anacrontab',
                   'shell_startup', 'desktop_autostart', 'ld_preload',
                   'kernel_module_load', 'modprobe_directive').
        scope: Context scope ('system', 'user', or 'unknown').
        target_user: Factual user context if identifiable (e.g. cron user, service User=).
        trigger_or_schedule: Factual scheduling configuration ONLY (e.g. cron expression,
                             OnCalendar=, OnBootSec=).
        command_or_path: Factual executable/command/path string (e.g. ExecStart=, cron command,
                         preloaded library path).
        attributes: IMMUTABLE tuple of key-value pairs (converted to dict in to_dict()).
        status: Parse status ('PARSED', 'UNPARSED', 'MALFORMED').
        raw_line: Decoded raw line or None if whole-file record.
    """

    persistence_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: Optional[int]
    category: str
    mechanism: str
    scope: str
    target_user: Optional[str]
    trigger_or_schedule: Optional[str]
    command_or_path: Optional[str]
    attributes: Tuple[Tuple[str, Any], ...]
    status: str
    raw_line: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a JSON-serializable dictionary with nested dict attributes."""
        return {
            "persistence_id": self.persistence_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "category": self.category,
            "mechanism": self.mechanism,
            "scope": self.scope,
            "target_user": self.target_user,
            "trigger_or_schedule": self.trigger_or_schedule,
            "command_or_path": self.command_or_path,
            "attributes": dict(self.attributes),
            "status": self.status,
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class PersistenceCollectionResult:
    """
    Immutable aggregate collection of discovered persistence-capable configurations.
    """

    evidence_root: str
    records: Tuple[PersistenceRecord, ...]
    total_records: int
    category_counts: Tuple[Tuple[str, int], ...]
    scope_counts: Tuple[Tuple[str, int], ...]

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary dictionary with category and scope metrics."""
        return {
            "total_records": self.total_records,
            "category_counts": dict(self.category_counts),
            "scope_counts": dict(self.scope_counts),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregate collection to a JSON-serializable dictionary."""
        return {
            "evidence_root": self.evidence_root,
            "summary": self.summary,
            "records": [r.to_dict() for r in self.records],
        }
