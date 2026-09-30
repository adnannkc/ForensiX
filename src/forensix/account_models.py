"""
Forensic Account, Group, and Privilege Models for ForensiX (V2.4).

Provides strongly typed, immutable dataclasses representing discovered Linux accounts,
groups, shadow metadata (with protected credentials), sudo rules, and SSH public keys.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple
import uuid


def generate_user_id() -> str:
    """Generate a unique tracking identifier for a user account (USER-<UUIDv4>)."""
    return f"USER-{uuid.uuid4()}"


def generate_group_id() -> str:
    """Generate a unique tracking identifier for a group record (GRP-<UUIDv4>)."""
    return f"GRP-{uuid.uuid4()}"


def generate_shadow_id() -> str:
    """Generate a unique tracking identifier for a shadow entry (SHAD-<UUIDv4>)."""
    return f"SHAD-{uuid.uuid4()}"


def generate_sudo_rule_id() -> str:
    """Generate a unique tracking identifier for a sudo rule (SUDO-<UUIDv4>)."""
    return f"SUDO-{uuid.uuid4()}"


def generate_ssh_key_id() -> str:
    """Generate a unique tracking identifier for an SSH public key (SSHKEY-<UUIDv4>)."""
    return f"SSHKEY-{uuid.uuid4()}"


@dataclass(frozen=True)
class UserAccount:
    """
    Immutable representation of a Linux user account derived from /etc/passwd.

    Forensic notes on raw_line:
        raw_line is the decoded line as read by V2.2. Valid UTF-8 preserves
        the original text; invalid UTF-8 bytes may be represented by Unicode
        replacement characters according to the V2.2 decoding policy.
    """

    user_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    username: str
    uid: int
    gid: int
    gecos: str
    home_directory: str
    login_shell: str
    is_privileged: bool
    primary_group: Optional[str]
    supplementary_groups: Tuple[str, ...]
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert user account to a JSON-serializable dictionary."""
        return {
            "user_id": self.user_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "gecos": self.gecos,
            "home_directory": self.home_directory,
            "login_shell": self.login_shell,
            "is_privileged": self.is_privileged,
            "primary_group": self.primary_group,
            "supplementary_groups": list(self.supplementary_groups),
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class GroupRecord:
    """
    Immutable representation of a Linux group derived from /etc/group.
    """

    group_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    group_name: str
    gid: int
    members: Tuple[str, ...]
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert group record to a JSON-serializable dictionary."""
        return {
            "group_id": self.group_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "group_name": self.group_name,
            "gid": self.gid,
            "members": list(self.members),
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class ShadowRecord:
    """
    Immutable representation of sanitized metadata from /etc/shadow.

    Security & Forensic Policy:
        Raw password hashes are never exposed in user-facing models or reports.
        Only factual account states (locked, empty, algorithm hint) are retained.
    """

    shadow_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    username: str
    has_password: bool
    is_locked: bool
    is_empty: bool
    hash_algorithm: Optional[str]
    last_changed_days: Optional[int]
    raw_line_redacted: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert shadow record to a JSON-serializable dictionary."""
        return {
            "shadow_id": self.shadow_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "username": self.username,
            "has_password": self.has_password,
            "is_locked": self.is_locked,
            "is_empty": self.is_empty,
            "hash_algorithm": self.hash_algorithm,
            "last_changed_days": self.last_changed_days,
            "raw_line_redacted": self.raw_line_redacted,
        }


@dataclass(frozen=True)
class SudoRule:
    """
    Immutable representation of a parsed or unparsed sudo privilege specification.

    If the rule syntax is unsupported or complex (e.g. User_Alias or non-standard syntax),
    is_parsed is False, user_spec is 'UNPARSED', and the complete raw line is preserved.
    """

    rule_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    is_parsed: bool
    user_spec: str
    host_spec: Optional[str]
    runas_spec: Optional[str]
    commands: Tuple[str, ...]
    options: Tuple[str, ...]
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert sudo rule to a JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "is_parsed": self.is_parsed,
            "user_spec": self.user_spec,
            "host_spec": self.host_spec,
            "runas_spec": self.runas_spec,
            "commands": list(self.commands),
            "options": list(self.options),
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class SshKeyInfo:
    """
    Immutable representation of an authorized SSH public key artifact.
    """

    key_id: str
    source_artifact_id: Optional[str]
    source_path: str
    line_number: int
    associated_user: Optional[str]
    key_type: str
    comment: Optional[str]
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert SSH key info to a JSON-serializable dictionary."""
        return {
            "key_id": self.key_id,
            "source_artifact_id": self.source_artifact_id,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "associated_user": self.associated_user,
            "key_type": self.key_type,
            "comment": self.comment,
            "raw_line": self.raw_line,
        }


@dataclass(frozen=True)
class AccountCollectionResult:
    """
    Immutable representation of aggregate account, group, and privilege discovery.
    """

    evidence_root: str
    users: Tuple[UserAccount, ...]
    groups: Tuple[GroupRecord, ...]
    shadow_records: Tuple[ShadowRecord, ...]
    sudo_rules: Tuple[SudoRule, ...]
    ssh_keys: Tuple[SshKeyInfo, ...]
    total_users: int
    privileged_users_count: int
    total_groups: int
    total_shadow_records: int
    total_sudo_rules: int
    total_ssh_keys: int

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metric counts."""
        return {
            "total_users": self.total_users,
            "privileged_users_count": self.privileged_users_count,
            "total_groups": self.total_groups,
            "total_shadow_records": self.total_shadow_records,
            "total_sudo_rules": self.total_sudo_rules,
            "total_ssh_keys": self.total_ssh_keys,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregate collection to a JSON-serializable dictionary."""
        return {
            "evidence_root": self.evidence_root,
            "summary": self.summary,
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "shadow_records": [s.to_dict() for s in self.shadow_records],
            "sudo_rules": [r.to_dict() for r in self.sudo_rules],
            "ssh_keys": [k.to_dict() for k in self.ssh_keys],
        }
