"""
Forensic Artifact Identification Engine for ForensiX.

Responsible for identifying and classifying Linux host artifacts based on
relative path patterns within an evidence directory, distinguishing known
forensic artifacts from generic filesystem files.
"""

from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import List, NamedTuple, Tuple, Union

from forensix.artifacts import ArtifactCategory, ArtifactType


class ArtifactRule(NamedTuple):
    """Rule definition for mapping path patterns to artifact classifications."""

    pattern: str
    category: ArtifactCategory
    artifact_type: ArtifactType
    is_glob: bool = False


# Known Linux host artifact rules
ARTIFACT_RULES: List[ArtifactRule] = [
    # Linux Accounts & Groups
    ArtifactRule("etc/passwd", ArtifactCategory.ACCOUNT, ArtifactType.PASSWD),
    ArtifactRule("etc/group", ArtifactCategory.ACCOUNT, ArtifactType.GROUP),
    ArtifactRule("etc/shadow", ArtifactCategory.ACCOUNT, ArtifactType.SHADOW),
    ArtifactRule("etc/gshadow", ArtifactCategory.ACCOUNT, ArtifactType.GROUP),

    # Host & Network Configuration
    ArtifactRule("etc/hosts", ArtifactCategory.HOST_CONFIG, ArtifactType.HOSTS),
    ArtifactRule("etc/hostname", ArtifactCategory.HOST_CONFIG, ArtifactType.HOSTNAME),
    ArtifactRule("etc/resolv.conf", ArtifactCategory.HOST_CONFIG, ArtifactType.RESOLV_CONF),
    ArtifactRule("etc/os-release", ArtifactCategory.HOST_CONFIG, ArtifactType.OS_RELEASE),
    ArtifactRule("usr/lib/os-release", ArtifactCategory.HOST_CONFIG, ArtifactType.OS_RELEASE),
    ArtifactRule("etc/issue", ArtifactCategory.HOST_CONFIG, ArtifactType.ISSUE),
    ArtifactRule("etc/issue.net", ArtifactCategory.HOST_CONFIG, ArtifactType.ISSUE),

    # Authentication & System Logs
    ArtifactRule("var/log/auth.log", ArtifactCategory.LOG, ArtifactType.AUTH_LOG),
    ArtifactRule("var/log/auth.log*", ArtifactCategory.LOG, ArtifactType.AUTH_LOG, is_glob=True),
    ArtifactRule("var/log/secure", ArtifactCategory.LOG, ArtifactType.AUTH_LOG),
    ArtifactRule("var/log/secure*", ArtifactCategory.LOG, ArtifactType.AUTH_LOG, is_glob=True),
    ArtifactRule("var/log/syslog", ArtifactCategory.LOG, ArtifactType.SYSLOG),
    ArtifactRule("var/log/syslog*", ArtifactCategory.LOG, ArtifactType.SYSLOG, is_glob=True),
    ArtifactRule("var/log/messages", ArtifactCategory.LOG, ArtifactType.MESSAGES),
    ArtifactRule("var/log/messages*", ArtifactCategory.LOG, ArtifactType.MESSAGES, is_glob=True),

    # SSH Configurations & Keys
    ArtifactRule("etc/ssh/sshd_config", ArtifactCategory.SSH, ArtifactType.SSH_CONFIG),
    ArtifactRule("etc/ssh/ssh_config", ArtifactCategory.SSH, ArtifactType.SSH_CONFIG),
    ArtifactRule("etc/ssh/*", ArtifactCategory.SSH, ArtifactType.SSH_CONFIG, is_glob=True),
    ArtifactRule("home/*/.ssh/authorized_keys*", ArtifactCategory.SSH, ArtifactType.SSH_AUTHORIZED_KEYS, is_glob=True),
    ArtifactRule("root/.ssh/authorized_keys*", ArtifactCategory.SSH, ArtifactType.SSH_AUTHORIZED_KEYS, is_glob=True),
    ArtifactRule("home/*/.ssh/known_hosts*", ArtifactCategory.SSH, ArtifactType.SSH_KNOWN_HOSTS, is_glob=True),
    ArtifactRule("root/.ssh/known_hosts*", ArtifactCategory.SSH, ArtifactType.SSH_KNOWN_HOSTS, is_glob=True),
    ArtifactRule("home/*/.ssh/id_*", ArtifactCategory.SSH, ArtifactType.SSH_KEY, is_glob=True),
    ArtifactRule("root/.ssh/id_*", ArtifactCategory.SSH, ArtifactType.SSH_KEY, is_glob=True),
    ArtifactRule("home/*/.ssh/*", ArtifactCategory.SSH, ArtifactType.SSH_CONFIG, is_glob=True),
    ArtifactRule("root/.ssh/*", ArtifactCategory.SSH, ArtifactType.SSH_CONFIG, is_glob=True),

    # User Space Artifacts
    ArtifactRule("home/*/*", ArtifactCategory.USER_FS, ArtifactType.USER_FILE, is_glob=True),
    ArtifactRule("root/*", ArtifactCategory.USER_FS, ArtifactType.USER_FILE, is_glob=True),
]


def normalize_relative_path(path: Union[str, Path, PurePosixPath]) -> str:
    """
    Normalize a path relative to the evidence root into a standard POSIX string.

    Strips leading slashes, dot-slashes, and redundant segments.
    """
    as_str = str(path).replace("\\", "/")
    # Remove leading slashes and dot-slashes
    while as_str.startswith("./") or as_str.startswith("/"):
        if as_str.startswith("./"):
            as_str = as_str[2:]
        elif as_str.startswith("/"):
            as_str = as_str[1:]
    return as_str


def identify_artifact(
    relative_path: Union[str, Path, PurePosixPath]
) -> Tuple[ArtifactCategory, ArtifactType, bool]:
    """
    Identify and classify a relative artifact path.

    Evaluates the path against known Linux artifact rules.
    If no rule matches, returns (GENERIC, GENERIC_FILE, False).

    Args:
        relative_path: Path relative to evidence root.

    Returns:
        Tuple of (ArtifactCategory, ArtifactType, is_known).
    """
    normalized = normalize_relative_path(relative_path)

    # 1. Exact match pass
    for rule in ARTIFACT_RULES:
        if not rule.is_glob and normalized == rule.pattern:
            return rule.category, rule.artifact_type, True

    # 2. Glob match pass
    for rule in ARTIFACT_RULES:
        if rule.is_glob and fnmatch(normalized, rule.pattern):
            return rule.category, rule.artifact_type, True

    # 3. Fallback generic filesystem artifact
    return ArtifactCategory.GENERIC, ArtifactType.GENERIC_FILE, False
