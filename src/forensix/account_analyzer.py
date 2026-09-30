"""
Forensic Account, Group, and Privilege Analyzer for ForensiX (V2.4).

Responsible for parsing, correlating, and structuring Linux identity and privilege
evidence from /etc/passwd, /etc/group, /etc/shadow, sudoers, and SSH authorized_keys
while preserving evidence immutability and separating observed facts from derived data.
"""

from collections import defaultdict
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from forensix.account_models import (
    AccountCollectionResult,
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
    generate_group_id,
    generate_shadow_id,
    generate_ssh_key_id,
    generate_sudo_rule_id,
    generate_user_id,
)

# Standard sudo rule: user/group host = (runas) [TAGS:] commands
RE_SUDO_SPEC = re.compile(
    r"^([^\s=]+)\s+([A-Za-z0-9_.*-]+)\s*=\s*(?:\(([^)]+)\)\s*)?(.*)$"
)

# Common SSH public key types
KNOWN_SSH_KEY_TYPES = {
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


def parse_passwd_file(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
) -> List[UserAccount]:
    """
    Parse Linux user account records from /etc/passwd.

    Fields expected: username:password:uid:gid:gecos:home:shell
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    users: List[UserAccount] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            fields = stripped.split(":")
            if len(fields) != 7:
                # Malformed entry; skip safely to avoid corrupting records
                continue

            try:
                uid = int(fields[2])
                gid = int(fields[3])
            except ValueError:
                # Malformed non-integer UID/GID
                continue

            is_privileged = (uid == 0)

            users.append(
                UserAccount(
                    user_id=generate_user_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=line_num,
                    username=fields[0],
                    uid=uid,
                    gid=gid,
                    gecos=fields[4],
                    home_directory=fields[5],
                    login_shell=fields[6],
                    is_privileged=is_privileged,
                    primary_group=None,
                    supplementary_groups=(),
                    raw_line=line.rstrip("\r\n"),
                )
            )

    return users


def parse_group_file(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
) -> List[GroupRecord]:
    """
    Parse Linux group records from /etc/group.

    Fields expected: group_name:password:gid:member1,member2,...
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    groups: List[GroupRecord] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            fields = stripped.split(":")
            if len(fields) != 4:
                continue

            try:
                gid = int(fields[2])
            except ValueError:
                continue

            members_raw = fields[3]
            members = tuple(m.strip() for m in members_raw.split(",") if m.strip())

            groups.append(
                GroupRecord(
                    group_id=generate_group_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=line_num,
                    group_name=fields[0],
                    gid=gid,
                    members=members,
                    raw_line=line.rstrip("\r\n"),
                )
            )

    return groups


def parse_shadow_file(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
) -> List[ShadowRecord]:
    """
    Safely extract account state metadata from /etc/shadow without exposing hashes.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    records: List[ShadowRecord] = []
    try:
        with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
            for line_num, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                fields = stripped.split(":")
                if len(fields) < 2:
                    continue

                username = fields[0]
                hash_val = fields[1]

                is_locked = hash_val.startswith("!") or hash_val.startswith("*")
                is_empty = (len(hash_val) == 0)
                has_password = not is_locked and not is_empty

                # Derive hash algorithm prefix without exposing raw hash string
                hash_algorithm: Optional[str] = None
                clean_hash = hash_val.lstrip("!*")
                if clean_hash.startswith("$6$"):
                    hash_algorithm = "SHA-512 ($6$)"
                elif clean_hash.startswith("$y$"):
                    hash_algorithm = "yescrypt ($y$)"
                elif clean_hash.startswith("$5$"):
                    hash_algorithm = "SHA-256 ($5$)"
                elif clean_hash.startswith("$1$"):
                    hash_algorithm = "MD5 ($1$)"
                elif clean_hash.startswith("$2a$") or clean_hash.startswith("$2b$"):
                    hash_algorithm = "bcrypt"

                last_changed_days: Optional[int] = None
                if len(fields) > 2 and fields[2].isdigit():
                    last_changed_days = int(fields[2])

                # Protect password hash: replace with [REDACTED] in raw line
                redacted_fields = list(fields)
                redacted_fields[1] = "[REDACTED]"
                redacted_line = ":".join(redacted_fields)

                records.append(
                    ShadowRecord(
                        shadow_id=generate_shadow_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        username=username,
                        has_password=has_password,
                        is_locked=is_locked,
                        is_empty=is_empty,
                        hash_algorithm=hash_algorithm,
                        last_changed_days=last_changed_days,
                        raw_line_redacted=redacted_line,
                    )
                )
    except (PermissionError, OSError):
        # Gracefully handle unreadable shadow
        return []

    return records


def parse_sudoers_line(
    line: str,
    line_number: int,
    source_path: str,
    artifact_id: Optional[str] = None,
) -> Optional[SudoRule]:
    """
    Parse a single sudoers line.

    Unsupported, alias, or complex syntax remains is_parsed=False with user_spec='UNPARSED'.
    Comments and empty lines return None.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    rule_id = generate_sudo_rule_id()

    # Skip Defaults lines entirely
    if stripped.startswith("Defaults"):
        return None

    # Check for Alias constructs (User_Alias, Runas_Alias, Host_Alias, Cmnd_Alias)
    # These represent complex syntax that must remain UNPARSED rather than pseudo-parsed
    if any(stripped.startswith(alias_prefix) for alias_prefix in ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias")):
        return SudoRule(
            rule_id=rule_id,
            source_artifact_id=artifact_id,
            source_path=source_path,
            line_number=line_number,
            is_parsed=False,
            user_spec="UNPARSED",
            host_spec=None,
            runas_spec=None,
            commands=(),
            options=(),
            raw_line=line.rstrip("\r\n"),
        )

    match = RE_SUDO_SPEC.match(stripped)
    if not match:
        # Complex or unsupported syntax: retain as UNPARSED
        return SudoRule(
            rule_id=rule_id,
            source_artifact_id=artifact_id,
            source_path=source_path,
            line_number=line_number,
            is_parsed=False,
            user_spec="UNPARSED",
            host_spec=None,
            runas_spec=None,
            commands=(),
            options=(),
            raw_line=line.rstrip("\r\n"),
        )

    user_spec = match.group(1)
    host_spec = match.group(2)
    runas_raw = match.group(3)
    cmd_section = match.group(4).strip()

    runas_spec = f"({runas_raw})" if runas_raw else "ALL"

    options: List[str] = []
    commands: List[str] = []

    # Parse tags such as NOPASSWD:, PASSWD:, NOEXEC:
    tokens = cmd_section.split()
    cmd_tokens: List[str] = []
    for token in tokens:
        if token.endswith(":") and token[:-1].upper() in ("NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV"):
            options.append(token[:-1].upper())
        else:
            cmd_tokens.append(token)

    cmd_str = " ".join(cmd_tokens).strip()
    if cmd_str:
        # Split multiple commands separated by comma
        for c in cmd_str.split(","):
            c_clean = c.strip()
            if c_clean:
                commands.append(c_clean)
    else:
        commands.append("ALL")

    return SudoRule(
        rule_id=rule_id,
        source_artifact_id=artifact_id,
        source_path=source_path,
        line_number=line_number,
        is_parsed=True,
        user_spec=user_spec,
        host_spec=host_spec,
        runas_spec=runas_spec,
        commands=tuple(commands),
        options=tuple(options),
        raw_line=line.rstrip("\r\n"),
    )


def parse_sudoers_file(
    file_path: Union[str, Path],
    artifact_id: Optional[str] = None,
) -> List[SudoRule]:
    """Parse all sudo rules from a sudoers or sudoers.d configuration file."""
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    rules: List[SudoRule] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            rule = parse_sudoers_line(
                line=line,
                line_number=line_num,
                source_path=str(target),
                artifact_id=artifact_id,
            )
            if rule is not None:
                rules.append(rule)

    return rules


def parse_authorized_keys_file(
    file_path: Union[str, Path],
    associated_user: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> List[SshKeyInfo]:
    """
    Extract public key metadata from an SSH authorized_keys file.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    keys: List[SshKeyInfo] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split()
            key_type = "unknown"
            comment = None

            # Standard format: [options] <key_type> <base64_key> [comment]
            for idx, part in enumerate(parts):
                if part in KNOWN_SSH_KEY_TYPES:
                    key_type = part
                    if len(parts) > idx + 2:
                        comment = " ".join(parts[idx + 2 :])
                    break

            keys.append(
                SshKeyInfo(
                    key_id=generate_ssh_key_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=line_num,
                    associated_user=associated_user,
                    key_type=key_type,
                    comment=comment,
                    raw_line=line.rstrip("\r\n"),
                )
            )

    return keys


def resolve_user_group_relationships(
    users: List[UserAccount],
    groups: List[GroupRecord],
) -> List[UserAccount]:
    """
    Link primary and supplementary group names to each UserAccount.
    """
    gid_to_name: Dict[int, str] = {g.gid: g.group_name for g in groups}
    user_supplementary: Dict[str, List[str]] = defaultdict(list)

    for g in groups:
        for member in g.members:
            user_supplementary[member].append(g.group_name)

    updated_users: List[UserAccount] = []
    for u in users:
        primary_group = gid_to_name.get(u.gid)
        supplementary = tuple(sorted(set(user_supplementary.get(u.username, []))))

        updated_users.append(
            UserAccount(
                user_id=u.user_id,
                source_artifact_id=u.source_artifact_id,
                source_path=u.source_path,
                line_number=u.line_number,
                username=u.username,
                uid=u.uid,
                gid=u.gid,
                gecos=u.gecos,
                home_directory=u.home_directory,
                login_shell=u.login_shell,
                is_privileged=u.is_privileged,
                primary_group=primary_group,
                supplementary_groups=supplementary,
                raw_line=u.raw_line,
            )
        )

    return updated_users


def analyze_account_artifacts(
    evidence_root: Union[str, Path],
) -> AccountCollectionResult:
    """
    Orchestrate full account, group, shadow, sudoers, and SSH key discovery from evidence.

    Args:
        evidence_root: Path to the root directory of host evidence.

    Returns:
        AccountCollectionResult: Immutable aggregate discovery of users, groups, and privileges.
    """
    root = Path(evidence_root).resolve()

    # 1. Parse /etc/passwd
    raw_users = parse_passwd_file(root / "etc" / "passwd")

    # 2. Parse /etc/group
    groups = parse_group_file(root / "etc" / "group")

    # 3. Correlate user & group relationships
    users = resolve_user_group_relationships(raw_users, groups)

    # 4. Parse /etc/shadow
    shadow_records = parse_shadow_file(root / "etc" / "shadow")

    # 5. Parse sudoers and sudoers.d/*
    sudo_rules: List[SudoRule] = []
    main_sudoers = root / "etc" / "sudoers"
    if main_sudoers.exists():
        sudo_rules.extend(parse_sudoers_file(main_sudoers))

    sudoers_d = root / "etc" / "sudoers.d"
    if sudoers_d.exists() and sudoers_d.is_dir():
        for conf_file in sorted(sudoers_d.glob("*")):
            if conf_file.is_file() and not conf_file.name.startswith("."):
                sudo_rules.extend(parse_sudoers_file(conf_file))

    # 6. Parse SSH authorized_keys across user homes and root
    ssh_keys: List[SshKeyInfo] = []

    # Check root .ssh
    root_auth = root / "root" / ".ssh" / "authorized_keys"
    if root_auth.exists():
        ssh_keys.extend(parse_authorized_keys_file(root_auth, associated_user="root"))

    # Check /home/*/.ssh/authorized_keys
    home_dir = root / "home"
    if home_dir.exists() and home_dir.is_dir():
        for user_folder in sorted(home_dir.glob("*")):
            if user_folder.is_dir():
                user_auth = user_folder / ".ssh" / "authorized_keys"
                if user_auth.exists():
                    ssh_keys.extend(
                        parse_authorized_keys_file(
                            user_auth,
                            associated_user=user_folder.name,
                        )
                    )

    privileged_count = sum(1 for u in users if u.is_privileged)

    return AccountCollectionResult(
        evidence_root=str(root),
        users=tuple(users),
        groups=tuple(groups),
        shadow_records=tuple(shadow_records),
        sudo_rules=tuple(sudo_rules),
        ssh_keys=tuple(ssh_keys),
        total_users=len(users),
        privileged_users_count=privileged_count,
        total_groups=len(groups),
        total_shadow_records=len(shadow_records),
        total_sudo_rules=len(sudo_rules),
        total_ssh_keys=len(ssh_keys),
    )
