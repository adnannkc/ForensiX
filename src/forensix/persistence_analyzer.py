"""
Forensic Persistence Analyzer for ForensiX (V2.5 Persistence Artifacts).

Responsible for identifying, extracting, and cataloging persistence-capable Linux
configurations (systemd units/timers, cron/anacron, init/rc.local, shell startup files,
XDG autostart, dynamic loader preload, and kernel module configuration) while preserving
evidence immutability, maintaining source traceability, and avoiding execution.
"""

from collections import Counter
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from forensix.identifier import normalize_relative_path
from forensix.persistence_models import (
    PersistenceCategory,
    PersistenceCollectionResult,
    PersistenceRecord,
    generate_persistence_id,
)

# Standard cron line regex (5 time fields + command or user + command)
RE_CRON_FIELDS = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
RE_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.*$")
RE_SPECIAL_CRON = re.compile(r"^@([A-Za-z]+)\s+(.*)$")

# Modprobe directives
MODPROBE_DIRECTIVES = {"options", "blacklist", "alias", "install", "remove", "softdep"}


def parse_systemd_unit_file(
    file_path: Union[str, Path],
    relative_path: str,
    scope: str = "system",
    target_user: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Parse a systemd unit configuration file (.service, .timer, .socket, etc.).

    Forensic Safety & Relationship Separation:
    - Never calls systemctl or queries the active system.
    - Strictly separates scheduling directives (OnCalendar, OnBootSec) from
      enablement relationships (WantedBy, RequiredBy) and ordering (After, Before).
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    unit_name = target.name
    unit_suffix = target.suffix.lower()

    if unit_suffix == ".service":
        mechanism = "systemd_service"
    elif unit_suffix == ".timer":
        mechanism = "systemd_timer"
    elif unit_suffix == ".socket":
        mechanism = "systemd_socket"
    else:
        mechanism = "systemd_unit"

    records: List[PersistenceRecord] = []

    current_section: Optional[str] = None
    exec_starts: List[Tuple[int, str]] = []  # (line_num, cmd)
    exec_pres: List[str] = []
    exec_posts: List[str] = []
    timer_triggers: List[Tuple[int, str, str]] = []  # (line_num, directive, val)
    user_val: Optional[str] = target_user
    group_val: Optional[str] = None
    wanted_by: List[str] = []
    required_by: List[str] = []
    after_val: List[str] = []
    before_val: List[str] = []
    unit_target: Optional[str] = None

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue

            if stripped.startswith("[") and stripped.endswith("]"):
                current_section = stripped[1:-1].strip()
                continue

            if "=" not in stripped:
                continue

            key, val = stripped.split("=", 1)
            key = key.strip()
            val = val.strip()

            if current_section == "Service":
                if key == "ExecStart":
                    exec_starts.append((line_num, val))
                elif key == "ExecStartPre":
                    exec_pres.append(val)
                elif key == "ExecStartPost":
                    exec_posts.append(val)
                elif key == "User":
                    user_val = val
                elif key == "Group":
                    group_val = val

            elif current_section == "Timer":
                if key in (
                    "OnCalendar",
                    "OnBootSec",
                    "OnStartupSec",
                    "OnUnitActiveSec",
                    "OnUnitInactiveSec",
                    "RandomizedDelaySec",
                ):
                    timer_triggers.append((line_num, key, val))
                elif key == "Unit":
                    unit_target = val

            elif current_section == "Install":
                if key == "WantedBy":
                    wanted_by.extend(val.split())
                elif key == "RequiredBy":
                    required_by.extend(val.split())

            elif current_section == "Unit":
                if key == "After":
                    after_val.extend(val.split())
                elif key == "Before":
                    before_val.extend(val.split())

    # Build base attributes tuple
    base_attrs: List[Tuple[str, Any]] = [
        ("unit_name", unit_name),
        ("unit_suffix", unit_suffix),
    ]
    if user_val:
        base_attrs.append(("user", user_val))
    if group_val:
        base_attrs.append(("group", group_val))
    if wanted_by:
        base_attrs.append(("wanted_by", tuple(wanted_by)))
    if required_by:
        base_attrs.append(("required_by", tuple(required_by)))
    if after_val:
        base_attrs.append(("after", tuple(after_val)))
    if before_val:
        base_attrs.append(("before", tuple(before_val)))

    # For Service units
    if unit_suffix == ".service":
        if exec_starts:
            for line_num, cmd in exec_starts:
                attrs = list(base_attrs)
                if exec_pres:
                    attrs.append(("exec_start_pre", tuple(exec_pres)))
                if exec_posts:
                    attrs.append(("exec_start_post", tuple(exec_posts)))

                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.SYSTEMD.value,
                        mechanism=mechanism,
                        scope=scope,
                        target_user=user_val,
                        trigger_or_schedule=None,
                        command_or_path=cmd,
                        attributes=tuple(attrs),
                        status="PARSED",
                        raw_line=f"ExecStart={cmd}",
                    )
                )
        else:
            # Service unit without explicit ExecStart
            records.append(
                PersistenceRecord(
                    persistence_id=generate_persistence_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=None,
                    category=PersistenceCategory.SYSTEMD.value,
                    mechanism=mechanism,
                    scope=scope,
                    target_user=user_val,
                    trigger_or_schedule=None,
                    command_or_path=None,
                    attributes=tuple(base_attrs),
                    status="PARSED",
                    raw_line=None,
                )
            )

    # For Timer units
    elif unit_suffix == ".timer":
        if timer_triggers:
            for line_num, directive, val in timer_triggers:
                attrs = list(base_attrs)
                attrs.append(("timer_directive", directive))
                if unit_target:
                    attrs.append(("target_unit", unit_target))

                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.SYSTEMD.value,
                        mechanism=mechanism,
                        scope=scope,
                        target_user=user_val,
                        trigger_or_schedule=f"{directive}={val}",
                        command_or_path=unit_target,
                        attributes=tuple(attrs),
                        status="PARSED",
                        raw_line=f"{directive}={val}",
                    )
                )
        else:
            records.append(
                PersistenceRecord(
                    persistence_id=generate_persistence_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=None,
                    category=PersistenceCategory.SYSTEMD.value,
                    mechanism=mechanism,
                    scope=scope,
                    target_user=user_val,
                    trigger_or_schedule=None,
                    command_or_path=unit_target,
                    attributes=tuple(base_attrs),
                    status="PARSED",
                    raw_line=None,
                )
            )

    # Other units (sockets, targets, etc.)
    else:
        records.append(
            PersistenceRecord(
                persistence_id=generate_persistence_id(),
                source_artifact_id=artifact_id,
                source_path=str(target),
                line_number=None,
                category=PersistenceCategory.SYSTEMD.value,
                mechanism=mechanism,
                scope=scope,
                target_user=user_val,
                trigger_or_schedule=None,
                command_or_path=None,
                attributes=tuple(base_attrs),
                status="PARSED",
                raw_line=None,
            )
        )

    return records


def parse_cron_file(
    file_path: Union[str, Path],
    relative_path: str,
    is_system_cron: bool = False,
    default_user: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Parse a cron configuration file (/etc/crontab, /etc/cron.d/*, or user crontabs).

    Strict distinction:
    - Environment assignments (PATH=...) receive mechanism='cron_env', status='PARSED'.
    - Valid cron jobs receive mechanism='crontab', status='PARSED'.
    - Only corrupted job syntax receives status='MALFORMED'.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    records: List[PersistenceRecord] = []
    scope = "system" if is_system_cron else "user"

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 1. Environment assignment (e.g. PATH=/bin:/usr/bin)
            if RE_ENV_ASSIGN.match(stripped):
                var_name, var_val = stripped.split("=", 1)
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.CRON.value,
                        mechanism="cron_env",
                        scope=scope,
                        target_user=default_user,
                        trigger_or_schedule=None,
                        command_or_path=stripped,
                        attributes=(
                            ("variable", var_name.strip()),
                            ("value", var_val.strip()),
                        ),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
                continue

            # 2. Special schedules (@reboot, @daily, etc.)
            spec_match = RE_SPECIAL_CRON.match(stripped)
            if spec_match:
                special_tag = f"@{spec_match.group(1)}"
                rest = spec_match.group(2).strip()

                if is_system_cron:
                    tokens = rest.split(None, 1)
                    if len(tokens) == 2:
                        target_user, cmd = tokens[0], tokens[1]
                    else:
                        target_user, cmd = default_user, rest
                else:
                    target_user, cmd = default_user, rest

                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.CRON.value,
                        mechanism="crontab",
                        scope=scope,
                        target_user=target_user,
                        trigger_or_schedule=special_tag,
                        command_or_path=cmd,
                        attributes=(("special_schedule", special_tag),),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
                continue

            # 3. Standard 5-field cron expression
            fields_match = RE_CRON_FIELDS.match(stripped)
            if fields_match:
                min_f, hr_f, dom_f, mon_f, dow_f, rest = (
                    fields_match.group(1),
                    fields_match.group(2),
                    fields_match.group(3),
                    fields_match.group(4),
                    fields_match.group(5),
                    fields_match.group(6),
                )
                schedule_expr = f"{min_f} {hr_f} {dom_f} {mon_f} {dow_f}"

                if is_system_cron:
                    tokens = rest.split(None, 1)
                    if len(tokens) == 2:
                        job_user, cmd = tokens[0], tokens[1]
                    else:
                        job_user, cmd = default_user, rest
                else:
                    job_user = default_user
                    cmd = rest

                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.CRON.value,
                        mechanism="crontab",
                        scope=scope,
                        target_user=job_user,
                        trigger_or_schedule=schedule_expr,
                        command_or_path=cmd,
                        attributes=(("schedule", schedule_expr),),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
            else:
                # Malformed cron line
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.CRON.value,
                        mechanism="crontab",
                        scope=scope,
                        target_user=default_user,
                        trigger_or_schedule=None,
                        command_or_path=None,
                        attributes=(),
                        status="MALFORMED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )

    return records


def parse_anacron_file(
    file_path: Union[str, Path],
    relative_path: str,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """Parse /etc/anacrontab period, delay, job identifier, and command."""
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    records: List[PersistenceRecord] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if RE_ENV_ASSIGN.match(stripped):
                var_name, var_val = stripped.split("=", 1)
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.ANACRON.value,
                        mechanism="anacron_env",
                        scope="system",
                        target_user="root",
                        trigger_or_schedule=None,
                        command_or_path=stripped,
                        attributes=(
                            ("variable", var_name.strip()),
                            ("value", var_val.strip()),
                        ),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
                continue

            tokens = stripped.split(None, 3)
            if len(tokens) == 4:
                period, delay, job_id, cmd = tokens[0], tokens[1], tokens[2], tokens[3]
                sched = f"period={period} delay={delay}"
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.ANACRON.value,
                        mechanism="anacrontab",
                        scope="system",
                        target_user="root",
                        trigger_or_schedule=sched,
                        command_or_path=cmd,
                        attributes=(
                            ("period", period),
                            ("delay", delay),
                            ("job_id", job_id),
                        ),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
            else:
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.ANACRON.value,
                        mechanism="anacrontab",
                        scope="system",
                        target_user="root",
                        trigger_or_schedule=None,
                        command_or_path=None,
                        attributes=(),
                        status="MALFORMED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )

    return records


def parse_init_script_or_rc(
    file_path: Union[str, Path],
    relative_path: str,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Conservative extraction of traditional init scripts (/etc/init.d/*, /etc/rc.local).

    Extracts shebang and selected non-comment lines without executing or emulating shell.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    shebang: Optional[str] = None
    selected_lines: List[Tuple[int, str]] = []

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if line_num == 1 and stripped.startswith("#!"):
                shebang = stripped
                continue

            if not stripped or stripped.startswith("#"):
                continue

            # Record selected non-comment, non-empty configuration lines
            if len(selected_lines) < 25:
                selected_lines.append((line_num, stripped))

    records: List[PersistenceRecord] = []
    attrs: List[Tuple[str, Any]] = [("script_name", target.name)]
    if shebang:
        attrs.append(("shebang", shebang))

    if selected_lines:
        for line_num, content in selected_lines:
            records.append(
                PersistenceRecord(
                    persistence_id=generate_persistence_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=line_num,
                    category=PersistenceCategory.INIT_SCRIPT.value,
                    mechanism="init_script",
                    scope="system",
                    target_user="root",
                    trigger_or_schedule="startup",
                    command_or_path=content,
                    attributes=tuple(attrs),
                    status="PARSED",
                    raw_line=content,
                )
            )
    else:
        records.append(
            PersistenceRecord(
                persistence_id=generate_persistence_id(),
                source_artifact_id=artifact_id,
                source_path=str(target),
                line_number=1,
                category=PersistenceCategory.INIT_SCRIPT.value,
                mechanism="init_script",
                scope="system",
                target_user="root",
                trigger_or_schedule="startup",
                command_or_path=str(target),
                attributes=tuple(attrs),
                status="PARSED",
                raw_line=shebang,
            )
        )

    return records


def parse_shell_startup_file(
    file_path: Union[str, Path],
    relative_path: str,
    target_user: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Conservative extraction of selected non-comment configuration lines from shell startup files.

    Forensic Notice:
    - Does NOT attempt to implement a full shell parser.
    - Captures selected non-comment lines (export, alias, source, command lines).
    - Never executes shell content.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    scope = "system" if ("etc" in target.parts and "home" not in target.parts) else "user"
    records: List[PersistenceRecord] = []

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Identify selected configuration directives
            directive_hint = "command"
            if stripped.startswith("export "):
                directive_hint = "export"
            elif stripped.startswith("alias "):
                directive_hint = "alias"
            elif stripped.startswith("source ") or stripped.startswith(". "):
                directive_hint = "source"

            records.append(
                PersistenceRecord(
                    persistence_id=generate_persistence_id(),
                    source_artifact_id=artifact_id,
                    source_path=str(target),
                    line_number=line_num,
                    category=PersistenceCategory.SHELL_STARTUP.value,
                    mechanism="shell_startup",
                    scope=scope,
                    target_user=target_user,
                    trigger_or_schedule="shell_login",
                    command_or_path=stripped,
                    attributes=(
                        ("directive_type", directive_hint),
                        ("config_file", target.name),
                    ),
                    status="PARSED",
                    raw_line=line.rstrip("\r\n"),
                )
            )

    return records


def parse_xdg_autostart_file(
    file_path: Union[str, Path],
    relative_path: str,
    scope: str = "system",
    target_user: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Extract configuration from XDG desktop autostart entry (.desktop).
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    name_val: Optional[str] = None
    exec_val: Optional[str] = None
    type_val: Optional[str] = None
    hidden_val: Optional[str] = None
    only_show_in: Optional[str] = None
    not_show_in: Optional[str] = None
    exec_line_num: Optional[int] = None

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue

            key, val = stripped.split("=", 1)
            key = key.strip()
            val = val.strip()

            if key == "Name":
                name_val = val
            elif key == "Exec":
                exec_val = val
                exec_line_num = line_num
            elif key == "Type":
                type_val = val
            elif key == "Hidden":
                hidden_val = val
            elif key == "OnlyShowIn":
                only_show_in = val
            elif key == "NotShowIn":
                not_show_in = val

    attrs: List[Tuple[str, Any]] = [("desktop_file", target.name)]
    if name_val:
        attrs.append(("name", name_val))
    if type_val:
        attrs.append(("type", type_val))
    if hidden_val:
        attrs.append(("hidden", hidden_val))
    if only_show_in:
        attrs.append(("only_show_in", only_show_in))
    if not_show_in:
        attrs.append(("not_show_in", not_show_in))

    return [
        PersistenceRecord(
            persistence_id=generate_persistence_id(),
            source_artifact_id=artifact_id,
            source_path=str(target),
            line_number=exec_line_num,
            category=PersistenceCategory.XDG_AUTOSTART.value,
            mechanism="desktop_autostart",
            scope=scope,
            target_user=target_user,
            trigger_or_schedule="desktop_login",
            command_or_path=exec_val,
            attributes=tuple(attrs),
            status="PARSED",
            raw_line=f"Exec={exec_val}" if exec_val else None,
        )
    ]


def parse_ld_preload_file(
    file_path: Union[str, Path],
    relative_path: str,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """Parse /etc/ld.so.preload library entries as observed configuration data."""
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    records: List[PersistenceRecord] = []
    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for lib in stripped.split():
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.DYNAMIC_LOADER.value,
                        mechanism="ld_preload",
                        scope="system",
                        target_user="root",
                        trigger_or_schedule="dynamic_link",
                        command_or_path=lib,
                        attributes=(("library_path", lib),),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )

    return records


def parse_kernel_module_config(
    file_path: Union[str, Path],
    relative_path: str,
    artifact_id: Optional[str] = None,
) -> List[PersistenceRecord]:
    """
    Parse kernel module configuration.

    Strict distinction:
    - /etc/modules and /etc/modules-load.d/* -> mechanism='kernel_module_load'.
    - /etc/modprobe.d/* -> mechanism='modprobe_directive'.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return []

    is_modprobe = "modprobe" in target.parts or "modprobe.d" in str(target)
    mechanism = "modprobe_directive" if is_modprobe else "kernel_module_load"
    records: List[PersistenceRecord] = []

    with target.open(mode="rt", encoding="utf-8", errors="replace") as stream:
        for line_num, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            tokens = stripped.split(None, 2)
            if is_modprobe:
                directive = tokens[0]
                mod_name = tokens[1] if len(tokens) > 1 else ""
                options_str = tokens[2] if len(tokens) > 2 else ""

                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.KERNEL_MODULE.value,
                        mechanism=mechanism,
                        scope="system",
                        target_user="root",
                        trigger_or_schedule="module_probe",
                        command_or_path=mod_name,
                        attributes=(
                            ("directive", directive),
                            ("module", mod_name),
                            ("options", options_str),
                        ),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )
            else:
                module_name = tokens[0]
                records.append(
                    PersistenceRecord(
                        persistence_id=generate_persistence_id(),
                        source_artifact_id=artifact_id,
                        source_path=str(target),
                        line_number=line_num,
                        category=PersistenceCategory.KERNEL_MODULE.value,
                        mechanism=mechanism,
                        scope="system",
                        target_user="root",
                        trigger_or_schedule="boot",
                        command_or_path=module_name,
                        attributes=(("module_name", module_name),),
                        status="PARSED",
                        raw_line=line.rstrip("\r\n"),
                    )
                )

    return records


def analyze_persistence_artifacts(
    evidence_root: Union[str, Path],
) -> PersistenceCollectionResult:
    """
    Orchestrate safe, recursive discovery and cataloging of persistence-capable artifacts.

    Forensic Safety:
    - Never executes evidence content or invokes live host tools.
    - Blocks and skips out-of-bounds symlinks.
    - Maintains deterministic lexicographical ordering.
    """
    root = Path(evidence_root).resolve()
    records: List[PersistenceRecord] = []

    def safe_rel(p: Path) -> str:
        return normalize_relative_path(p.relative_to(root))

    def is_contained(p: Path) -> bool:
        try:
            p.resolve().relative_to(root)
            return True
        except (ValueError, RuntimeError):
            return False

    # 1. Systemd System Units and Enablement Symlinks
    systemd_dirs = [
        root / "etc" / "systemd" / "system",
        root / "lib" / "systemd" / "system",
        root / "usr" / "lib" / "systemd" / "system",
        root / "run" / "systemd" / "system",
    ]
    for sdir in sorted(systemd_dirs):
        if sdir.exists() and sdir.is_dir():
            for entry in sorted(sdir.glob("**/*")):
                if not is_contained(entry):
                    continue

                # Check for enablement symlinks (e.g. multi-user.target.wants/example.service)
                if entry.is_symlink() and any(
                    part.endswith(".wants") or part.endswith(".requires")
                    for part in entry.parts
                ):
                    try:
                        raw_link = os.readlink(entry)
                        records.append(
                            PersistenceRecord(
                                persistence_id=generate_persistence_id(),
                                source_artifact_id=None,
                                source_path=str(entry),
                                line_number=None,
                                category=PersistenceCategory.SYSTEMD.value,
                                mechanism="systemd_enablement_symlink",
                                scope="system",
                                target_user="root",
                                trigger_or_schedule=None,
                                command_or_path=raw_link,
                                attributes=(
                                    ("symlink_name", entry.name),
                                    ("wants_directory", entry.parent.name),
                                    ("symlink_target", raw_link),
                                ),
                                status="PARSED",
                                raw_line=f"{entry.name} -> {raw_link}",
                            )
                        )
                    except OSError:
                        pass
                elif entry.is_file() and entry.suffix in (".service", ".timer", ".socket"):
                    records.extend(
                        parse_systemd_unit_file(
                            file_path=entry,
                            relative_path=safe_rel(entry),
                            scope="system",
                        )
                    )

    # 2. Systemd User Units
    user_systemd_roots = [
        (root / "root" / ".config" / "systemd" / "user", "root"),
    ]
    home_dir = root / "home"
    if home_dir.exists() and home_dir.is_dir():
        for ufolder in sorted(home_dir.glob("*")):
            if ufolder.is_dir():
                user_systemd_roots.append(
                    (ufolder / ".config" / "systemd" / "user", ufolder.name)
                )

    for udir, uname in user_systemd_roots:
        if udir.exists() and udir.is_dir():
            for entry in sorted(udir.glob("**/*")):
                if not is_contained(entry):
                    continue
                if entry.is_file() and entry.suffix in (".service", ".timer", ".socket"):
                    records.extend(
                        parse_systemd_unit_file(
                            file_path=entry,
                            relative_path=safe_rel(entry),
                            scope="user",
                            target_user=uname,
                        )
                    )

    # 3. Cron & Anacron
    crontab_file = root / "etc" / "crontab"
    if crontab_file.exists() and is_contained(crontab_file):
        records.extend(
            parse_cron_file(
                crontab_file,
                safe_rel(crontab_file),
                is_system_cron=True,
                default_user="root",
            )
        )

    cron_d = root / "etc" / "cron.d"
    if cron_d.exists() and cron_d.is_dir():
        for cfile in sorted(cron_d.glob("*")):
            if cfile.is_file() and is_contained(cfile) and not cfile.name.startswith("."):
                records.extend(
                    parse_cron_file(
                        cfile,
                        safe_rel(cfile),
                        is_system_cron=True,
                        default_user="root",
                    )
                )

    user_cron_dirs = [
        root / "var" / "spool" / "cron" / "crontabs",
        root / "var" / "spool" / "cron",
    ]
    seen_user_crons = set()
    for ucd in user_cron_dirs:
        if ucd.exists() and ucd.is_dir():
            for cfile in sorted(ucd.glob("*")):
                if cfile.is_file() and is_contained(cfile) and cfile.name not in seen_user_crons:
                    seen_user_crons.add(cfile.name)
                    records.extend(
                        parse_cron_file(
                            cfile,
                            safe_rel(cfile),
                            is_system_cron=False,
                            default_user=cfile.name,
                        )
                    )

    anacron_file = root / "etc" / "anacrontab"
    if anacron_file.exists() and is_contained(anacron_file):
        records.extend(parse_anacron_file(anacron_file, safe_rel(anacron_file)))

    # 4. Init scripts & rc.local
    rc_local = root / "etc" / "rc.local"
    if rc_local.exists() and is_contained(rc_local):
        records.extend(parse_init_script_or_rc(rc_local, safe_rel(rc_local)))

    init_d = root / "etc" / "init.d"
    if init_d.exists() and init_d.is_dir():
        for ifile in sorted(init_d.glob("*")):
            if ifile.is_file() and is_contained(ifile) and not ifile.name.startswith("."):
                records.extend(parse_init_script_or_rc(ifile, safe_rel(ifile)))

    # 5. Shell startup files
    system_shell_files = [
        root / "etc" / "profile",
        root / "etc" / "bash.bashrc",
    ]
    for sf in system_shell_files:
        if sf.exists() and is_contained(sf):
            records.extend(parse_shell_startup_file(sf, safe_rel(sf), target_user="root"))

    profile_d = root / "etc" / "profile.d"
    if profile_d.exists() and profile_d.is_dir():
        for pf in sorted(profile_d.glob("*")):
            if pf.is_file() and is_contained(pf) and not pf.name.startswith("."):
                records.extend(parse_shell_startup_file(pf, safe_rel(pf), target_user="root"))

    user_shell_targets = [
        (root / "root", "root"),
    ]
    if home_dir.exists() and home_dir.is_dir():
        for ufolder in sorted(home_dir.glob("*")):
            if ufolder.is_dir():
                user_shell_targets.append((ufolder, ufolder.name))

    shell_filenames = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile")
    for udir, uname in user_shell_targets:
        for sfn in shell_filenames:
            sf = udir / sfn
            if sf.exists() and is_contained(sf) and sf.is_file():
                records.extend(parse_shell_startup_file(sf, safe_rel(sf), target_user=uname))

    # 6. XDG Autostart
    xdg_sys = root / "etc" / "xdg" / "autostart"
    if xdg_sys.exists() and xdg_sys.is_dir():
        for df in sorted(xdg_sys.glob("*.desktop")):
            if df.is_file() and is_contained(df):
                records.extend(
                    parse_xdg_autostart_file(
                        df, safe_rel(df), scope="system", target_user="all"
                    )
                )

    for udir, uname in user_shell_targets:
        user_auto = udir / ".config" / "autostart"
        if user_auto.exists() and user_auto.is_dir():
            for df in sorted(user_auto.glob("*.desktop")):
                if df.is_file() and is_contained(df):
                    records.extend(
                        parse_xdg_autostart_file(
                            df, safe_rel(df), scope="user", target_user=uname
                        )
                    )

    # 7. Dynamic loader preload
    ld_preload = root / "etc" / "ld.so.preload"
    if ld_preload.exists() and is_contained(ld_preload):
        records.extend(parse_ld_preload_file(ld_preload, safe_rel(ld_preload)))

    # 8. Kernel modules
    modules_file = root / "etc" / "modules"
    if modules_file.exists() and is_contained(modules_file):
        records.extend(parse_kernel_module_config(modules_file, safe_rel(modules_file)))

    modules_d = root / "etc" / "modules-load.d"
    if modules_d.exists() and modules_d.is_dir():
        for mf in sorted(modules_d.glob("*.conf")):
            if mf.is_file() and is_contained(mf):
                records.extend(parse_kernel_module_config(mf, safe_rel(mf)))

    modprobe_d = root / "etc" / "modprobe.d"
    if modprobe_d.exists() and modprobe_d.is_dir():
        for mf in sorted(modprobe_d.glob("*.conf")):
            if mf.is_file() and is_contained(mf):
                records.extend(parse_kernel_module_config(mf, safe_rel(mf)))

    cat_counter = Counter(r.category for r in records)
    scope_counter = Counter(r.scope for r in records)

    cat_counts_tuple = tuple(sorted(cat_counter.items()))
    scope_counts_tuple = tuple(sorted(scope_counter.items()))

    return PersistenceCollectionResult(
        evidence_root=str(root),
        records=tuple(records),
        total_records=len(records),
        category_counts=cat_counts_tuple,
        scope_counts=scope_counts_tuple,
    )
