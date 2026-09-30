"""
Unified Forensic Host Artifact Adapters for ForensiX (V2.6).

Provides deterministic, read-only adapter functions to convert specialized V2 models
(V2.1 filesystem, V2.2 logs, V2.3 auth, V2.4 accounts/privileges, V2.5 persistence)
into immutable HostArtifact instances and build structured HostArtifactCollection aggregates.

Strict boundaries:
- Zero filesystem I/O
- Zero command execution
- Exact preservation of source paths and relationships
- Strict deep immutability
- Genuinely JSON-serializable outputs
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Optional, Sequence, Tuple

from forensix.account_models import (
    GroupRecord,
    ShadowRecord,
    SshKeyInfo,
    SudoRule,
    UserAccount,
)
from forensix.artifacts import ArtifactRecord
from forensix.auth_models import AuthenticationRecord
from forensix.log_models import LogEvent
from forensix.persistence_models import PersistenceRecord
from forensix.unified_models import (
    HostArtifact,
    HostArtifactCategory,
    HostArtifactCollection,
    SpecializedPayload,
    generate_host_artifact_id,
)


def artifact_record_to_host_artifact(rec: ArtifactRecord) -> HostArtifact:
    """Adapt a V2.1 ArtifactRecord into a unified HostArtifact."""
    if not isinstance(rec, ArtifactRecord):
        raise TypeError(f"Expected ArtifactRecord, got {type(rec).__name__}")
    warnings: Tuple[str, ...] = (rec.error,) if rec.error else ()
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=rec.artifact_id,
        source_event_id=None,
        source_artifact_id=rec.artifact_id,
        category=HostArtifactCategory.FILESYSTEM.value,
        artifact_type=rec.artifact_type,
        source_path=rec.source_path,
        line_number=None,
        raw_data=None,
        specialized_payload=rec,
        status=rec.status,
        warnings=warnings,
    )


def log_event_to_host_artifact(evt: LogEvent) -> HostArtifact:
    """Adapt a V2.2 LogEvent into a unified HostArtifact."""
    if not isinstance(evt, LogEvent):
        raise TypeError(f"Expected LogEvent, got {type(evt).__name__}")
    status = "UNPARSED" if evt.event_type == "unknown_format" else "PARSED"
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=evt.event_id,
        source_event_id=evt.event_id,
        source_artifact_id=evt.source_artifact_id,
        category=HostArtifactCategory.LOG.value,
        artifact_type=evt.event_type,
        source_path=evt.source_path,
        line_number=evt.line_number,
        raw_data=evt.raw_line,
        specialized_payload=evt,
        status=status,
        warnings=(),
    )


def auth_record_to_host_artifact(auth: AuthenticationRecord) -> HostArtifact:
    """Adapt a V2.3 AuthenticationRecord into a unified HostArtifact."""
    if not isinstance(auth, AuthenticationRecord):
        raise TypeError(f"Expected AuthenticationRecord, got {type(auth).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=auth.auth_id,
        source_event_id=auth.event_id,
        source_artifact_id=auth.source_artifact_id,
        category=HostArtifactCategory.AUTHENTICATION.value,
        artifact_type=auth.event_type,
        source_path=auth.source_path,
        line_number=auth.line_number,
        raw_data=auth.raw_line,
        specialized_payload=auth,
        status=auth.status,
        warnings=(),
    )


def user_account_to_host_artifact(user: UserAccount) -> HostArtifact:
    """Adapt a V2.4 UserAccount into a unified HostArtifact."""
    if not isinstance(user, UserAccount):
        raise TypeError(f"Expected UserAccount, got {type(user).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=user.user_id,
        source_event_id=None,
        source_artifact_id=user.source_artifact_id,
        category=HostArtifactCategory.ACCOUNT.value,
        artifact_type="user_account",
        source_path=user.source_path,
        line_number=user.line_number,
        raw_data=user.raw_line,
        specialized_payload=user,
        status="PARSED",
        warnings=(),
    )


def group_record_to_host_artifact(grp: GroupRecord) -> HostArtifact:
    """Adapt a V2.4 GroupRecord into a unified HostArtifact."""
    if not isinstance(grp, GroupRecord):
        raise TypeError(f"Expected GroupRecord, got {type(grp).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=grp.group_id,
        source_event_id=None,
        source_artifact_id=grp.source_artifact_id,
        category=HostArtifactCategory.GROUP.value,
        artifact_type="group",
        source_path=grp.source_path,
        line_number=grp.line_number,
        raw_data=grp.raw_line,
        specialized_payload=grp,
        status="PARSED",
        warnings=(),
    )


def shadow_record_to_host_artifact(shad: ShadowRecord) -> HostArtifact:
    """Adapt a V2.4 ShadowRecord into a unified HostArtifact."""
    if not isinstance(shad, ShadowRecord):
        raise TypeError(f"Expected ShadowRecord, got {type(shad).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=shad.shadow_id,
        source_event_id=None,
        source_artifact_id=shad.source_artifact_id,
        category=HostArtifactCategory.CREDENTIAL_METADATA.value,
        artifact_type="shadow_record",
        source_path=shad.source_path,
        line_number=shad.line_number,
        raw_data=shad.raw_line_redacted,
        specialized_payload=shad,
        status="PARSED",
        warnings=(),
    )


def sudo_rule_to_host_artifact(rule: SudoRule) -> HostArtifact:
    """Adapt a V2.4 SudoRule into a unified HostArtifact."""
    if not isinstance(rule, SudoRule):
        raise TypeError(f"Expected SudoRule, got {type(rule).__name__}")
    warnings = () if rule.is_parsed else ("Unsupported or complex sudoers syntax",)
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=rule.rule_id,
        source_event_id=None,
        source_artifact_id=rule.source_artifact_id,
        category=HostArtifactCategory.PRIVILEGE.value,
        artifact_type="sudo_rule",
        source_path=rule.source_path,
        line_number=rule.line_number,
        raw_data=rule.raw_line,
        specialized_payload=rule,
        status="PARSED" if rule.is_parsed else "UNPARSED",
        warnings=warnings,
    )


def ssh_key_to_host_artifact(key: SshKeyInfo) -> HostArtifact:
    """Adapt a V2.4 SshKeyInfo into a unified HostArtifact."""
    if not isinstance(key, SshKeyInfo):
        raise TypeError(f"Expected SshKeyInfo, got {type(key).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=key.key_id,
        source_event_id=None,
        source_artifact_id=key.source_artifact_id,
        category=HostArtifactCategory.SSH_KEY.value,
        artifact_type="ssh_authorized_key",
        source_path=key.source_path,
        line_number=key.line_number,
        raw_data=key.raw_line,
        specialized_payload=key,
        status="PARSED",
        warnings=(),
    )


def persistence_record_to_host_artifact(persist: PersistenceRecord) -> HostArtifact:
    """Adapt a V2.5 PersistenceRecord into a unified HostArtifact."""
    if not isinstance(persist, PersistenceRecord):
        raise TypeError(f"Expected PersistenceRecord, got {type(persist).__name__}")
    return HostArtifact(
        unified_id=generate_host_artifact_id(),
        source_id=persist.persistence_id,
        source_event_id=None,
        source_artifact_id=persist.source_artifact_id,
        category=HostArtifactCategory.PERSISTENCE.value,
        artifact_type=persist.mechanism,
        source_path=persist.source_path,
        line_number=persist.line_number,
        raw_data=persist.raw_line,
        specialized_payload=persist,
        status=persist.status,
        warnings=(),
    )


def to_host_artifact(record: SpecializedPayload) -> HostArtifact:
    """
    Polymorphic dispatcher to adapt any supported specialized V2 model to a HostArtifact.

    Raises TypeError if an unsupported type or arbitrary object is passed.
    """
    if isinstance(record, ArtifactRecord):
        return artifact_record_to_host_artifact(record)
    elif isinstance(record, LogEvent):
        return log_event_to_host_artifact(record)
    elif isinstance(record, AuthenticationRecord):
        return auth_record_to_host_artifact(record)
    elif isinstance(record, UserAccount):
        return user_account_to_host_artifact(record)
    elif isinstance(record, GroupRecord):
        return group_record_to_host_artifact(record)
    elif isinstance(record, ShadowRecord):
        return shadow_record_to_host_artifact(record)
    elif isinstance(record, SudoRule):
        return sudo_rule_to_host_artifact(record)
    elif isinstance(record, SshKeyInfo):
        return ssh_key_to_host_artifact(record)
    elif isinstance(record, PersistenceRecord):
        return persistence_record_to_host_artifact(record)
    raise TypeError(
        f"Unsupported record type for HostArtifact adaptation: {type(record).__name__}. "
        "Must be a valid V2 forensic result model."
    )


def build_host_artifact_collection(
    evidence_root: str,
    records: Sequence[SpecializedPayload],
    collected_at: Optional[str] = None,
) -> HostArtifactCollection:
    """
    Construct an immutable, deterministically sorted HostArtifactCollection from specialized records.

    Deterministic behavior guarantees:
    - Artifacts are sorted by: (source_path, line_number or 0, category, source_id)
    - Category and status counts are sorted alphabetically by key
    - All structures are deeply immutable and fully JSON-serializable
    """
    if collected_at is None:
        collected_at = datetime.now(timezone.utc).isoformat()

    adapted = [to_host_artifact(rec) for rec in records]

    # Deterministic sorting
    sorted_artifacts = sorted(
        adapted,
        key=lambda art: (
            art.source_path,
            art.line_number if art.line_number is not None else -1,
            art.category,
            art.source_id,
        ),
    )

    cat_counter = Counter(art.category for art in sorted_artifacts)
    stat_counter = Counter(art.status for art in sorted_artifacts)

    # Sort count pairs alphabetically for deterministic summary ordering
    sorted_cat_counts = tuple(sorted(cat_counter.items(), key=lambda x: x[0]))
    sorted_stat_counts = tuple(sorted(stat_counter.items(), key=lambda x: x[0]))

    return HostArtifactCollection(
        evidence_root=str(evidence_root),
        collected_at=collected_at,
        artifacts=tuple(sorted_artifacts),
        total_artifacts=len(sorted_artifacts),
        category_counts=sorted_cat_counts,
        status_counts=sorted_stat_counts,
    )
