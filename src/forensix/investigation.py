"""
Forensic Investigation and Analysis Interface for ForensiX (V2.7).

Provides strongly typed, deeply immutable in-memory query, filtering, search,
and cross-reference traversal capabilities over the Unified Host Artifact Model
(HostArtifact and HostArtifactCollection).

Strict boundaries:
- In-memory only; zero filesystem I/O
- Zero command execution, subprocesses, or network access
- Zero mutation of source artifacts
- Exact source path matching (no normalization or path alteration)
- Explicit searchable field set for textual search
- Purely factual relationship traversal based on explicit source/event/artifact IDs
- Fully JSON-serializable result sets
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

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
    freeze_value,
)

VALID_CATEGORIES = frozenset(c.value for c in HostArtifactCategory)


def artifact_sort_key(art: HostArtifact) -> Tuple[Any, ...]:
    """Deterministic ordering key for host artifacts."""
    return (
        art.source_path,
        art.line_number if art.line_number is not None else -1,
        art.category,
        art.artifact_type,
        art.source_id,
        art.unified_id,
    )


def extract_searchable_strings(art: HostArtifact) -> List[str]:
    """
    Extract factual strings from a host artifact and its specialized payload.

    Restricted strictly to documented factual fields.
    """
    strings: List[str] = []
    if art.raw_data:
        strings.append(art.raw_data)

    payload = art.specialized_payload
    if isinstance(payload, LogEvent):
        for field in (payload.raw_line, payload.raw_message, payload.service, payload.hostname):
            if field:
                strings.append(field)
    elif isinstance(payload, AuthenticationRecord):
        for field in (
            payload.raw_line,
            payload.raw_message,
            payload.username,
            payload.source_ip,
            payload.service,
            payload.hostname,
        ):
            if field:
                strings.append(field)
    elif isinstance(payload, UserAccount):
        for field in (
            payload.username,
            payload.gecos,
            payload.home_directory,
            payload.login_shell,
            payload.raw_line,
        ):
            if field:
                strings.append(field)
    elif isinstance(payload, GroupRecord):
        if payload.group_name:
            strings.append(payload.group_name)
        if payload.raw_line:
            strings.append(payload.raw_line)
        for m in payload.members:
            if m:
                strings.append(m)
    elif isinstance(payload, ShadowRecord):
        if payload.username:
            strings.append(payload.username)
        if payload.raw_line_redacted:
            strings.append(payload.raw_line_redacted)
    elif isinstance(payload, SudoRule):
        for field in (
            payload.user_spec,
            payload.host_spec,
            payload.runas_spec,
            payload.raw_line,
        ):
            if field:
                strings.append(field)
        for cmd in payload.commands:
            if cmd:
                strings.append(cmd)
        for opt in payload.options:
            if opt:
                strings.append(opt)
    elif isinstance(payload, SshKeyInfo):
        for field in (payload.associated_user, payload.key_type, payload.comment, payload.raw_line):
            if field:
                strings.append(field)
    elif isinstance(payload, PersistenceRecord):
        for field in (
            payload.target_user,
            payload.trigger_or_schedule,
            payload.command_or_path,
            payload.raw_line,
        ):
            if field:
                strings.append(field)
    elif isinstance(payload, ArtifactRecord):
        for field in (payload.source_path, payload.relative_path):
            if field:
                strings.append(field)

    return strings


@dataclass(frozen=True)
class ArtifactQuery:
    """
    Immutable specification of filter criteria for querying host artifacts.
    """

    category: Optional[Union[str, HostArtifactCategory]] = None
    artifact_type: Optional[str] = None
    source_id: Optional[str] = None
    source_path: Optional[str] = None
    path_exact: bool = True
    line_number: Optional[int] = None
    status: Optional[str] = None
    search_text: Optional[str] = None
    case_sensitive: bool = False
    source_event_id: Optional[str] = None
    source_artifact_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate all query criteria strictly."""
        if self.category is not None:
            if isinstance(self.category, HostArtifactCategory):
                object.__setattr__(self, "category", self.category.value)
            elif isinstance(self.category, str):
                if self.category not in VALID_CATEGORIES:
                    raise ValueError(
                        f"Invalid category: {self.category!r}. "
                        f"Must be one of: {sorted(VALID_CATEGORIES)}"
                    )
            else:
                raise TypeError(
                    f"category must be str or HostArtifactCategory, got {type(self.category).__name__}"
                )

        if self.artifact_type is not None:
            if not isinstance(self.artifact_type, str):
                raise TypeError(f"artifact_type must be str, got {type(self.artifact_type).__name__}")
            if not self.artifact_type.strip():
                raise ValueError("artifact_type cannot be empty or whitespace")

        if self.source_id is not None:
            if not isinstance(self.source_id, str):
                raise TypeError(f"source_id must be str, got {type(self.source_id).__name__}")
            if not self.source_id.strip():
                raise ValueError("source_id cannot be empty or whitespace")

        if self.source_path is not None:
            if not isinstance(self.source_path, str):
                raise TypeError(f"source_path must be str, got {type(self.source_path).__name__}")
            if not self.source_path.strip():
                raise ValueError("source_path cannot be empty or whitespace")

        if not isinstance(self.path_exact, bool):
            raise TypeError(f"path_exact must be bool, got {type(self.path_exact).__name__}")

        if self.line_number is not None:
            if not isinstance(self.line_number, int) or isinstance(self.line_number, bool):
                raise TypeError(f"line_number must be an int, got {type(self.line_number).__name__}")
            if self.line_number <= 0:
                raise ValueError(f"line_number must be positive, got {self.line_number}")

        if self.status is not None:
            if not isinstance(self.status, str):
                raise TypeError(f"status must be str, got {type(self.status).__name__}")
            if not self.status.strip():
                raise ValueError("status cannot be empty or whitespace")

        if self.search_text is not None:
            if not isinstance(self.search_text, str):
                raise TypeError(f"search_text must be str, got {type(self.search_text).__name__}")
            if not self.search_text.strip():
                raise ValueError("search_text cannot be empty or whitespace")

        if not isinstance(self.case_sensitive, bool):
            raise TypeError(f"case_sensitive must be bool, got {type(self.case_sensitive).__name__}")

        if self.source_event_id is not None:
            if not isinstance(self.source_event_id, str):
                raise TypeError(f"source_event_id must be str, got {type(self.source_event_id).__name__}")
            if not self.source_event_id.strip():
                raise ValueError("source_event_id cannot be empty or whitespace")

        if self.source_artifact_id is not None:
            if not isinstance(self.source_artifact_id, str):
                raise TypeError(f"source_artifact_id must be str, got {type(self.source_artifact_id).__name__}")
            if not self.source_artifact_id.strip():
                raise ValueError("source_artifact_id cannot be empty or whitespace")

    def to_dict(self) -> Dict[str, Any]:
        """Convert query parameters to a JSON-serializable dictionary."""
        return {
            "category": self.category,
            "artifact_type": self.artifact_type,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "path_exact": self.path_exact,
            "line_number": self.line_number,
            "status": self.status,
            "search_text": self.search_text,
            "case_sensitive": self.case_sensitive,
            "source_event_id": self.source_event_id,
            "source_artifact_id": self.source_artifact_id,
        }


@dataclass(frozen=True)
class InvestigationResultSet:
    """
    Immutable, deterministically ordered result container for an investigation query.
    """

    query: Optional[ArtifactQuery]
    artifacts: Tuple[HostArtifact, ...]
    total_matches: int
    category_breakdown: Tuple[Tuple[str, int], ...]
    status_breakdown: Tuple[Tuple[str, int], ...]

    def __post_init__(self) -> None:
        """Enforce deep immutability on results and breakdowns."""
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.category_breakdown, tuple):
            object.__setattr__(self, "category_breakdown", freeze_value(self.category_breakdown))
        if not isinstance(self.status_breakdown, tuple):
            object.__setattr__(self, "status_breakdown", freeze_value(self.status_breakdown))

    @property
    def summary(self) -> Dict[str, Any]:
        """Return summary metrics with category and status counts in stable key order."""
        return {
            "total_matches": self.total_matches,
            "category_breakdown": dict(self.category_breakdown),
            "status_breakdown": dict(self.status_breakdown),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert result set to a fully JSON-serializable dictionary."""
        return {
            "total_matches": self.total_matches,
            "summary": self.summary,
            "query": self.query.to_dict() if self.query else None,
            "artifacts": [art.to_dict() for art in self.artifacts],
        }

    def __iter__(self) -> Iterator[HostArtifact]:
        return iter(self.artifacts)

    def __len__(self) -> int:
        return len(self.artifacts)

    def __getitem__(self, index: int) -> HostArtifact:
        return self.artifacts[index]

    # Composability / Chaining methods
    def filter_by_category(self, category: Union[str, HostArtifactCategory]) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).filter_by_category(category)

    def filter_by_type(self, artifact_type: str) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).filter_by_type(artifact_type)

    def filter_by_source_path(self, source_path: str, exact: bool = True) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).filter_by_source_path(source_path, exact=exact)

    def filter_by_status(self, status: str) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).filter_by_status(status)

    def filter_by_line(self, line_number: int) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).filter_by_line(line_number)

    def search_text(self, text: str, case_sensitive: bool = False) -> "InvestigationResultSet":
        return HostArtifactInvestigator(self.artifacts).search_text(text, case_sensitive=case_sensitive)


class HostArtifactInvestigator:
    """
    In-memory investigation and query engine operating over unified host artifacts.
    """

    def __init__(self, target: Union[HostArtifactCollection, Sequence[HostArtifact]]) -> None:
        """Initialize investigator with validated HostArtifact instances."""
        if isinstance(target, HostArtifactCollection):
            self._artifacts: Tuple[HostArtifact, ...] = target.artifacts
        elif isinstance(target, (list, tuple)):
            for idx, item in enumerate(target):
                if not isinstance(item, HostArtifact):
                    raise TypeError(
                        f"Item at index {idx} is {type(item).__name__}, expected HostArtifact"
                    )
            self._artifacts = tuple(target)
        else:
            raise TypeError(
                f"target must be HostArtifactCollection or Sequence[HostArtifact], got {type(target).__name__}"
            )

        # Build in-memory lookup indexes
        self._by_unified_id: Dict[str, HostArtifact] = {}
        self._by_source_id: Dict[str, List[HostArtifact]] = defaultdict(list)
        self._by_source_path: Dict[str, List[HostArtifact]] = defaultdict(list)

        for art in self._artifacts:
            self._by_unified_id[art.unified_id] = art
            self._by_source_id[art.source_id].append(art)
            self._by_source_path[art.source_path].append(art)

    def get_by_unified_id(self, unified_id: str) -> Optional[HostArtifact]:
        """Direct O(1) lookup of a HostArtifact by its unified_id (HOSTART-xxx)."""
        if not isinstance(unified_id, str):
            raise TypeError(f"unified_id must be str, got {type(unified_id).__name__}")
        return self._by_unified_id.get(unified_id)

    def get_by_source_id(self, source_id: str) -> Tuple[HostArtifact, ...]:
        """Direct lookup of artifacts by specialized source ID (e.g. ART-, EVT-, AUTH-)."""
        if not isinstance(source_id, str):
            raise TypeError(f"source_id must be str, got {type(source_id).__name__}")
        matches = self._by_source_id.get(source_id, [])
        return tuple(sorted(matches, key=artifact_sort_key))

    def get_related_artifacts(self, record_id: str) -> InvestigationResultSet:
        """
        Retrieve all artifacts related to a given record ID via direct source relationships.

        Follows existing V2.6 lineage (matching source_id, source_event_id, or source_artifact_id).
        Does not perform speculative correlation or causal inference.
        """
        if not isinstance(record_id, str):
            raise TypeError(f"record_id must be str, got {type(record_id).__name__}")
        if not record_id.strip():
            raise ValueError("record_id cannot be empty or whitespace")

        matches: List[HostArtifact] = []
        for art in self._artifacts:
            if (
                art.source_id == record_id
                or art.source_event_id == record_id
                or art.source_artifact_id == record_id
            ):
                matches.append(art)

        return self._build_result(matches, query=None)

    def get_artifacts_for_file(self, source_path: str) -> InvestigationResultSet:
        """Retrieve all host artifacts associated with an exact source path."""
        return self.filter_by_source_path(source_path, exact=True)

    def filter_by_category(self, category: Union[str, HostArtifactCategory]) -> InvestigationResultSet:
        """Filter artifacts matching a specific HostArtifactCategory."""
        query = ArtifactQuery(category=category)
        return self.query(query)

    def filter_by_type(self, artifact_type: str) -> InvestigationResultSet:
        """Filter artifacts matching a canonical V2.6 artifact_type."""
        query = ArtifactQuery(artifact_type=artifact_type)
        return self.query(query)

    def filter_by_source_path(self, source_path: str, exact: bool = True) -> InvestigationResultSet:
        """Filter artifacts matching a source path (exact or substring)."""
        query = ArtifactQuery(source_path=source_path, path_exact=exact)
        return self.query(query)

    def filter_by_status(self, status: str) -> InvestigationResultSet:
        """Filter artifacts matching an analyzer status (e.g. PARSED, UNPARSED, MALFORMED)."""
        query = ArtifactQuery(status=status)
        return self.query(query)

    def filter_by_line(self, line_number: int) -> InvestigationResultSet:
        """Filter artifacts recorded at a specific line number."""
        query = ArtifactQuery(line_number=line_number)
        return self.query(query)

    def search_text(self, text: str, case_sensitive: bool = False) -> InvestigationResultSet:
        """
        Search textual/raw content across documented factual fields of artifacts.
        """
        query = ArtifactQuery(search_text=text, case_sensitive=case_sensitive)
        return self.query(query)

    def query(self, query: Optional[ArtifactQuery] = None, **kwargs: Any) -> InvestigationResultSet:
        """
        Execute a compound query against the in-memory host artifact collection.

        Combines all provided criteria via logical AND.
        """
        if query is None:
            query = ArtifactQuery(**kwargs)
        elif kwargs:
            raise ValueError("Pass either an ArtifactQuery instance or keyword arguments, not both")

        matches: List[HostArtifact] = []
        search_target = query.search_text if query.case_sensitive else (
            query.search_text.lower() if query.search_text else None
        )

        for art in self._artifacts:
            # 1. Category filter
            if query.category is not None and art.category != query.category:
                continue

            # 2. Artifact type filter (canonical V2.6 string)
            if query.artifact_type is not None and art.artifact_type != query.artifact_type:
                continue

            # 3. Source ID filter
            if query.source_id is not None and art.source_id != query.source_id:
                continue

            # 4. Source path filter (no normalization)
            if query.source_path is not None:
                if query.path_exact:
                    if art.source_path != query.source_path:
                        continue
                else:
                    if query.source_path not in art.source_path:
                        continue

            # 5. Line number filter
            if query.line_number is not None and art.line_number != query.line_number:
                continue

            # 6. Status filter
            if query.status is not None and art.status != query.status:
                continue

            # 7. Source event ID filter
            if query.source_event_id is not None and art.source_event_id != query.source_event_id:
                continue

            # 8. Source artifact ID filter
            if query.source_artifact_id is not None and art.source_artifact_id != query.source_artifact_id:
                continue

            # 9. Search text filter (over documented factual fields)
            if search_target is not None:
                fields = extract_searchable_strings(art)
                matched = False
                for f in fields:
                    comp = f if query.case_sensitive else f.lower()
                    if search_target in comp:
                        matched = True
                        break
                if not matched:
                    continue

            matches.append(art)

        return self._build_result(matches, query=query)

    def get_category_counts(self) -> Dict[str, int]:
        """Return counts of artifacts grouped by category."""
        return dict(Counter(a.category for a in self._artifacts))

    def get_status_counts(self) -> Dict[str, int]:
        """Return counts of artifacts grouped by status."""
        return dict(Counter(a.status for a in self._artifacts))

    def total_artifacts(self) -> int:
        """Return total number of loaded host artifacts."""
        return len(self._artifacts)

    def _build_result(
        self, matches: List[HostArtifact], query: Optional[ArtifactQuery]
    ) -> InvestigationResultSet:
        """Construct a deterministically sorted, immutable InvestigationResultSet."""
        sorted_matches = sorted(matches, key=artifact_sort_key)
        cat_counts = tuple(sorted(Counter(a.category for a in sorted_matches).items(), key=lambda x: x[0]))
        stat_counts = tuple(sorted(Counter(a.status for a in sorted_matches).items(), key=lambda x: x[0]))

        return InvestigationResultSet(
            query=query,
            artifacts=tuple(sorted_matches),
            total_matches=len(sorted_matches),
            category_breakdown=cat_counts,
            status_breakdown=stat_counts,
        )
