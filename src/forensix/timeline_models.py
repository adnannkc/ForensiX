"""
Forensic Timeline Event Models for ForensiX (V3.1 Timeline Reconstruction).

Provides strongly typed, deeply immutable dataclasses representing individual chronological
forensic observations derived from specialized V2 models (filesystem artifacts, logs,
authentication activity, user accounts, and persistence configurations) without duplicating
parsing logic or introducing speculative detection or event correlation.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
import uuid

class TimelineCategory(str, Enum):
    """Broad forensic categorization for timeline events corresponding to V2 sources."""

    FILESYSTEM = "filesystem"
    LOG = "log"
    AUTHENTICATION = "authentication"
    ACCOUNT = "account"
    PERSISTENCE = "persistence"


def generate_timeline_id() -> str:
    """Generate a unique tracking identifier for a timeline event (TIMELINE-<UUIDv4>)."""
    return f"TIMELINE-{uuid.uuid4()}"


class _FrozenList(tuple):
    """Immutable tuple marker representing a frozen list."""
    pass


class _FrozenDict(tuple):
    """Immutable tuple marker representing a frozen dict with sorted (key, value) pairs."""
    pass


def freeze_attributes(val: Any) -> Any:
    """
    Recursively freeze attribute structures into immutable tuples while preserving types.

    Guarantees:
    - Dicts are sorted by key for deterministic ordering and marked as _FrozenDict.
    - Lists are marked as _FrozenList.
    - Sets are sorted for deterministic ordering and marked as _FrozenList.
    - Scalars (bool, int, float, str, None) are preserved as-is.
    """
    if val is None:
        return _FrozenDict()
    if isinstance(val, dict):
        return _FrozenDict((k, freeze_attributes(v)) for k, v in sorted(val.items()))
    elif isinstance(val, set):
        try:
            sorted_items = sorted(val)
        except TypeError:
            sorted_items = sorted(val, key=str)
        return _FrozenList(freeze_attributes(item) for item in sorted_items)
    elif isinstance(val, list):
        return _FrozenList(freeze_attributes(item) for item in val)
    elif isinstance(val, tuple):
        if val and all(isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str) for x in val):
            return _FrozenDict((k, freeze_attributes(v)) for k, v in sorted(val))
        return tuple(freeze_attributes(item) for item in val)
    return val


def unfreeze_to_dict(val: Any) -> Any:
    """
    Recursively convert frozen attribute structures back into JSON-serializable types.

    Guarantees:
    - _FrozenDict converts to dict with sorted keys.
    - _FrozenList converts to list (including empty []).
    - Falsy scalar values (False, 0, 0.0, "") are preserved exactly without alteration.
    - None is preserved.
    """
    if isinstance(val, _FrozenDict):
        return {k: unfreeze_to_dict(v) for k, v in val}
    elif isinstance(val, _FrozenList):
        return [unfreeze_to_dict(item) for item in val]
    elif isinstance(val, tuple):
        if val and all(isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str) for x in val):
            return {k: unfreeze_to_dict(v) for k, v in val}
        return [unfreeze_to_dict(item) for item in val]
    elif isinstance(val, dict):
        return {k: unfreeze_to_dict(v) for k, v in sorted(val.items())}
    elif isinstance(val, list):
        return [unfreeze_to_dict(item) for item in val]
    return val


@dataclass(frozen=True)
class TimelineEvent:
    """
    Immutable forensic representation of a single chronological observation.

    Answers the foundational forensic questions:
    1. What happened? -> description, event_type
    2. When did it happen? -> timestamp (typed datetime or None), raw_timestamp
    3. What category/type of event is it? -> category (TimelineCategory), event_type
    4. Where did the observation come from? -> source_path, source_line (line_number)
    5. Which V2 artifact/event produced it? -> source_artifact_id, source_event_id
    6. What original information supports it? -> raw_data (raw_line), attributes

    Strict boundaries:
    - Factual observation representation only
    - No attack-chain detection or speculation
    - No event correlation or clustering
    - No risk or severity scoring
    - No compromise determination
    - Deeply immutable
    - Deterministic JSON-safe serialization
    """

    event_id: str
    timestamp: Optional[datetime]
    category: TimelineCategory
    event_type: str
    description: str
    source_path: Optional[str] = None
    source_line: Optional[int] = None
    source_artifact_id: Optional[str] = None
    source_event_id: Optional[str] = None
    raw_timestamp: Optional[str] = None
    raw_data: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        event_id: Optional[str] = None,
        timestamp: Optional[Union[datetime, str]] = None,
        category: Optional[Union[TimelineCategory, str]] = None,
        event_type: Optional[str] = None,
        description: Optional[str] = None,
        source_path: Optional[Union[str, Path]] = None,
        source_line: Optional[int] = None,
        source_artifact_id: Optional[str] = None,
        source_event_id: Optional[str] = None,
        raw_timestamp: Optional[str] = None,
        raw_data: Optional[str] = None,
        attributes: Any = (),
        *,
        line_number: Optional[int] = None,
        raw_line: Optional[str] = None,
    ) -> None:
        if category is None:
            raise TypeError("TimelineEvent missing required argument: 'category'")
        if isinstance(category, TimelineCategory):
            validated_category = category
        elif isinstance(category, str):
            cat_str = category.strip().lower()
            try:
                validated_category = TimelineCategory(cat_str)
            except ValueError:
                valid_cats = sorted([c.value for c in TimelineCategory])
                raise ValueError(
                    f"Invalid timeline category: '{category}'. Must be one of: {valid_cats}"
                )
        else:
            raise TypeError(
                f"category must be TimelineCategory or str, got {type(category).__name__}"
            )

        if event_type is None:
            raise TypeError("TimelineEvent missing required argument: 'event_type'")
        if not isinstance(event_type, str):
            raise TypeError(f"event_type must be a string, got {type(event_type).__name__}")
        clean_event_type = event_type.strip()
        if not clean_event_type:
            raise ValueError("event_type must be a non-empty string")

        disallowed_types = {
            "attack_detected",
            "compromise_confirmed",
            "malware_executed",
            "threat_detected",
            "incident_confirmed",
            "anomaly_detected",
        }
        if clean_event_type.lower() in disallowed_types:
            raise ValueError(
                f"Speculative or interpretive event type '{event_type}' is disallowed in V3.1. "
                "Timeline events represent factual forensic observations, not investigative conclusions."
            )

        if description is None:
            raise TypeError("TimelineEvent missing required argument: 'description'")
        if not isinstance(description, str):
            raise TypeError(f"description must be a string, got {type(description).__name__}")
        clean_description = description.strip()
        if not clean_description:
            raise ValueError("description must be a non-empty string")

        if event_id is None:
            validated_event_id = generate_timeline_id()
        elif not isinstance(event_id, str):
            raise TypeError(f"event_id must be a string or None, got {type(event_id).__name__}")
        else:
            clean_event_id = event_id.strip()
            if not clean_event_id:
                raise ValueError("event_id must not be empty")
            if not clean_event_id.startswith("TIMELINE-"):
                raise ValueError(f"event_id must start with 'TIMELINE-', got '{event_id}'")
            uuid_part = clean_event_id[len("TIMELINE-"):]
            try:
                val = uuid.UUID(uuid_part)
                if val.version != 4:
                    raise ValueError(
                        f"event_id UUID must be version 4, got version {val.version}"
                    )
            except (ValueError, AttributeError) as err:
                raise ValueError(
                    f"event_id must contain a valid UUIDv4, got '{event_id}'"
                ) from err
            validated_event_id = clean_event_id

        validated_timestamp: Optional[datetime] = None
        if timestamp is not None:
            if isinstance(timestamp, datetime):
                validated_timestamp = timestamp
            elif isinstance(timestamp, str):
                try:
                    validated_timestamp = datetime.fromisoformat(timestamp)
                except Exception as err:
                    raise ValueError(
                        f"Invalid or ambiguous timestamp string '{timestamp}'. "
                        "TimelineEvent requires a typed datetime or valid ISO 8601 string. "
                        "Do not infer dates from incomplete or ambiguous timestamps."
                    ) from err
            else:
                raise TypeError(
                    f"timestamp must be a datetime, valid ISO string, or None, got {type(timestamp).__name__}"
                )

        validated_raw_timestamp: Optional[str] = None
        if raw_timestamp is not None:
            if not isinstance(raw_timestamp, str):
                raise TypeError(f"raw_timestamp must be a string or None, got {type(raw_timestamp).__name__}")
            validated_raw_timestamp = raw_timestamp

        validated_source_path: Optional[str] = None
        if source_path is not None:
            if isinstance(source_path, (str, Path)):
                validated_source_path = str(source_path)
            else:
                raise TypeError(f"source_path must be a string, Path, or None, got {type(source_path).__name__}")

        chosen_line = source_line if source_line is not None else line_number
        if source_line is not None and line_number is not None and source_line != line_number:
            raise ValueError(f"Conflicting values provided for source_line ({source_line}) and line_number ({line_number})")
        validated_line: Optional[int] = None
        if chosen_line is not None:
            if isinstance(chosen_line, bool) or not isinstance(chosen_line, int):
                raise TypeError(f"source_line/line_number must be an integer, got {type(chosen_line).__name__}")
            if chosen_line < 1:
                raise ValueError(f"source_line/line_number must be >= 1 (1-indexed), got {chosen_line}")
            validated_line = chosen_line

        validated_source_artifact_id: Optional[str] = None
        if source_artifact_id is not None:
            if not isinstance(source_artifact_id, str):
                raise TypeError(f"source_artifact_id must be a string or None, got {type(source_artifact_id).__name__}")
            clean_aid = source_artifact_id.strip()
            if not clean_aid:
                raise ValueError("source_artifact_id must be a non-empty string or None")
            validated_source_artifact_id = clean_aid

        validated_source_event_id: Optional[str] = None
        if source_event_id is not None:
            if not isinstance(source_event_id, str):
                raise TypeError(f"source_event_id must be a string or None, got {type(source_event_id).__name__}")
            clean_eid = source_event_id.strip()
            if not clean_eid:
                raise ValueError("source_event_id must be a non-empty string or None")
            validated_source_event_id = clean_eid

        chosen_raw = raw_data if raw_data is not None else raw_line
        if raw_data is not None and raw_line is not None and raw_data != raw_line:
            raise ValueError("Conflicting values provided for raw_data and raw_line")
        validated_raw_data: Optional[str] = None
        if chosen_raw is not None:
            if not isinstance(chosen_raw, str):
                raise TypeError(f"raw_data/raw_line must be a string or None, got {type(chosen_raw).__name__}")
            validated_raw_data = chosen_raw

        if attributes is None or (isinstance(attributes, (dict, tuple, list)) and len(attributes) == 0):
            frozen_attributes: Tuple[Tuple[str, Any], ...] = _FrozenDict()
        elif isinstance(attributes, dict):
            frozen_attributes = freeze_attributes(attributes)
        elif isinstance(attributes, (tuple, list)):
            frozen_attributes = freeze_attributes(attributes)
        else:
            raise TypeError(f"attributes must be a dict, sequence of pairs, or None, got {type(attributes).__name__}")

        object.__setattr__(self, "event_id", validated_event_id)
        object.__setattr__(self, "timestamp", validated_timestamp)
        object.__setattr__(self, "category", validated_category)
        object.__setattr__(self, "event_type", clean_event_type)
        object.__setattr__(self, "description", clean_description)
        object.__setattr__(self, "source_path", validated_source_path)
        object.__setattr__(self, "source_line", validated_line)
        object.__setattr__(self, "source_artifact_id", validated_source_artifact_id)
        object.__setattr__(self, "source_event_id", validated_source_event_id)
        object.__setattr__(self, "raw_timestamp", validated_raw_timestamp)
        object.__setattr__(self, "raw_data", validated_raw_data)
        object.__setattr__(self, "attributes", frozen_attributes)

    @property
    def line_number(self) -> Optional[int]:
        """Alias for source_line for consistency with V2 models."""
        return self.source_line

    @property
    def raw_line(self) -> Optional[str]:
        """Alias for raw_data for consistency with V2 log/auth models."""
        return self.raw_data

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a deterministic JSON-serializable dictionary representation.

        Guarantees:
        - JSON-safe data types only
        - Explicit representation of None values
        - Deterministic field structure
        - No speculative runtime or correlation fields
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp is not None else None,
            "raw_timestamp": self.raw_timestamp,
            "category": self.category.value if isinstance(self.category, TimelineCategory) else str(self.category),
            "event_type": self.event_type,
            "description": self.description,
            "source_path": self.source_path,
            "source_line": self.source_line,
            "source_artifact_id": self.source_artifact_id,
            "source_event_id": self.source_event_id,
            "raw_data": self.raw_data,
            "attributes": unfreeze_to_dict(self.attributes),
        }


def create_timeline_event(
    category: Union[TimelineCategory, str],
    event_type: str,
    description: str,
    *,
    timestamp: Optional[Union[datetime, str]] = None,
    event_id: Optional[str] = None,
    source_path: Optional[Union[str, Path]] = None,
    source_line: Optional[int] = None,
    source_artifact_id: Optional[str] = None,
    source_event_id: Optional[str] = None,
    raw_timestamp: Optional[str] = None,
    raw_data: Optional[str] = None,
    attributes: Any = (),
    line_number: Optional[int] = None,
    raw_line: Optional[str] = None,
) -> TimelineEvent:
    """
    Convenience factory to construct an immutable TimelineEvent with automatic ID generation.
    """
    return TimelineEvent(
        event_id=event_id,
        timestamp=timestamp,
        category=category,
        event_type=event_type,
        description=description,
        source_path=source_path,
        source_line=source_line,
        source_artifact_id=source_artifact_id,
        source_event_id=source_event_id,
        raw_timestamp=raw_timestamp,
        raw_data=raw_data,
        attributes=attributes,
        line_number=line_number,
        raw_line=raw_line,
    )
