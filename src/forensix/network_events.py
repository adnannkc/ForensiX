"""
Forensic Network Event Extraction Layer for ForensiX (V5.3 Network Event Extraction).

Consumes validated NetworkEvidenceRecord instances (V5.1/V5.2) and produces
strongly typed, deeply immutable, deterministic NetworkEvent objects representing
factual network observations (TCP, UDP, ICMP, ICMPv6, ARP, IP fragments, and link-layer frames).

Strict Forensic Disciplines:
1. Observed vs Derived vs Interpreted:
   - OBSERVED: Network endpoints (IPs, ports, MACs), frame numbers, observed lengths,
     TCP flags, sequence/acknowledgment numbers, ICMP types/codes, fragment offsets,
     and ARP opcodes.
   - DERIVED: Deterministic event_id (RFC 4122 UUIDv5 via NETEVT- namespace),
     factual event_type classification, and structured descriptions.
   - INTERPRETED: Disallowed. A packet observation is not proof of a full network
     connection. A SYN packet alone does not prove success or compromise. No speculative
     labels (malicious, C2, attacker, incident).
2. Provenance Traceability:
   - Preserves source capture path, pcap filename, parent artifact ID, frame number,
     and references underlying record_id.
3. Deterministic Identity:
   - Every event receives a reproducible NETEVT-<UUIDv5> identifier derived from
     the immutable evidence facts and parent record_id.
   - Distinct frames produce distinct event identities, even if packet bytes match.
4. Timestamp & Precision Integrity:
   - Preserves exact normalized UTC datetimes and raw timestamp strings without
     subsecond precision loss or floating-point drift.
5. Deep Immutability & Streaming:
   - Frozen dataclass with recursively frozen attributes (_FrozenDict, _FrozenList).
   - Supports incremental generator extraction for bounded memory.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.network_models import (
    FORENSIX_V5_NETWORK_NAMESPACE,
    NetworkEvidenceRecord,
)
from forensix.network_pcap_parser import (
    DEFAULT_MAX_PACKET_SIZE,
    read_pcap,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)


# Canonical RFC 4122 UUID namespace for ForensiX V5 deterministic network event identities
FORENSIX_V5_NETWORK_EVENT_NAMESPACE = uuid.uuid5(
    FORENSIX_V5_NETWORK_NAMESPACE, "events"
)


class NetworkEventType(str, Enum):
    """
    Factual forensic classification of observed network packet events.

    Strict boundary: Represents observed wire phenomena only; does NOT imply
    application layer sessions, attack intent, or investigative conclusions.
    """

    TCP_PACKET = "tcp_packet"
    UDP_PACKET = "udp_packet"
    ICMP_PACKET = "icmp_packet"
    ICMPV6_PACKET = "icmpv6_packet"
    ARP_PACKET = "arp_packet"
    IP_FRAGMENT = "ip_fragment"
    IPV4_PACKET = "ipv4_packet"
    IPV6_PACKET = "ipv6_packet"
    GENERIC_PACKET = "generic_packet"


def compute_deterministic_network_event_id(
    record_id: str,
    event_type: str,
    frame_number: int,
) -> str:
    """
    Compute a deterministic RFC 4122 UUIDv5 network event identifier (NETEVT-<UUIDv5>).

    Identity Guarantees:
    1. Reproducibility: Identical record ID, event type, and frame produce the exact same ID.
    2. Distinctness: Separate frames produce distinct event IDs even if payloads match.
    3. Provenance: Directly linked to the underlying NetworkEvidenceRecord.record_id.
    """
    if not record_id or not isinstance(record_id, str):
        raise TypeError(f"record_id must be a non-empty string, got {type(record_id).__name__}")
    if not isinstance(frame_number, int) or isinstance(frame_number, bool) or frame_number < 1:
        raise ValueError(f"frame_number must be an integer >= 1, got {frame_number}")

    canonical_key = f"{record_id.strip()}|{str(event_type).strip().lower()}|frame:{frame_number}"
    det_uuid = uuid.uuid5(FORENSIX_V5_NETWORK_EVENT_NAMESPACE, canonical_key)
    return f"NETEVT-{det_uuid}"


def _classify_network_event_type(record: NetworkEvidenceRecord) -> str:
    """
    Classify a NetworkEvidenceRecord into a factual NetworkEventType string.
    """
    meta_dict = dict(record.packet_metadata) if record.packet_metadata else {}

    # 1. Non-initial IP fragments lacking transport headers
    if meta_dict.get("fragment") and meta_dict.get("fragment_offset", 0) > 0:
        return NetworkEventType.IP_FRAGMENT.value

    # 2. ARP traffic
    if record.protocol == "ARP" or record.network_protocol == "ARP":
        return NetworkEventType.ARP_PACKET.value

    # 3. Transport protocols
    if record.protocol == "TCP" or record.transport_protocol == "TCP":
        return NetworkEventType.TCP_PACKET.value

    if record.protocol == "UDP" or record.transport_protocol == "UDP":
        return NetworkEventType.UDP_PACKET.value

    if record.protocol == "ICMP" or record.transport_protocol == "ICMP":
        return NetworkEventType.ICMP_PACKET.value

    if record.protocol == "ICMPV6" or record.transport_protocol == "ICMPV6":
        return NetworkEventType.ICMPV6_PACKET.value

    # 4. Initial fragments without transport headers
    if meta_dict.get("fragment"):
        return NetworkEventType.IP_FRAGMENT.value

    # 5. Network layer protocols without transport layer
    if record.network_protocol == "IPV4":
        return NetworkEventType.IPV4_PACKET.value

    if record.network_protocol == "IPV6":
        return NetworkEventType.IPV6_PACKET.value

    # 6. Generic link-layer frames
    return NetworkEventType.GENERIC_PACKET.value


def _build_factual_description(
    record: NetworkEvidenceRecord,
    event_type: str,
) -> str:
    """
    Construct a concise, strictly factual human-readable forensic observation description.
    """
    meta_dict = dict(record.packet_metadata) if record.packet_metadata else {}

    if event_type == NetworkEventType.TCP_PACKET.value:
        flags_list = meta_dict.get("tcp_flags")
        flags_str = f" [{', '.join(flags_list)}]" if flags_list else ""
        src_ep = f"{record.src_ip or 'unknown'}:{record.src_port if record.src_port is not None else '?'}"
        dst_ep = f"{record.dst_ip or 'unknown'}:{record.dst_port if record.dst_port is not None else '?'}"
        return f"Observed TCP packet from {src_ep} to {dst_ep}{flags_str}"

    elif event_type == NetworkEventType.UDP_PACKET.value:
        src_ep = f"{record.src_ip or 'unknown'}:{record.src_port if record.src_port is not None else '?'}"
        dst_ep = f"{record.dst_ip or 'unknown'}:{record.dst_port if record.dst_port is not None else '?'}"
        len_str = f" (len: {record.captured_length})" if record.captured_length is not None else ""
        return f"Observed UDP packet from {src_ep} to {dst_ep}{len_str}"

    elif event_type in (NetworkEventType.ICMP_PACKET.value, NetworkEventType.ICMPV6_PACKET.value):
        proto = "ICMPv6" if event_type == NetworkEventType.ICMPV6_PACKET.value else "ICMP"
        src = record.src_ip or "unknown"
        dst = record.dst_ip or "unknown"
        type_code = ""
        if "icmp_type" in meta_dict:
            type_code = f" (type {meta_dict['icmp_type']}, code {meta_dict.get('icmp_code', 0)})"
        return f"Observed {proto} packet from {src} to {dst}{type_code}"

    elif event_type == NetworkEventType.ARP_PACKET.value:
        opcode = meta_dict.get("arp_opcode")
        op_str = "request" if opcode == 1 else ("reply" if opcode == 2 else ("packet" if opcode is None else f"opcode {opcode}"))
        src = record.src_mac or "unknown"
        dst = record.dst_mac or "unknown"
        return f"Observed ARP {op_str} from {src} to {dst}"

    elif event_type == NetworkEventType.IP_FRAGMENT.value:
        src = record.src_ip or "unknown"
        dst = record.dst_ip or "unknown"
        offset = meta_dict.get("fragment_offset")
        offset_str = f" (offset {offset})" if offset is not None else ""
        return f"Observed IP fragment from {src} to {dst}{offset_str}"

    elif event_type in (NetworkEventType.IPV4_PACKET.value, NetworkEventType.IPV6_PACKET.value):
        proto_ver = "IPv4" if event_type == NetworkEventType.IPV4_PACKET.value else "IPv6"
        src = record.src_ip or "unknown"
        dst = record.dst_ip or "unknown"
        proto = f" [{record.protocol}]" if record.protocol else ""
        return f"Observed {proto_ver} packet from {src} to {dst}{proto}"

    else:
        ll = record.link_layer or "network"
        len_info = f" ({record.captured_length} bytes)" if record.captured_length is not None else ""
        return f"Observed {ll} frame #{record.frame_number}{len_info}"


@dataclass(frozen=True)
class NetworkEvent:
    """
    Immutable, strongly typed forensic representation of an extracted network event.

    Strict Boundaries:
    - Factual forensic observation representation only.
    - Deeply immutable dataclass with recursively frozen attributes.
    - Deterministic JSON-safe serialization.
    - Fully traceable to the originating NetworkEvidenceRecord and PCAP frame.
    """

    event_id: str
    record_id: str
    frame_number: int
    timestamp: Optional[datetime]
    raw_timestamp: Optional[str]
    event_type: str
    description: str
    protocol: Optional[str] = None
    network_protocol: Optional[str] = None
    transport_protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    link_layer: Optional[str] = None
    captured_length: Optional[int] = None
    original_length: Optional[int] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    pcap_name: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        event_id: str,
        record_id: str,
        frame_number: int,
        event_type: str,
        description: str,
        *,
        timestamp: Optional[datetime] = None,
        raw_timestamp: Optional[str] = None,
        protocol: Optional[str] = None,
        network_protocol: Optional[str] = None,
        transport_protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        link_layer: Optional[str] = None,
        captured_length: Optional[int] = None,
        original_length: Optional[int] = None,
        source_path: Optional[str] = None,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        attributes: Any = None,
        # Ergonomic aliases:
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
    ) -> None:
        if not event_id or not isinstance(event_id, str):
            raise TypeError("event_id must be a non-empty string")
        if not record_id or not isinstance(record_id, str):
            raise TypeError("record_id must be a non-empty string")
        if isinstance(frame_number, bool) or not isinstance(frame_number, int) or frame_number < 1:
            raise ValueError(f"frame_number must be an integer >= 1, got {frame_number}")
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")
        if not description or not isinstance(description, str):
            raise ValueError("description must be a non-empty string")

        chosen_src_ip = src_ip if src_ip is not None else source_ip
        chosen_dst_ip = dst_ip if dst_ip is not None else destination_ip
        chosen_src_port = src_port if src_port is not None else source_port
        chosen_dst_port = dst_port if dst_port is not None else destination_port

        frozen_attrs: Tuple[Tuple[str, Any], ...] = freeze_attributes(attributes) if attributes else _FrozenDict()

        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "frame_number", frame_number)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "raw_timestamp", raw_timestamp)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "network_protocol", network_protocol)
        object.__setattr__(self, "transport_protocol", transport_protocol)
        object.__setattr__(self, "src_ip", chosen_src_ip)
        object.__setattr__(self, "dst_ip", chosen_dst_ip)
        object.__setattr__(self, "src_port", chosen_src_port)
        object.__setattr__(self, "dst_port", chosen_dst_port)
        object.__setattr__(self, "src_mac", src_mac)
        object.__setattr__(self, "dst_mac", dst_mac)
        object.__setattr__(self, "link_layer", link_layer)
        object.__setattr__(self, "captured_length", captured_length)
        object.__setattr__(self, "original_length", original_length)
        object.__setattr__(self, "source_path", source_path)
        object.__setattr__(self, "source_artifact_id", source_artifact_id)
        object.__setattr__(self, "pcap_name", pcap_name)
        object.__setattr__(self, "attributes", frozen_attrs)

    @property
    def source_ip(self) -> Optional[str]:
        """Alias for src_ip."""
        return self.src_ip

    @property
    def destination_ip(self) -> Optional[str]:
        """Alias for dst_ip."""
        return self.dst_ip

    @property
    def source_port(self) -> Optional[int]:
        """Alias for src_port."""
        return self.src_port

    @property
    def destination_port(self) -> Optional[int]:
        """Alias for dst_port."""
        return self.dst_port

    @property
    def packet_number(self) -> int:
        """Alias for frame_number."""
        return self.frame_number

    @property
    def packet_length(self) -> Optional[int]:
        """Alias for captured_length."""
        return self.captured_length

    @property
    def wire_length(self) -> Optional[int]:
        """Alias for original_length."""
        return self.original_length

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a deterministic JSON-serializable dictionary representation.
        """
        return {
            "event_id": self.event_id,
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp is not None else None,
            "raw_timestamp": self.raw_timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "protocol": self.protocol,
            "network_protocol": self.network_protocol,
            "transport_protocol": self.transport_protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "link_layer": self.link_layer,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "pcap_name": self.pcap_name,
            "attributes": unfreeze_to_dict(self.attributes),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize event to a deterministic JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkEvent":
        """Reconstruct a NetworkEvent from a dictionary representation."""
        if not isinstance(data, dict):
            raise TypeError(f"from_dict expects a dict, got {type(data).__name__}")
        ts = datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else None
        return cls(
            event_id=data["event_id"],
            record_id=data["record_id"],
            frame_number=data["frame_number"],
            event_type=data["event_type"],
            description=data["description"],
            timestamp=ts,
            raw_timestamp=data.get("raw_timestamp"),
            protocol=data.get("protocol"),
            network_protocol=data.get("network_protocol"),
            transport_protocol=data.get("transport_protocol"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            src_mac=data.get("src_mac"),
            dst_mac=data.get("dst_mac"),
            link_layer=data.get("link_layer"),
            captured_length=data.get("captured_length"),
            original_length=data.get("original_length"),
            source_path=data.get("source_path"),
            source_artifact_id=data.get("source_artifact_id"),
            pcap_name=data.get("pcap_name"),
            attributes=data.get("attributes"),
        )

    def to_timeline_event(self) -> TimelineEvent:
        """
        Bridge this NetworkEvent directly into a V3.1 TimelineEvent.

        Maps:
            category: TimelineCategory.NETWORK
            event_id: Generated valid TIMELINE-<UUIDv4>
            source_line: frame_number
            source_event_id: event_id (traceable NETEVT-<UUIDv5>)
        """
        attrs_dict = dict(self.attributes) if self.attributes else {}
        if self.src_ip and "src_ip" not in attrs_dict:
            attrs_dict["src_ip"] = self.src_ip
        if self.dst_ip and "dst_ip" not in attrs_dict:
            attrs_dict["dst_ip"] = self.dst_ip
        if self.src_port is not None and "src_port" not in attrs_dict:
            attrs_dict["src_port"] = self.src_port
        if self.dst_port is not None and "dst_port" not in attrs_dict:
            attrs_dict["dst_port"] = self.dst_port
        if self.protocol and "protocol" not in attrs_dict:
            attrs_dict["protocol"] = self.protocol
        if self.network_protocol and "network_protocol" not in attrs_dict:
            attrs_dict["network_protocol"] = self.network_protocol
        if self.transport_protocol and "transport_protocol" not in attrs_dict:
            attrs_dict["transport_protocol"] = self.transport_protocol

        return TimelineEvent(
            timestamp=self.timestamp,
            category=TimelineCategory.NETWORK,
            event_type=self.event_type,
            description=self.description,
            source_path=self.source_path,
            source_line=self.frame_number,
            source_artifact_id=self.source_artifact_id,
            source_event_id=self.event_id,
            raw_timestamp=self.raw_timestamp,
            attributes=attrs_dict,
        )


def extract_network_event(record: NetworkEvidenceRecord) -> NetworkEvent:
    """
    Extract a deterministic, typed NetworkEvent from a NetworkEvidenceRecord.

    Args:
        record: Validated V5.1 NetworkEvidenceRecord.

    Returns:
        NetworkEvent: Factual forensic network event.
    """
    if not isinstance(record, NetworkEvidenceRecord):
        raise TypeError(f"extract_network_event expects NetworkEvidenceRecord, got {type(record).__name__}")

    event_type = _classify_network_event_type(record)
    description = _build_factual_description(record, event_type)
    event_id = compute_deterministic_network_event_id(
        record_id=record.record_id,
        event_type=event_type,
        frame_number=record.frame_number,
    )

    # Build comprehensive factual attributes
    raw_meta = unfreeze_to_dict(record.packet_metadata) if record.packet_metadata else {}
    event_attrs: Dict[str, Any] = dict(raw_meta)
    event_attrs["record_id"] = record.record_id
    event_attrs["frame_number"] = record.frame_number
    if record.protocol:
        event_attrs["protocol"] = record.protocol
    if record.network_protocol:
        event_attrs["network_protocol"] = record.network_protocol
    if record.transport_protocol:
        event_attrs["transport_protocol"] = record.transport_protocol
    if record.src_ip:
        event_attrs["src_ip"] = record.src_ip
    if record.dst_ip:
        event_attrs["dst_ip"] = record.dst_ip
    if record.src_port is not None:
        event_attrs["src_port"] = record.src_port
    if record.dst_port is not None:
        event_attrs["dst_port"] = record.dst_port
    if record.src_mac:
        event_attrs["src_mac"] = record.src_mac
    if record.dst_mac:
        event_attrs["dst_mac"] = record.dst_mac
    if record.captured_length is not None:
        event_attrs["captured_length"] = record.captured_length
    if record.original_length is not None:
        event_attrs["original_length"] = record.original_length

    return NetworkEvent(
        event_id=event_id,
        record_id=record.record_id,
        frame_number=record.frame_number,
        timestamp=record.timestamp,
        raw_timestamp=record.raw_timestamp,
        event_type=event_type,
        description=description,
        protocol=record.protocol,
        network_protocol=record.network_protocol,
        transport_protocol=record.transport_protocol,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        src_mac=record.src_mac,
        dst_mac=record.dst_mac,
        link_layer=record.link_layer,
        captured_length=record.captured_length,
        original_length=record.original_length,
        source_path=record.source_path,
        source_artifact_id=record.source_artifact_id,
        pcap_name=record.pcap_name,
        attributes=event_attrs,
    )


def extract_network_events(
    records: Iterable[NetworkEvidenceRecord],
) -> Iterator[NetworkEvent]:
    """
    Streaming generator extracting NetworkEvents from an iterable of NetworkEvidenceRecords.

    Preserves exact frame ordering without loading the full collection into memory.
    """
    for rec in records:
        yield extract_network_event(rec)


class NetworkEventExtractor:
    """
    Forensic event extractor converting packet records or PCAP streams into NetworkEvents.
    """

    def extract(self, record: NetworkEvidenceRecord) -> NetworkEvent:
        """Extract a NetworkEvent from a single NetworkEvidenceRecord."""
        return extract_network_event(record)

    def extract_many(
        self,
        records: Iterable[NetworkEvidenceRecord],
    ) -> Iterator[NetworkEvent]:
        """Stream NetworkEvents from an iterable of NetworkEvidenceRecords."""
        return extract_network_events(records)

    def extract_all(
        self,
        records: Iterable[NetworkEvidenceRecord],
    ) -> List[NetworkEvent]:
        """Collect all extracted NetworkEvents into an in-memory list."""
        return list(extract_network_events(records))

    def extract_from_pcap(
        self,
        source: Union[str, Path, BinaryIO],
        *,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        max_packets: Optional[int] = None,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    ) -> Iterator[NetworkEvent]:
        """
        Stream NetworkEvents directly from a classic PCAP capture file or binary stream.
        """
        records = read_pcap(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
            max_packet_size=max_packet_size,
        )
        return extract_network_events(records)
