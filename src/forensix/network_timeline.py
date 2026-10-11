"""
Forensic Network-to-Timeline Integration Layer for ForensiX (V5.5).

Integrates network packet observations (V5.3) and application-layer metadata (V5.4)
into the canonical V3 ForensiX timeline architecture (TimelineEvent, TimelineReconstruction,
TimelineQuery, and TimelineReporting) under TimelineCategory.NETWORK.

Strict Forensic Disciplines:
1. Canonical Schema Fidelity:
   - Maps all network observations directly into canonical V3.1 TimelineEvent objects
     under TimelineCategory.NETWORK.
   - Preserves source capture path (source_path), 1-indexed frame number (source_line),
     traceable parent artifact ID (source_artifact_id), and deterministic source
     event ID (source_event_id).
2. Anti-Speculation & Factual Distinction:
   - Packet-level transport observations (TCP, UDP, ICMP, ICMPv6, ARP, IP fragments)
     and application-level metadata (DNS, HTTP, TLS) are cleanly distinguished via event_type.
   - No speculative attack labels, risk scores, threat verdicts, or anomaly assertions.
3. Provenance & Relationship Integrity:
   - When application metadata is extracted from a packet frame, the metadata timeline
     event explicitly references the originating packet event ID via attributes['packet_event_id'].
   - Distinct frames with identical headers/payloads maintain distinct frame numbers and
     distinct source event IDs, preventing improper collision during deduplication.
4. Timestamp Fidelity:
   - Normalized UTC datetimes and raw capture timestamps are preserved without loss.
   - Missing timestamps are preserved as None without synthetic timestamp fabrication.
5. Absolute Determinism & Streaming:
   - Reproducible event IDs and deterministic sorting across independent runs.
   - Incremental streaming generator avoids memory exhaustion on large PCAP captures.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

from forensix.artifact_adapters import BaseArtifactAdapter
from forensix.network_events import (
    NetworkEvent,
    extract_network_event,
)
from forensix.network_metadata import (
    DnsMetadata,
    HttpMetadata,
    NetworkApplicationMetadata,
    TlsMetadata,
    extract_metadata_from_packet,
)
from forensix.network_models import NetworkEvidenceRecord
from forensix.network_pcap_parser import (
    DEFAULT_MAX_PACKET_SIZE,
    DLT_EN10MB,
    PcapParser,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    _FrozenDict,
    freeze_attributes,
)
from forensix.timeline_reconstruction import (
    ReconstructedTimeline,
    reconstruct_timeline,
)


def adapt_network_event(event: NetworkEvent) -> TimelineEvent:
    """
    Adapt a V5.3 NetworkEvent into a canonical V3 TimelineEvent under TimelineCategory.NETWORK.

    Preserves:
    - timestamp & raw_timestamp
    - source_path
    - source_line (frame_number)
    - source_artifact_id
    - source_event_id (NETEVT-<UUIDv5>)
    - attributes (frozen transport, protocol, and endpoint details)
    """
    if not isinstance(event, NetworkEvent):
        raise TypeError(f"adapt_network_event expects NetworkEvent, got {type(event).__name__}")
    return event.to_timeline_event()


def adapt_network_metadata(
    metadata: Union[NetworkApplicationMetadata, DnsMetadata, HttpMetadata, TlsMetadata],
    packet_event_id: Optional[str] = None,
) -> TimelineEvent:
    """
    Adapt a V5.4 application metadata observation into a canonical V3 TimelineEvent.

    Args:
        metadata: Application metadata record (NetworkApplicationMetadata, DnsMetadata, HttpMetadata, or TlsMetadata).
        packet_event_id: Optional parent NetworkEvent ID to record in provenance attributes.

    Returns:
        TimelineEvent: Canonical timeline observation under TimelineCategory.NETWORK.
    """
    if isinstance(metadata, NetworkApplicationMetadata):
        app_meta = metadata
    elif isinstance(metadata, DnsMetadata):
        app_meta = NetworkApplicationMetadata(
            metadata_id=metadata.metadata_id,
            protocol="DNS",
            dns=metadata,
            record_id=metadata.record_id,
            frame_number=metadata.frame_number,
            timestamp=metadata.timestamp,
            raw_timestamp=metadata.raw_timestamp,
            source_ip=metadata.source_ip,
            destination_ip=metadata.destination_ip,
            source_port=metadata.source_port,
            destination_port=metadata.destination_port,
            transport_protocol=metadata.transport_protocol,
            source_path=metadata.source_path,
            source_artifact_id=metadata.source_artifact_id,
        )
    elif isinstance(metadata, HttpMetadata):
        app_meta = NetworkApplicationMetadata(
            metadata_id=metadata.metadata_id,
            protocol="HTTP",
            http=metadata,
            record_id=metadata.record_id,
            frame_number=metadata.frame_number,
            timestamp=metadata.timestamp,
            raw_timestamp=metadata.raw_timestamp,
            source_ip=metadata.source_ip,
            destination_ip=metadata.destination_ip,
            source_port=metadata.source_port,
            destination_port=metadata.destination_port,
            transport_protocol="TCP",
            source_path=metadata.source_path,
            source_artifact_id=metadata.source_artifact_id,
        )
    elif isinstance(metadata, TlsMetadata):
        app_meta = NetworkApplicationMetadata(
            metadata_id=metadata.metadata_id,
            protocol="TLS",
            tls=metadata,
            record_id=metadata.record_id,
            frame_number=metadata.frame_number,
            timestamp=metadata.timestamp,
            raw_timestamp=metadata.raw_timestamp,
            source_ip=metadata.source_ip,
            destination_ip=metadata.destination_ip,
            source_port=metadata.source_port,
            destination_port=metadata.destination_port,
            transport_protocol="TCP",
            source_path=metadata.source_path,
            source_artifact_id=metadata.source_artifact_id,
        )
    else:
        raise TypeError(f"Unsupported metadata type for timeline adaptation: {type(metadata).__name__}")

    tl_event = app_meta.to_timeline_event()
    if packet_event_id is not None:
        # Enrich attributes with parent packet_event_id provenance
        curr_attrs = dict(tl_event.attributes) if tl_event.attributes else {}
        curr_attrs["packet_event_id"] = packet_event_id
        return TimelineEvent(
            timestamp=tl_event.timestamp,
            raw_timestamp=tl_event.raw_timestamp,
            category=tl_event.category,
            event_type=tl_event.event_type,
            description=tl_event.description,
            source_path=tl_event.source_path,
            source_line=tl_event.source_line,
            source_artifact_id=tl_event.source_artifact_id,
            source_event_id=tl_event.source_event_id,
            attributes=curr_attrs,
        )
    return tl_event


def adapt_network_record(
    record: NetworkEvidenceRecord,
    packet_bytes: Optional[bytes] = None,
    link_type: int = DLT_EN10MB,
    include_packet_events: bool = True,
    include_metadata_events: bool = True,
) -> Tuple[TimelineEvent, ...]:
    """
    Adapt a single NetworkEvidenceRecord into one or more canonical TimelineEvents.

    If packet_bytes is provided and include_metadata_events is True, attempts application
    metadata extraction and links the resulting metadata event to the packet observation.

    Returns:
        Tuple[TimelineEvent, ...]: Tuple of 0, 1, or 2 TimelineEvents.
    """
    if not isinstance(record, NetworkEvidenceRecord):
        raise TypeError(f"adapt_network_record expects NetworkEvidenceRecord, got {type(record).__name__}")

    events: List[TimelineEvent] = []
    pkt_event: Optional[NetworkEvent] = None

    if include_packet_events:
        pkt_event = extract_network_event(record)
        events.append(adapt_network_event(pkt_event))

    if include_metadata_events and packet_bytes is not None:
        app_meta = extract_metadata_from_packet(record, packet_bytes, link_type)
        if app_meta is not None:
            parent_id = pkt_event.event_id if pkt_event is not None else None
            events.append(adapt_network_metadata(app_meta, packet_event_id=parent_id))

    return tuple(events)


def adapt_network_artifact(artifact: Any) -> Tuple[TimelineEvent, ...]:
    """
    Polymorphically adapt any supported network evidence entity into a tuple of TimelineEvents.

    Supported input types:
    - NetworkEvent
    - NetworkApplicationMetadata, DnsMetadata, HttpMetadata, TlsMetadata
    - NetworkEvidenceRecord
    """
    if artifact is None:
        raise ValueError("Artifact cannot be None")

    if isinstance(artifact, NetworkEvent):
        return (adapt_network_event(artifact),)

    if isinstance(artifact, (NetworkApplicationMetadata, DnsMetadata, HttpMetadata, TlsMetadata)):
        return (adapt_network_metadata(artifact),)

    if isinstance(artifact, NetworkEvidenceRecord):
        return adapt_network_record(artifact, include_packet_events=True, include_metadata_events=False)

    raise TypeError(
        f"Unsupported network artifact type for timeline adaptation: {type(artifact).__name__}. "
        "Must be NetworkEvent, NetworkApplicationMetadata, DnsMetadata, HttpMetadata, TlsMetadata, or NetworkEvidenceRecord."
    )


class NetworkTimelineAdapter(BaseArtifactAdapter):
    """
    Artifact adapter integrating network evidence into the V3 timeline architecture.

    Implements BaseArtifactAdapter for seamless polymorphic dispatch through
    adapt_artifact() and adapt_artifacts().
    """

    def can_adapt(self, artifact: Any) -> bool:
        """Return True if artifact is a supported network model."""
        if artifact is None:
            return False
        return isinstance(
            artifact,
            (
                NetworkEvent,
                NetworkApplicationMetadata,
                DnsMetadata,
                HttpMetadata,
                TlsMetadata,
                NetworkEvidenceRecord,
            ),
        )

    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """Adapt network artifact into an immutable tuple of TimelineEvents."""
        if not self.can_adapt(artifact):
            raise TypeError(
                f"Unsupported artifact type for NetworkTimelineAdapter: {type(artifact).__name__}"
            )
        return adapt_network_artifact(artifact)


def extract_network_timeline_events(
    source: Union[str, Path, BinaryIO],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    include_packet_events: bool = True,
    include_metadata_events: bool = True,
) -> Iterator[TimelineEvent]:
    """
    Stream TimelineEvents incrementally from a classic PCAP capture file.

    For each packet frame:
    1. Extracts packet-level network event (e.g. TCP, UDP, ICMP, ARP, IP fragment).
    2. Extracts application-level metadata (DNS, HTTP, TLS) if present and parseable.
    3. Yields TimelineEvents with strict provenance linking and preserved timestamps.

    Yields:
        TimelineEvent: Canonical timeline observations under TimelineCategory.NETWORK.
    """
    parser = PcapParser(
        source,
        source_artifact_id=source_artifact_id,
        pcap_name=pcap_name,
        max_packet_size=max_packet_size,
    )
    link_type = parser.global_header.network

    for record, packet_bytes in parser.read_raw_records(max_packets=max_packets):
        events = adapt_network_record(
            record=record,
            packet_bytes=packet_bytes,
            link_type=link_type,
            include_packet_events=include_packet_events,
            include_metadata_events=include_metadata_events,
        )
        for ev in events:
            yield ev


def reconstruct_network_timeline(
    source: Union[str, Path, BinaryIO, Iterable[TimelineEvent]],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    include_packet_events: bool = True,
    include_metadata_events: bool = True,
    deduplicate: bool = True,
) -> ReconstructedTimeline:
    """
    Stream and reconstruct network observations into an ordered, deduplicated ReconstructedTimeline.

    Args:
        source: PCAP file path, binary stream, or existing TimelineEvent iterable.
        deduplicate: If True (default), filter exact duplicate observations.

    Returns:
        ReconstructedTimeline: Fully ordered, immutable timeline container.
    """
    if isinstance(source, (str, Path)) or hasattr(source, "read"):
        events_iter = extract_network_timeline_events(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
            include_packet_events=include_packet_events,
            include_metadata_events=include_metadata_events,
        )
        events_list = list(events_iter)
    else:
        events_list = list(source)

    return reconstruct_timeline(events_list, deduplicate=deduplicate)


class NetworkTimelineExtractor:
    """
    Object-oriented facade for Network-to-Timeline integration in ForensiX.
    """

    def __init__(
        self,
        include_packet_events: bool = True,
        include_metadata_events: bool = True,
    ) -> None:
        self.include_packet_events = include_packet_events
        self.include_metadata_events = include_metadata_events
        self._adapter = NetworkTimelineAdapter()

    def adapt(self, artifact: Any) -> Tuple[TimelineEvent, ...]:
        """Adapt a single network entity into TimelineEvents."""
        return self._adapter.adapt(artifact)

    def extract_from_pcap(
        self,
        source: Union[str, Path, BinaryIO],
        *,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        max_packets: Optional[int] = None,
    ) -> Iterator[TimelineEvent]:
        """Stream TimelineEvents incrementally from a PCAP capture."""
        return extract_network_timeline_events(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
            include_packet_events=self.include_packet_events,
            include_metadata_events=self.include_metadata_events,
        )

    def reconstruct_from_pcap(
        self,
        source: Union[str, Path, BinaryIO],
        *,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        max_packets: Optional[int] = None,
        deduplicate: bool = True,
    ) -> ReconstructedTimeline:
        """Stream from PCAP and reconstruct into an ordered, deduplicated ReconstructedTimeline."""
        return reconstruct_network_timeline(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
            include_packet_events=self.include_packet_events,
            include_metadata_events=self.include_metadata_events,
            deduplicate=deduplicate,
        )
