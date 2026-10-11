"""
Forensic Network Evidence Models for ForensiX (V5.1 Network Evidence Model).

Provides strongly typed, deeply immutable dataclasses representing individual observed
network packets/frames derived from network packet captures (PCAP/PCAP-NG) without
introducing packet parsing engines, tshark integrations, speculative detection, or
flow clustering.

Foundational Forensic Discipline:
1. Observed vs Derived vs Interpreted:
   - OBSERVED: frame_number, capture timestamp, captured_length, original_length,
     link-layer metadata, source/destination IP addresses, source/destination ports,
     protocols, and packet metadata.
   - DERIVED: deterministic record_id (RFC 4122 UUIDv5), normalized timestamp (UTC),
     normalized uppercase protocol names.
   - INTERPRETED: Disallowed in V5.1. No verdict, risk score, malicious categorization,
     threat classification, or attack speculation.
2. Provenance Traceability:
   - Explicitly records source PCAP identity (source_path, source_artifact_id, pcap_name)
     and 1-indexed frame_number.
   - Never conflates PCAP frame number with log file line number.
3. Deep Immutability:
   - Frozen dataclass with recursively frozen nested containers (_FrozenDict, _FrozenList).
4. Deterministic Identity:
   - Fully reproducible NET-<UUIDv5> derived from stable evidence facts within the
     ForensiX V5 network namespace.
5. High-Precision Timestamps:
   - Supports microsecond precision via Python datetime and preserves arbitrary raw
     fractional precision (e.g. nanoseconds from PCAP-NG) via raw_timestamp without loss.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import posixpath
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.timeline_models import (
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)
from forensix.timestamp_normalizer import normalize_timestamp


# Canonical RFC 4122 UUID namespace for ForensiX V5 deterministic network evidence identities
FORENSIX_V5_NETWORK_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://forensix.local/v5/network"
)

# Forensic terms prohibited in network attributes to prevent speculative verdicts
DISALLOWED_SPECULATIVE_NETWORK_TERMS: Tuple[str, ...] = (
    "malicious",
    "attacker",
    "c2",
    "c2_traffic",
    "command_and_control",
    "threat_level",
    "risk_score",
    "verdict",
    "compromised",
    "attack_detected",
    "threat_detected",
    "anomaly_detected",
    "incident_confirmed",
)


def _normalize_evidence_path(path: Union[str, Path]) -> str:
    """
    Normalize an evidence path string for deterministic identity computation.

    Converts backslashes to forward slashes, normalizes relative dot components,
    and strips leading slashes for relative paths.
    """
    p_str = str(path).strip().replace("\\", "/")
    norm = posixpath.normpath(p_str)
    if not p_str.startswith("/"):
        norm = norm.lstrip("/")
    return norm


def _check_speculative_network_term(val: str, field_name: str) -> None:
    """Verify that a string field contains no prohibited speculative attack assertions."""
    lower_val = val.lower()
    for term in DISALLOWED_SPECULATIVE_NETWORK_TERMS:
        if term == lower_val or term in lower_val.split():
            raise ValueError(
                f"Speculative or interpretive term '{val}' is disallowed in {field_name}. "
                "Network evidence represents factual forensic observations, not investigative conclusions."
            )


def _check_metadata_speculative(data: Any) -> None:
    """Recursively check that metadata keys and values do not contain speculative terms."""
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str):
                _check_speculative_network_term(k, f"metadata key '{k}'")
            _check_metadata_speculative(v)
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            _check_metadata_speculative(item)


def compute_deterministic_network_id(
    frame_number: int,
    *,
    source_path: Optional[Union[str, Path]] = None,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    raw_timestamp: Optional[str] = None,
    timestamp: Optional[Union[datetime, str, float, int]] = None,
    captured_length: Optional[int] = None,
    original_length: Optional[int] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> str:
    """
    Compute a deterministic RFC 4122 UUIDv5 network evidence identifier (NET-<UUIDv5>).

    Identity Semantics:
    1. Provenance: Source evidence reference (artifact ID, normalized path, or pcap name).
    2. Packet identity: Mandatory 1-indexed frame/packet number within capture.
    3. Stable Facts: Timestamps, lengths, endpoints (IPs, ports, protocol).
    4. Guarantees:
       - Same facts always produce the exact same ID across runs and platforms.
       - Different frames or different sources produce distinct IDs.
       - Format: NET-<UUIDv5>.
    """
    if frame_number is None:
        raise TypeError("frame_number is required to compute deterministic network ID")
    if isinstance(frame_number, bool) or not isinstance(frame_number, int):
        raise TypeError(f"frame_number must be an integer, got {type(frame_number).__name__}")
    if frame_number < 1:
        raise ValueError(f"frame_number must be >= 1, got {frame_number}")

    # Canonical evidence source
    if source_artifact_id is not None and str(source_artifact_id).strip():
        source_key = f"art:{str(source_artifact_id).strip()}"
    elif source_path is not None and str(source_path).strip():
        source_key = f"path:{_normalize_evidence_path(source_path)}"
    elif pcap_name is not None and str(pcap_name).strip():
        source_key = f"pcap:{str(pcap_name).strip()}"
    else:
        source_key = "source:default"

    key_parts = [source_key, f"frame:{frame_number}"]

    if raw_timestamp is not None and str(raw_timestamp).strip():
        key_parts.append(f"raw_ts:{str(raw_timestamp).strip()}")
    elif timestamp is not None:
        if isinstance(timestamp, datetime):
            key_parts.append(f"ts:{timestamp.isoformat()}")
        else:
            key_parts.append(f"ts:{str(timestamp).strip()}")

    if captured_length is not None:
        key_parts.append(f"caplen:{captured_length}")
    if original_length is not None:
        key_parts.append(f"origlen:{original_length}")

    if src_ip is not None and str(src_ip).strip():
        key_parts.append(f"sip:{str(src_ip).strip()}")
    if dst_ip is not None and str(dst_ip).strip():
        key_parts.append(f"dip:{str(dst_ip).strip()}")
    if src_port is not None:
        key_parts.append(f"sport:{src_port}")
    if dst_port is not None:
        key_parts.append(f"dport:{dst_port}")
    if protocol is not None and str(protocol).strip():
        key_parts.append(f"proto:{str(protocol).strip().upper()}")

    canonical_key = "|".join(key_parts)
    det_uuid = uuid.uuid5(FORENSIX_V5_NETWORK_NAMESPACE, canonical_key)
    return f"NET-{det_uuid}"


def _validate_network_id(val: str) -> str:
    """Validate that a string conforms to the ForensiX NET-<UUID> specification."""
    if not isinstance(val, str):
        raise TypeError(f"record_id must be a string, got {type(val).__name__}")
    clean_id = val.strip()
    if not clean_id:
        raise ValueError("record_id must not be empty")
    if not clean_id.startswith("NET-"):
        raise ValueError(f"record_id must start with 'NET-', got '{val}'")
    suffix = clean_id[len("NET-"):].strip()
    if not suffix:
        raise ValueError(f"record_id UUID suffix must not be empty, got '{val}'")
    try:
        uuid.UUID(suffix)
    except (ValueError, AttributeError) as err:
        raise ValueError(f"record_id must contain a valid UUID, got '{val}'") from err
    return clean_id


@dataclass(frozen=True)
class NetworkEvidenceRecord:
    """
    Immutable forensic representation of a single observed network packet/frame.

    Strict Boundaries:
    - Factual forensic observation representation only.
    - No speculative security verdicts (malicious, C2, attacker, risk score).
    - No packet parsing, stream reassembly, or tshark dependency in V5.1.
    - Deeply immutable and deterministically serializable.

    Attributes:
        record_id: Unique deterministic tracking identifier (NET-<UUIDv5>).
        frame_number: 1-indexed packet/frame sequence number within the capture.
        timestamp: Canonical normalized UTC datetime, or None if unavailable.
        raw_timestamp: Unaltered original capture timestamp representation string.
        captured_length: Number of packet bytes captured in the trace (caplen), or None.
        original_length: Wire length of the packet in bytes (len), or None.
        link_layer: Observed link-layer encapsulation type (e.g. 'ETHERNET'), or None.
        src_mac: Link-layer source hardware address, or None.
        dst_mac: Link-layer destination hardware address, or None.
        src_ip: Network-layer source IP address (IPv4 or IPv6), or None.
        dst_ip: Network-layer destination IP address (IPv4 or IPv6), or None.
        src_port: Transport-layer source port number (0-65535), or None.
        dst_port: Transport-layer destination port number (0-65535), or None.
        protocol: Canonical normalized upper-case protocol name (e.g. 'TCP', 'UDP'), or None.
        network_protocol: Network-layer protocol (e.g. 'IPv4', 'IPv6', 'ARP'), or None.
        transport_protocol: Transport-layer protocol (e.g. 'TCP', 'UDP', 'ICMP'), or None.
        source_path: Filesystem path to the source capture file (PCAP/PCAP-NG), or None.
        source_artifact_id: Traceable ID of the parent evidence artifact (ART-...), or None.
        pcap_name: Base filename or identity of the capture file, or None.
        packet_metadata: Deeply frozen tuple of additional observed packet attributes.
    """

    record_id: str
    frame_number: int
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    captured_length: Optional[int] = None
    original_length: Optional[int] = None
    link_layer: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    network_protocol: Optional[str] = None
    transport_protocol: Optional[str] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    pcap_name: Optional[str] = None
    packet_metadata: Tuple[Tuple[str, Any], ...] = ()

    def __init__(
        self,
        frame_number: int,
        *,
        record_id: Optional[str] = None,
        timestamp: Optional[Union[datetime, str, float, int]] = None,
        raw_timestamp: Optional[str] = None,
        captured_length: Optional[int] = None,
        original_length: Optional[int] = None,
        link_layer: Optional[str] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        network_protocol: Optional[str] = None,
        transport_protocol: Optional[str] = None,
        source_path: Optional[Union[str, Path]] = None,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        packet_metadata: Any = None,
        # Ergonomic aliases:
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        source_mac: Optional[str] = None,
        destination_mac: Optional[str] = None,
        packet_length: Optional[int] = None,
        wire_length: Optional[int] = None,
        attributes: Any = None,
    ) -> None:
        # 1. Validate mandatory frame_number
        if frame_number is None:
            raise TypeError("NetworkEvidenceRecord missing required argument: 'frame_number'")
        if isinstance(frame_number, bool) or not isinstance(frame_number, int):
            raise TypeError(f"frame_number must be an integer, got {type(frame_number).__name__}")
        if frame_number < 1:
            raise ValueError(f"frame_number must be >= 1 (1-indexed), got {frame_number}")

        # 2. Resolve and validate aliases
        chosen_src_ip = src_ip if src_ip is not None else source_ip
        if src_ip is not None and source_ip is not None and src_ip != source_ip:
            raise ValueError(f"Conflicting values provided for src_ip ('{src_ip}') and source_ip ('{source_ip}')")

        chosen_dst_ip = dst_ip if dst_ip is not None else destination_ip
        if dst_ip is not None and destination_ip is not None and dst_ip != destination_ip:
            raise ValueError(f"Conflicting values provided for dst_ip ('{dst_ip}') and destination_ip ('{destination_ip}')")

        chosen_src_port = src_port if src_port is not None else source_port
        if src_port is not None and source_port is not None and src_port != source_port:
            raise ValueError(f"Conflicting values provided for src_port ({src_port}) and source_port ({source_port})")

        chosen_dst_port = dst_port if dst_port is not None else destination_port
        if dst_port is not None and destination_port is not None and dst_port != destination_port:
            raise ValueError(f"Conflicting values provided for dst_port ({dst_port}) and destination_port ({destination_port})")

        chosen_src_mac = src_mac if src_mac is not None else source_mac
        if src_mac is not None and source_mac is not None and src_mac != source_mac:
            raise ValueError("Conflicting values provided for src_mac and source_mac")

        chosen_dst_mac = dst_mac if dst_mac is not None else destination_mac
        if dst_mac is not None and destination_mac is not None and dst_mac != destination_mac:
            raise ValueError("Conflicting values provided for dst_mac and destination_mac")

        chosen_cap_len = captured_length if captured_length is not None else packet_length
        if captured_length is not None and packet_length is not None and captured_length != packet_length:
            raise ValueError("Conflicting values provided for captured_length and packet_length")

        chosen_orig_len = original_length if original_length is not None else wire_length
        if original_length is not None and wire_length is not None and original_length != wire_length:
            raise ValueError("Conflicting values provided for original_length and wire_length")

        chosen_meta = packet_metadata if packet_metadata is not None else attributes
        if packet_metadata is not None and attributes is not None and packet_metadata != attributes:
            raise ValueError("Conflicting values provided for packet_metadata and attributes")

        # 3. Validate packet lengths
        validated_cap_len: Optional[int] = None
        if chosen_cap_len is not None:
            if isinstance(chosen_cap_len, bool) or not isinstance(chosen_cap_len, int):
                raise TypeError(f"captured_length must be an integer, got {type(chosen_cap_len).__name__}")
            if chosen_cap_len < 0:
                raise ValueError(f"captured_length must be >= 0, got {chosen_cap_len}")
            validated_cap_len = chosen_cap_len

        validated_orig_len: Optional[int] = None
        if chosen_orig_len is not None:
            if isinstance(chosen_orig_len, bool) or not isinstance(chosen_orig_len, int):
                raise TypeError(f"original_length must be an integer, got {type(chosen_orig_len).__name__}")
            if chosen_orig_len < 0:
                raise ValueError(f"original_length must be >= 0, got {chosen_orig_len}")
            validated_orig_len = chosen_orig_len

        if validated_cap_len is not None and validated_orig_len is not None:
            if validated_cap_len > validated_orig_len:
                raise ValueError(
                    f"captured_length ({validated_cap_len}) cannot exceed original_length ({validated_orig_len})"
                )

        # 4. Validate transport ports
        validated_src_port: Optional[int] = None
        if chosen_src_port is not None:
            if isinstance(chosen_src_port, bool) or not isinstance(chosen_src_port, int):
                raise TypeError(f"src_port must be an integer, got {type(chosen_src_port).__name__}")
            if chosen_src_port < 0 or chosen_src_port > 65535:
                raise ValueError(f"src_port must be between 0 and 65535, got {chosen_src_port}")
            validated_src_port = chosen_src_port

        validated_dst_port: Optional[int] = None
        if chosen_dst_port is not None:
            if isinstance(chosen_dst_port, bool) or not isinstance(chosen_dst_port, int):
                raise TypeError(f"dst_port must be an integer, got {type(chosen_dst_port).__name__}")
            if chosen_dst_port < 0 or chosen_dst_port > 65535:
                raise ValueError(f"dst_port must be between 0 and 65535, got {chosen_dst_port}")
            validated_dst_port = chosen_dst_port

        # 5. Validate IP addresses
        validated_src_ip: Optional[str] = None
        if chosen_src_ip is not None:
            if not isinstance(chosen_src_ip, str):
                raise TypeError(f"src_ip must be a string, got {type(chosen_src_ip).__name__}")
            clean_sip = chosen_src_ip.strip()
            if not clean_sip:
                raise ValueError("src_ip must not be empty")
            try:
                ipaddress.ip_address(clean_sip)
            except ValueError as err:
                raise ValueError(f"Invalid IP address for src_ip: '{chosen_src_ip}'") from err
            validated_src_ip = clean_sip

        validated_dst_ip: Optional[str] = None
        if chosen_dst_ip is not None:
            if not isinstance(chosen_dst_ip, str):
                raise TypeError(f"dst_ip must be a string, got {type(chosen_dst_ip).__name__}")
            clean_dip = chosen_dst_ip.strip()
            if not clean_dip:
                raise ValueError("dst_ip must not be empty")
            try:
                ipaddress.ip_address(clean_dip)
            except ValueError as err:
                raise ValueError(f"Invalid IP address for dst_ip: '{chosen_dst_ip}'") from err
            validated_dst_ip = clean_dip

        # 6. Validate link-layer information
        validated_link_layer: Optional[str] = None
        if link_layer is not None:
            if not isinstance(link_layer, str):
                raise TypeError(f"link_layer must be a string, got {type(link_layer).__name__}")
            clean_ll = link_layer.strip()
            if not clean_ll:
                raise ValueError("link_layer must not be empty")
            validated_link_layer = clean_ll.upper()

        validated_src_mac: Optional[str] = None
        if chosen_src_mac is not None:
            if not isinstance(chosen_src_mac, str):
                raise TypeError(f"src_mac must be a string, got {type(chosen_src_mac).__name__}")
            clean_smac = chosen_src_mac.strip()
            if not clean_smac:
                raise ValueError("src_mac must not be empty")
            validated_src_mac = clean_smac

        validated_dst_mac: Optional[str] = None
        if chosen_dst_mac is not None:
            if not isinstance(chosen_dst_mac, str):
                raise TypeError(f"dst_mac must be a string, got {type(chosen_dst_mac).__name__}")
            clean_dmac = chosen_dst_mac.strip()
            if not clean_dmac:
                raise ValueError("dst_mac must not be empty")
            validated_dst_mac = clean_dmac

        # 7. Validate protocols
        validated_proto: Optional[str] = None
        if protocol is not None:
            if not isinstance(protocol, str):
                raise TypeError(f"protocol must be a string, got {type(protocol).__name__}")
            clean_proto = protocol.strip()
            if not clean_proto:
                raise ValueError("protocol must not be empty")
            _check_speculative_network_term(clean_proto, "protocol")
            validated_proto = clean_proto.upper()

        validated_np: Optional[str] = None
        if network_protocol is not None:
            if not isinstance(network_protocol, str):
                raise TypeError(f"network_protocol must be a string, got {type(network_protocol).__name__}")
            clean_np = network_protocol.strip()
            if not clean_np:
                raise ValueError("network_protocol must not be empty")
            _check_speculative_network_term(clean_np, "network_protocol")
            validated_np = clean_np.upper()

        validated_tp: Optional[str] = None
        if transport_protocol is not None:
            if not isinstance(transport_protocol, str):
                raise TypeError(f"transport_protocol must be a string, got {type(transport_protocol).__name__}")
            clean_tp = transport_protocol.strip()
            if not clean_tp:
                raise ValueError("transport_protocol must not be empty")
            _check_speculative_network_term(clean_tp, "transport_protocol")
            validated_tp = clean_tp.upper()

        # 8. Validate timestamps
        validated_raw_ts: Optional[str] = None
        if raw_timestamp is not None:
            if not isinstance(raw_timestamp, str):
                raise TypeError(f"raw_timestamp must be a string or None, got {type(raw_timestamp).__name__}")
            clean_raw_ts = raw_timestamp.strip()
            if not clean_raw_ts:
                raise ValueError("raw_timestamp must not be empty")
            validated_raw_ts = clean_raw_ts

        validated_ts: Optional[datetime] = None
        if timestamp is not None:
            if isinstance(timestamp, datetime):
                validated_ts = timestamp
                if validated_raw_ts is None:
                    validated_raw_ts = timestamp.isoformat()
            elif isinstance(timestamp, (int, float)):
                if isinstance(timestamp, bool):
                    raise TypeError("timestamp cannot be a boolean")
                if timestamp < 0:
                    raise ValueError(f"Numeric timestamp cannot be negative: {timestamp}")
                validated_ts = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                if validated_raw_ts is None:
                    validated_raw_ts = str(timestamp)
            elif isinstance(timestamp, str):
                clean_ts = timestamp.strip()
                if not clean_ts:
                    raise ValueError("timestamp string cannot be empty")
                validated_ts = normalize_timestamp(clean_ts)
                if validated_raw_ts is None:
                    validated_raw_ts = clean_ts
            else:
                raise TypeError(
                    f"timestamp must be a datetime, valid ISO string, epoch number, or None, got {type(timestamp).__name__}"
                )

        # 9. Validate provenance
        validated_source_path: Optional[str] = None
        if source_path is not None:
            if not isinstance(source_path, (str, Path)):
                raise TypeError(f"source_path must be a string, Path, or None, got {type(source_path).__name__}")
            clean_sp = str(source_path).strip()
            if not clean_sp:
                raise ValueError("source_path must not be empty")
            validated_source_path = clean_sp

        validated_aid: Optional[str] = None
        if source_artifact_id is not None:
            if not isinstance(source_artifact_id, str):
                raise TypeError(f"source_artifact_id must be a string or None, got {type(source_artifact_id).__name__}")
            clean_aid = source_artifact_id.strip()
            if not clean_aid:
                raise ValueError("source_artifact_id must not be empty")
            validated_aid = clean_aid

        validated_pcap: Optional[str] = None
        if pcap_name is not None:
            if not isinstance(pcap_name, str):
                raise TypeError(f"pcap_name must be a string or None, got {type(pcap_name).__name__}")
            clean_pn = pcap_name.strip()
            if not clean_pn:
                raise ValueError("pcap_name must not be empty")
            validated_pcap = clean_pn
        elif validated_source_path is not None:
            validated_pcap = Path(validated_source_path).name

        # 10. Validate and freeze packet metadata
        if chosen_meta is None or (isinstance(chosen_meta, (dict, tuple, list)) and len(chosen_meta) == 0):
            frozen_meta: Tuple[Tuple[str, Any], ...] = _FrozenDict()
        elif isinstance(chosen_meta, (dict, tuple, list)):
            _check_metadata_speculative(chosen_meta)
            frozen_meta = freeze_attributes(chosen_meta)
        else:
            raise TypeError(
                f"packet_metadata must be a dict, sequence of pairs, or None, got {type(chosen_meta).__name__}"
            )

        # 11. Compute or validate record ID
        if record_id is not None:
            validated_id = _validate_network_id(record_id)
        else:
            validated_id = compute_deterministic_network_id(
                frame_number=frame_number,
                source_path=validated_source_path,
                source_artifact_id=validated_aid,
                pcap_name=validated_pcap,
                raw_timestamp=validated_raw_ts,
                timestamp=validated_ts,
                captured_length=validated_cap_len,
                original_length=validated_orig_len,
                src_ip=validated_src_ip,
                dst_ip=validated_dst_ip,
                src_port=validated_src_port,
                dst_port=validated_dst_port,
                protocol=validated_proto,
            )

        # Assign immutable fields
        object.__setattr__(self, "record_id", validated_id)
        object.__setattr__(self, "frame_number", frame_number)
        object.__setattr__(self, "timestamp", validated_ts)
        object.__setattr__(self, "raw_timestamp", validated_raw_ts)
        object.__setattr__(self, "captured_length", validated_cap_len)
        object.__setattr__(self, "original_length", validated_orig_len)
        object.__setattr__(self, "link_layer", validated_link_layer)
        object.__setattr__(self, "src_mac", validated_src_mac)
        object.__setattr__(self, "dst_mac", validated_dst_mac)
        object.__setattr__(self, "src_ip", validated_src_ip)
        object.__setattr__(self, "dst_ip", validated_dst_ip)
        object.__setattr__(self, "src_port", validated_src_port)
        object.__setattr__(self, "dst_port", validated_dst_port)
        object.__setattr__(self, "protocol", validated_proto)
        object.__setattr__(self, "network_protocol", validated_np)
        object.__setattr__(self, "transport_protocol", validated_tp)
        object.__setattr__(self, "source_path", validated_source_path)
        object.__setattr__(self, "source_artifact_id", validated_aid)
        object.__setattr__(self, "pcap_name", validated_pcap)
        object.__setattr__(self, "packet_metadata", frozen_meta)

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
    def source_mac(self) -> Optional[str]:
        """Alias for src_mac."""
        return self.src_mac

    @property
    def destination_mac(self) -> Optional[str]:
        """Alias for dst_mac."""
        return self.dst_mac

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

    @property
    def attributes(self) -> Tuple[Tuple[str, Any], ...]:
        """Alias for packet_metadata."""
        return self.packet_metadata

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a deterministic JSON-serializable dictionary representation.

        Guarantees:
        - JSON-safe data types only
        - Explicit representation of None values
        - Deterministic key structure
        - Deeply unfrozen attributes
        """
        return {
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp is not None else None,
            "raw_timestamp": self.raw_timestamp,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "link_layer": self.link_layer,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "network_protocol": self.network_protocol,
            "transport_protocol": self.transport_protocol,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "pcap_name": self.pcap_name,
            "packet_metadata": unfreeze_to_dict(self.packet_metadata),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize record to a deterministic JSON string with sorted keys."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkEvidenceRecord":
        """
        Reconstruct a NetworkEvidenceRecord from a dictionary representation.
        """
        if not isinstance(data, dict):
            raise TypeError(f"from_dict expects a dict, got {type(data).__name__}")
        return cls(
            frame_number=data["frame_number"],
            record_id=data.get("record_id"),
            timestamp=data.get("timestamp"),
            raw_timestamp=data.get("raw_timestamp"),
            captured_length=data.get("captured_length"),
            original_length=data.get("original_length"),
            link_layer=data.get("link_layer"),
            src_mac=data.get("src_mac"),
            dst_mac=data.get("dst_mac"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            network_protocol=data.get("network_protocol"),
            transport_protocol=data.get("transport_protocol"),
            source_path=data.get("source_path"),
            source_artifact_id=data.get("source_artifact_id"),
            pcap_name=data.get("pcap_name"),
            packet_metadata=data.get("packet_metadata"),
        )


def create_network_evidence_record(
    frame_number: int,
    *,
    record_id: Optional[str] = None,
    timestamp: Optional[Union[datetime, str, float, int]] = None,
    raw_timestamp: Optional[str] = None,
    captured_length: Optional[int] = None,
    original_length: Optional[int] = None,
    link_layer: Optional[str] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    network_protocol: Optional[str] = None,
    transport_protocol: Optional[str] = None,
    source_path: Optional[Union[str, Path]] = None,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    packet_metadata: Any = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    source_mac: Optional[str] = None,
    destination_mac: Optional[str] = None,
    packet_length: Optional[int] = None,
    wire_length: Optional[int] = None,
    attributes: Any = None,
) -> NetworkEvidenceRecord:
    """
    Convenience factory to construct an immutable NetworkEvidenceRecord.
    """
    return NetworkEvidenceRecord(
        frame_number=frame_number,
        record_id=record_id,
        timestamp=timestamp,
        raw_timestamp=raw_timestamp,
        captured_length=captured_length,
        original_length=original_length,
        link_layer=link_layer,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        network_protocol=network_protocol,
        transport_protocol=transport_protocol,
        source_path=source_path,
        source_artifact_id=source_artifact_id,
        pcap_name=pcap_name,
        packet_metadata=packet_metadata,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        source_mac=source_mac,
        destination_mac=destination_mac,
        packet_length=packet_length,
        wire_length=wire_length,
        attributes=attributes,
    )
