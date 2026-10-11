"""
Forensic Network Application Metadata Extraction Layer for ForensiX (V5.4 DNS/HTTP/TLS).

Extracts bounded, read-only, deterministic metadata for supported application-layer
protocols (DNS, HTTP, and TLS) from observed network frames and transport payloads
without external lookups, packet injection, payload decryption, stream reassembly,
or speculative threat verdicts.

Strict Forensic Disciplines:
1. Observed vs Derived vs Interpreted:
   - OBSERVED: DNS queries, answers, RCODEs, record types, TTLs, cleartext HTTP methods,
     targets, status codes, selected headers, TLS ClientHello SNI, ALPN, and advertised versions.
   - DERIVED: Deterministic metadata_id (RFC 4122 UUIDv5 under NETMD- namespace),
     normalized domain strings, uppercase method/protocol names.
   - INTERPRETED: Strictly Disallowed. No speculative risk scores, threat verdicts,
     malicious domain classifications, C2 beacon accusations, or intrusion alerts.
2. Anti-Speculation & Bounded Extraction:
   - Does NOT assume single packet contains complete multi-packet message or TCP stream.
   - Does NOT claim negotiated TLS version from a ClientHello that only advertises legacy version.
   - Does NOT attempt to decrypt TLS or claim encrypted payloads were recovered.
   - Does NOT collect or store HTTP message bodies.
   - Prevents DNS compression pointer loops, excessive recursion, and buffer overruns.
3. Provenance Traceability:
   - Preserves source capture path, parent artifact ID, frame number, and record ID.
4. Deep Immutability & Determinism:
   - Strongly typed, frozen dataclasses with deeply frozen attributes.
   - Fully reproducible UUIDv5 identifiers.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import ipaddress
import json
from pathlib import Path
import struct
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union
import uuid

from forensix.network_models import (
    FORENSIX_V5_NETWORK_NAMESPACE,
    NetworkEvidenceRecord,
)
from forensix.network_pcap_parser import (
    DEFAULT_MAX_PACKET_SIZE,
    DLT_EN10MB,
    PcapParser,
    extract_transport_payload,
    read_pcap_raw,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
    _FrozenDict,
    _FrozenList,
    freeze_attributes,
    unfreeze_to_dict,
)


# Canonical RFC 4122 UUID namespace for ForensiX V5 deterministic network metadata identities
FORENSIX_V5_NETWORK_METADATA_NAMESPACE = uuid.uuid5(
    FORENSIX_V5_NETWORK_NAMESPACE, "metadata"
)

# Safety bounds
MAX_DNS_NAME_LENGTH: int = 255
MAX_DNS_LABEL_LENGTH: int = 63
MAX_DNS_POINTER_HOPS: int = 16
MAX_DNS_QUESTIONS: int = 50
MAX_DNS_ANSWERS: int = 100

MAX_HTTP_HEADER_BLOCK_SIZE: int = 8192
MAX_HTTP_HEADER_LINES: int = 64
MAX_HTTP_LINE_LENGTH: int = 4096

MAX_TLS_RECORD_LENGTH: int = 65535


# DNS Type and Class Mappings
DNS_TYPE_NAMES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}

DNS_CLASS_NAMES: Dict[int, str] = {
    1: "IN",
    3: "CH",
    4: "HS",
    255: "ANY",
}

DNS_RCODE_NAMES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

# TLS Version Mappings
TLS_VERSION_NAMES: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Standard HTTP request methods
HTTP_STANDARD_METHODS: Tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "CONNECT",
    "TRACE",
    "PATCH",
)

# Sensitive HTTP headers to redact from reports and timeline events by default
SENSITIVE_HTTP_HEADERS: Tuple[str, ...] = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
)


def compute_deterministic_dns_id(
    record_id: Optional[str],
    frame_number: Optional[int],
    transaction_id: int,
    query_name: Optional[str] = None,
) -> str:
    """Compute a deterministic RFC 4122 UUIDv5 identifier for DNS metadata."""
    rec_part = str(record_id).strip() if record_id else "unknown_record"
    frame_part = f"frame:{frame_number}" if frame_number is not None else "frame:0"
    name_part = str(query_name).strip().lower() if query_name else "none"
    key = f"{rec_part}|dns|0x{transaction_id:04x}|{name_part}|{frame_part}"
    det_uuid = uuid.uuid5(FORENSIX_V5_NETWORK_METADATA_NAMESPACE, key)
    return f"NETMD-DNS-{det_uuid}"


def compute_deterministic_http_id(
    record_id: Optional[str],
    frame_number: Optional[int],
    method_or_status: str,
    target_or_host: Optional[str] = None,
) -> str:
    """Compute a deterministic RFC 4122 UUIDv5 identifier for HTTP metadata."""
    rec_part = str(record_id).strip() if record_id else "unknown_record"
    frame_part = f"frame:{frame_number}" if frame_number is not None else "frame:0"
    verb_part = str(method_or_status).strip().upper()
    target_part = str(target_or_host).strip() if target_or_host else "none"
    key = f"{rec_part}|http|{verb_part}|{target_part}|{frame_part}"
    det_uuid = uuid.uuid5(FORENSIX_V5_NETWORK_METADATA_NAMESPACE, key)
    return f"NETMD-HTTP-{det_uuid}"


def compute_deterministic_tls_id(
    record_id: Optional[str],
    frame_number: Optional[int],
    sni: Optional[str] = None,
    handshake_type: Optional[int] = None,
) -> str:
    """Compute a deterministic RFC 4122 UUIDv5 identifier for TLS metadata."""
    rec_part = str(record_id).strip() if record_id else "unknown_record"
    frame_part = f"frame:{frame_number}" if frame_number is not None else "frame:0"
    sni_part = str(sni).strip().lower() if sni else "none"
    hs_part = f"hs:{handshake_type}" if handshake_type is not None else "hs:none"
    key = f"{rec_part}|tls|{sni_part}|{hs_part}|{frame_part}"
    det_uuid = uuid.uuid5(FORENSIX_V5_NETWORK_METADATA_NAMESPACE, key)
    return f"NETMD-TLS-{det_uuid}"


# ==============================================================================
# Domain Models: DNS, HTTP, TLS
# ==============================================================================

@dataclass(frozen=True)
class DnsQuestion:
    """Immutable forensic representation of a parsed DNS Question record."""

    name: str
    qtype: str
    qclass: str
    type_id: int
    class_id: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "qtype": self.qtype,
            "qclass": self.qclass,
            "type_id": self.type_id,
            "class_id": self.class_id,
        }


@dataclass(frozen=True)
class DnsAnswer:
    """Immutable forensic representation of a parsed DNS Resource Record answer."""

    name: str
    rtype: str
    rclass: str
    ttl: int
    data: str
    type_id: int
    class_id: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "rtype": self.rtype,
            "rclass": self.rclass,
            "ttl": self.ttl,
            "data": self.data,
            "type_id": self.type_id,
            "class_id": self.class_id,
        }


@dataclass(frozen=True)
class DnsMetadata:
    """
    Immutable forensic representation of extracted DNS protocol observation.
    """

    metadata_id: str
    transaction_id: int
    is_response: bool
    response_code: int
    response_status: str
    query_name: Optional[str] = None
    query_type: Optional[str] = None
    query_class: Optional[str] = None
    questions: Tuple[DnsQuestion, ...] = ()
    answers: Tuple[DnsAnswer, ...] = ()
    flags: Tuple[Tuple[str, bool], ...] = ()
    record_id: Optional[str] = None
    frame_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    transport_protocol: str = "UDP"
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata_id": self.metadata_id,
            "transaction_id": self.transaction_id,
            "is_response": self.is_response,
            "response_code": self.response_code,
            "response_status": self.response_status,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "query_class": self.query_class,
            "questions": [q.to_dict() for q in self.questions],
            "answers": [a.to_dict() for a in self.answers],
            "answers_data": [a.data for a in self.answers],
            "flags": dict(self.flags),
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "transport_protocol": self.transport_protocol,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "attributes": dict(self.attributes) if self.attributes else {},
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class HttpMetadata:
    """
    Immutable forensic representation of extracted cleartext HTTP protocol observation.
    """

    metadata_id: str
    is_request: bool
    method: Optional[str] = None
    target: Optional[str] = None
    http_version: Optional[str] = None
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None
    host: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    server: Optional[str] = None
    headers: Tuple[Tuple[str, str], ...] = ()
    record_id: Optional[str] = None
    frame_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata_id": self.metadata_id,
            "is_request": self.is_request,
            "method": self.method,
            "target": self.target,
            "http_version": self.http_version,
            "status_code": self.status_code,
            "reason_phrase": self.reason_phrase,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "server": self.server,
            "headers": list(self.headers),
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "attributes": dict(self.attributes) if self.attributes else {},
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class TlsMetadata:
    """
    Immutable forensic representation of extracted TLS handshake observation.
    """

    metadata_id: str
    content_type: int
    handshake_type: Optional[int] = None
    is_client_hello: bool = False
    server_name: Optional[str] = None
    alpn_protocols: Tuple[str, ...] = ()
    record_version: Optional[str] = None
    client_version: Optional[str] = None
    supported_versions: Tuple[str, ...] = ()
    record_id: Optional[str] = None
    frame_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata_id": self.metadata_id,
            "content_type": self.content_type,
            "handshake_type": self.handshake_type,
            "is_client_hello": self.is_client_hello,
            "server_name": self.server_name,
            "alpn_protocols": list(self.alpn_protocols),
            "record_version": self.record_version,
            "client_version": self.client_version,
            "supported_versions": list(self.supported_versions),
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "attributes": dict(self.attributes) if self.attributes else {},
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class NetworkApplicationMetadata:
    """
    Unified forensic envelope container for application-layer metadata observations.
    """

    metadata_id: str
    protocol: str
    dns: Optional[DnsMetadata] = None
    http: Optional[HttpMetadata] = None
    tls: Optional[TlsMetadata] = None
    record_id: Optional[str] = None
    frame_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    source_path: Optional[str] = None
    source_artifact_id: Optional[str] = None
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "metadata_id": self.metadata_id,
            "protocol": self.protocol,
            "record_id": self.record_id,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "transport_protocol": self.transport_protocol,
            "source_path": self.source_path,
            "source_artifact_id": self.source_artifact_id,
            "attributes": dict(self.attributes) if self.attributes else {},
        }
        if self.source_ip is not None:
            res["src_ip"] = self.source_ip
        if self.destination_ip is not None:
            res["dst_ip"] = self.destination_ip
        if self.source_port is not None:
            res["src_port"] = self.source_port
        if self.destination_port is not None:
            res["dst_port"] = self.destination_port

        if self.dns is not None:
            res["dns"] = self.dns.to_dict()
            if self.dns.query_name is not None:
                res["query_name"] = self.dns.query_name
            if self.dns.query_type is not None:
                res["query_type"] = self.dns.query_type
            if self.dns.answers:
                res["answers_data"] = [a.data for a in self.dns.answers]
        if self.http is not None:
            res["http"] = self.http.to_dict()
            if self.http.host is not None:
                res["host"] = self.http.host
            if self.http.target is not None:
                res["target"] = self.http.target
            if self.http.method is not None:
                res["method"] = self.http.method
            if self.http.status_code is not None:
                res["status_code"] = self.http.status_code
        if self.tls is not None:
            res["tls"] = self.tls.to_dict()
            if self.tls.server_name is not None:
                res["server_name"] = self.tls.server_name
                res["sni"] = self.tls.server_name
            if self.tls.alpn_protocols:
                res["alpn_protocols"] = list(self.tls.alpn_protocols)
        return res

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_timeline_event(self) -> TimelineEvent:
        """
        Convert this application metadata record into a canonical ForensiX TimelineEvent.
        """
        desc_parts: List[str] = [f"Network {self.protocol} observation"]
        if self.dns is not None:
            if self.dns.is_response:
                ans_summary = f" ({len(self.dns.answers)} answers, {self.dns.response_status})"
                desc_parts.append(f"DNS response for {self.dns.query_name or 'unknown'}{ans_summary}")
            else:
                desc_parts.append(f"DNS query for {self.dns.query_name or 'unknown'} ({self.dns.query_type or 'A'})")
        elif self.http is not None:
            if self.http.is_request:
                desc_parts.append(f"HTTP {self.http.method} {self.http.target} (Host: {self.http.host or 'unknown'})")
            else:
                desc_parts.append(f"HTTP response {self.http.status_code} {self.http.reason_phrase or ''}".strip())
        elif self.tls is not None:
            sni_info = f" (SNI: {self.tls.server_name})" if self.tls.server_name else ""
            desc_parts.append(f"TLS ClientHello{sni_info}")

        ep_src = f"{self.source_ip or 'unknown'}:{self.source_port or '?'}"
        ep_dst = f"{self.destination_ip or 'unknown'}:{self.destination_port or '?'}"
        description = f"{' - '.join(desc_parts)} from {ep_src} to {ep_dst}"

        raw_meta = self.to_dict()
        return TimelineEvent(
            timestamp=self.timestamp,
            raw_timestamp=self.raw_timestamp,
            category=TimelineCategory.NETWORK,
            event_type=f"network_{self.protocol.lower()}_metadata",
            description=description,
            source_path=self.source_path,
            source_line=self.frame_number,
            source_artifact_id=self.source_artifact_id,
            source_event_id=self.record_id or self.metadata_id,
            attributes=raw_meta,
        )


# ==============================================================================
# Protocol Parsers: DNS, HTTP, TLS
# ==============================================================================

def _parse_dns_name(data: bytes, offset: int, max_hops: int = MAX_DNS_POINTER_HOPS) -> Tuple[Optional[str], int]:
    """
    Safely parse and decompress a DNS domain name from packet payload.

    Guarantees:
    - Rejects compression pointer loops via visited offset set.
    - Limits pointer traversal to max_hops.
    - Enforces label length (<= 63) and domain length (<= 255) bounds.
    - Never raises out-of-bounds IndexError.
    - Returns (None, next_offset) if name is truncated or invalid.
    """
    labels: List[str] = []
    hops = 0
    visited = set()
    stepped = False
    next_offset = offset
    valid = False

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            if not stepped:
                next_offset = offset + 1
            valid = True
            break

        # Compression pointer (top 2 bits 11)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr_offset = ((length & 0x3F) << 8) | data[offset + 1]
            if not stepped:
                next_offset = offset + 2
                stepped = True
            if ptr_offset in visited or hops >= max_hops or ptr_offset >= len(data):
                # Detected pointer loop, excessive recursion, or out-of-bounds pointer
                break
            visited.add(ptr_offset)
            hops += 1
            offset = ptr_offset
            continue

        elif length <= MAX_DNS_LABEL_LENGTH:
            offset += 1
            if offset + length > len(data):
                break
            try:
                label = data[offset:offset + length].decode("utf-8", errors="replace")
            except Exception:
                label = "invalid_label"
            labels.append(label)
            offset += length
            if not stepped:
                next_offset = offset
        else:
            # Invalid label length
            break

    if not valid:
        return None, next_offset

    name = ".".join(labels)
    if len(name) > MAX_DNS_NAME_LENGTH:
        name = name[:MAX_DNS_NAME_LENGTH]
    return name, next_offset


def parse_dns_payload(
    payload: bytes,
    transport_protocol: str = "UDP",
    record_id: Optional[str] = None,
    frame_number: Optional[int] = None,
    timestamp: Optional[datetime] = None,
    raw_timestamp: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    source_path: Optional[str] = None,
    source_artifact_id: Optional[str] = None,
) -> Optional[DnsMetadata]:
    """
    Safely parse raw packet payload as a DNS query or response.

    Returns None if payload is too short, corrupt, malformed, or not valid DNS.
    """
    if not payload or len(payload) < 12:
        return None

    dns_data = payload

    # DNS over TCP is prefixed by a 2-byte message length
    if transport_protocol == "TCP":
        if len(payload) >= 14:
            tcp_len = struct.unpack(">H", payload[0:2])[0]
            if tcp_len <= len(payload) - 2:
                dns_data = payload[2:2 + tcp_len]
            else:
                # Truncated or multi-segment TCP message without stream reassembly
                dns_data = payload[2:]
        else:
            return None

    if len(dns_data) < 12:
        return None

    tx_id, flags_word, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", dns_data[0:12]
    )

    # Sanity checks on header invariants to prevent arbitrary UDP payload false positives
    opcode = (flags_word >> 11) & 0x0F
    if opcode > 5:
        return None
    if qdcount > MAX_DNS_QUESTIONS or ancount > MAX_DNS_ANSWERS or nscount > 50 or arcount > 50:
        return None

    is_response = bool(flags_word & 0x8000)
    rcode = flags_word & 0x000F
    rcode_name = DNS_RCODE_NAMES.get(rcode, f"RCODE-{rcode}")

    flags_tuple: Tuple[Tuple[str, bool], ...] = (
        ("aa", bool(flags_word & 0x0400)),
        ("tc", bool(flags_word & 0x0200)),
        ("rd", bool(flags_word & 0x0100)),
        ("ra", bool(flags_word & 0x0080)),
    )

    offset = 12
    questions: List[DnsQuestion] = []
    primary_qname: Optional[str] = None
    primary_qtype: Optional[str] = None
    primary_qclass: Optional[str] = None

    # Parse Questions
    for _ in range(qdcount):
        if offset >= len(dns_data):
            break
        qname, offset = _parse_dns_name(dns_data, offset)
        if qname is None or offset + 4 > len(dns_data):
            break
        qtype_num, qclass_num = struct.unpack(">HH", dns_data[offset:offset + 4])
        offset += 4
        qtype_str = DNS_TYPE_NAMES.get(qtype_num, f"TYPE-{qtype_num}")
        qclass_str = DNS_CLASS_NAMES.get(qclass_num, f"CLASS-{qclass_num}")
        questions.append(
            DnsQuestion(
                name=qname,
                qtype=qtype_str,
                qclass=qclass_str,
                type_id=qtype_num,
                class_id=qclass_num,
            )
        )
        if primary_qname is None:
            primary_qname = qname
            primary_qtype = qtype_str
            primary_qclass = qclass_str

    # Truncated query validation
    if qdcount > 0 and len(questions) < qdcount and not is_response:
        return None

    # Parse Answers
    answers: List[DnsAnswer] = []
    for _ in range(ancount):
        if offset >= len(dns_data):
            break
        ans_name, offset = _parse_dns_name(dns_data, offset)
        if ans_name is None or offset + 10 > len(dns_data):
            break
        ans_type, ans_class, ttl, rdlen = struct.unpack(">HHIH", dns_data[offset:offset + 10])
        offset += 10
        if offset + rdlen > len(dns_data):
            break

        rdata_bytes = dns_data[offset:offset + rdlen]
        rdata_str: str = ""

        if ans_type == 1 and rdlen == 4:  # A (IPv4)
            rdata_str = str(ipaddress.IPv4Address(rdata_bytes))
        elif ans_type == 28 and rdlen == 16:  # AAAA (IPv6)
            rdata_str = str(ipaddress.IPv6Address(rdata_bytes))
        elif ans_type in (5, 12):  # CNAME or PTR
            cname, _ = _parse_dns_name(dns_data, offset)
            rdata_str = cname or ""
        elif ans_type == 16:  # TXT
            txt_parts: List[str] = []
            t_idx = 0
            while t_idx < len(rdata_bytes):
                t_len = rdata_bytes[t_idx]
                t_idx += 1
                if t_idx + t_len <= len(rdata_bytes):
                    txt_parts.append(rdata_bytes[t_idx:t_idx + t_len].decode("utf-8", errors="replace"))
                    t_idx += t_len
                else:
                    break
            rdata_str = " ".join(txt_parts)
        elif ans_type == 15 and rdlen >= 2:  # MX
            pref = struct.unpack(">H", rdata_bytes[0:2])[0]
            mx_name, _ = _parse_dns_name(dns_data, offset + 2)
            rdata_str = f"{pref} {mx_name or ''}"
        else:
            rdata_str = rdata_bytes.hex()

        offset += rdlen
        answers.append(
            DnsAnswer(
                name=ans_name,
                rtype=DNS_TYPE_NAMES.get(ans_type, f"TYPE-{ans_type}"),
                rclass=DNS_CLASS_NAMES.get(ans_class, f"CLASS-{ans_class}"),
                ttl=ttl,
                data=rdata_str,
                type_id=ans_type,
                class_id=ans_class,
            )
        )

    # Truncated response validation
    if ancount > 0 and len(answers) < ancount:
        return None

    # Must contain at least one question or answer to be recognized as valid DNS
    if not questions and not answers:
        return None

    metadata_id = compute_deterministic_dns_id(
        record_id=record_id,
        frame_number=frame_number,
        transaction_id=tx_id,
        query_name=primary_qname,
    )

    return DnsMetadata(
        metadata_id=metadata_id,
        transaction_id=tx_id,
        is_response=is_response,
        response_code=rcode,
        response_status=rcode_name,
        query_name=primary_qname,
        query_type=primary_qtype,
        query_class=primary_qclass,
        questions=tuple(questions),
        answers=tuple(answers),
        flags=flags_tuple,
        record_id=record_id,
        frame_number=frame_number,
        timestamp=timestamp,
        raw_timestamp=raw_timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        transport_protocol=transport_protocol,
        source_path=source_path,
        source_artifact_id=source_artifact_id,
    )


def parse_http_payload(
    payload: bytes,
    record_id: Optional[str] = None,
    frame_number: Optional[int] = None,
    timestamp: Optional[datetime] = None,
    raw_timestamp: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    source_path: Optional[str] = None,
    source_artifact_id: Optional[str] = None,
) -> Optional[HttpMetadata]:
    """
    Safely parse raw packet payload as cleartext HTTP request or response.

    Returns None if payload is binary, TLS, or does not conform to HTTP syntax.
    Never stores or logs the HTTP message body.
    """
    if not payload or len(payload) < 10:
        return None

    # Fast rejection of TLS Handshake or binary records
    if payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        return None

    # Bound payload scan to prevent CPU exhaustion on oversized headers
    scan_limit = min(len(payload), MAX_HTTP_HEADER_BLOCK_SIZE)
    header_bytes = payload[:scan_limit]

    # Split into lines
    raw_lines = header_bytes.split(b"\n")
    if not raw_lines:
        return None

    first_line_raw = raw_lines[0].rstrip(b"\r")
    if len(first_line_raw) > MAX_HTTP_LINE_LENGTH:
        return None

    try:
        first_line = first_line_raw.decode("ascii", errors="replace").strip()
    except Exception:
        return None

    parts = first_line.split(" ")
    is_request = False
    method: Optional[str] = None
    target: Optional[str] = None
    http_version: Optional[str] = None
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None

    if len(parts) >= 3 and parts[0].upper() in HTTP_STANDARD_METHODS and parts[2].startswith("HTTP/"):
        # HTTP Request: METHOD SP TARGET SP HTTP/VERSION
        is_request = True
        method = parts[0].upper()
        target = parts[1]
        http_version = parts[2]
    elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
        # HTTP Response: HTTP/VERSION SP STATUS_CODE [SP REASON]
        is_request = False
        http_version = parts[0]
        try:
            status_code = int(parts[1])
            if status_code < 100 or status_code > 599:
                return None
        except ValueError:
            return None
        reason_phrase = " ".join(parts[2:]) if len(parts) > 2 else None
    else:
        # Not a valid HTTP request or response line
        return None

    # Parse headers up to blank line or limit
    headers: List[Tuple[str, str]] = []
    host: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    server: Optional[str] = None

    line_count = 0
    for line_bytes in raw_lines[1:]:
        line_count += 1
        if line_count > MAX_HTTP_HEADER_LINES:
            break
        stripped = line_bytes.rstrip(b"\r")
        if not stripped:
            # End of headers block
            break
        if len(stripped) > MAX_HTTP_LINE_LENGTH:
            continue
        try:
            line_str = stripped.decode("ascii", errors="replace")
        except Exception:
            continue

        if ":" in line_str:
            k, v = line_str.split(":", 1)
            hdr_name = k.strip()
            hdr_val = v.strip()
            lower_name = hdr_name.lower()
            if lower_name in SENSITIVE_HTTP_HEADERS:
                hdr_val = "[REDACTED]"
            headers.append((hdr_name, hdr_val))

            if lower_name == "host" and host is None:
                host = hdr_val
            elif lower_name == "user-agent" and user_agent is None:
                user_agent = hdr_val
            elif lower_name == "content-type" and content_type is None:
                content_type = hdr_val
            elif lower_name == "content-length" and content_length is None:
                try:
                    content_length = int(hdr_val)
                except ValueError:
                    pass
            elif lower_name == "server" and server is None:
                server = hdr_val

    verb_or_status = method if is_request else str(status_code)
    target_or_host = target if is_request else host

    metadata_id = compute_deterministic_http_id(
        record_id=record_id,
        frame_number=frame_number,
        method_or_status=verb_or_status or "UNKNOWN",
        target_or_host=target_or_host,
    )

    return HttpMetadata(
        metadata_id=metadata_id,
        is_request=is_request,
        method=method,
        target=target,
        http_version=http_version,
        status_code=status_code,
        reason_phrase=reason_phrase,
        host=host,
        user_agent=user_agent,
        content_type=content_type,
        content_length=content_length,
        server=server,
        headers=tuple(headers),
        record_id=record_id,
        frame_number=frame_number,
        timestamp=timestamp,
        raw_timestamp=raw_timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        source_path=source_path,
        source_artifact_id=source_artifact_id,
    )


def parse_tls_payload(
    payload: bytes,
    record_id: Optional[str] = None,
    frame_number: Optional[int] = None,
    timestamp: Optional[datetime] = None,
    raw_timestamp: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    source_path: Optional[str] = None,
    source_artifact_id: Optional[str] = None,
) -> Optional[TlsMetadata]:
    """
    Safely parse raw packet payload as TLS handshake metadata.

    Extracts ClientHello attributes including SNI, ALPN, and advertised versions.
    Does NOT attempt to decrypt traffic or claim negotiated version from ClientHello.
    """
    if not payload or len(payload) < 5:
        return None

    content_type = payload[0]
    # Valid TLS content types: 20 (ChangeCipherSpec), 21 (Alert), 22 (Handshake), 23 (ApplicationData)
    if content_type not in (20, 21, 22, 23):
        return None

    rec_version_raw = struct.unpack(">H", payload[1:3])[0]
    if rec_version_raw not in TLS_VERSION_NAMES and (rec_version_raw >> 8) != 3:
        return None

    rec_len = struct.unpack(">H", payload[3:5])[0]
    record_version_str = TLS_VERSION_NAMES.get(rec_version_raw, f"0x{rec_version_raw:04X}")

    handshake_type: Optional[int] = None
    is_client_hello = False
    server_name: Optional[str] = None
    alpn_list: List[str] = []
    client_version_str: Optional[str] = None
    supported_versions: List[str] = []

    if content_type == 22 and len(payload) >= 9:
        handshake_type = payload[5]
        hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]

        if handshake_type == 1:  # ClientHello
            is_client_hello = True
            offset = 9
            # Verify 2-byte client_version + 32-byte random
            if len(payload) >= offset + 34:
                c_ver_raw = struct.unpack(">H", payload[offset:offset + 2])[0]
                client_version_str = TLS_VERSION_NAMES.get(c_ver_raw, f"0x{c_ver_raw:04X}")
                offset += 34

                # Session ID
                if offset < len(payload):
                    sess_len = payload[offset]
                    offset += 1 + sess_len

                    # Cipher suites length
                    if offset + 2 <= len(payload):
                        cs_len = struct.unpack(">H", payload[offset:offset + 2])[0]
                        offset += 2 + cs_len

                        # Compression methods length
                        if offset + 1 <= len(payload):
                            comp_len = payload[offset]
                            offset += 1 + comp_len

                            # Extensions block
                            if offset + 2 <= len(payload):
                                exts_len = struct.unpack(">H", payload[offset:offset + 2])[0]
                                offset += 2
                                exts_end = min(offset + exts_len, len(payload))

                                # Parse extensions safely
                                while offset + 4 <= exts_end:
                                    ext_type, ext_len = struct.unpack(
                                        ">HH", payload[offset:offset + 4]
                                    )
                                    ext_data_end = offset + 4 + ext_len
                                    if ext_data_end > exts_end:
                                        # Extension cut off
                                        break
                                    ext_data = payload[offset + 4:ext_data_end]

                                    if ext_type == 0x0000:  # Server Name Indication (SNI)
                                        if len(ext_data) >= 5:
                                            # 2 bytes list len, 1 byte type, 2 bytes name len
                                            sni_type = ext_data[2]
                                            sni_len = struct.unpack(">H", ext_data[3:5])[0]
                                            if sni_type == 0 and len(ext_data) >= 5 + sni_len:
                                                server_name = ext_data[5:5 + sni_len].decode(
                                                    "ascii", errors="replace"
                                                )

                                    elif ext_type == 0x0010:  # ALPN
                                        if len(ext_data) >= 2:
                                            idx = 2
                                            while idx < len(ext_data):
                                                p_len = ext_data[idx]
                                                idx += 1
                                                if idx + p_len <= len(ext_data):
                                                    alpn_list.append(
                                                        ext_data[idx:idx + p_len].decode(
                                                            "ascii", errors="replace"
                                                        )
                                                    )
                                                    idx += p_len
                                                else:
                                                    break

                                    elif ext_type == 0x002B:  # supported_versions (TLS 1.3)
                                        if len(ext_data) >= 1:
                                            idx = 1
                                            while idx + 2 <= len(ext_data):
                                                ver_num = struct.unpack(
                                                    ">H", ext_data[idx:idx + 2]
                                                )[0]
                                                supported_versions.append(
                                                    TLS_VERSION_NAMES.get(
                                                        ver_num, f"0x{ver_num:04X}"
                                                    )
                                                )
                                                idx += 2

                                    offset = ext_data_end

    metadata_id = compute_deterministic_tls_id(
        record_id=record_id,
        frame_number=frame_number,
        sni=server_name,
        handshake_type=handshake_type,
    )

    return TlsMetadata(
        metadata_id=metadata_id,
        content_type=content_type,
        handshake_type=handshake_type,
        is_client_hello=is_client_hello,
        server_name=server_name,
        alpn_protocols=tuple(alpn_list),
        record_version=record_version_str,
        client_version=client_version_str,
        supported_versions=tuple(supported_versions),
        record_id=record_id,
        frame_number=frame_number,
        timestamp=timestamp,
        raw_timestamp=raw_timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        source_path=source_path,
        source_artifact_id=source_artifact_id,
    )


# ==============================================================================
# Unified Application Metadata Extraction
# ==============================================================================

def extract_application_metadata(
    payload: bytes,
    record: Optional[NetworkEvidenceRecord] = None,
    transport_protocol: Optional[str] = None,
) -> Optional[NetworkApplicationMetadata]:
    """
    Extract application-layer metadata (DNS, HTTP, or TLS) from a transport payload.

    Args:
        payload: Transport payload bytes.
        record: Optional originating NetworkEvidenceRecord for context and provenance.
        transport_protocol: Optional transport protocol override ('TCP' or 'UDP').

    Returns:
        NetworkApplicationMetadata if a supported protocol observation is parsed, else None.
    """
    if not payload:
        return None

    proto = transport_protocol or (record.transport_protocol if record else None)
    rec_id = record.record_id if record else None
    frame_num = record.frame_number if record else None
    ts = record.timestamp if record else None
    raw_ts = record.raw_timestamp if record else None
    s_ip = record.source_ip if record else None
    d_ip = record.destination_ip if record else None
    s_port = record.source_port if record else None
    d_port = record.destination_port if record else None
    s_path = record.source_path if record else None
    s_art = record.source_artifact_id if record else None

    # 1. Try TLS if TCP or starting with TLS record header (0x16, 0x14, 0x15, 0x17)
    if proto in (None, "TCP") and len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3:
        tls_meta = parse_tls_payload(
            payload,
            record_id=rec_id,
            frame_number=frame_num,
            timestamp=ts,
            raw_timestamp=raw_ts,
            source_ip=s_ip,
            destination_ip=d_ip,
            source_port=s_port,
            destination_port=d_port,
            source_path=s_path,
            source_artifact_id=s_art,
        )
        if tls_meta is not None:
            return NetworkApplicationMetadata(
                metadata_id=tls_meta.metadata_id,
                protocol="TLS",
                tls=tls_meta,
                record_id=rec_id,
                frame_number=frame_num,
                timestamp=ts,
                raw_timestamp=raw_ts,
                source_ip=s_ip,
                destination_ip=d_ip,
                source_port=s_port,
                destination_port=d_port,
                transport_protocol=proto or "TCP",
                source_path=s_path,
                source_artifact_id=s_art,
            )

    # 2. Try HTTP if TCP or port 80/8080 or starts with ASCII method/version
    if proto in (None, "TCP"):
        http_meta = parse_http_payload(
            payload,
            record_id=rec_id,
            frame_number=frame_num,
            timestamp=ts,
            raw_timestamp=raw_ts,
            source_ip=s_ip,
            destination_ip=d_ip,
            source_port=s_port,
            destination_port=d_port,
            source_path=s_path,
            source_artifact_id=s_art,
        )
        if http_meta is not None:
            return NetworkApplicationMetadata(
                metadata_id=http_meta.metadata_id,
                protocol="HTTP",
                http=http_meta,
                record_id=rec_id,
                frame_number=frame_num,
                timestamp=ts,
                raw_timestamp=raw_ts,
                source_ip=s_ip,
                destination_ip=d_ip,
                source_port=s_port,
                destination_port=d_port,
                transport_protocol=proto or "TCP",
                source_path=s_path,
                source_artifact_id=s_art,
            )

    # 3. Try DNS (UDP or TCP)
    dns_meta = parse_dns_payload(
        payload,
        transport_protocol=proto or "UDP",
        record_id=rec_id,
        frame_number=frame_num,
        timestamp=ts,
        raw_timestamp=raw_ts,
        source_ip=s_ip,
        destination_ip=d_ip,
        source_port=s_port,
        destination_port=d_port,
        source_path=s_path,
        source_artifact_id=s_art,
    )
    if dns_meta is not None:
        return NetworkApplicationMetadata(
            metadata_id=dns_meta.metadata_id,
            protocol="DNS",
            dns=dns_meta,
            record_id=rec_id,
            frame_number=frame_num,
            timestamp=ts,
            raw_timestamp=raw_ts,
            source_ip=s_ip,
            destination_ip=d_ip,
            source_port=s_port,
            destination_port=d_port,
            transport_protocol=proto or "UDP",
            source_path=s_path,
            source_artifact_id=s_art,
        )

    return None


def extract_metadata_from_packet(
    record: NetworkEvidenceRecord,
    packet_bytes: bytes,
    link_type: int = DLT_EN10MB,
) -> Optional[NetworkApplicationMetadata]:
    """
    Extract application metadata from a NetworkEvidenceRecord and raw captured frame.
    """
    trans_proto, s_port, d_port, payload = extract_transport_payload(packet_bytes, link_type)
    if not payload:
        return None
    return extract_application_metadata(
        payload,
        record=record,
        transport_protocol=trans_proto,
    )


def extract_metadata_from_pcap(
    source: Union[str, Path, BinaryIO],
    *,
    source_artifact_id: Optional[str] = None,
    pcap_name: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
) -> Iterator[NetworkApplicationMetadata]:
    """
    Stream application-layer metadata incrementally from a classic PCAP capture file.

    Yields:
        NetworkApplicationMetadata: Bounded, validated metadata for DNS, HTTP, or TLS frames.
    """
    parser = PcapParser(
        source,
        source_artifact_id=source_artifact_id,
        pcap_name=pcap_name,
        max_packet_size=max_packet_size,
    )
    link_type = parser.global_header.network

    for record, packet_bytes in parser.read_raw_records(max_packets=max_packets):
        meta = extract_metadata_from_packet(record, packet_bytes, link_type)
        if meta is not None:
            yield meta


class NetworkMetadataExtractor:
    """
    High-level, object-oriented metadata extractor for ForensiX network captures.
    """

    def __init__(self, default_link_type: int = DLT_EN10MB) -> None:
        self.default_link_type = default_link_type

    def extract_from_payload(
        self,
        payload: bytes,
        record: Optional[NetworkEvidenceRecord] = None,
        transport_protocol: Optional[str] = None,
    ) -> Optional[NetworkApplicationMetadata]:
        """Extract metadata from transport payload bytes."""
        return extract_application_metadata(
            payload,
            record=record,
            transport_protocol=transport_protocol,
        )

    def extract_from_packet(
        self,
        record: NetworkEvidenceRecord,
        packet_bytes: bytes,
        link_type: Optional[int] = None,
    ) -> Optional[NetworkApplicationMetadata]:
        """Extract metadata from an evidence record and frame bytes."""
        lt = link_type if link_type is not None else self.default_link_type
        return extract_metadata_from_packet(record, packet_bytes, lt)

    def extract_from_pcap(
        self,
        source: Union[str, Path, BinaryIO],
        *,
        source_artifact_id: Optional[str] = None,
        pcap_name: Optional[str] = None,
        max_packets: Optional[int] = None,
    ) -> Iterator[NetworkApplicationMetadata]:
        """Stream application metadata directly from a PCAP source."""
        return extract_metadata_from_pcap(
            source,
            source_artifact_id=source_artifact_id,
            pcap_name=pcap_name,
            max_packets=max_packets,
        )
