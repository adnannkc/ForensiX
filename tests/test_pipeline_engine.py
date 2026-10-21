"""
Comprehensive Integration Tests for ForensiX V9 Pipeline Engine.

Validates:
1. Host-only evidence run.
2. PCAP-only evidence run.
3. Memory-only evidence run.
4. Combined multi-domain run (Host + PCAP + Memory).
5. Error containment for malformed PCAP (contained as FAILED/PARTIAL, does not crash).
6. Evidence immutability verification proving original inputs are bitwise identical after runs.
7. Verification that run manifest is named exactly 'pipeline_manifest.json'.
"""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from forensix.case_config import CaseConfig
from forensix.pipeline_engine import (
    EXIT_SUCCESS,
    EXIT_VERIFICATION_OR_PARTIAL,
    InvestigationPipeline,
    run_pipeline,
)
from forensix.pipeline_models import PipelineRunStatus, PipelineStageId


def _create_synthetic_pcap(path: Path) -> None:
    """Create a minimal valid synthetic classic PCAP file."""
    # Global header (24 bytes): Magic 0xA1B2C3D4 (big endian), v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Frame 1: Packet header (16 bytes)
    # ts_sec=1760000000, ts_usec=500000, incl_len=54, orig_len=54
    pkt_hdr = struct.pack(">IIII", 1760000000, 500000, 54, 54)

    # Ethernet header (14 bytes): dst MAC, src MAC, EtherType 0x0800 (IPv4)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    # IPv4 header (20 bytes): ver/ihl=0x45, dscp/ecn=0, total_len=40, id=1, flags/frag=0x4000, ttl=64, proto=6 (TCP), cksum=0, src=192.0.2.10, dst=198.51.100.25
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0x4000, 64, 6, 0,
        bytes([192, 0, 2, 10]), bytes([198, 51, 100, 25])
    )

    # TCP header (20 bytes): src_port=54321, dst_port=22, seq=100, ack=0, offset/flags=0x5002 (SYN), win=64240, cksum=0, urg=0
    tcp = struct.pack(">HHIIBBHHH", 54321, 22, 100, 0, 0x50, 0x02, 64240, 0, 0)

    payload = global_hdr + pkt_hdr + eth + ip + tcp
    path.write_bytes(payload)


def _create_synthetic_host(root: Path) -> None:
    """Create minimal synthetic Linux host artifacts."""
    etc_dir = root / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    var_log = root / "var" / "log"
    var_log.mkdir(parents=True, exist_ok=True)

    # /etc/passwd
    (etc_dir / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "analyst:x:1000:1000:Forensic Analyst:/home/analyst:/bin/bash\n"
    )
    # /etc/group
    (etc_dir / "group").write_text(
        "root:x:0:\n"
        "sudo:x:27:analyst\n"
    )
    # /var/log/auth.log
    (var_log / "auth.log").write_text(
        "2026-10-21T08:00:00.100000+00:00 host sshd[1024]: Accepted password for analyst from 192.0.2.10 port 54321 ssh2\n"
        "2026-10-21T08:05:00.200000+00:00 host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id\n"
    )


def _create_synthetic_memory_json(path: Path) -> None:
    """Create minimal synthetic memory artifacts JSON."""
    records = [
        {
            "artifact_id": "MEMPROC-11111111-1111-4111-8111-111111111111",
            "evidence_id": "MEM-33333333-3333-4333-8333-333333333333",
            "pid": 1024,
            "ppid": 1,
            "process_name": "sshd",
            "source_plugin": "linux.pslist.PsList",
            "created_at": "2026-10-21T07:55:00+00:00",
            "raw_attributes": {"cmdline": "/usr/sbin/sshd -D"},
        },
        {
            "artifact_id": "MEMNET-22222222-2222-4222-8222-222222222222",
            "evidence_id": "MEM-33333333-3333-4333-8333-333333333333",
            "protocol": "TCP",
            "local_address": "0.0.0.0",
            "local_port": 22,
            "state": "LISTEN",
            "pid": 1024,
            "process_name": "sshd",
            "source_plugin": "linux.sockscan.SockScan",
            "raw_attributes": {},
        },
    ]
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


class TestPipelineEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.host_dir = self.base_dir / "evidence_host"
        _create_synthetic_host(self.host_dir)

        self.pcap_file = self.base_dir / "capture.pcap"
        _create_synthetic_pcap(self.pcap_file)

        self.mem_file = self.base_dir / "memory_artifacts.json"
        _create_synthetic_memory_json(self.mem_file)

        self.out_dir = self.base_dir / "reports_out"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_host_only_run(self):
        """Prove pipeline executes cleanly with host-only evidence input."""
        config = CaseConfig(
            case_id="HOST_ONLY_01",
            evidence_host_dir=self.host_dir,
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)
        self.assertEqual(res.run_manifest.run_status, PipelineRunStatus.SUCCESS.value)
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())
        self.assertTrue((self.out_dir / "report_HOST_ONLY_01.json").exists())
        self.assertTrue((self.out_dir / "report_HOST_ONLY_01.html").exists())
        self.assertTrue((self.out_dir / "ledger_HOST_ONLY_01.json").exists())

        # Check stage statuses
        stage_map = {s.stage_id: s.status for s in res.run_manifest.stages}
        self.assertEqual(stage_map["host_analysis"], "COMPLETED")
        self.assertEqual(stage_map["network_analysis"], "SKIPPED")
        self.assertEqual(stage_map["memory_analysis"], "SKIPPED")

    def test_02_pcap_only_run(self):
        """Prove pipeline executes cleanly with PCAP-only evidence input."""
        config = CaseConfig(
            case_id="PCAP-ONLY-01",
            evidence_pcap_files=(self.pcap_file,),
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)
        stage_map = {s.stage_id: s.status for s in res.run_manifest.stages}
        self.assertEqual(stage_map["host_analysis"], "SKIPPED")
        self.assertEqual(stage_map["network_analysis"], "COMPLETED")
        self.assertEqual(stage_map["memory_analysis"], "SKIPPED")
        self.assertGreater(res.run_manifest.stages[4].records_produced, 0)

    def test_03_memory_only_run(self):
        """Prove pipeline executes cleanly with memory-only evidence input."""
        config = CaseConfig(
            case_id="MEM-ONLY-01",
            evidence_mem_files=(self.mem_file,),
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)
        stage_map = {s.stage_id: s.status for s in res.run_manifest.stages}
        self.assertEqual(stage_map["host_analysis"], "SKIPPED")
        self.assertEqual(stage_map["network_analysis"], "SKIPPED")
        self.assertEqual(stage_map["memory_analysis"], "COMPLETED")

    def test_04_combined_multi_domain_run(self):
        """Prove pipeline combines Host, PCAP, and Memory into unified report and timeline."""
        config = CaseConfig(
            case_id="COMBINED_01",
            case_name="Multi-Domain Incident",
            investigator="Chief Forensic Lead",
            evidence_host_dir=self.host_dir,
            evidence_pcap_files=(self.pcap_file,),
            evidence_mem_files=(self.mem_file,),
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)
        self.assertEqual(res.run_manifest.run_status, PipelineRunStatus.SUCCESS.value)

        # Confirm all 12 stages executed in order
        stages = [s.stage_id for s in res.run_manifest.stages]
        self.assertEqual(stages, [
            "config_validation",
            "preflight_verification",
            "custody_initialization",
            "host_analysis",
            "network_analysis",
            "memory_analysis",
            "timeline_reconstruction",
            "correlation",
            "detection",
            "report_synthesis",
            "custody_finalization",
            "run_manifest",
        ])

        # Verify output manifest file name is exactly 'pipeline_manifest.json' (Condition 4)
        man_path = self.out_dir / "pipeline_manifest.json"
        self.assertTrue(man_path.exists())
        data = json.loads(man_path.read_text(encoding="utf-8"))
        self.assertEqual(data["run_status"], "SUCCESS")
        self.assertEqual(data["case_id"], "COMBINED_01")

        # Verify generated files recorded with sha256 digests
        gen_files = {f["relative_path"]: f["sha256"] for f in data["generated_files"]}
        self.assertIn("report_COMBINED_01.json", gen_files)
        self.assertIn("report_COMBINED_01.html", gen_files)
        self.assertIn("ledger_COMBINED_01.json", gen_files)

    def test_05_malformed_pcap_error_containment(self):
        """Prove malformed PCAP is recorded as FAILED without crashing the process, yielding PARTIAL_SUCCESS."""
        bad_pcap = self.base_dir / "corrupted.pcap"
        bad_pcap.write_bytes(b"NOT_A_VALID_PCAP_MAGIC_HEADER_BYTES")

        config = CaseConfig(
            case_id="CORRUPT_PCAP_TEST",
            evidence_host_dir=self.host_dir,
            evidence_pcap_files=(bad_pcap,),
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)

        # Condition 5: exit code 2 covers partial success
        self.assertEqual(res.exit_code, EXIT_VERIFICATION_OR_PARTIAL)
        self.assertEqual(res.run_manifest.run_status, PipelineRunStatus.PARTIAL_SUCCESS.value)

        stage_map = {s.stage_id: s for s in res.run_manifest.stages}
        self.assertEqual(stage_map["host_analysis"].status, "COMPLETED")
        self.assertEqual(stage_map["network_analysis"].status, "FAILED")
        self.assertTrue(any("corrupted.pcap" in err for err in stage_map["network_analysis"].errors))

        # Downstream report was still synthesized successfully
        self.assertTrue((self.out_dir / "report_CORRUPT_PCAP_TEST.json").exists())
        self.assertTrue((self.out_dir / "pipeline_manifest.json").exists())

    def test_06_input_files_unchanged_after_run(self):
        """Prove bitwise immutability of all original evidence inputs across pipeline execution."""
        # Calculate pre-execution digests
        pre_digests = {}
        for p in [self.pcap_file, self.mem_file, self.host_dir / "etc" / "passwd"]:
            pre_digests[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()

        config = CaseConfig(
            case_id="IMMUTABILITY_CHECK",
            evidence_host_dir=self.host_dir,
            evidence_pcap_files=(self.pcap_file,),
            evidence_mem_files=(self.mem_file,),
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)

        # Verify post-execution digests
        for p_str, pre_hash in pre_digests.items():
            post_hash = hashlib.sha256(Path(p_str).read_bytes()).hexdigest()
            self.assertEqual(pre_hash, post_hash, f"Evidence file {p_str} was altered!")

    def test_07_overwrite_protection_halts_with_error(self):
        """Prove existing output files with overwrite=False trigger clean abort with EXIT_FILESYSTEM_IO_ERROR."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "pipeline_manifest.json").write_text("existing", encoding="utf-8")

        config = CaseConfig(
            case_id="OVERWRITE_GUARD",
            evidence_host_dir=self.host_dir,
            output_dir=self.out_dir,
            overwrite=False,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, 4)
        self.assertEqual(res.run_manifest.run_status, "FAILURE")
        stage_map = {s.stage_id: s for s in res.run_manifest.stages}
        self.assertEqual(stage_map["preflight_verification"].status, "FAILED")
        self.assertTrue(any("already exist" in e for e in stage_map["preflight_verification"].errors))

    def test_08_manifest_discrepancy_yields_exit_code_2(self):
        """Prove manifest hash discrepancy yields exit code 2 (Condition 5) while run completes."""
        # Create a manifest with an incorrect hash for a file
        man_data = {
            "manifest_id": "MANIFEST-11111111-1111-4111-8111-111111111111",
            "manifest_version": "8.0",
            "created_at": "2026-10-21T08:00:00+00:00",
            "forensix_version": "8.0.0",
            "case_id": "DISCREPANCY_TEST",
            "entries": [
                {
                    "relative_path": "etc/passwd",
                    "size_bytes": 100,
                    "hashes": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
                    "artifact_type": "evidence",
                }
            ],
        }
        man_file = self.base_dir / "bad_manifest.json"
        man_file.write_text(json.dumps(man_data, indent=2), encoding="utf-8")

        config = CaseConfig(
            case_id="DISCREPANCY_TEST",
            evidence_host_dir=self.host_dir,
            manifest_path=man_file,
            output_dir=self.out_dir,
            overwrite=True,
        )
        res = run_pipeline(config)
        self.assertEqual(res.exit_code, EXIT_VERIFICATION_OR_PARTIAL)
        self.assertEqual(res.run_manifest.run_status, "PARTIAL_SUCCESS")


if __name__ == "__main__":
    unittest.main()

