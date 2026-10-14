"""
Unit test suite for ForensiX V6.4 Memory Network Socket Artifacts (memory_network.py).

Validates:
1. compute_deterministic_network_id determinism and uniqueness.
2. MemoryNetworkArtifact validation, immutability, and serialization.
3. NetworkRejectionRecord validation and serialization without data leakage.
4. NetworkExtractionResult aggregate metrics and reconciliation.
5. Successful Linux linux.sockstat extraction.
6. Successful Windows windows.netstat and windows.netscan extraction.
7. Combined endpoint (IP:Port) parsing.
8. Successful empty output preservation (distinct from execution failure).
9. Alias precedence and conflicting alias detection/rejection (CONFLICTING_ALIASES).
10. Concordant alias handling (matching values accepted).
11. Missing required protocol rejection (MISSING_PROTOCOL).
12. Invalid port, PID, and offset rejection (INVALID_PORT, INVALID_PID, INVALID_OFFSET).
13. Missing optional fields handling (remote_address=None, state=None, pid=None).
14. Exact duplicate source rows collapsing and duplicate_row_count tracking.
15. Distinct observations preservation with distinct IDs.
16. Strict failure-handling contract (re-raising existing V6.1 exceptions with execution_record).
17. Deep immutability of raw_attributes and nested structures.
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.memory_models import (
    MemoryNetworkArtifact,
    NetworkExtractionResult,
    NetworkRejectionRecord,
    VolatilityExecutionError,
    VolatilityExecutionRecord,
    VolatilityExecutionStatus,
    compute_deterministic_network_id,
)
from forensix.memory_network import (
    extract_network_artifacts,
)
from forensix.volatility_adapter import (
    VolatilityExecutionFailureError,
    VolatilityMissingSymbolsError,
    VolatilityOutputLimitExceededError,
    VolatilityResult,
    VolatilityTimeoutError,
    VolatilityUnsupportedPluginError,
)


class TestMemoryNetworkExtraction(unittest.TestCase):
    """Test suite covering V6.4 network socket models, normalizer, and extraction results."""

    def setUp(self) -> None:
        """Create standard test fixtures."""
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.execution_record = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            tool="volatility3",
            plugin="linux.sockstat",
            sanitized_args=("-f", "mem.raw", "-r", "json", "linux.sockstat"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )

    # -------------------------------------------------------------------------
    # 1. Deterministic Identifier Generation
    # -------------------------------------------------------------------------

    def test_compute_deterministic_network_id_determinism(self) -> None:
        """Deterministic network ID produces byte-identical UUIDv5 across identical inputs."""
        id1 = compute_deterministic_network_id(
            evidence_id=self.evidence_id,
            plugin="linux.sockstat",
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=443,
            remote_address="10.0.0.1",
            remote_port=54321,
            state="ESTABLISHED",
            pid=1234,
            offset="0x8000",
        )
        id2 = compute_deterministic_network_id(
            evidence_id=self.evidence_id,
            plugin="linux.sockstat",
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=443,
            remote_address="10.0.0.1",
            remote_port=54321,
            state="ESTABLISHED",
            pid=1234,
            offset="0x8000",
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("MEMNET-"))

    def test_compute_deterministic_network_id_uniqueness(self) -> None:
        """Network IDs differ when protocol, endpoints, state, PID, offset, or digest vary."""
        base = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.1", 54321, "ESTABLISHED", 100
        )
        diff_proto = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "UDP", "192.168.1.50", 443, "10.0.0.1", 54321, "ESTABLISHED", 100
        )
        diff_lport = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 8443, "10.0.0.1", 54321, "ESTABLISHED", 100
        )
        diff_raddr = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.2", 54321, "ESTABLISHED", 100
        )
        diff_state = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.1", 54321, "CLOSE_WAIT", 100
        )
        diff_pid = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.1", 54321, "ESTABLISHED", 200
        )
        diff_offset = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.1", 54321, "ESTABLISHED", 100, offset="0x9000"
        )
        diff_digest = compute_deterministic_network_id(
            self.evidence_id, "linux.sockstat", "TCP", "192.168.1.50", 443, "10.0.0.1", 54321, "ESTABLISHED", 100, content_digest="abcdef1234"
        )

        ids = {base, diff_proto, diff_lport, diff_raddr, diff_state, diff_pid, diff_offset, diff_digest}
        self.assertEqual(len(ids), 8)

    # -------------------------------------------------------------------------
    # 2. Model Validation & Immutability
    # -------------------------------------------------------------------------

    def test_memory_network_artifact_validation(self) -> None:
        """MemoryNetworkArtifact validates required fields and types strictly."""
        art_id = compute_deterministic_network_id(self.evidence_id, "linux.sockstat", "TCP")
        art = MemoryNetworkArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="linux.sockstat",
            local_address="127.0.0.1",
            local_port=8080,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            pid=500,
            process_name="nginx",
            offset="0x12340",
            created_at="2026-09-30T10:00:00Z",
            execution_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            source_row_indices=(0,),
            raw_attributes=(("Inode", 12345),),
        )

        self.assertEqual(art.protocol, "TCP")
        self.assertEqual(art.local_port, 8080)
        self.assertEqual(art.state, "LISTEN")
        self.assertEqual(art.source_row_indices, (0,))

        # Serialization
        data_dict = art.to_dict()
        self.assertEqual(data_dict["protocol"], "TCP")
        self.assertEqual(data_dict["local_port"], 8080)
        self.assertEqual(data_dict["raw_attributes"], {"Inode": 12345})
        self.assertIn("artifact_id", art.to_json())

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            art.local_port = 80  # type: ignore

    def test_memory_network_artifact_invalid_inputs_rejected(self) -> None:
        """MemoryNetworkArtifact rejects malformed identifiers, invalid port numbers, and negative PIDs."""
        valid_id = compute_deterministic_network_id(self.evidence_id, "linux.sockstat", "TCP")

        # Invalid artifact_id
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id="INVALID-ID",
                evidence_id=self.evidence_id,
                protocol="TCP",
                source_plugin="linux.sockstat",
            )

        # Invalid evidence_id
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id="NOT-MEM-ID",
                protocol="TCP",
                source_plugin="linux.sockstat",
            )

        # Empty protocol
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                protocol="   ",
                source_plugin="linux.sockstat",
            )

        # Invalid local_port (> 65535)
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                protocol="TCP",
                source_plugin="linux.sockstat",
                local_port=70000,
            )

        # Negative local_port
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                protocol="TCP",
                source_plugin="linux.sockstat",
                local_port=-1,
            )

        # Negative PID
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                protocol="TCP",
                source_plugin="linux.sockstat",
                pid=-10,
            )

        # Invalid offset (not hex)
        with self.assertRaises(ValueError):
            MemoryNetworkArtifact(
                artifact_id=valid_id,
                evidence_id=self.evidence_id,
                protocol="TCP",
                source_plugin="linux.sockstat",
                offset="invalid_hex",
            )

    def test_network_rejection_record_validation(self) -> None:
        """NetworkRejectionRecord validates row_index, reason_code, and serializes cleanly."""
        rej = NetworkRejectionRecord(
            row_index=2,
            reason_code="INVALID_PORT",
            field_name="local_port",
            message="Local port must be an integer between 0 and 65535",
        )
        self.assertEqual(rej.row_index, 2)
        self.assertEqual(rej.reason_code, "INVALID_PORT")
        d = rej.to_dict()
        self.assertEqual(d["row_index"], 2)
        self.assertEqual(d["reason_code"], "INVALID_PORT")

        with self.assertRaises(ValueError):
            NetworkRejectionRecord(row_index=-1, reason_code="ERR", field_name="f", message="m")

        with self.assertRaises(ValueError):
            NetworkRejectionRecord(row_index=0, reason_code="", field_name="f", message="m")

    def test_network_extraction_result_metrics(self) -> None:
        """NetworkExtractionResult computes total_rows, valid_count, and rejected_count accurately."""
        art_id = compute_deterministic_network_id(self.evidence_id, "linux.sockstat", "TCP")
        art = MemoryNetworkArtifact(
            artifact_id=art_id,
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="linux.sockstat",
        )
        rej = NetworkRejectionRecord(row_index=1, reason_code="MISSING_PROTOCOL", field_name="protocol", message="msg")

        res = NetworkExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=self.execution_record,
            artifacts=(art,),
            rejections=(rej,),
            duplicate_row_count=2,
        )

        self.assertEqual(res.valid_count, 1)
        self.assertEqual(res.rejected_count, 1)
        self.assertEqual(res.duplicate_row_count, 2)
        self.assertEqual(res.total_rows, 4)  # 1 valid + 1 rejected + 2 duplicates
        self.assertIn("evidence_id", res.to_dict())
        self.assertIn("artifacts", res.to_json())

    # -------------------------------------------------------------------------
    # 3. Extraction: Linux sockstat and Windows netstat/netscan
    # -------------------------------------------------------------------------

    def test_extract_linux_sockstat_success(self) -> None:
        """Valid Linux sockstat rows normalize into sorted MemoryNetworkArtifact models."""
        rows = (
            {
                "Offset": "0x2000",
                "Proto": "UDP",
                "Local Address": "0.0.0.0",
                "Local Port": 53,
                "Foreign Address": "0.0.0.0",
                "Foreign Port": 0,
                "State": None,
                "PID": 105,
                "COMM": "systemd-resolve",
            },
            {
                "Offset": "0x1000",
                "Proto": "TCP",
                "Local Address": "0.0.0.0",
                "Local Port": 22,
                "Foreign Address": "0.0.0.0",
                "Foreign Port": 0,
                "State": "LISTEN",
                "PID": 100,
                "COMM": "sshd",
            },
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="[]")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.rejected_count, 0)
        self.assertEqual(outcome.total_rows, 2)

        # Sorted by protocol: 'TCP' first, then 'UDP'
        s1, s2 = outcome.artifacts
        self.assertEqual(s1.protocol, "TCP")
        self.assertEqual(s1.local_port, 22)
        self.assertEqual(s1.state, "LISTEN")
        self.assertEqual(s1.pid, 100)
        self.assertEqual(s1.process_name, "sshd")
        self.assertEqual(s1.source_row_indices, (1,))

        self.assertEqual(s2.protocol, "UDP")
        self.assertEqual(s2.local_port, 53)
        self.assertIsNone(s2.state)
        self.assertEqual(s2.pid, 105)
        self.assertEqual(s2.source_row_indices, (0,))

    def test_extract_windows_netstat_success(self) -> None:
        """Valid Windows netstat rows with Proto, LocalAddr, ForeignAddr, and Owner normalize properly."""
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000001",
            tool="volatility3",
            plugin="windows.netstat",
            sanitized_args=("-f", "mem.raw", "windows.netstat"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        rows = (
            {
                "Proto": "TCP",
                "LocalAddr": "192.168.1.100",
                "LocalPort": 49152,
                "ForeignAddr": "192.168.1.1",
                "ForeignPort": 445,
                "State": "ESTABLISHED",
                "PID": 4,
                "Owner": "System",
            },
        )
        res = VolatilityResult(execution_record=exec_rec, data=rows, raw_output="[]")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        s = outcome.artifacts[0]
        self.assertEqual(s.protocol, "TCP")
        self.assertEqual(s.local_address, "192.168.1.100")
        self.assertEqual(s.local_port, 49152)
        self.assertEqual(s.remote_address, "192.168.1.1")
        self.assertEqual(s.remote_port, 445)
        self.assertEqual(s.state, "ESTABLISHED")
        self.assertEqual(s.pid, 4)
        self.assertEqual(s.process_name, "System")

    def test_extract_windows_netscan_success(self) -> None:
        """Valid Windows netscan rows with Offset and Created timestamp normalize properly."""
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000002",
            tool="volatility3",
            plugin="windows.netscan",
            sanitized_args=("-f", "mem.raw", "windows.netscan"),
            status=VolatilityExecutionStatus.SUCCESS.value,
            executed=True,
            exit_code=0,
        )
        rows = (
            {
                "Offset": "0xfffffa8002001000",
                "Proto": "TCPv4",
                "LocalAddr": "0.0.0.0",
                "LocalPort": 80,
                "ForeignAddr": "*",
                "ForeignPort": 0,
                "State": "LISTENING",
                "PID": 1024,
                "Owner": "httpd.exe",
                "Created": "2026-09-30 08:00:00 UTC",
            },
        )
        res = VolatilityResult(execution_record=exec_rec, data=rows, raw_output="[]")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        s = outcome.artifacts[0]
        self.assertEqual(s.protocol, "TCPV4")
        self.assertEqual(s.offset, "0xfffffa8002001000")
        self.assertEqual(s.local_port, 80)
        self.assertEqual(s.state, "LISTENING")
        self.assertEqual(s.created_at, "2026-09-30T08:00:00Z")

    def test_extract_combined_host_port_endpoint_parsing(self) -> None:
        """Combined IP:Port representations in LocalAddr and ForeignAddr are parsed cleanly."""
        rows = (
            {
                "Proto": "TCP",
                "LocalAddr": "10.0.0.5:8080",
                "ForeignAddr": "[fe80::1]:443",
                "State": "ESTABLISHED",
            },
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="[]")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        s = outcome.artifacts[0]
        self.assertEqual(s.local_address, "10.0.0.5")
        self.assertEqual(s.local_port, 8080)
        self.assertEqual(s.remote_address, "fe80::1")
        self.assertEqual(s.remote_port, 443)

    def test_extract_empty_network_output_preservation(self) -> None:
        """Successful Volatility execution returning 0 rows returns valid_count=0 without error."""
        res = VolatilityResult(execution_record=self.execution_record, data=(), raw_output="[]")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 0)
        self.assertEqual(outcome.rejected_count, 0)
        self.assertEqual(outcome.total_rows, 0)
        self.assertEqual(outcome.artifacts, ())
        self.assertEqual(outcome.rejections, ())

    # -------------------------------------------------------------------------
    # 4. Alias Precedence & Conflict Detection
    # -------------------------------------------------------------------------

    def test_conflicting_aliases_rejected(self) -> None:
        """Conflicting non-null values across alias keys reject row with CONFLICTING_ALIASES."""
        # 1. Conflicting Proto vs Protocol
        rows1 = ({"Proto": "TCP", "Protocol": "UDP", "LocalPort": 80},)
        out1 = extract_network_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows1, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out1.valid_count, 0)
        self.assertEqual(out1.rejected_count, 1)
        self.assertEqual(out1.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out1.rejections[0].field_name, "protocol")

        # 2. Conflicting State vs Status
        rows2 = ({"Proto": "TCP", "State": "LISTEN", "Status": "ESTABLISHED"},)
        out2 = extract_network_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows2, raw_output=""),
            self.evidence_id,
        )
        self.assertEqual(out2.valid_count, 0)
        self.assertEqual(out2.rejected_count, 1)
        self.assertEqual(out2.rejections[0].reason_code, "CONFLICTING_ALIASES")
        self.assertEqual(out2.rejections[0].field_name, "state")

    def test_concordant_aliases_accepted(self) -> None:
        """Matching non-null values across aliases are accepted cleanly."""
        rows = (
            {
                "Proto": "TCP",
                "Protocol": "tcp",
                "State": "LISTEN",
                "Status": "listen",
                "LocalPort": 80,
            },
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 0)
        s = outcome.artifacts[0]
        self.assertEqual(s.protocol, "TCP")
        self.assertEqual(s.state, "LISTEN")

    # -------------------------------------------------------------------------
    # 5. Missing & Invalid Fields Handling
    # -------------------------------------------------------------------------

    def test_missing_protocol_rejection(self) -> None:
        """Missing or whitespace-only protocol causes row rejection."""
        rows = (
            {"LocalPort": 80},  # Missing protocol
            {"Proto": "   ", "LocalPort": 80},  # Whitespace-only protocol
            {"Proto": "TCP", "LocalPort": 80},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(
            VolatilityResult(execution_record=self.execution_record, data=rows, raw_output=""),
            self.evidence_id,
        )

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 2)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MISSING_PROTOCOL")

    def test_invalid_port_rejection(self) -> None:
        """Invalid port number (out of 0..65535 or non-numeric) causes row rejection."""
        rows = (
            {"Proto": "TCP", "LocalPort": 70000},  # > 65535
            {"Proto": "TCP", "LocalPort": -1},  # Negative
            {"Proto": "TCP", "LocalPort": "not_a_port"},  # Non-numeric
            {"Proto": "TCP", "LocalPort": 443},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 3)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "INVALID_PORT")

    def test_invalid_pid_and_offset_rejection(self) -> None:
        """Invalid non-numeric PID or invalid hex offset causes row rejection."""
        rows = (
            {"Proto": "TCP", "PID": -5},  # Negative PID
            {"Proto": "TCP", "Offset": "bad_hex"},  # Bad offset
            {"Proto": "TCP", "PID": 100, "Offset": "0x5000"},  # Valid
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 2)
        codes = [r.reason_code for r in outcome.rejections]
        self.assertIn("INVALID_PID", codes)
        self.assertIn("INVALID_OFFSET", codes)

    def test_missing_optional_fields_populated_with_none(self) -> None:
        """Missing optional remote endpoint, state, PID, and process name cleanly default to None."""
        rows = (
            {"Proto": "UDP", "LocalAddr": "0.0.0.0", "LocalPort": 123},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        s = outcome.artifacts[0]
        self.assertIsNone(s.remote_address)
        self.assertIsNone(s.remote_port)
        self.assertIsNone(s.state)
        self.assertIsNone(s.pid)
        self.assertIsNone(s.process_name)

    def test_malformed_non_dict_row_rejection(self) -> None:
        """Non-dictionary row is rejected with MALFORMED_RECORD."""
        rows = (
            {"Proto": "TCP"},
            "primitive_string_row",
            12345,
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")  # type: ignore
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 1)
        self.assertEqual(outcome.rejected_count, 2)
        for r in outcome.rejections:
            self.assertEqual(r.reason_code, "MALFORMED_RECORD")

    # -------------------------------------------------------------------------
    # 6. Duplicates vs. Distinct Observations
    # -------------------------------------------------------------------------

    def test_exact_duplicate_rows_collapsed_with_traceability(self) -> None:
        """Exact duplicate source rows are collapsed while recording row indices and count."""
        identical_row = {"Proto": "TCP", "LocalPort": 80, "State": "LISTEN", "PID": 100}
        rows = (
            identical_row,  # row 0
            {"Proto": "TCP", "LocalPort": 443, "State": "LISTEN"},  # row 1
            identical_row,  # row 2 (exact duplicate of row 0)
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 1)
        self.assertEqual(outcome.total_rows, 3)

        # Port 80 socket has both row 0 and row 2 in source_row_indices
        s_80 = [a for a in outcome.artifacts if a.local_port == 80][0]
        self.assertEqual(s_80.source_row_indices, (0, 2))

    def test_distinct_observations_with_same_endpoints_preserved(self) -> None:
        """Sockets sharing endpoints but differing in PID or offset are preserved as distinct artifacts."""
        rows = (
            {"Proto": "TCP", "LocalPort": 80, "PID": 100, "Offset": "0x1000"},  # row 0
            {"Proto": "TCP", "LocalPort": 80, "PID": 200, "Offset": "0x2000"},  # row 1 (different PID and offset)
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        self.assertEqual(outcome.valid_count, 2)
        self.assertEqual(outcome.duplicate_row_count, 0)

        art0, art1 = outcome.artifacts
        self.assertNotEqual(art0.artifact_id, art1.artifact_id)
        self.assertEqual(art0.pid, 100)
        self.assertEqual(art1.pid, 200)

    # -------------------------------------------------------------------------
    # 7. Strict Failure Contract
    # -------------------------------------------------------------------------

    def test_failed_volatility_execution_re_raises_typed_v61_exceptions(self) -> None:
        """Failed VolatilityResult execution re-raises existing V6.1 typed exceptions carrying execution_record."""
        # 1. MISSING_SYMBOLS
        rec_sym = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000001",
            tool="vol3",
            plugin="linux.sockstat",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=1,
            error=VolatilityExecutionError(
                error_type="MISSING_SYMBOLS",
                error_message="Symbol table requirement not satisfied: linux.elf",
            ),
        )
        res_sym = VolatilityResult(execution_record=rec_sym, data=(), raw_output="")
        with self.assertRaises(VolatilityMissingSymbolsError) as ctx1:
            extract_network_artifacts(res_sym, self.evidence_id)
        self.assertEqual(ctx1.exception.exit_code, 1)
        self.assertIs(ctx1.exception.execution_record, rec_sym)

        # 2. UNSUPPORTED_PLUGIN
        rec_plug = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000002",
            tool="vol3",
            plugin="linux.badplugin",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=2,
            error=VolatilityExecutionError(
                error_type="UNSUPPORTED_PLUGIN",
                error_message="Unknown plugin: linux.badplugin",
            ),
        )
        res_plug = VolatilityResult(execution_record=rec_plug, data=(), raw_output="")
        with self.assertRaises(VolatilityUnsupportedPluginError) as ctx2:
            extract_network_artifacts(res_plug, self.evidence_id)
        self.assertEqual(ctx2.exception.exit_code, 2)
        self.assertIs(ctx2.exception.execution_record, rec_plug)

        # 3. TIMEOUT
        rec_time = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000003",
            tool="vol3",
            plugin="linux.sockstat",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.TIMEOUT.value,
            executed=True,
            error=VolatilityExecutionError(
                error_type="TIMEOUT",
                error_message="Process timed out",
            ),
        )
        res_time = VolatilityResult(execution_record=rec_time, data=(), raw_output="")
        with self.assertRaises(VolatilityTimeoutError) as ctx3:
            extract_network_artifacts(res_time, self.evidence_id)
        self.assertIs(ctx3.exception.execution_record, rec_time)

        # 4. OUTPUT_LIMIT_EXCEEDED
        rec_limit = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000004",
            tool="vol3",
            plugin="linux.sockstat",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.ERROR.value,
            executed=True,
            error=VolatilityExecutionError(
                error_type="OUTPUT_LIMIT_EXCEEDED",
                error_message="Max bytes exceeded",
            ),
        )
        res_limit = VolatilityResult(execution_record=rec_limit, data=(), raw_output="")
        with self.assertRaises(VolatilityOutputLimitExceededError) as ctx4:
            extract_network_artifacts(res_limit, self.evidence_id)
        self.assertIs(ctx4.exception.execution_record, rec_limit)

        # 5. GENERAL EXECUTION FAILURE
        rec_gen = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-0000-0000-0000-000000000005",
            tool="vol3",
            plugin="linux.sockstat",
            sanitized_args=("-f", "mem.raw"),
            status=VolatilityExecutionStatus.FAILED.value,
            executed=True,
            exit_code=137,
            error=VolatilityExecutionError(
                error_type="EXECUTION_FAILURE",
                error_message="Killed by signal",
            ),
        )
        res_gen = VolatilityResult(execution_record=rec_gen, data=(), raw_output="")
        with self.assertRaises(VolatilityExecutionFailureError) as ctx5:
            extract_network_artifacts(res_gen, self.evidence_id)
        self.assertEqual(ctx5.exception.exit_code, 137)
        self.assertIs(ctx5.exception.execution_record, rec_gen)

    # -------------------------------------------------------------------------
    # 8. Deep Immutability
    # -------------------------------------------------------------------------

    def test_extract_network_artifacts_deep_immutability(self) -> None:
        """Extracted artifacts contain deeply immutable tuples with no mutable references."""
        nested_dict = {"sub": {"key": [1, 2, 3]}}
        rows = (
            {"Proto": "TCP", "LocalPort": 80, "Extra": nested_dict},
        )
        res = VolatilityResult(execution_record=self.execution_record, data=rows, raw_output="")
        outcome = extract_network_artifacts(res, self.evidence_id)

        s = outcome.artifacts[0]
        self.assertIsInstance(s.raw_attributes, tuple)
        extra_val = dict(s.raw_attributes)["Extra"]
        self.assertIsInstance(extra_val, tuple)

        # Attempting to mutate original dictionary does not affect artifact
        nested_dict["sub"]["key"].append(4)  # type: ignore
        self.assertNotIn("4", str(s.raw_attributes))


if __name__ == "__main__":
    unittest.main()
