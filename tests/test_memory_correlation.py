"""
Unit test suite for ForensiX V6.6 Memory Correlation (memory_correlation.py).

Validates:
1. Deterministic correlation ID generation (compute_deterministic_memory_correlation_id).
2. MemoryCorrelation model validation, deep immutability, and serialization.
3. Canonical V4 correlation bridge (to_correlation).
4. Process PID matching across plugins and PID reuse detection with divergent names.
5. Parent-child process relationship derivation via ppid.
6. Process-to-network socket association via explicit PID.
7. Socket without PID boundary (never inferred from temporal proximity).
8. Process-to-module association requiring defensible binding (never inferred from name similarity alone).
9. Strict cross-evidence isolation (PIDs from different memory images never correlated).
10. Shared execution provenance correlation.
11. Temporal proximity correlation with compatible vs incompatible/missing timestamps.
12. Duplicate-edge suppression and input-order independence.
13. Empty inputs and non-matching artifact sets.
14. MemoryCorrelationCollection metrics and filtering.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, timedelta
import json
import unittest
import uuid

from forensix.correlation_models import Correlation
from forensix.memory_correlation import (
    MemoryCorrelation,
    MemoryCorrelationCollection,
    MemoryCorrelationConfidence,
    MemoryCorrelationConfig,
    MemoryCorrelationType,
    compute_deterministic_memory_correlation_id,
    correlate_memory_artifacts,
    memory_correlation_sort_key,
)
from forensix.memory_models import (
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    NetworkExtractionResult,
    ProcessExtractionResult,
    VolatilityExecutionRecord,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
    compute_deterministic_memory_event_id,
)


class TestDeterministicCorrelationIdentifiers(unittest.TestCase):
    """Test suite for deterministic UUIDv5 generation and canonical hashing."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.art_a = "MEMPROC-aaaaaaaa-1111-2222-3333-444444444444"
        self.art_b = "MEMNET-bbbbbbbb-1111-2222-3333-444444444444"

    def test_deterministic_id_repeatability(self) -> None:
        id1 = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        id2 = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("MEMCORR-"))
        suffix = id1[len("MEMCORR-"):]
        parsed = uuid.UUID(suffix)
        self.assertEqual(parsed.version, 5)

    def test_order_independence(self) -> None:
        id_ab = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        id_ba = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_b, self.art_a],
        )
        self.assertEqual(id_ab, id_ba)

    def test_distinct_relationships_yield_distinct_ids(self) -> None:
        id_net = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        id_prov = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE,
            artifact_ids=[self.art_a, self.art_b],
        )
        self.assertNotEqual(id_net, id_prov)

    def test_distinct_evidence_yields_distinct_ids(self) -> None:
        evidence2 = "MEM-99999999-8888-7777-6666-555555555555"
        id1 = compute_deterministic_memory_correlation_id(
            evidence_id=self.evidence_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        id2 = compute_deterministic_memory_correlation_id(
            evidence_id=evidence2,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            artifact_ids=[self.art_a, self.art_b],
        )
        self.assertNotEqual(id1, id2)

    def test_empty_artifact_ids_rejection(self) -> None:
        with self.assertRaises(ValueError):
            compute_deterministic_memory_correlation_id(
                evidence_id=self.evidence_id,
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                artifact_ids=[],
            )

    def test_invalid_relationship_type_rejection(self) -> None:
        with self.assertRaises(TypeError):
            compute_deterministic_memory_correlation_id(
                evidence_id=self.evidence_id,
                relationship_type=123,  # type: ignore
                artifact_ids=[self.art_a, self.art_b],
            )


class TestMemoryCorrelationModel(unittest.TestCase):
    """Test suite for MemoryCorrelation model validation, immutability, and serialization."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.art_a = "MEMPROC-aaaaaaaa-1111-2222-3333-444444444444"
        self.art_b = "MEMNET-bbbbbbbb-1111-2222-3333-444444444444"
        self.corr_id = compute_deterministic_memory_correlation_id(
            self.evidence_id, MemoryCorrelationType.PROCESS_NETWORK_SOCKET, [self.art_a, self.art_b]
        )

    def test_valid_correlation_instantiation(self) -> None:
        corr = MemoryCorrelation(
            correlation_id=self.corr_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            evidence_id=self.evidence_id,
            artifact_ids=(self.art_a, self.art_b),
            artifact_categories=((self.art_a, "process"), (self.art_b, "network_socket")),
            confidence="DIRECT",
            explanation="Socket bound to process PID 100",
            supporting_fields=(("pid", 100), ("protocol", "TCP")),
            source_plugins=("windows.pslist", "windows.netscan"),
            execution_ids=("VOLEXEC-12345678-1234-1234-1234-123456789abc",),
        )
        self.assertEqual(corr.correlation_id, self.corr_id)
        self.assertEqual(corr.confidence, "DIRECT")
        self.assertEqual(dict(corr.supporting_fields)["pid"], 100)
        self.assertEqual(corr.artifact_ids, (self.art_b, self.art_a))

    def test_invalid_correlation_id_rejection(self) -> None:
        with self.assertRaises(ValueError):
            MemoryCorrelation(
                correlation_id="INVALID-ID",
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                evidence_id=self.evidence_id,
                artifact_ids=(self.art_a, self.art_b),
                explanation="test",
            )
        with self.assertRaises(ValueError):
            MemoryCorrelation(
                correlation_id="MEMCORR-not-a-uuid",
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                evidence_id=self.evidence_id,
                artifact_ids=(self.art_a, self.art_b),
                explanation="test",
            )

    def test_invalid_evidence_id_rejection(self) -> None:
        with self.assertRaises(ValueError):
            MemoryCorrelation(
                correlation_id=self.corr_id,
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                evidence_id="NOT-A-MEM-ID",
                artifact_ids=(self.art_a, self.art_b),
                explanation="test",
            )

    def test_artifact_ids_length_validation(self) -> None:
        with self.assertRaises(ValueError):
            MemoryCorrelation(
                correlation_id=self.corr_id,
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                evidence_id=self.evidence_id,
                artifact_ids=(self.art_a,),  # Only 1 artifact
                explanation="test",
            )

    def test_confidence_validation(self) -> None:
        with self.assertRaises(ValueError):
            MemoryCorrelation(
                correlation_id=self.corr_id,
                relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
                evidence_id=self.evidence_id,
                artifact_ids=(self.art_a, self.art_b),
                confidence="SPECULATIVE",
                explanation="test",
            )

    def test_immutability(self) -> None:
        corr = MemoryCorrelation(
            correlation_id=self.corr_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            evidence_id=self.evidence_id,
            artifact_ids=(self.art_a, self.art_b),
            explanation="test",
        )
        with self.assertRaises(FrozenInstanceError):
            corr.explanation = "modified"  # type: ignore

    def test_to_dict_and_to_json(self) -> None:
        corr = MemoryCorrelation(
            correlation_id=self.corr_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            evidence_id=self.evidence_id,
            artifact_ids=(self.art_a, self.art_b),
            explanation="Socket linked to process",
            supporting_fields={"pid": 100},
        )
        d = corr.to_dict()
        self.assertEqual(d["correlation_id"], self.corr_id)
        self.assertEqual(d["relationship_type"], "PROCESS_NETWORK_SOCKET")
        self.assertEqual(d["supporting_fields"]["pid"], 100)

        json_str = corr.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["correlation_id"], self.corr_id)

    def test_to_correlation_canonical_bridge(self) -> None:
        corr = MemoryCorrelation(
            correlation_id=self.corr_id,
            relationship_type=MemoryCorrelationType.PROCESS_NETWORK_SOCKET,
            evidence_id=self.evidence_id,
            artifact_ids=(self.art_a, self.art_b),
            explanation="Socket bound to process PID 100",
            supporting_fields=(("pid", 100),),
        )
        v4_corr = corr.to_correlation()
        self.assertIsInstance(v4_corr, Correlation)
        self.assertTrue(v4_corr.correlation_id.startswith("CORR-"))
        self.assertEqual(v4_corr.description, "Socket bound to process PID 100")
        self.assertEqual(dict(v4_corr.attributes)["memory_correlation_id"], self.corr_id)
        self.assertEqual(dict(v4_corr.attributes)["evidence_id"], self.evidence_id)


class TestProcessCorrelations(unittest.TestCase):
    """Test suite covering PID match, PID reuse detection, and parent-child hierarchy."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_pid_match_same_evidence(self) -> None:
        # Two process observations with same PID (e.g. pslist and psscan)
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=400,
            process_name="services.exe",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=400,
            process_name="services.exe",
            source_plugin="windows.psscan",
        )
        collection = correlate_memory_artifacts([p1, p2])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.PROCESS_PID_MATCH)
        self.assertEqual(corr.confidence, "DIRECT")
        supp = dict(corr.supporting_fields)
        self.assertEqual(supp["pid"], 400)
        self.assertTrue(supp["name_concordant"])
        self.assertIn("services.exe", corr.explanation)

    def test_pid_reuse_divergent_names(self) -> None:
        # Two process observations with same PID but divergent names (PID reuse / unlinked block)
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=1000,
            process_name="svchost.exe",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=1000,
            process_name="malware.exe",
            source_plugin="windows.psscan",
        )
        collection = correlate_memory_artifacts([p1, p2])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.PROCESS_PID_MATCH)
        supp = dict(corr.supporting_fields)
        self.assertFalse(supp["name_concordant"])
        self.assertTrue(supp.get("pid_reuse_suspected"))
        self.assertIn("potential PID reuse", corr.explanation)

    def test_parent_child_relationship(self) -> None:
        parent = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=4,
            process_name="System",
            source_plugin="windows.pslist",
        )
        child = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=300,
            ppid=4,
            process_name="smss.exe",
            source_plugin="windows.pslist",
        )
        collection = correlate_memory_artifacts([parent, child])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.PARENT_CHILD_PROCESS)
        self.assertEqual(corr.confidence, "DIRECT")
        supp = dict(corr.supporting_fields)
        self.assertEqual(supp["parent_pid"], 4)
        self.assertEqual(supp["child_pid"], 300)
        self.assertIn("smss.exe", corr.explanation)
        self.assertIn("System", corr.explanation)

    def test_parent_child_self_reference_ignored(self) -> None:
        # A process where ppid == pid should not link to itself
        p = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=0,
            ppid=0,
            process_name="Idle",
            source_plugin="windows.pslist",
        )
        collection = correlate_memory_artifacts([p])
        self.assertEqual(collection.total_correlations, 0)


class TestProcessNetworkCorrelations(unittest.TestCase):
    """Test suite covering process-to-network socket association and PID-less boundary."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_socket_pid_matches_process(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=1200,
            process_name="chrome.exe",
            source_plugin="windows.pslist",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netscan",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="93.184.216.34",
            remote_port=443,
            state="ESTABLISHED",
            pid=1200,
            process_name="chrome.exe",
        )
        collection = correlate_memory_artifacts([proc, sock])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.PROCESS_NETWORK_SOCKET)
        self.assertEqual(corr.confidence, "DIRECT")
        supp = dict(corr.supporting_fields)
        self.assertEqual(supp["pid"], 1200)
        self.assertEqual(supp["protocol"], "TCP")
        self.assertTrue(supp["name_concordant"])
        self.assertIn("chrome.exe", corr.explanation)

    def test_socket_without_pid_not_correlated(self) -> None:
        # Socket without PID (e.g. raw sockstat) must NOT be correlated to any process
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=1200,
            process_name="chrome.exe",
            source_plugin="linux.pslist",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="UDP",
            source_plugin="linux.sockstat",
            local_address="0.0.0.0",
            local_port=53,
            pid=None,  # No PID
        )
        collection = correlate_memory_artifacts([proc, sock])
        self.assertEqual(collection.total_correlations, 0)


class TestProcessModuleCorrelations(unittest.TestCase):
    """Test suite covering defensible module-to-process binding vs negative name-similarity boundary."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_module_driver_path_matches_process(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=4,
            process_name="System",
            source_plugin="windows.pslist",
            raw_attributes={"ImagePath": "C:\\Windows\\System32\\drivers\\acpi.sys"},
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="acpi.sys",
            source_plugin="windows.modules",
            driver_path="C:\\Windows\\System32\\drivers\\acpi.sys",
        )
        collection = correlate_memory_artifacts([proc, mod])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.PROCESS_MODULE)
        self.assertEqual(corr.confidence, "DIRECT")
        supp = dict(corr.supporting_fields)
        self.assertEqual(supp["binding_field"], "path_binding")
        self.assertIn("acpi.sys", corr.explanation)

    def test_name_similarity_alone_does_not_correlate(self) -> None:
        # Crucial boundary: Process name matches module name, but no driver path or base address linkage exists
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=800,
            process_name="my_driver.sys",
            source_plugin="windows.pslist",
            raw_attributes={},  # No ImagePath or memory region
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="my_driver.sys",
            source_plugin="windows.modules",
            driver_path=None,  # No driver path
        )
        collection = correlate_memory_artifacts([proc, mod])
        # Must NOT manufacture a process-module relationship based solely on name
        self.assertEqual(collection.total_correlations, 0)


class TestCrossEvidenceIsolation(unittest.TestCase):
    """Test suite verifying that relationships are strictly scoped to the same evidence image."""

    def test_same_pid_different_evidence_isolated(self) -> None:
        # Process in Evidence A has PID 500
        p_a = MemoryProcessArtifact(
            artifact_id="MEMPROC-aaaaaaaa-1111-1111-1111-111111111111",
            evidence_id="MEM-11111111-1111-1111-1111-111111111111",
            pid=500,
            process_name="nginx",
            source_plugin="linux.pslist",
        )
        # Process in Evidence B has PID 500
        p_b = MemoryProcessArtifact(
            artifact_id="MEMPROC-bbbbbbbb-2222-2222-2222-222222222222",
            evidence_id="MEM-22222222-2222-2222-2222-222222222222",
            pid=500,
            process_name="nginx",
            source_plugin="linux.pslist",
        )
        collection = correlate_memory_artifacts([p_a, p_b])
        # PIDs across different machines/dumps must NEVER correlate
        self.assertEqual(collection.total_correlations, 0)

    def test_socket_pid_different_evidence_isolated(self) -> None:
        p_a = MemoryProcessArtifact(
            artifact_id="MEMPROC-aaaaaaaa-1111-1111-1111-111111111111",
            evidence_id="MEM-11111111-1111-1111-1111-111111111111",
            pid=8080,
            process_name="server",
            source_plugin="linux.pslist",
        )
        sock_b = MemoryNetworkArtifact(
            artifact_id="MEMNET-bbbbbbbb-2222-2222-2222-222222222222",
            evidence_id="MEM-22222222-2222-2222-2222-222222222222",
            protocol="TCP",
            source_plugin="linux.netstat",
            local_address="127.0.0.1",
            local_port=8080,
            pid=8080,
        )
        collection = correlate_memory_artifacts([p_a, sock_b])
        self.assertEqual(collection.total_correlations, 0)


class TestExecutionProvenanceAndTemporal(unittest.TestCase):
    """Test suite covering execution provenance and temporal proximity correlations."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_shared_execution_provenance(self) -> None:
        xid = "VOLEXEC-12345678-1234-1234-1234-123456789abc"
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="proc1",
            source_plugin="linux.pslist",
            execution_id=xid,
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="proc2",
            source_plugin="linux.pslist",
            execution_id=xid,
        )
        collection = correlate_memory_artifacts([p1, p2])
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE)
        self.assertEqual(corr.confidence, "CONTEXTUAL")
        self.assertEqual(corr.execution_ids, (xid,))

    def test_temporal_proximity_within_window(self) -> None:
        config = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_execution_provenance=False,
            include_temporal_proximity=True,
            temporal_window_seconds=60.0,
        )
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="proc1",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="proc2",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:30Z",  # 30 seconds delta
        )
        collection = correlate_memory_artifacts([p1, p2], config=config)
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.TEMPORAL_PROXIMITY)
        self.assertEqual(corr.confidence, "CONTEXTUAL")
        self.assertAlmostEqual(corr.time_delta_seconds or 0.0, 30.0, places=1)

    def test_temporal_proximity_outside_window(self) -> None:
        config = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_execution_provenance=False,
            include_temporal_proximity=True,
            temporal_window_seconds=60.0,
        )
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="proc1",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="proc2",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:15:00Z",  # 900 seconds delta
        )
        collection = correlate_memory_artifacts([p1, p2], config=config)
        self.assertEqual(collection.total_correlations, 0)

    def test_temporal_proximity_incompatible_or_missing_timestamps(self) -> None:
        config = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_execution_provenance=False,
            include_temporal_proximity=True,
            temporal_window_seconds=300.0,
        )
        # p1 has aware timestamp, p2 has NO timestamp
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="proc1",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="proc2",
            source_plugin="windows.pslist",
            created_at=None,
        )
        collection = correlate_memory_artifacts([p1, p2], config=config)
        # Missing timestamps cannot satisfy temporal proximity
        self.assertEqual(collection.total_correlations, 0)


class TestDuplicateEdgeSuppressionAndInputOrdering(unittest.TestCase):
    """Test suite covering deduplication and input-order invariance."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_duplicate_edges_suppressed(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=500,
            process_name="sshd",
            source_plugin="linux.pslist",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="linux.netstat",
            local_address="0.0.0.0",
            local_port=22,
            pid=500,
        )
        # Passing identical items multiple times
        collection = correlate_memory_artifacts([proc, sock, proc, sock])
        self.assertEqual(collection.total_correlations, 1)

    def test_input_ordering_invariance(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=500,
            process_name="sshd",
            source_plugin="linux.pslist",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="linux.netstat",
            local_address="0.0.0.0",
            local_port=22,
            pid=500,
        )
        c1 = correlate_memory_artifacts([proc, sock])
        c2 = correlate_memory_artifacts([sock, proc])
        self.assertEqual(c1.total_correlations, c2.total_correlations)
        self.assertEqual(c1[0].correlation_id, c2[0].correlation_id)
        self.assertEqual(c1[0].artifact_ids, c2[0].artifact_ids)


class TestCollectionAndEdgeCases(unittest.TestCase):
    """Test suite covering empty inputs, extraction results unpacking, and filtering."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_empty_input(self) -> None:
        collection = correlate_memory_artifacts([])
        self.assertEqual(collection.total_correlations, 0)
        self.assertEqual(len(collection), 0)
        self.assertEqual(collection.direct_count, 0)
        self.assertEqual(collection.contextual_count, 0)
        self.assertIn("total_correlations", collection.summary)

    def test_no_matching_relationships(self) -> None:
        # Two artifacts with completely disjoint fields
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="alpha",
            source_plugin="linux.pslist",
            execution_id="VOLEXEC-11111111-1111-1111-1111-111111111111",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="UDP",
            source_plugin="linux.sockstat",
            local_address="127.0.0.1",
            local_port=53,
            pid=999,  # Disjoint PID
            execution_id="VOLEXEC-22222222-2222-2222-2222-222222222222",  # Disjoint execution_id
        )
        collection = correlate_memory_artifacts([proc, sock])
        self.assertEqual(collection.total_correlations, 0)

    def test_extraction_results_unpacked(self) -> None:
        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-11111111-1111-1111-1111-111111111111",
            tool="volatility3",
            plugin="windows.pslist",
            sanitized_args=("-f", "mem.raw"),
            status="SUCCESS",
            executed=True,
        )
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=700,
            process_name="calc.exe",
            source_plugin="windows.pslist",
        )
        sock = MemoryNetworkArtifact(
            artifact_id="MEMNET-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netscan",
            local_address="10.0.0.5",
            local_port=12345,
            pid=700,
        )
        p_res = ProcessExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=exec_rec,
            artifacts=(proc,),
            rejections=(),
            duplicate_row_count=0,
        )
        n_res = NetworkExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=exec_rec,
            artifacts=(sock,),
            rejections=(),
            duplicate_row_count=0,
        )
        collection = correlate_memory_artifacts([p_res, n_res])
        self.assertEqual(collection.total_correlations, 1)
        self.assertEqual(collection[0].relationship_type, MemoryCorrelationType.PROCESS_NETWORK_SOCKET)

    def test_filter_functionality(self) -> None:
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=4,
            process_name="System",
            source_plugin="windows.pslist",
            execution_id="VOLEXEC-cccccccc-1111-2222-3333-444444444444",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=300,
            ppid=4,
            process_name="smss.exe",
            source_plugin="windows.pslist",
            execution_id="VOLEXEC-cccccccc-1111-2222-3333-444444444444",
        )
        collection = correlate_memory_artifacts([p1, p2])
        # Two correlations: PARENT_CHILD_PROCESS (DIRECT) and SHARED_EXECUTION_PROVENANCE (CONTEXTUAL)
        self.assertEqual(collection.total_correlations, 2)
        self.assertEqual(collection.direct_count, 1)
        self.assertEqual(collection.contextual_count, 1)

        # Filter by relationship_type
        direct_filtered = collection.filter(relationship_type=MemoryCorrelationType.PARENT_CHILD_PROCESS)
        self.assertEqual(len(direct_filtered), 1)
        self.assertEqual(direct_filtered[0].relationship_type, MemoryCorrelationType.PARENT_CHILD_PROCESS)

        # Filter by confidence
        context_filtered = collection.filter(confidence="CONTEXTUAL")
        self.assertEqual(len(context_filtered), 1)
        self.assertEqual(context_filtered[0].relationship_type, MemoryCorrelationType.SHARED_EXECUTION_PROVENANCE)


class TestSharedPluginCorrelations(unittest.TestCase):
    """Test suite covering SHARED_PLUGIN contextual correlation rule."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.config_enabled = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_module_associations=False,
            include_execution_provenance=False,
            include_shared_plugin=True,
        )

    def test_shared_plugin_enabled(self) -> None:
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="alpha",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="beta",
            source_plugin="windows.pslist",
        )
        collection = correlate_memory_artifacts([p1, p2], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.SHARED_PLUGIN)
        self.assertEqual(corr.confidence, "CONTEXTUAL")
        self.assertEqual(corr.source_plugins, ("windows.pslist",))
        self.assertEqual(dict(corr.supporting_fields)["source_plugin"], "windows.pslist")
        self.assertIn("windows.pslist", corr.explanation)
        self.assertTrue(corr.correlation_id.startswith("MEMCORR-"))

    def test_shared_plugin_default_disabled(self) -> None:
        # Default configuration has include_shared_plugin=False
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="alpha",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="beta",
            source_plugin="windows.pslist",
        )
        config_default = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_module_associations=False,
            include_execution_provenance=False,
        )
        collection = correlate_memory_artifacts([p1, p2], config=config_default)
        self.assertEqual(collection.total_correlations, 0)

    def test_shared_plugin_missing_or_empty_plugin_not_correlated(self) -> None:
        # Artifact with missing/empty source_plugin attribute should not generate a shared plugin link
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="alpha",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="beta",
            source_plugin="windows.pslist",
        )
        # Test empty / whitespace source_plugin bypassed onto frozen artifact
        object.__setattr__(p2, "source_plugin", "   ")
        collection = correlate_memory_artifacts([p1, p2], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 0)

    def test_shared_plugin_cross_evidence_isolated(self) -> None:
        # Same plugin used on two distinct memory evidence images
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id="MEM-11111111-1111-1111-1111-111111111111",
            pid=100,
            process_name="alpha",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id="MEM-22222222-2222-2222-2222-222222222222",
            pid=200,
            process_name="beta",
            source_plugin="windows.pslist",
        )
        collection = correlate_memory_artifacts([p1, p2], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 0)

    def test_shared_plugin_duplicate_suppression_and_no_self_edges(self) -> None:
        p1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="alpha",
            source_plugin="windows.pslist",
        )
        p2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=200,
            process_name="beta",
            source_plugin="windows.pslist",
        )
        # Duplicate input items and single artifact
        single_coll = correlate_memory_artifacts([p1, p1], config=self.config_enabled)
        self.assertEqual(single_coll.total_correlations, 0)

        dup_coll = correlate_memory_artifacts([p1, p2, p1, p2], config=self.config_enabled)
        self.assertEqual(dup_coll.total_correlations, 1)


class TestSameEvidenceCorrelations(unittest.TestCase):
    """Test suite covering SAME_EVIDENCE contextual cross-category correlation rule."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.config_enabled = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_module_associations=False,
            include_execution_provenance=False,
            include_same_evidence=True,
        )

    def test_same_evidence_enabled(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="processA",
            source_plugin="windows.pslist",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="driverB.sys",
            source_plugin="windows.modules",
        )
        collection = correlate_memory_artifacts([proc, mod], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 1)
        corr = collection[0]
        self.assertEqual(corr.relationship_type, MemoryCorrelationType.SAME_EVIDENCE)
        self.assertEqual(corr.confidence, "CONTEXTUAL")
        self.assertEqual(corr.evidence_id, self.evidence_id)
        self.assertEqual(corr.artifact_ids, tuple(sorted([proc.artifact_id, mod.artifact_id])))
        self.assertIn("co-located in memory evidence image", corr.explanation)

    def test_same_evidence_default_disabled(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="processA",
            source_plugin="windows.pslist",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="driverB.sys",
            source_plugin="windows.modules",
        )
        config_default = MemoryCorrelationConfig(
            include_pid_matches=False,
            include_parent_child=False,
            include_network_sockets=False,
            include_module_associations=False,
            include_execution_provenance=False,
        )
        collection = correlate_memory_artifacts([proc, mod], config=config_default)
        self.assertEqual(collection.total_correlations, 0)

    def test_same_evidence_cross_evidence_isolated(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id="MEM-11111111-1111-1111-1111-111111111111",
            pid=100,
            process_name="processA",
            source_plugin="windows.pslist",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id="MEM-22222222-2222-2222-2222-222222222222",
            module_name="driverB.sys",
            source_plugin="windows.modules",
        )
        collection = correlate_memory_artifacts([proc, mod], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 0)

    def test_same_evidence_duplicate_suppression(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="processA",
            source_plugin="windows.pslist",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="driverB.sys",
            source_plugin="windows.modules",
        )
        collection = correlate_memory_artifacts([proc, mod, proc, mod], config=self.config_enabled)
        self.assertEqual(collection.total_correlations, 1)

    def test_same_evidence_determinism(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="processA",
            source_plugin="windows.pslist",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="driverB.sys",
            source_plugin="windows.modules",
        )
        c1 = correlate_memory_artifacts([proc, mod], config=self.config_enabled)
        c2 = correlate_memory_artifacts([mod, proc], config=self.config_enabled)
        self.assertEqual(c1.total_correlations, c2.total_correlations)
        self.assertEqual(c1[0].correlation_id, c2[0].correlation_id)
        self.assertEqual(c1[0].artifact_ids, c2[0].artifact_ids)


if __name__ == "__main__":
    unittest.main()
