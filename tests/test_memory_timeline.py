"""
Unit test suite for ForensiX V6.5 Memory Timeline Integration (memory_timeline.py).

Validates:
1. Deterministic event ID generation (compute_deterministic_memory_event_id).
2. Deterministic UUIDv4 compatibility generation (compute_deterministic_v4_timeline_id).
3. MemoryTimelineEvent validation, deep immutability, and serialization.
4. Process artifact adaptation (created, exited, unanchored, temporal fidelity).
5. Kernel module artifact adaptation (unanchored, limitation documentation, provenance).
6. Network socket artifact adaptation (created vs observed, endpoint formatting).
7. Extraction result adapters (ProcessExtractionResult, ModuleExtractionResult, NetworkExtractionResult).
8. Temporal classification (TimestampClass.AWARE, NAIVE, MISSING).
9. Deterministic sorting hierarchy and safe cross-timezone handling.
10. Conservative deduplication and duplicate metrics accounting.
11. Preservation of distinct observations (no false deduplication across artifacts).
12. Empty and incomplete memory artifact collections.
13. Conversion bridge to canonical V3.1 TimelineEvent and compatibility.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, timedelta
import json
import unittest
import uuid

from forensix.memory_models import (
    FORENSIX_V6_MEMORY_NAMESPACE,
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
    ModuleExtractionResult,
    ModuleRejectionRecord,
    NetworkExtractionResult,
    NetworkRejectionRecord,
    ProcessExtractionResult,
    ProcessRejectionRecord,
    VolatilityExecutionRecord,
    compute_deterministic_module_id,
    compute_deterministic_network_id,
    compute_deterministic_process_id,
)
from forensix.memory_timeline import (
    MemoryTimelineCategory,
    MemoryTimelineEvent,
    ReconstructedMemoryTimeline,
    adapt_module_artifact,
    adapt_module_extraction_result,
    adapt_network_artifact,
    adapt_network_extraction_result,
    adapt_process_artifact,
    adapt_process_extraction_result,
    classify_memory_event_timestamp,
    compute_deterministic_memory_event_id,
    compute_deterministic_v4_timeline_id,
    compute_memory_event_fingerprint,
    memory_timeline_sort_key,
    reconstruct_memory_timeline,
)
from forensix.timeline_models import (
    TimelineCategory,
    TimelineEvent,
)
from forensix.timeline_reconstruction import (
    TimelineReconstructor,
    TimestampClass,
)


class TestDeterministicIdentifiers(unittest.TestCase):
    """Test suite for deterministic UUID generation and canonical hashing."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.artifact_id = "MEMPROC-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_compute_deterministic_memory_event_id_repeatability(self) -> None:
        id1 = compute_deterministic_memory_event_id(
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            event_type="memory_process_created",
            timestamp_origin="source_created_at",
        )
        id2 = compute_deterministic_memory_event_id(
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            event_type="memory_process_created",
            timestamp_origin="source_created_at",
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("MEMEVT-"))
        # Must be valid UUID suffix
        suffix = id1[len("MEMEVT-"):]
        parsed = uuid.UUID(suffix)
        self.assertEqual(parsed.version, 5)

    def test_distinct_events_yield_distinct_ids(self) -> None:
        created_id = compute_deterministic_memory_event_id(
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            event_type="memory_process_created",
            timestamp_origin="source_created_at",
        )
        exited_id = compute_deterministic_memory_event_id(
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            event_type="memory_process_exited",
            timestamp_origin="source_exit_time",
        )
        self.assertNotEqual(created_id, exited_id)

    def test_distinct_evidence_yields_distinct_ids(self) -> None:
        evidence2 = "MEM-99999999-8888-7777-6666-555555555555"
        id1 = compute_deterministic_memory_event_id(
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            event_type="memory_process_created",
        )
        id2 = compute_deterministic_memory_event_id(
            evidence_id=evidence2,
            artifact_id=self.artifact_id,
            event_type="memory_process_created",
        )
        self.assertNotEqual(id1, id2)

    def test_compute_deterministic_v4_timeline_id(self) -> None:
        v4_id1 = compute_deterministic_v4_timeline_id("test_input_key_1")
        v4_id2 = compute_deterministic_v4_timeline_id("test_input_key_1")
        v4_id3 = compute_deterministic_v4_timeline_id("test_input_key_2")

        self.assertEqual(v4_id1, v4_id2)
        self.assertNotEqual(v4_id1, v4_id3)

        parsed = uuid.UUID(v4_id1)
        self.assertEqual(parsed.version, 4)
        self.assertEqual(parsed.variant, uuid.RFC_4122)


class TestMemoryTimelineEventModel(unittest.TestCase):
    """Test suite for MemoryTimelineEvent model validation, immutability, and serialization."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.artifact_id = "MEMPROC-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        self.event_id = compute_deterministic_memory_event_id(
            self.evidence_id, self.artifact_id, "memory_process_created", "source_created_at"
        )
        self.timestamp = datetime(2026, 10, 12, 14, 30, 0, tzinfo=timezone.utc)

    def test_valid_event_creation(self) -> None:
        event = MemoryTimelineEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="memory_process_created",
            description="Process created: test.exe",
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            source_plugin="windows.pslist",
            execution_id="VOLEXEC-12345678-1234-1234-1234-123456789abc",
            source_row_indices=(0, 1),
            raw_timestamp="2026-10-12T14:30:00Z",
            timestamp_origin="source_created_at",
            timestamp_limitation=None,
            attributes=(("pid", 100), ("name", "test.exe")),
        )
        self.assertEqual(event.event_id, self.event_id)
        self.assertEqual(event.artifact_category, MemoryTimelineCategory.PROCESS)
        self.assertEqual(event.source_row_indices, (0, 1))
        self.assertEqual(dict(event.attributes)["pid"], 100)

    def test_string_category_coercion_and_invalid_category_rejection(self) -> None:
        event = MemoryTimelineEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            artifact_category="process",  # String converted to enum
            event_type="memory_process_created",
            description="Process created",
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            source_plugin="windows.pslist",
        )
        self.assertIsInstance(event.artifact_category, MemoryTimelineCategory)
        self.assertEqual(event.artifact_category, MemoryTimelineCategory.PROCESS)

        with self.assertRaises(ValueError):
            MemoryTimelineEvent(
                event_id=self.event_id,
                timestamp=self.timestamp,
                artifact_category="speculative_attack",
                event_type="memory_process_created",
                description="Process created",
                evidence_id=self.evidence_id,
                artifact_id=self.artifact_id,
                source_plugin="windows.pslist",
            )

    def test_invalid_event_id_rejection(self) -> None:
        with self.assertRaises(ValueError):
            MemoryTimelineEvent(
                event_id="INVALID-ID",
                timestamp=self.timestamp,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="test",
                description="test",
                evidence_id=self.evidence_id,
                artifact_id=self.artifact_id,
                source_plugin="windows.pslist",
            )

        with self.assertRaises(ValueError):
            MemoryTimelineEvent(
                event_id="MEMEVT-not-a-uuid",
                timestamp=self.timestamp,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="test",
                description="test",
                evidence_id=self.evidence_id,
                artifact_id=self.artifact_id,
                source_plugin="windows.pslist",
            )

    def test_invalid_evidence_id_rejection(self) -> None:
        with self.assertRaises(ValueError):
            MemoryTimelineEvent(
                event_id=self.event_id,
                timestamp=self.timestamp,
                artifact_category=MemoryTimelineCategory.PROCESS,
                event_type="test",
                description="test",
                evidence_id="NOT-A-MEM-ID",
                artifact_id=self.artifact_id,
                source_plugin="windows.pslist",
            )

    def test_immutability(self) -> None:
        event = MemoryTimelineEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="test",
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            source_plugin="windows.pslist",
            attributes=(("k", "v"),),
        )
        with self.assertRaises(FrozenInstanceError):
            event.description = "modified"  # type: ignore

    def test_to_dict_and_to_json_serialization(self) -> None:
        event = MemoryTimelineEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="memory_process_created",
            description="Process created",
            evidence_id=self.evidence_id,
            artifact_id=self.artifact_id,
            source_plugin="windows.pslist",
            attributes={"pid": 100},
        )
        d = event.to_dict()
        self.assertEqual(d["event_id"], self.event_id)
        self.assertEqual(d["artifact_category"], "process")
        self.assertEqual(d["attributes"]["pid"], 100)

        json_str = event.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["event_id"], self.event_id)


class TestArtifactAdapters(unittest.TestCase):
    """Test suite covering individual artifact adapters for processes, modules, and network sockets."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_adapt_process_with_both_created_and_exited_timestamps(self) -> None:
        art = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=400,
            process_name="updater.exe",
            source_plugin="windows.psscan",
            ppid=4,
            created_at="2026-10-12T10:00:00Z",
            exit_time="2026-10-12T10:05:00Z",
            offset=0x889900,
        )
        events = adapt_process_artifact(art)
        self.assertEqual(len(events), 2)

        created_evt = next(e for e in events if e.event_type == "memory_process_created")
        self.assertEqual(created_evt.timestamp, datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(created_evt.timestamp_origin, "source_created_at")
        self.assertEqual(dict(created_evt.attributes)["pid"], 400)

        exit_evt = next(e for e in events if e.event_type == "memory_process_exited")
        self.assertEqual(exit_evt.timestamp, datetime(2026, 10, 12, 10, 5, 0, tzinfo=timezone.utc))
        self.assertEqual(exit_evt.timestamp_origin, "source_exit_time")

    def test_adapt_process_without_timestamps_creates_unanchored_event(self) -> None:
        art = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=500,
            process_name="systemd",
            source_plugin="linux.pslist",
            ppid=0,
            created_at=None,
            exit_time=None,
        )
        events = adapt_process_artifact(art)
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt.event_type, "memory_process_observed")
        self.assertIsNone(evt.timestamp)
        self.assertEqual(evt.timestamp_origin, "none")
        self.assertIn("No reliable timestamp", evt.timestamp_limitation or "")

    def test_adapt_module_artifact_unanchored_by_design(self) -> None:
        art = MemoryModuleArtifact(
            artifact_id="MEMMOD-33333333-3333-3333-3333-333333333333",
            evidence_id=self.evidence_id,
            module_name="e1000e",
            source_plugin="linux.lsmod",
            base_address="0xffffffffc0000000",
            size_bytes=245760,
        )
        events = adapt_module_artifact(art)
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt.artifact_category, MemoryTimelineCategory.KERNEL_MODULE)
        self.assertEqual(evt.event_type, "memory_module_observed")
        self.assertIsNone(evt.timestamp)
        self.assertEqual(evt.timestamp_origin, "none")
        self.assertIn("Kernel modules do not contain reliable creation timestamps", evt.timestamp_limitation or "")
        attrs = dict(evt.attributes)
        self.assertEqual(attrs["module_name"], "e1000e")
        self.assertEqual(attrs["size_bytes"], 245760)

    def test_adapt_network_artifact_with_and_without_creation_timestamp(self) -> None:
        # 1. With timestamp (e.g. windows.netscan)
        net_ts = MemoryNetworkArtifact(
            artifact_id="MEMNET-44444444-4444-4444-4444-444444444444",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netscan",
            local_address="192.168.1.50",
            local_port=49152,
            remote_address="1.2.3.4",
            remote_port=443,
            state="ESTABLISHED",
            pid=1200,
            created_at="2026-10-12T12:00:00Z",
        )
        events_ts = adapt_network_artifact(net_ts)
        self.assertEqual(len(events_ts), 1)
        evt1 = events_ts[0]
        self.assertEqual(evt1.artifact_category, MemoryTimelineCategory.NETWORK_SOCKET)
        self.assertEqual(evt1.event_type, "memory_network_socket_created")
        self.assertEqual(evt1.timestamp, datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(evt1.timestamp_origin, "source_created_at")

        # 2. Without timestamp (e.g. linux.sockstat)
        net_no_ts = MemoryNetworkArtifact(
            artifact_id="MEMNET-55555555-5555-5555-5555-555555555555",
            evidence_id=self.evidence_id,
            protocol="UDP",
            source_plugin="linux.sockstat",
            local_address="0.0.0.0",
            local_port=53,
        )
        events_no_ts = adapt_network_artifact(net_no_ts)
        self.assertEqual(len(events_no_ts), 1)
        evt2 = events_no_ts[0]
        self.assertEqual(evt2.event_type, "memory_network_socket_observed")
        self.assertIsNone(evt2.timestamp)
        self.assertEqual(evt2.timestamp_origin, "none")
        self.assertIn("Socket structures do not record reliable creation timestamps", evt2.timestamp_limitation or "")

    def test_type_error_on_invalid_inputs(self) -> None:
        with self.assertRaises(TypeError):
            adapt_process_artifact("invalid")  # type: ignore
        with self.assertRaises(TypeError):
            adapt_module_artifact(123)  # type: ignore
        with self.assertRaises(TypeError):
            adapt_network_artifact({})  # type: ignore


class TestExtractionResultAdapters(unittest.TestCase):
    """Test suite covering adapters for batch extraction results."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"
        self.execution_record = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            tool="volatility3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw", "-r", "json", "linux.pslist"),
            status="SUCCESS",
            executed=True,
        )

    def test_adapt_process_extraction_result(self) -> None:
        art1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="init",
            source_plugin="linux.pslist",
        )
        rej = ProcessRejectionRecord(
            row_index=1,
            reason_code="MISSING_PID",
            field_name="PID",
            message="Missing PID",
        )
        result = ProcessExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=self.execution_record,
            artifacts=(art1,),
            rejections=(rej,),
            duplicate_row_count=0,
        )
        events = adapt_process_extraction_result(result)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_id, art1.artifact_id)

    def test_adapt_module_extraction_result(self) -> None:
        art = MemoryModuleArtifact(
            artifact_id="MEMMOD-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            module_name="ext4",
            source_plugin="linux.lsmod",
        )
        result = ModuleExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=self.execution_record,
            artifacts=(art,),
            rejections=(),
            duplicate_row_count=0,
        )
        events = adapt_module_extraction_result(result)
        self.assertEqual(len(events), 1)

    def test_adapt_network_extraction_result(self) -> None:
        art = MemoryNetworkArtifact(
            artifact_id="MEMNET-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netstat",
            local_address="127.0.0.1",
            local_port=8080,
        )
        result = NetworkExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=self.execution_record,
            artifacts=(art,),
            rejections=(),
            duplicate_row_count=0,
        )
        events = adapt_network_extraction_result(result)
        self.assertEqual(len(events), 1)


class TestTemporalCorrectnessAndSorting(unittest.TestCase):
    """Test suite covering timestamp classification, sorting hierarchy, and naive vs aware safety."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_classify_memory_event_timestamp(self) -> None:
        aware_evt = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-1", "test"),
            timestamp=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="desc",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-1",
            source_plugin="test",
        )
        naive_evt = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-2", "test"),
            timestamp=datetime(2026, 10, 12, 10, 0, 0),  # tzinfo=None
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="desc",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-2",
            source_plugin="test",
        )
        missing_evt = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-3", "test"),
            timestamp=None,
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="desc",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-3",
            source_plugin="test",
        )

        self.assertEqual(classify_memory_event_timestamp(aware_evt), TimestampClass.AWARE)
        self.assertEqual(classify_memory_event_timestamp(naive_evt), TimestampClass.NAIVE)
        self.assertEqual(classify_memory_event_timestamp(missing_evt), TimestampClass.MISSING)

    def test_sorting_hierarchy_aware_before_naive_before_missing(self) -> None:
        # Aware event at 10:00 UTC
        aware1 = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-1", "test"),
            timestamp=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="aware",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-1",
            source_plugin="test",
        )
        # Aware event at 15:30 +05:30 -> 10:00 UTC (exact instant tie with aware1)
        tz_offset = timezone(timedelta(hours=5, minutes=30))
        aware2 = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-2", "test"),
            timestamp=datetime(2026, 10, 12, 15, 30, 0, tzinfo=tz_offset),
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="aware offset",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-2",
            source_plugin="test",
        )
        # Naive event
        naive = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-3", "test"),
            timestamp=datetime(2026, 10, 12, 9, 0, 0),
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="naive",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-3",
            source_plugin="test",
        )
        # Unanchored missing event
        missing = MemoryTimelineEvent(
            event_id=compute_deterministic_memory_event_id(self.evidence_id, "MEMPROC-4", "test"),
            timestamp=None,
            artifact_category=MemoryTimelineCategory.PROCESS,
            event_type="test",
            description="missing",
            evidence_id=self.evidence_id,
            artifact_id="MEMPROC-4",
            source_plugin="test",
        )

        events = [missing, naive, aware2, aware1]
        events.sort(key=memory_timeline_sort_key)

        # Aware events must precede naive, naive must precede missing
        self.assertIn(events[0], (aware1, aware2))
        self.assertIn(events[1], (aware1, aware2))
        self.assertEqual(events[2], naive)
        self.assertEqual(events[3], missing)


class TestReconstructedMemoryTimeline(unittest.TestCase):
    """Test suite covering timeline reconstruction, deduplication, and metrics."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_reconstruct_timeline_from_mixed_sources(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        mod = MemoryModuleArtifact(
            artifact_id="MEMMOD-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            module_name="driver.sys",
            source_plugin="windows.modules",
        )
        net = MemoryNetworkArtifact(
            artifact_id="MEMNET-33333333-3333-3333-3333-333333333333",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netscan",
            local_address="0.0.0.0",
            local_port=80,
            created_at="2026-10-12T09:00:00Z",
        )

        timeline = reconstruct_memory_timeline([proc, mod, net])
        self.assertEqual(timeline.total_events, 3)
        self.assertEqual(timeline.duplicates_removed, 0)
        self.assertEqual(timeline.unanchored_event_count, 1)  # Module has no timestamp

        # First event chronologically is network (09:00 UTC)
        self.assertEqual(timeline[0].artifact_category, MemoryTimelineCategory.NETWORK_SOCKET)
        # Second event is process (10:00 UTC)
        self.assertEqual(timeline[1].artifact_category, MemoryTimelineCategory.PROCESS)
        # Third event is module (unanchored / missing)
        self.assertEqual(timeline[2].artifact_category, MemoryTimelineCategory.KERNEL_MODULE)

    def test_conservative_deduplication(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        # Feeding identical artifact twice
        timeline = reconstruct_memory_timeline([proc, proc], deduplicate=True)
        self.assertEqual(timeline.total_events, 1)
        self.assertEqual(timeline.duplicates_removed, 1)

    def test_preserves_distinct_artifacts_with_identical_timestamps_and_pids(self) -> None:
        # Two distinct artifacts (e.g. from different plugins or different base addresses)
        proc1 = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        proc2 = MemoryProcessArtifact(
            artifact_id="MEMPROC-22222222-2222-2222-2222-222222222222",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.psscan",  # Distinct source plugin & artifact_id
            created_at="2026-10-12T10:00:00Z",
        )
        timeline = reconstruct_memory_timeline([proc1, proc2], deduplicate=True)
        # Distinct artifacts must NOT be collapsed
        self.assertEqual(timeline.total_events, 2)
        self.assertEqual(timeline.duplicates_removed, 0)

    def test_empty_and_incomplete_collections(self) -> None:
        timeline = reconstruct_memory_timeline([])
        self.assertEqual(timeline.total_events, 0)
        self.assertEqual(timeline.duplicates_removed, 0)
        self.assertEqual(timeline.unanchored_event_count, 0)
        self.assertEqual(len(timeline), 0)

        exec_rec = VolatilityExecutionRecord(
            record_id="VOLEXEC-66666666-7777-8888-9999-000000000000",
            tool="volatility3",
            plugin="linux.pslist",
            sanitized_args=("-f", "mem.raw", "-r", "json", "linux.pslist"),
            status="SUCCESS",
            executed=True,
        )
        empty_result = ProcessExtractionResult(
            evidence_id=self.evidence_id,
            execution_record=exec_rec,
            artifacts=(),
            rejections=(),
            duplicate_row_count=0,
        )
        timeline2 = reconstruct_memory_timeline([empty_result])
        self.assertEqual(timeline2.total_events, 0)

    def test_idempotence(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        timeline1 = reconstruct_memory_timeline([proc])
        timeline2 = reconstruct_memory_timeline(timeline1.events)
        self.assertEqual(timeline1.events, timeline2.events)
        self.assertEqual(timeline1.total_events, timeline2.total_events)

    def test_summary_and_serialization(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        timeline = reconstruct_memory_timeline([proc])
        summary = timeline.summary
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["duplicates_removed"], 0)
        self.assertIn("process", summary["category_counts"])

        d = timeline.to_dict()
        self.assertIn("summary", d)
        self.assertIn("events", d)

        json_str = timeline.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["summary"]["total_events"], 1)


class TestCanonicalTimelineBridge(unittest.TestCase):
    """Test suite covering conversion of MemoryTimelineEvent to canonical V3.1 TimelineEvent."""

    def setUp(self) -> None:
        self.evidence_id = "MEM-11111111-2222-3333-4444-555555555555"

    def test_to_timeline_event_process_bridge(self) -> None:
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
            source_row_indices=(4,),
        )
        mem_events = adapt_process_artifact(proc)
        self.assertEqual(len(mem_events), 1)
        mem_evt = mem_events[0]

        v3_evt = mem_evt.to_timeline_event()
        self.assertIsInstance(v3_evt, TimelineEvent)
        self.assertTrue(v3_evt.event_id.startswith("TIMELINE-"))
        # UUID suffix must be version 4
        uuid_part = v3_evt.event_id[len("TIMELINE-"):]
        self.assertEqual(uuid.UUID(uuid_part).version, 4)

        self.assertEqual(v3_evt.category, TimelineCategory.LOG)
        self.assertEqual(v3_evt.source_line, 5)  # row index 4 -> line 5
        self.assertEqual(v3_evt.source_path, f"memory:{self.evidence_id}")
        self.assertEqual(v3_evt.source_artifact_id, proc.artifact_id)
        self.assertEqual(v3_evt.source_event_id, mem_evt.event_id)

        attrs = dict(v3_evt.attributes)
        self.assertEqual(attrs["evidence_id"], self.evidence_id)
        self.assertEqual(attrs["memory_artifact_id"], proc.artifact_id)
        self.assertEqual(attrs["memory_event_id"], mem_evt.event_id)

    def test_to_timeline_event_network_bridge(self) -> None:
        net = MemoryNetworkArtifact(
            artifact_id="MEMNET-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            protocol="TCP",
            source_plugin="windows.netscan",
            local_address="10.0.0.1",
            local_port=443,
            created_at="2026-10-12T10:00:00Z",
        )
        mem_events = adapt_network_artifact(net)
        mem_evt = mem_events[0]

        v3_evt = mem_evt.to_timeline_event()
        self.assertEqual(v3_evt.category, TimelineCategory.NETWORK)

    def test_reconstruction_with_timeline_reconstructor(self) -> None:
        # Verify that converted memory events work seamlessly with canonical TimelineReconstructor
        proc = MemoryProcessArtifact(
            artifact_id="MEMPROC-11111111-1111-1111-1111-111111111111",
            evidence_id=self.evidence_id,
            pid=100,
            process_name="test.exe",
            source_plugin="windows.pslist",
            created_at="2026-10-12T10:00:00Z",
        )
        mem_events = adapt_process_artifact(proc)
        v3_events = [e.to_timeline_event() for e in mem_events]

        reconstructor = TimelineReconstructor()
        reconstructed = reconstructor.reconstruct(v3_events)
        self.assertEqual(reconstructed.total_events, 1)
        self.assertEqual(reconstructed.events[0].source_artifact_id, proc.artifact_id)


if __name__ == "__main__":
    unittest.main()
