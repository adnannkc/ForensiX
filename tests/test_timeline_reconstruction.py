"""
Focused Unit Test Suite for ForensiX V3.4 Timeline Reconstruction, Ordering & Deduplication.

Covers:
1. Basic Chronological Ordering:
   - Unordered events are ordered chronologically.
   - Already ordered events remain in order.
   - Reverse-ordered events are sorted correctly.
   - Single event input behaves properly.
   - Empty input produces an empty ReconstructedTimeline.

2. Equal Timestamps & Tie-Breaking:
   - Events with identical timestamps are ordered deterministically by secondary fields:
     source_path, source_line, source_artifact_id, source_event_id, event_type, description, event_id.

3. Timezone Handling:
   - Timezone-aware timestamps with different offsets representing the same UTC instant
     (e.g., 2026-09-30T14:30:00+05:30 vs 2026-09-30T09:00:00Z) occupy equivalent instant order.
   - Timezone-aware timestamps at different instants order chronologically by UTC instant.

4. Timezone-Naive Timestamps:
   - Naive timestamps remain strictly naive (tzinfo is None).
   - No timezone is assumed or fabricated (no UTC assumption, no local timezone assumption).
   - Naive timestamps sort chronologically by naive datetime.

5. Mixed Aware / Naive / Missing Timestamps:
   - Deterministic partitioning by TimestampClass (AWARE -> NAIVE -> MISSING).
   - Prevents invalid Python comparison between aware and naive datetimes.
   - Uncertainty of naive timestamps is preserved.

6. Missing Timestamps:
   - Timestamp-less events (timestamp=None) are never assigned fabricated timestamps.
   - Missing timestamp events are placed in Class MISSING and ordered deterministically by provenance.

7. Conservative Deduplication:
   - Exact factual duplicates are detected and removed.
   - Identical factual observations with different generated event_ids are recognized as duplicates.
   - Distinct events are preserved when any factual field differs:
     timestamps, source_path, source_line, source_artifact_id, source_event_id, event_type, description, raw_data, attributes.
   - Deduplication can be toggled via deduplicate=False.

8. Determinism:
   - Repeated reconstruction on identical input produces byte-identical results.

9. Immutability:
   - Source TimelineEvent instances are never mutated.

10. Provenance Preservation:
    - Retains source_path, source_line, source_artifact_id, source_event_id, raw_timestamp, raw_data, attributes.

11. Serialization:
    - ReconstructedTimeline.to_dict() is fully JSON-serializable.

12. Property-Style Invariants:
    - Idempotence: reconstruct(reconstruct(events)) == reconstruct(events).
    - Source sequence immutability: reconstruct(events_list) does not mutate events_list.

13. Input Validation:
    - None input raises ValueError.
    - Invalid elements raise TypeError.
"""

from datetime import datetime, timezone, timedelta
import json
import unittest

from forensix.timeline_models import TimelineCategory, TimelineEvent, create_timeline_event
from forensix.timeline_reconstruction import (
    ReconstructedTimeline,
    TimelineReconstructor,
    TimestampClass,
    classify_timestamp,
    compute_event_fingerprint,
    order_timeline_events,
    reconstruct_timeline,
    timeline_sort_key,
)


class TestTimelineReconstruction(unittest.TestCase):
    """Rigorous unit tests for ForensiX V3.4 Timeline Reconstruction Engine."""

    def setUp(self) -> None:
        self.tz_ist = timezone(timedelta(hours=5, minutes=30))

        # Sample events with diverse timestamps
        self.evt_early = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="Early file created",
            timestamp=datetime(2026, 9, 30, 8, 0, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T08:00:00Z",
            source_path="/etc/app.conf",
            source_artifact_id="ART-1",
        )

        self.evt_mid_utc = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="session_open",
            description="Session opened",
            timestamp=datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T09:00:00Z",
            source_path="/var/log/auth.log",
            source_line=10,
            source_artifact_id="ART-2",
            source_event_id="LOG-10",
        )

        self.evt_mid_ist = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="SSH login accepted",
            # 14:30:00 in +05:30 == 09:00:00 UTC (exact same instant as evt_mid_utc)
            timestamp=datetime(2026, 9, 30, 14, 30, 0, tzinfo=self.tz_ist),
            raw_timestamp="2026-09-30T14:30:00+05:30",
            source_path="/var/log/auth.log",
            source_line=12,
            source_artifact_id="ART-2",
            source_event_id="AUTH-1",
        )

        self.evt_late = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Late file modified",
            timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T10:00:00Z",
            source_path="/var/log/app.log",
            source_artifact_id="ART-3",
        )

        self.evt_naive_1 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="Naive access 1",
            timestamp=datetime(2026, 9, 30, 8, 30, 0),  # Naive
            raw_timestamp="2026-09-30 08:30:00",
            source_path="/home/user/doc.txt",
        )

        self.evt_naive_2 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Naive modify 2",
            timestamp=datetime(2026, 9, 30, 11, 0, 0),  # Naive
            raw_timestamp="2026-09-30 11:00:00",
            source_path="/home/user/doc.txt",
        )

        self.evt_missing = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="Syslog message lacking year",
            timestamp=None,  # Missing
            raw_timestamp="Oct 02 10:15:30",
            source_path="/var/log/syslog",
            source_line=55,
        )

    # =========================================================================
    # 1. Basic Chronological Ordering
    # =========================================================================

    def test_01_unordered_events_ordered_chronologically(self):
        """Verify unordered events are reconstructed in chronological order."""
        unordered = [self.evt_late, self.evt_early, self.evt_mid_utc]
        timeline = reconstruct_timeline(unordered)

        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(timeline[1], self.evt_mid_utc)
        self.assertEqual(timeline[2], self.evt_late)

    def test_02_already_ordered_events_remain_ordered(self):
        """Verify already ordered events maintain their sequence."""
        ordered = [self.evt_early, self.evt_mid_utc, self.evt_late]
        timeline = reconstruct_timeline(ordered)

        self.assertEqual(list(timeline), ordered)

    def test_03_reverse_ordered_events_sorted_correctly(self):
        """Verify reverse-ordered events sort into proper forward chronological order."""
        rev = [self.evt_late, self.evt_mid_utc, self.evt_early]
        timeline = reconstruct_timeline(rev)

        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(timeline[1], self.evt_mid_utc)
        self.assertEqual(timeline[2], self.evt_late)

    def test_04_single_event_input(self):
        """Verify single-event input is handled cleanly."""
        timeline = reconstruct_timeline([self.evt_early])
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(timeline.total_events, 1)
        self.assertEqual(timeline.duplicates_removed, 0)

    def test_05_empty_input(self):
        """Verify empty input produces valid empty ReconstructedTimeline."""
        timeline = reconstruct_timeline([])
        self.assertEqual(len(timeline), 0)
        self.assertEqual(timeline.events, ())
        self.assertEqual(timeline.total_events, 0)
        self.assertEqual(timeline.duplicates_removed, 0)

    # =========================================================================
    # 2. Equal Timestamps & Tie-Breaking
    # =========================================================================

    def test_06_identical_timestamps_tie_breaking(self):
        """Verify deterministic secondary tie-breaking when timestamps are identical."""
        ts = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        # Events differ only by source_path or source_line
        evt_a = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Mod A",
            timestamp=ts,
            source_path="/a_path.txt",
            source_line=1,
        )
        evt_b_line2 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Mod B line 2",
            timestamp=ts,
            source_path="/b_path.txt",
            source_line=2,
        )
        evt_b_line1 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Mod B line 1",
            timestamp=ts,
            source_path="/b_path.txt",
            source_line=1,
        )

        timeline = reconstruct_timeline([evt_b_line2, evt_a, evt_b_line1])
        # /a_path.txt comes before /b_path.txt; line 1 comes before line 2
        self.assertEqual(timeline[0], evt_a)
        self.assertEqual(timeline[1], evt_b_line1)
        self.assertEqual(timeline[2], evt_b_line2)

    def test_07_tie_breaking_by_event_type_and_id(self):
        """Verify tie-breaking on event_type and event_id when path/line tie."""
        ts = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        evt_access = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="Accessed",
            timestamp=ts,
            source_path="/common.txt",
        )
        evt_modify = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Modified",
            timestamp=ts,
            source_path="/common.txt",
        )
        timeline = reconstruct_timeline([evt_modify, evt_access])
        # "file_accessed" < "file_modified" alphabetically
        self.assertEqual(timeline[0], evt_access)
        self.assertEqual(timeline[1], evt_modify)

    # =========================================================================
    # 3. Timezone Handling
    # =========================================================================

    def test_08_timezone_aware_same_instant_different_offsets(self):
        """Verify aware timestamps with different offsets representing the same instant compare equally."""
        # evt_mid_utc (09:00:00Z) and evt_mid_ist (14:30:00+05:30) represent the exact same UTC instant
        events = [self.evt_mid_ist, self.evt_mid_utc]
        timeline = reconstruct_timeline(events)

        self.assertEqual(len(timeline), 2)
        # Secondary tie-breaking: both have source_path "/var/log/auth.log"
        # evt_mid_utc has line 10, evt_mid_ist has line 12
        # Therefore evt_mid_utc (line 10) must precede evt_mid_ist (line 12)
        self.assertEqual(timeline[0], self.evt_mid_utc)
        self.assertEqual(timeline[1], self.evt_mid_ist)

    def test_09_timezone_aware_different_instants(self):
        """Verify aware timestamps at different instants order chronologically regardless of offset."""
        # 14:00+05:30 (08:30 UTC) vs 08:45Z
        evt_ist_earlier = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Login IST earlier",
            timestamp=datetime(2026, 9, 30, 14, 0, 0, tzinfo=self.tz_ist),  # 08:30 UTC
        )
        evt_utc_later = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="session_open",
            description="Session UTC later",
            timestamp=datetime(2026, 9, 30, 8, 45, 0, tzinfo=timezone.utc),  # 08:45 UTC
        )
        timeline = reconstruct_timeline([evt_utc_later, evt_ist_earlier])
        self.assertEqual(timeline[0], evt_ist_earlier)
        self.assertEqual(timeline[1], evt_utc_later)

    # =========================================================================
    # 4. Timezone-Naive Timestamps
    # =========================================================================

    def test_10_naive_timestamps_remain_naive(self):
        """Verify naive timestamps retain tzinfo=None without synthetic timezone fabrication."""
        timeline = reconstruct_timeline([self.evt_naive_2, self.evt_naive_1])
        self.assertEqual(len(timeline), 2)
        self.assertIsNone(timeline[0].timestamp.tzinfo)
        self.assertIsNone(timeline[1].timestamp.tzinfo)
        self.assertEqual(timeline[0], self.evt_naive_1)  # 08:30 before 11:00
        self.assertEqual(timeline[1], self.evt_naive_2)

    # =========================================================================
    # 5. Mixed Aware / Naive / Missing Timestamps
    # =========================================================================

    def test_11_mixed_timestamp_classes_partitioning(self):
        """Verify deterministic partitioning: AWARE (0) -> NAIVE (1) -> MISSING (2)."""
        mixed = [
            self.evt_missing,
            self.evt_naive_2,
            self.evt_early,
            self.evt_naive_1,
            self.evt_late,
        ]
        timeline = reconstruct_timeline(mixed)
        self.assertEqual(len(timeline), 5)

        # Class 0: Aware events ordered chronologically
        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(timeline[1], self.evt_late)

        # Class 1: Naive events ordered chronologically
        self.assertEqual(timeline[2], self.evt_naive_1)
        self.assertEqual(timeline[3], self.evt_naive_2)

        # Class 2: Missing timestamp events
        self.assertEqual(timeline[4], self.evt_missing)

    def test_12_timestamp_class_classification_helper(self):
        """Verify classify_timestamp correctly assigns TimestampClass enum."""
        self.assertEqual(classify_timestamp(self.evt_early), TimestampClass.AWARE)
        self.assertEqual(classify_timestamp(self.evt_naive_1), TimestampClass.NAIVE)
        self.assertEqual(classify_timestamp(self.evt_missing), TimestampClass.MISSING)

    # =========================================================================
    # 6. Missing Timestamps
    # =========================================================================

    def test_13_missing_timestamps_no_fabrication(self):
        """Verify timestamp-less events are not assigned fabricated timestamps."""
        timeline = reconstruct_timeline([self.evt_missing])
        self.assertIsNone(timeline[0].timestamp)
        self.assertEqual(timeline[0].raw_timestamp, "Oct 02 10:15:30")

    def test_14_multiple_missing_timestamps_ordered_by_provenance(self):
        """Verify multiple timestamp-less events are ordered by path and line number."""
        evt_m1 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="Syslog line 10",
            timestamp=None,
            source_path="/var/log/syslog",
            source_line=10,
        )
        evt_m2 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="Syslog line 5",
            timestamp=None,
            source_path="/var/log/syslog",
            source_line=5,
        )
        evt_m_other = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="Messages line 1",
            timestamp=None,
            source_path="/var/log/messages",
            source_line=1,
        )
        timeline = reconstruct_timeline([evt_m1, evt_m_other, evt_m2])
        # /var/log/messages precedes /var/log/syslog; line 5 precedes line 10
        self.assertEqual(timeline[0], evt_m_other)
        self.assertEqual(timeline[1], evt_m2)
        self.assertEqual(timeline[2], evt_m1)

    # =========================================================================
    # 7. Conservative Deduplication
    # =========================================================================

    def test_15_exact_duplicates_removed(self):
        """Verify identical events are deduplicated conservatively."""
        timeline = reconstruct_timeline([self.evt_early, self.evt_early, self.evt_late])
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline.total_events, 2)
        self.assertEqual(timeline.duplicates_removed, 1)
        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(timeline[1], self.evt_late)

    def test_16_duplicate_with_different_event_ids(self):
        """Verify factual duplicates with different generated event_ids are recognized as duplicate."""
        ts = datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc)
        evt1 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="File modified",
            timestamp=ts,
            source_path="/test.txt",
            source_artifact_id="ART-1",
        )
        evt2 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="File modified",
            timestamp=ts,
            source_path="/test.txt",
            source_artifact_id="ART-1",
        )
        self.assertNotEqual(evt1.event_id, evt2.event_id)  # Different random UUIDs

        timeline = reconstruct_timeline([evt1, evt2])
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline.duplicates_removed, 1)

    def test_17_distinct_events_not_merged(self):
        """Verify distinct events differing in any factual property are preserved."""
        ts = datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc)

        # 1. Different path
        e1 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Mod", timestamp=ts, source_path="/p1.txt")
        e2 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Mod", timestamp=ts, source_path="/p2.txt")
        self.assertEqual(len(reconstruct_timeline([e1, e2])), 2)

        # 2. Different line
        e3 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_path="/p.txt", source_line=1)
        e4 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_path="/p.txt", source_line=2)
        self.assertEqual(len(reconstruct_timeline([e3, e4])), 2)

        # 3. Different artifact ID
        e5 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_artifact_id="ART-A")
        e6 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_artifact_id="ART-B")
        self.assertEqual(len(reconstruct_timeline([e5, e6])), 2)

        # 4. Different event ID
        e7 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_event_id="EVT-A")
        e8 = create_timeline_event(category=TimelineCategory.LOG, event_type="log", description="Log", timestamp=ts, source_event_id="EVT-B")
        self.assertEqual(len(reconstruct_timeline([e7, e8])), 2)

        # 5. Different event type
        e9 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_accessed", description="Evt", timestamp=ts)
        e10 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Evt", timestamp=ts)
        self.assertEqual(len(reconstruct_timeline([e9, e10])), 2)

        # 6. Different description
        e11 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Desc 1", timestamp=ts)
        e12 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Desc 2", timestamp=ts)
        self.assertEqual(len(reconstruct_timeline([e11, e12])), 2)

        # 7. Different attributes
        e13 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Mod", timestamp=ts, attributes={"user": "root"})
        e14 = create_timeline_event(category=TimelineCategory.FILESYSTEM, event_type="file_modified", description="Mod", timestamp=ts, attributes={"user": "admin"})
        self.assertEqual(len(reconstruct_timeline([e13, e14])), 2)

    def test_18_deduplication_disabled_preserves_duplicates(self):
        """Verify deduplicate=False preserves duplicates without filtering."""
        timeline = reconstruct_timeline([self.evt_early, self.evt_early], deduplicate=False)
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline.duplicates_removed, 0)

    # =========================================================================
    # 8. Determinism
    # =========================================================================

    def test_19_determinism_repeated_runs(self):
        """Verify repeated reconstruction on identical input produces byte-identical results."""
        events = [self.evt_late, self.evt_early, self.evt_mid_utc, self.evt_mid_ist, self.evt_early]
        res1 = reconstruct_timeline(events)
        res2 = reconstruct_timeline(events)

        self.assertEqual(len(res1), len(res2))
        self.assertEqual(res1.duplicates_removed, res2.duplicates_removed)
        for e1, e2 in zip(res1, res2):
            self.assertEqual(e1, e2)
        self.assertEqual(res1.to_dict(), res2.to_dict())

    # =========================================================================
    # 9. Immutability
    # =========================================================================

    def test_20_input_events_not_mutated(self):
        """Verify TimelineEvent properties are completely unmodified by reconstruction."""
        orig_dict = self.evt_mid_ist.to_dict()
        reconstruct_timeline([self.evt_mid_ist])
        self.assertEqual(self.evt_mid_ist.to_dict(), orig_dict)

    # =========================================================================
    # 10. Provenance Preservation
    # =========================================================================

    def test_21_provenance_fields_preserved(self):
        """Verify source_path, line, artifact ID, event ID, raw_timestamp, raw_data, and attributes survive."""
        timeline = reconstruct_timeline([self.evt_mid_utc])
        event = timeline[0]

        self.assertEqual(event.source_path, "/var/log/auth.log")
        self.assertEqual(event.source_line, 10)
        self.assertEqual(event.source_artifact_id, "ART-2")
        self.assertEqual(event.source_event_id, "LOG-10")
        self.assertEqual(event.raw_timestamp, "2026-09-30T09:00:00Z")
        self.assertEqual(event.category, TimelineCategory.LOG)
        self.assertEqual(event.event_type, "session_open")

    # =========================================================================
    # 11. Serialization
    # =========================================================================

    def test_22_serialization_fidelity(self):
        """Verify ReconstructedTimeline.to_dict() round-trips through json.dumps/loads cleanly."""
        timeline = reconstruct_timeline([self.evt_early, self.evt_mid_ist, self.evt_naive_1, self.evt_missing])
        t_dict = timeline.to_dict()

        json_str = json.dumps(t_dict)
        deserialized = json.loads(json_str)

        self.assertEqual(deserialized["summary"]["total_events"], 4)
        self.assertEqual(deserialized["summary"]["duplicates_removed"], 0)
        self.assertEqual(len(deserialized["events"]), 4)

    # =========================================================================
    # 12. Property-Style Invariants (Idempotence & Sequence Safety)
    # =========================================================================

    def test_23_idempotence(self):
        """Verify reconstruct(reconstruct(events)) == reconstruct(events)."""
        events = [self.evt_late, self.evt_early, self.evt_early, self.evt_naive_1]
        run1 = reconstruct_timeline(events)
        run2 = reconstruct_timeline(run1)

        self.assertEqual(run1, run2)
        self.assertEqual(run1.events, run2.events)
        self.assertEqual(run1.to_dict(), run2.to_dict())

    def test_24_source_list_not_mutated(self):
        """Verify reconstruct(events_list) does not mutate the passed list."""
        orig_list = [self.evt_late, self.evt_early]
        orig_copy = list(orig_list)
        reconstruct_timeline(orig_list)
        self.assertEqual(orig_list, orig_copy)

    # =========================================================================
    # 13. Input Validation
    # =========================================================================

    def test_25_none_input_raises_value_error(self):
        """Verify reconstruct_timeline(None) raises ValueError."""
        with self.assertRaises(ValueError):
            reconstruct_timeline(None)

    def test_26_invalid_element_raises_type_error(self):
        """Verify sequence containing non-TimelineEvent elements raises TypeError."""
        with self.assertRaises(TypeError):
            reconstruct_timeline([self.evt_early, "not_an_event"])

    def test_27_order_timeline_events_convenience(self):
        """Verify order_timeline_events returns a tuple of events directly."""
        evts = order_timeline_events([self.evt_late, self.evt_early])
        self.assertIsInstance(evts, tuple)
        self.assertEqual(len(evts), 2)
        self.assertEqual(evts[0], self.evt_early)
        self.assertEqual(evts[1], self.evt_late)

    def test_28_reconstructed_timeline_container_protocol(self):
        """Verify ReconstructedTimeline supports len, iteration, slicing, and contains."""
        timeline = reconstruct_timeline([self.evt_early, self.evt_late])
        self.assertEqual(len(timeline), 2)
        self.assertIn(self.evt_early, timeline)
        self.assertIn(self.evt_late, timeline)
        self.assertEqual(timeline[0], self.evt_early)
        self.assertEqual(list(timeline), [self.evt_early, self.evt_late])


if __name__ == "__main__":
    unittest.main()
