"""
Focused Unit Test Suite for ForensiX V3.5 Timeline Querying.

Covers:
1. Basic Querying:
   - Empty query returns all events in canonical order.
   - Query against empty timeline returns empty result.
   - No-match query returns empty result without error.

2. Category Filtering:
   - Filtering by FILESYSTEM, LOG, AUTHENTICATION.
   - String category representation vs TimelineCategory enum.
   - Invalid category raises ValueError.

3. Event Type Filtering:
   - Exact match for specific event_type.
   - Non-matching event_type returns 0 events.
   - Empty/whitespace event_type raises ValueError.

4. Source Path Filtering:
   - Exact match by source_path (str and Path).
   - Non-matching source_path returns 0 events.

5. Source Artifact ID & Event ID Filtering:
   - Exact match by source_artifact_id.
   - Exact match by source_event_id.

6. Timestamp Range Filtering:
   - start only (inclusive).
   - end only (inclusive).
   - start and end range (inclusive).
   - Events before start or after end excluded.
   - Missing timestamps (timestamp=None) excluded from time-range queries.
   - Timezone-aware queries match aware events by UTC instant across different offsets.
   - Timezone-naive queries match naive events directly.
   - Incompatible timezone awareness (aware query + naive event or vice versa) treated as non-matching.
   - Invalid range (start > end) raises ValueError.
   - Mixed awareness in query start and end raises ValueError.
   - Date-only strings in query raise ValueError.

7. Text Search:
   - Substring match in description.
   - Substring match in raw_data.
   - Substring match in string attributes.
   - Case-insensitive search by default.
   - Case-sensitive search option.

8. Combined Filters (Logical AND):
   - category + event_type.
   - category + timestamp range.
   - category + source_path.
   - timestamp range + event_type.
   - Multiple combined filters require all conditions to match.

9. Ordering Preservation:
   - Query results strictly preserve the V3.4 canonical timeline ordering.

10. Immutability & Determinism:
    - Querying does not mutate source events or ReconstructedTimeline.
    - Repeated query execution produces identical results.
    - Query and QueryResult serialization round-trips cleanly via to_dict().
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import unittest

from forensix.timeline_models import TimelineCategory, TimelineEvent, create_timeline_event
from forensix.timeline_query import (
    TimelineQuery,
    TimelineQueryResult,
    query_timeline,
)
from forensix.timeline_reconstruction import reconstruct_timeline


class TestTimelineQuery(unittest.TestCase):
    """Rigorous unit tests for ForensiX V3.5 Timeline Querying Engine."""

    def setUp(self) -> None:
        self.tz_ist = timezone(timedelta(hours=5, minutes=30))
        self.tz_p04 = timezone(timedelta(hours=4))

        # Diverse sample events for querying
        self.evt_fs_1 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
            description="Created configuration file",
            timestamp=datetime(2026, 9, 30, 8, 0, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T08:00:00Z",
            source_path="/etc/app.conf",
            source_artifact_id="ART-FS-1",
            attributes={"permissions": "0644", "owner": "root"},
        )

        self.evt_fs_2 = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Modified configuration file",
            timestamp=datetime(2026, 9, 30, 8, 30, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T08:30:00Z",
            source_path="/etc/app.conf",
            source_artifact_id="ART-FS-1",
            attributes={"permissions": "0644", "owner": "root"},
        )

        self.evt_auth_1 = create_timeline_event(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for deploy user",
            # 14:30 in +05:30 == 09:00 UTC
            timestamp=datetime(2026, 9, 30, 14, 30, 0, tzinfo=self.tz_ist),
            raw_timestamp="2026-09-30T14:30:00+05:30",
            source_path="/var/log/auth.log",
            source_line=45,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="AUTH-101",
            raw_data="Sep 30 14:30:00 server sshd[123]: Accepted publickey for deploy",
            attributes={"user": "deploy", "src_ip": "10.0.1.50"},
        )

        self.evt_log_1 = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="session_open",
            description="Session opened for user deploy",
            timestamp=datetime(2026, 9, 30, 9, 5, 0, tzinfo=timezone.utc),
            raw_timestamp="2026-09-30T09:05:00Z",
            source_path="/var/log/auth.log",
            source_line=48,
            source_artifact_id="ART-AUTH-LOG",
            source_event_id="LOG-201",
            raw_data="Sep 30 09:05:00 server systemd-logind: Session opened for user deploy",
            attributes={"user": "deploy"},
        )

        self.evt_naive = create_timeline_event(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_accessed",
            description="Local document accessed",
            timestamp=datetime(2026, 9, 30, 10, 0, 0),  # Naive
            raw_timestamp="2026-09-30 10:00:00",
            source_path="/home/deploy/report.txt",
            source_artifact_id="ART-USER-DOC",
        )

        self.evt_missing = create_timeline_event(
            category=TimelineCategory.LOG,
            event_type="generic_syslog",
            description="Kernel ring buffer line lacking year",
            timestamp=None,  # Missing
            raw_timestamp="Oct 02 12:00:00",
            source_path="/var/log/messages",
            source_line=12,
            source_artifact_id="ART-MSG-LOG",
        )

        # Reconstructed timeline in canonical V3.4 order
        self.timeline = reconstruct_timeline([
            self.evt_missing,
            self.evt_naive,
            self.evt_log_1,
            self.evt_auth_1,
            self.evt_fs_2,
            self.evt_fs_1,
        ])

    # =========================================================================
    # 1. Basic Querying
    # =========================================================================

    def test_01_empty_query_returns_all_events_in_order(self):
        """Verify empty query returns all timeline events in original canonical order."""
        res = query_timeline(self.timeline)
        self.assertEqual(len(res), len(self.timeline))
        self.assertEqual(list(res), list(self.timeline))

    def test_02_query_against_empty_timeline(self):
        """Verify querying an empty timeline returns an empty result container."""
        empty_tl = reconstruct_timeline([])
        res = query_timeline(empty_tl, category=TimelineCategory.FILESYSTEM)
        self.assertEqual(len(res), 0)
        self.assertEqual(res.events, ())
        self.assertEqual(res.total_events, 0)

    def test_03_no_match_query(self):
        """Verify query with no matching events returns empty result without error."""
        res = query_timeline(self.timeline, event_type="non_existent_type")
        self.assertEqual(len(res), 0)
        self.assertEqual(res.total_events, 0)

    # =========================================================================
    # 2. Category Filtering
    # =========================================================================

    def test_04_filter_by_filesystem_category(self):
        """Verify filtering by TimelineCategory.FILESYSTEM returns only filesystem events."""
        res = query_timeline(self.timeline, category=TimelineCategory.FILESYSTEM)
        self.assertEqual(len(res), 3)  # evt_fs_1, evt_fs_2, evt_naive
        for e in res:
            self.assertEqual(e.category, TimelineCategory.FILESYSTEM)

    def test_05_filter_by_log_category(self):
        """Verify filtering by TimelineCategory.LOG returns log events including timestamp-less ones."""
        res = query_timeline(self.timeline, category=TimelineCategory.LOG)
        self.assertEqual(len(res), 2)  # evt_log_1 and evt_missing
        for e in res:
            self.assertEqual(e.category, TimelineCategory.LOG)
        # Verify missing timestamp event is included when non-time filter matches
        self.assertIn(self.evt_missing, res)

    def test_06_filter_by_authentication_category(self):
        """Verify filtering by TimelineCategory.AUTHENTICATION."""
        res = query_timeline(self.timeline, category=TimelineCategory.AUTHENTICATION)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_auth_1)

    def test_07_filter_by_string_category(self):
        """Verify category can be specified as case-insensitive string."""
        res = query_timeline(self.timeline, category="authentication")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_auth_1)

    def test_08_invalid_category_raises_value_error(self):
        """Verify invalid category raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            query_timeline(self.timeline, category="invalid_cat")
        self.assertIn("Invalid category", str(ctx.exception))

    # =========================================================================
    # 3. Event Type Filtering
    # =========================================================================

    def test_09_filter_by_event_type_exact(self):
        """Verify exact match filtering on event_type."""
        res = query_timeline(self.timeline, event_type="file_created")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_fs_1)

    def test_10_filter_by_event_type_no_match(self):
        """Verify non-matching event_type returns 0 events."""
        res = query_timeline(self.timeline, event_type="ssh_login_failure")
        self.assertEqual(len(res), 0)

    def test_11_invalid_event_type_raises_error(self):
        """Verify empty or non-string event_type raises appropriate error."""
        with self.assertRaises(ValueError):
            TimelineQuery(event_type="")
        with self.assertRaises(ValueError):
            TimelineQuery(event_type="   ")
        with self.assertRaises(TypeError):
            TimelineQuery(event_type=123)

    # =========================================================================
    # 4. Source Path Filtering
    # =========================================================================

    def test_12_filter_by_source_path_exact(self):
        """Verify filtering by source_path returns matching events across categories."""
        res = query_timeline(self.timeline, source_path="/var/log/auth.log")
        self.assertEqual(len(res), 2)  # evt_auth_1 and evt_log_1
        self.assertEqual(res[0], self.evt_auth_1)
        self.assertEqual(res[1], self.evt_log_1)

    def test_13_filter_by_path_object(self):
        """Verify Path instance can be passed as source_path."""
        res = query_timeline(self.timeline, source_path=Path("/etc/app.conf"))
        self.assertEqual(len(res), 2)  # evt_fs_1, evt_fs_2

    # =========================================================================
    # 5. Source Artifact ID & Event ID Filtering
    # =========================================================================

    def test_14_filter_by_source_artifact_id(self):
        """Verify filtering by source_artifact_id."""
        res = query_timeline(self.timeline, source_artifact_id="ART-FS-1")
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], self.evt_fs_1)
        self.assertEqual(res[1], self.evt_fs_2)

    def test_15_filter_by_source_event_id(self):
        """Verify filtering by source_event_id."""
        res = query_timeline(self.timeline, source_event_id="AUTH-101")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_auth_1)

    # =========================================================================
    # 6. Timestamp Range Filtering
    # =========================================================================

    def test_16_timestamp_range_start_only(self):
        """Verify start boundary only (inclusive)."""
        # Start at 08:30 UTC
        res = query_timeline(
            self.timeline,
            start=datetime(2026, 9, 30, 8, 30, 0, tzinfo=timezone.utc),
        )
        # Should include: evt_fs_2 (08:30Z), evt_auth_1 (09:00Z), evt_log_1 (09:05Z)
        # Should exclude: evt_fs_1 (08:00Z), evt_naive (incompatible), evt_missing (None)
        self.assertEqual(len(res), 3)
        self.assertEqual(res[0], self.evt_fs_2)
        self.assertEqual(res[1], self.evt_auth_1)
        self.assertEqual(res[2], self.evt_log_1)

    def test_17_timestamp_range_end_only(self):
        """Verify end boundary only (inclusive)."""
        # End at 08:30 UTC
        res = query_timeline(
            self.timeline,
            end=datetime(2026, 9, 30, 8, 30, 0, tzinfo=timezone.utc),
        )
        # Should include: evt_fs_1 (08:00Z), evt_fs_2 (08:30Z)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], self.evt_fs_1)
        self.assertEqual(res[1], self.evt_fs_2)

    def test_18_timestamp_range_start_and_end(self):
        """Verify bounded range start <= t <= end (inclusive)."""
        res = query_timeline(
            self.timeline,
            start="2026-09-30T08:30:00Z",
            end="2026-09-30T09:00:00Z",
        )
        # 08:30Z (evt_fs_2) and 09:00Z (evt_auth_1 expressed as 14:30+05:30)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], self.evt_fs_2)
        self.assertEqual(res[1], self.evt_auth_1)

    def test_19_timestamp_range_timezone_aware_instant_comparison(self):
        """Verify query with different timezone offset matches exact UTC instant."""
        # Query window from 13:00 to 14:00 in +04:00 (which is 09:00 to 10:00 UTC)
        start_p04 = datetime(2026, 9, 30, 13, 0, 0, tzinfo=self.tz_p04)  # 09:00 UTC
        end_p04 = datetime(2026, 9, 30, 14, 0, 0, tzinfo=self.tz_p04)    # 10:00 UTC

        res = query_timeline(self.timeline, start=start_p04, end=end_p04)
        # Matches: evt_auth_1 (09:00 UTC), evt_log_1 (09:05 UTC)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], self.evt_auth_1)
        self.assertEqual(res[1], self.evt_log_1)

    def test_20_timestamp_range_naive_query_matches_naive_events(self):
        """Verify naive timestamp query matches naive events directly."""
        res = query_timeline(
            self.timeline,
            start=datetime(2026, 9, 30, 9, 30, 0),  # Naive
            end=datetime(2026, 9, 30, 10, 30, 0),    # Naive
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_naive)  # 10:00:00 naive

    def test_21_incompatible_timezone_awareness_does_not_match(self):
        """Verify aware query never matches naive event, and naive query never matches aware event."""
        # Aware query on time window containing 10:00
        aware_res = query_timeline(
            self.timeline,
            start="2026-09-30T09:30:00Z",
            end="2026-09-30T10:30:00Z",
        )
        self.assertNotIn(self.evt_naive, aware_res)

        # Naive query on time window containing 08:00
        naive_res = query_timeline(
            self.timeline,
            start=datetime(2026, 9, 30, 7, 30, 0),
            end=datetime(2026, 9, 30, 8, 30, 0),
        )
        self.assertNotIn(self.evt_fs_1, naive_res)  # evt_fs_1 is aware, query is naive

    def test_22_missing_timestamp_never_matches_time_range(self):
        """Verify event with timestamp=None never matches a timestamp range query."""
        res = query_timeline(
            self.timeline,
            start="2026-01-01T00:00:00Z",
            end="2026-12-31T23:59:59Z",
        )
        self.assertNotIn(self.evt_missing, res)

    def test_23_invalid_timestamp_range_start_after_end(self):
        """Verify start > end raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            TimelineQuery(
                start="2026-09-30T10:00:00Z",
                end="2026-09-30T09:00:00Z",
            )
        self.assertIn("cannot be greater than end", str(ctx.exception))

    def test_24_mixed_awareness_in_query_raises_value_error(self):
        """Verify query with one aware and one naive boundary raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            TimelineQuery(
                start=datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc),
                end=datetime(2026, 9, 30, 10, 0, 0),  # Naive
            )
        self.assertIn("matching timezone awareness", str(ctx.exception))

    def test_25_date_only_string_in_query_raises_value_error(self):
        """Verify date-only string without time component raises ValueError via V3.2."""
        with self.assertRaises(ValueError) as ctx:
            TimelineQuery(start="2026-09-30")
        self.assertIn("lacks a time component", str(ctx.exception))

    # =========================================================================
    # 7. Text Search
    # =========================================================================

    def test_26_text_search_in_description(self):
        """Verify text substring search in description (case-insensitive)."""
        res = query_timeline(self.timeline, text="configuration")
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], self.evt_fs_1)
        self.assertEqual(res[1], self.evt_fs_2)

    def test_27_text_search_in_raw_data(self):
        """Verify text search matches content in raw_data."""
        res = query_timeline(self.timeline, text="systemd-logind")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_log_1)

    def test_28_text_search_in_attributes(self):
        """Verify text search matches string attribute values."""
        res = query_timeline(self.timeline, text="10.0.1.50")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_auth_1)

    def test_29_text_search_case_sensitive(self):
        """Verify case-sensitive search behavior."""
        # Lowercase search with case_sensitive=True on uppercase 'Accepted'
        res_no_match = query_timeline(self.timeline, text="accepted", case_sensitive=True)
        self.assertEqual(len(res_no_match), 0)

        res_match = query_timeline(self.timeline, text="Accepted", case_sensitive=True)
        self.assertEqual(len(res_match), 1)
        self.assertEqual(res_match[0], self.evt_auth_1)

    # =========================================================================
    # 8. Combined Filters (Logical AND)
    # =========================================================================

    def test_30_combined_category_and_event_type(self):
        """Verify category AND event_type conjunction."""
        res = query_timeline(
            self.timeline,
            category=TimelineCategory.FILESYSTEM,
            event_type="file_created",
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_fs_1)

    def test_31_combined_category_and_timestamp_range(self):
        """Verify category AND timestamp range conjunction."""
        res = query_timeline(
            self.timeline,
            category=TimelineCategory.FILESYSTEM,
            start="2026-09-30T08:15:00Z",
            end="2026-09-30T08:45:00Z",
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_fs_2)

    def test_32_combined_multiple_filters(self):
        """Verify multi-attribute query (category + source_path + event_type + text)."""
        res = query_timeline(
            self.timeline,
            category=TimelineCategory.AUTHENTICATION,
            source_path="/var/log/auth.log",
            event_type="ssh_login_success",
            text="deploy",
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], self.evt_auth_1)

    def test_33_combined_filter_mismatch_returns_empty(self):
        """Verify that failure of any one filter condition excludes the event."""
        res = query_timeline(
            self.timeline,
            category=TimelineCategory.AUTHENTICATION,
            source_path="/etc/app.conf",  # Mismatched path
        )
        self.assertEqual(len(res), 0)

    # =========================================================================
    # 9. Ordering Preservation
    # =========================================================================

    def test_34_query_preserves_canonical_v34_ordering(self):
        """Verify query results preserve the exact relative order from the input timeline."""
        # All events matching category FILESYSTEM
        res = query_timeline(self.timeline, category=TimelineCategory.FILESYSTEM)
        # Expected V3.4 order: evt_fs_1 (08:00 UTC), evt_fs_2 (08:30 UTC), evt_naive (Class NAIVE)
        self.assertEqual(len(res), 3)
        self.assertEqual(res[0], self.evt_fs_1)
        self.assertEqual(res[1], self.evt_fs_2)
        self.assertEqual(res[2], self.evt_naive)

    # =========================================================================
    # 10. Immutability, Serialization & Input Safety
    # =========================================================================

    def test_35_immutability_timeline_and_events_not_mutated(self):
        """Verify query execution does not alter source events or timeline."""
        orig_dict = self.evt_auth_1.to_dict()
        query_timeline(self.timeline, category=TimelineCategory.AUTHENTICATION)
        self.assertEqual(self.evt_auth_1.to_dict(), orig_dict)

    def test_36_determinism_repeated_queries(self):
        """Verify identical query produces identical result instances repeatedly."""
        q = TimelineQuery(category=TimelineCategory.FILESYSTEM)
        res1 = query_timeline(self.timeline, q)
        res2 = query_timeline(self.timeline, q)
        self.assertEqual(res1.events, res2.events)
        self.assertEqual(res1.to_dict(), res2.to_dict())

    def test_37_query_and_result_serialization(self):
        """Verify TimelineQuery and TimelineQueryResult serialize to JSON cleanly."""
        res = query_timeline(self.timeline, category=TimelineCategory.LOG)
        r_dict = res.to_dict()

        json_str = json.dumps(r_dict)
        deserialized = json.loads(json_str)

        self.assertEqual(deserialized["summary"]["total_events"], 2)
        self.assertEqual(deserialized["summary"]["query"]["category"], "log")
        self.assertEqual(len(deserialized["events"]), 2)

    def test_38_input_validation_timeline_none(self):
        """Verify query_timeline(None) raises ValueError."""
        with self.assertRaises(ValueError):
            query_timeline(None)

    def test_39_input_validation_invalid_timeline_elements(self):
        """Verify sequence with invalid elements raises TypeError."""
        with self.assertRaises(TypeError):
            query_timeline([self.evt_fs_1, "invalid_element"])

    def test_40_conflicting_query_object_and_kwargs(self):
        """Verify passing both a query object and keyword arguments raises ValueError."""
        q = TimelineQuery(category=TimelineCategory.LOG)
        with self.assertRaises(ValueError):
            query_timeline(self.timeline, query=q, category=TimelineCategory.FILESYSTEM)


if __name__ == "__main__":
    unittest.main()
