"""
Focused Unit Test Suite for ForensiX V3.2 Timestamp Normalization Engine.

Covers:
1. Valid ISO 8601 parsing (UTC, Z, offsets +05:30, -04:00, etc.).
2. Common datetime representations (space-separated, slash-separated, trailing UTC).
3. Python datetime input (aware and naive).
4. Timezone conversion: exact UTC instant alignment for aware timestamps.
5. Naive datetime preservation: no synthetic timezone or conversion applied.
6. Sub-second precision preservation: seconds, milliseconds, microseconds.
7. Date-only rejection: preventing fabricated midnight.
8. Incomplete / ambiguous string rejection (yearless syslog, non-timestamps).
9. Invalid date / time values rejection (leap-year rules, out-of-range months/days/hours/minutes).
10. Invalid type handling (non-string, non-datetime).
11. Provenance and raw timestamp preservation via NormalizedTimestamp.
12. Deterministic serialization and format_iso_timestamp formatting.
13. Seamless integration with V3.1 TimelineEvent model.
"""

from datetime import datetime, timezone, timedelta
import unittest

from forensix.timeline_models import TimelineCategory, TimelineEvent
from forensix.timestamp_normalizer import (
    NormalizedTimestamp,
    format_iso_timestamp,
    is_timezone_aware,
    normalize_timestamp,
    parse_timestamp,
)


class TestTimestampNormalizer(unittest.TestCase):
    """Rigorous unit tests for the V3.2 Timestamp Normalization Engine."""

    # 1. Valid ISO 8601 parsing
    def test_01_iso8601_utc_z(self):
        """1. Verify ISO 8601 with Z suffix parses to UTC datetime."""
        ts_str = "2026-09-30T14:30:00Z"
        result = normalize_timestamp(ts_str)
        self.assertIsInstance(result, datetime)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 9)
        self.assertEqual(result.day, 30)
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.minute, 30)
        self.assertEqual(result.second, 0)

    def test_02_iso8601_lowercase_z(self):
        """2. Verify ISO 8601 with lowercase z suffix parses cleanly to UTC."""
        result = normalize_timestamp("2026-09-30T14:30:00z")
        self.assertEqual(result, datetime(2026, 9, 30, 14, 30, 0, tzinfo=timezone.utc))

    def test_03_iso8601_positive_offset(self):
        """3. Verify ISO 8601 with positive offset converts to expected UTC instant."""
        # 14:30 in UTC+05:30 is 09:00 UTC
        ts_str = "2026-09-30T14:30:00+05:30"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))

    def test_04_iso8601_negative_offset(self):
        """4. Verify ISO 8601 with negative offset converts to expected UTC instant."""
        # 14:30 in UTC-04:00 is 18:30 UTC
        ts_str = "2026-09-30T14:30:00-04:00"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result, datetime(2026, 9, 30, 18, 30, 0, tzinfo=timezone.utc))

    # 2. Common datetime representations
    def test_05_space_separated_datetime_with_offset(self):
        """5. Verify space-separated datetime with offset converts correctly."""
        ts_str = "2026-09-30 14:30:00 +0530"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))

    def test_06_space_separated_datetime_with_colon_offset(self):
        """6. Verify space-separated datetime with colon in offset converts correctly."""
        ts_str = "2026-09-30 14:30:00 +05:30"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))

    def test_07_trailing_utc_notation(self):
        """7. Verify timestamps with trailing UTC suffix parse into UTC datetime."""
        ts_str = "2026-09-30 14:30:00 UTC"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result, datetime(2026, 9, 30, 14, 30, 0, tzinfo=timezone.utc))

    def test_08_slash_separated_date(self):
        """8. Verify slash-separated date formats parse correctly."""
        ts_str = "2026/09/30 14:30:00"
        result = normalize_timestamp(ts_str)
        self.assertIsNone(result.tzinfo)
        self.assertEqual(result, datetime(2026, 9, 30, 14, 30, 0))

    # 3. Python datetime input
    def test_09_python_datetime_aware(self):
        """9. Verify Python timezone-aware datetime instance converts to UTC."""
        tz_ist = timezone(timedelta(hours=5, minutes=30))
        input_dt = datetime(2026, 9, 30, 14, 30, 0, tzinfo=tz_ist)
        result = normalize_timestamp(input_dt)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))

    def test_10_python_datetime_naive(self):
        """10. Verify Python timezone-naive datetime instance is preserved unchanged."""
        input_dt = datetime(2026, 9, 30, 14, 30, 0)
        result = normalize_timestamp(input_dt)
        self.assertIsNone(result.tzinfo)
        self.assertEqual(result, input_dt)

    # 4. Timezone conversion controls
    def test_11_to_utc_false_preserves_original_offset(self):
        """11. Verify to_utc=False preserves the original timezone offset."""
        ts_str = "2026-09-30T14:30:00+05:30"
        result = normalize_timestamp(ts_str, to_utc=False)
        self.assertIsNotNone(result.tzinfo)
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.utcoffset(), timedelta(hours=5, minutes=30))

    # 5. Naive datetime preservation (no synthetic timezone)
    def test_12_naive_string_does_not_acquire_timezone(self):
        """12. Verify naive string input never acquires UTC or local timezone."""
        ts_str = "2026-09-30 14:30:00"
        result = normalize_timestamp(ts_str)
        self.assertIsNone(result.tzinfo)
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.minute, 30)

    def test_13_is_timezone_aware_helper(self):
        """13. Verify is_timezone_aware accurately distinguishes aware vs naive."""
        self.assertTrue(is_timezone_aware("2026-09-30T14:30:00Z"))
        self.assertTrue(is_timezone_aware("2026-09-30T14:30:00+05:30"))
        self.assertTrue(is_timezone_aware("2026-09-30 14:30:00 UTC"))
        self.assertFalse(is_timezone_aware("2026-09-30 14:30:00"))
        self.assertFalse(is_timezone_aware(datetime(2026, 9, 30, 14, 30, 0)))
        self.assertTrue(is_timezone_aware(datetime(2026, 9, 30, 14, 30, 0, tzinfo=timezone.utc)))

    # 6. Precision preservation
    def test_14_millisecond_precision_preserved(self):
        """14. Verify millisecond precision (3 decimals) is preserved."""
        ts_str = "2026-09-30T14:30:00.123Z"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result.microsecond, 123000)

    def test_15_microsecond_precision_preserved(self):
        """15. Verify microsecond precision (6 decimals) is preserved across UTC conversion."""
        ts_str = "2026-09-30T14:30:00.123456+05:30"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result.microsecond, 123456)
        self.assertEqual(result, datetime(2026, 9, 30, 9, 0, 0, 123456, tzinfo=timezone.utc))

    def test_16_naive_microsecond_preserved(self):
        """16. Verify naive timestamps preserve microsecond precision."""
        ts_str = "2026-09-30 14:30:00.654321"
        result = normalize_timestamp(ts_str)
        self.assertEqual(result.microsecond, 654321)
        self.assertIsNone(result.tzinfo)

    # 7. Date-only rejection (no fabricated midnight)
    def test_17_date_only_string_rejected(self):
        """17. Verify date-only string is rejected rather than guessing midnight."""
        date_only_cases = [
            "2026-09-30",
            "2026/09/30",
            "2026-01-01",
        ]
        for d in date_only_cases:
            with self.subTest(date=d):
                with self.assertRaises(ValueError) as ctx:
                    normalize_timestamp(d)
                self.assertIn("lacks a time component", str(ctx.exception))

    # 8. Incomplete / ambiguous string rejection
    def test_18_yearless_syslog_timestamp_rejected(self):
        """18. Verify yearless syslog timestamp is rejected (no inferred year)."""
        syslog_cases = [
            "Oct  1 12:00:00",
            "Sep 30 14:30:00",
            "Mar 15 08:12:33",
        ]
        for s in syslog_cases:
            with self.subTest(syslog=s):
                with self.assertRaises(ValueError):
                    normalize_timestamp(s)

    def test_19_empty_and_whitespace_rejected(self):
        """19. Verify empty and whitespace strings raise ValueError."""
        for empty_val in ["", "   ", "\t", "\n"]:
            with self.subTest(empty=empty_val):
                with self.assertRaises(ValueError):
                    normalize_timestamp(empty_val)

    def test_20_none_rejected(self):
        """20. Verify None input raises ValueError."""
        with self.assertRaises(ValueError):
            normalize_timestamp(None)  # type: ignore

    def test_21_malformed_string_rejected(self):
        """21. Verify arbitrary text strings raise ValueError."""
        for bad in ["not-a-timestamp", "yesterday", "2026-invalid"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    normalize_timestamp(bad)

    # 9. Invalid date/time values rejection
    def test_22_invalid_calendar_dates_rejected(self):
        """22. Verify invalid calendar values raise ValueError."""
        invalid_calendar = [
            "2026-02-30T12:00:00Z",  # Feb 30 invalid
            "2026-04-31T12:00:00Z",  # Apr 31 invalid
            "2026-13-01T12:00:00Z",  # Month 13 invalid
            "2026-00-10T12:00:00Z",  # Month 0 invalid
            "2026-05-32T12:00:00Z",  # Day 32 invalid
            "2026-05-00T12:00:00Z",  # Day 0 invalid
        ]
        for inv in invalid_calendar:
            with self.subTest(inv=inv):
                with self.assertRaises(ValueError):
                    normalize_timestamp(inv)

    def test_23_invalid_time_components_rejected(self):
        """23. Verify out-of-range hours, minutes, and seconds raise ValueError."""
        invalid_times = [
            "2026-09-30T25:00:00Z",  # Hour 25
            "2026-09-30T14:60:00Z",  # Minute 60
            "2026-09-30T14:30:61Z",  # Second 61
        ]
        for inv in invalid_times:
            with self.subTest(inv=inv):
                with self.assertRaises(ValueError):
                    normalize_timestamp(inv)

    def test_24_malformed_timezone_offset_rejected(self):
        """24. Verify malformed timezone offsets raise ValueError."""
        bad_offsets = [
            "2026-09-30T14:30:00+99:99",
            "2026-09-30T14:30:00+25:00",
            "2026-09-30T14:30:00-24:00",
        ]
        for bo in bad_offsets:
            with self.subTest(bo=bo):
                with self.assertRaises(ValueError):
                    normalize_timestamp(bo)

    # 10. Invalid type handling
    def test_25_invalid_types_raise_type_error(self):
        """25. Verify non-string, non-datetime types raise TypeError."""
        bad_types = [1234567890, 123.456, [], {}, object(), True]
        for bt in bad_types:
            with self.subTest(bt=bt):
                with self.assertRaises(TypeError):
                    normalize_timestamp(bt)  # type: ignore

    # 11. Provenance and raw timestamp preservation
    def test_26_parse_timestamp_structured_result(self):
        """26. Verify parse_timestamp returns complete NormalizedTimestamp record."""
        raw_input = "2026-09-30 14:30:00 +05:30"
        norm = parse_timestamp(raw_input)
        self.assertIsInstance(norm, NormalizedTimestamp)
        self.assertEqual(norm.raw_timestamp, raw_input)
        self.assertTrue(norm.is_timezone_aware)
        self.assertEqual(norm.original_tz_offset, "+05:30")
        self.assertEqual(norm.normalized_datetime, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))

        # to_dict verification
        d = norm.to_dict()
        self.assertEqual(d["raw_timestamp"], raw_input)
        self.assertTrue(d["is_timezone_aware"])
        self.assertEqual(d["original_tz_offset"], "+05:30")
        self.assertEqual(d["normalized_datetime"], "2026-09-30T09:00:00+00:00")

    def test_27_parse_timestamp_naive_structured_result(self):
        """27. Verify parse_timestamp handles naive timestamps with null offset."""
        raw_input = "2026-09-30 14:30:00"
        norm = parse_timestamp(raw_input)
        self.assertFalse(norm.is_timezone_aware)
        self.assertIsNone(norm.original_tz_offset)
        self.assertEqual(norm.raw_timestamp, raw_input)
        self.assertEqual(norm.normalized_datetime, datetime(2026, 9, 30, 14, 30, 0))

    # 12. Deterministic serialization & format_iso_timestamp
    def test_28_format_iso_timestamp(self):
        """28. Verify format_iso_timestamp produces deterministic ISO strings."""
        dt_utc = datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(format_iso_timestamp(dt_utc, use_z=True), "2026-09-30T09:00:00Z")
        self.assertEqual(format_iso_timestamp(dt_utc, use_z=False), "2026-09-30T09:00:00+00:00")

        dt_micro = datetime(2026, 9, 30, 9, 0, 0, 123456, tzinfo=timezone.utc)
        self.assertEqual(format_iso_timestamp(dt_micro, use_z=True), "2026-09-30T09:00:00.123456Z")

        dt_naive = datetime(2026, 9, 30, 14, 30, 0)
        self.assertEqual(format_iso_timestamp(dt_naive), "2026-09-30T14:30:00")

    def test_29_deterministic_behavior_repeated_calls(self):
        """29. Verify repeated normalization calls produce identical datetimes."""
        inputs = [
            "2026-09-30T14:30:00+05:30",
            "2026-09-30 14:30:00",
            "2026-09-30T14:30:00.999Z",
        ]
        for inp in inputs:
            res1 = normalize_timestamp(inp)
            res2 = normalize_timestamp(inp)
            self.assertEqual(res1, res2)
            self.assertEqual(res1.isoformat(), res2.isoformat())

    # 13. Seamless integration with TimelineEvent
    def test_30_timeline_event_integration_aware(self):
        """30. Verify normalized timestamp populates TimelineEvent preserving raw."""
        raw_ts = "2026-09-30 14:30:00 +05:30"
        normalized_dt = normalize_timestamp(raw_ts)

        event = TimelineEvent(
            category=TimelineCategory.AUTHENTICATION,
            event_type="ssh_login_success",
            description="Accepted publickey for root",
            timestamp=normalized_dt,
            raw_timestamp=raw_ts,
            source_path="/var/log/auth.log",
            source_line=10,
        )

        self.assertEqual(event.timestamp, datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(event.raw_timestamp, raw_ts)
        d = event.to_dict()
        self.assertEqual(d["timestamp"], "2026-09-30T09:00:00+00:00")
        self.assertEqual(d["raw_timestamp"], raw_ts)

    def test_31_timeline_event_integration_naive(self):
        """31. Verify naive normalized timestamp populates TimelineEvent preserving raw."""
        raw_ts = "2026-09-30 14:30:00"
        normalized_dt = normalize_timestamp(raw_ts)

        event = TimelineEvent(
            category=TimelineCategory.FILESYSTEM,
            event_type="file_modified",
            description="Config modified",
            timestamp=normalized_dt,
            raw_timestamp=raw_ts,
            source_path="/etc/hosts",
            source_line=1,
        )

        self.assertEqual(event.timestamp, datetime(2026, 9, 30, 14, 30, 0))
        self.assertIsNone(event.timestamp.tzinfo)
        self.assertEqual(event.raw_timestamp, raw_ts)
        d = event.to_dict()
        self.assertEqual(d["timestamp"], "2026-09-30T14:30:00")
        self.assertEqual(d["raw_timestamp"], raw_ts)


if __name__ == "__main__":
    unittest.main()
