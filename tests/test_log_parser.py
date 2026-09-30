"""
Unit and integration tests for Linux Log Parser (log_parser.py & log_models.py).
"""

import gzip
import os
from pathlib import Path
import tempfile
import unittest

from forensix.hasher import compute_hashes
from forensix.log_models import LogEvent, LogEventType, LogParseResult
from forensix.log_parser import (
    classify_log_message,
    iter_log_lines,
    parse_log_file,
    parse_log_line,
    parse_syslog_header,
    stream_log_events,
)


class TestLogParser(unittest.TestCase):
    """Test suite for Linux log parsing, streaming, and forensic immutability."""

    def setUp(self):
        """Create a temporary workspace for isolated log evidence files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_01_valid_auth_log_line(self):
        """1. Verify standard auth.log syslog header parsing."""
        line = "Sep 30 14:25:31 kali sshd[1234]: Accepted password for alice from 192.168.1.100 port 54321 ssh2"
        event = parse_log_line(line, line_number=1, source_path="/var/log/auth.log")

        self.assertEqual(event.hostname, "kali")
        self.assertEqual(event.service, "sshd")
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.raw_timestamp, "Sep 30 14:25:31")
        # BSD syslog lacks year; normalized_timestamp must be None
        self.assertIsNone(event.normalized_timestamp)
        self.assertEqual(event.event_type, LogEventType.SSH_LOGIN_SUCCESS.value)

    def test_02_failed_ssh_login(self):
        """2. Verify failed SSH login event extraction."""
        line = "Sep 30 14:26:00 kali sshd[1235]: Failed password for bob from 10.0.0.5 port 42100 ssh2"
        event = parse_log_line(line, line_number=2, source_path="/var/log/auth.log")

        self.assertEqual(event.event_type, LogEventType.SSH_LOGIN_FAILURE.value)
        self.assertEqual(event.attributes["user"], "bob")
        self.assertEqual(event.attributes["src_ip"], "10.0.0.5")
        self.assertEqual(event.attributes["src_port"], 42100)
        self.assertEqual(event.attributes["auth_method"], "password")

    def test_03_successful_ssh_login(self):
        """3. Verify successful SSH publickey and password login extraction."""
        line_pk = "Sep 30 14:27:12 kali sshd[1236]: Accepted publickey for analyst from 192.168.50.2 port 60123 ssh2: RSA SHA256:abc"
        event = parse_log_line(line_pk, line_number=3, source_path="/var/log/auth.log")

        self.assertEqual(event.event_type, LogEventType.SSH_LOGIN_SUCCESS.value)
        self.assertEqual(event.attributes["user"], "analyst")
        self.assertEqual(event.attributes["src_ip"], "192.168.50.2")
        self.assertEqual(event.attributes["src_port"], 60123)
        self.assertEqual(event.attributes["auth_method"], "publickey")

    def test_04_invalid_ssh_user(self):
        """4. Verify invalid SSH user attempt extraction."""
        line = "Sep 30 14:28:44 kali sshd[1237]: Failed password for invalid user admin from 172.16.0.40 port 33890 ssh2"
        event = parse_log_line(line, line_number=4, source_path="/var/log/auth.log")

        self.assertEqual(event.event_type, LogEventType.SSH_INVALID_USER.value)
        self.assertEqual(event.attributes["user"], "admin")
        self.assertEqual(event.attributes["src_ip"], "172.16.0.40")
        self.assertTrue(event.attributes.get("is_invalid_user"))

    def test_05_sudo_related_event(self):
        """5. Verify sudo command execution parsing."""
        line = "Sep 30 14:30:00 kali sudo:  analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        event = parse_log_line(line, line_number=5, source_path="/var/log/auth.log")

        self.assertEqual(event.event_type, LogEventType.SUDO_COMMAND.value)
        self.assertEqual(event.attributes["sudo_user"], "analyst")
        self.assertEqual(event.attributes["target_user"], "root")
        self.assertEqual(event.attributes["tty"], "pts/0")
        self.assertEqual(event.attributes["pwd"], "/home/analyst")
        self.assertEqual(event.attributes["command"], "/bin/cat /etc/shadow")

    def test_06_session_open_and_close(self):
        """6. Verify PAM and sshd session open/close extraction."""
        line_open = "Sep 30 14:31:01 kali sshd[1238]: pam_unix(sshd:session): session opened for user analyst by (uid=0)"
        evt_open = parse_log_line(line_open, line_number=6, source_path="/var/log/auth.log")
        self.assertEqual(evt_open.event_type, LogEventType.SESSION_OPEN.value)
        self.assertEqual(evt_open.attributes["user"], "analyst")

        line_close = "Sep 30 14:35:10 kali sshd[1238]: pam_unix(sshd:session): session closed for user analyst"
        evt_close = parse_log_line(line_close, line_number=7, source_path="/var/log/auth.log")
        self.assertEqual(evt_close.event_type, LogEventType.SESSION_CLOSE.value)
        self.assertEqual(evt_close.attributes["user"], "analyst")

    def test_07_valid_syslog_line(self):
        """7. Verify general syslog message extraction."""
        line = "Sep 30 14:36:00 kali systemd[1]: Started Daily apt upgrade and clean activities."
        event = parse_log_line(line, line_number=8, source_path="/var/log/syslog")

        self.assertEqual(event.event_type, LogEventType.GENERIC_SYSLOG.value)
        self.assertEqual(event.service, "systemd")
        self.assertEqual(event.pid, 1)
        self.assertIn("Started Daily apt upgrade", event.raw_message)

    def test_08_unknown_unrecognized_line(self):
        """8. Verify lines with non-syslog format fall back safely to UNKNOWN_FORMAT."""
        line = "Random unstructured application trace without timestamp or prefix"
        event = parse_log_line(line, line_number=9, source_path="/var/log/custom.log")

        self.assertEqual(event.event_type, LogEventType.UNKNOWN_FORMAT.value)
        self.assertIsNone(event.raw_timestamp)
        self.assertIsNone(event.service)
        self.assertEqual(event.raw_line, line)

    def test_09_empty_file(self):
        """9. Verify empty log file produces clean 0-event result."""
        empty_log = self.workspace / "empty.log"
        empty_log.touch()

        result = parse_log_file(empty_log)
        self.assertEqual(result.total_lines, 0)
        self.assertEqual(result.parsed_events, 0)
        self.assertEqual(len(result.events), 0)

    def test_10_empty_lines_handling(self):
        """10. Verify empty or whitespace-only lines are parsed without crashing."""
        log_file = self.workspace / "with_blanks.log"
        log_file.write_text("\n   \nSep 30 14:40:00 kali systemd[1]: Reloading.\n\n")

        result = parse_log_file(log_file)
        self.assertEqual(result.total_lines, 4)
        # The blank lines produce UNKNOWN_FORMAT
        self.assertEqual(result.event_counts[LogEventType.UNKNOWN_FORMAT.value], 3)
        self.assertEqual(result.event_counts[LogEventType.GENERIC_SYSLOG.value], 1)

    def test_11_malformed_lines_graceful_handling(self):
        """11. Verify corrupted, truncated, and irregular lines do not break parser."""
        log_file = self.workspace / "malformed.log"
        content = (
            "Sep 30 14:41:00 incomplete line\n"
            "::: missing all fields\n"
            "Sep 30 14:42:00 kali sshd[bad_pid]: bad pid format\n"
            "Sep 30 14:43:00 kali sshd[999]: Accepted password for bob from 1.2.3.4 port 9999\n"
        )
        log_file.write_text(content)

        result = parse_log_file(log_file)
        self.assertEqual(result.total_lines, 4)
        # The valid line must still be parsed accurately
        success_evt = [e for e in result.events if e.event_type == LogEventType.SSH_LOGIN_SUCCESS.value]
        self.assertEqual(len(success_evt), 1)
        self.assertEqual(success_evt[0].attributes["user"], "bob")

    def test_12_invalid_utf8_encoding(self):
        """12. Verify invalid UTF-8 bytes are handled via replacement without exception."""
        log_file = self.workspace / "corrupted_bytes.log"
        # Write binary containing invalid UTF-8 byte 0xff and 0xfe
        raw_data = b"Sep 30 14:45:00 kali kernel: Packet drop \xff\xfe on eth0\n"
        log_file.write_bytes(raw_data)

        result = parse_log_file(log_file)
        self.assertEqual(result.total_lines, 1)
        evt = result.events[0]
        self.assertEqual(evt.service, "kernel")
        self.assertIn("\ufffd", evt.raw_message)

    def test_13_and_14_multiple_lines_and_line_numbers(self):
        """13 & 14. Verify sequential 1-indexed line numbers across multiple lines."""
        log_file = self.workspace / "multi.log"
        lines = [
            "Sep 30 10:00:00 kali service[1]: msg 1",
            "Sep 30 10:00:01 kali service[2]: msg 2",
            "Sep 30 10:00:02 kali service[3]: msg 3",
        ]
        log_file.write_text("\n".join(lines) + "\n")

        result = parse_log_file(log_file)
        self.assertEqual(result.total_lines, 3)
        for idx, evt in enumerate(result.events, start=1):
            self.assertEqual(evt.line_number, idx)

    def test_15_timestamp_handling_bsd_vs_iso(self):
        """15. Verify BSD syslog preserves raw timestamp with None normalized, while ISO provides both."""
        # BSD style: lacks year
        bsd_line = "Oct  1 08:00:00 host sshd[1]: Accepted password for root from 1.1.1.1 port 22"
        bsd_evt = parse_log_line(bsd_line, 1, "auth.log")
        self.assertEqual(bsd_evt.raw_timestamp, "Oct  1 08:00:00")
        self.assertIsNone(bsd_evt.normalized_timestamp)

        # RFC 5424 / ISO 8601 style: contains year
        iso_line = "2026-10-01T08:00:00.123456+00:00 host sshd[1]: Accepted password for root from 1.1.1.1 port 22"
        iso_evt = parse_log_line(iso_line, 2, "auth.log")
        self.assertEqual(iso_evt.raw_timestamp, "2026-10-01T08:00:00.123456+00:00")
        self.assertEqual(iso_evt.normalized_timestamp, "2026-10-01T08:00:00.123456+00:00")

    def test_16_pid_extraction(self):
        """16. Verify PID extraction handles present, absent, and service-without-pid cases."""
        # With PID
        line_with_pid = "Sep 30 12:00:00 host sshd[5678]: message"
        evt1 = parse_log_line(line_with_pid, 1, "syslog")
        self.assertEqual(evt1.pid, 5678)

        # Without PID
        line_no_pid = "Sep 30 12:00:00 host kernel: message"
        evt2 = parse_log_line(line_no_pid, 2, "syslog")
        self.assertIsNone(evt2.pid)

    def test_17_source_path_and_artifact_id_preservation(self):
        """17. Verify source path and artifact_id reference are retained on every event."""
        log_file = self.workspace / "tracked.log"
        log_file.write_text("Sep 30 12:00:00 host test[1]: sample\n")

        result = parse_log_file(log_file, artifact_id="ART-TEST-UUID")
        self.assertEqual(result.artifact_id, "ART-TEST-UUID")
        self.assertEqual(result.events[0].source_artifact_id, "ART-TEST-UUID")
        self.assertEqual(result.events[0].source_path, str(log_file.resolve()))

    def test_18_large_file_streaming_behavior(self):
        """18. Verify generator streaming handles large sequences line-by-line."""
        log_file = self.workspace / "large_stream.log"
        num_lines = 1000
        with log_file.open("w", encoding="utf-8") as f:
            for i in range(num_lines):
                f.write(f"Sep 30 12:00:{i%60:02d} host daemon[{i}]: iteration {i}\n")

        count = 0
        for evt in stream_log_events(log_file):
            count += 1
            if count == 500:
                self.assertEqual(evt.line_number, 500)
                self.assertEqual(evt.pid, 499)

        self.assertEqual(count, num_lines)

    def test_19_evidence_immutability(self):
        """19. Verify log parsing never alters source file content, hashes, size, or mtime."""
        log_file = self.workspace / "immutable_evidence.log"
        content = (
            "Sep 30 12:00:00 host sshd[100]: Accepted password for root from 1.2.3.4 port 22\n"
            "Sep 30 12:01:00 host sudo: user : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n"
        )
        log_file.write_text(content)

        pre_hashes = compute_hashes(log_file)
        pre_stat = log_file.stat()

        # Run parsing multiple times
        _ = parse_log_file(log_file)
        _ = list(stream_log_events(log_file))

        post_hashes = compute_hashes(log_file)
        post_stat = log_file.stat()

        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(pre_hashes["md5"], post_hashes["md5"])
        self.assertEqual(pre_stat.st_size, post_stat.st_size)
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime)

    def test_20_directory_target_raises_error(self):
        """20. Verify attempting to parse a directory raises IsADirectoryError."""
        with self.assertRaises(IsADirectoryError):
            parse_log_file(self.workspace)

    def test_21_deterministic_output(self):
        """21. Verify parsing the same log yields identical event sequences and dictionaries."""
        log_file = self.workspace / "deterministic.log"
        log_file.write_text("Sep 30 12:00:00 host sshd[1]: Accepted password for user from 1.1.1.1 port 22\n")

        res1 = parse_log_file(log_file)
        res2 = parse_log_file(log_file)

        self.assertEqual(res1.events[0].event_type, res2.events[0].event_type)
        self.assertEqual(res1.events[0].attributes, res2.events[0].attributes)
        self.assertEqual(res1.to_dict()["summary"], res2.to_dict()["summary"])

    def test_22_rotated_uncompressed_log_file(self):
        """22. Verify rotated plain text log (e.g. auth.log.1) is parsed transparently."""
        rotated_log = self.workspace / "auth.log.1"
        rotated_log.write_text("Sep 29 23:59:00 host sshd[50]: Failed password for guest from 9.9.9.9 port 1234\n")

        result = parse_log_file(rotated_log)
        self.assertEqual(result.total_lines, 1)
        self.assertEqual(result.events[0].event_type, LogEventType.SSH_LOGIN_FAILURE.value)
        self.assertEqual(result.events[0].attributes["user"], "guest")

    def test_23_rotated_gzip_compressed_log_file(self):
        """23. Verify gzip-compressed log (.gz) is streamed and parsed in-memory without disk extraction."""
        gz_log = self.workspace / "auth.log.2.gz"
        content = "Sep 28 10:00:00 host sshd[10]: Accepted publickey for dev from 10.10.10.10 port 5555\n"
        with gzip.open(gz_log, "wt", encoding="utf-8") as f:
            f.write(content)

        pre_hashes = compute_hashes(gz_log)

        result = parse_log_file(gz_log)
        self.assertEqual(result.total_lines, 1)
        self.assertEqual(result.events[0].event_type, LogEventType.SSH_LOGIN_SUCCESS.value)
        self.assertEqual(result.events[0].attributes["user"], "dev")

        # Verify no extracted files were left in workspace
        files_in_workspace = list(self.workspace.glob("*"))
        self.assertEqual(len(files_in_workspace), 1)
        self.assertEqual(files_in_workspace[0].name, "auth.log.2.gz")

        # Verify gz evidence file remained unaltered
        post_hashes = compute_hashes(gz_log)
        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])


if __name__ == "__main__":
    unittest.main()
