"""
Unit and integration tests for Forensic Authentication Activity (V2.3).
"""

import gzip
import os
from pathlib import Path
import tempfile
import unittest

from forensix.auth_analyzer import (
    extract_authentication_activity,
    log_event_to_auth_record,
    stream_authentication_activity,
)
from forensix.auth_models import (
    AuthEventType,
    AuthStatus,
    AuthenticationActivityResult,
    AuthenticationRecord,
    generate_auth_id,
)
from forensix.hasher import compute_hashes
from forensix.log_parser import parse_log_line


class TestAuthenticationActivity(unittest.TestCase):
    """Test suite for extracting and structuring authentication activity."""

    def setUp(self):
        """Create a temporary workspace for isolated test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_01_ssh_successful_password_login(self):
        """1. Verify SSH successful password login produces correct record."""
        line = "Sep 30 14:00:00 host sshd[1001]: Accepted password for alice from 192.168.1.50 port 51234 ssh2"
        evt = parse_log_line(line, line_number=1, source_path="/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertTrue(rec.auth_id.startswith("AUTH-"))
        self.assertEqual(len(rec.auth_id.split("-")), 6)  # AUTH-<UUIDv4>
        self.assertEqual(rec.event_type, AuthEventType.SSH_LOGIN_SUCCESS.value)
        self.assertEqual(rec.status, AuthStatus.SUCCESS.value)
        self.assertEqual(rec.username, "alice")
        self.assertEqual(rec.source_ip, "192.168.1.50")
        self.assertEqual(rec.source_port, 51234)
        self.assertEqual(rec.authentication_method, "password")
        self.assertEqual(rec.service, "sshd")
        # BSD syslog lacks year; normalized_timestamp must be None
        self.assertIsNone(rec.normalized_timestamp)
        self.assertEqual(rec.raw_timestamp, "Sep 30 14:00:00")

    def test_02_ssh_successful_publickey_login(self):
        """2. Verify SSH successful publickey login extraction."""
        line = "Sep 30 14:05:00 host sshd[1002]: Accepted publickey for bob from 10.0.0.100 port 45123 ssh2: ED25519 SHA256:xyz"
        evt = parse_log_line(line, line_number=2, source_path="/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.SSH_LOGIN_SUCCESS.value)
        self.assertEqual(rec.status, AuthStatus.SUCCESS.value)
        self.assertEqual(rec.username, "bob")
        self.assertEqual(rec.source_ip, "10.0.0.100")
        self.assertEqual(rec.source_port, 45123)
        self.assertEqual(rec.authentication_method, "publickey")

    def test_03_ssh_failed_password_login(self):
        """3. Verify SSH failed password login extraction."""
        line = "Sep 30 14:10:00 host sshd[1003]: Failed password for charlie from 172.16.5.99 port 60001 ssh2"
        evt = parse_log_line(line, line_number=3, source_path="/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.SSH_LOGIN_FAILURE.value)
        self.assertEqual(rec.status, AuthStatus.FAILURE.value)
        self.assertEqual(rec.username, "charlie")
        self.assertEqual(rec.source_ip, "172.16.5.99")
        self.assertEqual(rec.source_port, 60001)
        self.assertEqual(rec.authentication_method, "password")

    def test_04_ssh_invalid_user(self):
        """4. Verify SSH invalid user login attempt."""
        line = "Sep 30 14:15:00 host sshd[1004]: Failed password for invalid user hacker from 203.0.113.5 port 44321 ssh2"
        evt = parse_log_line(line, line_number=4, source_path="/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.SSH_INVALID_USER.value)
        self.assertEqual(rec.status, AuthStatus.FAILURE.value)
        self.assertEqual(rec.username, "hacker")
        self.assertEqual(rec.source_ip, "203.0.113.5")
        self.assertTrue(rec.attributes.get("is_invalid_user"))

    def test_05_and_06_ssh_session_opened_and_closed(self):
        """5 & 6. Verify SSH session open and close records."""
        line_open = "Sep 30 14:20:00 host sshd[1005]: pam_unix(sshd:session): session opened for user alice by (uid=0)"
        evt_open = parse_log_line(line_open, line_number=5, source_path="/var/log/auth.log")
        rec_open = log_event_to_auth_record(evt_open)
        self.assertEqual(rec_open.event_type, AuthEventType.SESSION_OPEN.value)
        self.assertEqual(rec_open.status, AuthStatus.SUCCESS.value)
        self.assertEqual(rec_open.username, "alice")

        line_close = "Sep 30 14:30:00 host sshd[1005]: pam_unix(sshd:session): session closed for user alice"
        evt_close = parse_log_line(line_close, line_number=6, source_path="/var/log/auth.log")
        rec_close = log_event_to_auth_record(evt_close)
        self.assertEqual(rec_close.event_type, AuthEventType.SESSION_CLOSE.value)
        self.assertEqual(rec_close.status, AuthStatus.INFO.value)
        self.assertEqual(rec_close.username, "alice")

    def test_07_sudo_command_activity(self):
        """7. Verify sudo command execution activity extraction."""
        line = "Sep 30 14:35:00 host sudo:   analyst : TTY=pts/2 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/ps aux"
        evt = parse_log_line(line, line_number=7, source_path="/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.SUDO_COMMAND.value)
        self.assertEqual(rec.status, AuthStatus.INFO.value)
        self.assertEqual(rec.username, "analyst")
        self.assertEqual(rec.attributes["sudo_user"], "analyst")
        self.assertEqual(rec.attributes["target_user"], "root")
        self.assertEqual(rec.attributes["tty"], "pts/2")
        self.assertEqual(rec.attributes["pwd"], "/home/analyst")
        self.assertEqual(rec.attributes["command"], "/bin/ps aux")

    def test_08_and_09_sudo_session_open_and_close(self):
        """8 & 9. Verify sudo pam session open and close."""
        line_open = "Sep 30 14:36:00 host sudo: pam_unix(sudo:session): session opened for user root by analyst(uid=1000)"
        evt_open = parse_log_line(line_open, line_number=8, source_path="/var/log/auth.log")
        rec_open = log_event_to_auth_record(evt_open)
        self.assertEqual(rec_open.event_type, AuthEventType.SESSION_OPEN.value)
        self.assertEqual(rec_open.status, AuthStatus.SUCCESS.value)
        self.assertEqual(rec_open.username, "root")

        line_close = "Sep 30 14:37:00 host sudo: pam_unix(sudo:session): session closed for user root"
        evt_close = parse_log_line(line_close, line_number=9, source_path="/var/log/auth.log")
        rec_close = log_event_to_auth_record(evt_close)
        self.assertEqual(rec_close.event_type, AuthEventType.SESSION_CLOSE.value)
        self.assertEqual(rec_close.status, AuthStatus.INFO.value)

    def test_10_multiple_authentication_events_in_one_log(self):
        """10. Verify aggregate extraction across multiple events."""
        log_file = self.workspace / "auth.log"
        content = (
            "Sep 30 10:00:00 host sshd[1]: Accepted password for u1 from 1.1.1.1 port 100\n"
            "Sep 30 10:01:00 host sshd[2]: Failed password for u2 from 2.2.2.2 port 200\n"
            "Sep 30 10:02:00 host sudo: u1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n"
        )
        log_file.write_text(content)

        result = extract_authentication_activity(log_file)
        self.assertEqual(result.total_records, 3)
        self.assertEqual(result.success_count, 1)
        self.assertEqual(result.failure_count, 1)
        self.assertEqual(result.summary["event_counts"][AuthEventType.SSH_LOGIN_SUCCESS.value], 1)
        self.assertEqual(result.summary["event_counts"][AuthEventType.SSH_LOGIN_FAILURE.value], 1)
        self.assertEqual(result.summary["event_counts"][AuthEventType.SUDO_COMMAND.value], 1)

    def test_11_12_and_13_traceability_preservation(self):
        """11, 12, 13. Verify source path, line number, and raw message preservation."""
        log_file = self.workspace / "trace.log"
        raw_msg = "Accepted password for auditor from 10.10.10.10 port 9999"
        line = f"Sep 30 12:00:00 myhost sshd[555]: {raw_msg}\n"
        log_file.write_text(line)

        result = extract_authentication_activity(log_file, artifact_id="ART-112233")
        self.assertEqual(result.total_records, 1)
        rec = result.records[0]

        self.assertEqual(rec.source_artifact_id, "ART-112233")
        self.assertEqual(rec.source_path, str(log_file.resolve()))
        self.assertEqual(rec.line_number, 1)
        self.assertIn("auditor", rec.raw_message)
        self.assertEqual(rec.raw_line, line.rstrip("\n"))

    def test_14_to_17_field_extractions(self):
        """14, 15, 16, 17. Verify accurate username, IP, port, and method extraction."""
        line = "Sep 30 13:00:00 srv sshd[999]: Accepted password for sysadmin from 192.168.100.25 port 48822"
        evt = parse_log_line(line, 1, "/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertEqual(rec.username, "sysadmin")
        self.assertEqual(rec.source_ip, "192.168.100.25")
        self.assertEqual(rec.source_port, 48822)
        self.assertEqual(rec.authentication_method, "password")

    def test_18_missing_optional_fields(self):
        """18. Verify missing optional fields are represented as None rather than invented."""
        # Generic auth failure without source port or auth method
        line = "Sep 30 13:05:00 srv login[100]: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty1 ruser= rhost= user=root"
        evt = parse_log_line(line, 1, "/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.AUTHENTICATION_FAILURE.value)
        self.assertEqual(rec.username, "root")
        self.assertIsNone(rec.source_port)
        self.assertIsNone(rec.authentication_method)

    def test_19_unknown_authentication_message(self):
        """19. Verify unrecognized message in auth.log is preserved as UNKNOWN_AUTH_EVENT."""
        line = "Sep 30 13:10:00 srv sshd[123]: Some future OpenSSH debug output that ForensiX does not have a pattern for"
        evt = parse_log_line(line, 1, "/var/log/auth.log")
        rec = log_event_to_auth_record(evt)

        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.UNKNOWN_AUTH_EVENT.value)
        self.assertEqual(rec.status, AuthStatus.UNKNOWN.value)
        self.assertIsNone(rec.username)

    def test_20_malformed_authentication_line(self):
        """20. Verify corrupted/malformed line in auth log does not halt extraction."""
        log_file = self.workspace / "corrupted_auth.log"
        content = (
            "::: complete garbage line :::\n"
            "Sep 30 13:15:00 srv sshd[1]: Accepted password for user1 from 1.1.1.1 port 22\n"
        )
        log_file.write_text(content)

        result = extract_authentication_activity(log_file)
        # 1 unknown auth event from line 1, 1 success from line 2
        self.assertEqual(result.total_records, 2)
        self.assertEqual(result.success_count, 1)
        self.assertEqual(result.unknown_count, 1)

    def test_21_invalid_utf8_input(self):
        """21. Verify invalid UTF-8 bytes are handled via replacement without exception."""
        log_file = self.workspace / "invalid_utf8.log"
        raw_bytes = b"Sep 30 13:20:00 srv sshd[1]: Failed password for \xff\xfe from 1.1.1.1 port 22\n"
        log_file.write_bytes(raw_bytes)

        result = extract_authentication_activity(log_file)
        self.assertEqual(result.total_records, 1)
        rec = result.records[0]
        self.assertEqual(rec.event_type, AuthEventType.SSH_LOGIN_FAILURE.value)
        self.assertIn("\ufffd", rec.username)

    def test_22_empty_authentication_log(self):
        """22. Verify empty authentication log returns clean 0-record result."""
        empty_log = self.workspace / "empty_auth.log"
        empty_log.touch()

        result = extract_authentication_activity(empty_log)
        self.assertEqual(result.total_records, 0)
        self.assertEqual(result.success_count, 0)
        self.assertEqual(result.failure_count, 0)
        self.assertEqual(len(result.records), 0)

    def test_23_large_log_streaming_behavior(self):
        """23. Verify memory-bounded generator processing across 1,000 log events."""
        log_file = self.workspace / "large_auth.log"
        num_lines = 1000
        with log_file.open("w", encoding="utf-8") as f:
            for i in range(num_lines):
                f.write(f"Sep 30 12:00:{i%60:02d} srv sshd[{i}]: Accepted password for user_{i} from 10.0.0.1 port {1000+i}\n")

        count = 0
        for rec in stream_authentication_activity(log_file):
            count += 1
            if count == 250:
                self.assertEqual(rec.username, "user_249")
                self.assertEqual(rec.line_number, 250)

        self.assertEqual(count, num_lines)

    def test_24_compressed_authentication_log(self):
        """24. Verify gzip-compressed log (.gz) extraction in memory."""
        gz_file = self.workspace / "auth.log.3.gz"
        content = "Sep 30 12:00:00 srv sshd[1]: Accepted publickey for dev from 10.0.0.1 port 22\n"
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write(content)

        result = extract_authentication_activity(gz_file)
        self.assertEqual(result.total_records, 1)
        self.assertEqual(result.records[0].username, "dev")
        self.assertEqual(result.records[0].authentication_method, "publickey")

    def test_25_evidence_immutability(self):
        """25. Verify authentication analysis leaves source file untouched."""
        log_file = self.workspace / "immutable_auth.log"
        content = "Sep 30 12:00:00 srv sshd[1]: Accepted password for root from 1.2.3.4 port 22\n"
        log_file.write_text(content)

        pre_hashes = compute_hashes(log_file)
        pre_stat = log_file.stat()

        _ = extract_authentication_activity(log_file)
        _ = list(stream_authentication_activity(log_file))

        post_hashes = compute_hashes(log_file)
        post_stat = log_file.stat()

        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(pre_hashes["md5"], post_hashes["md5"])
        self.assertEqual(pre_stat.st_size, post_stat.st_size)
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime)

    def test_26_deterministic_output(self):
        """26. Verify identical output across repeated runs."""
        log_file = self.workspace / "det_auth.log"
        log_file.write_text("Sep 30 12:00:00 srv sshd[1]: Accepted password for root from 1.2.3.4 port 22\n")

        res1 = extract_authentication_activity(log_file)
        res2 = extract_authentication_activity(log_file)

        self.assertEqual(res1.records[0].event_type, res2.records[0].event_type)
        self.assertEqual(res1.records[0].username, res2.records[0].username)
        self.assertEqual(res1.summary, res2.summary)


if __name__ == "__main__":
    unittest.main()
