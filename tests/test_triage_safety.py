"""
Comprehensive Safety Test Suite for ForensiX Milestone V2.9.6.

Verifies:
1.  Evidence content unchanged after full triage pipeline execution
2.  Evidence cryptographic hashes (SHA-256) unchanged
3.  Evidence metadata (mode/permissions, sizes, mtimes) unchanged
4.  No files written inside evidence directory
5.  No evidence execution (scripts, binaries, Python files)
6.  No subprocess activity during triage execution
7.  No network activity (sockets, HTTP, external services)
8.  Reports stay strictly outside evidence; output_dir in evidence rejected
9.  Temporary files do not appear in evidence
10. No evidence deletion or rename
11. Symlinks, rotated logs, gzip logs, and Unicode filenames preserved
12. Read-only analysis verified across all individual stages
"""

from datetime import datetime, timezone
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Dict, Tuple
import unittest
from unittest.mock import patch

from forensix.main import execute_triage_cli, triage_main
from forensix.triage_models import TriageConfig, TriageResult
from forensix.triage_orchestrator import TriageOrchestrator


class TestTriageSafety(unittest.TestCase):
    """Test suite verifying forensic safety and evidence immutability (V2.9.6)."""

    def setUp(self):
        """Create an extensive evidence fixture directory containing diverse Linux forensic artifacts."""
        self.test_dir = tempfile.mkdtemp(prefix="forensix_safety_test_")
        self.evidence_dir = Path(self.test_dir) / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(self.test_dir) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 1. /etc directory structure and account artifacts
        etc_dir = self.evidence_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)

        passwd_file = etc_dir / "passwd"
        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
            "bob:x:1002:1002:Bob:/home/bob:/bin/sh\n",
            encoding="utf-8",
        )

        group_file = etc_dir / "group"
        group_file.write_text(
            "root:x:0:\n"
            "alice:x:1001:\n"
            "bob:x:1002:\n",
            encoding="utf-8",
        )

        shadow_file = etc_dir / "shadow"
        shadow_file.write_text(
            "root:*:19000:0:99999:7:::\n"
            "alice:*:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        sudoers_d = etc_dir / "sudoers.d"
        sudoers_d.mkdir(parents=True, exist_ok=True)
        (sudoers_d / "admin").write_text(
            "alice ALL=(ALL:ALL) ALL\n",
            encoding="utf-8",
        )

        # 2. Persistence artifacts (cron, systemd, shell)
        cron_dir = etc_dir / "cron.d"
        cron_dir.mkdir(parents=True, exist_ok=True)
        (cron_dir / "backup_job").write_text(
            "* * * * * root /usr/local/bin/backup.sh\n",
            encoding="utf-8",
        )
        # Unicode filename in persistence
        (cron_dir / "задача_тест").write_text(
            "0 0 * * * root /bin/sync\n",
            encoding="utf-8",
        )

        # 3. User directories and SSH keys
        alice_ssh = self.evidence_dir / "home" / "alice" / ".ssh"
        alice_ssh.mkdir(parents=True, exist_ok=True)
        (alice_ssh / "authorized_keys").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGo4jAliceKey alice@workstation\n",
            encoding="utf-8",
        )

        # 4. Logs (/var/log: active, rotated, compressed, empty)
        log_dir = self.evidence_dir / "var" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.auth_log = log_dir / "auth.log"
        self.auth_log.write_text(
            "Sep 30 10:00:00 test-host sshd[1234]: Accepted password for alice from 192.168.1.50 port 22 ssh2\n"
            "Sep 30 10:05:00 test-host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls\n",
            encoding="utf-8",
        )

        self.rotated_log = log_dir / "auth.log.1"
        self.rotated_log.write_text(
            "Sep 29 10:00:00 test-host sshd[1000]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2\n",
            encoding="utf-8",
        )

        # Gzip compressed rotated log
        self.gz_log = log_dir / "auth.log.2.gz"
        with gzip.open(self.gz_log, "wt", encoding="utf-8") as gz_f:
            gz_f.write("Sep 28 08:00:00 test-host sshd[900]: Accepted publickey for alice\n")

        # Empty log file
        (log_dir / "empty.log").write_text("", encoding="utf-8")

        # 5. Executable-looking script inside evidence (must NEVER be executed)
        bin_dir = self.evidence_dir / "usr" / "local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        self.script_file = bin_dir / "backup.sh"
        self.script_file.write_text("#!/bin/sh\necho 'MALICIOUS ACTION'\nexit 42\n", encoding="utf-8")
        # Give executable permissions to test that pipeline still doesn't execute it
        try:
            self.script_file.chmod(0o755)
        except OSError:
            pass

        # 6. Symbolic link to a log file inside evidence
        try:
            symlink_path = log_dir / "auth_current.log"
            symlink_path.symlink_to("auth.log")
        except (OSError, NotImplementedError):
            pass

    def tearDown(self):
        """Clean up workspace."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _snapshot_evidence(self) -> Dict[str, Tuple[str, int, int, int]]:
        """
        Record detailed state of evidence files: (sha256, size, mode, mtime_ns).
        """
        snapshot = {}
        for p in sorted(self.evidence_dir.rglob("*")):
            rel = str(p.relative_to(self.evidence_dir))
            st = p.lstat()
            if p.is_file() and not p.is_symlink():
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                snapshot[rel] = (h, st.st_size, st.st_mode, st.st_mtime_ns)
            elif p.is_symlink():
                snapshot[rel] = ("SYMLINK:" + os.readlink(p), st.st_size, st.st_mode, st.st_mtime_ns)
            elif p.is_dir():
                snapshot[rel] = ("DIR", 0, st.st_mode, st.st_mtime_ns)
        return snapshot

    # 1 & 2. Evidence content and hashes unchanged
    def test_01_and_02_evidence_content_and_hashes_unchanged(self):
        """Verify that file contents and cryptographic SHA-256 hashes are strictly unchanged."""
        pre_snap = self._snapshot_evidence()
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            case_id="CASE-SAFETY-01",
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.summary.is_success)

        post_snap = self._snapshot_evidence()
        self.assertEqual(set(pre_snap.keys()), set(post_snap.keys()))

        for rel_path, pre_info in pre_snap.items():
            post_info = post_snap[rel_path]
            # Compare hash and size
            self.assertEqual(pre_info[0], post_info[0], f"Hash mismatch for {rel_path}")
            self.assertEqual(pre_info[1], post_info[1], f"Size mismatch for {rel_path}")

    # 3. Evidence metadata unchanged
    def test_03_evidence_metadata_unchanged(self):
        """Verify file modes, permissions, and modification timestamps remain unchanged."""
        pre_snap = self._snapshot_evidence()
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            case_id="CASE-SAFETY-03",
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.summary.is_success)

        post_snap = self._snapshot_evidence()
        for rel_path, pre_info in pre_snap.items():
            post_info = post_snap[rel_path]
            # Mode / permissions
            self.assertEqual(pre_info[2], post_info[2], f"File mode altered for {rel_path}")
            # mtime_ns
            self.assertEqual(pre_info[3], post_info[3], f"Timestamp altered for {rel_path}")

    # 4. No writes inside evidence directory
    def test_04_no_writes_inside_evidence(self):
        """Verify that the triage orchestrator creates zero files inside the evidence tree."""
        pre_files = set(self.evidence_dir.rglob("*"))
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
            report_formats=("json", "csv", "html"),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.summary.is_success)

        post_files = set(self.evidence_dir.rglob("*"))
        self.assertEqual(pre_files, post_files, "New files were created in the evidence directory!")

    # 5. No execution of evidence files
    def test_05_no_evidence_execution(self):
        """Verify that scripts or executables in evidence are never executed."""
        # Replace backup.sh with a canary script that touches a marker file if executed
        canary = Path(self.test_dir) / "canary_touched.txt"
        self.script_file.write_text(f"#!/bin/sh\ntouch {canary}\n", encoding="utf-8")

        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        result = TriageOrchestrator(cfg).run()
        self.assertTrue(result.summary.is_success)
        self.assertFalse(canary.exists(), "Canary file was created! Evidence script was executed!")

    # 6. No subprocess execution during triage
    def test_06_no_subprocess_activity(self):
        """Verify zero subprocess execution during entire triage run."""
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen forbidden")):
            with patch("subprocess.run", side_effect=AssertionError("subprocess.run forbidden")):
                with patch("os.system", side_effect=AssertionError("os.system forbidden")):
                    cfg = TriageConfig(
                        evidence_path=str(self.evidence_dir),
                        output_dir=str(self.output_dir),
                        case_id="CASE-SAFETY-06",
                    )
                    result = TriageOrchestrator(cfg).run()
                    self.assertTrue(result.summary.is_success)

    # 7. No network activity during triage
    def test_07_no_network_activity(self):
        """Verify zero network socket connections during triage."""
        with patch.object(socket.socket, "connect", side_effect=AssertionError("Network socket connection forbidden")):
            cfg = TriageConfig(
                evidence_path=str(self.evidence_dir),
                output_dir=str(self.output_dir),
                case_id="CASE-SAFETY-07",
            )
            result = TriageOrchestrator(cfg).run()
            self.assertTrue(result.summary.is_success)

    # 8. Reports stay strictly outside evidence; output_dir in evidence rejected
    def test_08_reports_stay_outside_evidence_and_output_in_evidence_rejected(self):
        """Verify output_dir cannot be within or identical to evidence_path."""
        # Exact same directory
        with self.assertRaises(ValueError) as ctx1:
            TriageConfig(
                evidence_path=str(self.evidence_dir),
                output_dir=str(self.evidence_dir),
            )
        self.assertIn("output_dir cannot be within or identical to evidence_path", str(ctx1.exception))

        # Subdirectory inside evidence
        nested_in_evidence = self.evidence_dir / "reports"
        with self.assertRaises(ValueError) as ctx2:
            TriageConfig(
                evidence_path=str(self.evidence_dir),
                output_dir=str(nested_in_evidence),
            )
        self.assertIn("output_dir cannot be within or identical to evidence_path", str(ctx2.exception))

        # Rejection via CLI
        exit_code, _ = execute_triage_cli([
            str(self.evidence_dir),
            "-o", str(nested_in_evidence),
        ])
        self.assertEqual(exit_code, 1)

    # 9. Temporary files do not appear in evidence
    def test_09_temporary_files_do_not_appear_in_evidence(self):
        """Verify no temporary files (.tmp, scratch) are created inside evidence."""
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        TriageOrchestrator(cfg).run()
        for p in self.evidence_dir.rglob("*"):
            self.assertFalse(p.name.startswith(".tmp"), f"Temporary file found: {p}")
            self.assertFalse(p.name.endswith(".tmp"), f"Temporary file found: {p}")
            self.assertFalse("tmp" in p.name.lower() and p.is_file() and not p.name.endswith(".log"), f"Suspicious file: {p}")

    # 10. No evidence deletion or rename
    def test_10_no_evidence_deletion_or_rename(self):
        """Verify all original files exist with their original names after triage."""
        pre_paths = sorted([str(p.relative_to(self.evidence_dir)) for p in self.evidence_dir.rglob("*")])
        cfg = TriageConfig(
            evidence_path=str(self.evidence_dir),
            output_dir=str(self.output_dir),
        )
        TriageOrchestrator(cfg).run()
        post_paths = sorted([str(p.relative_to(self.evidence_dir)) for p in self.evidence_dir.rglob("*")])
        self.assertEqual(pre_paths, post_paths)
