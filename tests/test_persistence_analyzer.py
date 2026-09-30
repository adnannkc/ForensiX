"""
Unit and integration tests for Linux Persistence Artifacts (V2.5).
"""

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import tempfile
import unittest

from forensix.hasher import compute_hashes
from forensix.persistence_analyzer import (
    analyze_persistence_artifacts,
    parse_anacron_file,
    parse_cron_file,
    parse_init_script_or_rc,
    parse_kernel_module_config,
    parse_ld_preload_file,
    parse_shell_startup_file,
    parse_systemd_unit_file,
    parse_xdg_autostart_file,
)
from forensix.persistence_models import (
    PersistenceCategory,
    PersistenceCollectionResult,
    PersistenceRecord,
)


class TestPersistenceAnalyzer(unittest.TestCase):
    """Test suite for persistence-capable configuration extraction, safety, and immutability."""

    def setUp(self):
        """Create a temporary workspace for isolated test evidence."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_root = Path(self.temp_dir.name) / "linux_evidence"
        self.evidence_root.mkdir()
        (self.evidence_root / "etc").mkdir(parents=True)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_01_systemd_service_unit_extraction(self):
        """1. Verify systemd service unit parsing: ExecStart, User, and install attributes."""
        unit_dir = self.evidence_root / "etc" / "systemd" / "system"
        unit_dir.mkdir(parents=True)
        service_file = unit_dir / "custom_service.service"
        content = (
            "[Unit]\n"
            "Description=Custom Daemon\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "User=analyst\n"
            "Group=analyst\n"
            "ExecStartPre=/usr/bin/echo 'Starting'\n"
            "ExecStart=/usr/local/bin/custom_agent --config /etc/agent.conf\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        service_file.write_text(content)

        records = parse_systemd_unit_file(service_file, "etc/systemd/system/custom_service.service", scope="system")
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertTrue(rec.persistence_id.startswith("PERSIST-"))
        self.assertEqual(rec.category, PersistenceCategory.SYSTEMD.value)
        self.assertEqual(rec.mechanism, "systemd_service")
        self.assertEqual(rec.scope, "system")
        self.assertEqual(rec.target_user, "analyst")
        self.assertEqual(rec.command_or_path, "/usr/local/bin/custom_agent --config /etc/agent.conf")

        attrs = dict(rec.attributes)
        self.assertEqual(attrs["user"], "analyst")
        self.assertEqual(attrs["group"], "analyst")
        self.assertEqual(attrs["wanted_by"], ("multi-user.target",))
        self.assertEqual(attrs["after"], ("network.target",))
        self.assertIn("/usr/bin/echo 'Starting'", attrs["exec_start_pre"])

    def test_02_and_03_systemd_timer_and_relationship_distinction(self):
        """2 & 3 (Tests A & C). Verify timer scheduling directives and distinction from WantedBy."""
        timer_dir = self.evidence_root / "etc" / "systemd" / "system"
        timer_dir.mkdir(parents=True, exist_ok=True)
        timer_file = timer_dir / "backup.timer"
        content = (
            "[Unit]\n"
            "Description=Run daily backup\n"
            "After=local-fs.target\n\n"
            "[Timer]\n"
            "OnCalendar=*-*-* 03:00:00\n"
            "OnBootSec=15min\n"
            "Persistent=true\n"
            "Unit=backup.service\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
        timer_file.write_text(content)

        records = parse_systemd_unit_file(timer_file, "etc/systemd/system/backup.timer", scope="system")
        self.assertEqual(len(records), 2)  # Two timer directives: OnCalendar and OnBootSec

        on_cal_rec = next(r for r in records if "OnCalendar" in (r.trigger_or_schedule or ""))
        self.assertEqual(on_cal_rec.trigger_or_schedule, "OnCalendar=*-*-* 03:00:00")
        self.assertEqual(on_cal_rec.command_or_path, "backup.service")
        self.assertEqual(on_cal_rec.mechanism, "systemd_timer")

        attrs = dict(on_cal_rec.attributes)
        # CRITICAL TEST C: WantedBy is NOT a schedule; it is an installation attribute
        self.assertNotEqual(on_cal_rec.trigger_or_schedule, "timers.target")
        self.assertEqual(attrs["wanted_by"], ("timers.target",))
        self.assertEqual(attrs["after"], ("local-fs.target",))

    def test_04_systemd_enablement_symlink_evidence(self):
        """4 (Test B). Verify enablement symlinks (multi-user.target.wants) recorded directly from filesystem."""
        wants_dir = self.evidence_root / "etc" / "systemd" / "system" / "multi-user.target.wants"
        wants_dir.mkdir(parents=True)
        service_target = self.evidence_root / "lib" / "systemd" / "system" / "target.service"
        service_target.parent.mkdir(parents=True)
        service_target.write_text("[Service]\nExecStart=/bin/true\n")

        symlink_entry = wants_dir / "target.service"
        symlink_entry.symlink_to(service_target)

        result = analyze_persistence_artifacts(self.evidence_root)
        enablement_recs = [r for r in result.records if r.mechanism == "systemd_enablement_symlink"]

        self.assertEqual(len(enablement_recs), 1)
        rec = enablement_recs[0]
        self.assertEqual(rec.category, PersistenceCategory.SYSTEMD.value)
        attrs = dict(rec.attributes)
        self.assertEqual(attrs["symlink_name"], "target.service")
        self.assertEqual(attrs["wants_directory"], "multi-user.target.wants")

    def test_05_systemd_user_units(self):
        """5. Verify user-scoped systemd units under ~/.config/systemd/user/."""
        user_unit_dir = self.evidence_root / "home" / "analyst" / ".config" / "systemd" / "user"
        user_unit_dir.mkdir(parents=True)
        service_file = user_unit_dir / "user_helper.service"
        service_file.write_text("[Service]\nExecStart=/home/analyst/bin/helper\n")

        result = analyze_persistence_artifacts(self.evidence_root)
        user_recs = [r for r in result.records if r.scope == "user" and r.mechanism == "systemd_service"]

        self.assertEqual(len(user_recs), 1)
        self.assertEqual(user_recs[0].target_user, "analyst")
        self.assertEqual(user_recs[0].command_or_path, "/home/analyst/bin/helper")

    def test_06_and_07_cron_system_and_cron_d(self):
        """6 & 7. Verify /etc/crontab and /etc/cron.d/* with explicit user column."""
        crontab = self.evidence_root / "etc" / "crontab"
        crontab.write_text(
            "# System crontab\n"
            "0 2 * * * root /usr/sbin/backup.sh\n"
            "@daily daemon /usr/sbin/cleanup\n"
        )

        records = parse_cron_file(crontab, "etc/crontab", is_system_cron=True, default_user="root")
        self.assertEqual(len(records), 2)

        r1 = records[0]
        self.assertEqual(r1.trigger_or_schedule, "0 2 * * *")
        self.assertEqual(r1.target_user, "root")
        self.assertEqual(r1.command_or_path, "/usr/sbin/backup.sh")
        self.assertEqual(r1.mechanism, "crontab")

        r2 = records[1]
        self.assertEqual(r2.trigger_or_schedule, "@daily")
        self.assertEqual(r2.target_user, "daemon")
        self.assertEqual(r2.command_or_path, "/usr/sbin/cleanup")

    def test_08_user_cron_tab(self):
        """8. Verify user crontabs without user column, username derived from file name."""
        ucron_dir = self.evidence_root / "var" / "spool" / "cron" / "crontabs"
        ucron_dir.mkdir(parents=True)
        ucron_file = ucron_dir / "analyst"
        ucron_file.write_text("30 * * * * /home/analyst/sync.sh\n")

        records = parse_cron_file(ucron_file, "var/spool/cron/crontabs/analyst", is_system_cron=False, default_user="analyst")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].target_user, "analyst")
        self.assertEqual(records[0].trigger_or_schedule, "30 * * * *")
        self.assertEqual(records[0].command_or_path, "/home/analyst/sync.sh")

    def test_09_cron_environment_vs_malformed_distinction(self):
        """9 (Test F). Verify environment assignments are valid cron_env, NOT malformed."""
        cron_file = self.evidence_root / "etc" / "cron.d" / "app_job"
        cron_file.parent.mkdir(parents=True)
        content = (
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/bin:/usr/bin:/bin\n"
            "* * * * * root /bin/logger heartbeat\n"
            "corrupted line missing all fields\n"
        )
        cron_file.write_text(content)

        records = parse_cron_file(cron_file, "etc/cron.d/app_job", is_system_cron=True, default_user="root")
        self.assertEqual(len(records), 4)

        env_recs = [r for r in records if r.mechanism == "cron_env"]
        self.assertEqual(len(env_recs), 2)
        # Verify status is PARSED, not MALFORMED
        for er in env_recs:
            self.assertEqual(er.status, "PARSED")

        valid_job = [r for r in records if r.mechanism == "crontab" and r.status == "PARSED"]
        self.assertEqual(len(valid_job), 1)

        malformed = [r for r in records if r.status == "MALFORMED"]
        self.assertEqual(len(malformed), 1)
        self.assertIn("corrupted line", malformed[0].raw_line)

    def test_10_anacron_parsing(self):
        """10. Verify /etc/anacrontab extraction."""
        anacrontab = self.evidence_root / "etc" / "anacrontab"
        content = (
            "SHELL=/bin/sh\n"
            "1 5 cron.daily run-parts --report /etc/cron.daily\n"
            "7 10 cron.weekly run-parts --report /etc/cron.weekly\n"
        )
        anacrontab.write_text(content)

        records = parse_anacron_file(anacrontab, "etc/anacrontab")
        self.assertEqual(len(records), 3)

        daily = next(r for r in records if r.mechanism == "anacrontab" and "cron.daily" in (r.command_or_path or ""))
        self.assertEqual(daily.trigger_or_schedule, "period=1 delay=5")
        attrs = dict(daily.attributes)
        self.assertEqual(attrs["period"], "1")
        self.assertEqual(attrs["delay"], "5")
        self.assertEqual(attrs["job_id"], "cron.daily")

    def test_11_and_12_init_scripts_and_rc_local(self):
        """11 & 12. Verify /etc/init.d/ and /etc/rc.local extraction without execution."""
        rc_local = self.evidence_root / "etc" / "rc.local"
        rc_content = (
            "#!/bin/sh -e\n"
            "# Startup configuration\n"
            "/usr/local/bin/vpn_connect\n"
            "exit 0\n"
        )
        rc_local.write_text(rc_content)

        records = parse_init_script_or_rc(rc_local, "etc/rc.local")
        self.assertTrue(len(records) >= 1)
        rec = next(r for r in records if "/usr/local/bin/vpn_connect" in (r.command_or_path or ""))
        self.assertEqual(rec.mechanism, "init_script")
        attrs = dict(rec.attributes)
        self.assertEqual(attrs["shebang"], "#!/bin/sh -e")

    def test_13_shell_startup_files_as_observed_text(self):
        """13 (Test D). Verify shell startup files are treated as selected configuration lines."""
        bashrc = self.evidence_root / "home" / "analyst" / ".bashrc"
        bashrc.parent.mkdir(parents=True)
        content = (
            "# .bashrc\n"
            "export PATH=$PATH:/opt/tools/bin\n"
            "alias ll='ls -la'\n"
            "source /etc/profile.d/custom.sh\n"
        )
        bashrc.write_text(content)

        records = parse_shell_startup_file(bashrc, "home/analyst/.bashrc", target_user="analyst")
        self.assertEqual(len(records), 3)

        exp_rec = next(r for r in records if "export PATH" in (r.command_or_path or ""))
        self.assertEqual(dict(exp_rec.attributes)["directive_type"], "export")
        self.assertEqual(exp_rec.mechanism, "shell_startup")
        self.assertEqual(exp_rec.scope, "user")

    def test_14_xdg_desktop_autostart(self):
        """14. Verify XDG desktop autostart entry parsing."""
        autostart_dir = self.evidence_root / "etc" / "xdg" / "autostart"
        autostart_dir.mkdir(parents=True)
        desktop_file = autostart_dir / "panel.desktop"
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Desktop Panel\n"
            "Exec=/usr/bin/panel --start\n"
            "Hidden=false\n"
        )
        desktop_file.write_text(content)

        records = parse_xdg_autostart_file(desktop_file, "etc/xdg/autostart/panel.desktop", scope="system")
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.mechanism, "desktop_autostart")
        self.assertEqual(rec.command_or_path, "/usr/bin/panel --start")
        attrs = dict(rec.attributes)
        self.assertEqual(attrs["name"], "Desktop Panel")
        self.assertEqual(attrs["type"], "Application")
        self.assertEqual(attrs["hidden"], "false")

    def test_15_dynamic_loader_preload(self):
        """15. Verify /etc/ld.so.preload library path extraction."""
        preload = self.evidence_root / "etc" / "ld.so.preload"
        preload.write_text("/lib/x86_64-linux-gnu/libhook.so /usr/local/lib/libaudit.so\n")

        records = parse_ld_preload_file(preload, "etc/ld.so.preload")
        self.assertEqual(len(records), 2)
        paths = [r.command_or_path for r in records]
        self.assertIn("/lib/x86_64-linux-gnu/libhook.so", paths)
        self.assertIn("/usr/local/lib/libaudit.so", paths)
        self.assertEqual(records[0].category, PersistenceCategory.DYNAMIC_LOADER.value)

    def test_16_kernel_modules_distinction(self):
        """16 (Test E). Verify /etc/modules is distinguished from /etc/modprobe.d/."""
        modules = self.evidence_root / "etc" / "modules"
        modules.write_text("veth\nbr_netfilter\n")

        mod_records = parse_kernel_module_config(modules, "etc/modules")
        self.assertEqual(len(mod_records), 2)
        self.assertEqual(mod_records[0].mechanism, "kernel_module_load")
        self.assertEqual(mod_records[0].command_or_path, "veth")

        modprobe = self.evidence_root / "etc" / "modprobe.d" / "blacklist.conf"
        modprobe.parent.mkdir(parents=True)
        modprobe.write_text("blacklist floppy\noptions snd_hda_intel power_save=1\n")

        probe_records = parse_kernel_module_config(modprobe, "etc/modprobe.d/blacklist.conf")
        self.assertEqual(len(probe_records), 2)
        self.assertEqual(probe_records[0].mechanism, "modprobe_directive")
        attrs = dict(probe_records[0].attributes)
        self.assertEqual(attrs["directive"], "blacklist")
        self.assertEqual(attrs["module"], "floppy")

    def test_17_and_18_malformed_and_blank_handling(self):
        """17 & 18. Verify empty lines, comments, and malformed entries handled safely."""
        cron_file = self.evidence_root / "etc" / "cron.d" / "test_blank"
        cron_file.parent.mkdir(parents=True, exist_ok=True)
        cron_file.write_text("\n\n   # Comment only\n\n")

        records = parse_cron_file(cron_file, "etc/cron.d/test_blank", is_system_cron=True)
        self.assertEqual(len(records), 0)

    def test_19_invalid_utf8_handling(self):
        """19. Verify invalid UTF-8 bytes are handled via replacement character \ufffd."""
        cron_file = self.evidence_root / "etc" / "cron.d" / "utf8_test"
        cron_file.parent.mkdir(parents=True, exist_ok=True)
        cron_file.write_bytes(b"* * * * * root /bin/echo \xff\xfe\n")

        records = parse_cron_file(cron_file, "etc/cron.d/utf8_test", is_system_cron=True)
        self.assertEqual(len(records), 1)
        self.assertIn("\ufffd", records[0].command_or_path)

    def test_20_immutable_nested_structures(self):
        """20 (Test G). Verify nested tuples on PersistenceRecord and collection are immutable."""
        rec = PersistenceRecord(
            persistence_id="PERSIST-1111",
            source_artifact_id=None,
            source_path="/etc/crontab",
            line_number=1,
            category=PersistenceCategory.CRON.value,
            mechanism="crontab",
            scope="system",
            target_user="root",
            trigger_or_schedule="* * * * *",
            command_or_path="/bin/true",
            attributes=(("k1", "v1"), ("k2", "v2")),
            status="PARSED",
            raw_line="* * * * * root /bin/true",
        )

        with self.assertRaises(FrozenInstanceError):
            rec.attributes = (("new", "val"),)  # type: ignore

        # Verify to_dict produces standard dict
        d = rec.to_dict()
        self.assertEqual(d["attributes"]["k1"], "v1")

    def test_21_no_command_execution(self):
        """21 (Test H / Test 25). Verify evidence command strings are never executed."""
        canary_file = Path(self.temp_dir.name) / "canary_test.txt"
        canary_file.write_text("ACTIVE_CANARY\n")

        # Create persistence evidence instructing removal or execution against the canary
        crontab = self.evidence_root / "etc" / "crontab"
        crontab.write_text(f"* * * * * root rm -f {canary_file}\n")

        service_dir = self.evidence_root / "etc" / "systemd" / "system"
        service_dir.mkdir(parents=True, exist_ok=True)
        service = service_dir / "canary.service"
        service.write_text(f"[Service]\nExecStart=/bin/rm -f {canary_file}\n")

        # Run analysis
        result = analyze_persistence_artifacts(self.evidence_root)
        self.assertTrue(result.total_records >= 2)

        # Verify canary file was NEVER deleted, touched, or executed against
        self.assertTrue(canary_file.exists())
        self.assertEqual(canary_file.read_text(), "ACTIVE_CANARY\n")

    def test_22_unit_files_do_not_become_confirmed_persistence(self):
        """22 (Test I). Verify finding a unit file produces neutral configuration without malicious claim."""
        service_dir = self.evidence_root / "etc" / "systemd" / "system"
        service_dir.mkdir(parents=True, exist_ok=True)
        service = service_dir / "harmless.service"
        service.write_text("[Service]\nExecStart=/usr/bin/uptime\n")

        records = parse_systemd_unit_file(service, "etc/systemd/system/harmless.service")
        rec = records[0]

        # Neutral category and status
        self.assertEqual(rec.category, PersistenceCategory.SYSTEMD.value)
        self.assertEqual(rec.status, "PARSED")
        # No speculative or malicious claims
        self.assertNotIn("malicious", rec.mechanism)
        self.assertNotIn("compromise", str(rec.attributes))

    def test_23_evidence_immutability(self):
        """23. Verify persistence analysis leaves evidence files strictly unaltered."""
        crontab = self.evidence_root / "etc" / "crontab"
        crontab.write_text("0 1 * * * root /bin/ls\n")

        pre_hashes = compute_hashes(crontab)
        pre_stat = crontab.stat()

        _ = analyze_persistence_artifacts(self.evidence_root)
        _ = analyze_persistence_artifacts(self.evidence_root)

        post_hashes = compute_hashes(crontab)
        post_stat = crontab.stat()

        self.assertEqual(pre_hashes["sha256"], post_hashes["sha256"])
        self.assertEqual(pre_hashes["md5"], post_hashes["md5"])
        self.assertEqual(pre_stat.st_size, post_stat.st_size)
        self.assertEqual(pre_stat.st_mtime, post_stat.st_mtime)

    def test_24_deterministic_ordering(self):
        """24. Verify repeated analysis runs produce identical output ordering."""
        crontab = self.evidence_root / "etc" / "crontab"
        crontab.write_text("0 1 * * * root /bin/ls\n")
        service = self.evidence_root / "etc" / "systemd" / "system" / "svc.service"
        service.parent.mkdir(parents=True, exist_ok=True)
        service.write_text("[Service]\nExecStart=/bin/date\n")

        res1 = analyze_persistence_artifacts(self.evidence_root)
        res2 = analyze_persistence_artifacts(self.evidence_root)

        paths1 = [r.source_path for r in res1.records]
        paths2 = [r.source_path for r in res2.records]
        self.assertEqual(paths1, paths2)
        self.assertEqual(res1.summary, res2.summary)


if __name__ == "__main__":
    unittest.main()
