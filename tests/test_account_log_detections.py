"""Tests for log-based detection of account creation, modification, password changes, and SSH keys."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from forensix.account_rules import (
    RULE_NAME_PASSWORD_CHANGED,
    RULE_NAME_SSH_KEYS_ACTIVITY,
    RULE_NAME_USER_ADDED,
    RULE_NAME_USER_MODIFIED,
    SSH_KEY_MODIFIED_EXPLANATION,
    SSH_KEY_REFERENCED_EXPLANATION,
    create_canonical_account_rules,
)
from forensix.auth_analyzer import extract_authentication_activity, log_event_to_auth_record
from forensix.auth_models import AuthEventType, AuthStatus
from forensix.case_config import CaseConfig
from forensix.detection_engine import DetectionEngine
from forensix.initial_rules import create_initial_rules
from forensix.log_models import LogEventType
from forensix.log_parser import parse_log_file, parse_log_line
from forensix.pipeline_engine import EXIT_SUCCESS, run_pipeline


class TestAccountAndSshKeyLogDetection(unittest.TestCase):
    """Verify parsing, auth classification, rules, reporting, and dashboard output."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.repo_root = Path(__file__).resolve().parent.parent

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_useradd_and_adduser_parsing(self):
        line1 = (
            "Sep 30 14:10:00 srv useradd[101]: new user: name=backdoor, "
            "UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash"
        )
        evt1 = parse_log_line(line1, line_number=14, source_path="/var/log/auth.log")
        self.assertEqual(evt1.event_type, LogEventType.USER_ADDED.value)
        self.assertEqual(evt1.attributes["user"], "backdoor")
        self.assertEqual(evt1.attributes["uid"], 1005)
        self.assertEqual(evt1.attributes["gid"], 1005)
        self.assertEqual(evt1.attributes["home"], "/home/backdoor")
        self.assertEqual(evt1.attributes["shell"], "/bin/bash")
        self.assertEqual(evt1.attributes["action"], "create_user")
        self.assertEqual(evt1.attributes["line_number"], 14)

        line2 = "Sep 30 14:11:00 srv adduser[102]: Adding user 'helper' (1006) with group 'sudo'"
        evt2 = parse_log_line(line2, line_number=15, source_path="/var/log/auth.log")
        self.assertEqual(evt2.event_type, LogEventType.USER_ADDED.value)
        self.assertEqual(evt2.attributes["user"], "helper")
        self.assertEqual(evt2.attributes["uid"], 1006)
        self.assertEqual(evt2.attributes["group"], "sudo")
        self.assertEqual(evt2.attributes["action"], "create_user")
        self.assertEqual(evt2.attributes["line_number"], 15)

    def test_usermod_parsing(self):
        grp_line = "Sep 30 14:12:00 srv usermod[201]: add 'alice' to group 'sudo'"
        evt_grp = parse_log_line(grp_line, line_number=21, source_path="/var/log/auth.log")
        self.assertEqual(evt_grp.event_type, LogEventType.USER_MODIFIED.value)
        self.assertEqual(evt_grp.attributes["user"], "alice")
        self.assertEqual(evt_grp.attributes["group"], "sudo")
        self.assertEqual(evt_grp.attributes["action"], "add_to_group")
        self.assertEqual(evt_grp.attributes["line_number"], 21)

        shell_line = "Sep 30 14:13:00 srv usermod[202]: change user 'alice' shell from '/bin/sh' to '/bin/bash'"
        evt_shell = parse_log_line(shell_line, line_number=22, source_path="/var/log/auth.log")
        self.assertEqual(evt_shell.event_type, LogEventType.USER_MODIFIED.value)
        self.assertEqual(evt_shell.attributes["user"], "alice")
        self.assertEqual(evt_shell.attributes["shell"], "/bin/bash")
        self.assertEqual(evt_shell.attributes["action"], "change_shell")
        self.assertEqual(evt_shell.attributes["line_number"], 22)

        lock_line = "Sep 30 14:14:00 srv usermod[203]: lock user 'alice' password"
        evt_lock = parse_log_line(lock_line, line_number=23, source_path="/var/log/auth.log")
        self.assertEqual(evt_lock.event_type, LogEventType.USER_MODIFIED.value)
        self.assertEqual(evt_lock.attributes["user"], "alice")
        self.assertEqual(evt_lock.attributes["action"], "lock_password")
        self.assertEqual(evt_lock.attributes["line_number"], 23)

    def test_passwd_and_chpasswd_parsing(self):
        pam_line = "Sep 30 14:15:00 srv passwd[301]: pam_unix(passwd:chauthtok): password changed for bob"
        evt1 = parse_log_line(pam_line, line_number=31, source_path="/var/log/auth.log")
        self.assertEqual(evt1.event_type, LogEventType.PASSWORD_CHANGED.value)
        self.assertEqual(evt1.attributes["user"], "bob")
        self.assertEqual(evt1.attributes["action"], "password_changed")
        self.assertEqual(evt1.attributes["line_number"], 31)

        shadow_line = "Sep 30 14:16:00 srv chpasswd[302]: password for 'charlie' changed by 'root'"
        evt2 = parse_log_line(shadow_line, line_number=32, source_path="/var/log/auth.log")
        self.assertEqual(evt2.event_type, LogEventType.PASSWORD_CHANGED.value)
        self.assertEqual(evt2.attributes["user"], "charlie")
        self.assertEqual(evt2.attributes["changed_by"], "root")
        self.assertEqual(evt2.attributes["line_number"], 32)

    def test_authorized_keys_sudo_and_syslog_key_actions(self):
        sudo_read = (
            "Sep 30 14:17:00 srv sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; "
            "USER=root ; COMMAND=/bin/cat /root/.ssh/authorized_keys"
        )
        evt_sudo_read = parse_log_line(sudo_read, line_number=41, source_path="/var/log/auth.log")
        self.assertEqual(evt_sudo_read.event_type, LogEventType.SUDO_COMMAND.value)
        self.assertTrue(evt_sudo_read.attributes["references_authorized_keys"])
        self.assertEqual(evt_sudo_read.attributes["key_action"], "referenced")
        self.assertEqual(evt_sudo_read.attributes["user"], "root")
        self.assertEqual(evt_sudo_read.attributes["line_number"], 41)

        sudo_mod = (
            "Sep 30 14:18:00 srv sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; "
            "USER=root ; COMMAND=/usr/bin/python3 -c modify /home/deploy/.ssh/authorized_keys"
        )
        evt_sudo_mod = parse_log_line(sudo_mod, line_number=42, source_path="/var/log/auth.log")
        self.assertEqual(evt_sudo_mod.event_type, LogEventType.SUDO_COMMAND.value)
        self.assertTrue(evt_sudo_mod.attributes["references_authorized_keys"])
        self.assertEqual(evt_sudo_mod.attributes["key_action"], "modified")
        self.assertEqual(evt_sudo_mod.attributes["user"], "deploy")
        self.assertEqual(evt_sudo_mod.attributes["line_number"], 42)

        sys_mod = "Sep 30 14:19:00 srv audit[401]: added key to /home/alice/.ssh/authorized_keys"
        evt_sys_mod = parse_log_line(sys_mod, line_number=43, source_path="/var/log/auth.log")
        self.assertEqual(evt_sys_mod.event_type, LogEventType.SSH_KEY_MODIFIED.value)
        self.assertEqual(evt_sys_mod.attributes["key_action"], "modified")
        self.assertEqual(evt_sys_mod.attributes["user"], "alice")
        self.assertEqual(evt_sys_mod.attributes["line_number"], 43)

        sys_ref = "Sep 30 14:20:00 srv sshd[402]: inspecting /home/alice/.ssh/authorized_keys"
        evt_sys_ref = parse_log_line(sys_ref, line_number=44, source_path="/var/log/auth.log")
        self.assertEqual(evt_sys_ref.event_type, LogEventType.SSH_KEY_MODIFIED.value)
        self.assertEqual(evt_sys_ref.attributes["key_action"], "referenced")
        self.assertEqual(evt_sys_ref.attributes["user"], "alice")
        self.assertEqual(evt_sys_ref.attributes["line_number"], 44)

    def test_auth_analyzer_avoids_unknown_auth_event(self):
        log_file = self.workspace / "auth.log"
        log_file.write_text(
            "\n".join(
                [
                    "Sep 30 14:10:00 srv useradd[101]: new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash",
                    "Sep 30 14:12:00 srv usermod[201]: add 'backdoor' to group 'sudo'",
                    "Sep 30 14:15:00 srv passwd[301]: pam_unix(passwd:chauthtok): password changed for backdoor",
                    "Sep 30 14:19:00 srv logger[401]: added key to /home/backdoor/.ssh/authorized_keys",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        auth_res = extract_authentication_activity(log_file)
        self.assertEqual(auth_res.total_records, 4)
        self.assertEqual(auth_res.unknown_count, 0)
        types = [r.event_type for r in auth_res.records]
        self.assertEqual(
            types,
            [
                AuthEventType.USER_ADDED.value,
                AuthEventType.USER_MODIFIED.value,
                AuthEventType.PASSWORD_CHANGED.value,
                AuthEventType.SSH_KEY_MODIFIED.value,
            ],
        )
        for rec in auth_res.records:
            self.assertEqual(rec.status, AuthStatus.INFO.value)
            self.assertEqual(rec.username, "backdoor")

        # Sanity check direct log_event_to_auth_record conversion
        single = parse_log_line(
            "Sep 30 14:21:00 srv sshd[402]: checking /root/.ssh/authorized_keys",
            line_number=5,
            source_path=str(log_file),
        )
        rec = log_event_to_auth_record(single)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.event_type, AuthEventType.SSH_KEY_MODIFIED.value)
        self.assertNotEqual(rec.event_type, AuthEventType.UNKNOWN_AUTH_EVENT.value)

    def test_initial_rules_still_four_and_account_rules_four(self):
        self.assertEqual(len(create_initial_rules()), 4)
        account_rules = create_canonical_account_rules()
        self.assertEqual(len(account_rules), 4)
        self.assertEqual(
            {r.name for r in account_rules},
            {
                RULE_NAME_USER_ADDED,
                RULE_NAME_USER_MODIFIED,
                RULE_NAME_PASSWORD_CHANGED,
                RULE_NAME_SSH_KEYS_ACTIVITY,
            },
        )

    def test_end_to_end_pipeline_report_and_dashboard_findings(self):
        ev_dir = self.workspace / "evidence_host"
        log_dir = ev_dir / "var" / "log"
        log_dir.mkdir(parents=True)
        auth_log = log_dir / "auth.log"
        auth_log.write_text(
            "\n".join(
                [
                    "Sep 30 14:10:00 srv useradd[101]: new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash",
                    "Sep 30 14:12:00 srv usermod[201]: add 'backdoor' to group 'sudo'",
                    "Sep 30 14:15:00 srv passwd[301]: pam_unix(passwd:chauthtok): password changed for backdoor",
                    "Sep 30 14:17:00 srv sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /root/.ssh/authorized_keys",
                    "Sep 30 14:18:00 srv logger[401]: append key to /home/backdoor/.ssh/authorized_keys",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        out_dir = self.workspace / "reports"
        cfg = CaseConfig(
            case_id="CASE-ACCT-001",
            case_name="Account Log Detections",
            investigator="Tester",
            evidence_host_dir=ev_dir,
            output_dir=out_dir,
            report_formats=("json", "html"),
            log_year=2026,
        )
        res = run_pipeline(cfg)
        self.assertEqual(res.exit_code, EXIT_SUCCESS)

        json_report_path = next(p for p in res.output_files if p.suffix == ".json" and p.name.startswith("report_"))
        html_report_path = next(p for p in res.output_files if p.suffix == ".html" and p.name.startswith("report_"))

        raw_report = json.loads(json_report_path.read_text(encoding="utf-8"))
        detections = raw_report["details"]["detections"]
        self.assertEqual(len(detections), 5)

        by_line = {d["line_number"]: d for d in detections}
        self.assertEqual(set(by_line.keys()), {1, 2, 3, 4, 5})

        self.assertEqual(by_line[1]["rule_name"], RULE_NAME_USER_ADDED)
        self.assertEqual(by_line[2]["rule_name"], RULE_NAME_USER_MODIFIED)
        self.assertEqual(by_line[3]["rule_name"], RULE_NAME_PASSWORD_CHANGED)
        self.assertEqual(by_line[4]["rule_name"], RULE_NAME_SSH_KEYS_ACTIVITY)
        self.assertEqual(by_line[5]["rule_name"], RULE_NAME_SSH_KEYS_ACTIVITY)

        # Referenced vs modified wording check
        self.assertEqual(by_line[4]["explanation"], SSH_KEY_REFERENCED_EXPLANATION)
        self.assertNotIn("modified", by_line[4]["explanation"].lower())
        self.assertEqual(by_line[5]["explanation"], SSH_KEY_MODIFIED_EXPLANATION)

        for line_no, det in by_line.items():
            self.assertEqual(det["source_file"], "var/log/auth.log")
            self.assertEqual(det["line_number"], line_no)
            self.assertTrue(det["matched_event_ids"])

        # HTML report renders rule name, explanation, matched event ID, source file, and line number
        html_text = html_report_path.read_text(encoding="utf-8")
        self.assertIn("Matched Detections", html_text)
        self.assertIn(RULE_NAME_USER_ADDED, html_text)
        self.assertIn(SSH_KEY_REFERENCED_EXPLANATION, html_text)
        self.assertIn(SSH_KEY_MODIFIED_EXPLANATION, html_text)
        self.assertIn("var/log/auth.log", html_text)
        self.assertIn(by_line[1]["matched_event_ids"][0], html_text)

        # Dashboard renderSummaryTab displays detections in #summary-detections-container
        node_bin = shutil.which("node")
        if node_bin:
            js_path = self.repo_root / "src" / "forensix" / "ui" / "dashboard.js"
            report_summary = {
                "id": raw_report["report_id"],
                "report_type": "schema_8_0",
                "counts": {
                    "artifact_count": raw_report["findings_summary"]["total_host_artifacts"],
                    "event_count": raw_report["findings_summary"]["total_timeline_events"],
                    "correlation_count": raw_report["findings_summary"]["total_correlations"],
                    "detection_count": raw_report["findings_summary"]["total_rule_evaluations"],
                    "matched_detection_count": raw_report["findings_summary"]["matched_detections"],
                    "audit_event_count": 0,
                },
            }
            script = f"""
const fs = require('fs');
const vm = require('vm');
const jsCode = fs.readFileSync({json.dumps(str(js_path))}, 'utf8');
const elements = new Map();
function createMockElement(tag, id) {{
  const el = {{
    tagName: String(tag || 'div').toUpperCase(),
    id: id || '',
    children: [],
    className: '',
    textContent: '',
    classList: {{ add() {{}}, remove() {{}}, toggle() {{ return false; }} }},
    setAttribute() {{}},
    getAttribute() {{ return null; }},
    addEventListener() {{}},
    appendChild(child) {{ this.children.push(child); return child; }}
  }};
  if (id) elements.set(id, el);
  return el;
}}
function collectText(node) {{
  if (!node) return '';
  let out = node.textContent ? String(node.textContent) : '';
  if (Array.isArray(node.children)) {{
    out += ' ' + node.children.map(collectText).join(' ');
  }}
  return out;
}}
['summary-counts-grid', 'summary-detections-container'].forEach(id => createMockElement('div', id));
const sandbox = {{
  document: {{
    readyState: 'complete',
    getElementById(id) {{
      if (!elements.has(id)) elements.set(id, createMockElement('div', id));
      return elements.get(id);
    }},
    createElement: (tag) => createMockElement(tag),
    createTextNode: (t) => ({{ textContent: String(t) }}),
    querySelectorAll: () => []
  }},
  window: {{ location: {{ hash: '' }}, addEventListener() {{}} }},
  console,
  fetch: () => Promise.resolve({{ ok: true, json: () => Promise.resolve({{}}) }}),
  setTimeout: () => {{}},
  clearTimeout: () => {{}}
}};
const injected = jsCode.replace(
  'window.addEventListener("hashchange", handleHashRoute);',
  'window.__renderSummaryTab = renderSummaryTab; window.addEventListener("hashchange", handleHashRoute);'
);
vm.runInNewContext(injected, sandbox);
sandbox.window.__renderSummaryTab({json.dumps(report_summary)}, {json.dumps(raw_report)});
console.log(collectText(elements.get('summary-detections-container')));
"""
            proc = subprocess.run([node_bin, "-e", script], capture_output=True, text=True, check=True)
            rendered = proc.stdout
            self.assertIn("Matched Detections", rendered)
            self.assertIn(RULE_NAME_USER_ADDED, rendered)
            self.assertIn(SSH_KEY_REFERENCED_EXPLANATION, rendered)
            self.assertIn(SSH_KEY_MODIFIED_EXPLANATION, rendered)
            self.assertIn("var/log/auth.log", rendered)
            self.assertIn(by_line[1]["matched_event_ids"][0], rendered)


if __name__ == "__main__":
    unittest.main()

