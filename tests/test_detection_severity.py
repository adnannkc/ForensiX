"""Tests for detection severity levels, sorting, and per-severity counts."""

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from forensix.account_rules import create_canonical_account_rules
from forensix.advanced_report_builder import build_advanced_report, render_advanced_report_html
from forensix.advanced_report_models import FindingsSummary
from forensix.case_config import load_case_config_from_file
from forensix.detection_engine import DetectionEngine, DetectionResult
from forensix.initial_rules import create_initial_rules
from forensix.memory_rules import create_canonical_memory_rules
from forensix.network_rules import create_canonical_network_rules
from forensix.pipeline_engine import EXIT_SUCCESS, run_pipeline
from forensix.rule_models import DetectionRule, create_rule
from forensix.timeline_models import TimelineCategory, TimelineEvent


EXPECTED_SEVERITIES = {
    "Persistence Modification Following Authentication or Privilege": "critical",
    "Account Activity Followed by Privilege Activity": "critical",
    "New User Account Created (Log)": "high",
    "SSH Authorized Keys Referenced or Modified": "high",
    "Repeated Failed SSH Attempts Followed by Successful SSH Login": "high",
    "Baseline Memory Driver Path Review Indicator (/tmp)": "high",
    "Baseline Memory Listening Port Observation (TCP/4444)": "high",
    "SSH Authentication Followed by Sudo": "medium",
    "Account Password Changed (Log)": "medium",
    "User Account Modified (Log)": "medium",
    "Baseline Memory Process Name Observation (nc)": "medium",
    "Baseline Memory Process Network Socket Correlation": "medium",
    "Baseline Host and Network Correlation Observation": "medium",
    "Baseline SSH Network Port Observation": "low",
    "Baseline DNS Query Domain Observation": "low",
    "Baseline HTTP Request Observation": "low",
    "Baseline TLS Server Name Indication Observation": "low",
    "Baseline Memory Parent-Child Process Relationship": "low",
}


class TestDetectionSeverity(unittest.TestCase):
    """Verify rule/finding severity validation, defaults, ordering, and counts."""

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent

    def test_all_18_canonical_rules_have_approved_severity(self):
        all_rules = (
            list(create_initial_rules())
            + list(create_canonical_account_rules())
            + list(create_canonical_network_rules())
            + list(create_canonical_memory_rules())
        )
        self.assertEqual(len(all_rules), 18)
        actual = {r.name: r.severity for r in all_rules}
        self.assertEqual(actual, EXPECTED_SEVERITIES)

    def test_invalid_severity_raises_value_error(self):
        for bad in ("urgent", "extreme", "", "info"):
            with self.assertRaises(ValueError):
                create_rule(
                    name="Bad Severity Rule",
                    description="Test rule.",
                    detection_description="Observed test rule.",
                    severity=bad,
                )
            with self.assertRaises(ValueError):
                DetectionResult(
                    rule_id="RULE-01",
                    rule_name="Bad Severity Detection",
                    matched_event_ids=["EV-1"],
                    explanation="Observed test.",
                    severity=bad,
                )

    def test_legacy_serialized_rules_and_results_default_to_medium(self):
        old_rule_dict = {
            "name": "Legacy Rule",
            "description": "Legacy rule without severity.",
            "detection_description": "Observed legacy match.",
            "required_event_types": ["ssh_login_success"],
        }
        reconstructed_rule = DetectionRule.from_dict(old_rule_dict)
        self.assertEqual(reconstructed_rule.severity, "medium")

        old_det_dict = {
            "rule_id": "RULE-LEGACY",
            "rule_name": "Legacy Finding",
            "matched_event_ids": ["EV-1"],
            "explanation": "Observed legacy event.",
        }
        reconstructed_det = DetectionResult.from_dict(old_det_dict)
        self.assertEqual(reconstructed_det.severity, "medium")

    def test_detection_engine_stays_chronological_while_report_and_dashboard_sort_by_severity(self):
        rule_low = create_rule(
            name="Early Low Rule",
            description="Low test rule.",
            detection_description="Observed early low event.",
            required_categories=[TimelineCategory.LOG],
            required_event_types=["ev_low"],
            severity="low",
        )
        rule_crit = create_rule(
            name="Later Critical Rule",
            description="Critical test rule.",
            detection_description="Observed later critical event.",
            required_categories=[TimelineCategory.LOG],
            required_event_types=["ev_crit"],
            severity="critical",
        )
        rule_high = create_rule(
            name="Middle High Rule",
            description="High test rule.",
            detection_description="Observed middle high event.",
            required_categories=[TimelineCategory.LOG],
            required_event_types=["ev_high"],
            severity="high",
        )

        ev_low = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="ev_low",
            description="low",
            timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
            source_path="var/log/syslog",
            source_line=10,
        )
        ev_high = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="ev_high",
            description="high",
            timestamp=datetime(2026, 9, 30, 10, 1, 0, tzinfo=timezone.utc),
            source_path="var/log/syslog",
            source_line=20,
        )
        ev_crit = TimelineEvent(
            category=TimelineCategory.LOG,
            event_type="ev_crit",
            description="critical",
            timestamp=datetime(2026, 9, 30, 10, 2, 0, tzinfo=timezone.utc),
            source_path="var/log/syslog",
            source_line=30,
        )

        engine = DetectionEngine([rule_low, rule_crit, rule_high])
        results = engine.evaluate([ev_low, ev_high, ev_crit])
        # DetectionEngine keeps chronological order
        self.assertEqual([r.severity for r in results], ["low", "high", "critical"])

        # HTML report sorts highest severity first and handles legacy entries without severity
        det_dicts = [r.to_dict() for r in results]
        det_dicts.append(
            {
                "rule_id": "RULE-LEGACY",
                "rule_name": "Legacy Medium Rule",
                "matched_event_ids": ["EV-LEGACY"],
                "explanation": "Observed legacy event without severity.",
                "source_file": "var/log/syslog",
                "line_number": 5,
            }
        )
        report = build_advanced_report(
            case_metadata={"case_id": "CASE-SEV"},
            findings_summary=FindingsSummary(matched_detections=len(det_dicts)),
            details={"detections": det_dicts},
        )
        html = render_advanced_report_html(report)
        pos_crit = html.index("Later Critical Rule")
        pos_high = html.index("Middle High Rule")
        pos_med = html.index("Legacy Medium Rule")
        pos_low = html.index("Early Low Rule")
        self.assertLess(pos_crit, pos_high)
        self.assertLess(pos_high, pos_med)
        self.assertLess(pos_med, pos_low)
        self.assertIn("Critical: 1", html)
        self.assertIn("High: 1", html)
        self.assertIn("Medium: 1", html)
        self.assertIn("Low: 1", html)

        # Dashboard sorts highest severity first and shows per-severity counts
        node_bin = shutil.which("node")
        if node_bin:
            js_path = self.repo_root / "src" / "forensix" / "ui" / "dashboard.js"
            rep_dict = report.to_dict()
            rep_summary = {
                "id": rep_dict["report_id"],
                "report_type": "schema_8_0",
                "counts": {"artifact_count": 0, "event_count": 3, "correlation_count": 0, "detection_count": 4, "matched_detection_count": 4, "audit_event_count": 0},
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
  if (Array.isArray(node.children)) out += ' ' + node.children.map(collectText).join(' ');
  return out;
}}
['summary-counts-grid', 'summary-detections-container'].forEach(id => createMockElement('div', id));
const sandbox = {{
  document: {{
    readyState: 'complete',
    getElementById(id) {{ if (!elements.has(id)) elements.set(id, createMockElement('div', id)); return elements.get(id); }},
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
sandbox.window.__renderSummaryTab({json.dumps(rep_summary)}, {json.dumps(rep_dict)});
console.log(collectText(elements.get('summary-detections-container')));
"""
            proc = subprocess.run([node_bin, "-e", script], capture_output=True, text=True, check=True)
            rendered = proc.stdout
            self.assertLess(rendered.index("Later Critical Rule"), rendered.index("Middle High Rule"))
            self.assertLess(rendered.index("Middle High Rule"), rendered.index("Legacy Medium Rule"))
            self.assertLess(rendered.index("Legacy Medium Rule"), rendered.index("Early Low Rule"))
            self.assertIn("Critical: 1", rendered)
            self.assertIn("High: 1", rendered)
            self.assertIn("Medium: 1", rendered)
            self.assertIn("Low: 1", rendered)

    def test_case_synthetic_severity_counts_and_ordering(self):
        case_json = self.repo_root / "examples" / "case-synthetic" / "case.json"
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg = load_case_config_from_file(case_json)
            object.__setattr__(cfg, "output_dir", Path(tmp_dir) / "reports")
            res = run_pipeline(cfg)
            self.assertEqual(res.exit_code, EXIT_SUCCESS)

            json_path = next(p for p in res.output_files if p.name.startswith("report_") and p.suffix == ".json")
            raw_report = json.loads(json_path.read_text(encoding="utf-8"))
            details = raw_report["details"]

            self.assertEqual(
                details["severity_counts"],
                {"critical": 0, "high": 1, "medium": 2, "low": 2},
            )
            self.assertEqual(
                [d["severity"] for d in details["detections"]],
                ["high", "medium", "medium", "low", "low"],
            )


if __name__ == "__main__":
    unittest.main()

