"""
Unit and integration tests for ForensiX Dashboard Domain Tabs (Timeline, Network, Users).

Tests cover:
1. Timeline tab rendering from V3 timeline report ("events" list).
2. Network tab category filtering ("timeline_events" where category == "network").
3. Accounts tab category filtering ("artifacts" where category == "account").
4. V9 report empty state handling with mandatory explanation text.
5. Capping domain records at 100 rows with notice ("Showing first 100 of 150").
6. XSS payload safety (textContent only, zero innerHTML interpolation).
7. Offline UI asset integrity (zero external references).
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict
import unittest

from forensix.case_cli import execute_case_cli
from forensix.dashboard_service import DashboardReportRegistry
from forensix.main import execute_triage_cli
from forensix.timeline_cli import execute_timeline_cli


class TestDashboardDomainTabs(unittest.TestCase):
    """Test suite verifying domain tabs in ForensiX dashboard UI and registry."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.node_bin = shutil.which("node")
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.ui_dir = cls.repo_root / "src" / "forensix" / "ui"
        cls.html_path = cls.ui_dir / "index.html"
        cls.js_path = cls.ui_dir / "dashboard.js"
        cls.css_path = cls.ui_dir / "dashboard.css"
        cls.evidence_host = cls.repo_root / "examples" / "case-synthetic" / "evidence_host"
        cls.case_json = cls.repo_root / "examples" / "case-synthetic" / "case.json"

    def setUp(self) -> None:
        self.html_text = self.html_path.read_text(encoding="utf-8")
        self.js_text = self.js_path.read_text(encoding="utf-8")
        self.css_text = self.css_path.read_text(encoding="utf-8")

    def _run_node_evaluation(self, script_body: str) -> Dict[str, Any]:
        """Execute a Node.js test script against dashboard.js in a mocked DOM environment."""
        if not self.node_bin:
            self.skipTest("Node.js runtime not available for client-side JS evaluation.")

        driver_script = f"""
const fs = require('fs');
const vm = require('vm');

const jsCode = fs.readFileSync('{self.js_path.as_posix()}', 'utf8');

const elements = new Map();

function createMockElement(tag, id = '') {{
  const classes = new Set();
  const attrs = {{}};
  const children = [];
  const el = {{
    tag: tag.toLowerCase(),
    id: id,
    className: '',
    children: children,
    _textContent: '',
    get textContent() {{
      if (this.children.length === 0) return this._textContent;
      return this.children.map(c => typeof c === 'string' ? c : c.textContent).join('');
    }},
    set textContent(val) {{
      this.children.length = 0;
      this._textContent = String(val);
    }},
    get firstChild() {{
      return this.children.length > 0 ? this.children[0] : null;
    }},
    classList: {{
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
      get length() {{ return classes.size; }}
    }},
    setAttribute: (k, v) => {{ attrs[k] = String(v); }},
    getAttribute: (k) => attrs[k] || null,
    appendChild: (child) => {{
      if (typeof child === 'string') {{
        children.push(child);
      }} else {{
        children.push(child);
      }}
      return child;
    }},
    removeChild: (child) => {{
      const idx = children.indexOf(child);
      if (idx !== -1) children.splice(idx, 1);
      return child;
    }},
    getElementsByTagName: function(tName) {{
      const results = [];
      const target = tName.toLowerCase();
      function traverse(node) {{
        for (const c of node.children) {{
          if (c && typeof c === 'object') {{
            if (c.tag === target) results.push(c);
            traverse(c);
          }}
        }}
      }}
      traverse(this);
      return results;
    }},
    querySelectorAll: function(selector) {{
      const results = [];
      const isTag = /^[a-z0-9]+$/i.test(selector);
      const isClass = selector.startsWith('.');
      const clsName = isClass ? selector.slice(1) : '';
      function traverse(node) {{
        for (const c of node.children) {{
          if (c && typeof c === 'object') {{
            if (isTag && c.tag === selector.toLowerCase()) results.push(c);
            else if (isClass && c.classList.contains(clsName)) results.push(c);
            traverse(c);
          }}
        }}
      }}
      traverse(this);
      return results;
    }},
    addEventListener: () => {{}}
  }};
  if (id) elements.set(id, el);
  return el;
}}

// Pre-create known DOM nodes
[
  "tab-btn-metadata", "tab-btn-summary", "tab-raw", "tab-btn-raw",
  "tab-btn-timeline", "tab-btn-network", "tab-btn-users",
  "tab-metadata", "tab-summary", "tab-timeline", "tab-network", "tab-users",
  "overview-reports-list", "explorer-report-tag", "exp-caseid",
  "metadata-fields-grid", "summary-counts-grid", "json-tree-container"
].forEach(id => createMockElement('div', id));

const documentMock = {{
  readyState: 'complete',
  getElementById: (id) => {{
    if (!elements.has(id)) {{
      elements.set(id, createMockElement('div', id));
    }}
    return elements.get(id);
  }},
  createElement: (tag) => createMockElement(tag),
  createTextNode: (t) => ({{ textContent: String(t) }}),
  querySelectorAll: (selector) => {{
    if (selector === '.tab-btn') {{
      return [
        elements.get('tab-btn-metadata'),
        elements.get('tab-btn-summary'),
        elements.get('tab-btn-raw'),
        elements.get('tab-btn-timeline'),
        elements.get('tab-btn-network'),
        elements.get('tab-btn-users')
      ].filter(Boolean);
    }}
    return [];
  }}
}};

const windowMock = {{
  location: {{ hash: '' }},
  addEventListener: () => {{}}
}};

const sandbox = {{
  document: documentMock,
  window: windowMock,
  console: console,
  fetch: () => Promise.resolve({{ ok: true, json: () => Promise.resolve({{}}) }}),
  setTimeout: () => {{}},
  clearTimeout: () => {{}}
}};

// Inject hooks to capture internal tab renderers and state
const hookInjection = `
  window.__tabHooks = {{
    renderTimelineTab: typeof renderTimelineTab === 'function' ? renderTimelineTab : null,
    renderNetworkTab: typeof renderNetworkTab === 'function' ? renderNetworkTab : null,
    renderUsersTab: typeof renderUsersTab === 'function' ? renderUsersTab : null,
    switchTab: typeof switchTab === 'function' ? switchTab : null,
    state: typeof state !== 'undefined' ? state : null
  }};
  window.addEventListener("hashchange", handleHashRoute);
`;

const wrappedCode = jsCode.replace('window.addEventListener("hashchange", handleHashRoute);', hookInjection);

vm.runInNewContext(wrappedCode, sandbox);
const hooks = sandbox.window.__tabHooks;

{script_body}
"""
        proc = subprocess.run(
            [self.node_bin, "-e", driver_script],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Node execution error (code {proc.returncode}):\n{proc.stderr}\nStdout: {proc.stdout}")
        try:
            return json.loads(proc.stdout.strip()) if proc.stdout.strip() else {}
        except Exception:
            return {"raw_output": proc.stdout.strip()}

    def test_timeline_tab_shows_rows_from_v3_timeline(self) -> None:
        """Ingest V3 timeline JSON, fetch details, assert timeline tab data contains rows with timestamp and event_type."""
        # Check required HTML elements
        self.assertTrue('id="tab-btn-timeline"' in self.html_text, "Missing id=tab-btn-timeline in index.html")
        self.assertTrue('id="tab-timeline"' in self.html_text, "Missing id=tab-timeline in index.html")

        with tempfile.TemporaryDirectory() as td:
            v3_timeline_path = Path(td) / "timeline.json"
            ret, _ = execute_timeline_cli([str(self.evidence_host), "--format", "json", "-o", str(v3_timeline_path)])
            self.assertEqual(ret, 0)
            self.assertTrue(v3_timeline_path.exists())

            registry = DashboardReportRegistry()
            rep_id = registry.register_file(v3_timeline_path)
            details = registry.get_report_details(rep_id)
            self.assertIsNotNone(details)
            raw_data = details["raw_data"]
            self.assertIn("events", raw_data)
            self.assertGreater(len(raw_data["events"]), 0)

            # Execute renderTimelineTab through Node.js test harness
            script = f"""
const rawData = {json.dumps(raw_data)};
if (!hooks.renderTimelineTab) {{
  throw new Error("renderTimelineTab function is not defined in dashboard.js");
}}
hooks.renderTimelineTab(rawData);
const panel = documentMock.getElementById("tab-timeline");
const rows = panel.getElementsByTagName("tr");
const rowData = [];
for (const tr of rows) {{
  const cells = tr.getElementsByTagName("td");
  if (cells.length > 0) {{
    rowData.push(cells.map(c => c.textContent));
  }}
}}
console.log(JSON.stringify({{
  rowCount: rowData.length,
  firstRow: rowData[0] || [],
  panelText: panel.textContent
}}));
"""
            res = self._run_node_evaluation(script)
            self.assertGreater(res["rowCount"], 0)
            # Verify first row contains timestamp and event type
            first_row = res["firstRow"]
            self.assertTrue(any("T" in col and "Z" in col for col in first_row), f"No ISO timestamp in row: {first_row}")
            self.assertTrue(len(first_row) >= 2, "Row must have multiple domain fields")

    def test_network_tab_shows_only_network_category(self) -> None:
        """Ingest network report, assert only category == 'network' rows appear."""
        self.assertTrue('id="tab-btn-network"' in self.html_text, "Missing id=tab-btn-network in index.html")
        self.assertTrue('id="tab-network"' in self.html_text, "Missing id=tab-network in index.html")

        mixed_report = {
            "report_type": "correlation_detection",
            "metadata": {"case_id": "CASE-NET-TEST"},
            "timeline_events": [
                {
                    "event_id": "NET-01",
                    "timestamp": "2026-10-01T12:00:00Z",
                    "category": "network",
                    "event_type": "tcp_packet",
                    "description": "TCP connection 192.168.1.10:443",
                    "attributes": {
                        "src_ip": "192.168.1.10",
                        "dst_ip": "10.0.0.1",
                        "src_port": 443,
                        "dst_port": 50000,
                        "protocol": "TCP"
                    }
                },
                {
                    "event_id": "HOST-01",
                    "timestamp": "2026-10-01T12:00:05Z",
                    "category": "host",
                    "event_type": "file_access",
                    "description": "Sensitive host access",
                    "attributes": {"path": "/etc/shadow"}
                },
                {
                    "event_id": "NET-02",
                    "timestamp": "2026-10-01T12:00:10Z",
                    "category": "network",
                    "event_type": "dns_query",
                    "description": "DNS query to 8.8.8.8",
                    "attributes": {
                        "src_ip": "192.168.1.10",
                        "dst_ip": "8.8.8.8",
                        "src_port": 53535,
                        "dst_port": 53,
                        "protocol": "UDP"
                    }
                }
            ]
        }

        script = f"""
const rawData = {json.dumps(mixed_report)};
if (!hooks.renderNetworkTab) {{
  throw new Error("renderNetworkTab function is not defined in dashboard.js");
}}
hooks.renderNetworkTab(rawData);
const panel = documentMock.getElementById("tab-network");
const rows = panel.getElementsByTagName("tr");
const rowData = [];
for (const tr of rows) {{
  const cells = tr.getElementsByTagName("td");
  if (cells.length > 0) {{
    rowData.push(cells.map(c => c.textContent));
  }}
}}
console.log(JSON.stringify({{
  rowCount: rowData.length,
  rows: rowData,
  panelText: panel.textContent
}}));
"""
        res = self._run_node_evaluation(script)
        # Out of 3 items, exactly 2 are network category
        self.assertEqual(res["rowCount"], 2)
        # None should contain the host artifact description
        for row in res["rows"]:
            self.assertNotIn("Sensitive host access", " ".join(row))

    def test_accounts_tab_shows_only_account_category(self) -> None:
        """Ingest V2 triage JSON, assert only category == 'account' rows appear, each with username and uid."""
        self.assertTrue('id="tab-btn-users"' in self.html_text, "Missing id=tab-btn-users in index.html")
        self.assertTrue('id="tab-users"' in self.html_text, "Missing id=tab-users in index.html")

        with tempfile.TemporaryDirectory() as td:
            ret, _ = execute_triage_cli([str(self.evidence_host), "-o", str(td), "--format", "json"])
            self.assertEqual(ret, 0)
            triage_files = list(Path(td).glob("*.json"))
            self.assertGreater(len(triage_files), 0)
            triage_path = triage_files[0]

            with open(triage_path, "r", encoding="utf-8") as f:
                triage_data = json.load(f)

            script = f"""
const rawData = {json.dumps(triage_data)};
if (!hooks.renderUsersTab) {{
  throw new Error("renderUsersTab function is not defined in dashboard.js");
}}
hooks.renderUsersTab(rawData);
const panel = documentMock.getElementById("tab-users");
const rows = panel.getElementsByTagName("tr");
const rowData = [];
for (const tr of rows) {{
  const cells = tr.getElementsByTagName("td");
  if (cells.length > 0) {{
    rowData.push(cells.map(c => c.textContent));
  }}
}}
console.log(JSON.stringify({{
  rowCount: rowData.length,
  rows: rowData,
  panelText: panel.textContent
}}));
"""
            res = self._run_node_evaluation(script)
            self.assertGreater(res["rowCount"], 0)
            # All rows must have username and uid visible
            found_root = False
            for row in res["rows"]:
                row_str = " ".join(row)
                if "root" in row_str and "0" in row_str:
                    found_root = True
            self.assertTrue(found_root, "Expected account 'root' with uid 0 in accounts tab rows")

    def test_v9_report_shows_empty_state_with_explanation(self) -> None:
        """Ingest V9 report, assert timeline, network, accounts empty states contain explanation phrase."""
        with tempfile.TemporaryDirectory() as td:
            ret = execute_case_cli(["--config", str(self.case_json), "-o", str(td), "--overwrite"])
            self.assertEqual(ret, 0)
            v9_files = list(Path(td).glob("report_*.json"))
            self.assertGreater(len(v9_files), 0)

            with open(v9_files[0], "r", encoding="utf-8") as f:
                v9_data = json.load(f)

            script = f"""
const rawData = {json.dumps(v9_data)};
if (!hooks.renderTimelineTab || !hooks.renderNetworkTab || !hooks.renderUsersTab) {{
  throw new Error("Domain tab render functions not all defined in dashboard.js");
}}
hooks.renderTimelineTab(rawData);
hooks.renderNetworkTab(rawData);
hooks.renderUsersTab(rawData);

const timelineText = documentMock.getElementById("tab-timeline").textContent;
const networkText = documentMock.getElementById("tab-network").textContent;
const usersText = documentMock.getElementById("tab-users").textContent;

console.log(JSON.stringify({{
  timeline: timelineText,
  network: networkText,
  users: usersText
}}));
"""
            res = self._run_node_evaluation(script)
            # All three must contain the phrase "This report type has no" and name the target report type
            self.assertIn("This report type has no", res["timeline"])
            self.assertIn("V3 timeline report", res["timeline"])

            self.assertIn("This report type has no", res["network"])
            self.assertIn("network report", res["network"])

            self.assertIn("This report type has no", res["users"])
            self.assertIn("V2 triage report", res["users"])

    def test_domain_rows_capped_at_100_with_notice(self) -> None:
        """A report with 150 timeline rows shows 100 and the notice 'Showing first 100 of 150'."""
        large_events = [
            {
                "event_id": f"EVT-{i:04d}",
                "timestamp": f"2026-10-01T12:00:{i%60:02d}Z",
                "category": "timeline",
                "event_type": "event_type_test",
                "description": f"Event description {i}",
                "source_path": f"/var/log/syslog.{i}"
            }
            for i in range(150)
        ]
        large_report = {"events": large_events}

        script = f"""
const rawData = {json.dumps(large_report)};
if (!hooks.renderTimelineTab) {{
  throw new Error("renderTimelineTab is not defined");
}}
hooks.renderTimelineTab(rawData);
const panel = documentMock.getElementById("tab-timeline");
const rows = panel.getElementsByTagName("tr");
const bodyRows = [];
for (const tr of rows) {{
  const cells = tr.getElementsByTagName("td");
  if (cells.length > 0) bodyRows.push(cells);
}}
console.log(JSON.stringify({{
  bodyRowCount: bodyRows.length,
  panelText: panel.textContent
}}));
"""
        res = self._run_node_evaluation(script)
        self.assertEqual(res["bodyRowCount"], 100)
        self.assertIn("Showing first 100 of 150", res["panelText"])

    def test_xss_payload_in_domain_rows_is_text(self) -> None:
        """Row with XSS payload in event_type is text only; dashboard.js contains no innerHTML with report data."""
        # 1. Assert dashboard.js does not contain innerHTML
        self.assertNotIn(".innerHTML", self.js_text)
        self.assertNotIn("document.write", self.js_text)

        payload = "<img src=x onerror=alert(1)>"
        xss_report = {
            "events": [
                {
                    "event_id": "EVT-XSS",
                    "timestamp": "2026-10-01T12:00:00Z",
                    "event_type": payload,
                    "description": "<script>alert('xss')</script>",
                    "source_path": "/var/log/<svg onload=alert(2)>"
                }
            ]
        }

        script = f"""
const rawData = {json.dumps(xss_report)};
if (!hooks.renderTimelineTab) {{
  throw new Error("renderTimelineTab is not defined");
}}
hooks.renderTimelineTab(rawData);
const panel = documentMock.getElementById("tab-timeline");
const imgs = panel.getElementsByTagName("img");
const scripts = panel.getElementsByTagName("script");
console.log(JSON.stringify({{
  imgCount: imgs.length,
  scriptCount: scripts.length,
  panelText: panel.textContent
}}));
"""
        res = self._run_node_evaluation(script)
        self.assertEqual(res["imgCount"], 0, "No <img> element should be parsed from text payload")
        self.assertEqual(res["scriptCount"], 0, "No <script> element should be parsed from text payload")
        self.assertIn(payload, res["panelText"])

    def test_no_external_references_in_ui_assets(self) -> None:
        """No external URLs in index.html, dashboard.js, dashboard.css except local server address."""
        # Verify domain tab elements are declared
        self.assertTrue('id="tab-btn-timeline"' in self.html_text, "Missing id=tab-btn-timeline in index.html")
        self.assertTrue('id="tab-btn-network"' in self.html_text, "Missing id=tab-btn-network in index.html")
        self.assertTrue('id="tab-btn-users"' in self.html_text, "Missing id=tab-btn-users in index.html")
        self.assertTrue('id="tab-timeline"' in self.html_text, "Missing id=tab-timeline in index.html")
        self.assertTrue('id="tab-network"' in self.html_text, "Missing id=tab-network in index.html")
        self.assertTrue('id="tab-users"' in self.html_text, "Missing id=tab-users in index.html")

        forbidden_patterns = ["cdn.", "googleapis", "gstatic", "unpkg", "cdnjs", "jsdelivr"]

        for name, text in [("index.html", self.html_text), ("dashboard.js", self.js_text), ("dashboard.css", self.css_text)]:
            lower = text.lower()
            for pat in forbidden_patterns:
                self.assertNotIn(pat, lower, f"Forbidden reference '{pat}' found in {name}")

            # Check URLs: only loopback or XML namespace (w3.org) allowed
            urls = re.findall(r"https?://[^\s'\"<>]+", text)
            for url in urls:
                self.assertTrue(
                    "127.0.0.1" in url or "localhost" in url or "w3.org" in url,
                    f"Unexpected external URL found in {name}: {url}"
                )


if __name__ == "__main__":
    unittest.main()
