"""
Unit and integration tests for ForensiX Dashboard Case Overview.

Tests cover:
1. Primary report rule: case row uses primary report counts, not sum.
2. Case row states other report count ("Other reports: N").
3. Standalone reports row ("No case ID (standalone reports)") has no summed counts.
4. Case table headers are strictly neutral.
5. Case ID and name are rendered as safe text, never HTML elements.
6. Case table is hidden when zero reports are ingested.
"""

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict
import unittest


class TestDashboardCaseOverview(unittest.TestCase):
    """Test suite verifying case overview in ForensiX dashboard UI."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.node_bin = shutil.which("node")
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.ui_dir = cls.repo_root / "src" / "forensix" / "ui"
        cls.html_path = cls.ui_dir / "index.html"
        cls.js_path = cls.ui_dir / "dashboard.js"
        cls.css_path = cls.ui_dir / "dashboard.css"

    def setUp(self) -> None:
        self.html_text = self.html_path.read_text(encoding="utf-8")
        self.js_text = self.js_path.read_text(encoding="utf-8")
        self.css_text = self.css_path.read_text(encoding="utf-8")

    def _run_node_evaluation(self, script_body: str) -> Dict[str, Any]:
        """Execute Node.js against dashboard.js with mocked DOM."""
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
      return this.children.map(c => typeof c === 'string' ? c : (c.textContent || '')).join('');
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
      children.push(child);
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

// Known elements
[
  "view-overview", "view-explorer", "view-pivots", "loading-state", "error-state",
  "empty-state", "reports-table-container", "reports-table-body", "table-reports",
  "cases-section", "cases-table-container", "cases-table-body", "table-cases",
  "metric-total-reports", "metric-active-schemas", "metric-total-artifacts", "metric-total-events",
  "metric-total-detections", "metric-detections-label", "summary-counts-grid",
  "alert-banner", "alert-message", "badge-version"
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
  querySelectorAll: () => []
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

const hookInjection = `
  window.__caseHooks = {{
    renderCaseOverview: typeof renderCaseOverview === 'function' ? renderCaseOverview : null,
    renderOverview: typeof renderOverview === 'function' ? renderOverview : null,
    renderExplorer: typeof renderExplorer === 'function' ? renderExplorer : null,
    renderSummaryTab: typeof renderSummaryTab === 'function' ? renderSummaryTab : null,
    state: typeof state !== 'undefined' ? state : null,
    views: typeof views !== 'undefined' ? views : null,
  }};
  window.addEventListener("hashchange", handleHashRoute);
`;

const wrappedCode = jsCode.replace('window.addEventListener("hashchange", handleHashRoute);', hookInjection);

vm.runInNewContext(wrappedCode, sandbox);
const hooks = sandbox.window.__caseHooks;

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

    def test_case_row_uses_primary_report_counts_not_sum(self) -> None:
        """Two reports share case_id CASE-A: a V9 report (31 events) and V3 (19 events). The CASE-A row shows 31, not 50."""
        script = """
if (!hooks.renderCaseOverview) {
  throw new Error("renderCaseOverview is not defined in dashboard.js");
}
const testReports = [
  {
    id: "rep-v9",
    report_type: "schema_8_0",
    filename: "report_v9.json",
    metadata: { case_id: "CASE-A", case_name: "Test Case Alpha" },
    counts: { event_count: 31, artifact_count: 42, detection_count: 5, matched_detection_count: 5 }
  },
  {
    id: "rep-v3",
    report_type: "timeline",
    filename: "timeline.json",
    metadata: { case_id: "CASE-A", case_name: "Test Case Alpha" },
    counts: { event_count: 19, artifact_count: 0, detection_count: 0, matched_detection_count: 0 }
  }
];
hooks.renderCaseOverview(testReports);
const tbody = documentMock.getElementById("cases-table-body");
const rows = tbody.getElementsByTagName("tr");
const cells = rows.length > 0 ? rows[0].getElementsByTagName("td").map(c => c.textContent) : [];
console.log(JSON.stringify({ rowCount: rows.length, cells: cells }));
"""
        res = self._run_node_evaluation(script)
        self.assertGreater(res.get("rowCount", 0), 0, "No case rows rendered")
        cells = res["cells"]
        row_text = " ".join(cells)
        # Primary is 31 events, not 50 (sum)
        self.assertIn("31", row_text, f"Primary event count 31 missing from row: {row_text}")
        self.assertNotIn("50", row_text, f"Row incorrectly summed counts to 50: {row_text}")

    def test_case_row_states_other_report_count(self) -> None:
        """The CASE-A row shows 'Other reports: 1'."""
        script = """
if (!hooks.renderCaseOverview) {
  throw new Error("renderCaseOverview is not defined in dashboard.js");
}
const testReports = [
  {
    id: "rep-v9",
    report_type: "schema_8_0",
    filename: "report_v9.json",
    metadata: { case_id: "CASE-A", case_name: "Test Case Alpha" },
    counts: { event_count: 31, artifact_count: 42, detection_count: 5 }
  },
  {
    id: "rep-v3",
    report_type: "timeline",
    filename: "timeline.json",
    metadata: { case_id: "CASE-A", case_name: "Test Case Alpha" },
    counts: { event_count: 19, artifact_count: 0, detection_count: 0 }
  }
];
hooks.renderCaseOverview(testReports);
const tbody = documentMock.getElementById("cases-table-body");
const rows = tbody.getElementsByTagName("tr");
const cells = rows.length > 0 ? rows[0].getElementsByTagName("td").map(c => c.textContent) : [];
console.log(JSON.stringify({ rowCount: rows.length, cells: cells }));
"""
        res = self._run_node_evaluation(script)
        self.assertGreater(res.get("rowCount", 0), 0)
        row_text = " ".join(res["cells"])
        self.assertIn("Other reports: 1", row_text, f"'Other reports: 1' not found in row: {row_text}")

    def test_no_case_id_row_has_no_summed_counts(self) -> None:
        """Two reports with no case_id produce one 'No case ID' row showing 'Standalone reports: 2' and no event/artifact totals."""
        script = """
if (!hooks.renderCaseOverview) {
  throw new Error("renderCaseOverview is not defined in dashboard.js");
}
const testReports = [
  {
    id: "rep-standalone-1",
    report_type: "evidence_analysis",
    filename: "file1.json",
    metadata: { case_id: null },
    counts: { event_count: 10, artifact_count: 5 }
  },
  {
    id: "rep-standalone-2",
    report_type: "timeline",
    filename: "file2.json",
    metadata: { case_id: "" },
    counts: { event_count: 20, artifact_count: 8 }
  }
];
hooks.renderCaseOverview(testReports);
const tbody = documentMock.getElementById("cases-table-body");
const rows = tbody.getElementsByTagName("tr");
const cells = rows.length > 0 ? rows[0].getElementsByTagName("td").map(c => c.textContent) : [];
console.log(JSON.stringify({ rowCount: rows.length, cells: cells }));
"""
        res = self._run_node_evaluation(script)
        self.assertEqual(res.get("rowCount", 0), 1)
        row_text = " ".join(res["cells"])
        self.assertIn("No case ID (standalone reports)", row_text)
        self.assertIn("Standalone reports: 2", row_text)
        # Must not show summed totals (10+20=30, 5+8=13)
        self.assertNotIn("30", row_text, f"No case ID row must not show summed event total: {row_text}")
        self.assertNotIn("13", row_text, f"No case ID row must not show summed artifact total: {row_text}")

    def test_case_table_neutral_headers(self) -> None:
        """The case table headers are exactly: Case, Name, Reports, Primary Report, Observed Timeline Events, Observed Host Artifacts, Rule Matches."""
        # Check index.html table structure
        table_match = re.search(r'<table[^>]*id=["\']table-cases["\'][^>]*>(.*?)</table>', self.html_text, re.DOTALL)
        self.assertIsNotNone(table_match, "Missing table id=table-cases in index.html")
        table_html = table_match.group(1)
        headers = re.findall(r'<th[^>]*>(.*?)</th>', table_html, re.DOTALL)
        clean_headers = [re.sub(r'<[^>]+>', '', h).strip() for h in headers]
        expected_headers = [
            "Case",
            "Name",
            "Reports",
            "Primary Report",
            "Observed Timeline Events",
            "Observed Host Artifacts",
            "Rule Matches",
        ]
        self.assertEqual(clean_headers, expected_headers)
        # Verify prohibited words
        for h in clean_headers:
            for forbidden in ("severity", "attack", "threat", "malicious", "compromised"):
                self.assertNotIn(forbidden, h.lower(), f"Forbidden word '{forbidden}' found in header '{h}'")

    def test_case_name_is_text_not_html(self) -> None:
        """A case_id or name containing <img src=x onerror=alert(1)> is rendered as text."""
        script = """
if (!hooks.renderCaseOverview) {
  throw new Error("renderCaseOverview is not defined in dashboard.js");
}
const xssPayload = '<img src=x onerror=alert(1)>';
const testReports = [
  {
    id: "rep-xss",
    report_type: "schema_8_0",
    filename: "xss.json",
    metadata: { case_id: xssPayload, case_name: xssPayload },
    counts: { event_count: 5, artifact_count: 2, detection_count: 0 }
  }
];
hooks.renderCaseOverview(testReports);
const tbody = documentMock.getElementById("cases-table-body");
const imgs = tbody.getElementsByTagName("img");
console.log(JSON.stringify({ imgTagCount: imgs.length, fullText: tbody.textContent }));
"""
        res = self._run_node_evaluation(script)
        self.assertEqual(res.get("imgTagCount", -1), 0, "XSS HTML element was parsed as DOM node!")
        self.assertIn("<img src=x onerror=alert(1)>", res.get("fullText", ""))

    def test_case_table_hidden_when_no_reports(self) -> None:
        """With zero reports the cases table is hidden."""
        script = """
if (!hooks.renderOverview) {
  throw new Error("renderOverview is not defined in dashboard.js");
}
hooks.state.reports = [];
hooks.renderOverview();
const casesSection = documentMock.getElementById("cases-section") || documentMock.getElementById("cases-table-container");
const isHidden = casesSection ? casesSection.classList.contains("hidden") : false;
console.log(JSON.stringify({ isHidden: isHidden, exists: !!casesSection }));
"""
        res = self._run_node_evaluation(script)
        self.assertTrue(res.get("exists", False), "Cases table container element does not exist")
        self.assertTrue(res.get("isHidden", False), "Cases table is not hidden when reports list is empty")

    def test_cases_heading_and_overview_cards_split_and_cap_labels(self) -> None:
        """Verify visible Cases heading, split Artifacts/Timeline cards, Correlation links label, and identical cap text."""
        self.assertIn('<h2 class="cases-heading">Cases</h2>', self.html_text)
        self.assertIn("Artifacts analyzed", self.html_text)
        self.assertIn("Timeline events", self.html_text)
        self.assertIn("Correlation links", self.html_text)
        self.assertNotIn("Analyzed Artifacts &amp; Events", self.html_text)
        self.assertNotIn("Detections &amp; Correlations", self.html_text)

        script = """
hooks.state.reports = [
  {
    id: "rep-1",
    report_type: "schema_8_0",
    filename: "report_CASE-1.json",
    metadata: { case_id: "CASE-1", case_name: "Test" },
    counts: { artifact_count: 42, event_count: 31, detection_count: 5, correlation_count: 50000 },
    correlations_truncated: true,
    correlation_cap: 50000
  }
];
hooks.renderOverview();
const mArt = documentMock.getElementById("metric-total-artifacts").textContent;
const mEv = documentMock.getElementById("metric-total-events").textContent;
const mDet = documentMock.getElementById("metric-total-detections").textContent;
const mLabelTrunc = documentMock.getElementById("metric-detections-label").textContent;

hooks.state.reports[0].correlations_truncated = false;
hooks.renderOverview();
const mLabelNormal = documentMock.getElementById("metric-detections-label").textContent;

const rep = {
  id: "rep-1",
  report_type: "schema_8_0",
  filename: "report_CASE-1.json",
  metadata: { case_id: "CASE-1" },
  counts: { artifact_count: 42, event_count: 31, correlation_count: 50000, detection_count: 5, matched_detection_count: 5, audit_event_count: 0 }
};
const rawTrunc = {
  details: { correlations_truncated: true, correlation_cap: 50000, correlations_skipped: 228130 }
};
hooks.state.activeReportDetails = { id: "rep-1", raw_data: rawTrunc };
hooks.renderExplorer("rep-1");
const alertMsg = documentMock.getElementById("alert-message").textContent;
const summaryText = documentMock.getElementById("summary-counts-grid").textContent;

hooks.renderSummaryTab(rep, { details: {} });
const summaryUncappedText = documentMock.getElementById("summary-counts-grid").textContent;

console.log(JSON.stringify({
  mArt, mEv, mDet, mLabelTrunc, mLabelNormal, alertMsg, summaryText, summaryUncappedText
}));
"""
        res = self._run_node_evaluation(script)
        self.assertEqual(res["mArt"], "42")
        self.assertEqual(res["mEv"], "31")
        self.assertEqual(res["mDet"], "50005")
        self.assertEqual(res["mLabelTrunc"], "Correlation links (capped at 50,000)")
        self.assertEqual(res["mLabelNormal"], "Correlation links")
        expected_cap = "Correlation links capped at 50,000 per run. 228,130 candidate links were skipped."
        self.assertEqual(res["alertMsg"], expected_cap)
        self.assertIn("Correlation links (capped at 50,000)", res["summaryText"])
        self.assertIn(expected_cap, res["summaryText"])
        self.assertIn("Correlation links", res["summaryUncappedText"])
        self.assertNotIn("capped at 50,000", res["summaryUncappedText"])


if __name__ == "__main__":
    unittest.main()

