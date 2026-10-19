/**
 * ForensiX V7.3 / V7.4 — Offline Dashboard Client
 *
 * Pure Vanilla JavaScript • Zero Dependencies • Zero Remote Calls
 * Enforces Safe DOM APIs (zero innerHTML interpolation of report-derived data).
 */

(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // State Store
  // ---------------------------------------------------------------------------
  const state = {
    reports: [],
    reportsById: new Map(),
    activeReportId: null,
    activeReportDetails: null,
    activeTab: "tab-metadata",
    searchQuery: "",
    typeFilter: "all",
    isLoading: false,
    error: null,
    // Phase 3 Cross-Domain Drill-Down State
    lastPivotHash: null,
    previousReportId: null,
    pendingNamespacePivot: null,
    pendingPidPivot: null,
  };

  // ---------------------------------------------------------------------------
  // Safe DOM Helper Utilities
  // ---------------------------------------------------------------------------
  function el(tag, className, textContent, attrs) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (textContent !== undefined && textContent !== null) {
      element.textContent = String(textContent);
    }
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value !== undefined && value !== null) {
          element.setAttribute(key, String(value));
        }
      }
    }
    return element;
  }

  function clearNode(node) {
    while (node && node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function formatBytes(bytes) {
    if (typeof bytes !== "number" || isNaN(bytes)) return "—";
    if (bytes < 1024) return bytes + " B";
    const k = 1024;
    const sizes = ["B", "KiB", "MiB", "GiB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatTypeName(typeStr) {
    if (!typeStr) return "Unknown";
    return typeStr
      .split("_")
      .map(function (w) {
        return w.charAt(0).toUpperCase() + w.slice(1);
      })
      .join(" ");
  }

  // ---------------------------------------------------------------------------
  // UI State & View Transitions
  // ---------------------------------------------------------------------------
  const views = {
    overview: document.getElementById("view-overview"),
    explorer: document.getElementById("view-explorer"),
    pivots: document.getElementById("view-pivots"),
    loading: document.getElementById("loading-state"),
    error: document.getElementById("error-state"),
    empty: document.getElementById("empty-state"),
    tableContainer: document.getElementById("reports-table-container"),
    alertBanner: document.getElementById("alert-banner"),
    alertMessage: document.getElementById("alert-message"),
  };

  function showAlert(msg) {
    if (!views.alertBanner || !views.alertMessage) return;
    views.alertMessage.textContent = msg;
    views.alertBanner.classList.remove("hidden");
  }

  function hideAlert() {
    if (!views.alertBanner) return;
    views.alertBanner.classList.add("hidden");
  }

  function showLoading(show) {
    state.isLoading = show;
    if (views.loading) {
      if (show) {
        views.loading.classList.remove("hidden");
        if (views.overview) views.overview.classList.add("hidden");
        if (views.explorer) views.explorer.classList.add("hidden");
        if (views.pivots) views.pivots.classList.add("hidden");
        if (views.error) views.error.classList.add("hidden");
      } else {
        views.loading.classList.add("hidden");
      }
    }
  }

  function showError(title, desc) {
    showLoading(false);
    if (views.error) {
      const titleEl = document.getElementById("error-title");
      const descEl = document.getElementById("error-description");
      if (titleEl) titleEl.textContent = title;
      if (descEl) descEl.textContent = desc;
      views.error.classList.remove("hidden");
      if (views.overview) views.overview.classList.add("hidden");
      if (views.explorer) views.explorer.classList.add("hidden");
      if (views.pivots) views.pivots.classList.add("hidden");
    }
  }

  function navigateTo(hash) {
    window.location.hash = hash;
  }

  // ---------------------------------------------------------------------------
  // Pivot Field Detection & Validation Logic
  // ---------------------------------------------------------------------------
  const SHA256_HEX_REGEX = /^[0-9a-fA-F]{64}$/;

  function isValidIPv4(str) {
    if (typeof str !== "string") return false;
    const parts = str.trim().split(".");
    if (parts.length !== 4) return false;
    for (let i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return false;
      const num = parseInt(parts[i], 10);
      if (num < 0 || num > 255) return false;
    }
    return true;
  }

  function isValidIPv6(str) {
    if (typeof str !== "string") return false;
    const s = str.trim();
    return s.includes(":") && /^[0-9a-fA-F:]+$/.test(s);
  }

  function detectPivotField(keyName, val, parentKey) {
    if (val === null || val === undefined) return null;
    const effectiveKey = (keyName && isNaN(Number(keyName))) ? keyName : (parentKey || keyName || "");
    const key = effectiveKey.toLowerCase();
    const strVal = typeof val === "string" ? val.trim() : "";

    // 1. Case ID
    if (key === "case_id" && strVal) {
      return {
        fieldType: "case_id",
        value: strVal,
        label: "Pivot on Case ID: " + strVal,
      };
    }

    // 2. SHA-256
    const shaKeys = ["sha256", "file_sha256", "hash", "file_hash"];
    if (shaKeys.includes(key)) {
      if (strVal.length === 64 && SHA256_HEX_REGEX.test(strVal)) {
        return {
          fieldType: "sha256",
          value: strVal.toLowerCase(),
          label: "Pivot on SHA-256: " + strVal.toLowerCase(),
        };
      }
    }

    // 3. IP Address (Strictly exclude non-IP generic keys like 'source' and 'host')
    const ipKeys = [
      "source_ip",
      "src_ip",
      "destination_ip",
      "dst_ip",
      "remote_ip",
      "remote_address",
      "local_address",
      "ip_address",
      "ip",
    ];
    if (ipKeys.includes(key) && strVal) {
      if (isValidIPv4(strVal) || isValidIPv6(strVal)) {
        return {
          fieldType: "ip_address",
          value: strVal,
          label: "Pivot on IP Address: " + strVal,
        };
      }
    }

    // 4. PID (Requires defensible host/evidence scope)
    if (key === "pid") {
      let numVal = null;
      if (typeof val === "number" && Number.isInteger(val) && val >= 0) {
        numVal = val;
      } else if (typeof val === "string" && /^\d+$/.test(val.trim())) {
        numVal = parseInt(val.trim(), 10);
      }
      if (numVal !== null) {
        return {
          fieldType: "pid",
          value: String(numVal),
          requiresScope: true,
          label: "Pivot on Scoped PID: " + numVal,
        };
      }
    }

    // 5. Event ID
    const eventKeys = [
      "event_id",
      "source_event_id",
      "matched_event_ids",
      "matched_source_event_ids",
      "event_ids",
      "source_event_ids",
    ];
    if (eventKeys.includes(key) && strVal) {
      return {
        fieldType: "event_id",
        value: strVal,
        label: "Pivot on Event ID: " + strVal,
      };
    }

    // 6. Rule ID
    if (key === "rule_id" && strVal) {
      return {
        fieldType: "rule_id",
        value: strVal,
        label: "Pivot on Rule ID: " + strVal,
      };
    }

    // 7. Artifact ID
    const artifactNamespaceMap = {
      evidence_id: "evidence_id",
      unified_id: "unified_artifact_id",
      unified_artifact_id: "unified_artifact_id",
      source_id: "source_id",
      source_artifact_id: "source_artifact_id",
      matched_source_artifact_ids: "source_artifact_id",
      correlation_id: "correlation_id",
      matched_correlation_ids: "correlation_id",
      report_id: "report_id",
      payload_artifact_id: "payload_artifact_id",
    };

    if (artifactNamespaceMap[key] && strVal) {
      return {
        fieldType: "artifact_id",
        value: strVal,
        identifierKind: artifactNamespaceMap[key],
        isAmbiguous: false,
        label: "Pivot on Artifact ID (" + artifactNamespaceMap[key] + "): " + strVal,
      };
    }

    // Generic artifact_id key
    if ((key === "artifact_id" || key === "matched_artifacts") && strVal) {
      if (strVal.includes(":")) {
        const parts = strVal.split(":", 2);
        const prefix = parts[0].trim().toLowerCase();
        const remainder = parts[1].trim();
        const prefixKinds = {
          evidence_id: "evidence_id",
          unified_id: "unified_artifact_id",
          unified_artifact_id: "unified_artifact_id",
          source_id: "source_id",
          source_artifact_id: "source_artifact_id",
          correlation_id: "correlation_id",
          report_id: "report_id",
          payload_artifact_id: "payload_artifact_id",
        };
        if (prefixKinds[prefix] && remainder) {
          return {
            fieldType: "artifact_id",
            value: remainder,
            identifierKind: prefixKinds[prefix],
            isAmbiguous: false,
            label: "Pivot on Artifact ID (" + prefixKinds[prefix] + "): " + remainder,
          };
        }
      }
      return {
        fieldType: "artifact_id",
        value: strVal,
        identifierKind: null,
        isAmbiguous: true,
        label: "Pivot on Artifact ID: " + strVal,
      };
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Pivot UI Controls & Modals
  // ---------------------------------------------------------------------------
  function createPivotButton(pivotInfo) {
    const btn = el("button", "btn-pivot", "⤻ Pivot", {
      type: "button",
      "aria-label": pivotInfo.label || ("Pivot on " + pivotInfo.fieldType),
      title: pivotInfo.label || ("Pivot on " + pivotInfo.fieldType),
    });
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      handlePivotInteraction(pivotInfo);
    });
    return btn;
  }

  function handlePivotInteraction(pivotInfo) {
    if (pivotInfo.isAmbiguous) {
      openNamespaceModal(pivotInfo);
    } else if (pivotInfo.requiresScope) {
      openPidModal(pivotInfo);
    } else {
      if (state.activeReportId) {
        state.previousReportId = state.activeReportId;
      }
      navigateToPivot(pivotInfo.fieldType, pivotInfo.value, null, pivotInfo.identifierKind);
    }
  }

  function navigateToPivot(field, value, scope, identifierKind) {
    const params = new URLSearchParams();
    params.set("field", field);
    params.set("value", value);
    if (scope) params.set("scope", scope);
    if (identifierKind) params.set("identifier_kind", identifierKind);
    navigateTo("#pivots?" + params.toString());
  }

  function openNamespaceModal(pivotInfo) {
    state.pendingNamespacePivot = pivotInfo;
    const modal = document.getElementById("modal-namespace");
    const valEl = document.getElementById("modal-namespace-value");
    if (valEl) valEl.textContent = pivotInfo.value;
    if (modal) modal.classList.remove("hidden");
    const select = document.getElementById("select-artifact-namespace");
    if (select) {
      setTimeout(function () {
        select.focus();
      }, 50);
    }
  }

  function closeNamespaceModal() {
    state.pendingNamespacePivot = null;
    const modal = document.getElementById("modal-namespace");
    if (modal) modal.classList.add("hidden");
  }

  function confirmNamespaceModal() {
    if (!state.pendingNamespacePivot) return;
    const select = document.getElementById("select-artifact-namespace");
    const chosenKind = select ? select.value : "unified_artifact_id";
    const pivot = state.pendingNamespacePivot;
    closeNamespaceModal();
    if (state.activeReportId) {
      state.previousReportId = state.activeReportId;
    }
    navigateToPivot("artifact_id", pivot.value, null, chosenKind);
  }

  function openPidModal(pivotInfo) {
    state.pendingPidPivot = pivotInfo;
    const modal = document.getElementById("modal-pid-scope");
    const valEl = document.getElementById("modal-pid-value");
    const inputEl = document.getElementById("input-pid-scope-val");
    const errEl = document.getElementById("modal-pid-scope-error");
    if (valEl) valEl.textContent = pivotInfo.value;
    if (errEl) errEl.classList.add("hidden");

    let suggestedScope = "";
    const activeReport = state.reportsById.get(state.activeReportId);
    if (activeReport && activeReport.metadata) {
      suggestedScope =
        activeReport.metadata.evidence_root ||
        activeReport.metadata.case_id ||
        "";
    } else if (state.activeReportDetails && state.activeReportDetails.raw_data) {
      const rawMeta = state.activeReportDetails.raw_data.metadata || {};
      suggestedScope = rawMeta.evidence_root || rawMeta.case_id || "";
    }
    if (inputEl) {
      inputEl.value = suggestedScope;
      setTimeout(function () {
        inputEl.focus();
      }, 50);
    }
    if (modal) modal.classList.remove("hidden");
  }

  function closePidModal() {
    state.pendingPidPivot = null;
    const modal = document.getElementById("modal-pid-scope");
    if (modal) modal.classList.add("hidden");
  }

  function confirmPidModal() {
    if (!state.pendingPidPivot) return;
    const inputEl = document.getElementById("input-pid-scope-val");
    const errEl = document.getElementById("modal-pid-scope-error");
    const scopeVal = inputEl ? inputEl.value.trim() : "";
    if (!scopeVal) {
      if (errEl) errEl.classList.remove("hidden");
      return;
    }
    const pivot = state.pendingPidPivot;
    closePidModal();
    if (state.activeReportId) {
      state.previousReportId = state.activeReportId;
    }
    navigateToPivot("pid", pivot.value, scopeVal, null);
  }

  // ---------------------------------------------------------------------------
  // API Calls (Strictly Read-Only GET)
  // ---------------------------------------------------------------------------
  async function apiGet(endpoint) {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      let errorMsg = "HTTP error " + response.status;
      try {
        const errorJson = await response.json();
        if (errorJson && errorJson.error && errorJson.error.message) {
          errorMsg = errorJson.error.message;
        }
      } catch (e) {
        // Fallback to HTTP status
      }
      const err = new Error(errorMsg);
      err.status = response.status;
      throw err;
    }

    return await response.json();
  }

  async function loadDashboard() {
    showLoading(true);
    hideAlert();
    try {
      // 1. Health & version
      try {
        const health = await apiGet("/api/health");
        if (health && health.version) {
          const vBadge = document.getElementById("badge-version");
          if (vBadge) vBadge.textContent = "v" + health.version;
        }
      } catch (hErr) {
        console.warn("Health query warning:", hErr);
      }

      // 2. Reports list
      const data = await apiGet("/api/reports");
      state.reports = Array.isArray(data.reports) ? data.reports : [];
      state.reportsById.clear();
      state.reports.forEach(function (r) {
        if (r && r.id) {
          state.reportsById.set(r.id, r);
        }
      });

      showLoading(false);
      handleHashRoute();
    } catch (err) {
      showError(
        "Service Connection Failure",
        "Could not load reports from local service (" + err.message + "). Ensure ForensiX server is active on 127.0.0.1."
      );
    }
  }

  async function loadReportDetails(reportId) {
    showLoading(true);
    hideAlert();
    try {
      const details = await apiGet("/api/reports/" + encodeURIComponent(reportId) + "/details");
      state.activeReportDetails = details;
      showLoading(false);
      renderExplorer(reportId);
    } catch (err) {
      showLoading(false);
      showAlert("Failed to load details for report '" + reportId + "': " + err.message);
      if (err.status === 404) {
        navigateTo("#overview");
      }
    }
  }

  // ---------------------------------------------------------------------------
  // View 1: Overview Rendering
  // ---------------------------------------------------------------------------
  function renderOverview() {
    if (views.error) views.error.classList.add("hidden");
    if (views.explorer) views.explorer.classList.add("hidden");
    if (views.pivots) views.pivots.classList.add("hidden");
    if (views.overview) views.overview.classList.remove("hidden");

    // 1. Metrics tally
    const totalReports = state.reports.length;
    const schemasSet = new Set();
    let totalEvents = 0;
    let totalDetections = 0;

    state.reports.forEach(function (r) {
      if (r.report_type) schemasSet.add(r.report_type);
      if (r.counts) {
        const c = r.counts;
        totalEvents += (c.artifact_count || 0) + (c.event_count || 0) + (c.audit_event_count || 0);
        totalDetections += (c.detection_count || 0) + (c.correlation_count || 0);
      }
    });

    const mTotal = document.getElementById("metric-total-reports");
    const mSchemas = document.getElementById("metric-active-schemas");
    const mEvents = document.getElementById("metric-total-events");
    const mDetections = document.getElementById("metric-total-detections");

    if (mTotal) mTotal.textContent = totalReports;
    if (mSchemas) mSchemas.textContent = schemasSet.size;
    if (mEvents) mEvents.textContent = totalEvents;
    if (mDetections) mDetections.textContent = totalDetections;

    // 2. Empty state check
    if (totalReports === 0) {
      if (views.empty) views.empty.classList.remove("hidden");
      if (views.tableContainer) views.tableContainer.classList.add("hidden");
      return;
    }

    if (views.empty) views.empty.classList.add("hidden");
    if (views.tableContainer) views.tableContainer.classList.remove("hidden");

    // 3. Render Table
    renderReportsTable();
  }

  function getFilteredReports() {
    const q = state.searchQuery.trim().toLowerCase();
    const type = state.typeFilter;

    return state.reports.filter(function (r) {
      if (type !== "all" && r.report_type !== type) {
        return false;
      }
      if (q) {
        const idMatch = (r.id || "").toLowerCase().includes(q);
        const nameMatch = (r.filename || "").toLowerCase().includes(q);
        const typeMatch = (r.report_type || "").toLowerCase().includes(q);
        const caseMatch = r.metadata && (r.metadata.case_id || "").toLowerCase().includes(q);
        return idMatch || nameMatch || typeMatch || caseMatch;
      }
      return true;
    });
  }

  function renderReportsTable() {
    const tbody = document.getElementById("reports-table-body");
    if (!tbody) return;
    clearNode(tbody);

    const filtered = getFilteredReports();

    if (filtered.length === 0) {
      const tr = el("tr");
      const td = el("td", "text-muted", "No matching reports found for the active filter.", {
        colspan: "7",
        style: "text-align: center; padding: 2rem;",
      });
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    filtered.forEach(function (report) {
      const tr = el("tr");

      // ID Cell
      const tdId = el("td", "report-id-cell", report.id);
      tr.appendChild(tdId);

      // Schema Type Cell with Badge
      const tdType = el("td");
      const typeBadge = el("span", "badge badge-type badge-" + report.report_type, formatTypeName(report.report_type));
      tdType.appendChild(typeBadge);
      tr.appendChild(tdType);

      // Filename Cell
      const tdFile = el("td", "filename-cell", report.filename || "—");
      tr.appendChild(tdFile);

      // Size Cell
      const tdSize = el("td", null, formatBytes(report.file_size_bytes));
      tr.appendChild(tdSize);

      // Counts Summary Cell
      const tdCounts = el("td");
      if (report.counts) {
        const countParts = [];
        if (report.counts.artifact_count) countParts.push(report.counts.artifact_count + " artifacts");
        if (report.counts.event_count) countParts.push(report.counts.event_count + " events");
        if (report.counts.correlation_count) countParts.push(report.counts.correlation_count + " correlations");
        if (report.counts.detection_count) countParts.push(report.counts.detection_count + " detections");
        if (countParts.length === 0) {
          tdCounts.textContent = "—";
        } else {
          tdCounts.textContent = countParts.join(" • ");
        }
      } else {
        tdCounts.textContent = "—";
      }
      tr.appendChild(tdCounts);

      // SHA-256 Hash Preview Cell
      const tdHash = el("td");
      const hashStr = report.sha256 || "";
      const hashPreview = hashStr.length > 16 ? hashStr.slice(0, 8) + "…" + hashStr.slice(-8) : hashStr;
      const hashSpan = el("span", "monospace-hash", hashPreview, { title: hashStr });
      tdHash.appendChild(hashSpan);
      tr.appendChild(tdHash);

      // Actions Cell
      const tdAction = el("td", "td-actions");
      const btnInspect = el("button", "btn btn-sm btn-secondary", "Inspect →", {
        type: "button",
        "data-report-id": report.id,
      });
      btnInspect.addEventListener("click", function () {
        navigateTo("#report/" + encodeURIComponent(report.id));
      });
      tdAction.appendChild(btnInspect);
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------------------
  // View 2: Report Explorer Rendering
  // ---------------------------------------------------------------------------
  function renderExplorer(reportId) {
    state.activeReportId = reportId;
    if (views.error) views.error.classList.add("hidden");
    if (views.overview) views.overview.classList.add("hidden");
    if (views.pivots) views.pivots.classList.add("hidden");
    if (views.explorer) views.explorer.classList.remove("hidden");

    const report =
      state.reportsById.get(reportId) ||
      (state.activeReportDetails && state.activeReportDetails.id === reportId
        ? state.activeReportDetails
        : null);

    // 1. Header Information
    const repIdEl = document.getElementById("explorer-report-id");
    const repTypeBadge = document.getElementById("explorer-report-type-badge");
    const expFilename = document.getElementById("exp-filename");
    const expFilesize = document.getElementById("exp-filesize");
    const expSha256 = document.getElementById("exp-sha256");

    if (repIdEl) repIdEl.textContent = reportId;
    if (repTypeBadge) {
      const typeStr = report ? report.report_type : "unknown";
      repTypeBadge.className = "badge badge-type badge-" + typeStr;
      repTypeBadge.textContent = formatTypeName(typeStr);
    }
    if (expFilename) expFilename.textContent = report && report.filename ? report.filename : "—";
    if (expFilesize) expFilesize.textContent = report ? formatBytes(report.file_size_bytes) : "—";

    if (expSha256) {
      clearNode(expSha256);
      const shaVal = report && report.sha256 ? report.sha256 : "—";
      expSha256.appendChild(document.createTextNode(shaVal));
      if (report && report.sha256 && report.sha256.length === 64) {
        const pivotInfo = {
          fieldType: "sha256",
          value: report.sha256.toLowerCase(),
          label: "Pivot on SHA-256: " + report.sha256.toLowerCase(),
        };
        expSha256.appendChild(createPivotButton(pivotInfo));
      }
    }

    // Back to Pivots button visibility
    const btnBackToPivots = document.getElementById("btn-back-to-pivots");
    if (btnBackToPivots) {
      if (state.lastPivotHash) {
        btnBackToPivots.classList.remove("hidden");
      } else {
        btnBackToPivots.classList.add("hidden");
      }
    }

    // 2. Tab Content Rendering
    renderMetadataTab(report);
    renderSummaryTab(report);
    renderRawTab(state.activeReportDetails ? state.activeReportDetails.raw_data : null);

    // Activate current tab
    switchTab(state.activeTab || "tab-metadata");
  }

  function renderMetadataTab(report) {
    const grid = document.getElementById("metadata-fields-grid");
    if (!grid) return;
    clearNode(grid);

    const meta = report && report.metadata ? report.metadata : {};
    const fields = [
      {
        key: "Case ID",
        val: meta.case_id,
        pivot: meta.case_id
          ? { fieldType: "case_id", value: meta.case_id.trim(), label: "Pivot on Case ID: " + meta.case_id }
          : null,
      },
      { key: "Case Name", val: meta.case_name },
      { key: "Investigator", val: meta.investigator },
      { key: "Created At (UTC)", val: meta.created_at },
      { key: "ForensiX Engine Version", val: meta.forensix_version },
      { key: "Target Evidence Root", val: meta.evidence_root },
      {
        key: "Source Report UUID",
        val: meta.report_id,
        pivot: meta.report_id
          ? {
              fieldType: "artifact_id",
              value: meta.report_id.trim(),
              identifierKind: "report_id",
              isAmbiguous: false,
              label: "Pivot on Report ID: " + meta.report_id,
            }
          : null,
      },
    ];

    fields.forEach(function (f) {
      const card = el("div", "meta-field-card");
      const name = el("div", "meta-field-name", f.key);
      const val = el("div", "meta-field-value", f.val || "—");
      if (f.pivot && f.val) {
        val.appendChild(createPivotButton(f.pivot));
      }
      card.appendChild(name);
      card.appendChild(val);
      grid.appendChild(card);
    });
  }

  function renderSummaryTab(report) {
    const grid = document.getElementById("summary-counts-grid");
    if (!grid) return;
    clearNode(grid);

    const counts = report && report.counts ? report.counts : {};
    const metricCards = [
      { title: "Artifacts Analyzed", num: counts.artifact_count || 0, desc: "Total forensic artifacts processed" },
      { title: "Timeline Events", num: counts.event_count || 0, desc: "Chronologically reconstructed events" },
      { title: "Correlations Identified", num: counts.correlation_count || 0, desc: "Discovered incident correlation links" },
      { title: "Detection Results", num: counts.detection_count || 0, desc: "Evaluated detection rule assertions" },
      { title: "Matched Detections", num: counts.matched_detection_count || 0, desc: "Positive detection rule matches" },
      { title: "Audit Log Records", num: counts.audit_event_count || 0, desc: "Verified pipeline execution audit events" },
    ];

    metricCards.forEach(function (m) {
      const card = el("div", "count-card");
      const title = el("div", "count-card-title", m.title);
      const num = el("div", "count-card-number", m.num);
      const desc = el("div", "count-card-desc", m.desc);
      card.appendChild(title);
      card.appendChild(num);
      card.appendChild(desc);
      grid.appendChild(card);
    });
  }

  // ---------------------------------------------------------------------------
  // JSON Tree Inspector (Safe DOM Construction)
  // ---------------------------------------------------------------------------
  function buildJsonTree(value, keyName, isRoot, parentKey) {
    const container = el("div", isRoot ? "tree-node tree-root" : "tree-node");

    if (value === null) {
      if (keyName !== undefined) {
        container.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      container.appendChild(el("span", "tree-null", "null"));
      return container;
    }

    const type = typeof value;

    if (type === "string") {
      if (keyName !== undefined) {
        container.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      container.appendChild(el("span", "tree-str", '"' + value + '"'));
      const pivotInfo = detectPivotField(keyName, value, parentKey);
      if (pivotInfo) {
        container.appendChild(createPivotButton(pivotInfo));
      }
      return container;
    }

    if (type === "number") {
      if (keyName !== undefined) {
        container.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      container.appendChild(el("span", "tree-num", String(value)));
      const pivotInfo = detectPivotField(keyName, value, parentKey);
      if (pivotInfo) {
        container.appendChild(createPivotButton(pivotInfo));
      }
      return container;
    }

    if (type === "boolean") {
      if (keyName !== undefined) {
        container.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      container.appendChild(el("span", "tree-bool", String(value)));
      return container;
    }

    if (Array.isArray(value)) {
      const header = el("div", "tree-header");
      const toggle = el("span", "tree-toggle", "▼");
      header.appendChild(toggle);

      if (keyName !== undefined) {
        header.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      header.appendChild(el("span", "tree-brackets", "["));
      header.appendChild(el("span", "tree-count-badge", value.length + " items"));

      const childrenContainer = el("div", "tree-children");
      value.forEach(function (item, idx) {
        childrenContainer.appendChild(buildJsonTree(item, String(idx), false, keyName));
      });

      const footer = el("div", "tree-footer");
      footer.appendChild(el("span", "tree-brackets", "]"));

      toggle.addEventListener("click", function () {
        const isCollapsed = childrenContainer.classList.toggle("hidden");
        toggle.classList.toggle("collapsed", isCollapsed);
      });

      container.appendChild(header);
      container.appendChild(childrenContainer);
      container.appendChild(footer);
      return container;
    }

    if (type === "object") {
      const keys = Object.keys(value);
      const header = el("div", "tree-header");
      const toggle = el("span", "tree-toggle", "▼");
      header.appendChild(toggle);

      if (keyName !== undefined) {
        header.appendChild(el("span", "tree-key", '"' + keyName + '": '));
      }
      header.appendChild(el("span", "tree-brackets", "{"));
      header.appendChild(el("span", "tree-count-badge", keys.length + " keys"));

      const childrenContainer = el("div", "tree-children");
      keys.forEach(function (k) {
        childrenContainer.appendChild(buildJsonTree(value[k], k, false, keyName));
      });

      const footer = el("div", "tree-footer");
      footer.appendChild(el("span", "tree-brackets", "}"));

      toggle.addEventListener("click", function () {
        const isCollapsed = childrenContainer.classList.toggle("hidden");
        toggle.classList.toggle("collapsed", isCollapsed);
      });

      container.appendChild(header);
      container.appendChild(childrenContainer);
      container.appendChild(footer);
      return container;
    }

    container.appendChild(el("span", "tree-str", String(value)));
    return container;
  }

  function renderRawTab(rawData) {
    const container = document.getElementById("json-tree-container");
    if (!container) return;
    clearNode(container);

    if (!rawData) {
      container.appendChild(el("div", "text-muted", "No raw forensic payload loaded."));
      return;
    }

    const tree = buildJsonTree(rawData, undefined, true);
    container.appendChild(tree);
  }

  function switchTab(tabId) {
    state.activeTab = tabId;
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(function (b) {
      if (b.getAttribute("data-tab") === tabId) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });

    const panels = ["tab-metadata", "tab-summary", "tab-raw"];
    panels.forEach(function (pid) {
      const p = document.getElementById(pid);
      if (p) {
        if (pid === tabId) {
          p.classList.remove("hidden");
          p.classList.add("active");
        } else {
          p.classList.add("hidden");
          p.classList.remove("active");
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // View 3: Cross-Domain Pivot Drill-Down Results Rendering
  // ---------------------------------------------------------------------------
  let currentPivotRequestId = 0;

  function setupPivotHeader(field, value, scope, identifierKind) {
    const qHeader = document.getElementById("pivot-header-query");
    const badgeField = document.getElementById("pivot-header-field-badge");
    const qField = document.getElementById("pivot-query-field");
    const qValue = document.getElementById("pivot-query-value");
    const qNorm = document.getElementById("pivot-query-normalized");
    const qCounts = document.getElementById("pivot-query-counts");

    if (qHeader) qHeader.textContent = value;
    if (badgeField) badgeField.textContent = field;
    if (qField) qField.textContent = field;
    if (qValue) qValue.textContent = value;
    if (qNorm) qNorm.textContent = "—";
    if (qCounts) qCounts.textContent = "Querying in-memory index…";

    // Namespace item
    const itemNs = document.getElementById("pivot-item-namespace");
    const qNs = document.getElementById("pivot-query-namespace");
    if (itemNs && qNs) {
      if (identifierKind) {
        qNs.textContent = identifierKind;
        itemNs.classList.remove("hidden");
      } else {
        itemNs.classList.add("hidden");
      }
    }

    // Scope item
    const itemScope = document.getElementById("pivot-item-scope");
    const qScope = document.getElementById("pivot-query-scope");
    if (itemScope && qScope) {
      if (scope) {
        qScope.textContent = scope;
        itemScope.classList.remove("hidden");
      } else {
        itemScope.classList.add("hidden");
      }
    }

    // Back to active report button
    const btnBackRep = document.getElementById("btn-pivot-back-report");
    if (btnBackRep) {
      if (state.previousReportId) {
        clearNode(btnBackRep);
        const iconSpan = el("span", "btn-icon", "← ");
        btnBackRep.appendChild(iconSpan);
        btnBackRep.appendChild(document.createTextNode("Back to Report (" + state.previousReportId + ")"));
        btnBackRep.classList.remove("hidden");
      } else {
        btnBackRep.classList.add("hidden");
      }
    }
  }

  async function executePivotQuery(field, value, scope, identifierKind) {
    const requestId = ++currentPivotRequestId;
    showLoading(true);
    hideAlert();

    if (views.overview) views.overview.classList.add("hidden");
    if (views.explorer) views.explorer.classList.add("hidden");
    if (views.error) views.error.classList.add("hidden");
    if (views.pivots) views.pivots.classList.remove("hidden");

    setupPivotHeader(field, value, scope, identifierKind);

    // PID pivot guard: require defensible scope
    if (field === "pid" && (!scope || !scope.trim())) {
      showLoading(false);
      renderPivotError(
        new Error("Evidence scope is required for exact PID cross-report matching. Unscoped PID queries are rejected.")
      );
      return;
    }

    try {
      const params = new URLSearchParams();
      params.set("field", field);
      params.set("value", value);
      if (scope) params.set("scope", scope);
      if (identifierKind) params.set("identifier_kind", identifierKind);

      const endpoint = "/api/pivots?" + params.toString();
      const data = await apiGet(endpoint);

      // Late response protection: ignore response if newer query initiated
      if (requestId !== currentPivotRequestId) {
        return;
      }

      showLoading(false);
      renderPivotResults(data);
    } catch (err) {
      if (requestId !== currentPivotRequestId) {
        return;
      }
      showLoading(false);
      renderPivotError(err);
    }
  }

  function renderPivotResults(data) {
    const qNorm = document.getElementById("pivot-query-normalized");
    const qCounts = document.getElementById("pivot-query-counts");
    const truncBanner = document.getElementById("pivot-truncation-banner");
    const truncText = document.getElementById("pivot-truncation-text");
    const badgeMatches = document.getElementById("pivot-matches-badge");
    const emptyState = document.getElementById("pivot-empty-state");
    const matchesList = document.getElementById("pivot-matches-list");

    if (qNorm) qNorm.textContent = data.normalized_query || "—";
    if (qCounts) {
      qCounts.textContent =
        data.returned_matches + " returned of " + data.total_matches + " total matches";
    }

    // Truncation banner
    if (truncBanner && truncText) {
      if (data.truncated) {
        truncText.textContent =
          "Query results truncated: displaying first " +
          data.returned_matches +
          " of " +
          data.total_matches +
          " total matches. Maximum query limit reached.";
        truncBanner.classList.remove("hidden");
      } else {
        truncBanner.classList.add("hidden");
      }
    }

    if (badgeMatches) {
      badgeMatches.textContent =
        data.total_matches + (data.total_matches === 1 ? " Match" : " Matches");
    }

    if (!matchesList) return;
    clearNode(matchesList);

    if (data.returned_matches === 0) {
      if (emptyState) {
        emptyState.classList.remove("hidden");
        const emptyDesc = document.getElementById("pivot-empty-desc");
        if (emptyDesc) {
          if (data.field_type === "ip_address") {
            emptyDesc.textContent =
              "No other reports contain this exact IP address. Notice: IP addresses identify observed communication endpoints and do not imply common machine identity.";
          } else {
            emptyDesc.textContent =
              "No other reports in the local registry contain this exact observed value.";
          }
        }
      }
      return;
    }

    if (emptyState) emptyState.classList.add("hidden");

    data.matches.forEach(function (match) {
      const card = el("div", "pivot-match-card");

      // Match Card Header
      const headerRow = el("div", "pivot-match-header");
      const titleDiv = el("div", "pivot-match-title");
      titleDiv.appendChild(el("strong", null, match.report_id));
      const typeBadge = el(
        "span",
        "badge badge-type badge-" + match.report_type,
        formatTypeName(match.report_type)
      );
      titleDiv.appendChild(typeBadge);
      headerRow.appendChild(titleDiv);

      const btnInspect = el("button", "btn btn-sm btn-secondary", "Inspect Report →", {
        type: "button",
      });
      btnInspect.addEventListener("click", function () {
        state.lastPivotHash = window.location.hash;
        navigateTo("#report/" + encodeURIComponent(match.report_id));
      });
      headerRow.appendChild(btnInspect);
      card.appendChild(headerRow);

      // Match Card Grid Properties
      const grid = el("div", "pivot-match-grid");

      // Field Path
      const itemPath = el("div", "pivot-match-item");
      itemPath.appendChild(el("span", "pivot-match-label", "Field Path"));
      itemPath.appendChild(el("span", "pivot-match-val monospace-tag", match.field_path));
      grid.appendChild(itemPath);

      // Identifier Kind (if present)
      if (match.identifier_kind) {
        const itemKind = el("div", "pivot-match-item");
        itemKind.appendChild(el("span", "pivot-match-label", "Identifier Namespace"));
        itemKind.appendChild(el("span", "pivot-match-val badge", match.identifier_kind));
        grid.appendChild(itemKind);
      }

      // Observed Value
      const itemObs = el("div", "pivot-match-item");
      itemObs.appendChild(el("span", "pivot-match-label", "Observed Value"));
      itemObs.appendChild(el("span", "pivot-match-val monospace-tag", String(match.observed_value)));
      grid.appendChild(itemObs);

      // Normalized Value
      const itemNorm = el("div", "pivot-match-item");
      itemNorm.appendChild(el("span", "pivot-match-label", "Normalized Value"));
      itemNorm.appendChild(el("span", "pivot-match-val monospace-hash", match.normalized_value));
      grid.appendChild(itemNorm);

      // Timestamp
      const itemTs = el("div", "pivot-match-item");
      itemTs.appendChild(el("span", "pivot-match-label", "Timestamp"));
      itemTs.appendChild(el("span", "pivot-match-val", match.timestamp || "—"));
      grid.appendChild(itemTs);

      // Evidence Scope
      const itemScope = el("div", "pivot-match-item");
      itemScope.appendChild(el("span", "pivot-match-label", "Evidence Scope"));
      itemScope.appendChild(el("span", "pivot-match-val", match.evidence_scope || "—"));
      grid.appendChild(itemScope);

      card.appendChild(grid);

      // Context Box
      if (match.context && typeof match.context === "object" && Object.keys(match.context).length > 0) {
        const ctxBox = el("div", "pivot-context-box");
        ctxBox.appendChild(el("div", "pivot-context-title", "Observed Context (Factual Metadata)"));
        for (const [k, v] of Object.entries(match.context)) {
          if (v !== null && v !== undefined && v !== "") {
            const ctxRow = el("div", "pivot-context-row");
            ctxRow.appendChild(el("span", "pivot-context-k", k + ":"));
            ctxRow.appendChild(el("span", "pivot-context-v", String(v)));
            ctxBox.appendChild(ctxRow);
          }
        }
        if (data.field_type === "ip_address") {
          const ipNote = el(
            "div",
            "text-muted",
            "Notice: IP address match indicates an observed communication endpoint and does not establish common host identity."
          );
          ctxBox.appendChild(ipNote);
        }
        card.appendChild(ctxBox);
      }

      matchesList.appendChild(card);
    });
  }

  function renderPivotError(err) {
    const qNorm = document.getElementById("pivot-query-normalized");
    const qCounts = document.getElementById("pivot-query-counts");
    const truncBanner = document.getElementById("pivot-truncation-banner");
    const badgeMatches = document.getElementById("pivot-matches-badge");
    const emptyState = document.getElementById("pivot-empty-state");
    const matchesList = document.getElementById("pivot-matches-list");

    if (qNorm) qNorm.textContent = "Error";
    if (qCounts) qCounts.textContent = "Query failed";
    if (truncBanner) truncBanner.classList.add("hidden");
    if (badgeMatches) badgeMatches.textContent = "Error";

    if (matchesList) clearNode(matchesList);

    if (emptyState) {
      emptyState.classList.remove("hidden");
      const emptyTitle = document.getElementById("pivot-empty-title");
      const emptyDesc = document.getElementById("pivot-empty-desc");
      if (emptyTitle) emptyTitle.textContent = "Query Error";
      if (emptyDesc) emptyDesc.textContent = "Pivot query failed: " + err.message;
    }
  }

  // ---------------------------------------------------------------------------
  // Routing & Hash Management
  // ---------------------------------------------------------------------------
  function handleHashRoute() {
    let hash = "";
    try {
      hash = window.location.hash || "";
    } catch (e) {
      hash = "";
    }

    if (hash.startsWith("#report/")) {
      let reportId = null;
      try {
        reportId = decodeURIComponent(hash.slice("#report/".length));
      } catch (e) {
        navigateTo("#overview");
        return;
      }
      if (reportId) {
        loadReportDetails(reportId);
        return;
      }
    }

    if (hash === "#pivots" || hash === "#pivot" || hash.startsWith("#pivots?") || hash.startsWith("#pivot?")) {
      const qIndex = hash.indexOf("?");
      if (qIndex === -1) {
        showError("Invalid Pivot Query", "Pivot queries require both 'field' and 'value' parameters.");
        return;
      }
      const queryStr = hash.slice(qIndex + 1);
      let params = null;
      try {
        params = new URLSearchParams(queryStr);
      } catch (e) {
        showError("Invalid Route", "Malformed pivot URL query parameters.");
        return;
      }

      const field = params.get("field");
      const value = params.get("value");
      const scope = params.get("scope");
      const identifierKind = params.get("identifier_kind");

      if (!field || !value) {
        showError("Invalid Pivot Query", "Pivot queries require both 'field' and 'value' parameters.");
        return;
      }

      executePivotQuery(field, value, scope, identifierKind);
      return;
    }

    // Default: Overview
    renderOverview();
  }

  // ---------------------------------------------------------------------------
  // Event Listeners & Initialization
  // ---------------------------------------------------------------------------
  function setupEventListeners() {
    // Hash routing
    window.addEventListener("hashchange", handleHashRoute);

    // Refresh button
    const btnRefresh = document.getElementById("btn-refresh");
    if (btnRefresh) {
      btnRefresh.addEventListener("click", function () {
        loadDashboard();
      });
    }

    // Error retry button
    const btnRetry = document.getElementById("btn-error-retry");
    if (btnRetry) {
      btnRetry.addEventListener("click", function () {
        loadDashboard();
      });
    }

    // Alert dismiss button
    const btnAlertDismiss = document.getElementById("btn-alert-dismiss");
    if (btnAlertDismiss) {
      btnAlertDismiss.addEventListener("click", hideAlert);
    }

    // Back to overview buttons
    const btnBack = document.getElementById("btn-back-overview");
    if (btnBack) {
      btnBack.addEventListener("click", function () {
        navigateTo("#overview");
      });
    }

    const btnPivotBackOverview = document.getElementById("btn-pivot-back-overview");
    if (btnPivotBackOverview) {
      btnPivotBackOverview.addEventListener("click", function () {
        navigateTo("#overview");
      });
    }

    // Back to active report from pivots
    const btnPivotBackReport = document.getElementById("btn-pivot-back-report");
    if (btnPivotBackReport) {
      btnPivotBackReport.addEventListener("click", function () {
        if (state.previousReportId) {
          navigateTo("#report/" + encodeURIComponent(state.previousReportId));
        } else {
          navigateTo("#overview");
        }
      });
    }

    // Back to pivots button in explorer
    const btnBackToPivots = document.getElementById("btn-back-to-pivots");
    if (btnBackToPivots) {
      btnBackToPivots.addEventListener("click", function () {
        if (state.lastPivotHash) {
          navigateTo(state.lastPivotHash);
        }
      });
    }

    // Search filter input
    const inputSearch = document.getElementById("input-search");
    if (inputSearch) {
      inputSearch.addEventListener("input", function (e) {
        state.searchQuery = e.target.value;
        renderReportsTable();
      });
    }

    // Type filter select
    const selectFilter = document.getElementById("select-type-filter");
    if (selectFilter) {
      selectFilter.addEventListener("change", function (e) {
        state.typeFilter = e.target.value;
        renderReportsTable();
      });
    }

    // Tab buttons
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        const targetTab = btn.getAttribute("data-tab");
        if (targetTab) switchTab(targetTab);
      });
    });

    // Expand/Collapse all JSON Tree nodes
    const btnExpand = document.getElementById("btn-expand-all");
    const btnCollapse = document.getElementById("btn-collapse-all");

    if (btnExpand) {
      btnExpand.addEventListener("click", function () {
        const hiddenContainers = document.querySelectorAll("#json-tree-container .tree-children.hidden");
        hiddenContainers.forEach(function (c) {
          c.classList.remove("hidden");
        });
        const toggles = document.querySelectorAll("#json-tree-container .tree-toggle.collapsed");
        toggles.forEach(function (t) {
          t.classList.remove("collapsed");
        });
      });
    }

    if (btnCollapse) {
      btnCollapse.addEventListener("click", function () {
        const children = document.querySelectorAll("#json-tree-container .tree-children");
        children.forEach(function (c) {
          c.classList.add("hidden");
        });
        const toggles = document.querySelectorAll("#json-tree-container .tree-toggle");
        toggles.forEach(function (t) {
          t.classList.add("collapsed");
        });
      });
    }

    // Modals: Artifact Namespace
    const btnCloseNs = document.getElementById("btn-close-namespace-modal");
    const btnCancelNs = document.getElementById("btn-cancel-namespace");
    const btnConfirmNs = document.getElementById("btn-confirm-namespace");
    if (btnCloseNs) btnCloseNs.addEventListener("click", closeNamespaceModal);
    if (btnCancelNs) btnCancelNs.addEventListener("click", closeNamespaceModal);
    if (btnConfirmNs) btnConfirmNs.addEventListener("click", confirmNamespaceModal);

    // Modals: PID Scope
    const btnClosePid = document.getElementById("btn-close-pid-modal");
    const btnCancelPid = document.getElementById("btn-cancel-pid");
    const btnConfirmPid = document.getElementById("btn-confirm-pid");
    if (btnClosePid) btnClosePid.addEventListener("click", closePidModal);
    if (btnCancelPid) btnCancelPid.addEventListener("click", closePidModal);
    if (btnConfirmPid) btnConfirmPid.addEventListener("click", confirmPidModal);

    const inputPid = document.getElementById("input-pid-scope-val");
    if (inputPid) {
      inputPid.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          confirmPidModal();
        }
      });
    }

    // Modal keyboard accessibility: Escape key dismisses modals
    window.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        closeNamespaceModal();
        closePidModal();
      }
    });

    // Backdrop click dismisses modals
    const modalNs = document.getElementById("modal-namespace");
    if (modalNs) {
      modalNs.addEventListener("click", function (e) {
        if (e.target === modalNs) closeNamespaceModal();
      });
    }

    const modalPid = document.getElementById("modal-pid-scope");
    if (modalPid) {
      modalPid.addEventListener("click", function (e) {
        if (e.target === modalPid) closePidModal();
      });
    }
  }

  // Bootstrap when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      setupEventListeners();
      loadDashboard();
    });
  } else {
    setupEventListeners();
    loadDashboard();
  }
})();
