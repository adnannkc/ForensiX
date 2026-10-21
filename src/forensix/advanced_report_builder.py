"""
Advanced Forensic Report Builder for ForensiX (V8.4).

Provides synthesis, deterministic serialization, and secure presentation of
ForensiX Schema 8.0 Advanced Forensic Reports.

Key Architectural Guarantees:
- Synthesizes explicit, already-analyzed evidence, manifest verification, and custody models.
- Deep immutability: returns validated, deeply frozen AdvancedReport instances.
- Zero filesystem modification of evidence: evidence files remain strictly read-only.
- Non-destructive reporting: rejects writing reports inside or overlapping evidence directories.
- Race-safe no-clobber semantics: refuses to overwrite existing output files by default.
- Fail-safe verification fidelity: faithfully preserves UNVERIFIED, TAMPERED, and MISMATCH statuses.
- XSS prevention: 100% strict escaping of dynamic content in air-gapped standalone HTML.
- Purely deterministic JSON output: sorted keys, fixed spacing, zero non-serializable objects.
"""

from collections.abc import Mapping
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import uuid

from forensix import __version__
from forensix.advanced_report_models import (
    ADVANCED_REPORT_SCHEMA_VERSION,
    DEFAULT_ANALYTICAL_DISCLAIMER,
    AdvancedReport,
    AnalyticalLimitations,
    CustodySummary,
    EvidenceInventoryItem,
    FindingsSummary,
    generate_advanced_report_id,
    is_valid_advanced_report_id,
)
from forensix.custody_ledger import CustodyLedger
from forensix.custody_models import CUSTODY_LIMITATIONS_DISCLAIMER
from forensix.investigation import InvestigationResultSet
from forensix.manifest_models import ManifestRecord
from forensix.manifest_verifier import (
    MANIFEST_VERIFICATION_NOTICE,
    ManifestVerificationResult,
)
from forensix.unified_models import HostArtifact, HostArtifactCollection


def esc(value: Any) -> str:
    """
    Safely escape a value for inclusion in HTML attributes or body text.

    Args:
        value: Any primitive or stringifiable object.

    Returns:
        str: HTML-safe escaped string, or '<em>None</em>' if None.
    """
    if value is None:
        return "<em>None</em>"
    return html.escape(str(value), quote=True)


def _safe_write_file(
    content: str,
    output_path: Union[str, Path],
    overwrite: bool = False,
    evidence_root: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Safely write string content to destination file enforcing evidence boundary safety
    and race-safe atomic creation.

    Args:
        content: UTF-8 string content to write.
        output_path: Target file path.
        overwrite: If False, atomically reject existing file without clobbering.
        evidence_root: Optional evidence root to prevent report-evidence collision.

    Returns:
        Path: Resolved Path of the written report.

    Raises:
        ValueError: If destination path overlaps or is inside evidence_root.
        FileExistsError: If destination exists and overwrite is False.
        IsADirectoryError: If destination is an existing directory.
        OSError: If filesystem operations fail.
    """
    dest = Path(output_path).resolve()

    # 1. Enforce evidence directory separation (even if overwrite=True)
    if evidence_root is not None:
        ev_root = Path(evidence_root).resolve()
        if dest == ev_root or dest.is_relative_to(ev_root):
            raise ValueError(
                f"Forensic safety violation: report output path '{dest}' "
                f"overlaps or is located inside evidence root '{ev_root}'"
            )

    # 2. Check for directory collisions
    if dest.is_dir():
        raise IsADirectoryError(f"Destination path is a directory: '{dest}'")

    # 3. Ensure parent directory exists
    dest.parent.mkdir(parents=True, exist_ok=True)

    # 4. Atomic write
    if not overwrite:
        # Kernel-level atomic exclusive creation (O_CREAT | O_EXCL) prevents race-condition clobbering
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            raise FileExistsError(
                f"Report destination already exists and overwrite is False: '{dest}'"
            )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                pass
            raise
    else:
        # Atomic overwrite: write to unique sibling temporary file, then atomic rename (os.replace)
        temp_dest = dest.parent / f".tmp.{dest.name}.{os.getpid()}.{uuid.uuid4().hex}"
        try:
            with open(temp_dest, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temp_dest, dest)
        except Exception:
            try:
                temp_dest.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    return dest


def build_advanced_report(
    case_metadata: Mapping[str, Any],
    manifest: Optional[ManifestRecord] = None,
    manifest_verification: Optional[ManifestVerificationResult] = None,
    evidence_inventory: Optional[Sequence[EvidenceInventoryItem]] = None,
    custody_ledger: Optional[CustodyLedger] = None,
    custody_summary: Optional[CustodySummary] = None,
    investigation_results: Optional[
        Union[InvestigationResultSet, HostArtifactCollection, Sequence[HostArtifact]]
    ] = None,
    findings_summary: Optional[FindingsSummary] = None,
    warnings: Optional[Sequence[str]] = None,
    omissions: Optional[Sequence[str]] = None,
    evidentiary_disclaimer: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
    report_id: Optional[str] = None,
    created_at: Optional[str] = None,
    forensix_version: str = __version__,
) -> AdvancedReport:
    """
    Construct an immutable ForensiX Schema 8.0 Advanced Forensic Report.

    Integrates explicit evidence manifests, verification outcomes, runtime custody
    ledgers, and investigation metrics into a strongly typed, verifiable report.

    Args:
        case_metadata: Mapping containing administrative case parameters.
        manifest: Optional ManifestRecord for evidence inventory synthesis.
        manifest_verification: Optional ManifestVerificationResult providing verification statuses.
        evidence_inventory: Optional pre-constructed sequence of EvidenceInventoryItem instances.
        custody_ledger: Optional runtime CustodyLedger instance.
        custody_summary: Optional pre-constructed CustodySummary instance.
        investigation_results: Optional investigation result set or artifact collection.
        findings_summary: Optional pre-constructed FindingsSummary counters.
        warnings: Optional caller-specified analytical warnings.
        omissions: Optional caller-specified scope omissions.
        evidentiary_disclaimer: Optional override for the standard evidentiary disclaimer text.
        details: Optional granular mapping of findings, timeline events, or correlations.
        report_id: Optional canonical report ID (conforming to REP8-<UUIDv4>).
        created_at: Optional ISO 8601 UTC timestamp string.
        forensix_version: Software release version string.

    Returns:
        AdvancedReport: Immutable, validated Schema 8.0 advanced forensic report.

    Raises:
        TypeError: If an argument fails type validation.
        ValueError: If input values conflict or are structurally invalid.
    """
    # 1. Validate case_metadata
    if not isinstance(case_metadata, Mapping):
        raise TypeError(
            f"case_metadata must be a Mapping, got {type(case_metadata).__name__}"
        )

    accumulated_warnings: List[str] = list(warnings) if warnings else []
    accumulated_omissions: List[str] = list(omissions) if omissions else []

    # 2. Reconcile Custody Summary
    final_custody_summary: Optional[CustodySummary] = None

    if custody_ledger is not None and custody_summary is not None:
        if not isinstance(custody_ledger, CustodyLedger):
            raise TypeError(
                f"custody_ledger must be CustodyLedger, got {type(custody_ledger).__name__}"
            )
        if not isinstance(custody_summary, CustodySummary):
            raise TypeError(
                f"custody_summary must be CustodySummary, got {type(custody_summary).__name__}"
            )
        if custody_ledger.ledger_id != custody_summary.ledger_id:
            raise ValueError(
                f"Conflicting custody identifiers: custody_ledger id '{custody_ledger.ledger_id}' "
                f"does not match custody_summary id '{custody_summary.ledger_id}'"
            )
        final_custody_summary = custody_summary

    elif custody_ledger is not None:
        if not isinstance(custody_ledger, CustodyLedger):
            raise TypeError(
                f"custody_ledger must be CustodyLedger, got {type(custody_ledger).__name__}"
            )
        # Check case_id consistency if both present
        case_meta_id = case_metadata.get("case_id")
        if (
            case_meta_id is not None
            and custody_ledger.case_id is not None
            and str(case_meta_id).strip()
            and str(custody_ledger.case_id).strip()
        ):
            if str(case_meta_id).strip() != str(custody_ledger.case_id).strip():
                raise ValueError(
                    f"Conflicting case_id: case_metadata '{case_meta_id}' "
                    f"does not match custody_ledger '{custody_ledger.case_id}'"
                )
        final_custody_summary = custody_ledger.get_custody_summary()

    elif custody_summary is not None:
        if not isinstance(custody_summary, CustodySummary):
            raise TypeError(
                f"custody_summary must be CustodySummary, got {type(custody_summary).__name__}"
            )
        final_custody_summary = custody_summary

    # Audit custody status fidelity and record limitations
    if final_custody_summary is not None:
        if final_custody_summary.total_events == 0:
            accumulated_warnings.append(
                "Chain-of-custody ledger contains 0 events; custody chain status is UNVERIFIED."
            )
        elif final_custody_summary.chain_integrity == "TAMPERED":
            accumulated_warnings.append(
                "CRITICAL WARNING: Chain-of-custody verification failed with status TAMPERED; "
                "ledger records may have been altered, reordered, or deleted."
            )
        elif final_custody_summary.chain_integrity == "UNVERIFIED":
            accumulated_warnings.append(
                "Chain-of-custody verification status is UNVERIFIED; hash chain has not been validated."
            )

    # 3. Reconcile Evidence Inventory
    if evidence_inventory is not None and manifest is not None:
        raise ValueError(
            "Conflicting inventory sources: provide either 'evidence_inventory' or 'manifest', not both"
        )

    final_inventory: List[EvidenceInventoryItem] = []

    if evidence_inventory is not None:
        if not isinstance(evidence_inventory, (list, tuple)):
            raise TypeError(
                f"evidence_inventory must be a Sequence, got {type(evidence_inventory).__name__}"
            )
        for idx, item in enumerate(evidence_inventory):
            if not isinstance(item, EvidenceInventoryItem):
                raise TypeError(
                    f"Item at index {idx} in evidence_inventory is {type(item).__name__}, "
                    "expected EvidenceInventoryItem"
                )
            final_inventory.append(item)

    elif manifest is not None:
        if not isinstance(manifest, ManifestRecord):
            raise TypeError(
                f"manifest must be ManifestRecord, got {type(manifest).__name__}"
            )

        # Reconcile manifest.case_id against case_metadata["case_id"]
        case_meta_id = case_metadata.get("case_id")
        if (
            case_meta_id is not None
            and manifest.case_id is not None
            and str(case_meta_id).strip()
            and str(manifest.case_id).strip()
        ):
            if str(case_meta_id).strip() != str(manifest.case_id).strip():
                raise ValueError(
                    f"Conflicting case_id: case_metadata '{case_meta_id}' "
                    f"does not match manifest.case_id '{manifest.case_id}'"
                )

        if (
            custody_ledger is not None
            and custody_ledger.case_id is not None
            and manifest.case_id is not None
            and str(custody_ledger.case_id).strip()
            and str(manifest.case_id).strip()
        ):
            if str(custody_ledger.case_id).strip() != str(manifest.case_id).strip():
                raise ValueError(
                    f"Conflicting case_id: custody_ledger '{custody_ledger.case_id}' "
                    f"does not match manifest.case_id '{manifest.case_id}'"
                )

        verif_map: Dict[str, Any] = {}
        if manifest_verification is not None:
            if not isinstance(manifest_verification, ManifestVerificationResult):
                raise TypeError(
                    f"manifest_verification must be ManifestVerificationResult, "
                    f"got {type(manifest_verification).__name__}"
                )
            if manifest_verification.manifest_id != manifest.manifest_id:
                raise ValueError(
                    f"Conflicting manifest_id: manifest '{manifest.manifest_id}' "
                    f"does not match manifest_verification '{manifest_verification.manifest_id}'"
                )
            for entry_res in manifest_verification.entry_results:
                verif_map[entry_res.relative_path] = entry_res

            # Record manifest verification discrepancy warnings
            if manifest_verification.mismatch_count > 0:
                accumulated_warnings.append(
                    f"Manifest verification discrepancy: {manifest_verification.mismatch_count} "
                    "hash mismatch(es) detected between recorded baseline and current evidence bytes."
                )
            if manifest_verification.missing_count > 0:
                accumulated_warnings.append(
                    f"Manifest verification discrepancy: {manifest_verification.missing_count} "
                    "evidence file(s) recorded in manifest are missing from filesystem."
                )
            if manifest_verification.error_count > 0:
                accumulated_warnings.append(
                    f"Manifest verification error: {manifest_verification.error_count} "
                    "entry error(s) (permission, symlink, or algorithm) encountered during verification."
                )

        # Build inventory from manifest entries
        for entry in manifest.entries:
            ev_status: Optional[str] = None
            if entry.relative_path in verif_map:
                v_entry = verif_map[entry.relative_path]
                ev_status = v_entry.status.value

            ev_id = (
                entry.evidence_id
                if entry.evidence_id
                else f"EV-{entry.relative_path}"
            )

            item = EvidenceInventoryItem(
                evidence_id=str(ev_id),
                relative_path=entry.relative_path,
                size_bytes=entry.size_bytes,
                hashes=entry.hashes,
                registration_timestamp=manifest.created_at,
                verification_status=ev_status,
            )
            final_inventory.append(item)

    else:
        accumulated_omissions.append("Evidence inventory was not provided.")

    # 4. Reconcile Findings Summary
    final_findings: FindingsSummary

    if findings_summary is not None:
        if not isinstance(findings_summary, FindingsSummary):
            raise TypeError(
                f"findings_summary must be FindingsSummary, got {type(findings_summary).__name__}"
            )
        final_findings = findings_summary

    elif investigation_results is not None:
        if isinstance(investigation_results, InvestigationResultSet):
            art_count = len(investigation_results.artifacts)
            final_findings = FindingsSummary(total_host_artifacts=art_count)
        elif isinstance(investigation_results, HostArtifactCollection):
            art_count = len(investigation_results.artifacts)
            final_findings = FindingsSummary(total_host_artifacts=art_count)
        elif isinstance(investigation_results, (list, tuple)):
            for idx, a in enumerate(investigation_results):
                if not isinstance(a, HostArtifact):
                    raise TypeError(
                        f"Item at index {idx} in investigation_results is {type(a).__name__}, "
                        "expected HostArtifact"
                    )
            final_findings = FindingsSummary(total_host_artifacts=len(investigation_results))
        else:
            raise TypeError(
                "investigation_results must be InvestigationResultSet, HostArtifactCollection, "
                f"or Sequence[HostArtifact], got {type(investigation_results).__name__}"
            )
    else:
        final_findings = FindingsSummary()

    # 5. Reconcile Analytical Limitations & Evidentiary Disclaimers
    # Deduplicate warnings and omissions while preserving chronological insertion order
    dedup_warnings = list(dict.fromkeys(accumulated_warnings))
    dedup_omissions = list(dict.fromkeys(accumulated_omissions))

    if evidentiary_disclaimer is not None:
        if not isinstance(evidentiary_disclaimer, str) or not evidentiary_disclaimer.strip():
            raise ValueError("evidentiary_disclaimer must be a non-empty string if provided")
        final_disclaimer = evidentiary_disclaimer.strip()
    else:
        disclaimers = [DEFAULT_ANALYTICAL_DISCLAIMER]
        if final_custody_summary is not None:
            disclaimers.append(CUSTODY_LIMITATIONS_DISCLAIMER)
        if manifest is not None or manifest_verification is not None:
            disclaimers.append(MANIFEST_VERIFICATION_NOTICE)
        final_disclaimer = "\n\n".join(disclaimers)

    final_limitations = AnalyticalLimitations(
        warnings=tuple(dedup_warnings),
        omissions=tuple(dedup_omissions),
        evidentiary_disclaimer=final_disclaimer,
    )

    # 6. Report Identifiers and Timestamps
    if report_id is None:
        rep_id = generate_advanced_report_id()
    else:
        if not is_valid_advanced_report_id(report_id):
            raise ValueError(
                f"Invalid report_id '{report_id}': must conform to canonical REP8-<UUIDv4>"
            )
        rep_id = str(report_id)

    rep_created_at = (
        created_at
        if created_at is not None
        else datetime.now(timezone.utc).isoformat()
    )

    return AdvancedReport(
        report_schema=ADVANCED_REPORT_SCHEMA_VERSION,
        report_id=rep_id,
        created_at=rep_created_at,
        forensix_version=forensix_version,
        case_metadata=case_metadata,
        evidence_inventory=tuple(final_inventory),
        findings_summary=final_findings,
        limitations=final_limitations,
        custody_summary=final_custody_summary,
        details=details,
    )


def render_advanced_report_json(report: AdvancedReport, indent: int = 2) -> str:
    """
    Render an AdvancedReport instance as a formatted, canonical UTF-8 JSON string.

    Guarantees:
    - Standard JSON compliance with sorted dictionary keys.
    - Deterministic layout for identical report contents.
    - Zero non-serializable object pointers.

    Args:
        report: AdvancedReport instance.
        indent: Number of spaces for JSON indentation (default: 2).

    Returns:
        str: Canonical UTF-8 JSON string representation.

    Raises:
        TypeError: If report is not an AdvancedReport.
    """
    if not isinstance(report, AdvancedReport):
        raise TypeError(f"report must be AdvancedReport, got {type(report).__name__}")

    data = report.to_dict()
    return json.dumps(data, indent=indent, sort_keys=True, ensure_ascii=False)


def write_advanced_report_json(
    report: AdvancedReport,
    output_path: Union[str, Path],
    indent: int = 2,
    overwrite: bool = False,
    evidence_root: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Safely write rendered JSON advanced report to disk.

    Enforces forensic safety checks:
    - Never writes inside evidence_root.
    - Automatically checks report.case_metadata['evidence_root'] if not explicitly passed.
    - Refuses to overwrite existing files unless overwrite=True.

    Args:
        report: AdvancedReport instance.
        output_path: Destination file path.
        indent: JSON indentation spaces.
        overwrite: If True, allows atomic replacement of existing file.
        evidence_root: Optional evidence root path to enforce separation.

    Returns:
        Path: Resolved Path to written JSON report file.
    """
    if evidence_root is None and "evidence_root" in report.case_metadata:
        ev_val = report.case_metadata.get("evidence_root")
        if ev_val:
            evidence_root = str(ev_val)

    content = render_advanced_report_json(report, indent=indent)
    return _safe_write_file(
        content=content,
        output_path=output_path,
        overwrite=overwrite,
        evidence_root=evidence_root,
    )


def render_advanced_report_html(report: AdvancedReport) -> str:
    """
    Render an AdvancedReport instance as a standalone, air-gapped, XSS-safe HTML5 document.

    Guarantees:
    - Completely self-contained with zero CDN links, external scripts, or fonts.
    - 100% strict HTML escaping of untrusted evidence data and metadata.
    - Semantic structure matching Schema 8.0:
      1. Case Information & Metadata
      2. Chain of Custody Summary & Verification Status
      3. Evidence Inventory & Manifest Verification Status
      4. Findings & Analytical Metrics
      5. Granular Investigation Details (if present)
      6. Analytical Limitations, Warnings, and Evidentiary Disclaimers

    Args:
        report: AdvancedReport instance.

    Returns:
        str: Standalone HTML5 document string.

    Raises:
        TypeError: If report is not an AdvancedReport.
    """
    if not isinstance(report, AdvancedReport):
        raise TypeError(f"report must be AdvancedReport, got {type(report).__name__}")

    meta = report.case_metadata
    findings = report.findings_summary
    custody = report.custody_summary
    limitations = report.limitations

    # 1. Case Metadata Table Rows
    meta_rows = []
    for k in sorted(meta.keys()):
        val = meta[k]
        val_str = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
        meta_rows.append(
            f"<tr><th>{esc(k)}</th><td><code>{esc(val_str)}</code></td></tr>"
        )
    meta_table = "\n".join(meta_rows) if meta_rows else "<tr><td colspan='2'><em>No metadata provided.</em></td></tr>"

    # 2. Custody Section
    if custody is not None:
        c_status = custody.chain_integrity.upper()
        if c_status == "VERIFIED":
            c_badge = "<span class='badge badge-verified'>VERIFIED</span>"
        elif c_status == "TAMPERED":
            c_badge = "<span class='badge badge-tampered'>TAMPERED</span>"
        else:
            c_badge = "<span class='badge badge-unverified'>UNVERIFIED</span>"

        custody_html = f"""
        <div class="card">
            <h2>Chain of Custody Summary</h2>
            <table class="data-table">
                <tr><th>Ledger ID</th><td><code>{esc(custody.ledger_id)}</code></td></tr>
                <tr><th>Total Custody Events</th><td class="num">{custody.total_events}</td></tr>
                <tr><th>Terminal Event Hash</th><td><code>{esc(custody.terminal_hash)}</code></td></tr>
                <tr><th>Chain Integrity Status</th><td>{c_badge}</td></tr>
            </table>
        </div>
        """
    else:
        custody_html = """
        <div class="card">
            <h2>Chain of Custody Summary</h2>
            <p><em>No chain-of-custody ledger record was associated with this report.</em></p>
        </div>
        """

    # 3. Evidence Inventory Table
    inv_rows = []
    for item in report.evidence_inventory:
        status_val = item.verification_status
        if status_val == "MATCH" or status_val == "VERIFIED":
            status_badge = f"<span class='badge badge-verified'>{esc(status_val)}</span>"
        elif status_val == "MISMATCH":
            status_badge = f"<span class='badge badge-tampered'>{esc(status_val)}</span>"
        elif status_val in ("FILE_MISSING", "PERMISSION_DENIED", "UNSUPPORTED_ALGORITHM"):
            status_badge = f"<span class='badge badge-unverified'>{esc(status_val)}</span>"
        elif status_val is not None:
            status_badge = f"<span class='badge badge-neutral'>{esc(status_val)}</span>"
        else:
            status_badge = "<em>Unverified</em>"

        hash_list = []
        for algo, hval in item.hashes:
            hash_list.append(f"<div><strong>{esc(algo.upper())}:</strong> <code>{esc(hval)}</code></div>")
        hash_cell = "".join(hash_list) if hash_list else "<em>None</em>"

        inv_rows.append(
            f"<tr>"
            f"<td><code>{esc(item.evidence_id)}</code></td>"
            f"<td><span class='path-cell'>{esc(item.relative_path)}</span></td>"
            f"<td class='num'>{item.size_bytes:,}</td>"
            f"<td>{hash_cell}</td>"
            f"<td><small>{esc(item.registration_timestamp)}</small></td>"
            f"<td>{status_badge}</td>"
            f"</tr>"
        )
    inv_table = "\n".join(inv_rows) if inv_rows else "<tr><td colspan='6'><em>No evidence inventory recorded.</em></td></tr>"

    # 4. Details Section (if present)
    details_html = ""
    if report.details:
        details_json = json.dumps(report.to_dict().get("details", {}), indent=2, sort_keys=True, ensure_ascii=False)
        details_html = f"""
        <div class="card">
            <h2>Investigation Details</h2>
            <details>
                <summary>Click to view granular details JSON</summary>
                <pre class="code-box">{esc(details_json)}</pre>
            </details>
        </div>
        """

    # 5. Limitations & Disclaimers
    warnings_list = "".join(f"<li>{esc(w)}</li>" for w in limitations.warnings)
    warnings_html = f"<ul class='warnings-list'>{warnings_list}</ul>" if warnings_list else "<p><em>None</em></p>"

    omissions_list = "".join(f"<li>{esc(o)}</li>" for o in limitations.omissions)
    omissions_html = f"<ul class='omissions-list'>{omissions_list}</ul>" if omissions_list else "<p><em>None</em></p>"

    # HTML Document Template
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForensiX Advanced Forensic Report - {esc(report.report_id)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --verified-bg: #064e3b;
            --verified-text: #34d399;
            --tampered-bg: #7f1d1d;
            --tampered-text: #f87171;
            --unverified-bg: #78350f;
            --unverified-text: #fbbf24;
            --neutral-bg: #334155;
            --neutral-text: #cbd5e1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            border-bottom: 2px solid var(--card-border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        h1 {{ font-size: 1.8rem; color: var(--text-main); }}
        .header-meta {{ font-size: 0.9rem; color: var(--text-muted); }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h2 {{ font-size: 1.3rem; margin-bottom: 1rem; color: var(--accent); border-bottom: 1px solid var(--card-border); padding-bottom: 0.5rem; }}
        h3 {{ font-size: 1.1rem; margin: 1rem 0 0.5rem; color: var(--text-main); }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        .data-table th, .data-table td {{
            padding: 0.6rem 0.8rem;
            text-align: left;
            border-bottom: 1px solid var(--card-border);
        }}
        .data-table th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            font-weight: 600;
        }}
        .data-table tr:hover {{ background-color: rgba(51, 65, 85, 0.4); }}
        .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
        .path-cell {{ font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; word-break: break-all; }}
        code {{
            font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
            background-color: rgba(15, 23, 42, 0.8);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge-verified {{ background-color: var(--verified-bg); color: var(--verified-text); }}
        .badge-tampered {{ background-color: var(--tampered-bg); color: var(--tampered-text); }}
        .badge-unverified {{ background-color: var(--unverified-bg); color: var(--unverified-text); }}
        .badge-neutral {{ background-color: var(--neutral-bg); color: var(--neutral-text); }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        .metric-box {{
            background-color: rgba(15, 23, 42, 0.5);
            border: 1px solid var(--card-border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .metric-value {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
        .metric-label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }}
        .warnings-list, .omissions-list {{ margin-left: 1.5rem; margin-bottom: 1rem; }}
        .warnings-list li {{ color: var(--tampered-text); margin-bottom: 0.3rem; }}
        .omissions-list li {{ color: var(--unverified-text); margin-bottom: 0.3rem; }}
        .disclaimer-box {{
            background-color: rgba(15, 23, 42, 0.7);
            border-left: 4px solid var(--accent);
            padding: 1rem;
            font-size: 0.85rem;
            color: var(--text-muted);
            white-space: pre-line;
            border-radius: 0 4px 4px 0;
        }}
        .code-box {{
            background-color: rgba(15, 23, 42, 0.9);
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.85rem;
            margin-top: 0.5rem;
            border: 1px solid var(--card-border);
        }}
        details summary {{ cursor: pointer; color: var(--accent); font-weight: 600; padding: 0.3rem 0; }}
        footer {{
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-top: 1px solid var(--card-border);
            padding-top: 1rem;
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>ForensiX Advanced Forensic Report</h1>
                <div class="header-meta">Report ID: <code>{esc(report.report_id)}</code> | Schema: <code>{esc(report.report_schema)}</code></div>
            </div>
            <div class="header-meta" style="text-align: right;">
                <div>Generated: {esc(report.created_at)}</div>
                <div>ForensiX Version: {esc(report.forensix_version)}</div>
            </div>
        </header>

        <!-- Section 1: Case Information -->
        <div class="card">
            <h2>Case Information</h2>
            <table class="data-table">
                {meta_table}
            </table>
        </div>

        <!-- Section 2: Chain of Custody -->
        {custody_html}

        <!-- Section 3: Evidence Inventory -->
        <div class="card">
            <h2>Evidence Inventory</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Evidence ID</th>
                        <th>Relative Path</th>
                        <th class="num">Size (Bytes)</th>
                        <th>Cryptographic Hashes</th>
                        <th>Registered</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {inv_table}
                </tbody>
            </table>
        </div>

        <!-- Section 4: Analytical Findings Summary -->
        <div class="card">
            <h2>Analytical Findings Summary</h2>
            <div class="metrics-grid">
                <div class="metric-box">
                    <div class="metric-value">{findings.total_host_artifacts:,}</div>
                    <div class="metric-label">Host Artifacts</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{findings.total_timeline_events:,}</div>
                    <div class="metric-label">Timeline Events</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{findings.total_correlations:,}</div>
                    <div class="metric-label">Correlations</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{findings.total_rule_evaluations:,}</div>
                    <div class="metric-label">Rule Evaluations</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{findings.matched_detections:,}</div>
                    <div class="metric-label">Matched Detections</div>
                </div>
            </div>
        </div>

        <!-- Section 5: Investigation Details (Optional) -->
        {details_html}

        <!-- Section 6: Analytical Limitations & Disclaimers -->
        <div class="card">
            <h2>Analytical Limitations &amp; Evidentiary Disclaimers</h2>
            <h3>Warnings</h3>
            {warnings_html}

            <h3>Scope Omissions</h3>
            {omissions_html}

            <h3>Evidentiary Notices</h3>
            <div class="disclaimer-box">{esc(limitations.evidentiary_disclaimer)}</div>
        </div>

        <footer>
            ForensiX Forensic Investigation Platform &bull; Offline Air-Gapped Verifiable Artifact
        </footer>
    </div>
</body>
</html>
"""


def write_advanced_report_html(
    report: AdvancedReport,
    output_path: Union[str, Path],
    overwrite: bool = False,
    evidence_root: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Safely write rendered standalone HTML advanced report to disk.

    Enforces forensic safety checks:
    - Never writes inside evidence_root.
    - Automatically checks report.case_metadata['evidence_root'] if not explicitly passed.
    - Refuses to overwrite existing files unless overwrite=True.

    Args:
        report: AdvancedReport instance.
        output_path: Destination file path.
        overwrite: If True, allows atomic replacement of existing file.
        evidence_root: Optional evidence root path to enforce separation.

    Returns:
        Path: Resolved Path to written HTML report file.
    """
    if evidence_root is None and "evidence_root" in report.case_metadata:
        ev_val = report.case_metadata.get("evidence_root")
        if ev_val:
            evidence_root = str(ev_val)

    content = render_advanced_report_html(report)
    return _safe_write_file(
        content=content,
        output_path=output_path,
        overwrite=overwrite,
        evidence_root=evidence_root,
    )
