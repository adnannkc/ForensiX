"""
Advanced Forensic Triage Orchestrator for ForensiX (V8.5).

Coordinates end-to-end evidence ingestion, manifest baseline integrity verification,
runtime chain-of-custody tracking, and Schema 8.0 Advanced Forensic Report synthesis
while guaranteeing:
1. Strict read-only access to forensic evidence.
2. Output isolation ensuring reports and ledgers never overlap evidence directories.
3. Strict no-clobber and atomic single-file replacement semantics.
4. Cryptographic integrity and anti-silent-regeneration for resumed custody ledgers.
5. Explicit, honest evidentiary boundary separation between evidence custody and report publication.
6. Fail-safe preservation of manifest mismatches and missing files.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from forensix.advanced_report_builder import (
    build_advanced_report,
    write_advanced_report_html,
    write_advanced_report_json,
)
from forensix.advanced_report_models import (
    AdvancedReport,
    CustodySummary,
    FindingsSummary,
)
from forensix.custody_ledger import (
    CustodyChainVerificationResult,
    CustodyLedger,
)
from forensix.custody_models import (
    CustodyActionType,
    CustodyActor,
    CustodyEvent,
    TimestampSource,
)
from forensix.investigation import InvestigationResultSet
from forensix.manifest_models import (
    ManifestEntry,
    ManifestRecord,
)
from forensix.manifest_verifier import (
    ManifestVerificationResult,
    verify_manifest,
)
from forensix.unified_models import HostArtifact, HostArtifactCollection


class CustodyIntegrityError(ValueError):
    """Raised when a resumed or generated chain of custody fails cryptographic or sequential validation."""
    pass


@dataclass(frozen=True)
class AdvancedTriageConfig:
    """
    Immutable configuration specification for an advanced forensic triage workflow.

    Attributes:
        evidence_directory: Root directory containing evidence files (must exist, read-only).
        output_dir: Directory where generated reports and ledgers will be written.
        case_metadata: Case administrative context (case_id, case_name, investigator, etc.).
        manifest_path: Optional path to an evidence manifest JSON file.
        custody_ledger_path: Optional path to an existing custody ledger JSON file to resume.
        actor: Optional CustodyActor performing or supervising the triage workflow.
        findings_summary: Optional caller-supplied FindingsSummary metrics.
        investigation_results: Optional pre-extracted InvestigationResultSet or host artifacts.
        details: Optional granular dictionary of findings, timeline events, or correlations.
        formats: Sequence of report formats to produce (subset of 'json', 'html').
        allow_symlinks: If True, symlinks within evidence root are followed during verification.
        overwrite: If True, existing output files are atomically replaced.
        verify_only: If True, performs manifest verification and custody tracking without analysis.
        json_output_name: Optional explicit filename for the JSON report.
        html_output_name: Optional explicit filename for the HTML report.
        ledger_output_name: Optional explicit filename for the custody ledger JSON.
    """

    evidence_directory: Union[str, Path]
    output_dir: Union[str, Path] = Path("reports")
    case_metadata: Mapping[str, Any] = field(default_factory=dict)
    manifest_path: Optional[Union[str, Path]] = None
    custody_ledger_path: Optional[Union[str, Path]] = None
    actor: Optional[CustodyActor] = None
    findings_summary: Optional[FindingsSummary] = None
    investigation_results: Optional[
        Union[InvestigationResultSet, HostArtifactCollection, Sequence[HostArtifact]]
    ] = None
    details: Optional[Mapping[str, Any]] = None
    formats: Tuple[str, ...] = ("html", "json")
    allow_symlinks: bool = False
    overwrite: bool = False
    verify_only: bool = False
    json_output_name: Optional[str] = None
    html_output_name: Optional[str] = None
    ledger_output_name: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if not self.evidence_directory:
            raise ValueError("evidence_directory cannot be empty")
        if not isinstance(self.formats, tuple):
            object.__setattr__(self, "formats", tuple(self.formats))
        valid_formats = {"json", "html"}
        for fmt in self.formats:
            if fmt.lower() not in valid_formats:
                raise ValueError(f"Unsupported report format: '{fmt}'. Must be one of {sorted(valid_formats)}")


@dataclass(frozen=True)
class AdvancedTriageResult:
    """
    Immutable representation of the outcome of an advanced triage execution.

    Attributes:
        report: Schema 8.0 AdvancedReport instance.
        manifest_verification: ManifestVerificationResult if manifest was verified, else None.
        custody_ledger: Finalized CustodyLedger instance including publication event.
        custody_verification: CustodyChainVerificationResult verifying final ledger chain.
        json_report_path: Path to written JSON report if requested and persisted.
        html_report_path: Path to written HTML report if requested and persisted.
        ledger_path: Path to written custody ledger JSON if persisted.
        warnings: Tuple of warnings and discrepancies accumulated during execution.
        execution_success: True if workflow ran without errors and manifest had 0 discrepancies.
    """

    report: AdvancedReport
    manifest_verification: Optional[ManifestVerificationResult]
    custody_ledger: CustodyLedger
    custody_verification: CustodyChainVerificationResult
    json_report_path: Optional[Path] = None
    html_report_path: Optional[Path] = None
    ledger_path: Optional[Path] = None
    warnings: Tuple[str, ...] = ()
    execution_success: bool = True


class AdvancedTriageOrchestrator:
    """
    Forensic Orchestration Engine for Schema 8.0 Advanced Triage.

    Coordinates manifest verification, custody ledger lifecycle tracking,
    and report builder synthesis while enforcing strict filesystem isolation.
    """

    def __init__(self, config: AdvancedTriageConfig) -> None:
        if not isinstance(config, AdvancedTriageConfig):
            raise TypeError(f"config must be an instance of AdvancedTriageConfig, got {type(config).__name__}")
        self.config = config

    def run(self) -> AdvancedTriageResult:
        """
        Execute the advanced triage workflow.

        Returns:
            AdvancedTriageResult: Immutable record of the execution results and written file paths.

        Raises:
            FileNotFoundError: If evidence directory, manifest, or ledger path does not exist.
            NotADirectoryError: If evidence directory is not a directory.
            FileExistsError: If output files exist and overwrite is False.
            ValueError: If configuration or case metadata is conflicting or invalid.
            CustodyIntegrityError: If custody ledger chain verification fails.
            OSError: If filesystem operations fail.
        """
        # 1. Validate Evidence Directory
        raw_ev = Path(self.config.evidence_directory)
        if not raw_ev.exists():
            raise FileNotFoundError(f"Evidence directory does not exist: '{self.config.evidence_directory}'")
        if not raw_ev.is_dir():
            raise NotADirectoryError(f"Evidence target is not a directory: '{self.config.evidence_directory}'")
        ev_root = raw_ev.resolve()

        # 2. Determine and Validate Output Paths
        out_dir = Path(self.config.output_dir).resolve()
        case_id_val = self.config.case_metadata.get("case_id")
        clean_case_name = re.sub(r"[^\w\-.]", "_", str(case_id_val).strip()) if case_id_val else "case"

        json_dest: Optional[Path] = None
        html_dest: Optional[Path] = None
        ledger_dest: Optional[Path] = None

        if "json" in [f.lower() for f in self.config.formats]:
            fname = self.config.json_output_name or f"report_{clean_case_name}.json"
            json_dest = (out_dir / fname).resolve()

        if "html" in [f.lower() for f in self.config.formats]:
            fname = self.config.html_output_name or f"report_{clean_case_name}.html"
            html_dest = (out_dir / fname).resolve()

        ledger_fname = self.config.ledger_output_name or f"ledger_{clean_case_name}.json"
        ledger_dest = (out_dir / ledger_fname).resolve()

        # Validate output destinations
        all_targets: List[Path] = [p for p in (json_dest, html_dest, ledger_dest) if p is not None]
        if len(set(all_targets)) != len(all_targets):
            raise ValueError(
                "Output destination collision: requested destinations (JSON report, HTML report, "
                "custody ledger) must be distinct file paths"
            )

        for target in all_targets:
            if target == ev_root or target.is_relative_to(ev_root):
                raise ValueError(
                    f"Forensic safety violation: output destination '{target}' "
                    f"overlaps or resides inside evidence directory '{ev_root}'"
                )

        # Pre-flight no-clobber check
        if not self.config.overwrite:
            for target in all_targets:
                if target.exists():
                    raise FileExistsError(
                        f"Destination file already exists and overwrite is False: '{target}'"
                    )

        # 3. Initialize or Resume Custody Ledger
        actor = self.config.actor or CustodyActor(
            declared_identity="ForensiX Triage Engine",
            role="Automated Orchestrator",
        )

        ledger: CustodyLedger
        if self.config.custody_ledger_path is not None:
            ledger_file = Path(self.config.custody_ledger_path).resolve()
            if not ledger_file.exists():
                raise FileNotFoundError(f"Custody ledger file does not exist: '{self.config.custody_ledger_path}'")
            if not ledger_file.is_file():
                raise ValueError(f"Custody ledger path is not a regular file: '{self.config.custody_ledger_path}'")

            try:
                ledger = CustodyLedger.load_from_file(ledger_file)
            except ValueError as err:
                raise CustodyIntegrityError(
                    f"Cannot resume custody ledger due to integrity or format failure: {err}"
                ) from err

            initial_verif = ledger.validate_chain()
            if not initial_verif.is_valid or initial_verif.integrity_status == "TAMPERED":
                raise CustodyIntegrityError(
                    f"Cannot resume custody ledger: chain integrity validation failed with status "
                    f"'{initial_verif.integrity_status}': {'; '.join(initial_verif.discrepancies)}"
                )

            # Reconcile case_id if present in both
            if case_id_val and ledger.case_id:
                if str(case_id_val).strip() != str(ledger.case_id).strip():
                    raise ValueError(
                        f"Conflicting case_id: config case_metadata '{case_id_val}' "
                        f"does not match loaded ledger '{ledger.case_id}'"
                    )
        else:
            ledger = CustodyLedger(case_id=str(case_id_val).strip() if case_id_val else None)

        # Record EVIDENCE_RECEIVED
        ledger.append_event(
            action_type=CustodyActionType.EVIDENCE_RECEIVED,
            evidence_id=ev_root.name,
            actor=actor,
            source_location=str(ev_root.name),
            notes=f"Evidence directory '{ev_root.name}' received for triage analysis",
        )

        # 4. Manifest Verification
        verif_result: Optional[ManifestVerificationResult] = None
        manifest_record: Optional[ManifestRecord] = None

        if self.config.manifest_path is not None:
            man_file = Path(self.config.manifest_path).resolve()
            if not man_file.exists():
                raise FileNotFoundError(f"Manifest file does not exist: '{self.config.manifest_path}'")
            if not man_file.is_file():
                raise ValueError(f"Manifest path is not a regular file: '{self.config.manifest_path}'")

            try:
                with man_file.open("rb") as f:
                    raw_manifest = json.load(f)
            except Exception as err:
                raise ValueError(f"Failed to parse manifest JSON '{man_file}': {err}") from err

            # Reconcile case_id
            man_case_id = raw_manifest.get("case_id")
            if case_id_val and man_case_id:
                if str(case_id_val).strip() != str(man_case_id).strip():
                    raise ValueError(
                        f"Conflicting case_id: config case_metadata '{case_id_val}' "
                        f"does not match manifest.case_id '{man_case_id}'"
                    )
            if ledger.case_id and man_case_id:
                if str(ledger.case_id).strip() != str(man_case_id).strip():
                    raise ValueError(
                        f"Conflicting case_id: custody_ledger '{ledger.case_id}' "
                        f"does not match manifest.case_id '{man_case_id}'"
                    )

            verif_result = verify_manifest(
                manifest=man_file,
                base_dir=ev_root,
                allow_symlinks=self.config.allow_symlinks,
            )

            # Build ManifestRecord for report builder
            parsed_entries = []
            for e in raw_manifest.get("entries", []):
                parsed_entries.append(
                    ManifestEntry(
                        relative_path=e["relative_path"],
                        size_bytes=e["size_bytes"],
                        hashes=e["hashes"],
                        artifact_type=e.get("artifact_type", "evidence"),
                        evidence_id=e.get("evidence_id"),
                        metadata=e.get("metadata", ()),
                    )
                )

            manifest_record = ManifestRecord(
                manifest_id=raw_manifest["manifest_id"],
                manifest_version=raw_manifest.get("manifest_version", "8.0"),
                created_at=raw_manifest["created_at"],
                forensix_version=raw_manifest["forensix_version"],
                case_id=raw_manifest.get("case_id"),
                investigator=raw_manifest.get("investigator"),
                entries=parsed_entries,
            )

            # Append integrity verification custody event
            if verif_result.overall_status:
                ledger.append_event(
                    action_type=CustodyActionType.INTEGRITY_VERIFIED,
                    evidence_id=verif_result.manifest_id,
                    actor=actor,
                    notes=(
                        f"Manifest verification successful: {verif_result.verified_count}/"
                        f"{verif_result.total_entries} entries matched recorded baseline"
                    ),
                )
            else:
                ledger.append_event(
                    action_type=CustodyActionType.INTEGRITY_MISMATCH_DETECTED,
                    evidence_id=verif_result.manifest_id,
                    actor=actor,
                    notes=(
                        f"Manifest verification discrepancy: {verif_result.mismatch_count} mismatch(es), "
                        f"{verif_result.missing_count} missing file(s), {verif_result.error_count} entry error(s)"
                    ),
                )

        # 5. Build Report with Documented Evidentiary Boundary
        pre_report_terminal_hash = ledger.terminal_hash
        pre_report_total_events = len(ledger)

        accumulated_omissions: List[str] = list(self.config.case_metadata.get("omissions", []))

        effective_findings: Optional[FindingsSummary]
        effective_investigation: Optional[Any]
        effective_details: Optional[Mapping[str, Any]]

        if self.config.verify_only:
            effective_findings = FindingsSummary(total_host_artifacts=0)
            effective_investigation = None
            effective_details = None
            accumulated_omissions.append(
                "Investigation analysis skipped per verify_only flag; report reflects evidence inventory and custody ledger verification."
            )
        else:
            effective_findings = self.config.findings_summary
            effective_investigation = self.config.investigation_results
            effective_details = self.config.details
            if effective_findings is None and effective_investigation is None:
                accumulated_omissions.append(
                    "Automated host artifact analysis was not performed; report reflects evidence inventory and custody ledger verification."
                )

        accumulated_omissions.append(
            f"Embedded custody summary certifies evidence custody through verification "
            f"(terminal digest: {pre_report_terminal_hash}, total events: {pre_report_total_events}). "
            "Publication of this report (REPORT_GENERATED) is recorded as the terminal event in the accompanying custody ledger."
        )

        report = build_advanced_report(
            case_metadata=self.config.case_metadata,
            manifest=manifest_record,
            manifest_verification=verif_result,
            custody_ledger=ledger,
            findings_summary=effective_findings,
            investigation_results=effective_investigation,
            omissions=accumulated_omissions,
            details=effective_details,
        )

        # 6. Append Publication Event to Finalize Ledger
        ledger.append_event(
            action_type=CustodyActionType.REPORT_GENERATED,
            evidence_id=report.report_id,
            actor=actor,
            notes=(
                f"Generated Advanced Forensic Report {report.report_id} (Schema 8.0) "
                f"covering evidence custody terminal digest {pre_report_terminal_hash}"
            ),
        )

        final_chain_verif = ledger.validate_chain()
        if not final_chain_verif.is_valid:
            raise CustodyIntegrityError(
                f"Final custody chain validation failed: {'; '.join(final_chain_verif.discrepancies)}"
            )

        # 7. Safe Multi-File Persistence with Failure Cleanup
        written_files: List[Path] = []
        try:
            if json_dest:
                write_advanced_report_json(
                    report=report,
                    output_path=json_dest,
                    overwrite=self.config.overwrite,
                    evidence_root=ev_root,
                )
                written_files.append(json_dest)

            if html_dest:
                write_advanced_report_html(
                    report=report,
                    output_path=html_dest,
                    overwrite=self.config.overwrite,
                    evidence_root=ev_root,
                )
                written_files.append(html_dest)

            ledger.save_to_file(
                path=ledger_dest,
                overwrite=self.config.overwrite,
                evidence_root=ev_root,
            )
            written_files.append(ledger_dest)

        except Exception:
            # If an unhandled error occurs during write of subsequent files,
            # attempt best-effort cleanup of newly written files if overwrite was False
            if not self.config.overwrite:
                for wf in written_files:
                    try:
                        if wf.exists():
                            wf.unlink()
                    except OSError:
                        pass
            raise

        execution_success = verif_result is None or verif_result.overall_status

        return AdvancedTriageResult(
            report=report,
            manifest_verification=verif_result,
            custody_ledger=ledger,
            custody_verification=final_chain_verif,
            json_report_path=json_dest,
            html_report_path=html_dest,
            ledger_path=ledger_dest,
            warnings=report.limitations.warnings,
            execution_success=execution_success,
        )


def run_advanced_triage(config: AdvancedTriageConfig) -> AdvancedTriageResult:
    """
    Execute an advanced forensic triage workflow with the specified configuration.

    Args:
        config: AdvancedTriageConfig specifying inputs, parameters, and policies.

    Returns:
        AdvancedTriageResult: Result of the triage execution.
    """
    orchestrator = AdvancedTriageOrchestrator(config)
    return orchestrator.run()
