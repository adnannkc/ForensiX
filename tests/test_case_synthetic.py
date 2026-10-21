"""
Integration Tests for ForensiX V9 Synthetic Incident Case Dataset.

Validates:
1. (Condition 2) Loads examples/case-synthetic/evidence_memory/memory_artifacts.json
   through load_memory_artifacts before the sample run.
2. Validates end-to-end execution of the full synthetic case across all 12 stages.
"""

from pathlib import Path
import tempfile
import unittest

from forensix.case_config import load_case_config_from_file
from forensix.memory_cli import load_memory_artifacts
from forensix.memory_models import (
    MemoryModuleArtifact,
    MemoryNetworkArtifact,
    MemoryProcessArtifact,
)
from forensix.pipeline_engine import EXIT_SUCCESS, run_pipeline
from forensix.pipeline_models import PipelineRunStatus, PipelineStageId


class TestSyntheticCase(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.synthetic_dir = self.repo_root / "examples" / "case-synthetic"
        self.case_json = self.synthetic_dir / "case.json"
        self.mem_json = self.synthetic_dir / "evidence_memory" / "memory_artifacts.json"

    def test_condition_2_load_synthetic_memory_artifacts(self):
        """
        Condition 2: Explicit test that loads
        examples/case-synthetic/evidence_memory/memory_artifacts.json
        through load_memory_artifacts before any sample run.
        """
        self.assertTrue(
            self.mem_json.exists(),
            f"Synthetic memory artifacts file missing at '{self.mem_json}'",
        )

        artifacts, err = load_memory_artifacts(self.mem_json)

        self.assertIsNone(err, f"load_memory_artifacts reported unexpected error: {err}")
        self.assertGreater(len(artifacts), 0, "No memory artifacts were loaded from synthetic memory file")

        # Verify polymorphic artifact types are deserialized correctly
        process_arts = [a for a in artifacts if isinstance(a, MemoryProcessArtifact)]
        net_arts = [a for a in artifacts if isinstance(a, MemoryNetworkArtifact)]
        mod_arts = [a for a in artifacts if isinstance(a, MemoryModuleArtifact)]

        self.assertEqual(len(process_arts), 3, "Expected 3 MemoryProcessArtifact instances")
        self.assertEqual(len(net_arts), 2, "Expected 2 MemoryNetworkArtifact instances")
        self.assertEqual(len(mod_arts), 1, "Expected 1 MemoryModuleArtifact instance")

        # Verify key evidence IDs and processes
        proc_names = {p.process_name for p in process_arts}
        self.assertIn("sshd", proc_names)
        self.assertIn("bash", proc_names)
        self.assertIn("nc", proc_names)

        # Confirm all artifacts share the expected valid UUID evidence_id
        for art in artifacts:
            self.assertTrue(art.evidence_id.startswith("MEM-"))

    def test_synthetic_case_execution_in_isolated_output(self):
        """Execute the synthetic case through the pipeline in a temporary output directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_out = Path(tmp_dir) / "test_reports"
            config = load_case_config_from_file(self.case_json)

            # Override output_dir to isolated directory
            object.__setattr__(config, "output_dir", temp_out)

            res = run_pipeline(config)

            self.assertEqual(res.exit_code, EXIT_SUCCESS)
            self.assertEqual(res.run_manifest.run_status, PipelineRunStatus.SUCCESS.value)

            # Check that all 12 stages completed
            stage_ids = [s.stage_id for s in res.run_manifest.stages]
            self.assertEqual(len(stage_ids), 12)
            self.assertEqual(stage_ids[0], PipelineStageId.CONFIG_VALIDATION.value)
            self.assertEqual(stage_ids[11], PipelineStageId.RUN_MANIFEST.value)

            for st in res.run_manifest.stages:
                self.assertEqual(st.status, "COMPLETED", f"Stage {st.stage_id} did not complete: errors={st.errors}")

            # Verify manifest output file (Condition 4)
            manifest_file = temp_out / "pipeline_manifest.json"
            self.assertTrue(manifest_file.exists())

            # Verify report output files
            written_names = {p.name for p in res.output_files}
            self.assertTrue(any(n.startswith("report_") and n.endswith(".json") for n in written_names))
            self.assertTrue(any(n.startswith("report_") and n.endswith(".html") for n in written_names))
            self.assertTrue(any(n.startswith("ledger_") and n.endswith(".json") for n in written_names))


if __name__ == "__main__":
    unittest.main()
