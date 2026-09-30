"""
Unit tests for ForensiX Artifact Data Models (artifacts.py).
"""

from dataclasses import FrozenInstanceError
import unittest

from forensix.artifacts import (
    ArtifactCategory,
    ArtifactCollectionResult,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactType,
    generate_artifact_id,
)


class TestArtifactModels(unittest.TestCase):
    """Test suite for artifact data structures and immutability."""

    def test_artifact_id_format(self):
        """Verify generated artifact IDs follow ART-<UUIDv4> format."""
        aid = generate_artifact_id()
        self.assertTrue(aid.startswith("ART-"))
        self.assertEqual(len(aid.split("-")), 6)

    def test_artifact_record_immutability(self):
        """Verify ArtifactRecord is frozen and raises FrozenInstanceError on modification."""
        record = ArtifactRecord(
            artifact_id="ART-1234",
            relative_path="etc/passwd",
            source_path="/tmp/evidence/etc/passwd",
            category=ArtifactCategory.ACCOUNT.value,
            artifact_type=ArtifactType.PASSWD.value,
            is_known=True,
            size=1024,
            permissions="0644",
            modified="2026-09-30T12:00:00+00:00",
            accessed="2026-09-30T12:00:00+00:00",
            created=None,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=ArtifactStatus.COLLECTED.value,
        )

        with self.assertRaises(FrozenInstanceError):
            record.size = 2048  # type: ignore

    def test_artifact_record_to_dict_structure(self):
        """Verify ArtifactRecord serialization to dictionary format."""
        record = ArtifactRecord(
            artifact_id="ART-1234",
            relative_path="etc/passwd",
            source_path="/tmp/evidence/etc/passwd",
            category=ArtifactCategory.ACCOUNT.value,
            artifact_type=ArtifactType.PASSWD.value,
            is_known=True,
            size=1024,
            permissions="0644",
            modified="2026-09-30T12:00:00+00:00",
            accessed="2026-09-30T12:00:00+00:00",
            created=None,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=ArtifactStatus.COLLECTED.value,
            mime_type="text/plain",
        )
        as_dict = record.to_dict()
        self.assertEqual(as_dict["artifact_id"], "ART-1234")
        self.assertEqual(as_dict["relative_path"], "etc/passwd")
        self.assertEqual(as_dict["category"], "account")
        self.assertEqual(as_dict["artifact_type"], "passwd")
        self.assertTrue(as_dict["is_known"])
        self.assertEqual(as_dict["timestamps"]["modified"], "2026-09-30T12:00:00+00:00")
        self.assertEqual(as_dict["hashes"]["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_artifact_collection_result_serialization(self):
        """Verify ArtifactCollectionResult serialization and summary counts."""
        rec1 = ArtifactRecord(
            artifact_id="ART-1",
            relative_path="etc/passwd",
            source_path="/tmp/etc/passwd",
            category=ArtifactCategory.ACCOUNT.value,
            artifact_type=ArtifactType.PASSWD.value,
            is_known=True,
            size=100,
            permissions="0644",
            modified="2026-09-30T00:00:00+00:00",
            accessed="2026-09-30T00:00:00+00:00",
            created=None,
            md5="abc",
            sha256="def",
            status=ArtifactStatus.COLLECTED.value,
        )
        rec2 = ArtifactRecord(
            artifact_id="ART-2",
            relative_path="opt/data.bin",
            source_path="/tmp/opt/data.bin",
            category=ArtifactCategory.GENERIC.value,
            artifact_type=ArtifactType.GENERIC_FILE.value,
            is_known=False,
            size=200,
            permissions="0644",
            modified="2026-09-30T00:00:00+00:00",
            accessed="2026-09-30T00:00:00+00:00",
            created=None,
            md5="123",
            sha256="456",
            status=ArtifactStatus.COLLECTED.value,
        )
        result = ArtifactCollectionResult(
            evidence_id="EV-TEST",
            evidence_root="/tmp",
            collected_at="2026-09-30T00:00:00+00:00",
            artifacts=(rec1, rec2),
            total_artifacts=2,
            known_artifacts=1,
            generic_artifacts=1,
            unreadable_artifacts=0,
        )

        d = result.to_dict()
        self.assertEqual(d["evidence_id"], "EV-TEST")
        self.assertEqual(d["summary"]["total_artifacts"], 2)
        self.assertEqual(d["summary"]["known_artifacts"], 1)
        self.assertEqual(d["summary"]["generic_artifacts"], 1)
        self.assertEqual(len(d["artifacts"]), 2)


if __name__ == "__main__":
    unittest.main()
