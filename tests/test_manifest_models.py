"""
Unit tests for ForensiX Manifest Models (manifest_models.py).
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from forensix.manifest_models import (
    MANIFEST_SCHEMA_VERSION,
    HashAlgorithm,
    ManifestArtifactType,
    ManifestEntry,
    ManifestRecord,
    ManifestVerificationStatus,
    generate_manifest_id,
    is_valid_manifest_id,
    validate_relative_entry_path,
)


class TestManifestModels(unittest.TestCase):
    """Test suite for ManifestEntry, ManifestRecord, path validation, and security rules."""

    def setUp(self):
        self.sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_md5 = "d41d8cd98f00b204e9800998ecf8427e"

    def test_schema_version_constant(self):
        """Ensure MANIFEST_SCHEMA_VERSION is 8.0."""
        self.assertEqual(MANIFEST_SCHEMA_VERSION, "8.0")

    def test_generate_and_validate_manifest_id(self):
        """Verify MANIFEST-<UUIDv4> canonical format."""
        mid = generate_manifest_id()
        self.assertTrue(is_valid_manifest_id(mid))
        self.assertTrue(mid.startswith("MANIFEST-"))
        self.assertEqual(len(mid), 9 + 36)

        # Invalid cases
        self.assertFalse(is_valid_manifest_id("MANIFEST-not-a-uuid"))
        self.assertFalse(is_valid_manifest_id("INVALID-550e8400-e29b-41d4-a716-446655440000"))
        self.assertFalse(is_valid_manifest_id(mid.upper()))
        self.assertFalse(is_valid_manifest_id(123))

    def test_validate_relative_entry_path_valid(self):
        """Verify accepted relative POSIX paths."""
        valid_paths = [
            "var/log/auth.log",
            "etc/passwd",
            "reports/investigation_report.json",
            "sample.pcap",
            "evidence_01.raw",
        ]
        for p in valid_paths:
            self.assertEqual(validate_relative_entry_path(p), p)

    def test_validate_relative_entry_path_security_rejections(self):
        """Verify security rejections for absolute paths, traversal, Windows paths, and backslashes."""
        # Absolute POSIX path
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("/etc/shadow")
        self.assertIn("absolute paths with leading '/' are prohibited", str(ctx.exception))

        # Path traversal segments
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("../../etc/shadow")
        self.assertIn("path traversal segment '..' is strictly prohibited", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_relative_entry_path("var/log/../../etc/passwd")

        # Current-dir segment
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("./auth.log")
        self.assertIn("redundant current-directory segment '.' detected", str(ctx.exception))

        # Windows drive letters
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("C:/Windows/System32")
        self.assertIn("Windows drive letters or UNC paths are prohibited", str(ctx.exception))

        # Backslashes
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("var\\log\\auth.log")
        self.assertIn("backslashes are not permitted", str(ctx.exception))

        # Redundant empty segment //
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("var//log")
        self.assertIn("redundant or empty path segment '//' detected", str(ctx.exception))

        # Trailing slash (directory, not file)
        with self.assertRaises(ValueError) as ctx:
            validate_relative_entry_path("var/log/")
        self.assertIn("manifest paths must point to files", str(ctx.exception))

        # Empty / whitespace
        with self.assertRaises(ValueError):
            validate_relative_entry_path("")
        with self.assertRaises(ValueError):
            validate_relative_entry_path("   ")
        with self.assertRaises(TypeError):
            validate_relative_entry_path(None)

    def test_manifest_entry_valid_construction(self):
        """Verify valid ManifestEntry construction, freezing, and immutability."""
        entry = ManifestEntry(
            relative_path="var/log/auth.log",
            size_bytes=1024,
            hashes={"sha256": self.sample_sha256, "md5": self.sample_md5},
            artifact_type=ManifestArtifactType.EVIDENCE,
            evidence_id="EV-12345",
            metadata={"source": "disk1", "owner": "root"},
        )
        self.assertEqual(entry.relative_path, "var/log/auth.log")
        self.assertEqual(entry.size_bytes, 1024)
        self.assertEqual(entry.hashes, (("md5", self.sample_md5), ("sha256", self.sample_sha256)))
        self.assertEqual(entry.artifact_type, "evidence")
        self.assertEqual(entry.evidence_id, "EV-12345")
        self.assertEqual(entry.metadata, (("owner", "root"), ("source", "disk1")))

        # Frozen check
        with self.assertRaises(FrozenInstanceError):
            entry.size_bytes = 2048

    def test_manifest_entry_rejects_boolean_size(self):
        """size_bytes must reject booleans explicitly."""
        with self.assertRaises(TypeError):
            ManifestEntry(
                relative_path="var/log/auth.log",
                size_bytes=True,  # bool
                hashes={"sha256": self.sample_sha256},
            )
        with self.assertRaises(ValueError):
            ManifestEntry(
                relative_path="var/log/auth.log",
                size_bytes=-1,
                hashes={"sha256": self.sample_sha256},
            )

    def test_manifest_entry_requires_at_least_one_hash(self):
        """ManifestEntry must reject empty hash sets."""
        with self.assertRaises(ValueError):
            ManifestEntry(
                relative_path="var/log/auth.log",
                size_bytes=1024,
                hashes={},
            )

    def test_manifest_entry_defensive_immutability(self):
        """Mutating the dictionary passed into ManifestEntry must not mutate the instance."""
        mutable_hashes = {"sha256": self.sample_sha256}
        entry = ManifestEntry(
            relative_path="var/log/auth.log",
            size_bytes=100,
            hashes=mutable_hashes,
        )
        mutable_hashes["sha256"] = "0" * 64
        self.assertEqual(entry.hashes, (("sha256", self.sample_sha256),))

    def test_manifest_record_deterministic_sorting(self):
        """ManifestRecord must sort entries deterministically by relative_path."""
        entry_b = ManifestEntry(
            relative_path="var/log/syslog",
            size_bytes=200,
            hashes={"sha256": self.sample_sha256},
        )
        entry_a = ManifestEntry(
            relative_path="etc/passwd",
            size_bytes=100,
            hashes={"sha256": self.sample_sha256},
        )
        entry_c = ManifestEntry(
            relative_path="var/log/auth.log",
            size_bytes=150,
            hashes={"sha256": self.sample_sha256},
        )

        mid = generate_manifest_id()
        # Pass entries in jumbled order: [b, a, c]
        record = ManifestRecord(
            manifest_id=mid,
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            entries=[entry_b, entry_a, entry_c],
        )

        # Confirm sorted order: a ('etc/passwd'), c ('var/log/auth.log'), b ('var/log/syslog')
        paths = [e.relative_path for e in record.entries]
        self.assertEqual(paths, ["etc/passwd", "var/log/auth.log", "var/log/syslog"])
        self.assertEqual(record.entry_count, 3)

    def test_manifest_record_rejects_duplicate_paths(self):
        """ManifestRecord must raise ValueError if duplicate relative_path entries are supplied."""
        entry1 = ManifestEntry(
            relative_path="etc/passwd",
            size_bytes=100,
            hashes={"sha256": self.sample_sha256},
        )
        entry2 = ManifestEntry(
            relative_path="etc/passwd",
            size_bytes=200,
            hashes={"md5": self.sample_md5},
        )
        mid = generate_manifest_id()
        with self.assertRaises(ValueError) as ctx:
            ManifestRecord(
                manifest_id=mid,
                manifest_version=MANIFEST_SCHEMA_VERSION,
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[entry1, entry2],
            )
        self.assertIn("Duplicate relative_path detected in manifest: 'etc/passwd'", str(ctx.exception))

    def test_manifest_record_rejects_wrong_schema_version(self):
        """ManifestRecord must strictly enforce manifest_version == '8.0'."""
        mid = generate_manifest_id()
        with self.assertRaises(ValueError):
            ManifestRecord(
                manifest_id=mid,
                manifest_version="7.0",
                created_at="2026-10-20T10:00:00Z",
                forensix_version="5.0.0",
                entries=[],
            )

    def test_manifest_record_to_dict_round_trip(self):
        """Verify ManifestRecord to_dict produces clean serializable dictionary."""
        entry = ManifestEntry(
            relative_path="var/log/auth.log",
            size_bytes=500,
            hashes={"sha256": self.sample_sha256},
            artifact_type=ManifestArtifactType.EVIDENCE,
            evidence_id="EV-999",
        )
        mid = generate_manifest_id()
        record = ManifestRecord(
            manifest_id=mid,
            manifest_version=MANIFEST_SCHEMA_VERSION,
            created_at="2026-10-20T10:00:00Z",
            forensix_version="5.0.0",
            case_id="CASE-2026-01",
            investigator="Lead Analyst",
            entries=[entry],
        )
        d = record.to_dict()
        self.assertEqual(d["manifest_id"], mid)
        self.assertEqual(d["manifest_version"], "8.0")
        self.assertEqual(d["entry_count"], 1)
        self.assertEqual(len(d["entries"]), 1)
        self.assertEqual(d["entries"][0]["relative_path"], "var/log/auth.log")

        serialized = json.dumps(d)
        self.assertIn(mid, serialized)


    def test_manifest_entry_nested_metadata_immutability(self):
        """Verify nested metadata structures are recursively frozen and safe from caller mutation."""
        nested_list = ["tag1", "tag2"]
        nested_dict = {"owner": "root", "perms": "0644"}
        metadata = {
            "tags": nested_list,
            "security": nested_dict,
        }

        entry = ManifestEntry(
            relative_path="etc/shadow",
            size_bytes=1024,
            hashes={"sha256": self.sample_sha256},
            metadata=metadata,
        )

        # Mutate the original caller-owned objects
        nested_list.append("tag3_injected")
        nested_dict["owner"] = "attacker"
        nested_dict["injected_key"] = "bad"

        # Verify stored model metadata was not mutated
        stored_meta = dict(entry.metadata)
        self.assertEqual(stored_meta["tags"], ("tag1", "tag2"))
        self.assertEqual(stored_meta["security"]["owner"], "root")
        self.assertNotIn("injected_key", stored_meta["security"])

        # Verify to_dict unfreezes to standard dict/list and is JSON-serializable
        d = entry.to_dict()
        self.assertIsInstance(d["metadata"]["tags"], list)
        self.assertEqual(d["metadata"]["tags"], ["tag1", "tag2"])
        self.assertIsInstance(d["metadata"]["security"], dict)
        self.assertEqual(d["metadata"]["security"]["owner"], "root")

        serialized = json.dumps(d)
        self.assertIn('"tag1"', serialized)
        self.assertNotIn("tag3_injected", serialized)


if __name__ == "__main__":
    unittest.main()
