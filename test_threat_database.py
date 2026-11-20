import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import threat_database


class ThreatDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_file = Path(self.temporary_directory.name) / "threats.txt"
        self.patcher = patch.object(
            threat_database,
            "DATABASE_FILE",
            self.database_file
        )
        self.patcher.start()
        threat_database.reload_database()

    def tearDown(self):
        self.patcher.stop()
        threat_database.reload_database()
        self.temporary_directory.cleanup()

    def test_import_validates_and_deduplicates_local_signatures(self):
        source = Path(self.temporary_directory.name) / "incoming.txt"
        source.write_text(
            f"{'a' * 64}|Sample Threat\n"
            "not-a-hash|invalid\n"
            f"{'b' * 64}|Another Threat\n",
            encoding="utf-8"
        )

        result = threat_database.import_local_signatures(source)

        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["invalid_lines"], [2])
        self.assertEqual(
            threat_database.check_hash("a" * 64),
            "Sample Threat"
        )

    def test_database_reloads_when_local_file_changes(self):
        first_hash = "a" * 64
        second_hash = "b" * 64
        self.database_file.write_text(
            f"{first_hash}|First\n",
            encoding="utf-8"
        )
        self.assertEqual(threat_database.check_hash(first_hash), "First")

        self.database_file.write_text(
            f"{second_hash}|Second Signature\n",
            encoding="utf-8"
        )

        self.assertEqual(
            threat_database.check_hash(second_hash),
            "Second Signature"
        )

    def test_invalid_signature_is_never_written(self):
        self.assertFalse(
            threat_database.add_threat_hash("bad", "Invalid")
        )
        self.assertFalse(self.database_file.exists())

    def test_corrupted_database_metadata_fails_closed(self):
        threat_database.replace_database({"a" * 64: "Sample"})
        metadata_path = self.database_file.with_suffix(".txt.meta.json")
        metadata_path.write_text("{", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "metadata is invalid"):
            threat_database.reload_database()

    def test_malformed_database_entry_fails_closed(self):
        self.database_file.write_text(
            "not a valid signature row\n",
            encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "invalid entry"):
            threat_database.reload_database()

    def test_database_metadata_signature_count_is_verified(self):
        threat_database.replace_database({"a" * 64: "Sample"})
        metadata_path = self.database_file.with_suffix(".txt.meta.json")
        import json

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["signature_count"] = 2
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "signature count"):
            threat_database.reload_database()


if __name__ == "__main__":
    unittest.main()
