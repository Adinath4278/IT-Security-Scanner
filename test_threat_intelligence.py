import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import threat_database
from threat_database import get_signature_details
from threat_intelligence import (
    get_threat_intelligence_status,
    import_verified_update,
)


class ThreatIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "threats.txt"
        self.patcher = patch.object(
            threat_database,
            "DATABASE_FILE",
            self.database
        )
        self.patcher.start()
        threat_database.reload_database()

    def tearDown(self):
        self.patcher.stop()
        threat_database.reload_database()
        self.temporary_directory.cleanup()

    def test_hash_detection_and_unknown_hash(self):
        threat_database.add_threat_hash("a" * 64, "Trojan.Test")

        self.assertEqual(
            threat_database.check_hash("a" * 64),
            "Trojan.Test"
        )
        self.assertIsNone(threat_database.check_hash("b" * 64))

    def test_signature_category_and_empty_database_warning(self):
        threat_database.add_threat_hash("a" * 64, "Trojan.Win32.Test")
        threat_database.add_threat_hash("b" * 64, "Ransomware.Sample")

        self.assertEqual(
            get_signature_details("a" * 64)["category"],
            "trojan"
        )
        self.assertEqual(
            get_signature_details("b" * 64)["category"],
            "ransomware"
        )

        threat_database.replace_database({})
        status = get_threat_intelligence_status()
        self.assertFalse(status["available"])
        self.assertIn("not evidence", status["warning"])

    def test_database_metadata_verifies_version_and_integrity(self):
        threat_database.add_threat_hash("a" * 64, "Known.Test")

        status = threat_database.get_database_status()

        self.assertEqual(status["count"], 1)
        self.assertEqual(status["version"], 1)
        self.assertEqual(status["integrity"], "verified")

    def test_failed_database_update_rolls_back_signature_content(self):
        threat_database.add_threat_hash("a" * 64, "Existing.Test")
        original_database = self.database.read_bytes()
        original_metadata = self.database.with_suffix(
            self.database.suffix + ".meta.json"
        ).read_bytes()

        with patch.object(
            threat_database,
            "_write_metadata",
            side_effect=OSError("interrupted metadata write")
        ):
            self.assertFalse(
                threat_database.add_threat_hash("b" * 64, "New.Test")
            )

        self.assertEqual(self.database.read_bytes(), original_database)
        self.assertEqual(
            self.database.with_suffix(
                self.database.suffix + ".meta.json"
            ).read_bytes(),
            original_metadata
        )
        self.assertEqual(
            threat_database.check_hash("a" * 64),
            "Existing.Test"
        )
        self.assertIsNone(threat_database.check_hash("b" * 64))

    def test_database_corruption_is_reported_not_used_as_clean(self):
        threat_database.add_threat_hash("a" * 64, "Known.Test")
        self.database.write_text(
            self.database.read_text(encoding="utf-8") + "corruption\n",
            encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "integrity"):
            threat_database.reload_database()

    def test_verified_update_requires_matching_out_of_band_digest(self):
        bundle = Path(self.temporary_directory.name) / "update.txt"
        content = f"{'c' * 64}|Update.Sample\n".encode("utf-8")
        bundle.write_bytes(content)

        with self.assertRaisesRegex(ValueError, "digest"):
            import_verified_update(bundle, "0" * 64)

        result = import_verified_update(
            bundle,
            hashlib.sha256(content).hexdigest()
        )
        self.assertEqual(result["imported"], 1)
        self.assertEqual(
            threat_database.check_hash("c" * 64),
            "Update.Sample"
        )
        self.assertEqual(
            get_threat_intelligence_status()["integrity"],
            "verified"
        )

    def test_untrusted_or_invalid_bundle_never_partially_updates_database(self):
        bundle = Path(self.temporary_directory.name) / "invalid.txt"
        bundle.write_text(
            f"{'a' * 64}|Valid\nbroken entry\n",
            encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "invalid"):
            import_verified_update(
                bundle,
                hashlib.sha256(bundle.read_bytes()).hexdigest()
            )
        self.assertIsNone(threat_database.check_hash("a" * 64))


if __name__ == "__main__":
    unittest.main()
