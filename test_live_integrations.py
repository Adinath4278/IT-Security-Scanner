import os
import tempfile
import unittest
from pathlib import Path

from reputation import ReputationClient
from vulnerability_assessment import NvdClient


LIVE_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class LiveIntegrationTests(unittest.TestCase):
    def test_nvd_public_api(self):
        if os.environ.get("ITSS_LIVE_NVD_TEST") != "1":
            self.skipTest("Set ITSS_LIVE_NVD_TEST=1 to enable live NVD access.")

        findings = NvdClient(timeout=10).search_product({
            "name": "7-Zip",
            "version": "23.01",
        })

        self.assertIsInstance(findings, list)

    def test_virustotal_hash_lookup(self):
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if (
            os.environ.get("ITSS_LIVE_VIRUSTOTAL_TEST") != "1"
            or not api_key
        ):
            self.skipTest(
                "Set ITSS_LIVE_VIRUSTOTAL_TEST=1 and VIRUSTOTAL_API_KEY "
                "to enable live VirusTotal hash lookup."
            )

        with tempfile.TemporaryDirectory() as directory:
            client = ReputationClient(
                cache_path=Path(directory) / "cache.sqlite3"
            )
            result = client.lookup_virustotal(
                LIVE_HASH,
                api_key,
                consent=True
            )

        self.assertEqual(result["sha256"], LIVE_HASH)
        self.assertIn(result["status"], {"found", "not_found"})

    def test_malwarebazaar_hash_lookup(self):
        api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
        if (
            os.environ.get("ITSS_LIVE_MALWAREBAZAAR_TEST") != "1"
            or not api_key
        ):
            self.skipTest(
                "Set ITSS_LIVE_MALWAREBAZAAR_TEST=1 and "
                "MALWAREBAZAAR_API_KEY to enable live MalwareBazaar lookup."
            )

        with tempfile.TemporaryDirectory() as directory:
            client = ReputationClient(
                cache_path=Path(directory) / "cache.sqlite3"
            )
            result = client.lookup_malwarebazaar(
                LIVE_HASH,
                api_key,
                consent=True
            )

        self.assertEqual(result["sha256"], LIVE_HASH)
        self.assertIn(result["status"], {"found", "not_found"})


if __name__ == "__main__":
    unittest.main()
