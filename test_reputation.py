import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from reputation import (
    RateLimitError,
    ReputationClient,
    ReputationError,
    _NoRedirectHandler,
)


class FakeResponse:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        if isinstance(self.value, bytes):
            return self.value
        return json.dumps(self.value).encode("utf-8")


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.now = [1000.0]
        self.responses = []
        self.requests = []

        def open_response(request, timeout):
            self.requests.append((request, timeout))
            response = self.responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        self.client = ReputationClient(
            cache_path=self.root / "cache.sqlite3",
            minimum_interval=5,
            opener=open_response,
            clock=lambda: self.now[0]
        )
        self.file_hash = "a" * 64

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_virus_total_hash_lookup_and_cache(self):
        self.responses.append(FakeResponse({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 5,
                        "undetected": 10,
                    }
                }
            }
        }))

        result = self.client.lookup_virustotal(
            self.file_hash,
            "test-key",
            consent=True
        )
        cached = self.client.lookup_virustotal(
            self.file_hash,
            "test-key",
            consent=True
        )

        self.assertEqual(result["malicious"], 3)
        self.assertFalse(result["cached"])
        self.assertTrue(cached["cached"])

    def test_external_lookup_requires_explicit_consent(self):
        with self.assertRaises(PermissionError):
            self.client.lookup_malwarebazaar(self.file_hash)

    def test_invalid_hash_does_not_make_network_request(self):
        with self.assertRaises(ValueError):
            self.client.lookup_virustotal("not-hash", "key", consent=True)
        self.assertEqual(self.responses, [])

    def test_hash_with_embedded_whitespace_is_rejected(self):
        with self.assertRaises(ValueError):
            self.client.lookup_virustotal(
                "a" * 32 + " " + "a" * 31,
                "key",
                consent=True
            )
        self.assertEqual(self.responses, [])

    def test_malformed_provider_shape_is_reported(self):
        self.responses.append(FakeResponse(["unexpected", "list"]))
        with self.assertRaisesRegex(ReputationError, "invalid response"):
            self.client.lookup_virustotal(
                self.file_hash,
                "test-key",
                consent=True
            )

    def test_rate_limit_and_timeout_are_reported(self):
        self.responses.append(FakeResponse({"data": {"attributes": {}}}))
        self.client.lookup_virustotal(self.file_hash, "key", consent=True)

        with self.assertRaises(RateLimitError):
            self.client.lookup_virustotal(
                "b" * 64,
                "key",
                consent=True
            )

        self.now[0] += 6
        self.responses.append(TimeoutError("timed out"))
        with self.assertRaises(ReputationError):
            self.client.lookup_virustotal(
                "c" * 64,
                "key",
                consent=True
            )

    def test_http_429_is_reported_without_retry(self):
        self.responses.append(
            urllib.error.HTTPError(
                "https://example.invalid",
                429,
                "rate limited",
                {},
                None
            )
        )
        with self.assertRaises(RateLimitError):
            self.client.lookup_malwarebazaar(
                self.file_hash,
                api_key="test-key",
                consent=True
            )

    def test_malwarebazaar_hash_lookup_uses_api_key_and_local_cache(self):
        self.responses.append(FakeResponse({
            "query_status": "ok",
            "data": [{"sha256_hash": self.file_hash}],
        }))

        result = self.client.lookup_malwarebazaar(
            self.file_hash,
            api_key="test-key",
            consent=True
        )
        cached = self.client.lookup_malwarebazaar(
            self.file_hash,
            api_key="test-key",
            consent=True
        )

        self.assertEqual(result["status"], "found")
        self.assertFalse(result["cached"])
        self.assertTrue(cached["cached"])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(
            self.requests[0][0].get_header("Auth-key"),
            "test-key"
        )
        self.assertEqual(self.requests[0][1], 8)

    def test_hash_lookups_send_hashes_not_file_contents(self):
        self.responses.append(FakeResponse({
            "data": {"attributes": {}},
        }))
        self.client.lookup_virustotal(
            self.file_hash,
            "test-key",
            consent=True
        )
        request = self.requests[0][0]
        self.assertIsNone(request.data)
        self.assertIn(self.file_hash, request.full_url)

    def test_network_errors_do_not_expose_credentials(self):
        secret = "private-api-token"
        self.responses.append(TimeoutError(secret))

        with self.assertRaises(ReputationError) as raised:
            self.client.lookup_virustotal(
                self.file_hash,
                secret,
                consent=True
            )

        self.assertNotIn(secret, str(raised.exception))

    def test_malwarebazaar_rejects_mismatched_hash_records(self):
        self.responses.append(FakeResponse({
            "query_status": "ok",
            "data": [{"sha256_hash": "b" * 64}],
        }))

        with self.assertRaisesRegex(ReputationError, "invalid response"):
            self.client.lookup_malwarebazaar(
                self.file_hash,
                api_key="test-key",
                consent=True
            )

    def test_redirect_handler_refuses_provider_redirects(self):
        handler = _NoRedirectHandler()

        self.assertIsNone(
            handler.redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://redirect.example/"
            )
        )


if __name__ == "__main__":
    unittest.main()
