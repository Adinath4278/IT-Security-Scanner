"""Optional, consent-based hash lookups for public reputation services."""

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path

from app_state import default_data_directory


VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "IT-Security-Scanner/0.1"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


class ReputationError(RuntimeError):
    pass


class RateLimitError(ReputationError):
    pass


class CredentialStore:
    """Use Windows Credential Manager through keyring; never store keys in app files."""

    SERVICE = "IT-Security-Scanner"

    def __init__(self):
        try:
            import keyring
        except ImportError:
            keyring = None
        self._keyring = keyring

    @property
    def available(self):
        if self._keyring is None or os.name != "nt":
            return False
        backend = self._keyring.get_keyring()
        return (
            backend.__class__.__module__ == "keyring.backends.Windows"
            and backend.priority > 0
        )

    @staticmethod
    def _environment_name(provider):
        names = {
            "virustotal": "VIRUSTOTAL_API_KEY",
            "malwarebazaar": "MALWAREBAZAAR_API_KEY",
        }
        try:
            return names[provider]
        except KeyError as error:
            raise ValueError(f"Unsupported reputation provider: {provider}") from error

    def set(self, provider, credential):
        self._environment_name(provider)
        if not credential or not credential.strip():
            raise ValueError("API credentials must not be empty.")
        if not self.available:
            raise ReputationError(
                "Windows Credential Manager is unavailable or not selected. "
                "Install the optional keyring extra, or use the provider's "
                "environment variable."
            )
        self._keyring.set_password(self.SERVICE, provider, credential)

    def get(self, provider):
        environment_name = self._environment_name(provider)
        if os.environ.get(environment_name):
            return os.environ[environment_name]
        if not self.available:
            return None
        return self._keyring.get_password(self.SERVICE, provider)


class ReputationClient:
    def __init__(
        self,
        cache_path=None,
        timeout=8,
        cache_ttl=24 * 60 * 60,
        minimum_interval=15,
        opener=None,
        clock=None
    ):
        self.cache_path = Path(
            cache_path
            or default_data_directory() / "reputation_cache.sqlite3"
        )
        self.timeout = max(1, float(timeout))
        self.cache_ttl = max(1, int(cache_ttl))
        self.max_cache_entries = 2000
        self.minimum_interval = max(0, float(minimum_interval))
        self._opener = opener or urllib.request.build_opener(
            _NoRedirectHandler()
        ).open
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._last_request = {}
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.cache_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reputation_cache (
                        provider TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        fetched_at REAL NOT NULL,
                        response_json TEXT NOT NULL,
                        PRIMARY KEY (provider, file_hash)
                    )
                    """
                )

    @staticmethod
    def _validate_hash(file_hash):
        normalized = str(file_hash).lower().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("A valid SHA-256 hash is required.")
        return normalized

    def _cache_get(self, provider, file_hash):
        with closing(sqlite3.connect(self.cache_path)) as connection:
            row = connection.execute(
                """
                SELECT fetched_at, response_json
                FROM reputation_cache
                WHERE provider = ? AND file_hash = ?
                """,
                (provider, file_hash)
            ).fetchone()
        if not row or self._clock() - row[0] > self.cache_ttl:
            return None
        return json.loads(row[1])

    def _cache_put(self, provider, file_hash, response):
        serialized = json.dumps(response, separators=(",", ":"), sort_keys=True)
        with closing(sqlite3.connect(self.cache_path)) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO reputation_cache
                        (provider, file_hash, fetched_at, response_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(provider, file_hash) DO UPDATE SET
                        fetched_at = excluded.fetched_at,
                        response_json = excluded.response_json
                    """,
                    (provider, file_hash, self._clock(), serialized)
                )
                connection.execute(
                    """
                    DELETE FROM reputation_cache
                    WHERE fetched_at < ?
                       OR rowid NOT IN (
                            SELECT rowid
                            FROM reputation_cache
                            ORDER BY fetched_at DESC
                            LIMIT ?
                       )
                    """,
                    (
                        self._clock() - self.cache_ttl,
                        self.max_cache_entries,
                    )
                )

    def _request(self, provider, request):
        now = self._clock()
        with self._lock:
            wait_seconds = (
                self.minimum_interval
                - (now - self._last_request.get(provider, 0))
            )
            if provider in self._last_request and wait_seconds > 0:
                raise RateLimitError(
                    f"{provider} lookup is rate limited locally; "
                    f"retry in about {wait_seconds:.1f} seconds."
                )
            self._last_request[provider] = now
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ReputationError("Reputation response exceeded the size limit.")
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 429:
                raise RateLimitError(
                    "The reputation provider rate-limited this request."
                ) from error
            if error.code == 404:
                return {"status": "not_found", "provider": provider}
            raise ReputationError(
                f"{provider} returned HTTP {error.code}."
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ReputationError(
                f"{provider} network lookup failed "
                f"({type(error).__name__})."
            ) from error
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReputationError(
                f"{provider} returned an invalid response."
            ) from error

    def lookup_virustotal(self, file_hash, api_key, consent=False):
        if not consent:
            raise PermissionError("User consent is required for external lookups.")
        file_hash = self._validate_hash(file_hash)
        if not api_key or not api_key.strip():
            raise ReputationError("A VirusTotal API key is required.")
        cached = self._cache_get("virustotal", file_hash)
        if cached is not None:
            return {**cached, "cached": True}
        request = urllib.request.Request(
            VIRUSTOTAL_URL + file_hash,
            headers={
                "x-apikey": api_key.strip(),
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="GET"
        )
        payload = self._request("virustotal", request)
        if not isinstance(payload, dict):
            raise ReputationError("VirusTotal returned an invalid response.")
        if payload.get("status") == "not_found":
            response = {
                "provider": "virustotal",
                "status": "not_found",
                "sha256": file_hash,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "permalink": None,
            }
            self._cache_put("virustotal", file_hash, response)
            return {**response, "cached": False}
        data = payload.get("data")
        if not isinstance(data, dict) or "attributes" not in data:
            raise ReputationError("VirusTotal returned an invalid response.")
        attributes = data["attributes"]
        if not isinstance(attributes, dict):
            raise ReputationError("VirusTotal returned an invalid response.")
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            raise ReputationError("VirusTotal returned invalid analysis statistics.")
        response = {
            "provider": "virustotal",
            "status": "found" if attributes else payload.get("status", "unknown"),
            "sha256": file_hash,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "permalink": (
                f"https://www.virustotal.com/gui/file/{file_hash}"
                if attributes
                else None
            ),
        }
        self._cache_put("virustotal", file_hash, response)
        return {**response, "cached": False}

    def lookup_malwarebazaar(self, file_hash, api_key=None, consent=False):
        if not consent:
            raise PermissionError("User consent is required for external lookups.")
        file_hash = self._validate_hash(file_hash)
        if not api_key or not api_key.strip():
            raise ReputationError("A MalwareBazaar API key is required.")
        cached = self._cache_get("malwarebazaar", file_hash)
        if cached is not None:
            return {**cached, "cached": True}
        body = urllib.parse.urlencode({
            "query": "get_info",
            "hash": file_hash,
        }).encode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if api_key:
            headers["Auth-Key"] = api_key.strip()
        request = urllib.request.Request(
            MALWAREBAZAAR_URL,
            data=body,
            headers=headers,
            method="POST"
        )
        payload = self._request("malwarebazaar", request)
        if not isinstance(payload, dict):
            raise ReputationError("MalwareBazaar returned an invalid response.")
        query_status = payload.get("query_status")
        data = payload.get("data")
        if query_status == "ok":
            if not isinstance(data, list) or not data:
                raise ReputationError("MalwareBazaar returned an invalid response.")
            if any(
                not isinstance(record, dict)
                or (
                    record.get("sha256_hash") is not None
                    and (
                        not isinstance(record["sha256_hash"], str)
                        or record["sha256_hash"].lower() != file_hash
                    )
                )
                for record in data
            ):
                raise ReputationError("MalwareBazaar returned an invalid response.")
        elif query_status == "hash_not_found":
            if data not in (None, []):
                raise ReputationError("MalwareBazaar returned an invalid response.")
        else:
            raise ReputationError("MalwareBazaar returned an invalid response.")
        response = {
            "provider": "malwarebazaar",
            "status": (
                "found" if query_status == "ok" and data
                else "not_found" if query_status == "hash_not_found"
                else "unknown"
            ),
            "sha256": file_hash,
            "records": data or [],
        }
        self._cache_put("malwarebazaar", file_hash, response)
        return {**response, "cached": False}


def calculate_file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
