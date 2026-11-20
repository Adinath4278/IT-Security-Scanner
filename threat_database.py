import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from app_state import default_data_directory

BUNDLED_DATABASE_FILE = Path(__file__).parent / "known_threats.txt"
DATABASE_FILE = (
    default_data_directory() / "known_threats.txt"
    if getattr(sys, "frozen", False)
    else BUNDLED_DATABASE_FILE
)
THREAT_DATABASE = {}

_DATABASE_LOCK = threading.RLock()
_DATABASE_CACHE = None
_DATABASE_CACHE_KEY = None
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DATABASE_VERSION = 1
MAX_SIGNATURE_DATABASE_BYTES = 100 * 1024 * 1024
MAX_SIGNATURE_BUNDLE_BYTES = 50 * 1024 * 1024
MAX_SIGNATURE_COUNT = 1_000_000


def _metadata_path():
    return DATABASE_FILE.with_suffix(DATABASE_FILE.suffix + ".meta.json")


def _validate_database_integrity(content):
    metadata_path = _metadata_path()
    if not metadata_path.exists():
        return None
    if metadata_path.stat().st_size > 64 * 1024:
        raise ValueError("Threat database integrity metadata exceeds its size limit.")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Threat database integrity metadata is invalid.") from error
    if (
        not isinstance(metadata, dict)
        or metadata.get("version") != _DATABASE_VERSION
        or metadata.get("sha256") != hashlib.sha256(content).hexdigest()
        or not isinstance(metadata.get("signature_count"), int)
        or metadata.get("signature_count") < 0
    ):
        raise ValueError("Threat database failed its integrity check.")
    return metadata


def _write_metadata(content, signature_count, source="local"):
    metadata = {
        "version": _DATABASE_VERSION,
        "sha256": hashlib.sha256(content).hexdigest(),
        "signature_count": signature_count,
        "source": source,
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    destination = _metadata_path()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}-",
        suffix=".tmp",
        dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            json.dump(metadata, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _read_database_file(path):
    with Path(path).open("rb") as file:
        content = file.read(MAX_SIGNATURE_DATABASE_BYTES + 1)
    if len(content) > MAX_SIGNATURE_DATABASE_BYTES:
        raise ValueError("Threat database exceeds the 100 MiB size limit.")
    return content


def _ensure_database_file():
    with _DATABASE_LOCK:
        if (
            getattr(sys, "frozen", False)
            and
            not DATABASE_FILE.exists()
            and DATABASE_FILE != BUNDLED_DATABASE_FILE
            and BUNDLED_DATABASE_FILE.is_file()
        ):
            if BUNDLED_DATABASE_FILE.stat().st_size > MAX_SIGNATURE_DATABASE_BYTES:
                raise ValueError("Bundled threat database exceeds the size limit.")
            DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BUNDLED_DATABASE_FILE, DATABASE_FILE)
            content = _read_database_file(DATABASE_FILE)
            _write_metadata(
                content,
                sum(
                    1
                    for line in content.decode("utf-8-sig").splitlines()
                    if "|" in line and not line.lstrip().startswith("#")
                ),
                source="bundled",
            )


def get_database_status():
    _ensure_database_file()
    if (
        DATABASE_FILE.exists()
        and DATABASE_FILE.stat().st_size > MAX_SIGNATURE_DATABASE_BYTES
    ):
        raise ValueError("Threat database exceeds the 100 MiB size limit.")
    content = _read_database_file(DATABASE_FILE) if DATABASE_FILE.exists() else b""
    if not content:
        return {
            "version": _DATABASE_VERSION,
            "count": 0,
            "integrity": "unavailable",
            "sha256": hashlib.sha256(content).hexdigest(),
            "updated_at": None,
            "source": None,
        }
    _validate_database_integrity(content)
    try:
        metadata = json.loads(_metadata_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        metadata = {}
    return {
        "version": metadata.get("version", _DATABASE_VERSION),
        "count": len(load_database()),
        "integrity": "verified" if metadata else "unverified (legacy database)",
        "sha256": hashlib.sha256(content).hexdigest(),
        "updated_at": metadata.get("updated_at"),
        "source": metadata.get("source"),
    }


def load_database():
    global _DATABASE_CACHE, _DATABASE_CACHE_KEY

    _ensure_database_file()
    try:
        stat = DATABASE_FILE.stat()
        if stat.st_size > MAX_SIGNATURE_DATABASE_BYTES:
            raise ValueError("Threat database exceeds the 100 MiB size limit.")
        try:
            metadata_stat = _metadata_path().stat()
            metadata_key = (metadata_stat.st_mtime_ns, metadata_stat.st_size)
        except FileNotFoundError:
            metadata_key = None
        cache_key = (stat.st_mtime_ns, stat.st_size, metadata_key)
    except FileNotFoundError:
        cache_key = None
    except OSError:
        raise

    with _DATABASE_LOCK:
        database = {}
        if (
            _DATABASE_CACHE is not None
            and _DATABASE_CACHE_KEY == cache_key
        ):
            database.update(_DATABASE_CACHE)
            return database

        if cache_key is None:
            _DATABASE_CACHE = {}
            _DATABASE_CACHE_KEY = None
            return database

        loaded = {}
        try:
            content = _read_database_file(DATABASE_FILE)
            metadata = _validate_database_integrity(content)
            for line_number, raw_line in enumerate(
                content.decode("utf-8-sig").splitlines(),
                1
            ):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "|" not in line:
                    raise ValueError(
                        f"Threat database contains an invalid entry on line "
                        f"{line_number}."
                    )
                file_hash, threat_name = line.split("|", 1)
                file_hash = file_hash.strip().lower()
                threat_name = threat_name.strip()
                if not _valid_signature(file_hash, threat_name):
                    raise ValueError(
                        f"Threat database contains an invalid signature on "
                        f"line {line_number}."
                    )
                if file_hash in loaded:
                    raise ValueError(
                        f"Threat database contains a duplicate signature on "
                        f"line {line_number}."
                    )
                loaded[file_hash] = threat_name
            if (
                metadata is not None
                and len(loaded) != metadata["signature_count"]
            ):
                raise ValueError(
                    "Threat database signature count does not match its metadata."
                )
        except (OSError, UnicodeError) as error:
            raise ValueError(f"Threat database could not be loaded: {error}") from error

        _DATABASE_CACHE = loaded
        _DATABASE_CACHE_KEY = cache_key
        database.update(loaded)
        return database


def reload_database():
    global _DATABASE_CACHE, _DATABASE_CACHE_KEY
    with _DATABASE_LOCK:
        _DATABASE_CACHE = None
        _DATABASE_CACHE_KEY = None
    return load_database()


def _write_database(database, source="local"):
    global _DATABASE_CACHE, _DATABASE_CACHE_KEY

    if len(database) > MAX_SIGNATURE_COUNT:
        raise ValueError("Threat database exceeds the signature-count limit.")
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if (
        DATABASE_FILE.exists()
        and DATABASE_FILE.stat().st_size > MAX_SIGNATURE_DATABASE_BYTES
    ):
        raise ValueError("Existing threat database exceeds the size limit.")
    previous_database = (
        _read_database_file(DATABASE_FILE)
        if DATABASE_FILE.exists()
        else None
    )
    metadata_file = _metadata_path()
    previous_metadata = (
        metadata_file.read_bytes()
        if metadata_file.exists()
        else None
    )
    content = "".join(
        f"{file_hash}|{threat_name}\n"
        for file_hash, threat_name in sorted(database.items())
    ).encode("utf-8")
    if len(content) > MAX_SIGNATURE_DATABASE_BYTES:
        raise ValueError("Threat database exceeds the 100 MiB size limit.")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{DATABASE_FILE.name}-",
        suffix=".tmp",
        dir=DATABASE_FILE.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            file.write(content.decode("utf-8"))
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, DATABASE_FILE)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    try:
        _write_metadata(content, len(database), source=source)
    except Exception:
        if previous_database is None:
            DATABASE_FILE.unlink(missing_ok=True)
        else:
            DATABASE_FILE.write_bytes(previous_database)
        if previous_metadata is None:
            metadata_file.unlink(missing_ok=True)
        else:
            metadata_file.write_bytes(previous_metadata)
        raise
    _DATABASE_CACHE = dict(database)
    stat = DATABASE_FILE.stat()
    metadata_stat = _metadata_path().stat()
    _DATABASE_CACHE_KEY = (
        stat.st_mtime_ns,
        stat.st_size,
        (metadata_stat.st_mtime_ns, metadata_stat.st_size)
    )


def _valid_signature(file_hash, threat_name):
    if not isinstance(threat_name, str):
        return False

    return bool(
        _HASH_PATTERN.fullmatch(str(file_hash).strip().lower())
        and threat_name.strip()
        and len(threat_name) <= 256
        and not any(ord(character) < 32 for character in threat_name)
        and "\n" not in threat_name
        and "\r" not in threat_name
        and "|" not in threat_name
    )


def import_local_signatures(source_path):
    additions = {}
    invalid_lines = []
    source = Path(source_path)
    if (
        source.is_symlink()
        or (hasattr(source, "is_junction") and source.is_junction())
        or not source.is_file()
    ):
        raise ValueError("Select a regular local signature file.")
    if source.stat().st_size > MAX_SIGNATURE_BUNDLE_BYTES:
        raise ValueError("Signature bundle exceeds the 50 MiB size limit.")

    bytes_read = 0
    with source.open("rb") as file:
        line_number = 0
        while True:
            raw_bytes = file.readline(
                MAX_SIGNATURE_BUNDLE_BYTES - bytes_read + 1
            )
            if not raw_bytes:
                break
            bytes_read += len(raw_bytes)
            if bytes_read > MAX_SIGNATURE_BUNDLE_BYTES:
                raise ValueError("Signature bundle exceeds the 50 MiB size limit.")
            line_number += 1
            try:
                raw_line = raw_bytes.decode(
                    "utf-8-sig" if line_number == 1 else "utf-8"
                )
            except UnicodeError as error:
                raise ValueError("Signature bundle must be valid UTF-8 text.") from error
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" not in line:
                invalid_lines.append(line_number)
                continue

            file_hash, threat_name = line.split("|", 1)
            file_hash = file_hash.strip().lower()
            threat_name = threat_name.strip()
            if not _valid_signature(file_hash, threat_name):
                invalid_lines.append(line_number)
                continue
            additions[file_hash] = threat_name
            if len(additions) > MAX_SIGNATURE_COUNT:
                raise ValueError("Signature bundle exceeds the signature-count limit.")

    if not additions:
        raise ValueError("No valid SHA-256 threat signatures were found.")

    with _DATABASE_LOCK:
        database = load_database()
        database.update(additions)
        _write_database(database)

    return {
        "imported": len(additions),
        "invalid_lines": invalid_lines,
        "total": len(database),
    }


def replace_database(database, source="local"):
    if not isinstance(database, dict):
        raise TypeError("Threat database must be a mapping.")

    normalized = {}
    for file_hash, threat_name in database.items():
        file_hash = str(file_hash).strip().lower()
        if not _valid_signature(file_hash, threat_name):
            raise ValueError(f"Invalid threat signature: {file_hash}")
        normalized[file_hash] = str(threat_name).strip()

    with _DATABASE_LOCK:
        _write_database(normalized, source=source)
        THREAT_DATABASE.clear()
    return len(normalized)


def calculate_sha256(filepath):
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower()
    except (PermissionError, OSError):
        return None


def check_hash(file_hash):
    if not file_hash:
        return None
    return load_database().get(file_hash.lower())


def get_signature_details(file_hash, threat_name=None):
    if threat_name is None:
        threat_name = check_hash(file_hash)
    if not threat_name:
        return None
    tokens = set(re.findall(r"[a-z]+", threat_name.casefold()))
    if tokens.intersection({"ransom", "ransomware", "locker", "cryptolocker"}):
        category = "ransomware"
    elif tokens.intersection({"worm", "botnet"}):
        category = "worm"
    elif tokens.intersection({
        "spyware",
        "stealer",
        "steal",
        "keylogger",
    }):
        category = "spyware"
    elif tokens.intersection({"trojan", "backdoor", "rat"}):
        category = "trojan"
    elif tokens.intersection({"virus", "eicar"}):
        category = "virus / test signature"
    elif "rootkit" in tokens:
        category = "rootkit"
    elif "adware" in tokens:
        category = "adware"
    elif tokens.intersection({"downloader", "dropper"}):
        category = "downloader / dropper"
    else:
        category = "malware (signature category unspecified)"
    return {
        "name": threat_name,
        "category": category,
        "classification": "Confirmed malware signature",
        "confidence": "Confirmed",
    }


def add_threat_hash(file_hash, threat_name):
    if not _valid_signature(file_hash, threat_name):
        return False

    file_hash = file_hash.lower().strip()
    try:
        with _DATABASE_LOCK:
            database = load_database()
            database[file_hash] = threat_name.strip()
            _write_database(database)
            THREAT_DATABASE[file_hash] = threat_name.strip()
        return True
    except OSError:
        return False


def remove_threat_hash(file_hash):
    if not file_hash or not _HASH_PATTERN.fullmatch(file_hash.lower().strip()):
        return False

    file_hash = file_hash.lower().strip()
    try:
        with _DATABASE_LOCK:
            database = load_database()
            if file_hash not in database:
                return False
            database.pop(file_hash)
            _write_database(database)
            THREAT_DATABASE.pop(file_hash, None)
        return True
    except OSError:
        return False


def get_database_size():
    return len(load_database())


def get_all_threats():
    return load_database()
