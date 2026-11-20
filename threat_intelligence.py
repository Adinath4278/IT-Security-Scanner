"""Local threat-intelligence status and integrity-checked signature updates."""

import hashlib
import re
from pathlib import Path

from threat_database import (
    MAX_SIGNATURE_BUNDLE_BYTES,
    get_all_threats,
    get_database_status,
    import_local_signatures,
    reload_database,
    replace_database,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def import_verified_update(bundle_path, expected_sha256):
    """Merge a local text bundle only after an out-of-band digest check.

    The expected digest must come from a trusted source separate from the
    bundle. This is integrity verification, not a publisher signature.
    """
    expected = str(expected_sha256).strip().lower()
    if not _SHA256.fullmatch(expected):
        raise ValueError("Provide the trusted 64-character SHA-256 digest.")
    bundle_path = Path(bundle_path)
    if (
        bundle_path.is_symlink()
        or (
            hasattr(bundle_path, "is_junction")
            and bundle_path.is_junction()
        )
        or not bundle_path.is_file()
    ):
        raise ValueError("Select a regular local threat update file.")
    if bundle_path.stat().st_size > MAX_SIGNATURE_BUNDLE_BYTES:
        raise ValueError("Threat update exceeds the 50 MiB size limit.")
    with bundle_path.open("rb") as file:
        bundle = file.read(MAX_SIGNATURE_BUNDLE_BYTES + 1)
    if len(bundle) > MAX_SIGNATURE_BUNDLE_BYTES:
        raise ValueError("Threat update exceeds the 50 MiB size limit.")
    actual = hashlib.sha256(bundle).hexdigest()
    if actual != expected:
        raise ValueError("Threat update digest does not match the trusted digest.")

    additions = {}
    invalid_lines = []
    try:
        lines = bundle.decode("utf-8-sig").splitlines()
    except UnicodeError as error:
        raise ValueError("Threat update must be valid UTF-8 text.") from error
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            invalid_lines.append(line_number)
            continue
        file_hash, name = line.split("|", 1)
        file_hash = file_hash.strip().lower()
        name = name.strip()
        if not _SHA256.fullmatch(file_hash) or not name or "|" in name:
            invalid_lines.append(line_number)
            continue
        if len(name) > 256 or any(ord(character) < 32 for character in name):
            invalid_lines.append(line_number)
            continue
        additions[file_hash] = name
    if invalid_lines or not additions:
        raise ValueError(
            "Threat update contains invalid entries or no signatures; "
            "no database changes were made."
        )

    database = get_all_threats()
    database.update(additions)
    replace_database(database, source="verified-digest-import")
    return {
        "imported": len(additions),
        "total": len(database),
        "sha256": actual,
        "invalid_lines": [],
        "verification": (
            "out-of-band SHA-256 integrity check; publisher authenticity "
            "was not verified"
        ),
    }


def get_threat_intelligence_status():
    database = get_database_status()
    database["signature_count"] = database.pop("count")
    database["available"] = database["signature_count"] > 0
    database["warning"] = (
        "No local signatures are loaded; this is not evidence that the system is clean."
        if not database["available"]
        else None
    )
    return database


def refresh_local_intelligence():
    signatures = reload_database()
    status = get_threat_intelligence_status()
    return {"signatures": len(signatures), "status": status}


def import_user_selected_signatures(path):
    result = import_local_signatures(path)
    status = get_threat_intelligence_status()
    return {**result, "status": status}
