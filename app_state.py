import json
import os
import tempfile
import re
import zipfile
import threading
import hashlib
import shutil
from datetime import datetime
from pathlib import Path


DEFAULT_SETTINGS = {
    "appearance": "Dark",
    "resource_monitoring": True,
    "scan_workers": 4,
    "max_file_size_mb": 100,
    "scan_exclusions": [],
    "scheduled_scan_enabled": False,
    "scheduled_scan_interval_hours": 24,
    "scheduled_scan_type": "Quick Scan",
    "next_scheduled_scan": None,
}

MAX_HISTORY_EVENTS = 1000
MAX_BACKUP_SIZE = 2 * 1024 * 1024 * 1024
MAX_BACKUP_METADATA_SIZE = 64 * 1024 * 1024


def default_data_directory():
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "ITSecurityScanner"
        return Path.home() / "AppData" / "Local" / "ITSecurityScanner"

    return Path.home() / ".local" / "share" / "it-security-scanner"


class AppState:
    def __init__(self, data_directory=None):
        self.data_directory = Path(
            data_directory or default_data_directory()
        )
        self.settings_path = self.data_directory / "settings.json"
        self.history_path = self.data_directory / "events.jsonl"
        self._history_lock = threading.RLock()

    def load_settings(self):
        settings = DEFAULT_SETTINGS.copy()
        try:
            with self.settings_path.open("r", encoding="utf-8") as file:
                loaded = json.load(file)
        except FileNotFoundError:
            return settings

        if not isinstance(loaded, dict):
            raise ValueError("Settings file must contain a JSON object.")

        settings.update(loaded)
        settings["scan_exclusions"] = self._normalize_exclusions(
            settings.get("scan_exclusions")
        )

        if settings.get("appearance") not in {"Dark", "Light", "System"}:
            settings["appearance"] = DEFAULT_SETTINGS["appearance"]

        interval = settings.get("scheduled_scan_interval_hours")
        if not isinstance(interval, int) or interval not in {6, 12, 24, 168}:
            settings["scheduled_scan_interval_hours"] = 24

        if settings.get("scheduled_scan_type") not in {
            "Quick Scan",
            "Full Scan",
        }:
            settings["scheduled_scan_type"] = "Quick Scan"

        settings["resource_monitoring"] = bool(
            settings.get("resource_monitoring", True)
        )
        scan_workers = settings.get("scan_workers", 4)
        if (
            not isinstance(scan_workers, int)
            or isinstance(scan_workers, bool)
            or scan_workers not in {1, 2, 4, 8, 16}
        ):
            settings["scan_workers"] = 4
        max_file_size_mb = settings.get("max_file_size_mb", 100)
        if (
            not isinstance(max_file_size_mb, int)
            or isinstance(max_file_size_mb, bool)
            or max_file_size_mb not in {25, 50, 100, 250, 500}
        ):
            settings["max_file_size_mb"] = 100
        settings["scheduled_scan_enabled"] = bool(
            settings.get("scheduled_scan_enabled", False)
        )
        return settings

    def save_settings(self, settings):
        if not isinstance(settings, dict):
            raise TypeError("Settings must be a dictionary.")

        normalized = DEFAULT_SETTINGS.copy()
        normalized.update(settings)
        normalized["scan_exclusions"] = self._normalize_exclusions(
            normalized.get("scan_exclusions")
        )
        if (
            not isinstance(normalized.get("scan_workers"), int)
            or isinstance(normalized.get("scan_workers"), bool)
            or normalized["scan_workers"] not in {1, 2, 4, 8, 16}
        ):
            normalized["scan_workers"] = 4
        max_file_size_mb = normalized.get("max_file_size_mb", 100)
        if (
            not isinstance(max_file_size_mb, int)
            or isinstance(max_file_size_mb, bool)
            or max_file_size_mb not in {25, 50, 100, 250, 500}
        ):
            normalized["max_file_size_mb"] = 100
        self.data_directory.mkdir(parents=True, exist_ok=True)
        self._atomic_write(
            self.settings_path,
            json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"
        )

    @staticmethod
    def _normalize_exclusions(exclusions):
        if not isinstance(exclusions, list):
            return []

        normalized = []
        seen = set()
        for value in exclusions:
            if not isinstance(value, str) or not value.strip():
                continue
            path = str(Path(value.strip()).expanduser())
            key = os.path.normcase(os.path.normpath(path))
            if key not in seen:
                normalized.append(path)
                seen.add(key)
        return normalized

    def record_event(self, event_type, message, details=None):
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Event type must not be empty.")
        event = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "type": event_type.strip(),
            "message": str(message),
            "details": details if isinstance(details, dict) else {},
        }

        self.data_directory.mkdir(parents=True, exist_ok=True)
        with self._history_lock:
            with self.history_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(event, ensure_ascii=False) + "\n")
                file.flush()
                os.fsync(file.fileno())
            self._trim_history()
        return event

    def _trim_history(self):
        try:
            lines = self.history_path.read_text(
                encoding="utf-8"
            ).splitlines()
        except FileNotFoundError:
            return

        if len(lines) > MAX_HISTORY_EVENTS:
            content = "\n".join(lines[-MAX_HISTORY_EVENTS:]) + "\n"
            self._atomic_write(self.history_path, content)

    def get_recent_events(self, limit=50):
        if limit < 1:
            return []

        with self._history_lock:
            try:
                lines = self.history_path.read_text(
                    encoding="utf-8"
                ).splitlines()
            except FileNotFoundError:
                return []

        events = []
        for line in reversed(lines):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
                if len(events) >= limit:
                    break
        return events

    def create_backup(
        self,
        destination,
        quarantine_directory,
        signatures_file
    ):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="scanner-backup-",
            suffix=".tmp",
            dir=destination.parent
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)

        try:
            with zipfile.ZipFile(
                temporary_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=3
            ) as archive:
                self._write_backup_file(
                    archive,
                    self.settings_path,
                    "settings.json"
                )
                self._write_backup_file(
                    archive,
                    self.history_path,
                    "events.jsonl"
                )
                self._write_backup_file(
                    archive,
                    Path(signatures_file),
                    "known_threats.txt"
                )

                quarantine = Path(quarantine_directory)
                if quarantine.exists():
                    for item in quarantine.iterdir():
                        if item.is_file() and not item.is_symlink():
                            if item.name.startswith("."):
                                continue
                            if item.suffix not in {".quarantine", ".json", ".bin"}:
                                continue
                            if item.suffix == ".json":
                                if not re.fullmatch(r"[0-9a-f]{32}\.json", item.name):
                                    continue
                            if item.suffix == ".quarantine":
                                if not re.fullmatch(r"[0-9a-f]{32}\.quarantine", item.name):
                                    continue
                            archive.write(
                                item,
                                f"quarantine/{item.name}"
                            )

            os.replace(temporary_path, destination)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

        return destination

    @staticmethod
    def _write_backup_file(archive, source, archive_name):
        source = Path(source)
        if source.is_file():
            archive.write(source, archive_name)

    def restore_backup(
        self,
        archive_path,
        quarantine_directory,
        signatures_file
    ):
        archive_path = Path(archive_path)
        archive_path = Path(archive_path)
        quarantine = Path(quarantine_directory)
        signatures_file = Path(signatures_file)

        rollback_errors = []
        transaction = None
        committed_quarantine = []
        snapshot_targets = {}

        try:
            quarantine.parent.mkdir(parents=True, exist_ok=True)
            transaction = Path(tempfile.mkdtemp(
                prefix=".ITSecurityScanner-restore-",
                dir=quarantine.parent
            ))
            stage = transaction / "stage"
            snapshot = transaction / "snapshot"
            stage.mkdir()
            snapshot.mkdir()

            self._recover_interrupted_restore(
                quarantine,
                signatures_file,
                rollback_errors
            )

            with zipfile.ZipFile(archive_path, "r") as archive:
                entries = archive.infolist()
                if sum(item.file_size for item in entries) > MAX_BACKUP_SIZE:
                    raise ValueError("Backup exceeds the allowed restore size.")

                names = [entry.filename for entry in entries]
                if len(names) != len(set(names)):
                    raise ValueError("Backup contains duplicate entries.")

                allowed = {"settings.json", "events.jsonl", "known_threats.txt"}
                quarantine_entries = []
                for entry in entries:
                    name = entry.filename
                    if name in allowed:
                        if self._is_symlink(entry):
                            raise ValueError("Backup contains an invalid entry.")
                        if entry.file_size > MAX_BACKUP_METADATA_SIZE:
                            raise ValueError(
                                f"Backup metadata file is too large: {name}"
                            )
                        continue
                    if name.startswith("quarantine/"):
                        filename = name[len("quarantine/"):]
                        if (
                            not filename
                            or Path(filename).name != filename
                            or filename in {".", ".."}
                            or self._is_symlink(entry)
                        ):
                            raise ValueError("Backup contains an unsafe quarantine path.")
                        quarantine_entries.append((entry, filename))
                        continue
                    raise ValueError(f"Unexpected backup entry: {name}")

                staged = {}
                for archive_name, target in (
                    ("settings.json", self.settings_path),
                    ("events.jsonl", self.history_path),
                    ("known_threats.txt", signatures_file),
                ):
                    if archive_name in archive.namelist():
                        staged[target] = archive.read(archive_name)

                self._validate_backup_metadata(staged, signatures_file)

                staged_payloads = {}
                staged_manifests = {}
                for index, (entry, filename) in enumerate(quarantine_entries):
                    staged_file = stage / str(index)
                    with archive.open(entry, "r") as source:
                        with staged_file.open("xb") as destination:
                            while chunk := source.read(1024 * 1024):
                                destination.write(chunk)
                    if filename.endswith(".json"):
                        staged_manifests[filename] = staged_file
                    else:
                        staged_payloads[filename] = staged_file

                restore_records = self._validate_and_plan_quarantine_restore(
                    staged_payloads,
                    staged_manifests
                )

            if quarantine.exists() and not quarantine.is_dir():
                raise OSError("Quarantine location is not a directory.")
            quarantine.mkdir(parents=True, exist_ok=True)

            targets = (
                [(self.settings_path, staged.get(self.settings_path))]
                if self.settings_path in staged else []
            )
            targets += (
                [(self.history_path, staged.get(self.history_path))]
                if self.history_path in staged else []
            )
            targets += (
                [(signatures_file, staged.get(signatures_file))]
                if signatures_file in staged else []
            )
            for target, _content in targets:
                snapshot_targets[target] = self._snapshot_restore_target(
                    target,
                    snapshot,
                    len(snapshot_targets)
                )
                if target == signatures_file:
                    metadata_target = target.with_suffix(
                        target.suffix + ".meta.json"
                    )
                    snapshot_targets[metadata_target] = (
                        self._snapshot_restore_target(
                            metadata_target,
                            snapshot,
                            len(snapshot_targets)
                        )
                    )

            marker = transaction / "commit.marker"
            marker.write_text(
                json.dumps({
                    "state": "committing",
                    "quarantine": str(quarantine),
                    "signature_target": str(signatures_file),
                    "committed_quarantine": [],
                    "snapshots": [
                        {
                            "target": str(snapshot["target"]),
                            "exists": snapshot["exists"],
                            "backup": str(snapshot["backup"]),
                        }
                        for snapshot in snapshot_targets.values()
                    ],
                }),
                encoding="utf-8"
            )

            for record in restore_records:
                source = record["source"]
                target = quarantine / record["target_name"]
                target = self._reserve_restore_target(quarantine, target)
                planned_records = [target]
                manifest = record["manifest"]
                manifest_target = None
                if manifest is not None:
                    manifest_target = quarantine / f"{target.stem}.json"
                    planned_records.append(manifest_target)
                marker.write_text(
                    json.dumps({
                        "state": "committing",
                        "quarantine": str(quarantine),
                        "signature_target": str(signatures_file),
                        "committed_quarantine": [
                            str(path) for path in
                            list(committed_quarantine) + planned_records
                        ],
                        "snapshots": [
                            {
                                "target": str(snapshot["target"]),
                                "exists": snapshot["exists"],
                                "backup": str(snapshot["backup"]),
                            }
                            for snapshot in snapshot_targets.values()
                        ],
                    }),
                    encoding="utf-8"
                )
                os.replace(source, target)
                committed_quarantine.append(target)
                record["restored_name"] = target.name

                if manifest is not None:
                    manifest["id"] = target.stem
                    manifest["sha256"] = hashlib.sha256(
                        target.read_bytes()
                    ).hexdigest()
                    manifest_target = quarantine / f"{target.stem}.json"
                    if manifest_target.exists():
                        raise OSError(
                            f"Restore record collision: {manifest_target.name}"
                        )
                    manifest_descriptor, manifest_temp = tempfile.mkstemp(
                        prefix=".quarantine-manifest-",
                        suffix=".tmp",
                        dir=quarantine
                    )
                    with os.fdopen(
                        manifest_descriptor,
                        "w",
                        encoding="utf-8"
                    ) as manifest_file:
                        json.dump(
                            manifest,
                            manifest_file,
                            ensure_ascii=False,
                            indent=2
                        )
                        manifest_file.write("\n")
                    try:
                        os.replace(manifest_temp, manifest_target)
                    except OSError:
                        Path(manifest_temp).unlink(missing_ok=True)
                        raise
                    committed_quarantine.append(manifest_target)
                marker.write_text(
                    json.dumps({
                        "state": "committing",
                        "quarantine": str(quarantine),
                        "signature_target": str(signatures_file),
                        "committed_quarantine": [
                            str(path) for path in committed_quarantine
                        ],
                        "snapshots": [
                            {
                                "target": str(snapshot["target"]),
                                "exists": snapshot["exists"],
                                "backup": str(snapshot["backup"]),
                            }
                            for snapshot in snapshot_targets.values()
                        ],
                    }),
                    encoding="utf-8"
                )

            for target, content in targets:
                if content is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    self._atomic_write(target, content)
                    if target == signatures_file:
                        metadata_target = target.with_suffix(
                            target.suffix + ".meta.json"
                        )
                        try:
                            content_text = content.decode("utf-8")
                            lines = content_text.splitlines()
                            signatures = {
                                parts[0].strip().lower()
                                for line in lines
                                if "|" in line
                                for parts in [line.split("|", 1)]
                                if re.fullmatch(r"[0-9a-f]{64}", parts[0].strip())
                            }
                            metadata_target_content = json.dumps({
                                "version": 1,
                                "sha256": hashlib.sha256(content).hexdigest(),
                                "signature_count": len(signatures),
                                "source": "backup",
                            }, indent=2) + "\n"
                            self._atomic_write(
                                metadata_target,
                                metadata_target_content
                            )
                        except (UnicodeDecodeError, ValueError, OSError) as error:
                            raise OSError(
                                f"Could not restore signature integrity metadata: {error}"
                            ) from error

            marker.write_text(
                json.dumps({"state": "committed"}),
                encoding="utf-8"
            )
            shutil.rmtree(transaction)
            return {
                "restored_files": len(restore_records),
                "restored_quarantine": [
                    str(quarantine / record["restored_name"])
                    for record in restore_records
                ],
                "restored_settings": self.settings_path in staged,
                "restored_history": self.history_path in staged,
                "restored_signatures": signatures_file in staged,
            }
        except Exception as error:
            rollback_errors.extend(
                self._rollback_restore(
                    transaction,
                    snapshot_targets,
                    committed_quarantine
                )
            )
            if rollback_errors:
                detail = "; ".join(str(item) for item in rollback_errors)
                raise OSError(
                    f"Restore failed: {error}. Rollback also failed: {detail}"
                ) from error
            raise

    def _validate_backup_metadata(self, staged, signatures_file):
        settings = staged.get(self.settings_path)
        if settings is not None:
            try:
                parsed = json.loads(settings.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("Backup settings are invalid.") from error
            if not isinstance(parsed, dict):
                raise ValueError("Backup settings are invalid.")

        signatures = staged.get(signatures_file)
        if signatures is not None:
            try:
                signatures.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(
                    "Backup contains invalid UTF-8 threat signatures."
                ) from error
            signature_pattern = re.compile(
                rb"^[0-9a-fA-F]{64}\|[^\r\n|]+$"
            )
            for line in signatures.splitlines():
                if line and not line.startswith(b"#"):
                    if not signature_pattern.fullmatch(line):
                        raise ValueError(
                            "Backup contains an invalid threat signature."
                        )

        history = staged.get(self.history_path)
        if history is not None:
            for line in history.splitlines():
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError("Backup event history is invalid.") from error
                if not isinstance(event, dict):
                    raise ValueError("Backup event history is invalid.")

    def _validate_and_plan_quarantine_restore(
        self,
        staged_payloads,
        staged_manifests
    ):
        records = []
        for filename, source in staged_payloads.items():
            if re.fullmatch(r"[0-9a-f]{32}\.quarantine", filename):
                stem = filename[:-len(".quarantine")]
                target_name = filename
            else:
                source_stem = filename[:-len(".quarantine")] if filename.endswith(".quarantine") else Path(filename).stem
                if re.fullmatch(r"[0-9a-f]+", source_stem):
                    stem = source_stem
                else:
                    stem = hashlib.sha256(
                        filename.encode("utf-8") + source.read_bytes()
                    ).hexdigest()[:32]
                target_name = f"{stem.zfill(32)[-32:]}.quarantine"
            manifest_name = f"{stem}.json"
            manifest = None
            manifest_source = staged_manifests.get(manifest_name)
            if manifest_source is None:
                manifest_source = staged_manifests.get(
                    f"{Path(filename).stem}.json"
                )
            if manifest_source is not None:
                try:
                    manifest = json.loads(
                        manifest_source.read_text(encoding="utf-8")
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise ValueError(
                        "Backup contains corrupted quarantine metadata."
                    ) from error
                if not isinstance(manifest, dict):
                    raise ValueError(
                        "Backup contains invalid quarantine metadata."
                    )
                if (
                    manifest.get("id") != stem
                    or manifest.get("state") not in {
                        "pending",
                        "quarantined",
                        "restoring",
                        "integrity_error",
                    }
                    or not isinstance(manifest.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])
                    or not isinstance(manifest.get("original_name"), str)
                ):
                    raise ValueError(
                        "Backup contains invalid quarantine manifest structure."
                    )
            actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if manifest is not None and actual_hash != manifest["sha256"]:
                raise ValueError(
                    f"Quarantine payload SHA-256 mismatch: {filename}"
                )
            records.append({
                "source": source,
                "target_name": target_name,
                "manifest": manifest,
            })

        orphan_manifests = set(staged_manifests)
        for filename, source in staged_payloads.items():
            stem = Path(filename).stem
            orphan_manifests.discard(f"{stem}.json")
        if orphan_manifests:
            raise ValueError(
                "Backup contains quarantine manifests without matching payloads."
            )

        return records

    def _snapshot_restore_target(self, target, snapshot, index):
        backup = snapshot / f"{index}.previous"
        if target.is_symlink() or (
            hasattr(target, "is_junction") and target.is_junction()
        ):
            raise OSError(
                f"Refusing to replace linked restore target: {target}"
            )
        if target.exists():
            if not target.is_file():
                raise OSError(
                    f"Restore target is not a regular file: {target}"
                )
            shutil.copy2(target, backup)
            return {"target": target, "exists": True, "backup": backup}
        return {"target": target, "exists": False, "backup": backup}

    @staticmethod
    def _reserve_restore_target(quarantine, target):
        if not target.exists():
            return target
        stem, suffix = target.stem, target.suffix
        index = 1
        while target.exists():
            target = quarantine / f"{stem}_restored_{index}{suffix}"
            index += 1
        return target

    def _rollback_restore(
        self,
        transaction,
        snapshot_targets,
        committed_quarantine
    ):
        errors = []
        for target, snapshot in reversed(list(snapshot_targets.items())):
            try:
                if snapshot["exists"]:
                    os.replace(snapshot["backup"], target)
                else:
                    target.unlink(missing_ok=True)
            except OSError as error:
                errors.append(
                    f"Could not restore snapshot for {target}: {error}"
                )

        for path in reversed(committed_quarantine):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                errors.append(
                    f"Could not remove restored record {path}: {error}"
                )

        if transaction is not None:
            try:
                shutil.rmtree(transaction)
            except OSError as error:
                errors.append(
                    f"Could not clean restore transaction {transaction}: {error}"
                )
        return errors

    def recover_interrupted_restore(
        self,
        quarantine,
        signatures_file
    ):
        rollback_errors = []
        self._recover_interrupted_restore(
            Path(quarantine),
            Path(signatures_file),
            rollback_errors
        )
        return rollback_errors

    def _recover_interrupted_restore(
        self,
        quarantine,
        signatures_file,
        rollback_errors
    ):
        transaction_root = quarantine.parent
        try:
            candidates = sorted(
                transaction_root.glob(".ITSecurityScanner-restore-*"),
                key=lambda path: path.stat().st_mtime,
                reverse=True
            )
        except OSError as error:
            rollback_errors.append(
                f"Could not inspect interrupted restore transactions: {error}"
            )
            return

        for transaction in candidates:
            if (
                transaction.is_symlink()
                or not transaction.is_dir()
            ):
                rollback_errors.append(
                    f"Ignored unsafe restore transaction: {transaction}"
                )
                continue
            marker = transaction / "commit.marker"
            if (
                marker.is_symlink()
                or not marker.is_file()
            ):
                continue
            try:
                marker_data = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                rollback_errors.append(
                    f"Could not read interrupted restore marker "
                    f"{marker}: {error}"
                )
                continue
            if marker_data.get("state") != "committing":
                continue
            marker_quarantine = marker_data.get("quarantine")
            marker_signature = marker_data.get("signature_target")
            try:
                marker_quarantine = Path(marker_quarantine).resolve(strict=True)
                marker_signature = Path(marker_signature).resolve(strict=False)
                current_quarantine = quarantine.resolve(strict=True)
                current_signature = signatures_file.resolve(strict=False)
            except (OSError, TypeError, ValueError) as error:
                rollback_errors.append(
                    f"Ignored invalid restore transaction marker: {error}"
                )
                continue
            if (
                os.path.normcase(str(marker_quarantine))
                != os.path.normcase(str(current_quarantine))
                or os.path.normcase(str(marker_signature))
                != os.path.normcase(str(current_signature))
            ):
                rollback_errors.append(
                    "Ignored restore transaction for a different quarantine "
                    "or signature location."
                )
                continue

            allowed_metadata_targets = {
                self.settings_path.resolve(strict=False),
                self.history_path.resolve(strict=False),
                marker_signature,
                marker_signature.with_suffix(
                    marker_signature.suffix + ".meta.json"
                ),
            }
            allowed_metadata_targets = {
                os.path.normcase(str(path))
                for path in allowed_metadata_targets
            }
            snapshot_directory = (transaction / "snapshot").resolve(strict=False)
            restoring_errors = []
            for snapshot in marker_data.get("snapshots", []):
                target = Path(snapshot["target"])
                backup = Path(snapshot["backup"])
                try:
                    resolved_target = target.resolve(strict=False)
                    resolved_backup = backup.resolve(strict=False)
                    try:
                        resolved_backup.relative_to(snapshot_directory)
                    except ValueError as error:
                        raise OSError(
                            f"Refusing restore snapshot outside transaction: {backup}"
                        ) from error
                    if (
                        os.path.normcase(str(resolved_target))
                        not in allowed_metadata_targets
                    ):
                        raise OSError(
                            f"Refusing untrusted restore target: {target}"
                        )
                    if resolved_backup.is_symlink():
                        raise OSError(
                            f"Refusing linked rollback snapshot: {backup}"
                        )
                    if snapshot.get("exists"):
                        if not backup.is_file():
                            raise OSError(
                                f"Missing rollback snapshot: {backup}"
                            )
                        target.parent.mkdir(parents=True, exist_ok=True)
                        os.replace(backup, target)
                    else:
                        target.unlink(missing_ok=True)
                except OSError as error:
                    restoring_errors.append(
                        f"Could not restore {target}: {error}"
                    )
            for value in marker_data.get("committed_quarantine", []):
                path = Path(value)
                try:
                    resolved_path = path.resolve(strict=False)
                    if (
                        resolved_path.parent != current_quarantine
                        or not re.fullmatch(
                            r"[0-9a-f]{32}\.(?:quarantine|json)",
                            resolved_path.name
                        )
                    ):
                        raise OSError(
                            f"Refusing untrusted quarantine recovery path: {path}"
                        )
                    if resolved_path.is_symlink():
                        raise OSError(
                            f"Refusing linked quarantine recovery path: {path}"
                        )
                    resolved_path.unlink(missing_ok=True)
                except OSError as error:
                    restoring_errors.append(str(error))
            if restoring_errors:
                rollback_errors.extend(restoring_errors)

    @staticmethod
    def _is_symlink(entry):
        return (entry.external_attr >> 16) & 0o170000 == 0o120000

    @staticmethod
    def _atomic_write(destination, content):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}-",
            suffix=".tmp",
            dir=destination.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as file:
                if isinstance(content, str):
                    content = content.encode("utf-8")
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
