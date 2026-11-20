import json
import hashlib
import tempfile
import threading
import unittest
import zipfile
from unittest import mock
from pathlib import Path

from app_state import AppState, DEFAULT_SETTINGS


class AppStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.state = AppState(self.root / "state")
        self.quarantine = self.root / "quarantine"
        self.quarantine.mkdir()
        self.signatures = self.root / "known_threats.txt"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_settings_are_saved_normalized_and_reloaded(self):
        self.state.save_settings({
            "appearance": "Light",
            "scan_exclusions": [
                str(self.root / "skip"),
                str(self.root / "skip"),
            ],
            "scheduled_scan_interval_hours": 12,
            "max_file_size_mb": 250,
        })

        loaded = self.state.load_settings()

        self.assertEqual(loaded["appearance"], "Light")
        self.assertEqual(
            loaded["scan_exclusions"],
            [str(self.root / "skip")]
        )
        self.assertEqual(loaded["scheduled_scan_interval_hours"], 12)
        self.assertEqual(loaded["max_file_size_mb"], 250)
        self.assertEqual(
            loaded["scheduled_scan_enabled"],
            DEFAULT_SETTINGS["scheduled_scan_enabled"]
        )

    def test_unsupported_maximum_file_size_uses_safe_default(self):
        self.state.save_settings({"max_file_size_mb": 1000})

        self.assertEqual(
            self.state.load_settings()["max_file_size_mb"],
            DEFAULT_SETTINGS["max_file_size_mb"]
        )

    def test_history_is_newest_first_and_skips_corrupt_lines(self):
        self.state.record_event("scan", "first")
        self.state.record_event("scan", "second")
        with self.state.history_path.open("a", encoding="utf-8") as file:
            file.write("{broken json}\n")

        recent = self.state.get_recent_events(1)

        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["message"], "second")

    def test_concurrent_history_writes_are_all_preserved(self):
        threads = [
            threading.Thread(
                target=self.state.record_event,
                args=("scan", f"event-{index}")
            )
            for index in range(40)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        messages = {
            event["message"]
            for event in self.state.get_recent_events(100)
        }
        self.assertEqual(
            messages,
            {f"event-{index}" for index in range(40)}
        )

    def test_backup_restores_settings_history_signatures_and_quarantine(self):
        self.state.save_settings({"appearance": "Light"})
        self.state.record_event("scan", "saved event")
        self.signatures.write_text(
            f"{'a' * 64}|local-test\n",
            encoding="utf-8"
        )
        (self.quarantine / "isolated.bin").write_bytes(b"isolated payload")
        backup = self.root / "scanner-backup.zip"

        self.state.create_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        self.state.save_settings({"appearance": "Dark"})
        self.state.history_path.unlink()
        self.signatures.unlink()
        (self.quarantine / "isolated.bin").unlink()

        restored = self.state.restore_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        self.assertEqual(self.state.load_settings()["appearance"], "Light")
        self.assertEqual(
            self.state.get_recent_events(1)[0]["message"],
            "saved event"
        )
        self.assertIn("local-test", self.signatures.read_text(encoding="utf-8"))
        restored_payloads = [
            path for path in self.quarantine.iterdir()
            if path.is_file()
        ]
        self.assertEqual(len(restored_payloads), 1)
        self.assertEqual(
            restored_payloads[0].read_bytes(),
            b"isolated payload"
        )
        self.assertEqual(restored["restored_files"], 1)

    def test_backup_preserves_quarantine_manifest(self):
        record_id = "1234567890abcdef1234567890abcdef"
        payload = self.quarantine / f"{record_id}.quarantine"
        manifest = self.quarantine / f"{record_id}.json"
        payload.write_bytes(b"preserve payload")
        payload_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
        manifest.write_text(
            json.dumps({
                "id": record_id,
                "state": "quarantined",
                "original_name": "fixture.txt",
                "original_path": r"C:\test\fixture.txt",
                "sha256": payload_hash,
            }),
            encoding="utf-8"
        )
        backup = self.root / "manifest-backup.zip"
        self.state.create_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        payload.unlink()
        manifest.unlink()
        restored = self.state.restore_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        restored_payload = self.quarantine / payload.name
        restored_manifest = self.quarantine / manifest.name
        self.assertTrue(restored_payload.is_file())
        self.assertTrue(restored_manifest.is_file())
        self.assertEqual(
            json.loads(restored_manifest.read_text(encoding="utf-8"))[
                "original_name"
            ],
            "fixture.txt"
        )

    def test_restore_rejects_path_traversal(self):
        backup = self.root / "unsafe.zip"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr("quarantine/../../outside.txt", "unsafe")

        with self.assertRaises(ValueError):
            self.state.restore_backup(
                backup,
                self.quarantine,
                self.signatures
            )

        self.assertFalse((self.root.parent / "outside.txt").exists())

    def test_restore_rejects_invalid_signatures_before_installing_files(self):
        backup = self.root / "invalid-signatures.zip"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr("known_threats.txt", "not-a-hash|invalid\n")
            archive.writestr("quarantine/recovered.bin", b"payload")

        with self.assertRaises(ValueError):
            self.state.restore_backup(
                backup,
                self.quarantine,
                self.signatures
            )

        self.assertFalse((self.quarantine / "recovered.bin").exists())
        self.assertFalse(self.signatures.exists())

    def test_invalid_settings_are_rejected(self):
        self.state.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.state.settings_path.write_text("[]", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.state.load_settings()

    def test_transactional_restore_failure_preserves_original_state(self):
        self.state.save_settings({"appearance": "Light"})
        self.state.record_event("scan", "original event")
        self.signatures.write_text(
            f"{'b' * 64}|original\n",
            encoding="utf-8"
        )
        (self.quarantine / "original.bin").write_bytes(b"original payload")

        backup = self.root / "rollback.zip"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr("settings.json", json.dumps({
                "appearance": "Dark"
            }))
            archive.writestr(
                "events.jsonl",
                json.dumps({
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "type": "scan",
                    "message": "replacement event",
                    "details": {}
                }) + "\n"
            )
            archive.writestr(
                "known_threats.txt",
                f"{'c' * 64}|replacement\n"
            )
            archive.writestr(
                "quarantine/deadbeef.quarantine",
                b"replacement payload"
            )

        with mock.patch.object(
            self.state,
            "_atomic_write",
            side_effect=OSError("simulated record replacement failure")
        ):
            with self.assertRaisesRegex(
                OSError,
                "record replacement failure"
            ):
                self.state.restore_backup(
                    backup,
                    self.quarantine,
                    self.signatures
                )

        self.assertEqual(
            self.state.load_settings()["appearance"],
            "Light"
        )
        self.assertEqual(
            self.state.get_recent_events(1)[0]["message"],
            "original event"
        )
        self.assertIn(
            "original",
            self.signatures.read_text(encoding="utf-8")
        )
        self.assertEqual(
            (self.quarantine / "original.bin").read_bytes(),
            b"original payload"
        )

    def test_payload_staging_failure_preserves_original_state(self):
        (self.quarantine / "original.bin").write_bytes(b"keep")
        backup = self.root / "staging-failure.zip"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr(
                "quarantine/1234567890abcdef.quarantine",
                b"replacement"
            )

        original_open = zipfile.ZipFile.open

        def failing_open(_self, name, *args, **kwargs):
            filename = getattr(name, "filename", name)
            if str(filename).startswith("quarantine/"):
                raise OSError("simulated payload staging failure")
            return original_open(_self, name, *args, **kwargs)

        with mock.patch.object(
            zipfile.ZipFile,
            "open",
            failing_open
        ):
            with self.assertRaisesRegex(
                OSError,
                "payload staging failure"
            ):
                self.state.restore_backup(
                    backup,
                    self.quarantine,
                    self.signatures
                )

        self.assertEqual(
            (self.quarantine / "original.bin").read_bytes(),
            b"keep"
        )

    def test_hash_mismatch_is_rejected_before_commit(self):
        digest = "a" * 64
        backup = self.root / "hash-mismatch.zip"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr(
                "quarantine/1234567890abcdef.quarantine",
                b"payload"
            )
            archive.writestr(
                "quarantine/1234567890abcdef.json",
                json.dumps({
                    "id": "1234567890abcdef",
                    "state": "quarantined",
                    "original_name": "fixture.txt",
                    "original_path": "",
                    "sha256": digest,
                })
            )

        with self.assertRaisesRegex(
            ValueError,
            "SHA-256 mismatch"
        ):
            self.state.restore_backup(
                backup,
                self.quarantine,
                self.signatures
            )

        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_manifest_payload_mismatch_is_rejected_before_commit(self):
        backup = self.root / "manifest-mismatch.zip"
        record_id = "1234567890abcdef1234567890abcdef"
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr(
                f"quarantine/{record_id}.quarantine",
                b"payload"
            )
            archive.writestr(
                f"quarantine/{record_id}.json",
                json.dumps({
                    "id": record_id,
                    "state": "quarantined",
                    "original_name": "fixture.txt",
                    "original_path": "",
                    "sha256": "f" * 64,
                })
            )

        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.state.restore_backup(
                backup,
                self.quarantine,
                self.signatures
            )
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_interrupted_restore_recovers_snapshot_and_committed_records(self):
        original = self.settings_path if hasattr(self, "settings_path") else self.root / "settings.json"
        original.parent.mkdir(parents=True, exist_ok=True)
        original.write_text(
            json.dumps({"appearance": "Light"}),
            encoding="utf-8"
        )
        transaction = self.root / ".ITSecurityScanner-restore-interrupted"
        snapshot = transaction / "snapshot"
        snapshot.mkdir(parents=True)
        backup = snapshot / "0.previous"
        backup.write_text(
            json.dumps({"appearance": "Light"}),
            encoding="utf-8"
        )
        committed = self.quarantine / "1234567890abcdef1234567890abcdef.quarantine"
        committed.write_bytes(b"partial")
        marker = transaction / "commit.marker"
        marker.write_text(
            json.dumps({
                "state": "committing",
                "quarantine": str(self.quarantine),
                "signature_target": str(self.signatures),
                "committed_quarantine": [str(committed)],
                "snapshots": [{
                    "target": str(original),
                    "exists": True,
                    "backup": str(backup),
                }],
            }),
            encoding="utf-8"
        )

        backup_archive = self.root / "empty-valid.zip"
        with zipfile.ZipFile(backup_archive, "w") as archive:
            archive.writestr(
                "settings.json",
                json.dumps({"appearance": "Dark"})
            )

        self.state.restore_backup(
            backup_archive,
            self.quarantine,
            self.signatures
        )

        self.assertFalse(committed.exists())
        self.assertEqual(
            json.loads(original.read_text(encoding="utf-8"))["appearance"],
            "Light"
        )


    def test_backup_excludes_quarantine_temporary_files(self):
        (self.quarantine / ".scanner-transfer-abc.tmp").write_bytes(b"temporary")
        (self.quarantine / "valid-backup.bin").write_bytes(b"legacy")
        backup = self.root / "filtered-backup.zip"

        self.state.create_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        with zipfile.ZipFile(backup, "r") as archive:
            names = archive.namelist()
        self.assertIn("quarantine/valid-backup.bin", names)
        self.assertFalse(
            any(".scanner-transfer-" in name for name in names)
        )

    def test_signature_restore_updates_integrity_metadata(self):
        backup = self.root / "signature-backup.zip"
        content = f"{'d' * 64}|restored-threat\n".encode("utf-8")
        with zipfile.ZipFile(backup, "w") as archive:
            archive.writestr("known_threats.txt", content)
        self.state.restore_backup(
            backup,
            self.quarantine,
            self.signatures
        )

        metadata_path = self.signatures.with_suffix(
            self.signatures.suffix + ".meta.json"
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(
            metadata["sha256"],
            hashlib.sha256(content).hexdigest()
        )
        self.assertEqual(metadata["signature_count"], 1)
        self.assertEqual(metadata["source"], "backup")


    def test_interrupted_restore_rejects_untrusted_snapshot_target(self):
        outside = self.root / "outside.txt"
        outside.write_text("preserve", encoding="utf-8")
        transaction = self.quarantine.parent / ".ITSecurityScanner-restore-untrusted"
        snapshot = transaction / "snapshot"
        snapshot.mkdir(parents=True)
        backup = snapshot / "0.previous"
        backup.write_text("backup", encoding="utf-8")
        marker = transaction / "commit.marker"
        marker.write_text(
            json.dumps({
                "state": "committing",
                "quarantine": str(self.quarantine),
                "signature_target": str(self.signatures),
                "committed_quarantine": [],
                "snapshots": [{
                    "target": str(outside),
                    "exists": True,
                    "backup": str(backup),
                }],
            }),
            encoding="utf-8"
        )

        errors = self.state.recover_interrupted_restore(
            self.quarantine,
            self.signatures
        )

        self.assertTrue(errors)
        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve")

    def test_interrupted_restore_rejects_linked_snapshot(self):
        transaction = self.quarantine.parent / ".ITSecurityScanner-restore-linked"
        snapshot = transaction / "snapshot"
        snapshot.mkdir(parents=True)
        outside = self.root / "linked-outside.txt"
        outside.write_text("preserve", encoding="utf-8")
        backup = snapshot / "0.previous"
        try:
            backup.symlink_to(outside)
        except OSError:
            self.skipTest("Symbolic-link creation is unavailable.")
        marker = transaction / "commit.marker"
        marker.write_text(
            json.dumps({
                "state": "committing",
                "quarantine": str(self.quarantine),
                "signature_target": str(self.signatures),
                "committed_quarantine": [],
                "snapshots": [{
                    "target": str(self.state.settings_path),
                    "exists": True,
                    "backup": str(backup),
                }],
            }),
            encoding="utf-8"
        )

        errors = self.state.recover_interrupted_restore(
            self.quarantine,
            self.signatures
        )

        self.assertTrue(errors)
        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
