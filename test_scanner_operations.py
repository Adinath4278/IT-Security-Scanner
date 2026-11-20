import errno
import hashlib
import json
import os
import re
import subprocess
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import SecurityScanner
from yara_scanner import YaraScanner


class ScannerOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.quarantine = self.root / "quarantine"
        self.quarantine.mkdir()
        self.assertNotEqual(
            self.quarantine.resolve(),
            (Path.home() / "SecurityScanner_Quarantine").resolve()
        )
        if os.name == "nt":
            identity = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            ).stdout
            user_sid = re.search(
                r"\bS-\d-\d+(?:-\d+)+\b",
                identity
            ).group(0)
            self._windows_acl_patch = patch.object(
                SecurityScanner,
                "_get_windows_owner_and_acl",
                return_value=(
                    user_sid,
                    {
                        "protected": True,
                        "allowed_sids": {user_sid, "S-1-5-18"},
                    }
                )
            )
            self._windows_acl_patch.start()
            self.addCleanup(self._windows_acl_patch.stop)
        self.scanner = SecurityScanner(self.quarantine)
        self.scanner.yara_scanner = type(
            "NoYara",
            (),
            {"scan_file": lambda self, path: []}
        )()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_scan_streams_progress_and_skips_exclusions(self):
        included = self.root / "included"
        excluded = self.root / "excluded"
        included.mkdir()
        excluded.mkdir()
        (included / "one.txt").write_text("one", encoding="utf-8")
        (excluded / "two.txt").write_text("two", encoding="utf-8")
        self.scanner.set_exclusions([excluded])
        seen = []
        self.scanner.analyze_file = (
            lambda path, analysis_errors=None:
            seen.append(Path(path)) or None
        )
        progress = []

        result = self.scanner.custom_scan(
            self.root,
            lambda scanned, total, path: progress.append(
                (scanned, total, path)
            )
        )

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["total"], 1)
        self.assertEqual(seen, [included / "one.txt"])
        self.assertEqual(progress[-1], (1, 1, ""))

    def test_progress_callback_failure_marks_scan_incomplete(self):
        target = self.root / "callback-error.txt"
        target.write_text("test", encoding="utf-8")
        self.scanner.analyze_file = lambda *_args, **_kwargs: None

        def broken_callback(*_args):
            raise RuntimeError("progress sink failed")

        result = self.scanner.custom_scan(self.root, broken_callback)

        self.assertEqual(result["error_count"], 2)
        self.assertTrue(
            all("progress callback failed" in error.lower()
                for error in result["errors"])
        )
        self.assertEqual(result["detection_status"], "Incomplete scan")

    def test_custom_scan_missing_folder_fails_instead_of_reporting_clean(self):
        with self.assertRaises(FileNotFoundError):
            self.scanner.custom_scan(self.root / "no-longer-exists")

        file_target = self.root / "not-a-folder.txt"
        file_target.write_text("test", encoding="utf-8")
        with self.assertRaises(NotADirectoryError):
            self.scanner.custom_scan(file_target)

    def test_file_analysis_error_is_counted_and_scan_continues(self):
        (self.root / "first").write_text("one", encoding="utf-8")
        (self.root / "second").write_text("two", encoding="utf-8")
        processed = []

        def analyze(path, analysis_errors=None):
            if Path(path).name == "first":
                raise ValueError("invalid test file")
            processed.append(Path(path).name)
            return None

        self.scanner.analyze_file = analyze
        result = self.scanner.custom_scan(self.root)

        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("ValueError", result["errors"][0])
        self.assertEqual(processed, ["second"])

    def test_permission_failure_is_reported_without_stopping_the_scan(self):
        denied = self.root / "denied.txt"
        readable = self.root / "readable.txt"
        denied.write_text("denied", encoding="utf-8")
        readable.write_text("readable", encoding="utf-8")
        processed = []

        def analyze(path, analysis_errors=None):
            if Path(path).name == "denied.txt":
                raise PermissionError("access denied")
            processed.append(Path(path).name)
            return None

        self.scanner.analyze_file = analyze
        result = self.scanner.custom_scan(self.root)

        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("PermissionError", result["errors"][0])
        self.assertEqual(processed, ["readable.txt"])

    def test_quarantine_directory_is_not_scanned(self):
        (self.quarantine / "isolated.bin").write_bytes(b"isolated")
        visited = []
        self.scanner.analyze_file = (
            lambda path, analysis_errors=None:
            visited.append(Path(path)) or None
        )

        self.scanner.custom_scan(self.root)

        self.assertEqual(visited, [])

    def test_hash_failure_is_reported_as_incomplete_scan(self):
        unreadable = self.root / "unreadable.txt"
        readable = self.root / "readable.txt"
        unreadable.write_text("one", encoding="utf-8")
        readable.write_text("two", encoding="utf-8")
        calculate_hash = self.scanner.calculate_hash

        def hash_file(path):
            if Path(path).name == "unreadable.txt":
                return None
            return calculate_hash(path)

        with patch.object(
            self.scanner,
            "calculate_hash",
            side_effect=hash_file
        ):
            result = self.scanner.custom_scan(self.root)

        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("Unable to calculate SHA-256", result["errors"][0])

    def test_yara_failure_is_reported_without_losing_known_threat(self):
        path = self.root / "known-threat.bin"
        path.write_bytes(b"known threat content")

        class FailingYara:
            def scan_file(self, filepath):
                raise RuntimeError("rule engine failed")

        self.scanner.yara_scanner = FailingYara()
        with patch("scanner.check_hash", return_value="Test threat"):
            result = self.scanner.custom_scan(self.root)

        self.assertEqual(result["error_count"], 1)
        self.assertIn("YARA analysis failed", result["errors"][0])
        self.assertEqual(len(result["suspicious"]), 1)
        self.assertEqual(
            result["suspicious"][0]["detection_type"],
            "Known Threat"
        )

    def test_script_read_failure_is_not_treated_as_empty_content(self):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                self.scanner.read_script_content(self.root / "script.ps1")

    def test_yara_runtime_failure_is_not_silently_discarded(self):
        class FailingRules:
            def match(self, filepath, timeout):
                raise RuntimeError("rule engine failed")

        yara_scanner = YaraScanner.__new__(YaraScanner)
        yara_scanner.rules = FailingRules()

        with self.assertRaisesRegex(RuntimeError, "rule engine failed"):
            yara_scanner.scan_file(self.root / "sample.bin")

    def test_quarantine_restore_requires_safe_non_existing_destination(self):
        quarantined = self.quarantine / "safe.txt"
        quarantined.write_text("safe", encoding="utf-8")
        existing = self.root / "existing.txt"
        existing.write_text("keep", encoding="utf-8")
        missing_parent = self.root / "missing" / "restored.txt"

        self.assertFalse(
            self.scanner.restore_quarantined_file(
                quarantined,
                existing
            )["success"]
        )
        self.assertFalse(
            self.scanner.restore_quarantined_file(
                quarantined,
                missing_parent
            )["success"]
        )
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")

        destination = self.root / "restored.txt"
        result = self.scanner.restore_quarantined_file(
            quarantined,
            destination
        )

        self.assertTrue(result["success"])
        self.assertFalse(quarantined.exists())
        self.assertEqual(destination.read_text(encoding="utf-8"), "safe")

    def test_quarantine_moves_support_cross_volume_fallback(self):
        source = self.root / "source.bin"
        destination = self.quarantine / "destination.bin"
        source.write_bytes(b"cross-volume payload")
        original_link = os.link
        calls = 0

        def link_after_cross_volume(source_path, destination_path):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EXDEV, "cross-device move")
            return original_link(source_path, destination_path)

        with patch(
            "scanner.os.link",
            side_effect=link_after_cross_volume
        ):
            self.scanner._move_file_safely(source, destination)

        self.assertEqual(calls, 2)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), b"cross-volume payload")

    def test_quarantine_move_never_overwrites_a_racing_destination(self):
        source = self.root / "source.bin"
        destination = self.quarantine / "destination.bin"
        source.write_bytes(b"original")
        original_link = os.link

        def create_destination_then_link(source_path, destination_path):
            Path(destination_path).write_bytes(b"existing")
            return original_link(source_path, destination_path)

        with patch(
            "scanner.os.link",
            side_effect=create_destination_then_link
        ):
            with self.assertRaises(FileExistsError):
                self.scanner._move_file_safely(source, destination)

        self.assertEqual(source.read_bytes(), b"original")
        self.assertEqual(destination.read_bytes(), b"existing")

    def test_individual_file_scan_scans_one_file(self):
        target = self.root / "single.txt"
        target.write_text("content", encoding="utf-8")

        result = self.scanner.individual_file_scan(target)

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["total"], 1)
        self.assertFalse(result["cancelled"])

    def test_file_type_identification_uses_magic_bytes(self):
        target = self.root / "renamed.bin"
        target.write_bytes(b"MZ" + b"\x00" * 64)

        self.assertEqual(
            self.scanner.identify_file_type(target),
            "Windows PE executable"
        )

    def test_large_file_is_skipped_without_becoming_a_detection(self):
        target = self.root / "large.bin"
        target.write_bytes(b"\x00" * 2048)
        scanner = SecurityScanner(self.quarantine, max_file_size=128)
        scanner.yara_scanner = type(
            "NoYara",
            (),
            {"scan_file": lambda self, path: []}
        )()

        result = scanner.individual_file_scan(target)

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("exceeds configured maximum size", result["errors"][0])
        self.assertEqual(result["suspicious"], [])

    def test_scan_cancellation_is_reported(self):
        target = self.root / "cancel.bin"
        target.write_bytes(b"sample")
        seen = []

        def cancel_on_callback(scanned, total, path):
            seen.append(path)
            self.scanner.cancel()

        result = self.scanner.individual_file_scan(
            target,
            cancel_on_callback
        )

        self.assertTrue(result["cancelled"])
        self.assertEqual(result["scanned"], 1)
        self.assertIn(str(target), seen)

    def test_quarantine_uses_unique_names_and_sha256_manifest(self):
        first = self.root / "same.txt"
        second = self.root / "another" / "same.txt"
        second.parent.mkdir()
        first.write_bytes(b"first content")
        second.write_bytes(b"second content")

        first_result = self.scanner.quarantine_file(first)
        second_result = self.scanner.quarantine_file(second)

        self.assertTrue(first_result["success"])
        self.assertTrue(second_result["success"])
        self.assertNotEqual(
            first_result["quarantine_path"],
            second_result["quarantine_path"]
        )
        metadata = self.scanner.get_quarantine_metadata(
            first_result["quarantine_path"]
        )
        self.assertEqual(metadata["original_path"], str(first.resolve()))
        self.assertEqual(
            metadata["sha256"],
            hashlib.sha256(b"first content").hexdigest()
        )
        self.assertEqual(metadata["state"], "quarantined")

    @unittest.skipUnless(os.name == "nt", "Windows quarantine ACL test")
    def test_windows_quarantine_acl_excludes_broad_user_groups(self):
        source = self.root / "restricted.txt"
        source.write_bytes(b"restricted")
        result = self.scanner.quarantine_file(source)
        self.assertTrue(result["success"], result["message"])

        acl = subprocess.run(
            ["icacls.exe", result["quarantine_path"]],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        ).stdout

        self.assertIn("NT AUTHORITY\\SYSTEM", acl)
        self.assertNotIn("Everyone:", acl)
        self.assertNotIn("BUILTIN\\Users:", acl)
        self.assertNotIn("Authenticated Users:", acl)

    def test_quarantine_restore_rejects_tampered_content(self):
        source = self.root / "tampered.txt"
        source.write_bytes(b"original")
        result = self.scanner.quarantine_file(source)
        quarantined = Path(result["quarantine_path"])
        quarantined.write_bytes(b"modified")

        restored = self.scanner.restore_quarantined_file(
            quarantined,
            self.root / "restored.txt"
        )

        self.assertFalse(restored["success"])
        self.assertIn("integrity", restored["message"].lower())
        self.assertFalse((self.root / "restored.txt").exists())

    def test_corrupted_quarantine_metadata_blocks_restore(self):
        source = self.root / "broken.txt"
        source.write_bytes(b"content")
        result = self.scanner.quarantine_file(source)
        quarantined = Path(result["quarantine_path"])
        self.scanner._manifest_path(quarantined).write_text(
            "{broken",
            encoding="utf-8"
        )

        restored = self.scanner.restore_quarantined_file(
            quarantined,
            self.root / "restored.txt"
        )

        self.assertFalse(restored["success"])
        self.assertIn("metadata", restored["message"].lower())
        self.assertTrue(quarantined.exists())

    def test_interrupted_quarantine_is_recovered_from_manifest(self):
        quarantine_id = "a" * 32
        quarantined = self.quarantine / f"{quarantine_id}.quarantine"
        content = b"interrupted but complete move"
        quarantined.write_bytes(content)
        manifest = self.quarantine / f"{quarantine_id}.json"
        manifest.write_text(
            json.dumps({
                "id": quarantine_id,
                "state": "pending",
                "original_path": str(self.root / "source.bin"),
                "original_name": "source.bin",
                "sha256": hashlib.sha256(content).hexdigest(),
                "quarantined_at": "2026-01-01T00:00:00+00:00",
            }),
            encoding="utf-8"
        )

        recovered_scanner = SecurityScanner(self.quarantine)

        self.assertEqual(
            recovered_scanner.get_quarantine_metadata(quarantined)["state"],
            "pending"
        )
        self.assertTrue(recovered_scanner.quarantine_recovery_errors)
        self.assertIn(str(quarantined), recovered_scanner.list_quarantine())

        recovered_scanner.recover_quarantine_operations()
        self.assertEqual(
            recovered_scanner.get_quarantine_metadata(quarantined)["state"],
            "quarantined"
        )

    def test_existing_unexpected_file_fails_closed_without_modification(self):
        unsafe_directory = self.root / "unexpected-quarantine"
        unsafe_directory.mkdir()
        unexpected = unsafe_directory / "virus.bat"
        original = b"preserve this legacy record"
        unexpected.write_bytes(original)

        with self.assertRaisesRegex(OSError, "Unexpected file"):
            SecurityScanner(unsafe_directory)

        self.assertEqual(unexpected.read_bytes(), original)

    def test_quarantine_location_can_be_configured_with_environment(self):
        configured = self.root / "configured-quarantine"
        with patch.dict(
            os.environ,
            {"ITSS_QUARANTINE_DIR": str(configured)}
        ):
            scanner = SecurityScanner(max_workers=1)

        self.assertEqual(scanner.quarantine_dir, configured)
        self.assertTrue(configured.is_dir())

    def test_environment_quarantine_takes_precedence_over_production_default(self):
        configured = self.root / "acceptance-quarantine"
        production_default = (
            Path.home() / "AppData" / "Local" / "ITSecurityScanner"
            / "SecurityScanner_Quarantine"
        )
        with patch.dict(
            os.environ,
            {"ITSS_QUARANTINE_DIR": str(configured)}
        ):
            scanner = SecurityScanner(max_workers=1)

        self.assertEqual(scanner.quarantine_dir, configured)
        self.assertNotEqual(scanner.quarantine_dir, production_default)

    def test_first_run_uses_local_app_data_and_preserves_legacy_directory(self):
        data_directory = self.root / "local-app-data" / "ITSecurityScanner"
        profile = self.root / "profile"
        legacy_directory = profile / "SecurityScanner_Quarantine"
        legacy_directory.mkdir(parents=True)
        legacy_record = legacy_directory / "legacy-record"
        legacy_record.write_bytes(b"preserve")

        with patch(
            "scanner.default_data_directory",
            return_value=data_directory
        ), patch(
            "scanner.Path.home",
            return_value=profile
        ), patch.dict(
            os.environ,
            {"ITSS_QUARANTINE_DIR": ""}
        ):
            scanner = SecurityScanner(max_workers=1)

        expected = data_directory / "SecurityScanner_Quarantine"
        self.assertEqual(scanner.quarantine_dir, expected)
        self.assertTrue(expected.is_dir())
        self.assertEqual(legacy_record.read_bytes(), b"preserve")
        self.assertIn(str(legacy_directory), scanner.legacy_quarantine_notice)
        self.assertIn(
            scanner.legacy_quarantine_notice,
            scanner.quarantine_recovery_errors
        )

    def test_windows_quarantine_owner_is_explicit_for_both_token_modes(self):
        user_sid = "S-1-5-21-1-2-3-1000"
        for token_default_owner in (user_sid, "S-1-5-32-544"):
            with self.subTest(token_default_owner=token_default_owner):
                descriptor = SecurityScanner._quarantine_directory_sddl(
                    user_sid
                )
                self.assertTrue(descriptor.startswith(f"O:{user_sid}D:P"))
                if token_default_owner != user_sid:
                    self.assertNotIn(
                        f"O:{token_default_owner}D:P",
                        descriptor
                    )
                self.assertIn(f"(A;OICI;FA;;;{user_sid})", descriptor)
                self.assertIn("(A;OICI;FA;;;S-1-5-18)", descriptor)
                self.assertNotIn("S-1-5-32-544", descriptor)

    @unittest.skipUnless(os.name == "nt", "Windows security descriptors required")
    def test_created_quarantine_owner_matches_current_windows_user_sid(self):
        self._windows_acl_patch.stop()
        user_sid = SecurityScanner._get_windows_user_sid()
        quarantine = self.root / "current-user-owned-quarantine"

        created = SecurityScanner._create_windows_quarantine_directory(
            quarantine,
            user_sid
        )
        owner_sid, acl = SecurityScanner._get_windows_owner_and_acl(
            quarantine
        )

        self.assertTrue(created)
        self.assertEqual(owner_sid, user_sid)
        self.assertEqual(
            acl["allowed_sids"],
            {user_sid, "S-1-5-18"}
        )
        self.assertTrue(acl["protected"])

    def test_quarantine_location_must_be_absolute_and_dedicated(self):
        with self.assertRaisesRegex(OSError, "must be absolute"):
            SecurityScanner("relative-quarantine")

        with self.assertRaisesRegex(OSError, "profile directory"):
            SecurityScanner(Path.home())

    def test_existing_quarantine_records_are_not_changed_at_startup(self):
        source = self.root / "preserve-record.txt"
        source.write_bytes(b"preserve this quarantined object")
        result = self.scanner.quarantine_file(source)
        quarantined = Path(result["quarantine_path"])
        manifest = self.scanner._manifest_path(quarantined)
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
        metadata["state"] = "pending"
        manifest.write_text(json.dumps(metadata), encoding="utf-8")
        object_bytes = quarantined.read_bytes()
        manifest_bytes = manifest.read_bytes()

        reopened = SecurityScanner(self.quarantine)

        self.assertEqual(quarantined.read_bytes(), object_bytes)
        self.assertEqual(manifest.read_bytes(), manifest_bytes)
        self.assertEqual(
            reopened.get_quarantine_metadata(quarantined)["state"],
            "pending"
        )

    def test_quarantine_acl_application_never_resets_existing_acl(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr=""
        )
        with patch("scanner.subprocess.run", return_value=completed) as run:
            SecurityScanner._apply_quarantine_acl(
                self.quarantine,
                "S-1-5-21-1-2-3-1000",
                directory=True
            )

        command = run.call_args.args[0]
        self.assertNotIn("/reset", command)
        self.assertIn("/inheritance:r", command)

    def test_quarantine_acl_failure_fails_closed_and_preserves_data(self):
        configured = self.root / "acl-failure-quarantine"
        with patch("scanner.os.name", "nt"), patch.object(
            SecurityScanner,
            "_get_windows_user_sid",
            return_value="S-1-5-21-1-2-3-1000"
        ), patch.object(
            SecurityScanner,
            "_get_windows_owner_and_acl",
            return_value=(
                "S-1-5-21-1-2-3-1000",
                {"protected": True, "allowed_sids": {
                    "S-1-5-21-1-2-3-1000", "S-1-5-18"
                }}
            )
        ), patch.object(
            SecurityScanner,
            "_create_windows_quarantine_directory",
            side_effect=lambda path, _sid: (path.mkdir(), True)[1]
        ), patch.object(
            SecurityScanner,
            "_apply_quarantine_acl",
            side_effect=OSError("simulated ACL failure")
        ):
            with self.assertRaisesRegex(OSError, "simulated ACL failure"):
                SecurityScanner(configured)

        self.assertTrue(configured.is_dir())
        self.assertEqual(list(configured.iterdir()), [])

    def test_unverified_directory_owner_fails_before_acl_changes(self):
        configured = self.root / "wrong-owner-quarantine"
        configured.mkdir()
        record = configured / f"{'a' * 32}.quarantine"
        record.write_bytes(b"keep")
        with patch("scanner.os.name", "nt"), patch.object(
            SecurityScanner,
            "_get_windows_user_sid",
            return_value="S-1-5-21-1-2-3-1000"
        ), patch.object(
            SecurityScanner,
            "_get_windows_owner_and_acl",
            return_value=(
                "S-1-5-32-544",
                {"protected": True, "allowed_sids": set()}
            )
        ), patch.object(
            SecurityScanner,
            "_apply_quarantine_acl"
        ) as apply_acl:
            with self.assertRaisesRegex(OSError, "ownership could not be verified"):
                SecurityScanner(configured)

        apply_acl.assert_not_called()
        self.assertEqual(record.read_bytes(), b"keep")

    def test_quarantine_directory_rejects_symbolic_link_paths(self):
        target = self.root / "quarantine-target"
        target.mkdir()
        link = self.root / "quarantine-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"Directory symbolic links are unavailable: {error}")

        with self.assertRaisesRegex(OSError, "symbolic link|junction"):
            SecurityScanner(link)

        self.assertTrue(target.is_dir())
        self.assertEqual(list(target.iterdir()), [])

    def test_non_windows_quarantine_setup_uses_no_windows_sid(self):
        with patch("scanner.os.name", "posix"), patch.object(
            self.scanner,
            "_validate_existing_quarantine_entries"
        ) as validate_entries, patch.object(
            self.scanner,
            "_inspect_quarantine_storage"
        ), patch.object(
            SecurityScanner,
            "_apply_quarantine_acl"
        ) as apply_acl:
            self.scanner._secure_quarantine_directory(
                directory_created=True,
                user_sid=None
            )

        validate_entries.assert_called_once_with(None, newly_created=True)
        apply_acl.assert_not_called()

    def test_failed_restore_preserves_quarantined_file_and_metadata(self):
        source = self.root / "restore-failure.txt"
        source.write_bytes(b"content")
        result = self.scanner.quarantine_file(source)

        with patch.object(
            self.scanner,
            "_move_file_safely",
            side_effect=PermissionError("denied")
        ):
            restored = self.scanner.restore_quarantined_file(
                result["quarantine_path"],
                self.root / "restored.txt"
            )

        self.assertFalse(restored["success"])
        self.assertTrue(Path(result["quarantine_path"]).exists())
        self.assertEqual(
            self.scanner.get_quarantine_metadata(
                result["quarantine_path"]
            )["state"],
            "quarantined"
        )

    def test_post_move_hash_mismatch_returns_file_to_quarantine(self):
        source = self.root / "restore-hash-fixture.txt"
        source.write_bytes(b"harmless fixture")
        quarantined = self.scanner.quarantine_file(source)
        quarantine_path = Path(quarantined["quarantine_path"])
        original_hash = quarantined["sha256"]
        destination = self.root / "restored-fixture.txt"

        original_calculate_hash = self.scanner.calculate_hash
        calls = 0

        def mismatched_destination_hash(path):
            nonlocal calls
            calls += 1
            if Path(path) == destination:
                return "0" * 64
            return original_calculate_hash(path)

        with patch.object(
            self.scanner,
            "calculate_hash",
            side_effect=mismatched_destination_hash
        ):
            restored = self.scanner.restore_quarantined_file(
                quarantine_path,
                destination
            )

        self.assertFalse(restored["success"])
        self.assertTrue(quarantine_path.exists())
        self.assertFalse(destination.exists())
        self.assertEqual(
            self.scanner.get_quarantine_metadata(quarantine_path)["state"],
            "quarantined"
        )

    def test_quarantine_rejects_paths_outside_its_directory(self):
        outside = self.root / "outside.txt"
        outside.write_text("keep", encoding="utf-8")

        self.assertFalse(self.scanner.delete_quarantined_file(outside))
        self.assertFalse(
            self.scanner.restore_quarantined_file(
                outside,
                self.root / "restored.txt"
            )["success"]
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_quarantine_apis_reject_invalid_path_values(self):
        self.assertFalse(self.scanner.quarantine_file(None)["success"])
        self.assertFalse(
            self.scanner.restore_quarantined_file(None, None)["success"]
        )
        self.assertFalse(self.scanner.delete_quarantined_file(None))

    def test_quarantine_rejects_symbolic_links(self):
        source = self.root / "link-target.txt"
        link = self.root / "linked.txt"
        source.write_text("keep", encoding="utf-8")
        try:
            link.symlink_to(source)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"Symbolic links are unavailable: {error}")

        result = self.scanner.quarantine_file(link)

        self.assertFalse(result["success"])
        self.assertTrue(source.exists())
        self.assertTrue(link.is_symlink())

    def test_quarantine_permission_failure_keeps_original_file(self):
        source = self.root / "permission-failure.bin"
        source.write_bytes(b"keep")
        with patch.object(
            self.scanner,
            "_move_file_safely",
            side_effect=PermissionError("access denied")
        ):
            result = self.scanner.quarantine_file(source)

        self.assertFalse(result["success"])
        self.assertTrue(source.exists())
        self.assertEqual(source.read_bytes(), b"keep")

    def test_malformed_pe_file_does_not_crash_scan(self):
        malformed = self.root / "malformed.exe"
        malformed.write_bytes(b"MZ" + b"\x00" * 24)

        result = self.scanner.individual_file_scan(malformed)

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("PE analysis failed", result["errors"][0])
        self.assertEqual(result["suspicious"], [])

    def test_duplicate_roots_do_not_process_the_same_file_twice(self):
        target = self.root / "duplicate.txt"
        target.write_text("content", encoding="utf-8")
        seen = []
        self.scanner.analyze_file = (
            lambda path, analysis_errors=None:
            seen.append(Path(path)) or None
        )

        result = self.scanner._scan_locations([self.root, self.root])

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(seen, [target])

    def test_scan_cancellation_during_active_file_processing(self):
        target = self.root / "active.bin"
        target.write_bytes(b"sample")
        started = threading.Event()
        release = threading.Event()
        results = []

        def analyze(path, analysis_errors=None):
            started.set()
            release.wait(timeout=2)
            return None

        self.scanner.analyze_file = analyze
        worker = threading.Thread(
            target=lambda: results.append(
                self.scanner.individual_file_scan(target)
            )
        )
        worker.start()
        self.assertTrue(started.wait(timeout=2))
        self.scanner.cancel()
        release.set()
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0]["cancelled"])
        self.assertEqual(results[0]["scanned"], 1)

    def test_scanner_uses_bounded_parallel_workers(self):
        for index in range(6):
            (self.root / f"parallel-{index}.txt").write_text(
                "content",
                encoding="utf-8"
            )
        with patch(
            "scanner._available_memory_bytes",
            return_value=1024 ** 3
        ), patch("scanner.os.cpu_count", return_value=16):
            scanner = SecurityScanner(self.quarantine, max_workers=2)
        scanner.yara_scanner = self.scanner.yara_scanner
        active = 0
        max_active = 0
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def analyze(_path, analysis_errors=None):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            barrier.wait(timeout=2)
            with lock:
                active -= 1
            return None

        scanner.analyze_file = analyze
        result = scanner.custom_scan(self.root)

        self.assertEqual(result["scanned"], 6)
        self.assertEqual(max_active, 2)

    def test_worker_limit_is_constrained_by_available_memory(self):
        with patch("scanner._available_memory_bytes", return_value=1024**3), patch(
            "scanner.os.cpu_count",
            return_value=16
        ):
            scanner = SecurityScanner(self.quarantine, max_workers=16)

        self.assertEqual(scanner.max_workers, 2)

    def test_unknown_memory_availability_uses_one_worker(self):
        with patch("scanner._available_memory_bytes", return_value=None), patch(
            "scanner.os.cpu_count",
            return_value=16
        ):
            scanner = SecurityScanner(self.quarantine, max_workers=16)

        self.assertEqual(scanner.max_workers, 1)

    def test_finding_limit_reports_actual_count_and_incomplete_results(self):
        for index in range(3):
            (self.root / f"finding-{index}.txt").write_text(
                "sample",
                encoding="utf-8"
            )
        self.scanner.analyze_file = (
            lambda path, analysis_errors=None: {"path": str(path)}
        )

        with patch("scanner.MAX_SCAN_FINDINGS", 2):
            result = self.scanner.custom_scan(self.root)

        self.assertEqual(result["finding_count"], 3)
        self.assertEqual(len(result["suspicious"]), 2)
        self.assertTrue(result["findings_truncated"])
        self.assertGreater(result["error_count"], 0)
        self.assertEqual(result["detection_status"], "Incomplete scan")

    def test_parallel_scan_cancellation_stops_queued_work(self):
        for index in range(20):
            (self.root / f"cancel-parallel-{index}.txt").write_text(
                "content",
                encoding="utf-8"
            )
        scanner = SecurityScanner(self.quarantine, max_workers=2)
        scanner.yara_scanner = self.scanner.yara_scanner
        started = threading.Event()
        release = threading.Event()
        results = []

        def analyze(_path, analysis_errors=None):
            started.set()
            release.wait(timeout=2)
            return None

        scanner.analyze_file = analyze
        worker = threading.Thread(
            target=lambda: results.append(
                scanner.custom_scan(self.root)
            )
        )
        worker.start()
        self.assertTrue(started.wait(timeout=2))
        scanner.cancel()
        release.set()
        worker.join(timeout=3)

        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0]["cancelled"])
        self.assertLess(results[0]["scanned"], 20)

    @unittest.skipUnless(os.name == "nt", "Windows removable-drive API test")
    def test_removable_drive_scan_identifies_only_removable_volumes(self):
        with patch("scanner.os.name", "nt"), patch(
            "ctypes.windll.kernel32.GetLogicalDrives",
            return_value=1 << 4
        ), patch(
            "ctypes.windll.kernel32.GetDriveTypeW",
            return_value=2
        ), patch.object(
            self.scanner,
            "_scan_locations",
            return_value={"scanned": 0}
        ) as scan_locations:
            result = self.scanner.removable_drive_scan()

        self.assertEqual(result, {"scanned": 0})
        self.assertEqual(
            scan_locations.call_args.args[0],
            [Path("E:\\")]
        )

    @unittest.skipUnless(os.name == "nt", "Windows removable-drive API test")
    def test_removable_drive_unknown_root_is_reported_as_error(self):
        with patch("scanner.os.name", "nt"), patch(
            "ctypes.windll.kernel32.GetLogicalDrives",
            return_value=1 << 4
        ), patch(
            "ctypes.windll.kernel32.GetDriveTypeW",
            return_value=0
        ):
            result = self.scanner.removable_drive_scan()

        self.assertEqual(result["scanned"], 0)
        self.assertEqual(result["error_count"], 1)
        self.assertIn("could not access", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
