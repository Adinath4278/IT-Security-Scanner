import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yara_scanner
from yara_scanner import YaraScanner


class FakeMatch:
    rule = "EICAR_Test"
    namespace = "local"
    tags = ["test", "eicar"]


class FakeRules:
    def match(self, _filepath, timeout):
        if timeout != 10:
            raise AssertionError("Unexpected YARA timeout.")
        return [FakeMatch()]


class YaraScannerTests(unittest.TestCase):
    def test_rule_matching_returns_namespaces_and_tags(self):
        scanner = YaraScanner.__new__(YaraScanner)
        scanner.rules = FakeRules()

        result = scanner.scan_file("harmless-test-file")

        self.assertEqual(result[0]["rule"], "EICAR_Test")
        self.assertEqual(result[0]["tags"], ["test", "eicar"])

    def test_invalid_yara_rule_is_not_installed(self):
        class FakeYara:
            @staticmethod
            def compile(**_kwargs):
                raise ValueError("invalid rule syntax")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bad.yar"
            source.write_text("not a rule", encoding="utf-8")
            rules_dir = root / "rules"
            scanner = YaraScanner.__new__(YaraScanner)
            scanner.rules_directory = rules_dir
            scanner.rules = None
            scanner.error = None

            with patch.object(yara_scanner, "yara", FakeYara):
                with self.assertRaisesRegex(ValueError, "invalid rule"):
                    scanner.install_rule(source)

            self.assertFalse((rules_dir / "bad.yar").exists())

    def test_unavailable_engine_is_reported_in_status(self):
        scanner = YaraScanner.__new__(YaraScanner)
        scanner.rules_directory = Path("missing-yara-rules")
        scanner.rules = None
        scanner.error = "yara-python unavailable"

        with patch.object(yara_scanner, "yara", None):
            self.assertEqual(
                scanner.get_status()["error"],
                "yara-python unavailable"
            )

    def test_yara_extension_files_are_loaded(self):
        class FakeYara:
            @staticmethod
            def compile(filepaths):
                if not any(path.endswith(".yara") for path in filepaths.values()):
                    raise AssertionError(".yara file was not included")
                return FakeRules()

        with tempfile.TemporaryDirectory() as directory:
            rules_directory = Path(directory)
            (rules_directory / "local.yara").write_text(
                "rule local_test { condition: true }",
                encoding="utf-8"
            )
            with patch.object(yara_scanner, "yara", FakeYara):
                scanner = YaraScanner(rules_directory)
                status = scanner.get_status()

        self.assertTrue(status["available"])
        self.assertEqual(len(status["rule_files"]), 1)

    def test_bundled_rules_load_and_new_rules_use_writable_directory(self):
        class FakeYara:
            @staticmethod
            def compile(**kwargs):
                if "filepaths" in kwargs:
                    paths = kwargs["filepaths"].values()
                    if not any("bundled" in path for path in paths):
                        raise AssertionError("Bundled rules were not loaded.")
                    if not any("user" in path for path in paths):
                        raise AssertionError("User rules were not loaded.")
                return FakeRules()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "bundled"
            writable = root / "user"
            bundled.mkdir()
            writable.mkdir()
            (bundled / "bundled.yar").write_text(
                "rule bundled { condition: true }",
                encoding="utf-8",
            )
            (writable / "user.yar").write_text(
                "rule user { condition: true }",
                encoding="utf-8",
            )
            source = root / "new.yar"
            source.write_text(
                "rule installed { condition: true }",
                encoding="utf-8",
            )

            with patch.object(yara_scanner, "yara", FakeYara):
                scanner = YaraScanner(
                    bundled,
                    user_rules_directory=writable,
                )
                installed = scanner.install_rule(source)

        self.assertEqual(Path(installed).parent, writable)
        self.assertEqual(Path(installed).name, "new.yar")


if __name__ == "__main__":
    unittest.main()
