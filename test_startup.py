import unittest
from unittest.mock import patch

import startup_scanner


class StartupScannerTests(unittest.TestCase):
    def test_extracts_quoted_executable_path(self):
        command = '"C:\\Program Files\\Example\\agent.exe" --background'

        self.assertEqual(
            startup_scanner.extract_file_path(command),
            "C:\\Program Files\\Example\\agent.exe"
        )

    def test_classifies_startup_script_and_temporary_executable(self):
        script = startup_scanner.analyze_startup_entry(
            "Script",
            r"C:\Users\Example\Downloads\launch.ps1",
            "Run"
        )
        temporary_executable = startup_scanner.analyze_startup_entry(
            "Program",
            r"C:\Users\Example\AppData\Local\Temp\agent.exe",
            "Run"
        )

        self.assertEqual(script["risk"], "High")
        self.assertEqual(temporary_executable["risk"], "High")

    def test_registry_scan_closes_open_keys_and_returns_entries(self):
        class FakeRegistry:
            HKEY_CURRENT_USER = 1
            HKEY_LOCAL_MACHINE = 2
            KEY_READ = 0x20019

            def __init__(self):
                self.closed = []

            @staticmethod
            def OpenKey(hive, _path, _reserved, _access):
                return hive

            @staticmethod
            def EnumValue(key, index):
                if key == 1 and index == 0:
                    return (
                        "Example",
                        '"C:\\Program Files\\Example\\agent.exe"',
                        1
                    )
                raise OSError("No more registry values")

            def CloseKey(self, key):
                self.closed.append(key)

        fake_registry = FakeRegistry()
        with patch.object(startup_scanner, "winreg", fake_registry):
            entries = startup_scanner.scan_startup_entries()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "Example")
        self.assertCountEqual(fake_registry.closed, [1, 2])


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("WINDOWS STARTUP SCANNER")
    print("=" * 60)
    print()

    entries = startup_scanner.scan_startup_entries()
    if not entries:
        print("No startup entries found.")
    else:
        for entry in entries:
            print("Name     :", entry["name"])
            print("Program  :", entry["value"])
            print("Location :", entry["location"])
            print("-" * 60)

    print()
    print("Total Startup Entries:", len(entries))
