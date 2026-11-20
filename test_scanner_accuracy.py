import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import SecurityScanner


class NoYaraMatches:
    def scan_file(self, filepath):
        return []


class ScannerAccuracyTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecurityScanner.__new__(SecurityScanner)
        self.scanner.yara_scanner = NoYaraMatches()
        self.scanner.calculate_hash = lambda filepath: "0" * 64

    def test_script_comments_do_not_trigger_detections(self):
        content = """
        # shutdown /s /t 0
        <# Invoke-Expression and DownloadString #>
        Write-Output "routine status"
        """

        score, reasons = self.scanner.analyze_script(
            content,
            ".ps1"
        )

        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_javascript_and_batch_comments_do_not_trigger_detections(self):
        examples = (
            (
                "const status = 'ok'; // shutdown /s\n"
                "/* Invoke-Expression DownloadString */",
                ".js"
            ),
            (
                "rem shutdown /s\n"
                "@echo off & rem del /f target\n",
                ".bat"
            ),
        )

        for content, extension in examples:
            with self.subTest(extension=extension):
                score, reasons = self.scanner.analyze_script(
                    content,
                    extension
                )

                self.assertEqual(score, 0)
                self.assertEqual(reasons, [])

    def test_script_detection_uses_word_boundaries(self):
        content = "Write-Output 'mydownloadstringer and iexhelper'"

        score, reasons = self.scanner.analyze_script(
            content,
            ".ps1"
        )

        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_suspicious_script_behavior_is_still_detected(self):
        content = (
            "Invoke-Expression (New-Object Net.WebClient)."
            "DownloadString('example')"
        )

        score, reasons = self.scanner.analyze_script(
            content,
            ".ps1"
        )

        self.assertEqual(score, 65)
        self.assertEqual(
            reasons,
            [
                "PowerShell expression execution detected",
                "Remote content download detected",
            ]
        )

    def test_persistence_reference_is_a_static_suspicion_signal(self):
        score, reasons = self.scanner.analyze_script(
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            ".ps1"
        )

        self.assertGreaterEqual(score, 20)
        self.assertIn(
            "Windows Run-key persistence reference detected",
            reasons
        )

    def test_suspicious_filename_alone_does_not_trigger_a_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ransomware.exe"
            path.write_bytes(b"not an executable")

            with patch(
                "scanner.analyze_pe",
                return_value={
                    "suspicious_imports": [],
                    "entropy": [],
                }
            ):
                result = self.scanner.analyze_file(path)

        self.assertIsNone(result)

    def test_magic_byte_pe_analysis_applies_to_renamed_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.dat"
            path.write_bytes(b"MZ" + b"\x00" * 510)

            with patch("scanner.check_hash", return_value=None), patch(
                "scanner.analyze_pe",
                return_value={
                    "suspicious_imports": [
                        "kernel32.dll:VirtualAlloc",
                        "kernel32.dll:WriteProcessMemory",
                        "kernel32.dll:CreateRemoteThread",
                        "advapi32.dll:RegSetValue",
                    ],
                    "entropy": [{"entropy": 7.9}],
                }
            ) as analyze_pe:
                result = self.scanner.analyze_file(path)

        analyze_pe.assert_called_once_with(str(path))
        self.assertEqual(result["file_type"], "Windows PE executable")
        self.assertEqual(result["classification"], "Potentially suspicious")

    def test_low_signal_script_is_an_informational_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routine.ps1"
            path.write_text("Write-Output 'status'", encoding="utf-8")

            with patch("scanner.check_hash", return_value=None):
                result = self.scanner.analyze_file(path)

        self.assertEqual(result["classification"], "Informational finding")
        self.assertEqual(result["confidence"], "Low")

    def test_duplicate_pe_imports_do_not_inflate_score(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "application.exe"
            path.write_bytes(b"not an executable")

            with patch(
                "scanner.analyze_pe",
                return_value={
                    "suspicious_imports": [
                        "kernel32.dll:VirtualAlloc",
                        "kernel32.dll:VirtualAlloc",
                    ],
                    "entropy": [],
                }
            ):
                result = self.scanner.analyze_file(path)

        self.assertIsNone(result)

    def test_multiple_indicators_produce_capped_critical_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alert.ps1"
            path.write_text(
                "shutdown /s\n"
                "del /f target\n"
                "Invoke-Expression $command\n"
                "DownloadString($url)\n"
                "Set-MpPreference -DisableRealtimeMonitoring $true\n",
                encoding="utf-8"
            )

            result = self.scanner.analyze_file(path)

        self.assertEqual(result["risk"], "Critical")
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["detection_type"], "Script Heuristic")
        self.assertTrue(result["reasons"])


if __name__ == "__main__":
    unittest.main()
