import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from report_generator import generate_report


class ReportGeneratorTests(unittest.TestCase):
    def test_report_contains_scan_summary_and_escaped_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = generate_report(
                {
                    "scanned": 4,
                    "error_count": 1,
                    "errors": ["<permission denied>"],
                    "suspicious": [
                        {
                            "name": "<script>alert(1)</script>.exe",
                            "extension": ".exe",
                            "risk": "Critical",
                            "risk_score": 100,
                            "path": "C:/sample<&>.exe",
                            "detection_type": "YARA",
                            "reasons": ["<img src=x>"],
                            "hash": "a" * 64,
                        }
                    ],
                },
                output_directory=directory,
                metadata={
                    "scan_type": "Custom Scan",
                    "started_at": "2026-01-01T10:00:00+00:00",
                    "duration": "2 seconds",
                    "exclusions": ["C:/private<&>"],
                }
            )

            report = Path(path).read_text(encoding="utf-8")

        self.assertIn("Files scanned", report)
        self.assertIn("Critical 1", report)
        self.assertIn("Custom Scan", report)
        self.assertIn("Security score unavailable", report)
        self.assertIn('<meta name="scan-status" content="Incomplete">', report)
        self.assertIn("<strong>Unavailable</strong>", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img src=x&gt;", report)
        self.assertIn("&lt;permission denied&gt;", report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertNotIn("<img src=x>", report)

    def test_report_rejects_bad_result_shapes(self):
        with self.assertRaises(TypeError):
            generate_report([])

        with self.assertRaises(TypeError):
            generate_report({"suspicious": {}})

    def test_report_discloses_truncated_finding_details(self):
        with tempfile.TemporaryDirectory() as directory:
            path = generate_report(
                {
                    "scanned": 4,
                    "finding_count": 8,
                    "findings_truncated": True,
                    "error_count": 1,
                    "suspicious": [{"name": "retained.txt"}],
                },
                output_directory=directory
            )
            report = Path(path).read_text(encoding="utf-8")

        self.assertIn("Threat findings (8)", report)
        self.assertIn("Only 1 of 8 finding details are included", report)
        self.assertIn("Security score unavailable", report)

    def test_cancelled_scan_report_does_not_assign_a_security_score(self):
        with tempfile.TemporaryDirectory() as directory:
            path = generate_report(
                {
                    "scanned": 1,
                    "cancelled": True,
                    "suspicious": [{"risk": "Critical"}],
                },
                output_directory=directory
            )
            report = Path(path).read_text(encoding="utf-8")

        self.assertIn("<strong>Unavailable</strong>", report)
        self.assertIn("Results are partial because the scan was cancelled", report)
        self.assertIn('<meta name="scan-status" content="Cancelled">', report)

    def test_complete_scan_report_exposes_report_history_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = generate_report(
                {"scanned": 2, "suspicious": []},
                output_directory=directory,
                metadata={"scan_type": 'Custom & "selected"'}
            )
            report = Path(path).read_text(encoding="utf-8")

        self.assertIn(
            '<meta name="scan-type" content="Custom &amp; &quot;selected&quot;">',
            report
        )
        self.assertIn('<meta name="scan-status" content="Complete">', report)
        self.assertIn('<meta name="finding-count" content="0">', report)

    def test_default_reports_use_the_user_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "report_generator.default_data_directory",
                return_value=Path(directory),
            ):
                path = generate_report({"scanned": 0, "suspicious": []})

        self.assertEqual(Path(path).parent, Path(directory) / "reports")


if __name__ == "__main__":
    unittest.main()
