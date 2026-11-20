import unittest

from ui import SecurityScannerUI


class UiRedesignLogicTests(unittest.TestCase):
    def test_page_navigation_uses_the_shared_scroll_viewport(self):
        class FakePage:
            def __init__(self):
                self.pack_options = {}
                self.hidden = False

            def pack(self, **options):
                self.pack_options.update(options)
                self.hidden = False

            def pack_forget(self):
                self.hidden = True

        class FakeWidget:
            def __init__(self):
                self.options = {}

            def configure(self, **options):
                self.options.update(options)

        class FakeCanvas:
            def __init__(self):
                self.scroll_positions = []

            def yview_moveto(self, position):
                self.scroll_positions.append(position)

        previous_page = FakePage()
        next_page = FakePage()
        canvas = FakeCanvas()
        app_stub = type("AppStub", (), {})()
        app_stub.pages = {
            "Dashboard": previous_page,
            "About": next_page
        }
        app_stub.resolve_page_name = SecurityScannerUI.resolve_page_name
        app_stub._current_page = "Dashboard"
        app_stub._navigation_animation_id = None
        app_stub.container = type(
            "ContainerStub",
            (),
            {"_parent_canvas": canvas}
        )()
        app_stub.header_page_title = FakeWidget()
        app_stub.nav_buttons = {
            "Dashboard": FakeWidget(),
            "About": FakeWidget()
        }
        app_stub.BLUE_DARK = "#2563EB"
        app_stub.after_idle = lambda callback, *args: callback(*args)
        app_stub._animate_page_in = lambda _page, _offset: None

        SecurityScannerUI.show_page(app_stub, "About")

        self.assertTrue(previous_page.hidden)
        self.assertFalse(next_page.hidden)
        self.assertEqual(next_page.pack_options["fill"], "both")
        self.assertTrue(next_page.pack_options["expand"])
        self.assertEqual(canvas.scroll_positions, [0])
        self.assertEqual(app_stub.header_page_title.options["text"], "About")

    def test_existing_scan_and_report_routes_resolve_to_new_shell_pages(self):
        self.assertEqual(
            SecurityScannerUI.resolve_page_name("Quick Scan"),
            "File Scanner"
        )
        self.assertEqual(
            SecurityScannerUI.resolve_page_name("Custom Scan"),
            "File Scanner"
        )
        self.assertEqual(
            SecurityScannerUI.resolve_page_name("Reports"),
            "Scan Reports"
        )
        self.assertEqual(
            SecurityScannerUI.resolve_page_name("Vulnerability Assessment"),
            "Vulnerability Assessment"
        )

    def test_dashboard_metrics_use_recorded_scans_and_latest_findings(self):
        events = [
            {
                "type": "scan_completed",
                "timestamp": "2026-03-01T10:00:00",
                "message": "Quick scan completed",
                "details": {"files_scanned": 12, "findings": 2}
            },
            {
                "type": "scan_cancelled",
                "details": {"files_scanned": 3, "findings": 1}
            },
            {
                "type": "report_generated",
                "details": {"files_scanned": 999}
            }
        ]
        latest_result = {
            "suspicious": [
                {"classification": "Confirmed malware signature"},
                {"classification": "Strongly suspicious"},
                {"classification": "Potentially suspicious"},
                {"classification": "Informational finding"}
            ]
        }

        metrics = SecurityScannerUI.dashboard_metric_values(
            events,
            latest_result,
            ["q1", "q2"]
        )

        self.assertEqual(metrics["files_scanned"], 15)
        self.assertEqual(metrics["findings_total"], 3)
        self.assertEqual(metrics["confirmed_latest"], 1)
        self.assertEqual(metrics["suspicious_latest"], 2)
        self.assertEqual(metrics["quarantined"], 2)
        self.assertEqual(metrics["last_scan"], events[0])

    def test_empty_dashboard_does_not_invent_scan_metrics(self):
        metrics = SecurityScannerUI.dashboard_metric_values([], None, [])

        self.assertEqual(metrics["files_scanned"], 0)
        self.assertEqual(metrics["confirmed_latest"], 0)
        self.assertEqual(metrics["suspicious_latest"], 0)
        self.assertIsNone(metrics["last_scan"])
        self.assertEqual(metrics["findings"], [])

    def test_findings_can_be_filtered_and_sorted_by_severity_or_name(self):
        findings = [
            {"name": "zeta.exe", "risk": "Low"},
            {"name": "alpha.exe", "risk": "Critical"},
            {"name": "beta.exe", "risk": "High"}
        ]

        severe_first = SecurityScannerUI.filter_and_sort_findings(
            findings,
            "All severities",
            "Severity",
            reverse=True
        )
        self.assertEqual(
            [finding["name"] for finding in severe_first],
            ["alpha.exe", "beta.exe", "zeta.exe"]
        )
        only_high = SecurityScannerUI.filter_and_sort_findings(
            findings,
            "High",
            "Name"
        )
        self.assertEqual([finding["name"] for finding in only_high], ["beta.exe"])

    def test_finding_details_show_detection_evidence_and_recommendation(self):
        details = SecurityScannerUI.format_finding_details({
            "classification": "Strongly suspicious",
            "risk": "High",
            "confidence": "High",
            "path": r"C:\test\sample.exe",
            "hash": "a" * 64,
            "timestamp": "2026-03-01T10:00:00",
            "detection_explanation": "Matched a local heuristic.",
            "recommended_action": "Review and isolate."
        })

        self.assertIn("High · Confidence High", details)
        self.assertIn(r"C:\test\sample.exe", details)
        self.assertIn("SHA-256", details)
        self.assertIn("2026-03-01T10:00:00", details)
        self.assertIn("Review and isolate.", details)

    def test_scan_state_never_labels_cancelled_or_incomplete_as_complete(self):
        self.assertEqual(
            SecurityScannerUI.scan_result_state({"cancelled": True}),
            "Cancelled"
        )
        self.assertEqual(
            SecurityScannerUI.scan_result_state({"error_count": 1}),
            "Incomplete"
        )
        self.assertEqual(
            SecurityScannerUI.scan_result_state({"findings_truncated": True}),
            "Incomplete"
        )
        self.assertEqual(
            SecurityScannerUI.scan_result_state({"error_count": 0}),
            "Complete"
        )

    def test_quarantine_integrity_status_requires_hash_match(self):
        digest = "a" * 64
        self.assertEqual(
            SecurityScannerUI.compare_quarantine_hashes(digest, digest),
            "Verified"
        )
        self.assertEqual(
            SecurityScannerUI.compare_quarantine_hashes(
                digest,
                "b" * 64
            ),
            "HASH MISMATCH"
        )

    def test_report_history_reads_embedded_metadata(self):
        content = (
            '<meta name="scan-type" content="Custom Folder Scan">'
            '<meta name="scan-status" content="Incomplete">'
            '<meta name="finding-count" content="4">'
        )
        self.assertEqual(
            SecurityScannerUI._report_meta(content, "scan-type"),
            "Custom Folder Scan"
        )
        self.assertEqual(
            SecurityScannerUI._report_meta(content, "scan-status"),
            "Incomplete"
        )
        self.assertEqual(
            SecurityScannerUI._report_meta(content, "finding-count"),
            "4"
        )


if __name__ == "__main__":
    unittest.main()
