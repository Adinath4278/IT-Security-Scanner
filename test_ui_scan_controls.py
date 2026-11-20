import unittest
import threading
from types import SimpleNamespace
from unittest.mock import patch

from ui import SecurityScannerUI


class FakeWidget:
    def __init__(self):
        self.options = {}

    def configure(self, **options):
        self.options.update(options)


class FakeScanner:
    def __init__(self):
        self.cancel_requests = 0

    def cancel(self):
        self.cancel_requests += 1


class ScanControlTests(unittest.TestCase):
    def test_cancel_button_requests_cancellation_without_touching_tk(self):
        scanner = FakeScanner()
        cancel_button = FakeWidget()
        status = FakeWidget()
        app_stub = SimpleNamespace(
            scan_running=True,
            active_scan="Custom Scan",
            scanner=scanner,
            scan_widgets={
                "Custom Scan": {
                    "cancel_button": cancel_button,
                    "status": status,
                }
            },
            YELLOW="#ffb020"
        )

        SecurityScannerUI.cancel_scan(app_stub)

        self.assertEqual(scanner.cancel_requests, 1)
        self.assertEqual(cancel_button.options["state"], "disabled")
        self.assertIn("Cancellation requested", status.options["text"])

    def test_cancel_button_is_noop_when_no_scan_is_active(self):
        scanner = FakeScanner()
        app_stub = SimpleNamespace(
            scan_running=False,
            active_scan=None,
            scanner=scanner,
            scan_widgets={}
        )

        SecurityScannerUI.cancel_scan(app_stub)

        self.assertEqual(scanner.cancel_requests, 0)

    def test_scan_worker_posts_progress_for_main_thread_rendering(self):
        events = []
        app_stub = SimpleNamespace(
            _progress_lock=threading.Lock(),
            _last_progress_emit=0,
            _queue_ui_event=lambda *event: events.append(event),
        )
        app_stub.update_scan_progress = lambda *values: (
            SecurityScannerUI.update_scan_progress(app_stub, *values)
        )
        results = []

        def scan(callback):
            callback(1, 1, "sample.txt")
            return {"scanned": 1}

        worker = threading.Thread(
            target=lambda: SecurityScannerUI.run_scan_worker(
                app_stub,
                scan,
                "Custom Scan",
                "Custom Scan"
            )
        )
        worker.start()
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(events[0][0], "scan_progress")
        self.assertEqual(events[0][1:], (
            "Custom Scan",
            1,
            1,
            "sample.txt"
        ))
        self.assertEqual(events[1][0], "scan_finished")
        self.assertEqual(events[1][1]["scan_type"], "Custom Scan")


    def test_shutdown_is_blocked_during_restore_or_signature_operation(self):
        app_stub = SimpleNamespace(
            _settings_operation_running=True,
            _signature_import_running=False,
            scan_running=False,
        )

        with patch("ui.messagebox.showwarning") as showwarning:
            result = SecurityScannerUI._request_application_close(app_stub)

        self.assertIsNone(result)
        showwarning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
