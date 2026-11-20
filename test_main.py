import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main


class MainStartupTests(unittest.TestCase):
    def test_quarantine_startup_error_is_shown_clearly(self):
        ui_module = types.ModuleType("ui")
        ui_module.SecurityScannerUI = Mock(
            side_effect=OSError("quarantine owner could not be verified")
        )

        with patch.object(main, "configure_logging"), patch.object(
            main.ctk,
            "set_appearance_mode"
        ), patch.object(
            main.ctk,
            "set_default_color_theme"
        ), patch.object(
            main.messagebox,
            "showerror"
        ) as showerror, patch.dict(sys.modules, {"ui": ui_module}):
            result = main.main()

        self.assertEqual(result, 1)
        self.assertEqual(showerror.call_args.args[0], "Application Storage Error")
        self.assertIn(
            "quarantine owner could not be verified",
            showerror.call_args.args[1]
        )

    def test_existing_quarantine_data_is_reported_without_blocking_startup(self):
        notice = "Legacy quarantine data was left unchanged."
        app = SimpleNamespace(
            scanner=SimpleNamespace(legacy_quarantine_notice=notice),
            mainloop=Mock()
        )
        ui_module = types.ModuleType("ui")
        ui_module.SecurityScannerUI = Mock(return_value=app)

        with patch.object(main, "configure_logging"), patch.object(
            main.ctk,
            "set_appearance_mode"
        ), patch.object(
            main.ctk,
            "set_default_color_theme"
        ), patch.object(
            main.messagebox,
            "showwarning"
        ) as showwarning, patch.dict(sys.modules, {"ui": ui_module}):
            result = main.main()

        self.assertEqual(result, 0)
        showwarning.assert_called_once_with(
            "Existing Quarantine Data",
            notice
        )
        app.mainloop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
