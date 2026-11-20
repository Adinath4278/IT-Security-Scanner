import logging
from logging.handlers import RotatingFileHandler
from tkinter import messagebox

import customtkinter as ctk

from app_state import default_data_directory


def configure_logging():
    log_directory = default_data_directory() / "logs"
    try:
        log_directory.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_directory / "application.log",
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
    except OSError as error:
        messagebox.showerror(
            "Startup Error",
            f"Application logging could not be initialized:\n{error}",
        )
        raise

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[handler],
        force=True,
    )


def main():
    configure_logging()
    from ui import SecurityScannerUI

    ctk.set_appearance_mode("dark")      # light / dark / system
    ctk.set_default_color_theme("blue")

    try:
        app = SecurityScannerUI()
    except OSError as error:
        logging.getLogger("ITSecurityScanner").exception(
            "Application storage initialization failed."
        )
        messagebox.showerror(
            "Application Storage Error",
            "IT Security Scanner could not safely initialize its storage.\n\n"
            f"{error}",
        )
        return 1
    legacy_quarantine_notice = getattr(
        getattr(app, "scanner", None),
        "legacy_quarantine_notice",
        None
    )
    if legacy_quarantine_notice:
        messagebox.showwarning(
            "Existing Quarantine Data",
            legacy_quarantine_notice
        )
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    
    