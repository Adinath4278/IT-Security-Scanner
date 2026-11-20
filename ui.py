import ctypes
import copy
import html
import logging
import os
import queue
import re
import string
import sys
import time
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timedelta
from ctypes import wintypes
from pathlib import Path
from tkinter import filedialog, ttk, messagebox

import customtkinter as ctk
from customtkinter.windows.widgets.appearance_mode.appearance_mode_tracker import (
    AppearanceModeTracker,
)
from customtkinter.windows.widgets.scaling.scaling_tracker import ScalingTracker

from app_state import AppState, DEFAULT_SETTINGS
from app_state import default_data_directory
from scanner import SecurityScanner
from report_generator import generate_report
from startup_scanner import scan_startup_entries
from threat_database import (
    DATABASE_FILE,
    get_database_size,
    import_local_signatures,
    reload_database,
)
from reputation import (
    CredentialStore,
    ReputationClient,
    calculate_file_sha256,
)
from threat_intelligence import (
    get_threat_intelligence_status,
    import_verified_update,
)
from vulnerability_assessment import (
    NvdClient,
    VulnerabilityAssessmentError,
    inventory_installed_software,
)
from version import __version__


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SecurityScannerUI(ctk.CTk):
    PAGE_ALIASES = {
        "Quick Scan": "File Scanner",
        "Full Scan": "File Scanner",
        "Custom Scan": "File Scanner",
        "Reports": "Scan Reports",
    }

    NAVIGATION = (
        ("⌂", "Dashboard"),
        ("⌕", "File Scanner"),
        ("◈", "Threat Detection"),
        ("▣", "Quarantine"),
        ("◇", "Vulnerability Assessment"),
        ("▤", "Scan Reports"),
        ("⚙", "Settings"),
        ("ⓘ", "About"),
    )

    def __init__(self):
        super().__init__()

        self.state_store = AppState()
        self.startup_issues = []
        try:
            self.settings = self.state_store.load_settings()
        except (OSError, ValueError, TypeError) as error:
            self.settings = DEFAULT_SETTINGS.copy()
            self.startup_issues.append(f"Settings could not be loaded: {error}")

        # ======================================================
        # WINDOW
        # ======================================================

        self.title(f"IT Security Scanner {__version__}")
        self.geometry("1440x900")
        self.minsize(980, 650)

        # Default appearance
        ctk.set_appearance_mode(
            self.settings.get("appearance", "Dark").lower()
        )
        ctk.set_default_color_theme("blue")

        # ======================================================
        # COLORS
        # ======================================================
        # CustomTkinter accepts:
        # (light_mode_color, dark_mode_color)
        #
        # This allows the same widgets to automatically change
        # when Light / Dark / System mode is selected.
        # ======================================================

        self.BG = ("#F4F6F8", "#0B1120")

        self.SIDEBAR = ("#FFFFFF", "#111827")

        self.CARD = ("#FFFFFF", "#172235")

        self.CARD2 = ("#EEF1F4", "#1D2A3D")

        self.BLUE = ("#1976D2", "#3B82F6")

        self.BLUE_DARK = ("#1565C0", "#2563EB")

        self.CYAN = ("#078AA8", "#06B6D4")
        self.GREEN = ("#15803D", "#22C55E")

        self.YELLOW = ("#C77700", "#F59E0B")

        self.RED = ("#D9363E", "#EF4444")

        self.RED_HOVER = ("#B71C1C", "#DC2626")

        self.TEXT = ("#1F2937", "#F8FAFC")

        self.MUTED = ("#667085", "#94A3B8")

        self.STATUS_BG = ("#E9EDF1", "#172235")

        self.NAV_HOVER = ("#E6EEF8", "#1E293B")
        self.BORDER = ("#D5DDE8", "#26354A")
        self.FONT = "Segoe UI"

        self.configure(
            fg_color=self.BG
        )

        # ======================================================
        # STATE
        # ======================================================

        self.scanner = SecurityScanner(
            max_workers=self.settings.get("scan_workers", 4),
            max_file_size=self.settings.get("max_file_size_mb", 100)
            * 1024 * 1024
        )
        self.reputation_client = ReputationClient()
        self.credential_store = CredentialStore()
        self.nvd_client = NvdClient()
        self._software_inventory = []
        self._selected_reputation_file = None
        self.scanner.set_exclusions(
            self.settings.get("scan_exclusions", [])
        )

        self.pages = {}
        self.scan_widgets = {}

        self.last_result = None
        self.active_scan = None

        self.scan_running = False
        self.scan_start = None
        self._scan_thread = None
        self._scan_operation_name = None

        self.custom_folder = None
        self.last_scan_page = None
        self._ui_events = queue.Queue()
        self._progress_lock = threading.Lock()
        self._last_progress_emit = 0.0
        self._current_page = None
        self._navigation_animation_id = None
        self.resource_monitoring = self.settings.get(
            "resource_monitoring",
            True
        )
        self._cpu_sample = None
        self._kernel32 = None
        self._resource_update_id = None
        self._scan_started_at = None
        self._scheduled_launch = False
        self._startup_scan_running = False
        self._settings_operation_running = False
        self._signature_import_running = False
        self._scan_event_generation = 0
        try:
            recovery_errors = self.state_store.recover_interrupted_restore(
                self.scanner.quarantine_dir,
                DATABASE_FILE
            )
            if recovery_errors:
                self.startup_issues.extend(recovery_errors)
        except (OSError, ValueError, TypeError) as error:
            self.startup_issues.append(
                f"Interrupted restore recovery could not be checked: {error}"
            )
        self.protocol(
            "WM_DELETE_WINDOW",
            self._request_application_close
        )

        # ======================================================
        # GRID
        # ======================================================

        self.grid_columnconfigure(
            1,
            weight=1
        )

        self.grid_rowconfigure(
            0,
            weight=1
        )

        # ======================================================
        # CREATE UI
        # ======================================================

        self.create_sidebar()
        self.create_pages()

        # Setup native Tkinter tables
        self.setup_ttk_style()

        self.show_page("Dashboard")
        self.update_dashboard_metrics()
        self.after(75, self._process_ui_events)
        self._resource_update_id = self.after(
            500,
            self._update_resource_metrics
        )
        self._install_error_handlers()
        self._run_startup_health_checks()
        self._refresh_local_signature_status()
        self._refresh_protection_history()
        self.after(5000, self._check_scheduled_scan)

    # ==========================================================
    # TTK TABLE THEME
    # ==========================================================

    def setup_ttk_style(self):

        """
        Configure native ttk.Treeview widgets.

        CustomTkinter widgets automatically understand
        light/dark tuples, but ttk.Treeview does not.
        Therefore we update its colors manually.
        """

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        mode = ctk.get_appearance_mode()

        if mode == "Light":

            background = "#FFFFFF"
            field_background = "#FFFFFF"
            foreground = "#1F2937"

            heading_background = "#E8EEF5"
            heading_foreground = "#1F2937"

            selected_background = "#BFD9F5"
            selected_foreground = "#1F2937"

            scrollbar_background = "#E8EEF5"
            scrollbar_trough = "#F4F6F8"

        else:

            background = "#111C2E"
            field_background = "#111C2E"
            foreground = "#F5F7FA"

            heading_background = "#172338"
            heading_foreground = "#F5F7FA"

            selected_background = "#155EAF"
            selected_foreground = "#FFFFFF"

            scrollbar_background = "#263650"
            scrollbar_trough = "#0B1220"

        # ------------------------------------------------------
        # TREEVIEW
        # ------------------------------------------------------

        style.configure(
            "Treeview",
            background=background,
            fieldbackground=field_background,
            foreground=foreground,
            rowheight=28,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=heading_background,
            foreground=heading_foreground,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[
                (
                    "selected",
                    selected_background
                )
            ],
            foreground=[
                (
                    "selected",
                    selected_foreground
                )
            ]
        )

        style.map(
            "Treeview.Heading",
            background=[
                (
                    "active",
                    heading_background
                )
            ],
            foreground=[
                (
                    "active",
                    heading_foreground
                )
            ]
        )

        # ------------------------------------------------------
        # SCROLLBAR
        # ------------------------------------------------------

        style.configure(
            "Vertical.TScrollbar",
            background=scrollbar_background,
            troughcolor=scrollbar_trough,
            borderwidth=0,
            arrowcolor=foreground
        )

        style.configure(
            "Horizontal.TScrollbar",
            background=scrollbar_background,
            troughcolor=scrollbar_trough,
            borderwidth=0,
            arrowcolor=foreground
        )

    # ==========================================================
    # SIDEBAR
    # ==========================================================

    def create_sidebar(self):

        self.sidebar = ctk.CTkFrame(
            self,
            width=230,
            corner_radius=0,
            fg_color=self.SIDEBAR
        )

        self.sidebar.grid(
            row=0,
            column=0,
            rowspan=2,
            sticky="nsew"
        )

        self.sidebar.grid_propagate(False)

        # ------------------------------------------------------
        # LOGO
        # ------------------------------------------------------

        logo_frame = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )

        logo_frame.pack(
            fill="x",
            padx=15,
            pady=(20, 12)
        )

        ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=("Segoe UI Emoji", 42)
        ).pack()

        ctk.CTkLabel(
            logo_frame,
            text="IT SECURITY",
            font=(self.FONT, 19, "bold"),
            text_color=self.TEXT
        ).pack()

        ctk.CTkLabel(
            logo_frame,
            text="SCANNER",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        ).pack()

        # ------------------------------------------------------
        # NAVIGATION
        # ------------------------------------------------------

        self.nav_buttons = {}
        self.navigation_frame = ctk.CTkScrollableFrame(
            self.sidebar,
            fg_color="transparent",
            corner_radius=0
        )
        self.navigation_frame.pack(
            fill="both",
            expand=True,
            padx=7,
            pady=(0, 8)
        )

        for icon, name in self.NAVIGATION:

            button = ctk.CTkButton(
                self.navigation_frame,
                text=f"{icon}   {name}",
                height=42,
                corner_radius=8,
                anchor="w",
                font=(self.FONT, 13),
                fg_color="transparent",
                hover_color=self.NAV_HOVER,
                text_color=self.TEXT,
                command=lambda page=name:
                    self.show_page(page)
            )

            button.pack(
                fill="x",
                padx=6,
                pady=3
            )

            self.nav_buttons[name] = button

        # ------------------------------------------------------
        # BOTTOM STATUS
        # ------------------------------------------------------

        status_frame = ctk.CTkFrame(
            self.sidebar,
            fg_color=self.STATUS_BG,
            corner_radius=10
        )

        status_frame.pack(
            side="bottom",
            fill="x",
            padx=15,
            pady=14
        )

        self.status_dot = ctk.CTkLabel(
            status_frame,
            text="●",
            text_color=self.GREEN,
            font=("Segoe UI", 13)
        )

        self.status_dot.pack(
            side="left",
            padx=(12, 5),
            pady=10
        )

        self.sidebar_status = ctk.CTkLabel(
            status_frame,
            text="Scanner Ready",
            text_color=self.MUTED,
            font=(self.FONT, 11)
        )

        self.sidebar_status.pack(
            side="left",
            pady=10
        )

    # ==========================================================
    # PAGES
    # ==========================================================

    def create_pages(self):

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

        self.header = ctk.CTkFrame(
            self,
            height=76,
            corner_radius=0,
            fg_color=self.BG,
            border_width=1,
            border_color=self.BORDER
        )
        self.header.grid(
            row=0,
            column=1,
            sticky="ew"
        )
        self.header.grid_propagate(False)
        self.header.grid_columnconfigure(0, weight=1)
        self.header_page_title = ctk.CTkLabel(
            self.header,
            text="Dashboard",
            font=(self.FONT, 20, "bold"),
            text_color=self.TEXT
        )
        self.header_page_title.grid(
            row=0,
            column=0,
            sticky="w",
            padx=26,
            pady=(13, 0)
        )
        ctk.CTkLabel(
            self.header,
            text=f"IT SECURITY SCANNER  ·  v{__version__}",
            font=(self.FONT, 10, "bold"),
            text_color=self.MUTED
        ).grid(
            row=1,
            column=0,
            sticky="w",
            padx=27,
            pady=(0, 12)
        )
        self.header_status = ctk.CTkLabel(
            self.header,
            text="●  Scanner ready",
            font=(self.FONT, 12, "bold"),
            text_color=self.GREEN
        )
        self.header_status.grid(
            row=0,
            column=1,
            rowspan=2,
            padx=(8, 12)
        )
        ctk.CTkButton(
            self.header,
            text="⚙",
            width=38,
            height=36,
            command=lambda: self.show_page("Settings")
        ).grid(
            row=0,
            column=2,
            rowspan=2,
            padx=(0, 20)
        )

        self.container = ctk.CTkScrollableFrame(
            self,
            fg_color=self.BG,
            corner_radius=0
        )

        self.container.grid(
            row=1,
            column=1,
            sticky="nsew",
            padx=0,
            pady=0
        )

        self.container.grid_rowconfigure(
            0,
            weight=1
        )

        self.container.grid_columnconfigure(
            0,
            weight=1
        )

        self.create_dashboard_page()
        self.create_file_scanner_page()
        self.create_threat_detection_page()
        self.create_startup_page()
        self.create_reports_page()
        self.create_quarantine_page()
        self.create_threat_intelligence_page()
        self.create_vulnerability_page()
        self.create_reputation_page()
        self.create_settings_page()
        self.create_about_page()

    def create_page(self, name):

        page = ctk.CTkFrame(
            self.container,
            fg_color="transparent",
            corner_radius=0
        )

        self.pages[name] = page

        return page

    def show_page(self, name):
        name = self.resolve_page_name(name)
        page = self.pages.get(name)

        if not page:
            return

        if self._current_page == name:
            return

        if self._current_page in self.pages:
            self.pages[self._current_page].pack_forget()

        if self._navigation_animation_id is not None:
            self.after_cancel(self._navigation_animation_id)
            self._navigation_animation_id = None

        page.pack(
            fill="both",
            expand=True,
            padx=8
        )
        self._current_page = name
        self.after_idle(self.container._parent_canvas.yview_moveto, 0)
        self._animate_page_in(page, 8)
        self.header_page_title.configure(text=name)

        # Highlight navigation button
        for page_name, button in self.nav_buttons.items():

            if page_name == name:

                button.configure(
                    fg_color=self.BLUE_DARK
                )

            else:

                button.configure(
                    fg_color="transparent"
                )

        if name == "Quarantine":
            self.refresh_quarantine()

        if name == "Scan Reports":
            self.refresh_reports()
        if name == "Threat Detection":
            self.refresh_threat_detections()
        if name == "Dashboard":
            self.update_dashboard_metrics()
        if name == "Settings":
            self.settings_section_status.configure(
                text="Choose a feature below. External lookups remain opt-in."
            )

    @classmethod
    def resolve_page_name(cls, name):
        return cls.PAGE_ALIASES.get(name, name)

    def _animate_page_in(self, page, offset):
        if page is not self.pages.get(self._current_page):
            return

        if offset <= 0:
            page.pack_configure(padx=0)
            self._navigation_animation_id = None
            return

        page.pack_configure(padx=offset)
        self._navigation_animation_id = self.after(
            12,
            lambda: self._animate_page_in(page, offset - 2)
        )

    def _queue_ui_event(self, event_type, *payload):
        self._ui_events.put((event_type, payload))

    def _process_ui_events(self):
        for _ in range(100):
            try:
                event_type, payload = self._ui_events.get_nowait()
            except queue.Empty:
                break

            try:
                if event_type == "scan_progress":
                    self._render_scan_progress(*payload)
                elif event_type == "scan_finished":
                    self.scan_finished(*payload)
                elif event_type == "scan_error":
                    self.scan_error(*payload)
                elif event_type == "startup_finished":
                    self.display_startup_results(*payload)
                elif event_type == "startup_error":
                    self.startup_scan_error(*payload)
                elif event_type == "report_finished":
                    self._report_finished(*payload)
                elif event_type == "report_error":
                    self._report_failed(*payload)
                elif event_type == "backup_finished":
                    self._backup_finished(*payload)
                elif event_type == "backup_error":
                    self._backup_failed(*payload)
                elif event_type == "restore_finished":
                    self._restore_finished(*payload)
                elif event_type == "restore_error":
                    self._restore_failed(*payload)
                elif event_type == "threat_intelligence_status":
                    self._render_threat_intelligence_status(*payload)
                elif event_type == "threat_intelligence_result":
                    self._render_threat_intelligence_result(*payload)
                elif event_type == "threat_intelligence_error":
                    self._render_threat_intelligence_error(*payload)
                elif event_type == "local_signature_import_result":
                    self._render_local_signature_import_result(*payload)
                elif event_type == "local_signature_import_error":
                    self._render_local_signature_import_error(*payload)
                elif event_type == "signature_update_result":
                    self._render_local_signature_import_result(*payload)
                elif event_type == "signature_update_error":
                    self._render_local_signature_import_error(*payload)
                elif event_type == "software_inventory_result":
                    self._render_software_inventory(*payload)
                elif event_type == "vulnerability_result":
                    self._render_vulnerability_results(*payload)
                elif event_type == "vulnerability_error":
                    self._render_vulnerability_error(*payload)
                elif event_type == "reputation_result":
                    self._render_reputation_result(*payload)
                elif event_type == "reputation_error":
                    self._render_reputation_error(*payload)
                elif event_type == "quarantine_integrity_result":
                    self._render_quarantine_integrity(*payload)
                elif event_type == "fatal_thread_error":
                    self._handle_application_error(*payload)
            except Exception as error:
                self._handle_application_error(
                    "UI event processing",
                    error
                )

        if self.winfo_exists():
            self.after(75, self._process_ui_events)

    def _install_error_handlers(self):
        self._previous_sys_excepthook = sys.excepthook
        self._installed_sys_excepthook = self._handle_uncaught_exception
        sys.excepthook = self._installed_sys_excepthook
        if hasattr(threading, "excepthook"):
            self._previous_thread_excepthook = threading.excepthook
            self._installed_thread_excepthook = (
                self._handle_uncaught_thread_exception
            )
            threading.excepthook = self._installed_thread_excepthook

    def _request_application_close(self):
        if (
            getattr(self, "_settings_operation_running", False)
            or getattr(self, "_signature_import_running", False)
        ):
            messagebox.showwarning(
                "Operation in Progress",
                "Wait for backup, restore, or signature operations to finish "
                "before closing IT Security Scanner."
            )
            return
        if getattr(self, "scan_running", False):
            if not messagebox.askyesno(
                "Cancel Scan?",
                "A scan is running. Cancel it and close the application?"
            ):
                return
            self.scanner.cancel()
        self.destroy()

    def destroy(self):
        if self.scan_running:
            self.scanner.cancel()
        if (
            getattr(self, "_settings_operation_running", False)
            or getattr(self, "_signature_import_running", False)
        ):
            messagebox.showwarning(
                "Operation in Progress",
                "Wait for backup, restore, or signature operations to finish "
                "before closing IT Security Scanner."
            )
            return

        installed_sys_hook = getattr(
            self,
            "_installed_sys_excepthook",
            None
        )
        if installed_sys_hook is not None:
            if sys.excepthook is installed_sys_hook:
                sys.excepthook = self._previous_sys_excepthook
            self._installed_sys_excepthook = None

        installed_thread_hook = getattr(
            self,
            "_installed_thread_excepthook",
            None
        )
        if installed_thread_hook is not None:
            if threading.excepthook is installed_thread_hook:
                threading.excepthook = self._previous_thread_excepthook
            self._installed_thread_excepthook = None

        super().destroy()
        if self in AppearanceModeTracker.app_list:
            AppearanceModeTracker.app_list.remove(self)
        if not AppearanceModeTracker.app_list:
            AppearanceModeTracker.update_loop_running = False
        ScalingTracker.window_dpi_scaling_dict.pop(self, None)
        if not ScalingTracker.window_widgets_dict:
            ScalingTracker.update_loop_running = False

    def report_callback_exception(self, exception_type, exception, tb):
        self._handle_application_error(
            "UI callback",
            exception,
            tb
        )

    def _handle_uncaught_exception(self, exception_type, exception, tb):
        self._handle_application_error(
            "Uncaught application exception",
            exception,
            tb
        )

    def _handle_uncaught_thread_exception(self, args):
        self._queue_ui_event(
            "fatal_thread_error",
            "Uncaught background exception",
            args.exc_value,
            args.exc_traceback
        )

    def _handle_application_error(self, context, error, tb=None):
        logging.getLogger("ITSecurityScanner").exception(
            "%s: %s",
            context,
            error,
            exc_info=(type(error), error, tb) if tb else None
        )
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return

        self._record_event(
            "application_error",
            f"{context}: {error}"
        )
        if hasattr(self, "sidebar_status"):
            self.sidebar_status.configure(text="Recovered from error")
        if hasattr(self, "dashboard_status_message"):
            self.dashboard_status_message.configure(
                text=f"{context} failed. Details are saved in protection history."
            )

    def _record_event(self, event_type, message, details=None):
        try:
            event = self.state_store.record_event(
                event_type,
                message,
                details
            )
        except (OSError, ValueError, TypeError) as error:
            logging.getLogger("ITSecurityScanner").exception(
                "Could not save protection history"
            )
            if hasattr(self, "sidebar_status"):
                self.sidebar_status.configure(text="History storage unavailable")
            return None

        self._refresh_protection_history()
        return event

    def _refresh_protection_history(self):
        if not hasattr(self, "protection_history_box"):
            return

        try:
            events = self.state_store.get_recent_events(6)
        except (OSError, UnicodeError) as error:
            logging.getLogger("ITSecurityScanner").exception(
                "Could not read protection history"
            )
            self.protection_history_box.configure(state="normal")
            self.protection_history_box.delete("1.0", "end")
            self.protection_history_box.insert(
                "end",
                f"Protection history unavailable: {error}"
            )
            self.protection_history_box.configure(state="disabled")
            return

        self.protection_history_box.configure(state="normal")
        self.protection_history_box.delete("1.0", "end")
        if not events:
            self.protection_history_box.insert(
                "end",
                "No protection events recorded."
            )
        else:
            for event in events:
                timestamp = event.get("timestamp", "")
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp
                    ).strftime("%b %d %H:%M")
                except ValueError:
                    timestamp = timestamp[:16]
                self.protection_history_box.insert(
                    "end",
                    f"{timestamp}  ·  {event.get('message', '')}\n"
                )
        self.protection_history_box.configure(state="disabled")

    def _save_settings(self):
        try:
            self.state_store.save_settings(self.settings)
            if hasattr(self, "settings_status_label"):
                self.settings_status_label.configure(
                    text="Settings saved locally."
                )
            return True
        except (OSError, TypeError, ValueError) as error:
            logging.getLogger("ITSecurityScanner").exception(
                "Could not save settings"
            )
            if hasattr(self, "settings_status_label"):
                self.settings_status_label.configure(
                    text=f"Settings could not be saved: {error}"
                )
            return False

    def _run_startup_health_checks(self):
        checks = []
        state_ok = True
        try:
            self.state_store.data_directory.mkdir(
                parents=True,
                exist_ok=True
            )
            probe = self.state_store.data_directory / ".health-check"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as error:
            state_ok = False
            checks.append(f"Local settings storage unavailable: {error}")
        if state_ok:
            checks.append("Local settings storage is writable.")

        quarantine_ok = True
        try:
            self.scanner.quarantine_dir.mkdir(
                parents=True,
                exist_ok=True
            )
            probe = self.scanner.quarantine_dir / ".health-check"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as error:
            quarantine_ok = False
            checks.append(f"Quarantine storage unavailable: {error}")
        if quarantine_ok:
            checks.append("Quarantine storage is writable.")
        if self.scanner.quarantine_recovery_errors:
            quarantine_ok = False
            checks.extend(
                f"Quarantine recovery warning: {error}"
                for error in self.scanner.quarantine_recovery_errors
            )
            self._record_event(
                "quarantine_recovery_warning",
                "One or more quarantine operations require review.",
                {"errors": self.scanner.quarantine_recovery_errors[:20]}
            )

        try:
            signature_count = get_database_size()
            checks.append(
                f"Local signature database loaded ({signature_count} signatures)."
            )
        except (OSError, UnicodeError) as error:
            checks.append(f"Signature database unavailable: {error}")

        if self.scanner.yara_scanner.error:
            checks.append(
                f"YARA scanning unavailable: {self.scanner.yara_scanner.error}"
            )
        else:
            checks.append("YARA rules are loaded.")

        self.health_checks = checks
        if hasattr(self, "health_status_label"):
            self.health_status_label.configure(
                text="\n".join(checks),
                text_color=self.RED if not state_ok or not quarantine_ok else self.MUTED
            )

        if self.startup_issues:
            self._record_event(
                "health_check_warning",
                "; ".join(self.startup_issues)
            )
        self._record_event("health_check", "Application startup checks completed.")

    def _refresh_local_signature_status(self):
        if not hasattr(self, "signature_status_label"):
            return
        try:
            count = get_database_size()
            self.signature_status_label.configure(
                text=f"{count:,} local SHA-256 signatures loaded."
            )
        except (OSError, UnicodeError) as error:
            self.signature_status_label.configure(
                text=f"Local signature database unavailable: {error}"
            )

    @staticmethod
    def _filetime_value(filetime):
        return (
            (filetime.dwHighDateTime << 32)
            | filetime.dwLowDateTime
        )

    def _read_system_resources(self):
        if os.name != "nt":
            raise OSError("System resource monitoring requires Windows.")

        if self._kernel32 is None:
            self._kernel32 = ctypes.WinDLL(
                "kernel32",
                use_last_error=True
            )

            self._kernel32.GetSystemTimes.argtypes = [
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
            ]
            self._kernel32.GetSystemTimes.restype = wintypes.BOOL
            self._kernel32.GlobalMemoryStatusEx.argtypes = [
                ctypes.POINTER(_MEMORYSTATUSEX)
            ]
            self._kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL

        idle = _FILETIME()
        kernel = _FILETIME()
        user = _FILETIME()

        if not self._kernel32.GetSystemTimes(
            ctypes.byref(idle),
            ctypes.byref(kernel),
            ctypes.byref(user)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        idle_time = self._filetime_value(idle)
        total_time = (
            self._filetime_value(kernel)
            + self._filetime_value(user)
        )
        current_sample = (idle_time, total_time)

        cpu_percent = None
        if self._cpu_sample is not None:
            previous_idle, previous_total = self._cpu_sample
            total_delta = total_time - previous_total
            idle_delta = idle_time - previous_idle

            if total_delta > 0:
                cpu_percent = max(
                    0.0,
                    min(
                        100.0,
                        (total_delta - idle_delta) * 100.0 / total_delta
                    )
                )

        self._cpu_sample = current_sample

        memory = _MEMORYSTATUSEX()
        memory.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)

        if not self._kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            raise ctypes.WinError(ctypes.get_last_error())

        return cpu_percent, int(memory.dwMemoryLoad)

    def _update_resource_metrics(self):
        if not self.winfo_exists():
            return

        self._resource_update_id = None
        self._render_resource_metrics()
        self._resource_update_id = self.after(
            2500,
            self._update_resource_metrics
        )

    def _render_resource_metrics(self):
        if not self.resource_monitoring:
            self.cpu_card.configure(text="Paused")
            self.ram_card.configure(text="Paused")
            self.resource_status_label.configure(
                text="System resource monitoring is paused."
            )
        else:
            try:
                cpu_percent, memory_percent = self._read_system_resources()
                self.cpu_card.configure(
                    text=(
                        f"{cpu_percent:.0f}%"
                        if cpu_percent is not None
                        else "Sampling..."
                    )
                )
                self.ram_card.configure(text=f"{memory_percent}%")
                self.resource_status_label.configure(
                    text="CPU and memory use are sampled locally."
                )
            except (OSError, AttributeError) as error:
                self.cpu_card.configure(text="N/A")
                self.ram_card.configure(text="N/A")
                self.resource_status_label.configure(
                    text=f"Resource monitoring unavailable: {error}"
                )

    def set_resource_monitoring(self, persist=True):
        self.resource_monitoring = bool(
            self.resource_monitor_switch.get()
        )
        self._render_resource_metrics()
        self.settings["resource_monitoring"] = self.resource_monitoring
        if persist:
            self._save_settings()

    def open_latest_results(self):
        if self.last_scan_page in self.scan_widgets:
            self.show_page(self.last_scan_page)
            table = self.scan_widgets[self.last_scan_page]["table"]
            rows = table.get_children()
            if rows:
                table.selection_set(rows[0])
                table.see(rows[0])
                self.on_threat_selected(self.last_scan_page)
            return

        self.show_page("Quick Scan")

    def show_score_details(self):
        if self.last_result is None:
            messagebox.showinfo(
                "Security Score",
                "Run a scan to calculate a device security score."
            )
            return

        error_count = self.last_result.get("error_count", 0)
        if error_count:
            messagebox.showinfo(
                "Security Score",
                "The latest scan had "
                f"{error_count:,} error(s), so a complete security score "
                "is unavailable."
            )
            return

        threats = self.last_result.get("suspicious", [])
        counts = self._severity_counts(threats)
        score = self.calculate_security_score(threats)
        breakdown = "\n".join(
            f"{risk}: {counts[risk]}"
            for risk in (
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational",
            )
        )

        messagebox.showinfo(
            "Security Score",
            f"Current score: {score}/100\n\n"
            f"{breakdown}\n\n"
            "The score is reduced according to suspicious finding severity; "
            "informational findings do not reduce it. This is not a guarantee "
            "that the system is clean."
        )

    # ==========================================================
    # COMMON HEADER
    # ==========================================================

    def page_header(
        self,
        parent,
        title,
        subtitle
    ):

        header = ctk.CTkFrame(
            parent,
            fg_color="transparent"
        )

        header.pack(
            fill="x",
            padx=25,
            pady=(25, 15)
        )

        ctk.CTkLabel(
            header,
            text=title,
            font=("Segoe UI", 30, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w"
        )

        ctk.CTkLabel(
            header,
            text=subtitle,
            font=("Segoe UI", 13),
            text_color=self.MUTED
        ).pack(
            anchor="w",
            pady=(5, 0)
        )

    # ==========================================================
    # DASHBOARD
    # ==========================================================

    def create_dashboard_page(self):

        page = self.create_page("Dashboard")

        self.page_header(
            page,
            "Security Dashboard",
            "Monitor your device protection and scan activity."
        )

        # ------------------------------------------------------
        # STAT CARDS
        # ------------------------------------------------------

        cards = ctk.CTkFrame(
            page,
            fg_color="transparent"
        )

        cards.pack(
            fill="x",
            padx=20,
            pady=10
        )

        for i in range(3):

            cards.grid_columnconfigure(
                i,
                weight=1
            )

        self.protection_card = self.dashboard_card(
            cards,
            0,
            "🛡️",
            "Protection",
            "Ready"
        )

        self.score_card = self.dashboard_card(
            cards,
            1,
            "📊",
            "Security Score",
            "—/100"
        )

        self.threat_card = self.dashboard_card(
            cards,
            2,
            "🦠",
            "Threats detected",
            "—"
        )

        self.last_scan_card = self.dashboard_card(
            cards,
            3,
            "🕒",
            "Last Scan",
            "Never"
        )

        self.suspicious_card = self.dashboard_card(
            cards, 4, "◈", "Suspicious", "0"
        )
        self.quarantined_card = self.dashboard_card(
            cards, 5, "▤", "Quarantined", "0"
        )
        self.score_card = self.dashboard_card(
            cards, 6, "◉", "Security Score", "—"
        )
        self.files_scanned_card = self.dashboard_card(
            cards, 7, "▤", "Files scanned", "0"
        )
        self.cpu_card = self.dashboard_card(
            cards, 8, "⌁", "CPU", "—"
        )
        self.ram_card = self.dashboard_card(
            cards, 9, "▤", "Memory", "—"
        )

        for metric in (self.score_card, self.threat_card, self.last_scan_card):
            metric.configure(cursor="hand2")

        self.score_card.bind(
            "<Button-1>",
            lambda event: self.show_score_details()
        )
        self.threat_card.bind(
            "<Button-1>",
            lambda event: self.open_latest_results()
        )
        self.last_scan_card.bind(
            "<Button-1>",
            lambda event: self.show_page("Reports")
        )

        # ------------------------------------------------------
        # SECURITY STATUS
        # ------------------------------------------------------

        status = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        status.pack(
            fill="x",
            padx=20,
            pady=15
        )

        self.dashboard_status_title = ctk.CTkLabel(
            status,
            text="READY TO SCAN",
            font=("Segoe UI", 19, "bold"),
            text_color=self.BLUE
        )

        self.dashboard_status_title.pack(
            anchor="w",
            padx=25,
            pady=(16, 5)
        )

        self.dashboard_status_message = ctk.CTkLabel(
            status,
            text="Run a scan to assess this device.",
            font=("Segoe UI", 14),
            text_color=self.TEXT
        )

        self.dashboard_status_message.pack(
            anchor="w",
            padx=25,
            pady=(5, 16)
        )
        self.dashboard_start_scan_button = ctk.CTkButton(
            status,
            text="Start Quick Scan",
            width=190,
            height=42,
            font=(self.FONT, 13, "bold"),
            command=self.start_quick_scan
        )
        self.dashboard_start_scan_button.pack(
            anchor="w",
            padx=24,
            pady=(0, 18)
        )

        # ------------------------------------------------------
        # QUICK ACTIONS
        # ------------------------------------------------------

        ctk.CTkLabel(
            page,
            text="Quick Actions",
            font=("Segoe UI", 21, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(20, 10)
        )

        actions = ctk.CTkFrame(
            page,
            fg_color="transparent"
        )

        actions.pack(
            fill="x",
            padx=20
        )

        for i in range(3):

            actions.grid_columnconfigure(
                i,
                weight=1
            )

        self.action_button(
            actions,
            0,
            "⚡ Quick Scan",
            "Desktop • Downloads • Documents",
            lambda: self._open_scanner_with_mode("Quick Scan")
        )

        self.action_button(
            actions,
            1,
            "💻 Full Scan",
            "Scan available Windows drives",
            lambda: self._open_scanner_with_mode("Full Scan")
        )

        self.action_button(
            actions,
            2,
            "📂 Custom Scan",
            "Choose a folder to scan",
            lambda: self._open_scanner_with_mode("Custom Folder")
        )

        # ------------------------------------------------------
        # LATEST SCAN
        # ------------------------------------------------------

        recent = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        recent.pack(
            fill="x",
            padx=20,
            pady=25
        )

        ctk.CTkLabel(
            recent,
            text="Latest Scan",
            font=("Segoe UI", 19, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(20, 5)
        )

        self.dashboard_recent_label = ctk.CTkLabel(
            recent,
            text="No scan performed yet.",
            font=("Segoe UI", 14),
            text_color=self.MUTED
        )

        self.dashboard_recent_label.pack(
            anchor="w",
            padx=25,
            pady=(5, 10)
        )

        ctk.CTkLabel(
            recent,
            text="Recent Protection Events",
            font=("Segoe UI", 13, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(4, 4)
        )

        self.protection_history_box = ctk.CTkTextbox(
            recent,
            height=92,
            font=("Consolas", 10),
            fg_color=self.CARD2,
            text_color=self.MUTED,
            wrap="word"
        )
        self.protection_history_box.pack(
            fill="x",
            padx=20,
            pady=(0, 15)
        )
        ctk.CTkLabel(
            recent,
            text="Recent findings",
            font=(self.FONT, 13, "bold"),
            text_color=self.TEXT
        ).pack(anchor="w", padx=25, pady=(4, 6))
        self.dashboard_findings_table = ttk.Treeview(
            recent,
            columns=("Severity", "Finding", "File"),
            show="headings",
            height=4
        )
        for column in ("Severity", "Finding", "File"):
            self.dashboard_findings_table.heading(column, text=column)
        self.dashboard_findings_table.column("Severity", width=110)
        self.dashboard_findings_table.column("Finding", width=240)
        self.dashboard_findings_table.column("File", width=600)
        self.dashboard_findings_table.pack(
            fill="x",
            padx=20,
            pady=(0, 16)
        )
        self.dashboard_findings_table.bind(
            "<Double-1>",
            lambda _event: self.show_page("Threat Detection")
        )
        self.protection_history_box.configure(state="disabled")

    @staticmethod
    def dashboard_metric_values(events, last_result, quarantined_paths):
        scan_events = [
            event for event in events
            if event.get("type") in {"scan_completed", "scan_cancelled"}
        ]
        files_scanned = sum(
            max(0, int((event.get("details") or {}).get("files_scanned", 0)))
            for event in scan_events
        )
        findings_total = sum(
            max(0, int((event.get("details") or {}).get("findings", 0)))
            for event in scan_events
        )
        findings = (
            last_result.get("suspicious", [])
            if isinstance(last_result, dict)
            else []
        )
        if not isinstance(findings, list):
            findings = []
        confirmed = sum(
            1 for finding in findings
            if finding.get("classification") == "Confirmed malware signature"
        )
        suspicious = sum(
            1 for finding in findings
            if finding.get("classification") in {
                "Strongly suspicious",
                "Potentially suspicious"
            }
        )
        return {
            "files_scanned": files_scanned,
            "findings_total": findings_total,
            "confirmed_latest": confirmed,
            "suspicious_latest": suspicious,
            "quarantined": len(quarantined_paths),
            "last_scan": scan_events[0] if scan_events else None,
            "findings": findings
        }

    @staticmethod
    def scan_result_state(result):
        if result.get("cancelled"):
            return "Cancelled"
        if result.get("error_count", 0) or result.get("findings_truncated"):
            return "Incomplete"
        return "Complete"

    @staticmethod
    def compare_quarantine_hashes(expected_hash, actual_hash):
        return (
            "Verified"
            if expected_hash.casefold() == actual_hash.casefold()
            else "HASH MISMATCH"
        )

    def update_dashboard_metrics(self):
        if not hasattr(self, "score_card"):
            return
        try:
            events = self.state_store.get_recent_events(1000)
            quarantined = self.scanner.list_quarantine()
            values = self.dashboard_metric_values(
                events,
                self.last_result,
                quarantined
            )
        except (OSError, ValueError, TypeError) as error:
            self.dashboard_status_title.configure(
                text="STATUS UNAVAILABLE",
                text_color=self.YELLOW
            )
            self.dashboard_status_message.configure(
                text=f"Dashboard data could not be loaded: {error}"
            )
            return

        self.protection_card.configure(
            text="Scanning" if self.scan_running else "Ready"
        )
        self.last_scan_card.configure(
            text=(
                values["last_scan"].get("timestamp", "Recorded")
                if values["last_scan"]
                else "No scan yet"
            )
        )
        self.threat_card.configure(
            text=(
                str(values["confirmed_latest"])
                if self.last_result is not None
                else "—"
            )
        )
        self.suspicious_card.configure(
            text=(
                str(values["suspicious_latest"])
                if self.last_result is not None
                else "—"
            )
        )
        self.quarantined_card.configure(text=str(values["quarantined"]))
        self.files_scanned_card.configure(
            text=f"{values['files_scanned']:,}"
        )

        if self.last_result is None:
            self.score_card.configure(text="Not assessed")
            self.dashboard_status_title.configure(
                text="READY TO SCAN",
                text_color=self.BLUE
            )
            if values["last_scan"]:
                self.dashboard_status_message.configure(
                    text=(
                        "A previous scan is in history, but findings are not "
                        "loaded in this session. Run a scan to refresh the assessment."
                    )
                )
                self.dashboard_recent_label.configure(
                    text=values["last_scan"].get("message", "Previous scan recorded.")
                )
            else:
                self.dashboard_status_message.configure(
                    text=(
                        "No scan has been performed. Start a scan to assess "
                        "accessible files."
                    )
                )
                self.dashboard_recent_label.configure(
                    text="No scan performed yet."
                )
        else:
            if self.scan_result_state(self.last_result) != "Complete":
                self.score_card.configure(text="Unavailable")
                self.dashboard_status_title.configure(
                    text="SCAN INCOMPLETE",
                    text_color=self.YELLOW
                )
                self.dashboard_status_message.configure(
                    text=(
                        "The latest scan was cancelled, had errors, or "
                        "retained only partial findings."
                    )
                )
            else:
                score = self.calculate_security_score(
                    self.last_result.get("suspicious", [])
                )
                self.score_card.configure(text=f"{score}/100")
            latest = values["last_scan"]
            if latest:
                self.dashboard_recent_label.configure(
                    text=latest.get("message", "Latest scan recorded.")
                )

        table = self.dashboard_findings_table
        for item in table.get_children():
            table.delete(item)
        for finding in values["findings"][:5]:
            table.insert(
                "",
                "end",
                values=(
                    finding.get("risk", "Unknown"),
                    finding.get("name", "Unknown"),
                    finding.get("path", "")
                )
            )

        self.protection_history_box.configure(state="normal")
        self.protection_history_box.delete("1.0", "end")
        history_lines = [
            f"{event.get('timestamp', '')}  {event.get('message', '')}"
            for event in events[:8]
        ]
        self.protection_history_box.insert(
            "1.0",
            "\n".join(history_lines) if history_lines else "No recent activity."
        )
        self.protection_history_box.configure(state="disabled")

    def dashboard_card(
        self,
        parent,
        column,
        icon,
        title,
        value
    ):

        box = ctk.CTkFrame(
            parent,
            fg_color=self.CARD,
            corner_radius=12,
            height=112
        )

        row, grid_column = divmod(column, 3)
        box.grid(
            row=row,
            column=grid_column,
            sticky="ew",
            padx=6
        )

        box.grid_propagate(False)

        ctk.CTkLabel(
            box,
            text=f"{icon}  {title}",
            font=(self.FONT, 12),
            text_color=self.MUTED
        ).pack(
            anchor="w",
            padx=12,
            pady=(14, 5)
        )

        label = ctk.CTkLabel(
            box,
            text=value,
            font=(self.FONT, 18, "bold"),
            text_color=self.TEXT
        )

        label.pack(
            anchor="w",
            padx=12
        )

        return label

    def action_button(
        self,
        parent,
        column,
        title,
        subtitle,
        command
    ):

        box = ctk.CTkFrame(
            parent,
            fg_color=self.CARD,
            corner_radius=12
        )

        box.grid(
            row=0,
            column=column,
            sticky="ew",
            padx=6
        )

        ctk.CTkButton(
            box,
            text=title,
            height=48,
            font=("Segoe UI", 14, "bold"),
            command=command
        ).pack(
            fill="x",
            padx=15,
            pady=(15, 5)
        )

        ctk.CTkLabel(
            box,
            text=subtitle,
            font=("Segoe UI", 11),
            text_color=self.MUTED
        ).pack(
            pady=(0, 15)
        )

    def create_file_scanner_page(self):
        page = self.create_page("File Scanner")
        self.page_header(
            page,
            "File Scanner",
            "Choose a scan type and inspect progress, findings, and results."
        )

        controls = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        controls.pack(fill="x", padx=20, pady=(8, 10))
        ctk.CTkLabel(
            controls,
            text="Scan configuration",
            font=(self.FONT, 16, "bold"),
            text_color=self.TEXT
        ).pack(anchor="w", padx=20, pady=(16, 5))

        row = ctk.CTkFrame(controls, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(4, 14))
        self.scan_mode_menu = ctk.CTkOptionMenu(
            row,
            values=[
                "Quick Scan",
                "Full Scan",
                "Custom Folder",
                "Single File",
                "Removable Drive"
            ],
            command=self._update_scan_target_controls,
            width=190
        )
        self.scan_mode_menu.set("Quick Scan")
        self.scan_mode_menu.pack(side="left", padx=5)

        self.scan_target_entry = ctk.CTkEntry(
            row,
            placeholder_text="Optional scan path",
            state="disabled"
        )
        self.scan_target_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )
        self.scan_target_button = ctk.CTkButton(
            row,
            text="Browse",
            width=100,
            command=self._select_scan_target
        )
        self.scan_target_button.pack(side="left", padx=5)
        self.scan_target_help = ctk.CTkLabel(
            controls,
            text="Quick Scan checks common user folders.",
            anchor="w",
            font=(self.FONT, 11),
            text_color=self.MUTED
        )
        self.scan_target_help.pack(
            fill="x",
            padx=20,
            pady=(0, 12)
        )

        self.create_scan_area(
            page,
            "File Scanner",
            self.start_selected_scan
        )
        self.scan_target_path = ""

    def _open_scanner_with_mode(self, mode):
        self.show_page("File Scanner")
        self.scan_mode_menu.set(mode)
        self._update_scan_target_controls(mode)

    def _update_scan_target_controls(self, mode):
        needs_target = mode in {"Custom Folder", "Single File"}
        self.scan_target_entry.configure(
            state="normal" if needs_target else "disabled"
        )
        self.scan_target_button.configure(
            state="normal" if needs_target else "disabled"
        )
        help_text = {
            "Quick Scan": "Quick Scan checks common user folders.",
            "Full Scan": "Scans accessible fixed Windows drives.",
            "Custom Folder": "Choose a folder you are authorized to scan.",
            "Single File": "Select one file; the file itself is not modified.",
            "Removable Drive": "Select a removable drive when prompted."
        }
        self.scan_target_help.configure(text=help_text.get(mode, ""))

    def _select_scan_target(self):
        mode = self.scan_mode_menu.get()
        if mode == "Custom Folder":
            selected = filedialog.askdirectory(
                title="Select a folder to scan"
            )
        elif mode == "Single File":
            selected = filedialog.askopenfilename(
                title="Select a file to scan",
                filetypes=[("All files", "*.*")]
            )
        else:
            return
        if selected:
            self.scan_target_path = selected
            self.scan_target_entry.configure(state="normal")
            self.scan_target_entry.delete(0, "end")
            self.scan_target_entry.insert(0, selected)
            self.scan_target_entry.configure(state="disabled")

    def start_selected_scan(self):
        mode = self.scan_mode_menu.get()
        if mode == "Quick Scan":
            self.start_quick_scan()
        elif mode == "Full Scan":
            self.start_full_scan()
        elif mode == "Removable Drive":
            self.start_removable_drive_scan()
        elif mode == "Single File":
            filepath = self.scan_target_path or filedialog.askopenfilename(
                title="Select a file to scan",
                filetypes=[("All files", "*.*")]
            )
            if filepath:
                self._start_individual_file_scan(filepath)
        elif mode == "Custom Folder":
            folder = self.scan_target_path or filedialog.askdirectory(
                title="Select a folder to scan"
            )
            if folder:
                self.custom_folder = folder
                self._launch_scan(
                    "File Scanner",
                    "Custom Folder Scan",
                    lambda callback: self.scanner.custom_scan(
                        folder,
                        callback
                    )
                )
        else:
            messagebox.showerror(
                "Scan Mode Error",
                f"Unsupported scan mode: {mode}"
            )

    def create_threat_detection_page(self):
        page = self.create_page("Threat Detection")
        self.page_header(
            page,
            "Threat Detection",
            "Review findings produced by the latest scan. No threat data is inferred."
        )
        card = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=12)
        card.pack(fill="both", expand=True, padx=20, pady=10)
        filters = ctk.CTkFrame(card, fg_color="transparent")
        filters.pack(fill="x", padx=16, pady=(14, 8))
        ctk.CTkLabel(
            filters,
            text="Severity",
            text_color=self.MUTED
        ).pack(side="left", padx=(0, 8))
        self.finding_severity_filter = ctk.CTkOptionMenu(
            filters,
            values=[
                "All severities",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational"
            ],
            command=lambda _value: self.refresh_threat_detections()
        )
        self.finding_severity_filter.set("All severities")
        self.finding_severity_filter.pack(side="left")
        self.findings_status = ctk.CTkLabel(
            filters,
            text="No scan findings available.",
            text_color=self.MUTED
        )
        self.findings_status.pack(side="right")

        columns = (
            "Name",
            "Severity",
            "Confidence",
            "Detection",
            "Detected",
            "Path"
        )
        findings_table_frame = ctk.CTkFrame(
            card,
            fg_color="transparent"
        )
        findings_table_frame.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=5
        )
        self.findings_table = ttk.Treeview(
            findings_table_frame,
            columns=columns,
            show="headings",
            height=12
        )
        for column in columns:
            self.findings_table.heading(
                column,
                text=column,
                command=lambda selected=column: self.sort_threat_findings(
                    selected
                )
            )
        self.findings_table.column("Name", width=170)
        self.findings_table.column("Severity", width=100)
        self.findings_table.column("Confidence", width=100)
        self.findings_table.column("Detection", width=160)
        self.findings_table.column("Detected", width=150)
        self.findings_table.column("Path", width=500)
        self.findings_table.pack(
            side="left",
            fill="both",
            expand=True
        )
        findings_vertical_scroll = ttk.Scrollbar(
            findings_table_frame,
            orient="vertical",
            command=self.findings_table.yview
        )
        findings_vertical_scroll.pack(side="right", fill="y")
        findings_horizontal_scroll = ttk.Scrollbar(
            findings_table_frame,
            orient="horizontal",
            command=self.findings_table.xview
        )
        findings_horizontal_scroll.pack(side="bottom", fill="x")
        self.findings_table.configure(
            yscrollcommand=findings_vertical_scroll.set,
            xscrollcommand=findings_horizontal_scroll.set
        )
        self.findings_table.bind(
            "<<TreeviewSelect>>",
            self._show_selected_finding_details
        )
        self.findings_table.tag_configure("Critical", foreground="#EF4444")
        self.findings_table.tag_configure("High", foreground="#F97316")
        self.findings_table.tag_configure("Medium", foreground="#F59E0B")
        self.findings_table.tag_configure("Low", foreground="#3B82F6")
        self.findings_by_iid = {}
        self.findings_sort_column = "Severity"
        self.findings_sort_reverse = True

        self.finding_details = ctk.CTkTextbox(
            card,
            height=130,
            font=("Consolas", 11)
        )
        self.finding_details.pack(fill="x", padx=16, pady=(5, 10))
        self.finding_details.insert("1.0", "Select a finding to inspect details.")
        self.finding_details.configure(state="disabled")
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(
            actions,
            text="Quarantine selected finding",
            command=self.quarantine_selected_finding
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            actions,
            text="Open latest scan",
            command=lambda: self.show_page("File Scanner")
        ).pack(side="left", padx=4)

    def refresh_threat_detections(self):
        if not hasattr(self, "findings_table"):
            return
        table = self.findings_table
        for item in table.get_children():
            table.delete(item)
        self.findings_by_iid = {}
        findings = (
            self.last_result.get("suspicious", [])
            if isinstance(self.last_result, dict)
            else []
        )
        if not isinstance(findings, list):
            findings = []
        severity_filter = self.finding_severity_filter.get()
        visible = self.filter_and_sort_findings(
            findings,
            severity_filter,
            getattr(self, "findings_sort_column", "Severity"),
            getattr(self, "findings_sort_reverse", True)
        )
        if not self.last_result:
            status = "No scan has been performed."
        elif self.last_result.get("cancelled"):
            status = f"Partial findings from cancelled scan: {len(visible)}"
        elif self.last_result.get("error_count", 0):
            status = (
                f"Partial findings · {self.last_result['error_count']} scan "
                f"error(s) · {len(visible)} shown"
            )
        elif self.last_result.get("findings_truncated"):
            status = (
                f"Partial finding details · {len(visible)} of "
                f"{self.last_result.get('finding_count', len(findings))} "
                "retained"
            )
        else:
            status = f"{len(visible)} finding(s) · latest scan"
        self.findings_status.configure(text=status)

        for index, finding in enumerate(visible):
            iid = str(index)
            self.findings_by_iid[iid] = finding
            table.insert(
                "",
                "end",
                iid=iid,
                values=(
                    finding.get("name", "Unknown"),
                    finding.get("risk", "Unknown"),
                    finding.get("confidence", "N/A"),
                    finding.get("detection_type", "Unknown"),
                    finding.get("timestamp", "N/A"),
                    finding.get("path", "")
                ),
                tags=(finding.get("risk", "Unknown"),)
            )
        self._show_selected_finding_details(None)

    @staticmethod
    def filter_and_sort_findings(
        findings,
        severity_filter,
        sort_column,
        reverse=False
    ):
        filtered = [
            finding for finding in findings
            if severity_filter == "All severities"
            or finding.get("risk", "Unknown") == severity_filter
        ]
        sort_fields = {
            "Name": "name",
            "Severity": "risk",
            "Confidence": "confidence",
            "Detection": "detection_type",
            "Detected": "timestamp",
            "Path": "path"
        }
        field = sort_fields.get(sort_column, "risk")
        if field == "risk":
            severity_order = {
                "Informational": 0,
                "Low": 1,
                "Medium": 2,
                "High": 3,
                "Critical": 4
            }
            filtered.sort(
                key=lambda finding: severity_order.get(
                    finding.get(field, "Unknown"),
                    -1
                ),
                reverse=reverse
            )
        else:
            filtered.sort(
                key=lambda finding: str(
                    finding.get(field, "")
                ).casefold(),
                reverse=reverse
            )
        return filtered

    def sort_threat_findings(self, column):
        if self.findings_sort_column == column:
            self.findings_sort_reverse = not self.findings_sort_reverse
        else:
            self.findings_sort_column = column
            self.findings_sort_reverse = False
        self.refresh_threat_detections()

    def _show_selected_finding_details(self, _event):
        if not hasattr(self, "finding_details"):
            return
        selected = self.findings_table.selection()
        finding = self.findings_by_iid.get(selected[0]) if selected else None
        self.finding_details.configure(state="normal")
        self.finding_details.delete("1.0", "end")
        self.finding_details.insert(
            "1.0",
            self.format_finding_details(finding)
        )
        self.finding_details.configure(state="disabled")

    @staticmethod
    def format_finding_details(finding):
        if finding is None:
            return "Select a finding to inspect its evidence and recommended action."
        return (
            f"{finding.get('classification', 'Unclassified')} · "
            f"{finding.get('risk', 'Unknown')} · "
            f"Confidence {finding.get('confidence', 'N/A')}\n"
            f"Path: {finding.get('path', 'N/A')}\n"
            f"SHA-256: {finding.get('hash', 'N/A')}\n"
            f"Detected: {finding.get('timestamp', 'N/A')}\n"
            f"Explanation: {finding.get('detection_explanation', 'N/A')}\n"
            f"Recommended action: "
            f"{finding.get('recommended_action', 'Review manually.')}"
        )

    def quarantine_selected_finding(self):
        selected = self.findings_table.selection()
        if not selected:
            messagebox.showinfo(
                "No Finding Selected",
                "Select a finding before requesting quarantine."
            )
            return
        finding = self.findings_by_iid.get(selected[0])
        scan_widgets = self.scan_widgets.get("File Scanner")
        if not finding or not scan_widgets:
            messagebox.showerror(
                "Quarantine Unavailable",
                "The finding is not associated with an active scan result."
            )
            return
        path = finding.get("path")
        row = next(
            (
                item for item in scan_widgets["table"].get_children()
                if str(scan_widgets["table"].item(item).get("values", ["", "", "", ""])[3]) == str(path)
            ),
            None
        )
        if row is None:
            messagebox.showerror(
                "Quarantine Unavailable",
                "The selected finding is not present in the latest scan table."
            )
            return
        self.active_scan = "File Scanner"
        scan_widgets["table"].selection_set(row)
        self.quarantine_selected_file("File Scanner")

    def create_about_page(self):
        page = self.create_page("About")
        self.page_header(
            page,
            "About IT-Security-Scanner",
            "Local-first security assessment for Windows."
        )
        card = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=12)
        card.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            card,
            text=f"IT-Security-Scanner  ·  v{__version__}",
            font=(self.FONT, 23, "bold"),
            text_color=self.TEXT
        ).pack(anchor="w", padx=24, pady=(22, 8))
        ctk.CTkLabel(
            card,
            text=(
                "A local Windows security scanner combining file hashes, "
                "script heuristics, PE analysis, entropy analysis, YARA rules, "
                "optional consent-based hash reputation lookups, and an "
                "optional NVD vulnerability assessment.\n\n"
                "This tool is an on-demand scanner, not real-time antivirus "
                "protection. Findings require review; a clean scan is limited "
                "to the files and checks that completed successfully. External "
                "lookups are optional and require explicit consent."
            ),
            wraplength=950,
            justify="left",
            font=(self.FONT, 13),
            text_color=self.MUTED
        ).pack(anchor="w", padx=24, pady=(0, 22))
    # ==========================================================
    # SCAN PAGES
    # ==========================================================

    def create_quick_scan_page(self):

        page = self.create_page("Quick Scan")

        self.page_header(
            page,
            "⚡ Quick Scan",
            "Scan common user folders for suspicious files."
        )

        info = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=10
        )

        info.pack(
            fill="x",
            padx=20,
            pady=5
        )
        self.quarantine_integrity_status = ctk.CTkLabel(
            info,
            text="Integrity status is verified asynchronously.",
            font=(self.FONT, 11),
            text_color=self.MUTED
        )
        self.quarantine_integrity_status.pack(
            anchor="w",
            padx=20,
            pady=(0, 12)
        )

        existing_targets = [
            label
            for label, folder in (
                ("Desktop", Path.home() / "Desktop"),
                ("Downloads", Path.home() / "Downloads"),
                ("Documents", Path.home() / "Documents"),
            )
            if folder.exists()
        ]
        target_text = " · ".join(existing_targets) or "No default folders available"

        ctk.CTkLabel(
            info,
            text=f"SCAN SCOPE  ·  {target_text}",
            font=("Segoe UI", 14),
            text_color=self.TEXT
        ).pack(
            padx=20,
            pady=(14, 4)
        )

        ctk.CTkLabel(
            info,
            text=f"User profile: {Path.home()}",
            font=("Segoe UI", 11),
            text_color=self.MUTED
        ).pack(
            padx=20,
            pady=(0, 14)
        )

        self.create_scan_area(
            page,
            "Quick Scan",
            self.start_quick_scan
        )

    def create_full_scan_page(self):

        page = self.create_page("Full Scan")

        self.page_header(
            page,
            "💻 Full System Scan",
            "Scan available Windows drives for suspicious files."
        )

        warning = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=10
        )

        warning.pack(
            fill="x",
            padx=20,
            pady=5
        )

        if os.name == "nt":
            available_drives = [
                f"{drive}:\\"
                for drive in string.ascii_uppercase
                if Path(f"{drive}:\\").exists()
            ]
        else:
            available_drives = ["/"]
        drive_text = ", ".join(available_drives) or "No available drives detected"

        ctk.CTkLabel(
            warning,
            text=(
                f"SCAN SCOPE  ·  {drive_text}\n"
                "A full scan may take longer on large drives."
            ),
            font=("Segoe UI", 13),
            text_color=self.YELLOW
        ).pack(
            padx=20,
            pady=18
        )

        self.create_scan_area(
            page,
            "Full Scan",
            self.start_full_scan
        )
        ctk.CTkButton(
            page,
            text="Scan Removable Drives",
            width=220,
            height=40,
            command=self.start_removable_drive_scan
        ).pack(pady=(0, 12))

    def create_custom_scan_page(self):

        page = self.create_page("Custom Scan")

        self.page_header(
            page,
            "📂 Custom Scan",
            "Select a folder and scan it for suspicious files."
        )

        folder = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=10
        )

        folder.pack(
            fill="x",
            padx=20,
            pady=5
        )

        self.custom_folder_label = ctk.CTkLabel(
            folder,
            text="No folder selected",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        )

        self.custom_folder_label.pack(
            side="left",
            padx=20,
            pady=18
        )

        ctk.CTkButton(
            folder,
            text="📂 Select Folder",
            width=170,
            height=40,
            command=self.select_custom_folder
        ).pack(
            side="right",
            padx=20,
            pady=10
        )
        ctk.CTkButton(
            folder,
            text="Scan Individual File",
            width=180,
            height=40,
            command=self.start_individual_file_scan
        ).pack(
            side="right",
            padx=(0, 10),
            pady=10
        )

        self.create_scan_area(
            page,
            "Custom Scan",
            self.start_custom_scan
        )

    # ==========================================================
    # SCAN AREA
    # ==========================================================

    def create_scan_area(
        self,
        parent,
        name,
        command
    ):

        frame = ctk.CTkFrame(
            parent,
            fg_color=self.CARD,
            corner_radius=12
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        # ------------------------------------------------------
        # START BUTTON
        # ------------------------------------------------------

        scan_controls = ctk.CTkFrame(frame, fg_color="transparent")
        scan_controls.pack(pady=(18, 8))

        button = ctk.CTkButton(
            scan_controls,
            text="▶  Start Scan",
            width=240,
            height=48,
            font=("Segoe UI", 15, "bold"),
            command=command
        )
        button.pack(side="left", padx=5)

        cancel_button = ctk.CTkButton(
            scan_controls,
            text="Cancel Scan",
            width=140,
            height=48,
            fg_color=self.RED,
            hover_color=self.RED_HOVER,
            state="disabled",
            command=self.cancel_scan
        )
        cancel_button.pack(side="left", padx=5)

        # ------------------------------------------------------
        # PROGRESS
        # ------------------------------------------------------

        progress = ctk.CTkProgressBar(
            frame,
            height=13
        )

        progress.pack(
            fill="x",
            padx=30,
            pady=7
        )

        progress.set(0)

        status = ctk.CTkLabel(
            frame,
            text="Ready",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        )

        status.pack(
            pady=5
        )
        current_file = ctk.CTkLabel(
            frame,
            text="Current file: —",
            font=("Segoe UI", 11),
            text_color=self.MUTED,
            wraplength=1100,
            justify="left"
        )
        current_file.pack(fill="x", padx=30, pady=(0, 5))

        # ------------------------------------------------------
        # STATS
        # ------------------------------------------------------

        stats = ctk.CTkFrame(
            frame,
            fg_color="transparent"
        )

        stats.pack(
            fill="x",
            padx=20,
            pady=7
        )

        for i in range(4):

            stats.grid_columnconfigure(
                i,
                weight=1
            )

        files_label = self.stat_box(
            stats,
            0,
            "Files Scanned",
            "0"
        )

        threat_label = self.stat_box(
            stats,
            1,
            "Threats Found",
            "0"
        )

        percent_label = self.stat_box(
            stats,
            2,
            "Progress",
            "0%"
        )

        time_label = self.stat_box(
            stats,
            3,
            "Elapsed",
            "00:00"
        )

        # ------------------------------------------------------
        # RESULT SECTION
        # ------------------------------------------------------

        result_frame = ctk.CTkFrame(
            frame,
            fg_color=self.CARD2,
            corner_radius=10
        )

        result_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        ctk.CTkLabel(
            result_frame,
            text="🔍  Detected Threats",
            font=("Segoe UI", 18, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=15,
            pady=(12, 5)
        )

        # ------------------------------------------------------
        # ACTION BUTTONS
        # ------------------------------------------------------

        actions = ctk.CTkFrame(
            result_frame,
            fg_color="transparent"
        )

        actions.pack(
            fill="x",
            padx=10,
            pady=5
        )

        quarantine_button = ctk.CTkButton(
            actions,
            text="🔒  Quarantine Selected",
            width=220,
            height=40,
            font=("Segoe UI", 13, "bold"),
            fg_color=self.RED,
            hover_color=self.RED_HOVER,
            state="disabled",
            command=lambda n=name:
                self.quarantine_selected_file(n)
        )

        quarantine_button.pack(
            side="left",
            padx=5
        )

        report_button = ctk.CTkButton(
            actions,
            text="📄  Generate Report",
            width=190,
            height=40,
            command=self.generate_scan_report
        )

        report_button.pack(
            side="left",
            padx=5
        )

        # ------------------------------------------------------
        # TABLE
        # ------------------------------------------------------

        table_frame = ctk.CTkFrame(
            result_frame,
            fg_color="transparent"
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        columns = (
            "File Name",
            "Extension",
            "Severity",
            "Location"
        )

        table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=7
        )

        for col in columns:

            table.heading(
                col,
                text=col
            )

        for risk, color in {
            "Critical": "#FF6B6B",
            "High": "#FF8A65",
            "Medium": "#FFCA66",
            "Low": "#8DBBFF",
            "Informational": "#9AA4B2",
        }.items():
            table.tag_configure(risk, foreground=color)

        table.column(
            "File Name",
            width=180,
            minwidth=120
        )

        table.column(
            "Extension",
            width=90,
            minwidth=70
        )

        table.column(
            "Severity",
            width=90,
            minwidth=70
        )

        table.column(
            "Location",
            width=650,
            minwidth=300
        )

        table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=table.yview
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        table.configure(
            yscrollcommand=scrollbar.set
        )
        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=table.xview
        )
        horizontal_scrollbar.pack(
            side="bottom",
            fill="x"
        )
        table.configure(xscrollcommand=horizontal_scrollbar.set)

        table.bind(
            "<<TreeviewSelect>>",
            lambda event, n=name:
                self.on_threat_selected(n)
        )

        # ------------------------------------------------------
        # DETAILS
        # ------------------------------------------------------

        ctk.CTkLabel(
            result_frame,
            text="Detection Details",
            font=("Segoe UI", 14, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=15,
            pady=(5, 2)
        )

        results_box = ctk.CTkTextbox(
            result_frame,
            height=150,
            font=("Consolas", 11)
        )

        results_box.pack(
            fill="x",
            padx=10,
            pady=(2, 12)
        )

        results_box.insert(
            "1.0",
            "No scan performed."
        )

        results_box.configure(
            state="disabled"
        )

        # ------------------------------------------------------
        # SAVE REFERENCES
        # ------------------------------------------------------

        self.scan_widgets[name] = {

            "button": button,

            "cancel_button": cancel_button,

            "progress": progress,

            "status": status,

            "current_file": current_file,

            "files": files_label,

            "threats": threat_label,

            "percent": percent_label,

            "time": time_label,

            "table": table,

            "results": results_box,

            "quarantine_button":
                quarantine_button,

            "report_button":
                report_button,

            "generation": 0,

            "threats_data": [],
        }

    def stat_box(
        self,
        parent,
        column,
        title,
        value
    ):

        box = ctk.CTkFrame(
            parent,
            fg_color=self.CARD2,
            corner_radius=8
        )

        box.grid(
            row=0,
            column=column,
            sticky="ew",
            padx=4
        )

        ctk.CTkLabel(
            box,
            text=title,
            font=("Segoe UI", 11),
            text_color=self.MUTED
        ).pack(
            pady=(8, 2)
        )

        label = ctk.CTkLabel(
            box,
            text=value,
            font=("Segoe UI", 17, "bold"),
            text_color=self.TEXT
        )

        label.pack(
            pady=(0, 8)
        )

        return label

    # ==========================================================
    # CUSTOM FOLDER
    # ==========================================================

    def select_custom_folder(self):

        folder = filedialog.askdirectory(
            title="Select Folder to Scan"
        )

        if folder:

            self.custom_folder = folder

            self.custom_folder_label.configure(
                text=folder,
                text_color=self.TEXT
            )

    # ==========================================================
    # SCAN START
    # ==========================================================

    def prepare_scan(self, name, operation_name=None):

        if self.scan_running:

            messagebox.showinfo(
                "Scan Running",
                "A scan is already running."
            )

            return False

        self.active_scan = name

        self.show_page(name)

        w = self.scan_widgets[name]

        w["generation"] += 1
        w["threats_data"] = []

        w["progress"].stop()
        w["progress"].set(0)
        w["progress"].start()
        w["indeterminate"] = True

        w["files"].configure(
            text="0"
        )

        w["threats"].configure(
            text="—"
        )

        w["percent"].configure(
            text="0%"
        )

        w["time"].configure(
            text="00:00"
        )

        w["status"].configure(
            text="Discovering files...",
            text_color=self.YELLOW
        )

        # Clear table
        for item in w["table"].get_children():

            w["table"].delete(item)

        # Disable quarantine
        w["quarantine_button"].configure(
            state="disabled"
        )

        # Clear details
        w["results"].configure(
            state="normal"
        )

        w["results"].delete(
            "1.0",
            "end"
        )

        w["results"].insert(
            "1.0",
            "Scanning..."
        )

        w["results"].configure(
            state="disabled"
        )

        # Disable start button
        w["button"].configure(
            state="disabled",
            text="⏳  Scanning..."
        )

        self.scan_running = True
        self.scanner.reset_cancel()
        self._scan_operation_name = operation_name or name
        w["cancel_button"].configure(state="normal")
        w["current_file"].configure(text="Current file: —")

        self.scan_start = time.time()
        self._scan_started_at = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
        with self._progress_lock:
            self._last_progress_emit = 0.0
        is_scheduled = self._scheduled_launch
        self._scheduled_launch = False
        self._record_event(
            "scan_started",
            f"{'Scheduled' if is_scheduled else 'Manual'} "
            f"{self._scan_operation_name.lower()} started.",
            {
                "scan_type": self._scan_operation_name,
                "scheduled": is_scheduled
            }
        )

        self.status_dot.configure(
            text_color=self.YELLOW
        )

        self.sidebar_status.configure(
            text="Scan Running"
        )
        self.header_status.configure(
            text="●  Scan running",
            text_color=self.YELLOW
        )

        return True

    def cancel_scan(self):
        if not self.scan_running or not self.active_scan:
            return
        self.scanner.cancel()
        widgets = self.scan_widgets.get(self.active_scan)
        if widgets:
            widgets["cancel_button"].configure(state="disabled")
            widgets["status"].configure(
                text="Cancellation requested; finishing current file...",
                text_color=self.YELLOW
            )

    def _launch_scan(self, page_name, operation_name, scan_function):
        if not self.prepare_scan(page_name, operation_name):
            return False
        self._scan_thread = threading.Thread(
            target=self.run_scan_worker,
            args=(scan_function, page_name, operation_name),
            name=f"ITSecurityScanner-{operation_name.replace(' ', '')}",
            daemon=True
        )
        self._scan_thread.start()
        return True

    def start_quick_scan(self):
        self._launch_scan(
            "File Scanner" if "File Scanner" in self.scan_widgets else "Quick Scan",
            "Quick Scan",
            lambda callback: self.scanner.quick_scan(callback)
        )

    def quick_scan_worker(self):

        self.run_scan_worker(
            lambda callback:
                self.scanner.quick_scan(callback),
            "Quick Scan"
        )

    def start_full_scan(self):
        self._launch_scan(
            "File Scanner" if "File Scanner" in self.scan_widgets else "Full Scan",
            "Full Scan",
            lambda callback: self.scanner.full_scan(callback)
        )

    def start_removable_drive_scan(self):
        self._launch_scan(
            "File Scanner" if "File Scanner" in self.scan_widgets else "Full Scan",
            "Removable Drive Scan",
            lambda callback: self.scanner.removable_drive_scan(callback)
        )

    def start_individual_file_scan(self):
        filepath = filedialog.askopenfilename(
            title="Select a file to scan",
            filetypes=[("All files", "*.*")]
        )
        if not filepath:
            return
        self._start_individual_file_scan(filepath)

    def _start_individual_file_scan(self, filepath):
        self._launch_scan(
            "File Scanner" if "File Scanner" in self.scan_widgets else "Custom Scan",
            "Individual File Scan",
            lambda callback: self.scanner.individual_file_scan(
                filepath,
                callback
            )
        )

    def full_scan_worker(self):

        self.run_scan_worker(
            lambda callback:
                self.scanner.full_scan(callback),
            "Full Scan"
        )

    def start_custom_scan(self):

        if not self.custom_folder:

            messagebox.showinfo(
                "Select Folder",
                "Please select a folder first."
            )

            return

        folder = self.custom_folder
        self._launch_scan(
            "File Scanner" if "File Scanner" in self.scan_widgets else "Custom Scan",
            "Custom Folder Scan",
            lambda callback: self.scanner.custom_scan(
                folder,
                callback
            )
        )

    def custom_scan_worker(
        self,
        folder
    ):

        self.run_scan_worker(
            lambda callback:
                self.scanner.custom_scan(
                    folder,
                    callback
                ),
            "Custom Scan"
        )

    # ==========================================================
    # SCAN WORKER
    # ==========================================================

    def run_scan_worker(
        self,
        scan_function,
        page_name,
        operation_name=None
    ):

        try:

            def callback(
                scanned,
                total,
                current_file
            ):

                self.update_scan_progress(
                    page_name,
                    scanned,
                    total,
                    current_file
                )

            result = scan_function(callback)
            result["scan_type"] = operation_name or page_name

            self._queue_ui_event(
                "scan_finished",
                result,
                page_name
            )

        except Exception as error:

            self._queue_ui_event(
                "scan_error",
                error,
                page_name
            )

    # ==========================================================
    # PROGRESS
    # ==========================================================

    def update_scan_progress(
        self,
        page_name,
        scanned,
        total,
        current_file
    ):

        now = time.monotonic()
        with self._progress_lock:
            if (
                scanned != total
                and now - self._last_progress_emit < 0.15
            ):
                return
            self._last_progress_emit = now

        self._queue_ui_event(
            "scan_progress",
            page_name,
            scanned,
            total,
            str(current_file)
        )

    def _render_scan_progress(
        self,
        page_name,
        scanned,
        total,
        current_file
    ):
        w = self.scan_widgets.get(page_name)
        if not w:
            return

        elapsed = max(0, int(time.time() - self.scan_start))
        minutes, seconds = divmod(elapsed, 60)
        filename = os.path.basename(current_file) if current_file else "—"

        if total > 0:
            if w.get("indeterminate"):
                w["progress"].stop()
                w["indeterminate"] = False
            progress_value = min(scanned / total, 1)
            w["progress"].set(progress_value)
            w["files"].configure(text=f"{scanned:,} / {total:,}")
            w["percent"].configure(
                text=f"{int(progress_value * 100)}%"
            )
        else:
            if not w.get("indeterminate"):
                w["progress"].start()
                w["indeterminate"] = True
            w["files"].configure(text=f"{scanned:,} files")
            w["percent"].configure(text="…")
        w["time"].configure(text=f"{minutes:02}:{seconds:02}")
        w["current_file"].configure(
            text=f"Current file: {current_file or '—'}"
        )
        w["status"].configure(
            text=(
                f"Scanning {scanned:,} files · {filename}"
                if total <= 0
                else f"Scanning {scanned:,} of {total:,} · {filename}"
            ),
            text_color=self.YELLOW
        )

    # ==========================================================
    # SCAN FINISHED
    # ==========================================================

    def scan_finished(
        self,
        result,
        page_name
    ):

        self.scan_running = False
        self._scan_thread = None

        self.active_scan = page_name
        self.last_scan_page = page_name

        self.last_result = result
        operation_name = result.get(
            "scan_type",
            self._scan_operation_name or page_name
        )
        result["scan_type"] = operation_name
        result["started_at"] = self._scan_started_at
        cancelled = bool(result.get("cancelled"))

        w = self.scan_widgets[
            page_name
        ]

        threats_list = result.get(
            "suspicious",
            []
        )
        w["threats_data"] = threats_list

        threats = len(
            threats_list
        )
        total_findings = result.get("finding_count", threats)
        findings_truncated = result.get("findings_truncated", False)
        informational_count = sum(
            item.get("classification") == "Informational finding"
            for item in threats_list
        )
        confirmed_count = sum(
            item.get("classification") == "Confirmed malware signature"
            for item in threats_list
        )
        suspicious_count = sum(
            item.get("classification") in {
                "Strongly suspicious",
                "Potentially suspicious"
            }
            for item in threats_list
        )
        error_count = result.get("error_count", 0)
        severity_counts = self._severity_counts(threats_list)
        scanned = result.get(
            "scanned",
            result.get("files_scanned", 0)
        )
        total = result.get("total", scanned)
        elapsed = max(0, int(time.time() - self.scan_start))
        result["duration_seconds"] = elapsed
        minutes, seconds = divmod(elapsed, 60)

        # ------------------------------------------------------
        # UPDATE STATS
        # ------------------------------------------------------

        w["progress"].stop()
        w["indeterminate"] = False
        if not cancelled:
            w["progress"].set(1)

        w["files"].configure(
            text=f"{scanned:,} files" if cancelled else f"{scanned:,} / {total:,}"
        )

        w["percent"].configure(
            text="Cancelled" if cancelled else "100%"
        )
        w["cancel_button"].configure(state="disabled")
        w["current_file"].configure(text="Current file: —")

        w["time"].configure(
            text=f"{minutes:02}:{seconds:02}"
        )

        w["threats"].configure(
            text=str(total_findings)
        )

        w["button"].configure(
            state="normal",
            text="▶  Start Scan"
        )

        # ------------------------------------------------------
        # UPDATE STATUS
        # ------------------------------------------------------

        if cancelled:
            w["status"].configure(
                text=f"Scan cancelled · {scanned:,} file(s) checked",
                text_color=self.YELLOW
            )
        elif error_count:
            w["status"].configure(
                text=(
                    f"Scan incomplete · {scanned:,} files checked · "
                    f"{total_findings:,} finding(s) · {error_count:,} error(s)"
                ),
                text_color=self.YELLOW
            )
        elif findings_truncated:
            w["status"].configure(
                text=(
                    f"Results incomplete · {scanned:,} files checked · "
                    "finding details were truncated"
                ),
                text_color=self.YELLOW
            )
        elif not suspicious_count and informational_count:
            w["status"].configure(
                text=(
                    f"Scan complete · {scanned:,} files checked · "
                    f"no suspicious detections · "
                    f"{informational_count:,} informational finding(s)"
                ),
                text_color=self.MUTED
            )
        elif total_findings == 0:

            w["status"].configure(
                text=f"Scan complete · {scanned:,} files checked · no detections reported",
                text_color=self.GREEN
            )

        else:

            w["status"].configure(
                text=(
                    f"Scan complete · {scanned:,} files checked · "
                    f"{total_findings:,} finding(s)"
                    + (
                        f" · {error_count:,} error(s)"
                        if error_count
                        else ""
                    )
                ),
                text_color=self.RED
            )

        # ------------------------------------------------------
        # TABLE
        # ------------------------------------------------------

        for item in w["table"].get_children():

            w["table"].delete(item)

        self._append_threat_rows(
            page_name,
            threats_list,
            0,
            w["generation"]
        )

        # ------------------------------------------------------
        # DETAILS
        # ------------------------------------------------------

        w["results"].configure(
            state="normal"
        )

        w["results"].delete(
            "1.0",
            "end"
        )

        if cancelled:
            w["results"].insert(
                "end",
                (
                    "Scan cancelled. Results include only the files "
                    "checked before cancellation.\n\n"
                    f"Files checked: {scanned:,}\n"
                    f"Findings: {total_findings:,}\n"
                    f"Elapsed: {minutes:02}:{seconds:02}"
                )
            )
        elif threats == 0:

            w["results"].insert(
                "end",
                (
                    "No threats detected.\n\n"
                    if not error_count
                    else
                    "Scan incomplete. No threats were detected in scanned files, "
                    f"but {error_count:,} error(s) prevented complete coverage.\n\n"
                )
                    + f"Files checked: {scanned:,}\n"
                    + (
                        f"Findings: {total_findings:,}\n"
                        if total_findings
                        else ""
                    )
                    + f"Elapsed: {minutes:02}:{seconds:02}"
            )

        else:
            w["results"].insert(
                "end",
                f"{total_findings:,} finding(s) · "
                f"{severity_counts['Critical']} Critical · "
                f"{severity_counts['High']} High · "
                f"{severity_counts['Medium']} Medium · "
                f"{severity_counts['Low']} Low"
                + (
                    f" · {error_count:,} scan error(s)"
                    if error_count
                    else ""
                )
                + (
                    f"\n\nDetails retained for the first {threats:,} of "
                    f"{total_findings:,} findings."
                    if findings_truncated
                    else "\n\nSelect a finding to inspect its details."
                )
            )

        if error_count and result.get("errors"):
            error_details = "\n".join(
                str(error) for error in result["errors"][:5]
            )
            w["results"].insert(
                "end",
                f"\n\nFirst scan errors:\n{error_details}"
            )

        w["results"].configure(
            state="disabled"
        )

        # ------------------------------------------------------
        # DASHBOARD
        # ------------------------------------------------------

        score = self.calculate_security_score(threats_list)

        self.score_card.configure(
            text=(
                "Unavailable"
                if error_count or cancelled or findings_truncated
                else f"{score}/100"
            ),
            text_color=(
                self.MUTED
                if error_count or cancelled or findings_truncated
                else self._score_color(score)
            )
        )

        self.threat_card.configure(
            text=str(confirmed_count),
            text_color=self.RED if confirmed_count else self.GREEN
        )
        self.suspicious_card.configure(text=str(suspicious_count))

        self.last_scan_card.configure(
            text=time.strftime("%H:%M")
        )

        self.update_security_alert(threats_list)
        if error_count:
            self.dashboard_status_title.configure(
                text="SCAN INCOMPLETE",
                text_color=self.YELLOW
            )
            self.dashboard_status_message.configure(
                text=(
                    f"{error_count:,} scan error(s) occurred. "
                    "Threat coverage and security score are incomplete."
                )
            )
        self.refresh_reports()
        self._record_event(
            "scan_cancelled" if cancelled else "scan_completed",
            (
                f"{operation_name} cancelled after {scanned:,} files."
                if cancelled
                else f"{operation_name} completed: {scanned:,} files, {total_findings:,} finding(s)."
            ),
            {
                "scan_type": operation_name,
                "files_scanned": scanned,
                "findings": total_findings,
                "errors": result.get("error_count", 0),
                "cancelled": cancelled,
                "started_at": self._scan_started_at,
                "completed_at": datetime.now().astimezone().isoformat(
                    timespec="seconds"
                ),
            }
        )
        self.refresh_threat_detections()
        self.update_dashboard_metrics()
        if cancelled:
            self.header_status.configure(
                text="●  Scan cancelled",
                text_color=self.YELLOW
            )
        elif self.scan_result_state(result) == "Incomplete":
            self.header_status.configure(
                text="●  Scan incomplete",
                text_color=self.YELLOW
            )
        elif confirmed_count:
            self.header_status.configure(
                text="●  Threats detected",
                text_color=self.RED
            )
        else:
            self.header_status.configure(
                text="●  Scan complete",
                text_color=self.GREEN
            )

        # ------------------------------------------------------
        # SIDEBAR
        # ------------------------------------------------------

        if cancelled:
            self.protection_card.configure(text="Scan Cancelled")
            self.dashboard_recent_label.configure(
                text=f"⚠️ {operation_name} was cancelled after {scanned:,} files."
            )
            self.dashboard_status_title.configure(
                text="SCAN CANCELLED",
                text_color=self.YELLOW
            )
            self.dashboard_status_message.configure(
                text="Results are partial and do not establish that the scanned area is clean."
            )
            self.status_dot.configure(text_color=self.YELLOW)
            self.sidebar_status.configure(text="Scan Cancelled")
        elif total_findings == 0 and not error_count:

            self.protection_card.configure(
                text="Protected"
            )

            self.dashboard_recent_label.configure(
                text=f"✅ {page_name} completed — "
                     "no threats detected."
            )

            self.status_dot.configure(
                text_color=self.GREEN
            )

            self.sidebar_status.configure(
                text="Scanner Ready"
            )

        elif total_findings == 0:
            self.protection_card.configure(text="Scan Incomplete")
            self.dashboard_recent_label.configure(
                text=(
                    f"⚠️ {page_name} checked {scanned:,} files with "
                    f"{error_count:,} error(s); coverage is incomplete."
                )
            )
            self.status_dot.configure(text_color=self.YELLOW)
            self.sidebar_status.configure(text="Scan Incomplete")

        else:

            self.protection_card.configure(
                text="⚠️ Threats Detected"
            )

            self.dashboard_recent_label.configure(
                text=f"⚠️ {page_name} found "
                     f"{total_findings} finding(s)."
            )

            self.status_dot.configure(
                text_color=self.RED
            )

            self.sidebar_status.configure(
                text="Threat Detected"
            )

    def _append_threat_rows(
        self,
        page_name,
        threats,
        start,
        generation,
        batch_size=100
    ):
        widgets = self.scan_widgets.get(page_name)
        if not widgets or widgets["generation"] != generation:
            return

        table = widgets["table"]
        end = min(start + batch_size, len(threats))

        for threat in threats[start:end]:
            risk = threat.get("risk", "Unknown")
            table.insert(
                "",
                "end",
                values=(
                    threat.get("name", "Unknown"),
                    threat.get("extension", ""),
                    risk,
                    threat.get("path", ""),
                ),
                tags=(risk,)
            )

        if end < len(threats):
            self.after(
                1,
                lambda: self._append_threat_rows(
                    page_name,
                    threats,
                    end,
                    generation,
                    batch_size
                )
            )

    def _show_threat_details(self, widgets, threat):
        widgets["results"].configure(state="normal")
        widgets["results"].delete("1.0", "end")
        widgets["results"].insert(
            "end",
            f"{threat.get('risk', 'Unknown')} · "
            f"Score {threat.get('risk_score', 0)}/100\n"
            f"Classification: {threat.get('classification', 'N/A')} · "
            f"Confidence: {threat.get('confidence', 'N/A')}\n"
            f"File: {threat.get('name', 'Unknown')}\n"
            f"Type: {threat.get('detection_type', 'N/A')}\n"
            f"Category: {threat.get('detection_category', 'N/A')}\n"
            f"Path: {threat.get('path', '')}\n"
            f"SHA-256: {threat.get('hash', 'N/A')}\n"
            f"Explanation: {threat.get('detection_explanation', 'N/A')}\n"
            f"Recommended action: {threat.get('recommended_action', 'Review manually.')}"
        )
        widgets["results"].configure(state="disabled")

    # ==========================================================
    # SCAN ERROR
    # ==========================================================

    def scan_error(
        self,
        error,
        page_name
    ):

        self.scan_running = False
        self._scan_thread = None

        w = self.scan_widgets.get(
            page_name
        )

        if w:
            w["progress"].stop()
            w["indeterminate"] = False
            w["cancel_button"].configure(state="disabled")
            w["current_file"].configure(text="Current file: —")

            w["button"].configure(
                state="normal",
                text="▶  Start Scan"
            )

            w["status"].configure(
                text=f"Scan failed: {error}",
                text_color=self.RED
            )

        self.status_dot.configure(
            text_color=self.GREEN
        )

        self.sidebar_status.configure(
            text="Scan failed"
        )
        self.header_status.configure(
            text="●  Scan failed",
            text_color=self.RED
        )

        self._record_event(
            "scan_failed",
            f"{self._scan_operation_name or page_name} failed: {error}",
            {
                "scan_type": self._scan_operation_name or page_name,
                "error": str(error),
            }
        )
        self.dashboard_status_title.configure(
            text="SCAN FAILED",
            text_color=self.RED
        )
        self.dashboard_status_message.configure(
            text=(
                f"{self._scan_operation_name or page_name} failed: {error}"
            )
        )

    # ==========================================================
    # THREAT SELECTION
    # ==========================================================

    def on_threat_selected(
        self,
        page_name
    ):

        w = self.scan_widgets.get(
            page_name
        )

        if not w:
            return

        selected = w["table"].selection()

        if selected:

            w["quarantine_button"].configure(
                state="normal"
            )
            values = w["table"].item(
                selected[0]
            ).get("values", [])
            if len(values) >= 4:
                filepath = values[3]
                threat = next(
                    (
                        item
                        for item in w["threats_data"]
                        if item.get("path") == filepath
                    ),
                    None
                )
                if threat:
                    self._show_threat_details(w, threat)

        else:

            w["quarantine_button"].configure(
                state="disabled"
            )

    # ==========================================================
    # SECURITY SCORE
    # ==========================================================

    @staticmethod
    def _severity_counts(threats):
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for threat in threats:
            risk = threat.get("risk", "Low")
            if risk in counts:
                counts[risk] += 1

        return counts

    def calculate_security_score(self, threats):
        if isinstance(threats, int):
            severity = (
                "Critical" if threats > 10
                else "High" if threats > 5
                else "Medium" if threats > 2
                else "Low"
            )
            threats = [{"risk": severity}] * max(threats, 0)

        penalties = {
            "Critical": 40,
            "High": 25,
            "Medium": 12,
            "Low": 5,
            "Informational": 0,
        }
        penalty = sum(
            penalties.get(threat.get("risk", "Low"), 0)
            for threat in threats
        )
        return max(0, 100 - penalty)

    def _score_color(self, score):
        if score >= 80:
            return self.GREEN
        if score >= 50:
            return self.YELLOW
        return self.RED

    def update_security_alert(
        self,
        threats
    ):

        if isinstance(threats, int):
            threat_count = threats
            counts = None
        else:
            threat_count = len(threats)
            counts = self._severity_counts(threats)

        if threat_count == 0:

            self.dashboard_status_title.configure(
                text="🟢  NO DETECTIONS REPORTED",
                text_color=self.GREEN
            )

            self.dashboard_status_message.configure(
                text="No detections were reported by the latest scan."
            )

        else:
            if counts is not None and not any(
                value
                for risk, value in counts.items()
                if risk != "Informational"
            ):
                self.dashboard_status_title.configure(
                    text="ℹ️  INFORMATIONAL FINDINGS",
                    text_color=self.MUTED
                )
                self.dashboard_status_message.configure(
                    text=(
                        f"{counts['Informational']} low-confidence "
                        "informational finding(s); no suspicious detections."
                    )
                )
                return

            self.dashboard_status_title.configure(
                text="🚨  SECURITY ALERT",
                text_color=self.RED
            )

            if counts is None:
                detail = f"{threat_count} finding(s) detected."
            else:
                detail = (
                    f"{threat_count} finding(s): "
                    f"{counts['Critical']} Critical · "
                    f"{counts['High']} High · "
                    f"{counts['Medium']} Medium · "
                    f"{counts['Low']} Low · "
                    f"{counts['Informational']} Informational."
                )

            self.dashboard_status_message.configure(
                text=f"{detail} Select Threats to review."
            )

    # ==========================================================
    # QUARANTINE
    # ==========================================================

    def quarantine_selected_file(
        self,
        page_name=None
    ):

        page_name = (
            page_name
            or self.active_scan
        )

        if (
            not page_name
            or page_name not in self.scan_widgets
        ):

            messagebox.showinfo(
                "No Results",
                "Run a scan and select a suspicious file first."
            )

            return

        w = self.scan_widgets[
            page_name
        ]

        selected = w["table"].selection()

        if not selected:

            messagebox.showinfo(
                "No File Selected",
                "Select a suspicious file from the table first."
            )

            return

        values = w["table"].item(
            selected[0]
        ).get(
            "values",
            []
        )

        if len(values) < 4:

            messagebox.showerror(
                "Error",
                "Unable to identify the selected file."
            )

            return

        filename = str(
            values[0]
        )

        filepath = str(
            values[3]
        )

        # ------------------------------------------------------
        # CONFIRMATION
        # ------------------------------------------------------

        confirm = messagebox.askyesno(
            "Quarantine File",
            "Move this file to quarantine?\n\n"
            f"File: {filename}\n\n"
            f"Location:\n{filepath}\n\n"
            "The file will be moved to the isolated "
            "SecurityScanner_Quarantine folder."
        )

        if not confirm:
            return

        # ------------------------------------------------------
        # QUARANTINE
        # ------------------------------------------------------

        try:

            result = self.scanner.quarantine_file(
                filepath
            )

            if result.get("success"):

                # Remove from table
                w["table"].delete(
                    selected[0]
                )

                # Disable button
                w["quarantine_button"].configure(
                    state="disabled"
                )

                # Remove from last result
                if self.last_result:

                    self.last_result[
                        "suspicious"
                    ] = [

                        f for f in
                        self.last_result.get(
                            "suspicious",
                            []
                        )

                        if f.get(
                            "path"
                        ) != filepath
                    ]

                remaining_items = (
                    self.last_result.get(
                        "suspicious",
                        []
                    )
                    if self.last_result
                    else []
                )
                remaining = len(remaining_items)
                w["threats_data"] = remaining_items
                w["generation"] += 1
                w["threats"].configure(text=str(remaining))
                for item in w["table"].get_children():
                    w["table"].delete(item)
                self._append_threat_rows(
                    page_name,
                    remaining_items,
                    0,
                    w["generation"]
                )

                # Update dashboard
                self.threat_card.configure(
                    text=str(remaining),
                    text_color=self.RED if remaining else self.GREEN
                )

                remaining_score = self.calculate_security_score(
                    remaining_items
                )
                self.score_card.configure(
                    text=f"{remaining_score}/100",
                    text_color=self._score_color(remaining_score)
                )

                if remaining == 0:

                    self.protection_card.configure(
                        text="Protected"
                    )

                    self.update_security_alert(
                        remaining_items
                    )

                    self.status_dot.configure(
                        text_color=self.GREEN
                    )

                    self.sidebar_status.configure(
                        text="Scanner Ready"
                    )
                else:
                    self.update_security_alert(remaining_items)

                self.refresh_reports()

                # Update details
                w["results"].configure(
                    state="normal"
                )

                w["results"].insert(
                    "end",
                    "\n\n"
                    "🔒 FILE QUARANTINED SUCCESSFULLY\n"
                    f"{filename}\n"
                    "The file has been isolated."
                )

                w["results"].configure(
                    state="disabled"
                )

                messagebox.showinfo(
                    "Quarantine Successful",
                    result.get(
                        "message",
                        "File quarantined successfully."
                    )
                )

                self.refresh_quarantine()
                self._record_event(
                    "file_quarantined",
                    f"Quarantined {filename}.",
                    {
                        "original_path": filepath,
                        "quarantine_path": result.get("quarantine_path"),
                    }
                )
                self.refresh_threat_detections()
                self.update_dashboard_metrics()

            else:

                self._record_event(
                    "quarantine_failed",
                    result.get(
                        "message",
                        f"Unable to quarantine file: {filepath}.",
                    ),
                    {"path": filepath}
                )
                messagebox.showerror(
                    "Quarantine Failed",
                    result.get(
                        "message",
                        "Unable to quarantine the file."
                    )
                )
                self._record_event(
                    "quarantine_failed",
                    result.get("message", "Unable to quarantine file."),
                    {"path": filepath}
                )

        except Exception as error:

            self._record_event(
                "quarantine_failed",
                f"Unable to quarantine {filepath}: {error}",
                {"path": filepath}
            )
            messagebox.showerror(
                "Quarantine Error",
                str(error)
            )
            self._record_event(
                "quarantine_failed",
                f"Unable to quarantine {filepath}: {error}"
            )

    # ==========================================================
    # QUARANTINE PAGE
    # ==========================================================

    def create_quarantine_page(self):

        page = self.create_page(
            "Quarantine"
        )

        self.page_header(
            page,
            "🔒 Quarantine",
            "Manage files isolated by IT Security Scanner."
        )

        info = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=10
        )

        info.pack(
            fill="x",
            padx=20,
            pady=5
        )

        ctk.CTkLabel(
            info,
            text=(
                "🔒 Quarantined files are moved away from "
                "their original location and isolated."
            ),
            font=("Segoe UI", 13),
            text_color=self.MUTED
        ).pack(
            padx=20,
            pady=17
        )

        # ------------------------------------------------------
        # TABLE
        # ------------------------------------------------------

        table_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=10
        )

        table_card.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        columns = (
            "File Name",
            "Quarantine Location",
            "Original Path",
            "Quarantined",
            "SHA-256",
            "Integrity"
        )

        self.quarantine_table = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            height=12
        )

        self.quarantine_table.heading(
            "File Name",
            text="File Name"
        )

        self.quarantine_table.heading(
            "Quarantine Location",
            text="Quarantine Location"
        )
        for column in columns[2:]:
            self.quarantine_table.heading(column, text=column)

        self.quarantine_table.column(
            "File Name",
            width=300
        )

        self.quarantine_table.column(
            "Quarantine Location",
            width=340
        )
        self.quarantine_table.column("Original Path", width=340)
        self.quarantine_table.column("Quarantined", width=170)
        self.quarantine_table.column("SHA-256", width=350)
        self.quarantine_table.column("Integrity", width=130)

        self.quarantine_table.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=10
        )

        scrollbar = ttk.Scrollbar(
            table_card,
            orient="vertical",
            command=self.quarantine_table.yview
        )

        scrollbar.pack(
            side="right",
            fill="y",
            padx=(0, 10),
            pady=10
        )

        self.quarantine_table.configure(
            yscrollcommand=scrollbar.set
        )
        horizontal_scrollbar = ttk.Scrollbar(
            table_card,
            orient="horizontal",
            command=self.quarantine_table.xview
        )
        horizontal_scrollbar.pack(
            side="bottom",
            fill="x",
            padx=10,
            pady=(0, 10)
        )
        self.quarantine_table.configure(
            xscrollcommand=horizontal_scrollbar.set
        )

        # ------------------------------------------------------
        # BUTTONS
        # ------------------------------------------------------

        buttons = ctk.CTkFrame(
            page,
            fg_color="transparent"
        )

        buttons.pack(
            pady=10
        )

        ctk.CTkButton(
            buttons,
            text="🔄  Refresh",
            width=160,
            height=42,
            command=self.refresh_quarantine
        ).pack(
            side="left",
            padx=5
        )

        ctk.CTkButton(
            buttons,
            text="↩  Restore Selected",
            width=180,
            height=42,
            command=self.restore_quarantined_file
        ).pack(
            side="left",
            padx=5
        )

        ctk.CTkButton(
            buttons,
            text="🗑️  Delete Permanently",
            width=200,
            height=42,
            fg_color=self.RED,
            hover_color=self.RED_HOVER,
            command=self.delete_quarantined_file
        ).pack(
            side="left",
            padx=5
        )

    def refresh_quarantine(self):

        if not hasattr(
            self,
            "quarantine_table"
        ):
            return

        for item in self.quarantine_table.get_children():

            self.quarantine_table.delete(
                item
            )

        try:

            files = self.scanner.list_quarantine()
            self._quarantine_refresh_generation = (
                getattr(self, "_quarantine_refresh_generation", 0) + 1
            )
            generation = self._quarantine_refresh_generation
            integrity_checks = []

            for filepath in files:
                metadata = {}
                try:
                    metadata = self.scanner.get_quarantine_metadata(filepath)
                    display_name = metadata.get(
                        "original_name",
                        os.path.basename(filepath)
                    )
                    integrity = metadata.get("state", "unknown")
                    if integrity == "integrity_error":
                        display_name = f"INTEGRITY ERROR · {display_name}"
                except (OSError, ValueError) as error:
                    display_name = (
                        f"METADATA ERROR · {os.path.basename(filepath)}"
                    )
                    logging.error(
                        "Unable to read quarantine metadata for %s: %s",
                        filepath,
                        error
                    )

                item_id = self.quarantine_table.insert(
                    "",
                    "end",
                    values=(
                        display_name,
                        filepath,
                        metadata.get("original_path", "Unknown"),
                        metadata.get("quarantined_at", "Unknown"),
                        metadata.get("sha256", "Unavailable"),
                        (
                            "Checking..."
                            if metadata.get("sha256")
                            else "Unverified"
                        )
                    )
                )
                if metadata.get("sha256"):
                    integrity_checks.append(
                        (item_id, filepath, metadata["sha256"])
                    )

            if integrity_checks:
                threading.Thread(
                    target=self._quarantine_integrity_worker,
                    args=(generation, integrity_checks),
                    daemon=True,
                    name="QuarantineIntegrityCheck"
                ).start()
            else:
                self.quarantine_integrity_status.configure(
                    text="No quarantined files require integrity verification."
                )
            self.update_dashboard_metrics()

        except Exception as error:

            messagebox.showerror(
                "Quarantine Error",
                str(error)
            )

    def _quarantine_integrity_worker(self, generation, entries):
        for item_id, filepath, expected_hash in entries:
            try:
                actual_hash = self.scanner.calculate_hash(filepath)
                status = self.compare_quarantine_hashes(
                    expected_hash,
                    actual_hash
                )
                self._queue_ui_event(
                    "quarantine_integrity_result",
                    generation,
                    item_id,
                    status,
                    None
                )
            except (OSError, ValueError, TypeError) as error:
                self._queue_ui_event(
                    "quarantine_integrity_result",
                    generation,
                    item_id,
                    "Unverified",
                    str(error)
                )

    def _render_quarantine_integrity(
        self,
        generation,
        item_id,
        status,
        error
    ):
        if generation != getattr(self, "_quarantine_refresh_generation", None):
            return
        if not self.quarantine_table.exists(item_id):
            return
        values = list(self.quarantine_table.item(item_id).get("values", []))
        if len(values) >= 6:
            values[5] = status
            self.quarantine_table.item(item_id, values=values)
        current_statuses = [
            (
                str(self.quarantine_table.item(row).get("values", ["Unknown"] * 5)[0]),
                str(self.quarantine_table.item(row).get("values", ["", "", "", "", "", ""])[5])
            )
            for row in self.quarantine_table.get_children()
        ]
        incomplete = next(
            (
                (name, state)
                for name, state in current_statuses
                if state != "Verified"
            ),
            None
        )
        if incomplete:
            name, state = incomplete
            message = f"{name}: {state}"
            if name == values[0] and error:
                message += f" · {error}"
            self.quarantine_integrity_status.configure(
                text=message,
                text_color=(
                    self.RED
                    if state == "HASH MISMATCH"
                    else self.YELLOW
                )
            )
        else:
            self.quarantine_integrity_status.configure(
                text="Quarantined file hash matches its stored SHA-256.",
                text_color=self.GREEN
            )

    def restore_quarantined_file(self):
        selected = self.quarantine_table.selection()
        if not selected:
            messagebox.showinfo(
                "No File Selected",
                "Select a quarantined file first."
            )
            return

        values = self.quarantine_table.item(
            selected[0]
        ).get("values", [])
        if len(values) < 2:
            messagebox.showerror(
                "Restore Failed",
                "Unable to identify the selected quarantined file."
            )
            return

        quarantine_path = Path(str(values[1]))
        try:
            metadata = self.scanner.get_quarantine_metadata(quarantine_path)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "Restore Failed",
                f"Quarantine metadata is unavailable or invalid:\n{error}"
            )
            return
        destination = filedialog.asksaveasfilename(
            title="Choose a safe restore destination",
            initialfile=metadata.get("original_name", quarantine_path.name),
            defaultextension=Path(
                metadata.get("original_name", quarantine_path.name)
            ).suffix,
            filetypes=[("All files", "*.*")]
        )
        if not destination:
            return

        if not messagebox.askyesno(
            "Restore Quarantined File",
            "Restore this file to the selected location?\n\n"
            f"{destination}\n\n"
            "Only restore a file if you trust it."
        ):
            return

        result = self.scanner.restore_quarantined_file(
            quarantine_path,
            destination
        )
        if not result.get("success"):
            messagebox.showerror(
                "Restore Failed",
                result.get("message", "Unable to restore the file.")
            )
            self._record_event(
                "quarantine_restore_failed",
                result.get("message", "Unable to restore quarantined file.")
            )
            return

        self.refresh_quarantine()
        self._record_event(
            "quarantine_file_restored",
            f"Restored file to {result['restored_path']}.",
            result
        )
        messagebox.showinfo("File Restored", result["message"])

    def delete_quarantined_file(self):

        selected = self.quarantine_table.selection()

        if not selected:

            messagebox.showinfo(
                "No File Selected",
                "Select a quarantined file first."
            )

            return

        values = self.quarantine_table.item(
            selected[0]
        ).get(
            "values",
            []
        )

        if len(values) < 2:
            return

        filename = str(
            values[0]
        )

        filepath = str(
            values[1]
        )

        confirm = messagebox.askyesno(
            "Delete Permanently",
            "Permanently delete this quarantined file?\n\n"
            f"{filename}\n\n"
            "⚠️ This action cannot be undone."
        )

        if not confirm:
            return

        try:

            success = self.scanner.delete_quarantined_file(
                filepath
            )

            if success:

                self.refresh_quarantine()
                self._record_event(
                    "quarantine_file_deleted",
                    f"Permanently deleted quarantined file: {filename}.",
                    {"path": filepath}
                )

                messagebox.showinfo(
                    "File Deleted",
                    f"{filename}\n\n"
                    "The quarantined file was permanently deleted."
                )

            else:

                messagebox.showerror(
                    "Delete Failed",
                    "Unable to delete the quarantined file."
                )

        except Exception as error:

            messagebox.showerror(
                "Delete Error",
                str(error)
            )

    def create_threat_intelligence_page(self):
        page = self.create_page("Threat Intelligence")
        self.page_header(
            page,
            "🧠 Threat Intelligence",
            "Local SHA-256 signatures and trusted local YARA rules."
        )
        card = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=12)
        card.pack(fill="x", padx=20, pady=12)
        self.threat_intelligence_status_label = ctk.CTkLabel(
            card,
            text="Threat database status has not been checked.",
            anchor="w",
            justify="left",
            wraplength=950,
            text_color=self.MUTED
        )
        self.threat_intelligence_status_label.pack(
            fill="x",
            padx=24,
            pady=(20, 10)
        )
        self.yara_status_label = ctk.CTkLabel(
            card,
            text="YARA rule status has not been checked.",
            anchor="w",
            justify="left",
            wraplength=950,
            text_color=self.MUTED
        )
        self.yara_status_label.pack(fill="x", padx=24, pady=8)
        controls = ctk.CTkFrame(card, fg_color="transparent")
        controls.pack(anchor="w", padx=18, pady=(8, 20))
        ctk.CTkButton(
            controls,
            text="Refresh local status",
            command=self.refresh_threat_intelligence
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls,
            text="Import local signatures",
            command=self.import_signature_file
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls,
            text="Import digest-verified update",
            command=self.import_verified_signature_update
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls,
            text="Add local YARA rule",
            command=self.install_yara_rule
        ).pack(side="left", padx=5)

        explanation = ctk.CTkTextbox(page, height=170, wrap="word")
        explanation.pack(fill="x", padx=20, pady=10)
        explanation.insert(
            "1.0",
            "Detection levels\n"
            "• Confirmed malware signature: exact local SHA-256 signature match.\n"
            "• Strongly suspicious / potentially suspicious: static heuristic "
            "indicators; these are not proof of malware.\n"
            "• Informational: low-confidence static indicator.\n"
            "• No detection: no enabled engine reported an indicator. An empty "
            "or outdated database is not evidence that a system is clean.\n\n"
            "Database updates are local-only. A digest-verified update requires "
            "the expected SHA-256 digest from a trusted source separate from "
            "the file; a digest alone does not authenticate its publisher."
        )
        explanation.configure(state="disabled")
        self.refresh_threat_intelligence()

    def refresh_threat_intelligence(self):
        try:
            status = get_threat_intelligence_status()
            yara_status = self.scanner.yara_scanner.get_status()
            self._render_threat_intelligence_status(status, yara_status)
        except (OSError, ValueError, UnicodeError) as error:
            self._render_threat_intelligence_error(str(error))

    def _render_threat_intelligence_status(self, status, yara_status):
        if not hasattr(self, "threat_intelligence_status_label"):
            return
        integrity = status.get("integrity", "unknown")
        message = (
            f"SHA-256 signatures: {status.get('signature_count', 0):,} · "
            f"Database version: {status.get('version', 'unknown')} · "
            f"Integrity: {integrity}"
        )
        if status.get("updated_at"):
            message += f" · Updated: {status['updated_at']}"
        if status.get("warning"):
            message += f"\n{status['warning']}"
        self.threat_intelligence_status_label.configure(
            text=message,
            text_color=self.YELLOW if status.get("warning") else self.TEXT
        )
        rule_files = yara_status.get("rule_files", [])
        self.yara_status_label.configure(
            text=(
                f"YARA: {'available' if yara_status.get('available') else 'unavailable'} · "
                f"{len(rule_files)} rule file(s) · "
                f"Directory: {yara_status.get('directory', '')}"
                + (
                    f"\n{yara_status['error']}"
                    if yara_status.get("error")
                    else ""
                )
            ),
            text_color=self.TEXT if yara_status.get("available") else self.YELLOW
        )

    def _render_threat_intelligence_error(self, error):
        self.threat_intelligence_status_label.configure(
            text=f"Threat intelligence unavailable: {error}",
            text_color=self.RED
        )
        self._record_event(
            "threat_intelligence_error",
            f"Threat intelligence status could not be loaded: {error}"
        )

    def import_verified_signature_update(self):
        if self._signature_import_running or self.scan_running:
            messagebox.showinfo(
                "Scanner Busy",
                "Wait for the current scan or signature operation to finish."
            )
            return
        filename = filedialog.askopenfilename(
            title="Select a local SHA-256 signature update",
            filetypes=[("Signature text files", "*.txt"), ("All files", "*.*")]
        )
        if not filename:
            return
        digest_dialog = ctk.CTkInputDialog(
            text="Enter the expected SHA-256 from a trusted, separate source.",
            title="Verify Threat Update"
        )
        expected_digest = digest_dialog.get_input()
        if not expected_digest:
            return
        if not messagebox.askyesno(
            "Import Threat Update",
            "Verify this local update against the entered SHA-256 and merge "
            "its signatures? The bundle will not be executed or uploaded."
        ):
            return
        self._signature_import_running = True
        threading.Thread(
            target=self._verified_update_worker,
            args=(filename, expected_digest),
            daemon=True,
            name="ThreatSignatureUpdate"
        ).start()

    def _verified_update_worker(self, filename, expected_digest):
        try:
            result = import_verified_update(filename, expected_digest)
            self._queue_ui_event(
                "signature_update_result",
                result
            )
        except (OSError, ValueError) as error:
            self._queue_ui_event(
                "signature_update_error",
                str(error)
            )

    def _render_threat_intelligence_result(self, result):
        self._render_local_signature_import_result(result)

    def install_yara_rule(self):
        filename = filedialog.askopenfilename(
            title="Select a local YARA rule",
            filetypes=[("YARA rules", "*.yar *.yara")]
        )
        if not filename:
            return
        try:
            installed = self.scanner.yara_scanner.install_rule(filename)
            self._record_event(
                "yara_rule_installed",
                f"Installed and compiled local YARA rule {Path(installed).name}."
            )
            self.refresh_threat_intelligence()
        except (OSError, ValueError, RuntimeError) as error:
            messagebox.showerror("YARA Rule Import Failed", str(error))
            self._record_event("yara_rule_import_failed", str(error))

    def create_vulnerability_page(self):
        page = self.create_page("Vulnerability Assessment")
        self.page_header(
            page,
            "🛡️ Vulnerability Assessment",
            "Inventory installed Windows software and optionally check a selected item against NVD."
        )
        ctk.CTkLabel(
            page,
            text=(
                "CVE matches are reported separately from malware detections. "
                "Product-to-CPE matching is conservative and may miss software "
                "with incomplete vendor or version information."
            ),
            text_color=self.MUTED,
            wraplength=980,
            justify="left"
        ).pack(anchor="w", padx=24, pady=10)
        controls = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=10)
        controls.pack(fill="x", padx=20, pady=8)
        ctk.CTkButton(
            controls,
            text="Inventory installed software",
            command=self.start_software_inventory
        ).pack(side="left", padx=12, pady=12)
        ctk.CTkButton(
            controls,
            text="Check selected software against NVD",
            command=self.check_selected_software_cves
        ).pack(side="left", padx=5, pady=12)
        self.software_inventory_table = ttk.Treeview(
            page,
            columns=("Software", "Version", "Publisher"),
            show="headings",
            height=12
        )
        for column in ("Software", "Version", "Publisher"):
            self.software_inventory_table.heading(column, text=column)
            self.software_inventory_table.column(
                column,
                width=300 if column != "Version" else 140
            )
        self.software_inventory_table.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=8
        )
        self.vulnerability_results = ctk.CTkTextbox(page, height=180)
        self.vulnerability_results.pack(fill="x", padx=20, pady=8)
        self.vulnerability_results.insert(
            "1.0",
            "Inventory has not been collected. NVD queries are sent only after "
            "you select software and confirm the external lookup."
        )
        self.vulnerability_results.configure(state="disabled")

    def start_software_inventory(self):
        self.vulnerability_results.configure(state="normal")
        self.vulnerability_results.delete("1.0", "end")
        self.vulnerability_results.insert("1.0", "Reading Windows uninstall inventory...")
        self.vulnerability_results.configure(state="disabled")
        threading.Thread(
            target=self._software_inventory_worker,
            daemon=True,
            name="SoftwareInventory"
        ).start()

    def _software_inventory_worker(self):
        try:
            inventory = inventory_installed_software()
            self._queue_ui_event("software_inventory_result", inventory)
        except (OSError, RuntimeError) as error:
            self._queue_ui_event("vulnerability_error", str(error))

    def _render_software_inventory(self, inventory):
        self._software_inventory = inventory
        for row in self.software_inventory_table.get_children():
            self.software_inventory_table.delete(row)
        for item in inventory:
            self.software_inventory_table.insert(
                "",
                "end",
                values=(
                    item.get("name", ""),
                    item.get("version", ""),
                    item.get("publisher", "")
                )
            )
        self._show_vulnerability_text(
            f"Found {len(inventory):,} installed software entries. "
            "Select one item and explicitly consent before an NVD query."
        )

    def check_selected_software_cves(self):
        selection = self.software_inventory_table.selection()
        if not selection:
            messagebox.showinfo(
                "Select Software",
                "Inventory software and select one entry first."
            )
            return
        values = self.software_inventory_table.item(
            selection[0]
        ).get("values", [])
        item = next(
            (
                software
                for software in self._software_inventory
                if len(values) >= 2
                and software.get("name") == values[0]
                and software.get("version") == values[1]
            ),
            None
        )
        if not item:
            messagebox.showerror(
                "Selection Error",
                "Selected software entry is no longer available."
            )
            return
        if not messagebox.askyesno(
            "NVD Lookup Consent",
            "Send the selected software name and version to the NVD API over "
            "HTTPS? No files will be uploaded."
        ):
            return
        threading.Thread(
            target=self._nvd_lookup_worker,
            args=(item,),
            daemon=True,
            name="NvdSoftwareLookup"
        ).start()
        self._show_vulnerability_text(
            f"Checking {item['name']} {item['version']} against NVD..."
        )

    def _nvd_lookup_worker(self, software):
        try:
            result = self.nvd_client.search_product(software)
            self._queue_ui_event("vulnerability_result", software, result)
        except VulnerabilityAssessmentError as error:
            self._queue_ui_event("vulnerability_error", str(error))

    def _render_vulnerability_results(self, software, findings):
        if not findings:
            self._show_vulnerability_text(
                f"No exact CPE/version matches were found for "
                f"{software['name']} {software['version']}. This is not proof "
                "that the software has no vulnerabilities."
            )
            return
        lines = [
            f"{len(findings)} CVE match(es) for "
            f"{software['name']} {software['version']}:"
        ]
        for finding in findings:
            cvss = finding.get("cvss") or {}
            lines.extend([
                "",
                f"{finding['cve']} · CVSS {cvss.get('score', 'N/A')} "
                f"{cvss.get('severity', 'Unknown')}",
                finding.get("description", "No description provided."),
                f"CPE: {finding.get('cpe', '')}",
                f"Recommendation: {finding['recommendation']}",
                f"Reference: https://nvd.nist.gov/vuln/detail/{finding['cve']}",
            ])
        self._show_vulnerability_text("\n".join(lines))
        self._record_event(
            "vulnerability_assessment",
            f"NVD reported {len(findings)} match(es) for {software['name']}.",
            {"software": software, "findings": findings}
        )

    def _render_vulnerability_error(self, error):
        self._show_vulnerability_text(f"Vulnerability assessment failed: {error}")
        self._record_event("vulnerability_assessment_failed", str(error))

    def _show_vulnerability_text(self, text):
        self.vulnerability_results.configure(state="normal")
        self.vulnerability_results.delete("1.0", "end")
        self.vulnerability_results.insert("1.0", text)
        self.vulnerability_results.configure(state="disabled")

    def create_reputation_page(self):
        page = self.create_page("File Reputation")
        self.page_header(
            page,
            "🌐 File Reputation",
            "Optional external hash-only lookups. No files are uploaded."
        )
        card = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=10)
        card.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            card,
            text=(
                "Store API keys in Windows Credential Manager using the "
                "optional keyring package. Credentials are never written to "
                "scanner settings. MalwareBazaar also requires an API key."
            ),
            wraplength=980,
            justify="left",
            text_color=self.MUTED
        ).pack(anchor="w", padx=20, pady=(16, 8))
        self.virustotal_key_entry = ctk.CTkEntry(
            card,
            placeholder_text="VirusTotal API key",
            show="*",
            width=400
        )
        self.virustotal_key_entry.pack(anchor="w", padx=20, pady=5)
        ctk.CTkButton(
            card,
            text="Save VirusTotal key securely",
            command=lambda: self._save_reputation_credential(
                "virustotal",
                self.virustotal_key_entry
            )
        ).pack(anchor="w", padx=20, pady=5)
        self.malwarebazaar_key_entry = ctk.CTkEntry(
            card,
            placeholder_text="MalwareBazaar API key",
            show="*",
            width=400
        )
        self.malwarebazaar_key_entry.pack(anchor="w", padx=20, pady=5)
        ctk.CTkButton(
            card,
            text="Save MalwareBazaar key securely",
            command=lambda: self._save_reputation_credential(
                "malwarebazaar",
                self.malwarebazaar_key_entry
            )
        ).pack(anchor="w", padx=20, pady=5)
        self.reputation_status_label = ctk.CTkLabel(
            card,
            text="No external lookups have been requested.",
            anchor="w",
            justify="left",
            wraplength=980
        )
        self.reputation_status_label.pack(
            fill="x",
            padx=20,
            pady=(12, 8)
        )
        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.pack(anchor="w", padx=15, pady=(0, 16))
        ctk.CTkButton(
            buttons,
            text="VirusTotal hash lookup",
            command=lambda: self.start_reputation_lookup("virustotal")
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            buttons,
            text="MalwareBazaar hash lookup",
            command=lambda: self.start_reputation_lookup("malwarebazaar")
        ).pack(side="left", padx=5)

    def _save_reputation_credential(self, provider, entry):
        credential = entry.get().strip()
        if not credential:
            messagebox.showerror("Credential Required", "Enter an API key first.")
            return
        try:
            self.credential_store.set(provider, credential)
            entry.delete(0, "end")
            messagebox.showinfo(
                "Credential Saved",
                "The credential was saved through the system credential store."
            )
        except Exception as error:
            messagebox.showerror("Credential Storage Unavailable", str(error))

    def start_reputation_lookup(self, provider):
        filepath = filedialog.askopenfilename(
            title="Select a file (only its SHA-256 will be queried)",
            filetypes=[("All files", "*.*")]
        )
        if not filepath:
            return
        if not messagebox.askyesno(
            "External Hash Lookup Consent",
            f"Calculate the SHA-256 of the selected file and send only that "
            f"hash to {provider}? The file itself and its path will not be sent."
        ):
            return
        try:
            credential = self.credential_store.get(provider)
        except Exception as error:
            messagebox.showerror("Credential Error", str(error))
            return
        if not credential:
            messagebox.showerror(
                "API Key Required",
                f"Configure a {provider} API key or set its documented environment variable first."
            )
            return
        self.reputation_status_label.configure(
            text=f"Calculating a local SHA-256 and querying {provider}..."
        )
        threading.Thread(
            target=self._reputation_worker,
            args=(provider, filepath, credential),
            daemon=True,
            name=f"{provider.title()}HashLookup"
        ).start()

    def _reputation_worker(self, provider, filepath, credential):
        try:
            file_hash = calculate_file_sha256(filepath)
            if provider == "virustotal":
                result = self.reputation_client.lookup_virustotal(
                    file_hash,
                    credential,
                    consent=True
                )
            elif provider == "malwarebazaar":
                result = self.reputation_client.lookup_malwarebazaar(
                    file_hash,
                    api_key=credential,
                    consent=True
                )
            else:
                raise ValueError(f"Unsupported reputation provider: {provider}")
            self._queue_ui_event("reputation_result", result)
        except Exception as error:
            self._queue_ui_event("reputation_error", provider, str(error))

    def _render_reputation_result(self, result):
        self.reputation_status_label.configure(
            text=(
                f"{result.get('provider')} · {result.get('status')} · "
                f"SHA-256 {result.get('sha256')} · "
                f"{'cached' if result.get('cached') else 'fresh lookup'}\n"
                f"Malicious detections: {result.get('malicious', 'N/A')} · "
                f"Suspicious: {result.get('suspicious', 'N/A')}\n"
                f"MalwareBazaar records: {len(result.get('records', []))}"
            )
        )
        self._record_event(
            "file_reputation_lookup",
            f"Completed {result.get('provider')} hash lookup.",
            {
                "provider": result.get("provider"),
                "status": result.get("status"),
                "sha256": result.get("sha256"),
                "cached": result.get("cached"),
            }
        )

    def _render_reputation_error(self, provider, error):
        self.reputation_status_label.configure(
            text=f"{provider} lookup failed: {error}",
            text_color=self.RED
        )
        self._record_event(
            "file_reputation_lookup_failed",
            f"{provider} lookup failed: {error}"
        )

    # ==========================================================
    # REPORTS
    # ==========================================================

    def create_reports_page(self):

        page = self.create_page(
            "Scan Reports"
        )

        self.page_header(
            page,
            "📊 Security Reports",
            "Generate a report from your latest scan."
        )

        card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        card.pack(
            fill="x",
            padx=20,
            pady=15
        )

        ctk.CTkLabel(
            card,
            text="📄  Latest Scan Report",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(25, 5)
        )

        self.report_status = ctk.CTkLabel(
            card,
            text="No scan has been performed yet.",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        )

        self.report_status.pack(
            anchor="w",
            padx=25,
            pady=10
        )

        self.report_summary = ctk.CTkLabel(
            card,
            text="Run a scan to populate this report summary.",
            font=("Segoe UI", 12),
            text_color=self.MUTED,
            justify="left"
        )

        self.report_summary.pack(
            anchor="w",
            padx=25,
            pady=(0, 10)
        )

        self.report_generate_button = ctk.CTkButton(
            card,
            text="📄  Generate Security Report",
            width=250,
            height=48,
            command=self.generate_scan_report
        )
        self.report_generate_button.pack(
            anchor="w",
            padx=25,
            pady=(10, 25)
        )
        history_card = ctk.CTkFrame(page, fg_color=self.CARD, corner_radius=12)
        history_card.pack(fill="both", expand=True, padx=20, pady=10)
        ctk.CTkLabel(
            history_card,
            text="Report history",
            font=(self.FONT, 17, "bold"),
            text_color=self.TEXT
        ).pack(anchor="w", padx=20, pady=(16, 5))
        self.report_history_status = ctk.CTkLabel(
            history_card,
            text="Reports are stored in LocalAppData.",
            anchor="w",
            text_color=self.MUTED
        )
        self.report_history_status.pack(fill="x", padx=20, pady=(0, 8))
        columns = ("Report", "Created", "Scan type", "Status", "Findings")
        self.report_history_table = ttk.Treeview(
            history_card,
            columns=columns,
            show="headings",
            height=8
        )
        for column in columns:
            self.report_history_table.heading(column, text=column)
        self.report_history_table.column("Report", width=290)
        self.report_history_table.column("Created", width=170)
        self.report_history_table.column("Scan type", width=160)
        self.report_history_table.column("Status", width=110)
        self.report_history_table.column("Findings", width=90)
        self.report_history_table.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=5
        )
        self.report_history_table.bind(
            "<Double-1>",
            lambda _event: self.open_selected_report()
        )
        ctk.CTkButton(
            history_card,
            text="Open selected report",
            command=self.open_selected_report
        ).pack(anchor="w", padx=16, pady=(4, 14))

    def refresh_reports(self):

        if self.last_result is None:

            self.report_status.configure(
                text="No scan has been performed yet."
            )
            self.report_summary.configure(
                text="Run a scan to populate this report summary."
            )

        else:

            threats = self.last_result.get("suspicious", [])
            counts = self._severity_counts(threats)
            scanned = self.last_result.get(
                "scanned",
                self.last_result.get("files_scanned", 0)
            )

            self.report_status.configure(
                text=(
                    f"{self.last_scan_page or 'Latest scan'} · "
                    f"{len(threats):,} finding(s)"
                )
            )
            self.report_summary.configure(
                text=(
                    f"Files checked: {scanned:,}    "
                    + (
                        "Security score: unavailable (incomplete results)\n"
                        if self.scan_result_state(self.last_result) != "Complete"
                        else
                        f"Security score: {self.calculate_security_score(threats)}/100\n"
                    )
                    + f"Critical: {counts['Critical']}    "
                    + f"High: {counts['High']}    "
                    + f"Medium: {counts['Medium']}    "
                    + f"Low: {counts['Low']}"
                )
            )
        self._refresh_report_history()

    def _refresh_report_history(self):
        if not hasattr(self, "report_history_table"):
            return
        table = self.report_history_table
        for item in table.get_children():
            table.delete(item)
        reports_directory = Path(default_data_directory()) / "reports"
        try:
            reports = sorted(
                reports_directory.glob("Scan_Report_*.html"),
                key=lambda path: path.stat().st_mtime,
                reverse=True
            )
            for path in reports:
                try:
                    content = path.read_text(
                        encoding="utf-8",
                        errors="replace"
                    )[:100_000]
                    scan_type = self._report_meta(content, "scan-type")
                    status = self._report_meta(content, "scan-status")
                    count = self._report_meta(content, "finding-count")
                    created = datetime.fromtimestamp(
                        path.stat().st_mtime
                    ).astimezone().strftime("%Y-%m-%d %H:%M")
                    table.insert(
                        "",
                        "end",
                        iid=str(path),
                        values=(
                            path.name,
                            created,
                            scan_type or "Unknown",
                            status or "Unknown",
                            count or "Unknown"
                        )
                    )
                except OSError as error:
                    logging.error("Unable to read report %s: %s", path, error)
            self.report_history_status.configure(
                text=f"{len(reports)} report(s) · {reports_directory}"
            )
        except OSError as error:
            self.report_history_status.configure(
                text=f"Report history unavailable: {error}"
            )

    @staticmethod
    def _report_meta(content, name):
        match = re.search(
            rf'<meta\s+name="{re.escape(name)}"\s+content="([^"]*)"',
            content,
            flags=re.IGNORECASE
        )
        return html.unescape(match.group(1)) if match else ""

    def open_selected_report(self):
        selected = self.report_history_table.selection()
        if not selected:
            messagebox.showinfo(
                "No Report Selected",
                "Select a report to open."
            )
            return
        path = Path(selected[0])
        if not path.is_file():
            messagebox.showerror(
                "Report Unavailable",
                "The selected report no longer exists."
            )
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(str(path))
            else:
                webbrowser.open(path.resolve().as_uri())
        except OSError as error:
            messagebox.showerror("Unable to Open Report", str(error))

    def generate_scan_report(self):

        if self.last_result is None:

            messagebox.showinfo(
                "No Scan",
                "Please run a scan before generating a report."
            )

            return

        result = copy.deepcopy(self.last_result)
        metadata = {
            "scan_type": result.get("scan_type", self.last_scan_page or "Unknown"),
            "started_at": result.get("started_at", "Unknown"),
            "duration": (
                f"{int(result.get('duration_seconds', 0))} seconds"
            ),
            "exclusions": list(self.settings.get("scan_exclusions", [])),
        }
        self.report_generate_button.configure(
            state="disabled",
            text="Generating report..."
        )
        threading.Thread(
            target=self._generate_report_worker,
            args=(result, metadata),
            daemon=True
        ).start()

    def _generate_report_worker(self, result, metadata):
        try:
            filename = generate_report(
                result,
                metadata=metadata
            )
            self._queue_ui_event("report_finished", filename)
        except Exception as error:
            self._queue_ui_event("report_error", error)

    def _report_finished(self, filename):
        self.report_generate_button.configure(
            state="normal",
            text="📄  Generate Security Report"
        )
        self.report_status.configure(
            text=f"Report generated:\n{filename}"
        )
        self._record_event(
            "report_generated",
            f"Security report generated: {filename}"
        )
        self._refresh_report_history()

    def _report_failed(self, error):
        self.report_generate_button.configure(
            state="normal",
            text="📄  Generate Security Report"
        )
        self.report_status.configure(
            text=f"Report generation failed: {error}"
        )
        self._record_event(
            "report_failed",
            f"Security report generation failed: {error}"
        )

    # ==========================================================
    # STARTUP SECURITY
    # ==========================================================

    def create_startup_page(self):

        page = self.create_page(
            "Startup Security"
        )

        self.page_header(
            page,
            "🚀 Startup Security",
            "Review programs configured to start with Windows."
        )

        self.startup_count_label = ctk.CTkLabel(
            page,
            text="Startup Programs: Not scanned",
            font=("Segoe UI", 14),
            text_color=self.MUTED
        )

        self.startup_count_label.pack(
            anchor="w",
            padx=25,
            pady=10
        )

        table_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        table_card.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        columns = (
            "Program",
            "Command",
            "Risk",
            "Reason"
        )

        self.startup_table = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            height=12
        )

        for col in columns:

            self.startup_table.heading(
                col,
                text=col
            )

        for risk, color in {
            "High": "#FF8A65",
            "Medium": "#FFCA66",
            "Low": "#8DBBFF",
            "Unknown": "#9AA4B2",
        }.items():
            self.startup_table.tag_configure(risk, foreground=color)

        self.startup_table.column(
            "Program",
            width=200
        )

        self.startup_table.column(
            "Command",
            width=500
        )

        self.startup_table.column(
            "Risk",
            width=100
        )

        self.startup_table.column(
            "Reason",
            width=450
        )

        self.startup_table.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=10
        )

        scrollbar = ttk.Scrollbar(
            table_card,
            orient="vertical",
            command=self.startup_table.yview
        )

        scrollbar.pack(
            side="right",
            fill="y",
            padx=(0, 10),
            pady=10
        )

        self.startup_table.configure(
            yscrollcommand=scrollbar.set
        )
        horizontal_scrollbar = ttk.Scrollbar(
            table_card,
            orient="horizontal",
            command=self.startup_table.xview
        )
        horizontal_scrollbar.pack(
            side="bottom",
            fill="x"
        )
        self.startup_table.configure(
            xscrollcommand=horizontal_scrollbar.set
        )

        self.startup_scan_btn = ctk.CTkButton(
            page,
            text="🚀  Scan Startup Programs",
            width=250,
            height=48,
            command=self.run_startup_scan
        )

        self.startup_scan_btn.pack(
            pady=15
        )

    def run_startup_scan(self):

        self.startup_scan_btn.configure(
            state="disabled",
            text="⏳  Scanning..."
        )

        self.status_dot.configure(
            text_color=self.YELLOW
        )

        self.sidebar_status.configure(
            text="Working..."
        )

        threading.Thread(
            target=self.startup_scan_worker,
            daemon=True
        ).start()

    def startup_scan_worker(self):

        try:

            entries = scan_startup_entries()

            self._queue_ui_event(
                "startup_finished",
                entries
            )

        except Exception as error:

            self._queue_ui_event(
                "startup_error",
                error
            )

    def display_startup_results(
        self,
        entries
    ):

        for item in self.startup_table.get_children():

            self.startup_table.delete(
                item
            )

        for entry in entries:

            self.startup_table.insert(
                "",
                "end",
                values=(
                    entry.get(
                        "name",
                        ""
                    ),

                    entry.get(
                        "value",
                        ""
                    ),

                    entry.get(
                        "risk",
                        ""
                    ),

                    entry.get(
                        "reason",
                        ""
                    )
                ),
                tags=(entry.get("risk", "Unknown"),)
            )

        high = sum(
            1 for e in entries
            if e.get("risk") == "High"
        )

        medium = sum(
            1 for e in entries
            if e.get("risk") == "Medium"
        )

        low = sum(
            1 for e in entries
            if e.get("risk") == "Low"
        )

        self.startup_count_label.configure(
            text=(
                f"Startup Programs: {len(entries)}   |   "
                f"🔴 High: {high}   |   "
                f"🟠 Medium: {medium}   |   "
                f"🟢 Low: {low}"
            )
        )

        self._record_event(
            "startup_scan_completed",
            (
                f"Startup scan completed: {len(entries)} entries, "
                f"{high} high-risk finding(s)."
            ),
            {
                "entries": len(entries),
                "high_risk": high,
                "medium_risk": medium,
                "low_risk": low,
            }
        )

        self.startup_scan_btn.configure(
            state="normal",
            text="🚀  Scan Startup Programs"
        )

        self.status_dot.configure(
            text_color=self.GREEN
        )

        self.sidebar_status.configure(
            text="Scanner Ready"
        )

        if high:

            messagebox.showwarning(
                "Startup Security Alert",
                f"Startup scan completed.\n\n"
                f"Programs: {len(entries)}\n"
                f"High Risk: {high}\n"
                f"Medium Risk: {medium}\n"
                f"Low Risk: {low}"
            )

        else:

            messagebox.showinfo(
                "Startup Scan Complete",
                f"Startup scan completed.\n\n"
                f"Programs: {len(entries)}\n"
                f"High Risk: {high}\n"
                f"Medium Risk: {medium}\n"
                f"Low Risk: {low}"
            )

    def startup_scan_error(
        self,
        error
    ):

        self.startup_scan_btn.configure(
            state="normal",
            text="🚀  Scan Startup Programs"
        )

        self.status_dot.configure(
            text_color=self.GREEN
        )

        self.sidebar_status.configure(
            text="Scanner Ready"
        )

        self._record_event(
            "startup_scan_failed",
            f"Startup scan failed: {error}",
        )

        messagebox.showerror(
            "Startup Scan Error",
            f"Unable to scan startup entries.\n\n"
            f"{error}"
        )

    # ==========================================================
    # SETTINGS
    # ==========================================================

    def create_settings_page(self):

        page = self.create_page(
            "Settings"
        )

        self.page_header(
            page,
            "⚙️ Settings",
            "Configure the application."
        )

        appearance = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        appearance.pack(
            fill="x",
            padx=20,
            pady=15
        )

        ctk.CTkLabel(
            appearance,
            text="Appearance",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 5)
        )

        ctk.CTkLabel(
            appearance,
            text="Choose the application theme.",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        ).pack(
            anchor="w",
            padx=25,
            pady=5
        )

        self.appearance_menu = ctk.CTkOptionMenu(
            appearance,
            values=[
                "Dark",
                "Light",
                "System"
            ],
            command=self.change_appearance
        )

        self.appearance_menu.set(
            self.settings.get("appearance", "Dark")
        )

        self.appearance_menu.pack(
            anchor="w",
            padx=25,
            pady=(10, 25)
        )

        resources = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        resources.pack(
            fill="x",
            padx=20,
            pady=15
        )

        ctk.CTkLabel(
            resources,
            text="System Monitoring",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 5)
        )

        self.resource_status_label = ctk.CTkLabel(
            resources,
            text="Reading local CPU and memory usage.",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        )

        self.resource_status_label.pack(
            anchor="w",
            padx=25,
            pady=(4, 8)
        )

        self.resource_monitor_switch = ctk.CTkSwitch(
            resources,
            text="Monitor CPU and memory",
            command=self.set_resource_monitoring
        )
        if self.resource_monitoring:
            self.resource_monitor_switch.select()
        else:
            self.resource_monitor_switch.deselect()
        self.resource_monitor_switch.pack(
            anchor="w",
            padx=25,
            pady=(5, 22)
        )

        scan_settings = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        scan_settings.pack(
            fill="x",
            padx=20,
            pady=15
        )
        ctk.CTkLabel(
            scan_settings,
            text="Scan Settings",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 6)
        )
        ctk.CTkLabel(
            scan_settings,
            text="Excluded files and folders are skipped by all scan types.",
            font=("Segoe UI", 12),
            text_color=self.MUTED
        ).pack(
            anchor="w",
            padx=25,
            pady=(0, 10)
        )

        self.exclusion_table = ttk.Treeview(
            scan_settings,
            columns=("Excluded path",),
            show="headings",
            height=4
        )
        self.exclusion_table.heading(
            "Excluded path",
            text="Excluded path"
        )
        self.exclusion_table.column("Excluded path", width=900)
        self.exclusion_table.pack(
            fill="x",
            padx=25,
            pady=5
        )

        exclusion_actions = ctk.CTkFrame(
            scan_settings,
            fg_color="transparent"
        )
        exclusion_actions.pack(
            fill="x",
            padx=20,
            pady=(5, 8)
        )
        worker_controls = ctk.CTkFrame(
            scan_settings,
            fg_color="transparent"
        )
        worker_controls.pack(anchor="w", padx=20, pady=5)
        ctk.CTkLabel(
            worker_controls,
            text="Concurrent scan workers (1–16):"
        ).pack(side="left", padx=5)
        self.scan_workers_menu = ctk.CTkOptionMenu(
            worker_controls,
            values=["1", "2", "4", "8", "16"],
            command=self.set_scan_workers
        )
        self.scan_workers_menu.set(
            str(self.settings.get("scan_workers", 4))
        )
        self.scan_workers_menu.pack(side="left", padx=5)
        ctk.CTkLabel(
            worker_controls,
            text="Maximum file size (MB):"
        ).pack(side="left", padx=(18, 5))
        self.max_file_size_menu = ctk.CTkOptionMenu(
            worker_controls,
            values=["25", "50", "100", "250", "500"],
            command=self.set_max_file_size
        )
        self.max_file_size_menu.set(
            str(self.settings.get("max_file_size_mb", 100))
        )
        self.max_file_size_menu.pack(side="left", padx=5)
        self.exclusion_path_entry = ctk.CTkEntry(
            exclusion_actions,
            placeholder_text="Enter an existing file or folder path"
        )
        self.exclusion_path_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )
        ctk.CTkButton(
            exclusion_actions,
            text="Add path",
            width=100,
            command=self.add_exclusion_from_entry
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            exclusion_actions,
            text="Browse",
            width=90,
            command=self.add_exclusion_from_picker
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            exclusion_actions,
            text="Remove selected",
            width=140,
            command=self.remove_selected_exclusion
        ).pack(side="left", padx=4)

        ctk.CTkLabel(
            scan_settings,
            text="Scheduled Scanning",
            font=("Segoe UI", 16, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(12, 4)
        )
        schedule_controls = ctk.CTkFrame(
            scan_settings,
            fg_color="transparent"
        )
        schedule_controls.pack(
            anchor="w",
            padx=20,
            pady=5
        )
        self.schedule_switch = ctk.CTkSwitch(
            schedule_controls,
            text="Enable automatic scans",
            command=self.update_schedule_settings
        )
        if self.settings.get("scheduled_scan_enabled"):
            self.schedule_switch.select()
        self.schedule_switch.pack(side="left", padx=5)

        self.schedule_type_menu = ctk.CTkOptionMenu(
            schedule_controls,
            values=["Quick Scan", "Full Scan"],
            command=lambda value: self.update_schedule_settings()
        )
        self.schedule_type_menu.set(
            self.settings.get("scheduled_scan_type", "Quick Scan")
        )
        self.schedule_type_menu.pack(side="left", padx=8)

        self.schedule_interval_menu = ctk.CTkOptionMenu(
            schedule_controls,
            values=["6 hours", "12 hours", "24 hours", "7 days"],
            command=lambda value: self.update_schedule_settings()
        )
        interval = self.settings.get("scheduled_scan_interval_hours", 24)
        interval_labels = {
            6: "6 hours",
            12: "12 hours",
            24: "24 hours",
            168: "7 days",
        }
        self.schedule_interval_menu.set(
            interval_labels.get(interval, "24 hours")
        )
        self.schedule_interval_menu.pack(side="left", padx=8)

        self.schedule_status_label = ctk.CTkLabel(
            scan_settings,
            text="Scheduled scans are disabled.",
            font=("Segoe UI", 12),
            text_color=self.MUTED
        )
        self.schedule_status_label.pack(
            anchor="w",
            padx=25,
            pady=(4, 12)
        )

        self.settings_status_label = ctk.CTkLabel(
            scan_settings,
            text="Settings are stored locally.",
            font=("Segoe UI", 11),
            text_color=self.MUTED
        )
        self.settings_status_label.pack(
            anchor="w",
            padx=25,
            pady=(0, 15)
        )

        signatures_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        signatures_card.pack(
            fill="x",
            padx=20,
            pady=15
        )
        ctk.CTkLabel(
            signatures_card,
            text="Offline Threat Signatures",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 5)
        )
        self.signature_status_label = ctk.CTkLabel(
            signatures_card,
            text="Loading local signatures...",
            font=("Segoe UI", 12),
            text_color=self.MUTED
        )
        self.signature_status_label.pack(
            anchor="w",
            padx=25,
            pady=5
        )
        signature_buttons = ctk.CTkFrame(
            signatures_card,
            fg_color="transparent"
        )
        signature_buttons.pack(
            anchor="w",
            padx=20,
            pady=(5, 20)
        )
        ctk.CTkButton(
            signature_buttons,
            text="Import local signature file",
            command=self.import_signature_file
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            signature_buttons,
            text="Reload signatures",
            command=self.reload_local_signatures
        ).pack(side="left", padx=5)

        backup_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        backup_card.pack(
            fill="x",
            padx=20,
            pady=15
        )
        ctk.CTkLabel(
            backup_card,
            text="Backup & Recovery",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 5)
        )
        ctk.CTkLabel(
            backup_card,
            text=(
                "Backups contain settings, protection history, local signatures, "
                "and isolated quarantine files."
            ),
            font=("Segoe UI", 12),
            text_color=self.MUTED
        ).pack(anchor="w", padx=25, pady=5)
        backup_buttons = ctk.CTkFrame(
            backup_card,
            fg_color="transparent"
        )
        backup_buttons.pack(
            anchor="w",
            padx=20,
            pady=(5, 20)
        )
        self.backup_button = ctk.CTkButton(
            backup_buttons,
            text="Create backup",
            command=self.create_backup
        )
        self.backup_button.pack(side="left", padx=5)
        self.restore_button = ctk.CTkButton(
            backup_buttons,
            text="Restore backup",
            command=self.restore_backup
        )
        self.restore_button.pack(side="left", padx=5)

        health_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        health_card.pack(
            fill="x",
            padx=20,
            pady=15
        )
        ctk.CTkLabel(
            health_card,
            text="Startup Health",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 5)
        )
        self.health_status_label = ctk.CTkLabel(
            health_card,
            text="Startup checks pending.",
            font=("Segoe UI", 12),
            text_color=self.MUTED,
            justify="left"
        )
        self.health_status_label.pack(
            anchor="w",
            padx=25,
            pady=(5, 20)
        )
        if hasattr(self, "health_checks"):
            self.health_status_label.configure(
                text="\n".join(self.health_checks)
            )

        tools_card = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )
        tools_card.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(
            tools_card,
            text="Security tools",
            font=(self.FONT, 18, "bold"),
            text_color=self.TEXT
        ).pack(anchor="w", padx=22, pady=(18, 5))
        self.settings_section_status = ctk.CTkLabel(
            tools_card,
            text=(
                "External hash lookups require explicit consent. "
                "Threat intelligence updates must be locally verified."
            ),
            font=(self.FONT, 12),
            text_color=self.MUTED
        )
        self.settings_section_status.pack(anchor="w", padx=22, pady=(0, 10))
        ctk.CTkLabel(
            tools_card,
            text=f"Quarantine storage: {self.scanner.quarantine_dir}",
            font=(self.FONT, 11),
            text_color=self.MUTED,
            wraplength=950,
            justify="left"
        ).pack(anchor="w", padx=22, pady=(0, 10))
        tools_row = ctk.CTkFrame(tools_card, fg_color="transparent")
        tools_row.pack(anchor="w", padx=16, pady=(0, 16))
        for label, destination in (
            ("Startup Security", "Startup Security"),
            ("Threat Intelligence", "Threat Intelligence"),
            ("File Reputation", "File Reputation"),
        ):
            ctk.CTkButton(
                tools_row,
                text=label,
                command=lambda page_name=destination: self.show_page(page_name)
            ).pack(side="left", padx=5)

        self._refresh_exclusion_table()

        # ------------------------------------------------------
        # ABOUT
        # ------------------------------------------------------

        about = ctk.CTkFrame(
            page,
            fg_color=self.CARD,
            corner_radius=12
        )

        about.pack(
            fill="x",
            padx=20,
            pady=15
        )

        ctk.CTkLabel(
            about,
            text="About IT Security Scanner",
            font=("Segoe UI", 20, "bold"),
            text_color=self.TEXT
        ).pack(
            anchor="w",
            padx=25,
            pady=(22, 8)
        )

        ctk.CTkLabel(
            about,
            text=(
                "Local Windows Security Scanner\n\n"
                "Features:\n"
                "• File scanning\n"
                "• SHA-256 detection\n"
                "• Script heuristics\n"
                "• PE analysis\n"
                "• Entropy analysis\n"
                "• Startup security\n"
                "• Threat quarantine\n"
                "• Permanent deletion\n"
                "• Security reports\n\n"
                "No cloud service or external API is required."
            ),
            justify="left",
            font=("Segoe UI", 13),
            text_color=self.MUTED
        ).pack(
            anchor="w",
            padx=25,
            pady=(5, 25)
        )

    def set_scan_workers(self, value):
        try:
            worker_count = int(value)
            if worker_count not in {1, 2, 4, 8, 16}:
                raise ValueError("Choose a supported worker count.")
            previous = self.settings.get("scan_workers", 4)
            self.settings["scan_workers"] = worker_count
            if not self._save_settings():
                self.settings["scan_workers"] = previous
                raise OSError("Unable to save the scan worker setting.")
            effective_workers = self.scanner.set_max_workers(worker_count)
            self.settings_status_label.configure(
                text=(
                    f"Concurrent file scanning uses up to "
                    f"{effective_workers} workers."
                )
            )
        except (ValueError, OSError) as error:
            messagebox.showerror("Scan Setting Error", str(error))

    def set_max_file_size(self, value):
        try:
            maximum_mb = int(value)
            if maximum_mb not in {25, 50, 100, 250, 500}:
                raise ValueError("Choose a supported maximum file size.")
            previous = self.settings.get("max_file_size_mb", 100)
            self.settings["max_file_size_mb"] = maximum_mb
            if not self._save_settings():
                self.settings["max_file_size_mb"] = previous
                raise OSError("Unable to save the maximum file size setting.")
            self.scanner.max_file_size = maximum_mb * 1024 * 1024
            self.settings_status_label.configure(
                text=f"Files larger than {maximum_mb} MB are skipped."
            )
        except (ValueError, OSError) as error:
            messagebox.showerror("Scan Setting Error", str(error))

    def _refresh_exclusion_table(self):
        if not hasattr(self, "exclusion_table"):
            return

        children = self.exclusion_table.get_children()
        if children:
            self.exclusion_table.delete(*children)
        for path in self.settings.get("scan_exclusions", []):
            self.exclusion_table.insert("", "end", values=(path,))

    def _add_exclusion(self, value):
        path = Path(value).expanduser()
        if not path.exists():
            messagebox.showerror(
                "Invalid exclusion",
                "Select an existing file or folder."
            )
            return

        normalized = str(path.resolve())
        key = os.path.normcase(os.path.normpath(normalized))
        existing = {
            os.path.normcase(os.path.normpath(item))
            for item in self.settings.get("scan_exclusions", [])
        }
        if key in existing:
            return

        self.settings.setdefault("scan_exclusions", []).append(normalized)
        self.scanner.set_exclusions(
            self.settings["scan_exclusions"]
        )
        self._refresh_exclusion_table()
        self._save_settings()
        self._record_event(
            "scan_exclusion_added",
            f"Added scan exclusion: {normalized}"
        )

    def add_exclusion_from_entry(self):
        value = self.exclusion_path_entry.get().strip()
        if value:
            self._add_exclusion(value)
            self.exclusion_path_entry.delete(0, "end")

    def add_exclusion_from_picker(self):
        folder = filedialog.askdirectory(
            title="Choose a folder to exclude"
        )
        if folder:
            self._add_exclusion(folder)

    def remove_selected_exclusion(self):
        selected = self.exclusion_table.selection()
        if not selected:
            return

        values = self.exclusion_table.item(
            selected[0]
        ).get("values", [])
        if not values:
            return

        exclusion = str(values[0])
        self.settings["scan_exclusions"] = [
            item
            for item in self.settings.get("scan_exclusions", [])
            if os.path.normcase(os.path.normpath(item))
            != os.path.normcase(os.path.normpath(exclusion))
        ]
        self.scanner.set_exclusions(
            self.settings["scan_exclusions"]
        )
        self._refresh_exclusion_table()
        self._save_settings()
        self._record_event(
            "scan_exclusion_removed",
            f"Removed scan exclusion: {exclusion}"
        )

    def update_schedule_settings(self):
        self.settings["scheduled_scan_enabled"] = bool(
            self.schedule_switch.get()
        )
        self.settings["scheduled_scan_type"] = (
            self.schedule_type_menu.get()
        )
        interval = {
            "6 hours": 6,
            "12 hours": 12,
            "24 hours": 24,
            "7 days": 168,
        }.get(self.schedule_interval_menu.get(), 24)
        self.settings["scheduled_scan_interval_hours"] = interval

        if self.settings["scheduled_scan_enabled"]:
            self.settings["next_scheduled_scan"] = (
                datetime.now().astimezone()
                + timedelta(hours=interval)
            ).isoformat(timespec="seconds")
            self.schedule_status_label.configure(
                text=f"Next {self.settings['scheduled_scan_type'].lower()} "
                     f"due {self.settings['next_scheduled_scan']}."
            )
        else:
            self.settings["next_scheduled_scan"] = None
            self.schedule_status_label.configure(
                text="Scheduled scans are disabled."
            )

        self._save_settings()
        self._record_event(
            "schedule_updated",
            (
                f"Scheduled scanning "
                f"{'enabled' if self.settings['scheduled_scan_enabled'] else 'disabled'}."
            ),
            {
                "enabled": self.settings["scheduled_scan_enabled"],
                "scan_type": self.settings["scheduled_scan_type"],
                "interval_hours": interval,
            }
        )

    def _check_scheduled_scan(self, schedule_next=True):
        if not self.winfo_exists():
            return

        if self.settings.get("scheduled_scan_enabled"):
            next_run = self.settings.get("next_scheduled_scan")
            try:
                due = datetime.fromisoformat(next_run)
                if due.tzinfo is None:
                    due = due.astimezone()
            except (TypeError, ValueError):
                due = datetime.now().astimezone() + timedelta(
                    hours=self.settings.get(
                        "scheduled_scan_interval_hours",
                        24
                    )
                )
                self.settings["next_scheduled_scan"] = due.isoformat(
                    timespec="seconds"
                )
                self._save_settings()

            now = datetime.now().astimezone()
            self.schedule_status_label.configure(
                text=f"Next {self.settings.get('scheduled_scan_type', 'Quick Scan').lower()} "
                     f"due {due.astimezone().strftime('%Y-%m-%d %H:%M %Z')}."
            )
            if now >= due:
                if self.scan_running:
                    next_run = now + timedelta(minutes=5)
                    self.settings["next_scheduled_scan"] = (
                        next_run.isoformat(timespec="seconds")
                    )
                    self._save_settings()
                    self._record_event(
                        "scheduled_scan_deferred",
                        "Scheduled scan deferred because another scan is running."
                    )
                else:
                    scan_type = self.settings.get(
                        "scheduled_scan_type",
                        "Quick Scan"
                    )
                    interval = self.settings.get(
                        "scheduled_scan_interval_hours",
                        24
                    )
                    self.settings["next_scheduled_scan"] = (
                        (now + timedelta(hours=interval)).isoformat(
                            timespec="seconds"
                        )
                    )
                    self._save_settings()
                    self._scheduled_launch = True
                    if scan_type == "Full Scan":
                        self.start_full_scan()
                    else:
                        self.start_quick_scan()

        if schedule_next and self.winfo_exists():
            self.after(30_000, self._check_scheduled_scan)

    def import_signature_file(self):
        if self._signature_import_running or self.scan_running:
            messagebox.showinfo(
                "Scanner Busy",
                "Wait for the current scan or signature operation to finish."
            )
            return
        filename = filedialog.askopenfilename(
            title="Import offline SHA-256 signatures",
            filetypes=[
                ("Threat signatures", "*.txt *.sha256 *.sig"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ]
        )
        if not filename:
            return
        if not messagebox.askyesno(
            "Import Local Signatures",
            "Only import signature data from a source you trust. Merge this "
            "local file into the scanner database? It will not be executed "
            "or uploaded."
        ):
            return

        self._signature_import_running = True
        if hasattr(self, "signature_status_label"):
            self.signature_status_label.configure(
                text="Importing local signatures..."
            )
        threading.Thread(
            target=self._local_signature_import_worker,
            args=(filename,),
            daemon=True,
            name="LocalSignatureImport"
        ).start()

    def _local_signature_import_worker(self, filename):
        try:
            result = import_local_signatures(filename)
            self._queue_ui_event(
                "local_signature_import_result",
                result
            )
        except (OSError, ValueError, UnicodeError) as error:
            self._queue_ui_event(
                "local_signature_import_error",
                str(error)
            )

    def _render_local_signature_import_result(self, result):
        self._signature_import_running = False
        invalid_count = len(result.get("invalid_lines", []))
        if hasattr(self, "signature_status_label"):
            self.signature_status_label.configure(
                text=(
                    f"Imported {result['imported']:,}; "
                    f"{result['total']:,} signatures loaded. "
                    f"Skipped {invalid_count} invalid line(s)."
                )
            )
        verification = result.get(
            "verification",
            "local file import; publisher authenticity was not verified"
        )
        self._record_event(
            "signatures_imported",
            f"Imported {result['imported']} local threat signatures.",
            {**result, "verification": verification}
        )
        self._refresh_local_signature_status()
        self.refresh_threat_intelligence()

    def _render_local_signature_import_error(self, error):
        self._signature_import_running = False
        if hasattr(self, "signature_status_label"):
            self.signature_status_label.configure(
                text=f"Signature import failed: {error}"
            )
        if hasattr(self, "threat_intelligence_status_label"):
            self._render_threat_intelligence_error(error)
        self._record_event(
            "signature_import_failed",
            f"Local signature import failed: {error}"
        )

    def reload_local_signatures(self):
        try:
            database = reload_database()
            self.signature_status_label.configure(
                text=f"{len(database):,} local SHA-256 signatures loaded."
            )
            self._record_event(
                "signatures_reloaded",
                f"Reloaded {len(database):,} local threat signatures."
            )
        except (OSError, UnicodeError) as error:
            self.signature_status_label.configure(
                text=f"Signature reload failed: {error}"
            )
            self._record_event(
                "signature_reload_failed",
                f"Local signature reload failed: {error}"
            )

    def create_backup(self):
        if self._settings_operation_running:
            return
        destination = filedialog.asksaveasfilename(
            title="Save IT Security Scanner backup",
            defaultextension=".zip",
            filetypes=[("Scanner backup", "*.zip")]
        )
        if not destination:
            return

        self._settings_operation_running = True
        self.backup_button.configure(
            state="disabled",
            text="Creating backup..."
        )
        threading.Thread(
            target=self._backup_worker,
            args=(destination,),
            daemon=True
        ).start()

    def _backup_worker(self, destination):
        try:
            archive = self.state_store.create_backup(
                destination,
                self.scanner.quarantine_dir,
                DATABASE_FILE
            )
            self._queue_ui_event("backup_finished", str(archive))
        except Exception as error:
            self._queue_ui_event("backup_error", error)

    def _backup_finished(self, archive):
        self._settings_operation_running = False
        self.backup_button.configure(
            state="normal",
            text="Create backup"
        )
        self.settings_status_label.configure(
            text=f"Backup created: {archive}"
        )
        self._record_event(
            "backup_created",
            f"Created local backup: {archive}"
        )

    def _backup_failed(self, error):
        self._settings_operation_running = False
        self.backup_button.configure(
            state="normal",
            text="Create backup"
        )
        self.settings_status_label.configure(
            text=f"Backup failed: {error}"
        )
        self._record_event("backup_failed", f"Backup failed: {error}")

    def restore_backup(self):
        if self._settings_operation_running:
            return
        if self.scan_running:
            messagebox.showinfo(
                "Scan running",
                "Wait for the current scan to finish before restoring a backup."
            )
            return

        archive = filedialog.askopenfilename(
            title="Restore IT Security Scanner backup",
            filetypes=[("Scanner backup", "*.zip")]
        )
        if not archive:
            return
        if not messagebox.askyesno(
            "Restore backup",
            "Restore settings, history, signatures and quarantined files?\n\n"
            "Existing quarantine files will not be overwritten."
        ):
            return

        self._settings_operation_running = True
        self.restore_button.configure(
            state="disabled",
            text="Restoring..."
        )
        threading.Thread(
            target=self._restore_worker,
            args=(archive,),
            daemon=True
        ).start()

    def _restore_worker(self, archive):
        try:
            result = self.state_store.restore_backup(
                archive,
                self.scanner.quarantine_dir,
                DATABASE_FILE
            )
            self._queue_ui_event("restore_finished", result)
        except Exception as error:
            self._queue_ui_event("restore_error", error)

    def _restore_finished(self, result):
        self._settings_operation_running = False
        self.restore_button.configure(
            state="normal",
            text="Restore backup"
        )
        try:
            self.settings = self.state_store.load_settings()
            self.scanner.set_exclusions(
                self.settings.get("scan_exclusions", [])
            )
            effective_workers = self.scanner.set_max_workers(
                self.settings.get("scan_workers", 4)
            )
            self.scanner.max_file_size = (
                self.settings.get("max_file_size_mb", 100)
                * 1024 * 1024
            )
            self.scan_workers_menu.set(
                str(self.settings.get("scan_workers", 4))
            )
            self.max_file_size_menu.set(
                str(self.settings.get("max_file_size_mb", 100))
            )
            self._refresh_exclusion_table()
            self.appearance_menu.set(
                self.settings.get("appearance", "Dark")
            )
            self.change_appearance(
                self.settings.get("appearance", "Dark"),
                persist=False
            )
            if self.settings.get("resource_monitoring", True):
                self.resource_monitor_switch.select()
            else:
                self.resource_monitor_switch.deselect()
            self.set_resource_monitoring(persist=False)
            if self.settings.get("scheduled_scan_enabled"):
                self.schedule_switch.select()
            else:
                self.schedule_switch.deselect()
            self.schedule_type_menu.set(
                self.settings.get("scheduled_scan_type", "Quick Scan")
            )
            interval_labels = {
                6: "6 hours",
                12: "12 hours",
                24: "24 hours",
                168: "7 days",
            }
            self.schedule_interval_menu.set(
                interval_labels.get(
                    self.settings.get("scheduled_scan_interval_hours", 24),
                    "24 hours"
                )
            )
            self._check_scheduled_scan(schedule_next=False)
            self._refresh_local_signature_status()
            self._refresh_protection_history()
            self.refresh_quarantine()
            self.settings_status_label.configure(
                text=f"Backup restored; {result['restored_files']} file(s) added to quarantine."
            )
            self._record_event(
                "backup_restored",
                f"Restored backup; {result['restored_files']} quarantine file(s) recovered.",
                result
            )
        except Exception as error:
            self._restore_failed(error)

    def _restore_failed(self, error):
        self._settings_operation_running = False
        self.restore_button.configure(
            state="normal",
            text="Restore backup"
        )
        self.settings_status_label.configure(
            text=f"Backup restore failed: {error}"
        )
        self._record_event(
            "backup_restore_failed",
            f"Backup restore failed: {error}"
        )

    def change_appearance(
        self,
        value,
        persist=True
    ):

        mapping = {
            "Dark": "dark",
            "Light": "light",
            "System": "system"
        }

        mode = mapping.get(
            value,
            "dark"
        )

        # Change CustomTkinter appearance
        ctk.set_appearance_mode(
            mode
        )

        # Update native ttk tables
        self.setup_ttk_style()
        self.settings["appearance"] = value
        if persist:
            self._save_settings()


# ==============================================================
# START APPLICATION
# ==============================================================

if __name__ == "__main__":

    app = SecurityScannerUI()

    app.mainloop()