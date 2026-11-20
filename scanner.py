import os
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
import ctypes
from ctypes import wintypes
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from app_state import default_data_directory
from pe_analyzer import analyze_pe
from threat_database import (
    calculate_sha256,
    check_hash,
    get_signature_details,
)
from yara_scanner import YaraScanner 

MAX_SCAN_FINDINGS = 10_000
MEMORY_RESERVE_BYTES = 512 * 1024 * 1024
MEMORY_PER_WORKER_BYTES = 256 * 1024 * 1024
OWNER_RIGHTS_SID = "S-1-3-4"


def _available_memory_bytes():
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        kernel32 = ctypes.windll.kernel32
        kernel32.GlobalMemoryStatusEx.argtypes = [
            ctypes.POINTER(MemoryStatus)
        ]
        kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.ullAvailPhys)

    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        available_pages = os.sysconf("SC_AVPHYS_PAGES")
        return int(page_size * available_pages)
    except (AttributeError, OSError, ValueError):
        return None


# ============================================================
# FILE TYPES
# ============================================================

SUSPICIOUS_EXTENSIONS = {
    ".scr",
    ".pif",
    ".com",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".bat",
    ".cmd",
    ".ps1",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".ps1",
}

PE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".ocx",
}

DOUBLE_EXTENSIONS = {
    ".exe.exe",
    ".pdf.exe",
    ".doc.exe",
    ".docx.exe",
    ".jpg.exe",
    ".jpeg.exe",
    ".png.exe",
    ".txt.exe",
    ".zip.exe",
    ".rar.exe",
    ".mp3.exe",
    ".mp4.exe",
    ".bat.exe",
    ".cmd.exe",
    ".pdf.scr",
    ".jpg.scr",
    ".png.scr",
    ".txt.scr",
}


# ============================================================
# SCRIPT CONTENT PATTERNS
# ============================================================

DANGEROUS_SCRIPT_PATTERNS = {
    "shutdown": (
        30,
        "System shutdown command detected"
    ),

    "shutdown /s": (
        40,
        "Forced system shutdown detected"
    ),

    "shutdown /r": (
        35,
        "System restart command detected"
    ),

    "del /f": (
        25,
        "Forced file deletion command detected"
    ),

    "del /s": (
        25,
        "Recursive file deletion command detected"
    ),

    "rmdir /s": (
        25,
        "Recursive directory deletion detected"
    ),

    "rd /s": (
        25,
        "Recursive directory deletion detected"
    ),

    "format ": (
        40,
        "Disk formatting command detected"
    ),

    "diskpart": (
        30,
        "Disk partition management command detected"
    ),

    "powershell": (
        10,
        "PowerShell command detected"
    ),

    "invoke-expression": (
        30,
        "PowerShell expression execution detected"
    ),

    "iex ": (
        30,
        "PowerShell IEX execution detected"
    ),

    "downloadstring": (
        35,
        "Remote content download detected"
    ),

    "downloadfile": (
        30,
        "File download operation detected"
    ),

    "wscript": (
        15,
        "Windows Script Host detected"
    ),

    "cscript": (
        15,
        "Command-line script host detected"
    ),

    "reg add": (
        15,
        "Registry modification detected"
    ),

    "reg delete": (
        20,
        "Registry deletion detected"
    ),

    "currentversion\\run": (
        20,
        "Windows Run-key persistence reference detected"
    ),

    "schtasks /create": (
        20,
        "Scheduled-task creation command detected"
    ),

    "sc create": (
        20,
        "Windows service creation command detected"
    ),

    "new-service": (
        20,
        "PowerShell service creation command detected"
    ),

    "register-scheduledtask": (
        20,
        "PowerShell scheduled-task registration detected"
    ),

    "net stop windefend": (
        40,
        "Windows Defender service stop detected"
    ),

    "sc stop windefend": (
        40,
        "Windows Defender service stop detected"
    ),

    "set-mppreference": (
        30,
        "Windows Defender configuration modification detected"
    ),

    "net user": (
        15,
        "Windows user-account command detected"
    ),

    "net localgroup": (
        20,
        "Windows local-group modification detected"
    ),
}


# ============================================================
# SECURITY SCANNER
# ============================================================

class SecurityScanner:

    def __init__(
        self,
        quarantine_dir=None,
        max_file_size=100 * 1024 * 1024,
        max_workers=None
    ):

        self.quarantine_recovery_errors = []
        environment_directory = os.environ.get("ITSS_QUARANTINE_DIR")
        using_default_directory = not quarantine_dir and not environment_directory
        configured_directory = quarantine_dir or environment_directory
        if using_default_directory:
            configured_directory = (
                default_data_directory() / "SecurityScanner_Quarantine"
            )
        self.legacy_quarantine_notice = None
        legacy_directory = Path.home() / "SecurityScanner_Quarantine"
        if (
            os.path.normcase(os.path.abspath(legacy_directory))
            != os.path.normcase(os.path.abspath(configured_directory))
            and (
                legacy_directory.exists()
                or legacy_directory.is_symlink()
                or (
                    hasattr(legacy_directory, "is_junction")
                    and legacy_directory.is_junction()
                )
            )
        ):
            self.legacy_quarantine_notice = (
                f"An existing quarantine directory was found at "
                f"{legacy_directory}. It has not been moved or changed. "
                f"This application uses {configured_directory}; review and "
                "migrate any existing records before removing the old folder."
            )
            self.quarantine_recovery_errors.append(
                self.legacy_quarantine_notice
            )
        self.quarantine_dir = self._validate_quarantine_location(
            configured_directory
        )
        user_sid = (
            self._get_windows_user_sid()
            if os.name == "nt"
            else None
        )
        directory_created = self._create_quarantine_directory(user_sid)
        self._secure_quarantine_directory(directory_created, user_sid)
        self.yara_scanner = YaraScanner()
        self.excluded_paths = set()
        self.max_file_size = max(1, int(max_file_size))
        default_workers = min(4, max(1, os.cpu_count() or 1))
        self.set_max_workers(
            default_workers if max_workers is None else max_workers
        )
        self._cancel_event = threading.Event()

    def set_max_workers(self, max_workers):
        requested_workers = int(max_workers)
        self.requested_max_workers = max(
            1,
            min(16, requested_workers, os.cpu_count() or 1)
        )
        available_memory = _available_memory_bytes()
        if available_memory is None:
            memory_worker_limit = 1
        else:
            memory_worker_limit = max(
                1,
                (available_memory - MEMORY_RESERVE_BYTES)
                // MEMORY_PER_WORKER_BYTES
            )
        self.max_workers = min(
            self.requested_max_workers,
            memory_worker_limit
        )
        return self.max_workers

    def cancel(self):
        self._cancel_event.set()

    def reset_cancel(self):
        self._cancel_event.clear()

    def is_cancelled(self):
        return self._cancel_event.is_set()

    @staticmethod
    def _validate_quarantine_location(directory):
        try:
            path = Path(directory).expanduser()
        except (TypeError, ValueError, OSError) as error:
            raise OSError("Invalid quarantine directory path.") from error
        if not path.is_absolute():
            raise OSError("Quarantine directory path must be absolute.")

        normalized = Path(os.path.abspath(path))
        if normalized == Path(normalized.anchor):
            raise OSError("A filesystem root cannot be used for quarantine.")
        if os.path.normcase(str(normalized)) == os.path.normcase(
            str(Path.home().resolve())
        ):
            raise OSError("The user profile directory cannot be used for quarantine.")
        if normalized.is_symlink() or (
            hasattr(normalized, "is_junction") and normalized.is_junction()
        ):
            raise OSError("Quarantine directory cannot be a symbolic link or junction.")
        resolved = normalized.resolve(strict=False)
        if os.path.normcase(str(resolved)) != os.path.normcase(
            str(normalized)
        ):
            raise OSError(
                "Quarantine path resolves through a symbolic link or junction."
            )
        if normalized.exists() and not normalized.is_dir():
            raise OSError("Quarantine location exists but is not a directory.")
        if normalized.exists():
            resolved = normalized.resolve(strict=True)
            if os.path.normcase(str(resolved)) != os.path.normcase(
                str(normalized)
            ):
                raise OSError(
                    "Quarantine path resolves to a different location; "
                    "symbolic links and junctions are not allowed."
                )
            return resolved
        return normalized

    def _create_quarantine_directory(self, user_sid=None):
        try:
            if os.name == "nt":
                if user_sid is None:
                    raise OSError(
                        "Unable to verify the current Windows user before "
                        "creating quarantine storage."
                    )
                self.quarantine_dir.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )
                created = self._create_windows_quarantine_directory(
                    self.quarantine_dir,
                    user_sid
                )
                self.quarantine_dir = self._validate_quarantine_location(
                    self.quarantine_dir
                )
                return created
            self.quarantine_dir.mkdir(parents=True, exist_ok=False)
            return True
        except FileExistsError:
            if not self.quarantine_dir.is_dir():
                raise OSError("Quarantine location exists but is not a directory.")
            return False
        except OSError as error:
            raise OSError(
                f"Unable to create quarantine directory "
                f"{self.quarantine_dir}: {error}"
            ) from error

    @staticmethod
    def _quarantine_directory_sddl(user_sid):
        return (
            f"O:{user_sid}D:P"
            f"(A;OICI;FA;;;{user_sid})"
            "(A;OICI;FA;;;S-1-5-18)"
        )

    @staticmethod
    def _create_windows_quarantine_directory(path, user_sid):
        class SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL),
            ]

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        security_descriptor = ctypes.c_void_p()
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            wintypes.BOOL
        )
        kernel32.CreateDirectoryW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(SecurityAttributes),
        ]
        kernel32.CreateDirectoryW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        sddl = SecurityScanner._quarantine_directory_sddl(user_sid)
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            1,
            ctypes.byref(security_descriptor),
            None
        ):
            raise OSError(
                "Unable to prepare a current-user quarantine security "
                f"descriptor (Windows error {ctypes.get_last_error()})."
            )

        try:
            attributes = SecurityAttributes(
                ctypes.sizeof(SecurityAttributes),
                security_descriptor,
                False
            )
            if kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                return True

            error_code = ctypes.get_last_error()
            if error_code in {80, 183}:
                if not Path(path).is_dir():
                    raise OSError(
                        "Quarantine location exists but is not a directory."
                    )
                return False
            raise OSError(
                f"Unable to create quarantine directory {path} "
                f"(Windows error {error_code})."
            )
        finally:
            kernel32.LocalFree(security_descriptor)

    def _secure_quarantine_directory(
        self,
        directory_created=False,
        user_sid=None
    ):
        sid = None
        if os.name == "nt":
            sid = user_sid or self._get_windows_user_sid()
            owner_sid, _ = self._get_windows_owner_and_acl(self.quarantine_dir)
            if owner_sid != sid:
                raise OSError(
                    "Quarantine directory ownership could not be verified for "
                    f"the current user (owner {owner_sid}, expected {sid}). "
                    "Do not change its permissions automatically. Set "
                    "ITSS_QUARANTINE_DIR to a new, dedicated user-owned directory "
                    "or follow the documented migration procedure."
                )
        self._validate_existing_quarantine_entries(
            sid,
            newly_created=directory_created
        )
        self._inspect_quarantine_storage()

        if os.name != "nt":
            return
        self._apply_quarantine_acl(self.quarantine_dir, sid, directory=True)
        self._verify_quarantine_acl(self.quarantine_dir, sid)

    @staticmethod
    def _get_windows_user_sid():
        try:
            identity = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise OSError(
                f"Unable to verify the current Windows user: {error}"
            ) from error
        sid_match = re.search(r"\bS-\d-\d+(?:-\d+)+\b", identity)
        if not sid_match:
            raise OSError("Unable to determine the current Windows user SID.")
        return sid_match.group(0)

    @staticmethod
    def _get_windows_owner_and_acl(path):
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        void_pointer = ctypes.c_void_p
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(void_pointer),
            ctypes.POINTER(void_pointer),
            ctypes.POINTER(void_pointer),
            ctypes.POINTER(void_pointer),
            ctypes.POINTER(void_pointer),
        ]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetSecurityDescriptorControl.argtypes = [
            void_pointer,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        advapi32.GetAclInformation.argtypes = [
            void_pointer,
            void_pointer,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        advapi32.GetAclInformation.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = [
            void_pointer,
            wintypes.DWORD,
            ctypes.POINTER(void_pointer),
        ]
        advapi32.GetAce.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [void_pointer]
        kernel32.LocalFree.restype = void_pointer
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = advapi32.GetNamedSecurityInfoW(
            str(path),
            1,
            0x00000001 | 0x00000004,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor)
        )
        if result:
            raise OSError(
                f"Unable to verify quarantine ownership and permissions "
                f"(Windows error {result})."
            )

        try:
            owner_sid = SecurityScanner._sid_to_string(owner)
            if not dacl:
                raise OSError("Quarantine directory has no access-control list.")

            class AclSizeInformation(ctypes.Structure):
                _fields_ = [
                    ("AceCount", wintypes.DWORD),
                    ("AclBytesInUse", wintypes.DWORD),
                    ("AclBytesFree", wintypes.DWORD),
                ]

            class SecurityDescriptorControl(ctypes.Structure):
                _fields_ = [
                    ("control", wintypes.WORD),
                    ("revision", wintypes.DWORD),
                ]

            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision)
            ):
                raise OSError("Unable to inspect quarantine ACL inheritance.")
            acl_info = AclSizeInformation()
            if not advapi32.GetAclInformation(
                dacl,
                ctypes.byref(acl_info),
                ctypes.sizeof(acl_info),
                2
            ):
                raise OSError("Unable to inspect quarantine ACL entries.")

            allowed_sids = set()
            for index in range(acl_info.AceCount):
                ace = ctypes.c_void_p()
                if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                    raise OSError("Unable to inspect a quarantine ACL entry.")
                ace_type = ctypes.cast(
                    ace,
                    ctypes.POINTER(ctypes.c_ubyte)
                ).contents.value
                if ace_type != 0:
                    raise OSError(
                        "Quarantine ACL contains an unsupported or unsafe "
                        f"entry type ({ace_type})."
                    )
                sid_pointer = ctypes.c_void_p(ace.value + 8)
                allowed_sids.add(SecurityScanner._sid_to_string(sid_pointer))

            return owner_sid, {
                "protected": bool(control.value & 0x1000),
                "allowed_sids": allowed_sids,
            }
        finally:
            if descriptor:
                kernel32.LocalFree(descriptor)

    @staticmethod
    def _sid_to_string(sid):
        value = wintypes.LPWSTR()
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if not advapi32.ConvertSidToStringSidW(
            sid,
            ctypes.byref(value)
        ):
            raise OSError("Unable to convert a Windows security identifier.")
        try:
            return value.value
        finally:
            kernel32.LocalFree(ctypes.cast(value, ctypes.c_void_p))

    def _verify_quarantine_acl(self, path, user_sid):
        owner_sid, acl = self._get_windows_owner_and_acl(path)
        if owner_sid != user_sid:
            raise OSError("Quarantine object owner changed during setup.")
        allowed = {
            user_sid,
            "S-1-5-18",
            "S-1-5-32-544",
            OWNER_RIGHTS_SID,
        }
        required = {user_sid, "S-1-5-18"}
        if (
            not acl["protected"]
            or not required.issubset(acl["allowed_sids"])
            or not acl["allowed_sids"].issubset(allowed)
        ):
            raise OSError(
                "Quarantine permissions are not restricted to the current "
                "user, Local System, and built-in Administrators. Review the "
                "ACL manually; the application will not reset it."
            )

    @staticmethod
    def _apply_quarantine_acl(path, sid, directory=False):
        inheritance = "(OI)(CI)F" if directory else "F"
        try:
            result = subprocess.run(
                [
                    "icacls.exe",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"*{sid}:{inheritance}",
                    f"*S-1-5-18:{inheritance}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise OSError(
                f"Unable to apply restrictive quarantine permissions "
                f"without resetting the existing ACL: {error}"
            ) from error
        if result.returncode:
            raise OSError(
                "Unable to apply restrictive quarantine permissions "
                "without resetting the existing ACL: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def _validate_existing_quarantine_entries(
        self,
        user_sid,
        newly_created=False
    ):
        allowed_sids = {
            user_sid,
            "S-1-5-18",
            "S-1-5-32-544",
            OWNER_RIGHTS_SID,
        }
        entries = list(self.quarantine_dir.iterdir())
        if newly_created and entries:
            raise OSError(
                "Files appeared in the new quarantine directory during setup; "
                "no files were changed."
            )
        for path in entries:
            if path.is_symlink() or (
                hasattr(path, "is_junction") and path.is_junction()
            ):
                raise OSError(
                    f"Unsafe symbolic link or junction in quarantine: {path.name}"
                )
            if not path.is_file():
                raise OSError(
                    f"Unexpected directory or non-file in quarantine: {path.name}"
                )
            if not re.fullmatch(
                r"[0-9a-f]{32}\.(?:quarantine|json)",
                path.name
            ):
                raise OSError(
                    f"Unexpected file in quarantine: {path.name}. "
                    "Existing data was left untouched."
                )

            if os.name == "nt":
                owner_sid, acl = self._get_windows_owner_and_acl(path)
                required = {user_sid, "S-1-5-18"}
                if (
                    owner_sid != user_sid
                    or not required.issubset(acl["allowed_sids"])
                    or not acl["allowed_sids"].issubset(allowed_sids)
                ):
                    raise OSError(
                        f"Ownership or permissions could not be verified for "
                        f"quarantine record {path.name}."
                    )

    def _inspect_quarantine_storage(self):
        files = list(self.quarantine_dir.iterdir())
        manifests = {
            path.stem: path
            for path in files
            if path.suffix == ".json"
        }
        objects = {
            path.stem: path
            for path in files
            if path.suffix == ".quarantine"
        }

        for identifier, manifest_path in manifests.items():
            object_path = objects.get(identifier)
            if object_path is None:
                self.quarantine_recovery_errors.append(
                    f"Quarantine manifest {manifest_path.name} has no "
                    "matching object; manual recovery is required."
                )
                continue
            try:
                metadata = self.get_quarantine_metadata(object_path)
            except (OSError, ValueError) as error:
                raise OSError(
                    f"Quarantine record {manifest_path.name} is invalid: {error}. "
                    "Existing data was left untouched."
                ) from error
            actual_hash = self.calculate_hash(object_path)
            if actual_hash != metadata["sha256"]:
                raise OSError(
                    f"Quarantine integrity verification failed for "
                    f"{object_path.name}. Existing data was left untouched."
                )
            if metadata["state"] in {"pending", "restoring"}:
                self.quarantine_recovery_errors.append(
                    f"Quarantine operation {metadata['state']} for "
                    f"{object_path.name}; explicit recovery is required."
                )

        for identifier, object_path in objects.items():
            if identifier not in manifests:
                self.quarantine_recovery_errors.append(
                    f"Legacy quarantine object {object_path.name} has no "
                    "manifest; it was preserved."
                )

    def _secure_quarantine_file(self, path):
        if os.name != "nt":
            return
        identity = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        ).stdout
        sid_match = re.search(r"\bS-\d-\d+(?:-\d+)+\b", identity)
        if not sid_match:
            raise OSError("Unable to determine the current Windows user SID.")
        path = Path(path)
        if path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        ):
            raise OSError("Quarantine objects cannot be symbolic links.")
        sid = sid_match.group(0)
        self._apply_quarantine_acl(path, sid)
        self._verify_quarantine_acl(path, sid)

    def _manifest_path(self, quarantine_path):
        return Path(quarantine_path).with_suffix(".json")

    def _write_quarantine_manifest(self, manifest_path, metadata):
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".quarantine-manifest-",
            suffix=".tmp",
            dir=self.quarantine_dir
        )
        try:
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n"
            ) as file:
                json.dump(metadata, file, ensure_ascii=False, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            if os.name == "nt":
                self._secure_quarantine_file(temporary_name)
            os.replace(temporary_name, manifest_path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

    def get_quarantine_metadata(self, filepath):
        path = self._validated_quarantine_path(filepath)
        manifest_path = self._manifest_path(path)
        if not manifest_path.exists():
            return {
                "id": path.stem,
                "state": "legacy",
                "original_name": path.name,
                "original_path": "",
                "sha256": self.calculate_hash(path),
            }
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("Quarantine metadata is an unsafe file.")
        try:
            with manifest_path.open("r", encoding="utf-8") as file:
                metadata = json.load(file)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("Quarantine metadata is corrupted or unreadable.") from error
        if (
            not isinstance(metadata, dict)
            or metadata.get("id") != path.stem
            or metadata.get("state") not in {
                "pending",
                "quarantined",
                "restoring",
                "integrity_error",
            }
            or not isinstance(metadata.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
            or not isinstance(metadata.get("original_name"), str)
        ):
            raise ValueError("Quarantine metadata has an invalid structure.")
        return metadata

    def _validated_quarantine_path(self, filepath):
        try:
            path = Path(filepath)
        except (TypeError, ValueError, OSError) as error:
            raise ValueError("Invalid quarantine file path.") from error
        quarantine_root = self.quarantine_dir.resolve(strict=True)
        if path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        ):
            raise ValueError("Symbolic links cannot be used as quarantine objects.")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ValueError("Quarantine object does not exist or is inaccessible.") from error
        if resolved.parent != quarantine_root or not resolved.is_file():
            raise ValueError("Selected file is not a regular quarantine object.")
        return resolved

    def _recover_quarantine_operations(self):
        for manifest_path in self.quarantine_dir.glob("*.json"):
            try:
                if manifest_path.is_symlink():
                    raise ValueError("Symbolic-link metadata was found.")
                quarantine_path = manifest_path.with_suffix(".quarantine")
                with manifest_path.open("r", encoding="utf-8") as file:
                    metadata = json.load(file)
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("id") != manifest_path.stem
                    or metadata.get("state") not in {
                        "pending",
                        "quarantined",
                        "restoring",
                        "integrity_error",
                    }
                    or not isinstance(metadata.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
                ):
                    raise ValueError("Quarantine metadata has an invalid structure.")
                state = metadata["state"]
                if state == "pending":
                    if quarantine_path.exists():
                        actual_hash = self.calculate_hash(quarantine_path)
                        metadata["state"] = (
                            "quarantined"
                            if actual_hash == metadata["sha256"]
                            else "integrity_error"
                        )
                        self._write_quarantine_manifest(
                            manifest_path,
                            metadata
                        )
                    elif (
                        isinstance(metadata.get("original_path"), str)
                        and Path(metadata["original_path"]).is_file()
                    ):
                        manifest_path.unlink()
                elif state == "restoring":
                    destination = Path(metadata.get("restore_destination", ""))
                    if (
                        metadata.get("restore_destination")
                        and
                        destination.is_file()
                        and not destination.is_symlink()
                        and self.calculate_hash(destination) == metadata["sha256"]
                        and not quarantine_path.exists()
                    ):
                        manifest_path.unlink()
                    elif quarantine_path.is_file():
                        metadata["state"] = "quarantined"
                        metadata.pop("restore_destination", None)
                        self._write_quarantine_manifest(
                            manifest_path,
                            metadata
                        )
                        if destination.exists():
                            self.quarantine_recovery_errors.append(
                                f"Interrupted restore left an additional destination "
                                f"for {quarantine_path.name}; review both copies."
                            )
                    else:
                        self.quarantine_recovery_errors.append(
                            f"Interrupted restore needs manual recovery for "
                            f"{quarantine_path.name}."
                        )
                elif state in {"quarantined", "integrity_error"}:
                    if quarantine_path.is_file():
                        actual_hash = self.calculate_hash(quarantine_path)
                        if actual_hash != metadata["sha256"]:
                            metadata["state"] = "integrity_error"
                            self._write_quarantine_manifest(
                                manifest_path,
                                metadata
                            )
                    else:
                        self.quarantine_recovery_errors.append(
                            f"Quarantine object is missing for {manifest_path.name}."
                        )
                if metadata["state"] == "integrity_error":
                    self.quarantine_recovery_errors.append(
                        f"Quarantine integrity check failed for {quarantine_path.name}."
                    )
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                self.quarantine_recovery_errors.append(
                    f"{manifest_path.name}: {error}"
                )

    def recover_quarantine_operations(self):
        """Explicitly reconcile interrupted quarantine operations.

        Back up the entire quarantine directory before calling this method.
        Unlike startup inspection, recovery may update or remove manifests
        after validating the corresponding files and hashes.
        """
        self.quarantine_recovery_errors.clear()
        self._recover_quarantine_operations()
        self._inspect_quarantine_storage()
        return list(self.quarantine_recovery_errors)

    def set_exclusions(self, paths):
        exclusions = set()
        for path in paths:
            if not str(path).strip():
                continue
            exclusions.add(self._normalized_path(path))
        self.excluded_paths = exclusions

    @staticmethod
    def _normalized_path(path):
        return os.path.normcase(
            os.path.abspath(
                os.path.expanduser(os.fspath(path))
            )
        )

    def _is_excluded(self, path):
        normalized = self._normalized_path(path)
        if normalized == self._normalized_path(self.quarantine_dir):
            return True

        for excluded in self.excluded_paths:
            if (
                normalized == excluded
                or normalized.startswith(
                    excluded.rstrip(os.sep) + os.sep
                )
            ):
                return True

        return False

    @staticmethod
    def identify_file_type(filepath):
        """Identify common file types from magic bytes, not only the extension."""
        try:
            with open(filepath, "rb") as file:
                header = file.read(512)
        except (PermissionError, OSError):
            return "Unknown"

        if header.startswith(b"MZ"):
            return "Windows PE executable"
        if header.startswith(b"\x7fELF"):
            return "ELF executable"
        if header.startswith(b"%PDF-"):
            return "PDF document"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG image"
        if header.startswith(b"\xff\xd8\xff"):
            return "JPEG image"
        if header.startswith(b"PK\x03\x04"):
            return "ZIP archive"
        if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE compound document"
        if header.startswith((b"#!/", b"@echo ", b"::")):
            return "Script"
        return "Unknown"

    # ========================================================
    # SHA-256 HASH
    # ========================================================

    def calculate_hash(self, filepath):

        try:

            result = calculate_sha256(filepath)

            if result:
                return result

        except Exception:
            pass

        try:

            sha256 = hashlib.sha256()

            with open(
                filepath,
                "rb"
            ) as file:

                while True:

                    chunk = file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    sha256.update(chunk)

            return sha256.hexdigest()

        except (
            PermissionError,
            OSError
        ):

            return None


    # ========================================================
    # READ SCRIPT CONTENT
    # ========================================================

    def read_script_content(self, filepath):

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            # Maximum 1 MB.
            # The script is only read, never executed.
            return file.read(1024 * 1024)


    # ========================================================
    # ANALYZE SCRIPT
    # ========================================================

    def _strip_script_comments(self, content, extension):

        extension = (extension or "").lower()

        if extension in {".ps1"}:
            line_markers = ("#",)
            block_markers = (("<#", "#>"),)
            quote_chars = {"'", '"'}
        elif extension in {".js", ".jse", ".hta"}:
            line_markers = ("//",)
            block_markers = (("/*", "*/"), ("<!--", "-->"))
            quote_chars = {"'", '"', "`"}
        elif extension in {".vbs", ".vbe"}:
            line_markers = ("'",)
            block_markers = ()
            quote_chars = {'"'}
        elif extension in {".wsf", ".wsh"}:
            line_markers = ("'",)
            block_markers = (("<!--", "-->"),)
            quote_chars = {'"'}
        elif extension in {".bat", ".cmd"}:
            line_markers = ()
            block_markers = ()
            quote_chars = {'"'}
        else:
            return content

        output = []
        index = 0
        quote = None
        block_end = None
        line_has_code = False
        batch_command_start = True

        while index < len(content):
            char = content[index]

            if block_end:
                if content.startswith(block_end, index):
                    index += len(block_end)
                    block_end = None
                    continue
                if char == "\n":
                    output.append(char)
                    line_has_code = False
                    batch_command_start = True
                index += 1
                continue

            if quote:
                output.append(char)
                if char == "\\" and extension in {".js", ".jse", ".hta"}:
                    if index + 1 < len(content):
                        output.append(content[index + 1])
                        index += 2
                        continue
                elif (
                    char == quote
                    and extension in {".vbs", ".vbe", ".wsf", ".wsh"}
                    and content[index:index + 2] == quote * 2
                ):
                    output.append(content[index + 1])
                    index += 2
                    continue
                elif (
                    char == quote == "'"
                    and extension == ".ps1"
                    and content[index:index + 2] == "''"
                ):
                    output.append(content[index + 1])
                    index += 2
                    continue
                elif char == "`" and extension == ".ps1":
                    if index + 1 < len(content):
                        output.append(content[index + 1])
                        index += 2
                        continue
                elif char == quote:
                    quote = None
                index += 1
                continue

            block_start = next(
                (
                    (start, end)
                    for start, end in block_markers
                    if content.startswith(start, index)
                ),
                None
            )

            if block_start:
                block_end = block_start[1]
                index += len(block_start[0])
                continue

            comment_start = None

            if extension in {".bat", ".cmd"}:
                if (
                    content.startswith("::", index)
                    and not line_has_code
                ):
                    comment_start = index
                elif (
                    content[index:index + 3].lower() == "rem"
                    and batch_command_start
                    and (
                        index + 3 == len(content)
                        or content[index + 3].isspace()
                    )
                ):
                    comment_start = index
            else:
                comment_start = next(
                    (
                        index
                        for marker in line_markers
                        if content.startswith(marker, index)
                    ),
                    None
                )

            if comment_start is not None:
                newline = content.find("\n", index)
                if newline == -1:
                    break
                output.append("\n")
                index = newline + 1
                line_has_code = False
                batch_command_start = True
                continue

            if char in quote_chars:
                quote = char
                if extension in {".bat", ".cmd"}:
                    line_has_code = True
                    batch_command_start = False
            elif char == "\n":
                line_has_code = False
                batch_command_start = True
            elif extension in {".bat", ".cmd"} and not char.isspace():
                if char in "&|":
                    batch_command_start = True
                else:
                    line_has_code = True
                    batch_command_start = False

            output.append(char)
            index += 1

        return "".join(output)

    def analyze_script(self, content, extension=None):

        """
        Static script analysis.

        The script is NEVER executed.
        """

        content = self._strip_script_comments(content, extension)
        score = 0
        reasons = []

        content_lower = content.lower()
        shutdown_action = bool(
            re.search(
                r"(?<![\w])shutdown\s+/[sr](?!\w)",
                content_lower
            )
        )

        for pattern, (weight, reason) in DANGEROUS_SCRIPT_PATTERNS.items():
            tokens = pattern.strip().split()
            expression = r"(?<![\w])" + r"\s+".join(
                re.escape(token) for token in tokens
            ) + r"(?![\w])"

            if (
                pattern == "shutdown"
                and shutdown_action
            ):
                continue

            if re.search(expression, content_lower):
                score += weight
                reasons.append(reason)

        return score, reasons


    # ========================================================
    # ANALYZE FILE
    # ========================================================

    def analyze_file(self, filepath, analysis_errors=None):

        filepath = str(filepath)

        path = Path(filepath)

        score = 0
        reasons = []
        signal_sources = set()

        detection_type = None
        known_threat = None
        signature_details = None
        pe_result = None

        # ----------------------------------------------------
        # Basic information
        # ----------------------------------------------------

        file_size = path.stat().st_size
        max_file_size = getattr(
            self,
            "max_file_size",
            100 * 1024 * 1024
        )
        if file_size > max_file_size:
            if analysis_errors is not None:
                analysis_errors.append(
                    f"Skipped: file exceeds configured maximum size "
                    f"of {max_file_size} bytes"
                )
            return None

        file_type = self.identify_file_type(filepath)


        extension = path.suffix.lower()

        # ----------------------------------------------------
        # SHA-256
        # ----------------------------------------------------

        file_hash = self.calculate_hash(
            filepath
        )

        if not file_hash:
            raise OSError(
                f"Unable to calculate SHA-256 for {filepath}"
            )


        # ----------------------------------------------------
        # Local known-threat database
        # ----------------------------------------------------

        if file_hash:

            try:
                known_threat = check_hash(file_hash)
                if known_threat:
                    signature_details = get_signature_details(
                        file_hash,
                        known_threat
                    )
            except Exception as error:
                if analysis_errors is None:
                    raise
                analysis_errors.append(
                    f"Threat signature lookup failed: "
                    f"{type(error).__name__}: {error}"
                )

        if known_threat:

            score = 100
            signal_sources.add("signature")

            reasons.append(
                f"Known threat hash: {known_threat}"
            )

            detection_type = "Known Threat"

        # ----------------------------------------------------
        # YARA ANALYSIS
        # ----------------------------------------------------

        yara_matches = []

        try:
            yara_error = getattr(self.yara_scanner, "error", None)
            if yara_error:
                raise RuntimeError(f"YARA engine unavailable: {yara_error}")
            yara_matches = self.yara_scanner.scan_file(
                filepath
            )
        except Exception as error:
            if analysis_errors is None:
                raise
            analysis_errors.append(
                f"YARA analysis failed: {type(error).__name__}: {error}"
            )
            yara_matches = []

        if yara_matches:

            score = max(score, 100)
            signal_sources.add("yara")

            for match in yara_matches:

                rule_name = match.get(
                    "rule",
                    "Unknown YARA rule"
                )

                reasons.append(
                    f"YARA detection: {rule_name}"
                )

            detection_type = "YARA Detection"
        # ----------------------------------------------------
        # SCRIPT ANALYSIS
        # ----------------------------------------------------

        if extension in SCRIPT_EXTENSIONS:

            content = self.read_script_content(
                filepath
            )

            script_score, script_reasons = (
                self.analyze_script(content, extension)
            )

            if script_score > 0:

                score += script_score
                signal_sources.add("script")

                reasons.extend(
                    script_reasons
                )

                if detection_type is None:

                    detection_type = (
                        "Script Heuristic"
                    )


        # ----------------------------------------------------
        # DOUBLE EXTENSION
        # ----------------------------------------------------

        lower_name = path.name.lower()

        for suspicious_double in DOUBLE_EXTENSIONS:

            if lower_name.endswith(
                suspicious_double
            ):

                score += 35
                signal_sources.add("file-name")

                reasons.append(
                    "Suspicious double file extension"
                )

                if detection_type is None:

                    detection_type = (
                        "Filename Heuristic"
                    )

                break


        # ====================================================
        # IMPORTANT FALSE-POSITIVE FIX
        # ====================================================
        #
        # Filename keywords are ONLY checked for files that
        # can potentially execute.
        #
        # Therefore:
        #
        #   hacking.pdf       -> Safe
        #   hacker.pdf        -> Safe
        #   virus.bat         -> Detected
        #   hacker.exe        -> Detected
        #
        # This prevents educational PDFs from being flagged
        # simply because they contain words like "hack".
        # ====================================================

        # ----------------------------------------------------
        # Hidden file
        # ----------------------------------------------------

        try:

            if os.name == "nt":

                import ctypes

                attributes = (
                    ctypes.windll.kernel32.GetFileAttributesW(
                        filepath
                    )
                )

                if (
                    attributes != -1
                    and
                    attributes & 0x2
                ):

                    score += 5
                    signal_sources.add("file-attributes")

                    reasons.append(
                        "Hidden file attribute detected"
                    )

        except Exception:

            pass


        # ----------------------------------------------------
        # Small script
        # ----------------------------------------------------

        if (
            extension in SCRIPT_EXTENSIONS
            and
            file_size < 1024
        ):

            score += 10
            signal_sources.add("script")

            reasons.append(
                "Unusually small script file"
            )


        # ----------------------------------------------------
        # PE ANALYSIS
        # ----------------------------------------------------

        if extension in PE_EXTENSIONS or file_type == "Windows PE executable":

            try:

                pe_result = analyze_pe(
                    filepath
                )

            except Exception as error:
                pe_result = {
                    "errors": [
                        f"PE analysis failed: {type(error).__name__}: {error}"
                    ]
                }

            pe_errors = pe_result.get("errors", []) if pe_result else []
            if pe_errors:
                if analysis_errors is None:
                    raise ValueError("; ".join(str(item) for item in pe_errors))
                analysis_errors.extend(
                    f"PE analysis failed: {item}"
                    for item in pe_errors
                )


            if pe_result:

                # --------------------------------------------
                # Suspicious APIs
                # --------------------------------------------

                suspicious_imports = (
                    pe_result.get(
                        "suspicious_imports",
                        []
                    )
                )

                import_count = len(
                    set(suspicious_imports)
                )


                if import_count >= 4:

                    score += 15
                    signal_sources.add("pe")

                    reasons.append(
                        "Multiple suspicious Windows APIs detected"
                    )

                    if detection_type is None:

                        detection_type = (
                            "PE Heuristic"
                        )


                elif import_count >= 2:

                    score += 8
                    signal_sources.add("pe")

                    reasons.append(
                        "Suspicious Windows APIs detected"
                    )

                    if detection_type is None:

                        detection_type = (
                            "PE Heuristic"
                        )


                # --------------------------------------------
                # Entropy
                # --------------------------------------------

                entropy_values = (
                    pe_result.get(
                        "entropy",
                        []
                    )
                )

                high_entropy = False

                for section in entropy_values:

                    entropy_value = section.get(
                        "entropy",
                        0
                    )

                    if entropy_value >= 7.8:

                        high_entropy = True

                        break


                if high_entropy:

                    score += 10
                    signal_sources.add("pe")

                    reasons.append(
                        "High PE section entropy detected"
                    )

                    if detection_type is None:

                        detection_type = (
                            "PE Heuristic"
                        )


        # ----------------------------------------------------
        # RISK CLASSIFICATION
        # ----------------------------------------------------

        score = min(score, 100)

        if score >= 100:

            risk = "Critical"

        elif score >= 70:

            risk = "High"

        elif score >= 40:

            risk = "Medium"

        elif score >= 20:

            risk = "Low"

        elif score > 0:

            risk = "Informational"

        else:

            risk = "No detection"


        # ----------------------------------------------------
        # SAFE FILE
        # ----------------------------------------------------

        if risk == "No detection":

            return None


        # ----------------------------------------------------
        # DEFAULT DETECTION TYPE
        # ----------------------------------------------------

        if detection_type is None:

            detection_type = (
                "File Heuristic"
            )

        if known_threat:
            classification = "Confirmed malware signature"
            confidence = "Confirmed"
        elif score >= 70 and len(signal_sources) >= 2:
            classification = "Strongly suspicious"
            confidence = "High"
        elif score >= 20:
            classification = "Potentially suspicious"
            confidence = "Medium" if len(set(reasons)) > 1 else "Low"
        else:
            classification = "Informational finding"
            confidence = "Low"

        # ----------------------------------------------------
        # RETURN RESULT
        # ----------------------------------------------------

        return {

            "name": path.name,

            "extension": extension,

            "file_type": file_type,

            "sha256": file_hash,
            "severity": risk,
            "confidence": confidence,
            "classification": classification,
            "detection_category": (
                signature_details["category"]
                if signature_details
                else "YARA rule"
                if yara_matches
                else "heuristic"
            ),
            "signature_classification": (
                signature_details["classification"]
                if signature_details
                else None
            ),
            "detection_source": (
                "SHA-256 signature"
                if known_threat
                else "YARA or static heuristic"
            ),
            "detection_explanation": "; ".join(dict.fromkeys(reasons)),
            "recommended_action": (
                "Quarantine this signature-matched file and investigate."
                if known_threat
                else "Informational only; no action is recommended."
                if classification == "Informational finding"
                else "Review the indicators and verify with trusted sources "
                "before taking action."
            ),
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),

            "path": filepath,

            "risk": risk,

            "risk_score": score,

            "reasons": list(dict.fromkeys(reasons)),

            "size": file_size,

            "hash": file_hash,

            "known_threat": known_threat,

            "detection_type": detection_type,

            "pe_analysis": pe_result,
            
            "yara_matches": yara_matches,
        }


    # ========================================================
    # QUICK SCAN
    # ========================================================

    def quick_scan(self, callback=None):

        locations = []

        home = Path.home()

        desktop = home / "Desktop"

        downloads = home / "Downloads"

        documents = home / "Documents"


        for location in (
            desktop,
            downloads,
            documents
        ):

            if location.exists():

                locations.append(
                    location
                )


        return self._scan_locations(
            locations,
            callback
        )


    # ========================================================
    # FULL SCAN
    # ========================================================

    def full_scan(self, callback=None):

        locations = []

        if os.name == "nt":

            import string

            for drive in string.ascii_uppercase:

                drive_path = Path(
                    f"{drive}:\\"
                )

                if drive_path.exists():

                    locations.append(
                        drive_path
                    )

        else:

            locations.append(
                Path("/")
            )


        return self._scan_locations(
            locations,
            callback
        )


    # ========================================================
    # CUSTOM SCAN
    # ========================================================

    def custom_scan(
        self,
        folder,
        callback=None
    ):

        path = Path(folder)

        if not path.exists():
            raise FileNotFoundError(
                f"Custom scan folder does not exist: {path}"
            )

        if not path.is_dir():
            raise NotADirectoryError(
                f"Custom scan target is not a folder: {path}"
            )


        return self._scan_locations(
            [path],
            callback
        )

    def individual_file_scan(self, filepath, callback=None):
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {path}")
        if not path.is_file():
            raise NotADirectoryError(f"Scan target is not a file: {path}")
        if path.is_symlink():
            raise ValueError("Symbolic links cannot be scanned.")
        return self._scan_locations([path], callback)

    def removable_drive_scan(self, callback=None):
        if os.name != "nt":
            raise NotImplementedError(
                "Removable drive scanning is currently available only on Windows."
            )
        import string
        import ctypes

        drives = []
        drive_errors = []
        kernel32 = ctypes.windll.kernel32
        kernel32.GetLogicalDrives.argtypes = []
        kernel32.GetLogicalDrives.restype = ctypes.c_uint32
        kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetDriveTypeW.restype = ctypes.c_uint32
        logical_mask = kernel32.GetLogicalDrives()
        if not logical_mask:
            raise OSError("Windows could not enumerate logical drives.")
        for drive_letter in string.ascii_uppercase:
            bit = 1 << (ord(drive_letter) - ord("A"))
            if not logical_mask & bit:
                continue
            drive = Path(f"{drive_letter}:\\")
            try:
                drive_type = kernel32.GetDriveTypeW(str(drive))
            except OSError as error:
                drive_errors.append(f"Unable to identify drive {drive}: {error}")
                continue
            if drive_type == 2:
                drives.append(drive)
            elif drive_type in {0, 1}:
                drive_errors.append(
                    f"Windows could not access the root of drive {drive}."
                )
        if not drives:
            if not drive_errors:
                drive_errors.append("No removable drives are currently available.")
            return {
                "scanned": 0,
                "files_scanned": 0,
                "total": 0,
                "suspicious": [],
                "errors": drive_errors[:100],
                "error_count": len(drive_errors),
                "cancelled": False,
                "detection_status": "Incomplete scan",
            }
        result = self._scan_locations(drives, callback)
        if drive_errors:
            result["errors"].extend(drive_errors[:max(0, 100 - len(result["errors"]))])
            result["error_count"] += len(drive_errors)
            result["detection_status"] = "Incomplete scan"
        return result


    # ========================================================
    # SCAN LOCATIONS
    # ========================================================

    def _scan_locations(
        self,
        locations,
        callback=None
    ):
        scanned = 0
        suspicious = []
        errors = []
        error_count = 0
        cancelled = False
        finding_count = 0
        findings_truncated = False

        def walk_error(error):
            nonlocal error_count
            error_count += 1
            if len(errors) < 100:
                errors.append(str(error))

        def report_progress(*values):
            nonlocal error_count
            if not callback:
                return
            try:
                callback(*values)
            except Exception as error:
                error_count += 1
                if len(errors) < 100:
                    errors.append(
                        f"Scan progress callback failed: "
                        f"{type(error).__name__}: {error}"
                    )

        def unique_locations():
            candidates = []
            seen = set()
            for value in locations:
                location = Path(value)
                normalized = self._normalized_path(location)
                if normalized in seen:
                    continue
                seen.add(normalized)
                candidates.append((location, normalized))

            candidates.sort(
                key=lambda item: (
                    len(Path(item[1]).parts),
                    item[1]
                )
            )
            selected_directories = []
            for location, normalized in candidates:
                covered = False
                for directory in selected_directories:
                    try:
                        if os.path.commonpath(
                            (directory, normalized)
                        ) == directory:
                            covered = True
                            break
                    except ValueError:
                        continue
                if covered:
                    continue
                if location.is_dir() and not location.is_symlink():
                    selected_directories.append(normalized)
                yield location

        def candidate_files():
            for location in unique_locations():
                if self.is_cancelled():
                    return
                try:
                    if self._is_excluded(location):
                        continue
                    if location.is_symlink() or (
                        hasattr(location, "is_junction")
                        and location.is_junction()
                    ):
                        continue
                    if location.is_file():
                        yield location
                        continue
                    for root, dirs, filenames in os.walk(
                        location,
                        topdown=True,
                        onerror=walk_error,
                        followlinks=False
                    ):
                        if self.is_cancelled():
                            return
                        dirs[:] = [
                            directory
                            for directory in dirs
                            if not self._is_excluded(Path(root) / directory)
                            and not (Path(root) / directory).is_symlink()
                            and not (
                                hasattr(Path(root) / directory, "is_junction")
                                and (Path(root) / directory).is_junction()
                            )
                        ]
                        for filename in filenames:
                            if self.is_cancelled():
                                return
                            filepath = Path(root) / filename
                            if (
                                self._is_excluded(filepath)
                                or filepath.is_symlink()
                                or (
                                    hasattr(filepath, "is_junction")
                                    and filepath.is_junction()
                                )
                            ):
                                continue
                            yield filepath
                except (PermissionError, OSError) as error:
                    walk_error(error)

        def analyze(filepath):
            analysis_errors = []
            try:
                result = self.analyze_file(
                    filepath,
                    analysis_errors=analysis_errors
                )
                error = None
            except Exception as caught_error:
                result = None
                error = caught_error
            return filepath, result, analysis_errors, error

        iterator = iter(candidate_files())
        pending = set()
        exhausted = False
        max_pending = self.max_workers * 2
        with ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="security-scan"
        ) as executor:
            while pending or not exhausted:
                if self.is_cancelled():
                    cancelled = True
                    exhausted = True
                    for future in pending:
                        future.cancel()

                while (
                    not exhausted
                    and not self.is_cancelled()
                    and len(pending) < max_pending
                ):
                    try:
                        filepath = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    pending.add(executor.submit(analyze, filepath))

                if not pending:
                    break

                completed, pending = wait(
                    pending,
                    return_when=FIRST_COMPLETED
                )
                for future in completed:
                    if future.cancelled():
                        continue
                    filepath, result, analysis_errors, error = future.result()
                    scanned += 1
                    if error is not None:
                        error_count += 1
                        if len(errors) < 100:
                            errors.append(
                                f"{filepath}: {type(error).__name__}: {error}"
                            )
                    if analysis_errors:
                        error_count += len(analysis_errors)
                        if len(errors) < 100:
                            errors.extend(
                                f"{filepath}: {analysis_error}"
                                for analysis_error in analysis_errors[
                                    :100 - len(errors)
                                ]
                            )
                    if result:
                        finding_count += 1
                        if len(suspicious) < MAX_SCAN_FINDINGS:
                            suspicious.append(result)
                        elif not findings_truncated:
                            findings_truncated = True
                            error_count += 1
                            if len(errors) < 100:
                                errors.append(
                                    "Finding detail limit reached; only the "
                                    f"first {MAX_SCAN_FINDINGS:,} finding records "
                                    "are retained. Scan results are incomplete."
                                )
                    report_progress(scanned, 0, str(filepath))
                if self.is_cancelled():
                    cancelled = True

        if not cancelled:
            report_progress(scanned, scanned, "")

        result = {
            "scanned": scanned,
            "files_scanned": scanned,
            "total": scanned,
            "suspicious": suspicious,
            "finding_count": finding_count,
            "findings_truncated": findings_truncated,
            "errors": errors,
            "error_count": error_count,
            "cancelled": cancelled,
            "detection_status": (
                "Incomplete scan"
                if cancelled or error_count
                else "Detections reported"
                if suspicious
                else "No detection reported"
            ),
        }
        self._cancel_event.clear()
        return result


    # ========================================================
    # QUARANTINE FILE
    # ========================================================

    def quarantine_file(self, filepath):
        try:
            source = Path(filepath)
        except (TypeError, ValueError, OSError) as error:
            return {
                "success": False,
                "message": f"Invalid file path: {error}",
            }
        if not source.exists():
            return {"success": False, "message": "File does not exist."}
        if source.is_symlink() or (
            hasattr(source, "is_junction") and source.is_junction()
        ) or not source.is_file():
            return {
                "success": False,
                "message": "Only regular, non-linked files can be quarantined."
            }

        try:
            resolved_source = source.resolve(strict=True)
            resolved_source.relative_to(self.quarantine_dir.resolve(strict=True))
            return {
                "success": False,
                "message": "File is already in quarantine."
            }
        except ValueError:
            pass
        except OSError as error:
            return {"success": False, "message": f"Unable to validate file: {error}"}

        file_hash = self.calculate_hash(source)
        if not file_hash:
            return {
                "success": False,
                "message": "Unable to calculate SHA-256 before quarantine."
            }

        quarantine_id = uuid.uuid4().hex
        destination = self.quarantine_dir / f"{quarantine_id}.quarantine"
        manifest_path = self._manifest_path(destination)
        metadata = {
            "id": quarantine_id,
            "state": "pending",
            "original_path": str(resolved_source),
            "original_name": source.name,
            "sha256": file_hash,
            "quarantined_at": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
        }

        try:
            initial_stat = source.stat()
            self._write_quarantine_manifest(manifest_path, metadata)
            current_stat = source.stat()
            if (
                (initial_stat.st_dev, initial_stat.st_ino, initial_stat.st_size)
                != (current_stat.st_dev, current_stat.st_ino, current_stat.st_size)
            ):
                raise OSError("File changed before quarantine could begin.")
            self._move_file_safely(source, destination)
            self._secure_quarantine_file(destination)
            if self.calculate_hash(destination) != file_hash:
                metadata["state"] = "integrity_error"
                self._write_quarantine_manifest(manifest_path, metadata)
                return {
                    "success": False,
                    "message": (
                        "File was moved to quarantine, but its SHA-256 changed "
                        "during the operation. Do not restore it."
                    ),
                    "quarantine_path": str(destination),
                }
            metadata["state"] = "quarantined"
            self._write_quarantine_manifest(manifest_path, metadata)
            return {
                "success": True,
                "message": f"File quarantined and integrity verified:\n{destination}",
                "original_path": str(resolved_source),
                "quarantine_path": str(destination),
                "sha256": file_hash,
            }
        except (PermissionError, OSError) as error:
            if not destination.exists():
                try:
                    manifest_path.unlink(missing_ok=True)
                except OSError as cleanup_error:
                    self.quarantine_recovery_errors.append(
                        f"Unable to clean pending manifest {manifest_path.name}: "
                        f"{cleanup_error}"
                    )
            return {
                "success": False,
                "message": f"Unable to quarantine file: {error}",
                "quarantine_path": (
                    str(destination) if destination.exists() else None
                ),
            }

    def restore_quarantined_file(self, filepath, destination):
        source = None
        requested_destination = destination
        destination = None
        metadata = None
        manifest_path = None
        try:
            source = self._validated_quarantine_path(filepath)
            metadata = self.get_quarantine_metadata(source)
            if metadata["state"] == "integrity_error":
                raise ValueError("Quarantine integrity verification failed.")
            if metadata["state"] not in {"quarantined", "legacy"}:
                raise ValueError("Quarantine operation is incomplete or in progress.")

            destination = Path(requested_destination)
            if destination.name in {"", ".", ".."}:
                raise ValueError("Choose a valid restore filename.")
            if destination.exists() or destination.is_symlink() or (
                hasattr(destination, "is_junction")
                and destination.is_junction()
            ):
                raise FileExistsError("Restore destination already exists or is linked.")
            if destination.parent.is_symlink() or (
                hasattr(destination.parent, "is_junction")
                and destination.parent.is_junction()
            ):
                raise ValueError("Restore destination folder cannot be a link.")
            destination_parent = destination.parent.resolve(strict=True)
            destination = destination_parent / destination.name
            try:
                destination.relative_to(self.quarantine_dir.resolve(strict=True))
            except ValueError:
                pass
            else:
                raise ValueError("Restore destination must be outside quarantine.")

            expected_hash = metadata.get("sha256")
            if expected_hash and self.calculate_hash(source) != expected_hash:
                raise ValueError("Quarantined file failed SHA-256 integrity verification.")

            manifest_path = self._manifest_path(source)
            if metadata["state"] != "legacy":
                metadata["state"] = "restoring"
                metadata["restore_destination"] = str(destination)
                self._write_quarantine_manifest(manifest_path, metadata)
            self._move_file_safely(source, destination)
            if expected_hash and self.calculate_hash(destination) != expected_hash:
                raise OSError(
                    "Restored file failed SHA-256 verification; recovery is required."
                )
            if metadata["state"] != "legacy":
                try:
                    manifest_path.unlink()
                except OSError as error:
                    self.quarantine_recovery_errors.append(
                        f"Restored file metadata cleanup is pending: {error}"
                    )
            return {
                "success": True,
                "message": f"File restored and integrity verified:\n{destination}",
                "restored_path": str(destination),
                "sha256": expected_hash,
            }
        except (OSError, ValueError, TypeError) as error:
            if (
                source is not None
                and metadata is not None
                and manifest_path is not None
                and metadata.get("state") == "restoring"
            ):
                if not source.exists() and destination is not None and destination.exists():
                    try:
                        self._move_file_safely(destination, source)
                    except OSError as recovery_error:
                        self.quarantine_recovery_errors.append(
                            f"Unable to recover restored file to quarantine "
                            f"{source.name}: {recovery_error}"
                        )
                metadata["state"] = "quarantined"
                metadata.pop("restore_destination", None)
                try:
                    self._write_quarantine_manifest(manifest_path, metadata)
                except OSError as recovery_error:
                    self.quarantine_recovery_errors.append(
                        f"Unable to recover restore manifest "
                        f"{manifest_path.name}: {recovery_error}"
                    )
            return {
                "success": False,
                "message": f"Unable to restore file: {error}"
            }

    @staticmethod
    def _move_file_safely(source, destination):
        try:
            os.link(source, destination)
        except FileExistsError:
            raise
        except OSError:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".scanner-transfer-",
                dir=destination.parent
            )
            temporary = Path(temporary_name)
        else:
            try:
                source.unlink()
            except OSError:
                destination.unlink()
                raise
            return

        destination_created = False
        try:
            with os.fdopen(descriptor, "wb") as target_file:
                with source.open("rb") as source_file:
                    shutil.copyfileobj(
                        source_file,
                        target_file,
                        length=1024 * 1024
                    )
                    target_file.flush()
                    os.fsync(target_file.fileno())
            shutil.copystat(source, temporary)

            try:
                os.link(temporary, destination)
                destination_created = True
            except FileExistsError:
                raise
            except OSError:
                descriptor = os.open(
                    destination,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600
                )
                destination_created = True
                with os.fdopen(descriptor, "wb") as target_file:
                    with temporary.open("rb") as source_file:
                        shutil.copyfileobj(
                            source_file,
                            target_file,
                            length=1024 * 1024
                        )
                    target_file.flush()
                    os.fsync(target_file.fileno())
                shutil.copystat(temporary, destination)

            try:
                source.unlink()
            except OSError:
                destination.unlink()
                destination_created = False
                raise
        except Exception:
            if destination_created:
                try:
                    destination.unlink()
                except OSError:
                    pass
            raise
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


    # ========================================================
    # LIST QUARANTINED FILES
    # ========================================================

    def list_quarantine(self):
        return [
            str(path)
            for path in self.quarantine_dir.iterdir()
            if (
                path.is_file()
                and not path.is_symlink()
                and path.suffix != ".json"
                and not path.name.startswith(".scanner-transfer-")
            )
        ]


    # ========================================================
    # DELETE QUARANTINED FILE
    # ========================================================

    def delete_quarantined_file(
        self,
        filepath
    ):

        try:
            path = self._validated_quarantine_path(filepath)
            metadata = self.get_quarantine_metadata(path)
            if metadata["state"] in {"pending", "restoring"}:
                return False
            path.unlink()
            manifest_path = self._manifest_path(path)
            if manifest_path.exists():
                manifest_path.unlink()
            return True
        except (OSError, ValueError, TypeError):
            return False