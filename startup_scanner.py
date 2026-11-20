import os
import re
import winreg


# Extensions that deserve extra attention
SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".ps1",
    ".scr"
}


def extract_file_path(command):

    if not command:
        return None

    command = command.strip()

    # Example:
    # "C:\Program Files\App\App.exe" --background
    quoted = re.search(r'"([^"]+)"', command)

    if quoted:
        return quoted.group(1)

    # Example:
    # C:\Program Files\App\App.exe --background
    match = re.search(
        r'([A-Za-z]:\\[^ ]+\.(?:exe|dll|bat|cmd|vbs|js|ps1|scr))',
        command,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return command.split()[0]


def analyze_startup_entry(name, command, location):

    file_path = extract_file_path(command)

    risk = "Low"
    reasons = []

    if not file_path:

        return {
            "name": name,
            "value": command,
            "location": location,
            "path": "",
            "risk": "Unknown",
            "reason": "Unable to determine program path"
        }

    extension = os.path.splitext(file_path)[1].lower()

    # ------------------------------------------------------
    # SCRIPT FILES
    # ------------------------------------------------------

    if extension in SCRIPT_EXTENSIONS:

        risk = "High"

        reasons.append(
            f"Startup script detected ({extension})"
        )

    # ------------------------------------------------------
    # TEMPORARY LOCATIONS
    # ------------------------------------------------------

    suspicious_locations = [
        "\\temp\\",
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\public\\"
    ]

    lower_path = file_path.lower()

    for suspicious_location in suspicious_locations:

        if suspicious_location in lower_path:

            risk = "High"

            reasons.append(
                "Program is located in a suspicious directory"
            )

            break

    # ------------------------------------------------------
    # POWERSHELL
    # ------------------------------------------------------

    if "powershell" in command.lower():

        risk = "High"

        reasons.append(
            "PowerShell command detected"
        )

    # ------------------------------------------------------
    # COMMAND SCRIPTING
    # ------------------------------------------------------

    if "cmd.exe" in command.lower():

        if risk != "High":
            risk = "Medium"

        reasons.append(
            "Command shell execution detected"
        )

    # ------------------------------------------------------
    # EXECUTABLE
    # ------------------------------------------------------

    if extension == ".exe" and risk == "Low":

        reasons.append(
            "Executable registered for startup"
        )

    # ------------------------------------------------------
    # DEFAULT REASON
    # ------------------------------------------------------

    if not reasons:

        reasons.append(
            "No obvious suspicious characteristics detected"
        )

    return {
        "name": name,
        "value": command,
        "location": location,
        "path": file_path,
        "risk": risk,
        "reason": "; ".join(reasons)
    }


def scan_startup_entries():

    startup_entries = []

    registry_locations = [

        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),

        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        )
    ]

    for hive, key_path in registry_locations:

        try:

            key = winreg.OpenKey(
                hive,
                key_path,
                0,
                winreg.KEY_READ
            )

            index = 0

            while True:

                try:

                    name, value, value_type = winreg.EnumValue(
                        key,
                        index
                    )

                    result = analyze_startup_entry(
                        name,
                        value,
                        key_path
                    )

                    startup_entries.append(result)

                    index += 1

                except OSError:

                    break

            winreg.CloseKey(key)

        except PermissionError:

            continue

        except FileNotFoundError:

            continue

    return startup_entries