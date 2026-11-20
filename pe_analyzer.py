import pefile


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
}


def analyze_pe(filepath):

    result = {
        "is_pe": False,
        "imports": [],
        "suspicious_imports": [],
        "sections": [],
        "entropy": [],
        "entry_point": None,
        "errors": []
    }

    pe = None
    try:
        pe = pefile.PE(filepath)

        result["is_pe"] = True

        result["entry_point"] = hex(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        # -----------------------------
        # Sections
        # -----------------------------

        for section in pe.sections:

            name = section.Name.rstrip(
                b"\x00"
            ).decode(
                errors="ignore"
            )

            entropy = section.get_entropy()

            result["sections"].append(name)

            result["entropy"].append({
                "section": name,
                "entropy": round(entropy, 2)
            })

        # -----------------------------
        # Imports
        # -----------------------------

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                dll_name = entry.dll.decode(
                    errors="ignore"
                )

                for imported in entry.imports:

                    if imported.name:

                        api = imported.name.decode(
                            errors="ignore"
                        )

                        result["imports"].append(
                            f"{dll_name}:{api}"
                        )

                        if api in SUSPICIOUS_APIS:

                            result[
                                "suspicious_imports"
                            ].append(
                                f"{dll_name}:{api}"
                            )

    except Exception as e:
        result["errors"].append(
            str(e)
        )
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception as error:
                result["errors"].append(
                    f"Unable to close PE analysis resources: {error}"
                )

    return result