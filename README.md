# IT Security Scanner

**Version 0.1.0** is a Windows desktop application for local, static file
analysis and security review. It does not execute scanned files. Detection
results are indicators for investigation, not proof that a file is malicious
or safe.

## Features

- Quick, full, custom-folder, individual-file, and removable-drive scans.
- Cooperative cancellation, per-file progress, and bounded parallel processing with a configurable worker limit.
- Magic-byte file identification, SHA-256 signatures, local YARA rules, script indicators, and static PE inspection.
- Detection output distinguishes confirmed local signature matches from heuristic findings. Heuristics are indicators, not proof.
- Local threat signature import, version and integrity status, and digest-checked local updates.
- Optional, consent-based VirusTotal and MalwareBazaar SHA-256 lookups. The application does not upload files.
- Windows installed-software inventory and optional NVD CVE lookup for a selected inventory entry. This is separate from malware scanning.
- Confirmation-based quarantine, per-object SHA-256 manifests, safe restoration, and interrupted-operation recovery.
- Local HTML scan reports and scan history.

## Requirements

- Windows 10 or later.
- Python 3.10 or later (64-bit recommended).
- `requirements.txt` pins runtime dependencies, including `yara-python`.
- Optional secure API credential storage: `keyring==25.5.0`, installed with
  the `credentials` extra.
- PyInstaller is included in the `build` extra for packaging.

## Installation and run from source

Open PowerShell in the project directory:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

For optional Windows Credential Manager integration:

```powershell
python -m pip install ".[credentials]"
```

If PowerShell activation is unavailable, run the virtual-environment
interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

## Desktop interface

The dark application shell provides Dashboard, File Scanner, Threat Detection,
Quarantine, Vulnerability Assessment, Scan Reports, Settings, and About pages.
The scanner page groups quick, full, custom-folder, single-file, and removable
drive scans while keeping work off the UI thread. Findings show the scanner's
classification, severity, confidence, timestamp, evidence, and recommendation;
cancelled, errored, and truncated results remain visibly incomplete. The
dashboard uses recorded scan activity and current-session findings rather than
invented counts. Report history is read from the user's LocalAppData reports
directory. Scan worker limits and maximum file size are configurable in
Settings.

## Security limitations

- This is not a replacement for Microsoft Defender or a commercial endpoint security product. There is no real-time protection, automatic remediation, or guarantee that a system is clean.
- An empty or outdated signature database is not evidence that a system is clean. The application reports its status.
- Digest verification detects a mismatch only when the expected digest is obtained through a trusted, separate channel. A SHA-256 digest by itself does not authenticate a publisher. Signature updates are imported locally; there is no automatic threat-feed downloader.
- Digitally signed update manifests, a pinned publisher key, and authenticated update-source/version replay protection are not configured. Do not treat digest-checked imports as publisher-authenticated; signed updates remain deferred until an approved source and verification key are established.
- YARA rules are user-supplied/local. Install rules only from sources you trust. If the YARA engine is unavailable, the application reports that state rather than treating it as a clean result.
- Static PE/script indicators can produce false positives and cannot establish runtime behavior. Unknown file type does not mean safe.
- Software-to-CPE matching is conservative and may miss products whose vendor/product naming differs. NVD results depend on network availability and the quality of public CVE/CPE data; verify remediation guidance with the software vendor.
- External reputation services receive the selected file's SHA-256 only, after confirmation. Review provider terms and privacy policies. API keys are stored through the system credential store when the optional `keyring` extra is installed; provider environment variables are also supported.
- Removable-drive discovery is Windows-specific. Inaccessible files/drives are reported as errors; cancelled or errored scans are partial.
- A Windows executable build is produced by the existing build script. Clean-machine installation, standard-user GUI acceptance, and production deployment remain separate verification steps.

## Testing

Run compilation and the automated test suite with:

```powershell
python -m compileall -q .
python -m unittest discover -v
```

Live integration tests are opt-in. Set `ITSS_LIVE_NVD_TEST=1` to contact the public NVD API, or additionally set `ITSS_LIVE_VIRUSTOTAL_TEST=1` / `ITSS_LIVE_MALWAREBAZAAR_TEST=1` with the corresponding API key to perform a SHA-256-only lookup. These tests use a fixed empty-file hash and never upload file contents.

## Dependency hash verification

The runtime and build dependencies are version-pinned. Hash-locked installation is
recommended for offline/reproducible builds. Generate a separate requirements
lock from a trusted package index; do not copy hashes from an unknown source:

```powershell
python -m pip download --dest .\wheelhouse -r requirements.txt
python -m pip download --dest .\wheelhouse ".[credentials,build]"
python -m pip install --require-hashes --no-deps -r requirements.lock.txt
```

The lockfile must contain real SHA-256 values for every package and
transitive dependency selected for the target Python version and architecture.

## Build for Windows

On Windows, run:

```powershell
.\build_windows.ps1
```

The script installs the pinned runtime dependencies, optional credential
storage support, and pinned PyInstaller, then invokes `ITSecurityScanner.spec`.
It creates a one-folder distribution at `dist\ITSecurityScanner`. Distribute
the complete folder, not just the executable. The project does not create an
installer or sign the executable; clean-machine installation, target-Windows
acceptance, and packaged GUI acceptance are separate verification steps and
must not be inferred from a successful build.

## Data, credentials, and quarantine

- The bundled signature list and local YARA rule files are supplied as starter data; keep local intelligence under trusted administrative control. Packaged signature updates are persisted in the user's local application-data directory.
- Settings, scan history, and reputation cache are local to the current user. Reputation cache entries expire and are bounded.
- API credentials are stored with Windows Credential Manager through `keyring` when available. Otherwise, use `VIRUSTOTAL_API_KEY` or `MALWAREBAZAAR_API_KEY`; do not put secrets in source code or settings files.
- Settings, scan history, signatures, reputation cache, generated reports, application logs, and user-installed YARA rules are stored under the current user's local application-data directory. Bundled YARA rules remain read-only application resources.
- Quarantine defaults to `%LOCALAPPDATA%\ITSecurityScanner\SecurityScanner_Quarantine` on Windows (and the application data directory on other platforms). The new Windows directory is created with the current user's SID as owner and a restrictive user/System ACL, then its owner and ACL are verified. Set `ITSS_QUARANTINE_DIR` to an absolute path to select another dedicated directory (for example, a test-only location). The application verifies the directory owner, expected canonical path, and existing record ACLs before restricting directory access. It never takes ownership of an existing directory, resets an existing directory ACL, or changes existing record ACLs during startup. Unexpected files, unsafe ACLs, invalid records, and ownership mismatches fail closed with a startup error. Quarantine data is never deleted automatically.
- Quarantine uses random identifiers and JSON manifests containing the original path, operation state, and SHA-256. Integrity failures block restoration. Restoration and permanent deletion require explicit confirmation.
- Startup and restore workflows validate quarantine ownership and records without resetting existing ACLs. When the old home-directory quarantine location exists, startup reports that it remains untouched and requires review; its contents are not automatically moved into the new location. Make a separate backup of the complete quarantine directory before recovery. Interrupted restore transactions use commit markers and snapshots to recover or remove partial records; rollback failures are reported rather than silently ignored. For a legacy directory whose owner or ACLs cannot be verified, do not change its permissions in place. Launch the prior trusted application, create its backup using **Settings → Create backup**, choose a new empty user-owned quarantine directory (for example, `$env:ITSS_QUARANTINE_DIR = Join-Path $env:LOCALAPPDATA 'ITSecurityScanner\\Quarantine'`), and restore that backup in the application. If the backup contains unexpected quarantine filenames, retain the original backup and have those entries reviewed separately rather than importing them into quarantine. Keep the original directory unchanged until the migrated records and hashes have been verified.
- Backups contain application state, signatures, and quarantined objects; protect backup files as sensitive data.

## Version and release verification

The project version is maintained in `version.py` and `version_info.txt`.
Version 0.1.0 release details and verification status are recorded in
[`RELEASE-REPORT.md`](./RELEASE-REPORT.md); highlights are in
[`RELEASE-NOTES-v0.1.0.md`](./RELEASE-NOTES-v0.1.0.md). Automated tests do not
constitute packaged GUI acceptance or clean-machine verification.

## License

This project is distributed under the MIT License. See [LICENSE](./LICENSE).

## Third-party dependencies and notices

Main runtime dependencies are pinned in `requirements.txt` and mirrored in `pyproject.toml`; optional dependencies are listed under project extras. Review upstream package licenses and include required notices when redistributing a bundled build. This repository does not include a generated third-party license inventory.
