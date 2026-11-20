# IT Security Scanner v0.1.0

Initial public release of IT Security Scanner, a Windows desktop utility for
local static file analysis and security review.

## Highlights

- Quick, full, custom-folder, individual-file, and removable-drive scans with
  progress reporting and cooperative cancellation.
- Local SHA-256 signature checks, YARA rules, script indicators, and static PE
  inspection. Scanned files are not executed.
- Findings include severity, confidence, evidence, and recommended actions;
  heuristic results are distinguished from confirmed local signature matches.
- Confirmation-based quarantine with SHA-256 manifests, integrity checks, and
  guarded restoration.
- Local HTML reports, scan history, and a dashboard based on recorded scan
  activity.
- Optional, consent-based hash lookups with VirusTotal and MalwareBazaar.
- Windows installed-software inventory and optional NVD vulnerability lookup.
- User-configurable scan limits and settings.
- Windows one-folder executable build using the included PyInstaller
  configuration.

## Security and privacy

- Files are analyzed locally and are not uploaded by scanning.
- External reputation lookups use the selected file's SHA-256 after
  confirmation; review the providers' terms and privacy policies.
- Quarantine data is stored separately from the executable and is never
  automatically deleted.
- This tool is not a replacement for endpoint protection and cannot guarantee
  a system is clean. Static indicators can produce false positives and cannot
  establish runtime behavior.
- The executable is unsigned. Clean-machine installation and packaged GUI
  acceptance are not claimed.

## Verification

The release report records automated tests, compilation, dependency checks,
and package verification. These checks do not imply clean-machine or full GUI
acceptance.

See [README.md](./README.md) for installation, build instructions, security
limitations, and data handling details.
