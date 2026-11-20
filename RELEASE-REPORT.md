# IT Security Scanner 0.1.0 Release Report

## Release summary

IT Security Scanner is a Windows desktop utility for local static file
analysis, optional hash-only reputation lookup, and conservative software
vulnerability assessment. It does not execute scanned files.

## Windows package

- Version: `0.1.0`
- Build time: `2026-11-20 15:57:08 +05:30`
- Output: `dist\ITSecurityScanner\ITSecurityScanner.exe`
- Executable size: `5,266,100 bytes`
- SHA-256: `565A6A49D7E6062A2D6A99AB62618D5D1B695550CEBCD6E012299863B1C72F68`
- PE subsystem: Windows GUI
- Distribution format: PyInstaller one-folder package

Distribute the complete `dist\ITSecurityScanner` folder, not only the
executable. The application is not code-signed.

## Automated verification

- Automated test suite: `146` passed; `6` skipped.
- `python -m compileall -q .`: passed.
- `python -m pip check`: passed.
- PyInstaller build: passed.
- Windows GUI subsystem and embedded version metadata: verified.
- The package contains CustomTkinter assets, the YARA native module, the
  bundled YARA rule, and the threat database.

Skipped tests include opt-in live integrations and Windows symbolic-link
checks unavailable under the test account's current privileges.

## Acceptance limitations

- Packaged GUI acceptance and clean-machine installation were not performed.
- Acceptance under a different or standard-user account was not performed.
- The executable is unsigned; no code-signing claim is made.
- Live network integrations require explicit opt-in and service credentials.
- This report records automated/package checks only; it is not a claim of
  production readiness.

## Quarantine and privacy

On Windows, the default quarantine directory is
`%LOCALAPPDATA%\ITSecurityScanner\SecurityScanner_Quarantine`. The program
validates ownership, ACLs, records, manifests, and file hashes. It does not
silently take ownership of or migrate an existing directory. Existing data in
the legacy home-directory path remains untouched and requires separate review.
The source repository excludes generated reports, local logs, quarantine
contents, virtual environments, build output, and distribution binaries.
