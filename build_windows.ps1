$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This build script must be run on Windows."
}

python -m pip install --disable-pip-version-check "pip==25.1.1" "setuptools==75.6.0" "wheel==0.45.1"
if ($LASTEXITCODE -ne 0) {
    throw "Build tooling installation failed."
}

if ($env:ITSS_REQUIREMENT_LOCK) {
    if (-not (Test-Path -LiteralPath $env:ITSS_REQUIREMENT_LOCK)) {
        throw "ITSS_REQUIREMENT_LOCK points to a missing requirements file."
    }
    python -m pip install --disable-pip-version-check --require-hashes --requirement $env:ITSS_REQUIREMENT_LOCK
} else {
    python -m pip install --disable-pip-version-check --requirement requirements.txt
}
if ($LASTEXITCODE -ne 0) {
    throw "Runtime dependency installation failed."
}

python -m pip install ".[credentials,build]"
if ($LASTEXITCODE -ne 0) {
    throw "Credential-storage and build dependency installation failed."
}

python -m PyInstaller --clean --noconfirm ITSecurityScanner.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

Write-Host "Build completed: dist\ITSecurityScanner\ITSecurityScanner.exe"
