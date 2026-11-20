# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all


customtkinter_data, customtkinter_binaries, customtkinter_hidden = collect_all(
    "customtkinter"
)
keyring_data, keyring_binaries, keyring_hidden = collect_all("keyring")
a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=customtkinter_binaries + keyring_binaries,
    datas=[
        ("known_threats.txt", "."),
        ("yara_rules", "yara_rules"),
    ] + customtkinter_data + keyring_data,
    hiddenimports=customtkinter_hidden + keyring_hidden + ["yara"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ITSecurityScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version="version_info.txt",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ITSecurityScanner",
)
