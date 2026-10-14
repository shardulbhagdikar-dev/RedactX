# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for RedactX Windows Desktop Application."""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

project_dir = Path(".").resolve()

a = Analysis(
    [str(project_dir / "redactX" / "app.py")],
    pathex=[str(project_dir)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "sqlite3",
        "json",
        "hashlib",
        "dataclasses",
        "redactX",
        "redactX.models",
        "redactX.detectors",
        "redactX.analysis",
        "redactX.scanner",
        "redactX.redaction",
        "redactX.reports",
        "redactX.storage",
        "redactX.utils",
        "redactX.gui",
        "redactX.gui.views",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "scipy",
        "numpy",
        "pandas",
        "IPython",
        "notebook",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RedactX",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="RedactX",
)
