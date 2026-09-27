# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the self-contained AISRF distribution (onedir, console application).

Build from the repository root with `.venv/bin/python scripts/build_binary.py` (recommended,
adds archives, checksums and a smoke test) or directly with
`python -m PyInstaller --noconfirm --clean packaging/pyinstaller/aisrf.spec`.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

SPEC_DIR = Path(SPECPATH).resolve()  # noqa: F821  (SPECPATH is injected by PyInstaller)
REPO_ROOT = SPEC_DIR.parents[1]
sys.path.insert(0, str(SPEC_DIR))

from manifest import COLLECT_DATA, COLLECT_SUBMODULES, EXCLUDES, HIDDEN_IMPORTS, data_pairs  # noqa: E402

datas = list(data_pairs(REPO_ROOT))
for pkg in COLLECT_DATA:
    datas += collect_data_files(pkg)

hiddenimports = list(HIDDEN_IMPORTS)
for pkg in COLLECT_SUBMODULES:
    hiddenimports += collect_submodules(pkg)

a = Analysis(
    [str(SPEC_DIR / "launcher.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=list(EXCLUDES),
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="aisrf",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="aisrf",
)
