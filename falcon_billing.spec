# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for falcon-billing single-file binary."""

from pathlib import Path

block_cipher = None

# Locate package data
pkg_dir = Path("falcon_billing")
web_templates = str(pkg_dir / "web" / "templates")
web_static = str(pkg_dir / "web" / "static")

a = Analysis(
    ["falcon_billing/cli/main.py"],
    pathex=["."],
    binaries=[],
    datas=[
        (web_templates, "falcon_billing/web/templates"),
        (web_static, "falcon_billing/web/static"),
    ],
    hiddenimports=[
        "flask",
        "falconpy",
        "falconpy.hosts",
        "falconpy.sensor_usage",
        "falconpy.flight_control",
        "falconpy.oauth2",
        "falcon_billing.web.app",
        "falcon_billing.web.auth",
        "falcon_billing.credentials",
        "falcon_billing.database",
        "falcon_billing.collector",
        "falcon_billing.billing",
        "falcon_billing.classifier",
        "falcon_billing.ngsiem",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="falcon-billing",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
