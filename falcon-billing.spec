# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['falcon_billing/cli/main.py'],
    pathex=[],
    binaries=[],
    datas=[('falcon_billing/web/templates', 'falcon_billing/web/templates'), ('falcon_billing/web/static', 'falcon_billing/web/static')],
    hiddenimports=['flask', 'falconpy'],
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
    a.binaries,
    a.datas,
    [],
    name='falcon-billing',
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
