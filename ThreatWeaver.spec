# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

block_cipher = None

datas = [
    ('assets/threatweaver.ico', 'assets'),
    ('artifacts/checkpoints/*', 'artifacts/checkpoints'),
    ('samples/*', 'samples'),
]

hiddenimports = [
    'webview',
    'clr',
    'pythonnet',
    'pefile',
    'torch',
    'numpy',
    'sklearn',
    'threatweaver',
    'threatweaver.app',
    'threatweaver.app.server',
    'threatweaver.app.desktop',
    'threatweaver.app.ui_html',
    'threatweaver.scanner',
    'threatweaver.scanner.scan_service',
    'threatweaver.scanner.inference',
    'threatweaver.scanner.signature_verifier',
    'threatweaver.scanner.hash_cache',
    'threatweaver.models',
    'threatweaver.models.classifier',
    'threatweaver.models.encoder',
    'threatweaver.models.novelty',
    'threatweaver.models.calibration',
    'threatweaver.learning',
    'threatweaver.learning.adaptation_service',
    'threatweaver.reporting',
]

a = Analysis(
    ['ThreatWeaver.py'],
    pathex=['.', 'src'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'tkinter', 'pytest', 'IPython'],
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
    name='ThreatWeaver',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='assets/threatweaver.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ThreatWeaver',
)
