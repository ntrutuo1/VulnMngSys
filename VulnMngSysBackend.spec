# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['platform', 'ctypes', '_ctypes', 'uuid', 'pymetasploit3', 'pymetasploit3.msfrpc']
hiddenimports += collect_submodules('vulnmngsys_app')
hiddenimports += collect_submodules('pymetasploit3')


a = Analysis(
    ['backend.py'],
    pathex=['D:\\VulnMngSys\\VulnMngSys'],
    binaries=[],
    datas=[('D:\\VulnMngSys\\VulnMngSys\\rules', 'rules'), ('D:\\VulnMngSys\\VulnMngSys\\scripts', 'scripts'), ('D:\\VulnMngSys\\VulnMngSys\\metasploit_modules', 'metasploit_modules')],
    hiddenimports=hiddenimports,
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
    name='VulnMngSysBackend',
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
