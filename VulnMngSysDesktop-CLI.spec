# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['platform', 'ctypes', '_ctypes', 'uuid', 'webbrowser', 'pymetasploit3', 'pymetasploit3.msfrpc', 'pyarmor_runtime_000000']
hiddenimports += collect_submodules('app_bootstrap')
hiddenimports += collect_submodules('vulnmngsys_app')
hiddenimports += collect_submodules('application')
hiddenimports += collect_submodules('domain')
hiddenimports += collect_submodules('infrastructure')
hiddenimports += collect_submodules('webview')
hiddenimports += collect_submodules('pymetasploit3')


a = Analysis(
    ['D:\\VulnMngSys\\VulnMngSys\\obfuscated_src\\cli.py'],
    pathex=['D:\\VulnMngSys\\VulnMngSys\\obfuscated_src', 'D:\\VulnMngSys\\VulnMngSys'],
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
    name='VulnMngSysDesktop-CLI',
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
