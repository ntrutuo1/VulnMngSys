$ErrorActionPreference = 'Stop'

Set-Location $PSScriptRoot

$reactUiDir = Join-Path $PSScriptRoot 'react-ui'
$pythonExe = 'D:\VulnMngSys\.venv\Scripts\python.exe'
$distExe = Join-Path $PSScriptRoot 'dist\VulnMngSysDesktop.exe'
$buildTag = Get-Date -Format 'yyyyMMdd-HHmmss'
$env:VULNMGN_EXE_NAME = "VulnMngSysDesktop-$buildTag"

Write-Host '[1/3] Building React UI...'
Push-Location $reactUiDir
npm install
npm run build
Pop-Location

Write-Host '[1.5/3] Installing Python requirements...'
& $pythonExe -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')

Write-Host '[1.75/3] Stopping old app and clearing previous exe...'
Get-Process -Name 'VulnMngSysDesktop' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Test-Path $distExe) {
  Remove-Item -Force $distExe -ErrorAction SilentlyContinue
}

Write-Host '[2/3] Building Python exe...'
& $pythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --add-data "rules;rules" `
  --add-data "react-ui/dist;react-ui/dist" `
  main.py

Write-Host "[3/3] Done. Output: dist\$($env:VULNMGN_EXE_NAME).exe"
