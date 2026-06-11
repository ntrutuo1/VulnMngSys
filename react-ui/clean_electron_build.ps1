$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = $PSScriptRoot
$ElectronDist = Join-Path $RootDir 'electron-dist'
$ProcessNames = @(
  'vulnmngsys-react-ui',
  'VulnMngSysBackend'
)

foreach ($name in $ProcessNames) {
  Get-Process -Name $name -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

if (Test-Path $ElectronDist) {
  Remove-Item -LiteralPath $ElectronDist -Recurse -Force
}
