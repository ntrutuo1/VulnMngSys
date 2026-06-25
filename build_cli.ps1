param(
  [switch]$SkipToolInstall,
  [switch]$Obfuscate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$args = @('-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'build_windows.ps1'), '-CliOnly')
if ($SkipToolInstall) { $args += '-SkipToolInstall' }
if ($Obfuscate) { $args += '-Obfuscate' }

& powershell @args
if ($LASTEXITCODE -ne 0) {
  throw "CLI build failed."
}
