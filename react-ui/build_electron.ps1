$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = $PSScriptRoot
$CleanScript = Join-Path $RootDir 'clean_electron_build.ps1'
$BackendBuildScript = Join-Path $RootDir '..\build_backend.ps1'
$ElectronCache = Join-Path $RootDir '.electron-cache'
$ElectronBuilderCache = Join-Path $RootDir '.electron-builder-cache'

Set-Location $RootDir
New-Item -ItemType Directory -Path $ElectronCache, $ElectronBuilderCache -Force | Out-Null
$env:ELECTRON_CACHE = $ElectronCache
$env:ELECTRON_BUILDER_CACHE = $ElectronBuilderCache

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$Label
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE."
  }
}

function Invoke-ElectronBuilder {
  $process = Start-Process `
    -FilePath 'npx.cmd' `
    -ArgumentList @('electron-builder', '--win', '--config', 'electron-builder.yml') `
    -WorkingDirectory $RootDir `
    -NoNewWindow `
    -Wait `
    -PassThru
  return [int]$process.ExitCode
}

Invoke-Checked -FilePath 'npm.cmd' -Arguments @('run', 'build') -Label 'Vite build'
Invoke-Checked -FilePath 'powershell.exe' -Arguments @('-ExecutionPolicy', 'Bypass', '-File', $BackendBuildScript) -Label 'Backend build'
Invoke-Checked -FilePath 'powershell.exe' -Arguments @('-ExecutionPolicy', 'Bypass', '-File', $CleanScript) -Label 'Electron output clean'

$exitCode = Invoke-ElectronBuilder
if ($exitCode -ne 0) {
  Write-Warning "electron-builder failed with exit code $exitCode. Cleaning electron-dist and retrying once."
  Invoke-Checked -FilePath 'powershell.exe' -Arguments @('-ExecutionPolicy', 'Bypass', '-File', $CleanScript) -Label 'Electron output retry clean'
  Start-Sleep -Seconds 2
  $exitCode = Invoke-ElectronBuilder
}

if ($exitCode -ne 0) {
  throw "electron-builder failed with exit code $exitCode after retry."
}
