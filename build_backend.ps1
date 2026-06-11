param(
  [switch]$SkipToolInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = $PSScriptRoot
$ParentDir = Resolve-Path (Join-Path $RootDir '..')
$DistDir = Join-Path $RootDir 'dist'
$BuildDir = Join-Path $RootDir 'build'
$RulesDir = Join-Path $RootDir 'rules'
$ScriptsDir = Join-Path $RootDir 'scripts'
$MsfModulesDir = Join-Path $RootDir 'metasploit_modules'
$PythonExe = Join-Path $ParentDir '.venv\Scripts\python.exe'
if (-not (Test-Path $PythonExe)) { $PythonExe = 'python' }

Set-Location $RootDir

function Invoke-Checked {
  param([string]$FilePath, [string[]]$Arguments)
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed: $FilePath $($Arguments -join ' ')"
  }
}

function Remove-PathIfExists {
  param([string]$Path)
  if (Test-Path $Path) {
    Remove-Item -Recurse -Force $Path
  }
}

if (-not $SkipToolInstall) {
  Invoke-Checked $PythonExe @('-m', 'pip', 'install', '--quiet', 'pyinstaller', 'pymetasploit3')
}

Remove-PathIfExists (Join-Path $BuildDir 'VulnMngSysBackend')
Remove-PathIfExists (Join-Path $DistDir 'VulnMngSysBackend.exe')

$args = @(
  '-m', 'PyInstaller',
  '--noconfirm',
  '--clean',
  '--onefile',
  '--name', 'VulnMngSysBackend',
  '--paths', $RootDir,
  '--hidden-import', 'platform',
  '--hidden-import', 'ctypes',
  '--hidden-import', '_ctypes',
  '--hidden-import', 'uuid',
  '--hidden-import', 'pymetasploit3',
  '--hidden-import', 'pymetasploit3.msfrpc',
  '--collect-submodules', 'app_bootstrap',
  '--collect-submodules', 'vulnmngsys_app',
  '--collect-submodules', 'application',
  '--collect-submodules', 'domain',
  '--collect-submodules', 'infrastructure',
  '--collect-submodules', 'pymetasploit3',
  '--add-data', "${RulesDir};rules",
  '--add-data', "${ScriptsDir};scripts",
  '--add-data', "${MsfModulesDir};metasploit_modules",
  'backend.py'
)

Invoke-Checked $PythonExe $args

$output = Join-Path $DistDir 'VulnMngSysBackend.exe'
if (-not (Test-Path $output)) {
  throw "Expected output not found: $output"
}

Write-Host "Backend build complete: $output"
