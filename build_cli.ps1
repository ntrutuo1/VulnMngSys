$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Set-Location $PSScriptRoot

$rootDir = $PSScriptRoot
$parentDir = Resolve-Path (Join-Path $rootDir '..')
$obfuscatedDir = Join-Path $rootDir 'obfuscated_src'
$distDir = Join-Path $rootDir 'dist'
$rulesDir = Join-Path $rootDir 'rules'
$scriptsDir = Join-Path $rootDir 'scripts'
$msfModulesDir = Join-Path $rootDir 'metasploit_modules'
$pythonExe = Join-Path $parentDir '.venv\Scripts\python.exe'
if (-not (Test-Path $pythonExe)) {
  $pythonExe = 'python'
}
$pythonScriptsDir = Split-Path $pythonExe -Parent
$pyarmorExe = Join-Path $pythonScriptsDir 'pyarmor.exe'
if (-not (Test-Path $pyarmorExe)) {
  $pyarmorExe = 'pyarmor'
}

$exeName = 'VulnMngSysDesktop-CLI'
$finalExe = Join-Path $parentDir "$exeName.exe"

function Invoke-CheckedCommand {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed: $FilePath $($Arguments -join ' ')"
  }
}

Write-Host '[1/4] Preparing Python build tools...'
Invoke-CheckedCommand -FilePath $pythonExe -Arguments @('-m', 'pip', 'install', '--quiet', 'pyarmor', 'pyinstaller', 'pywebview', 'pymetasploit3')

Write-Host '[2/4] Obfuscating CLI sources with PyArmor...'
if (Test-Path $obfuscatedDir) {
  Remove-Item -Recurse -Force $obfuscatedDir
}

Invoke-CheckedCommand -FilePath $pyarmorExe -Arguments @(
  'gen',
  '-O', $obfuscatedDir,
  '-r',
  'cli.py',
  'app_bootstrap',
  'vulnmngsys_app',
  'scripts'
)

$pyarmorRuntime = Get-ChildItem -Path $obfuscatedDir -Directory -Filter 'pyarmor_runtime_*' | Select-Object -First 1
$pyarmorHiddenImportArgs = @()
if ($pyarmorRuntime) {
  $pyarmorHiddenImportArgs = @('--hidden-import', $pyarmorRuntime.Name)
}

Write-Host '[3/4] Packaging CLI executable with PyInstaller...'
if (Test-Path $distDir) {
  Remove-Item -Recurse -Force $distDir
}
if (Test-Path (Join-Path $rootDir 'build')) {
  Remove-Item -Recurse -Force (Join-Path $rootDir 'build')
}

$pyinstallerArgs = @(
  '-m', 'PyInstaller',
  '--noconfirm',
  '--clean',
  '--onefile',
  '--name', $exeName,
  '--paths', $obfuscatedDir,
  '--paths', $rootDir,
  '--hidden-import', 'platform',
  '--hidden-import', 'ctypes',
  '--hidden-import', '_ctypes',
  '--hidden-import', 'uuid',
  '--hidden-import', 'webbrowser',
  '--collect-submodules', 'app_bootstrap',
  '--collect-submodules', 'vulnmngsys_app',
  '--collect-submodules', 'application',
  '--collect-submodules', 'domain',
  '--collect-submodules', 'infrastructure',
  '--collect-submodules', 'pymetasploit3',
  '--hidden-import', 'pymetasploit3',
  '--hidden-import', 'pymetasploit3.msfrpc',
  '--add-data', "${rulesDir};rules",
  '--add-data', "${scriptsDir};scripts",
  '--add-data', "${msfModulesDir};metasploit_modules",
  (Join-Path $obfuscatedDir 'cli.py')
)

if ($pyarmorHiddenImportArgs.Count -gt 0) {
  $pyinstallerArgs += $pyarmorHiddenImportArgs
}

Invoke-CheckedCommand -FilePath $pythonExe -Arguments $pyinstallerArgs

if (-not (Test-Path (Join-Path $distDir "$exeName.exe"))) {
  throw "Expected output not found: $(Join-Path $distDir "$exeName.exe")"
}

if (Test-Path $finalExe) {
  try {
    Remove-Item $finalExe -Force -ErrorAction Stop
  }
  catch {
    Write-Warning "Could not remove existing output '$finalExe': $($_.Exception.Message)"
  }
}

try {
  Copy-Item -Path (Join-Path $distDir "$exeName.exe") -Destination $finalExe -Force -ErrorAction Stop
}
catch {
  Write-Warning "Could not copy '$exeName.exe' to '$finalExe': $($_.Exception.Message)"
  Write-Warning "Keeping the built executable in '$distDir' instead."
}

Write-Host '[4/4] Copying output to deployment folder...'
Write-Host "Build complete: $finalExe"
