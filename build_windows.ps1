$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Set-Location $PSScriptRoot

$rootDir = $PSScriptRoot
$parentDir = Resolve-Path (Join-Path $rootDir '..')
$reactUiDir = Join-Path $rootDir 'react-ui'
$reactDistDir = Join-Path $reactUiDir 'dist'
$frontendDistDir = Join-Path $rootDir 'vulnmngsys_app\frontend\dist'
$rulesDir = Join-Path $rootDir 'rules'
$scriptsDir = Join-Path $rootDir 'scripts' # Đã thêm biến khai báo thư mục scripts
$obfuscatedDir = Join-Path $rootDir 'obfuscated_src'
$distDir = Join-Path $rootDir 'dist'
$pythonExe = Join-Path $parentDir '.venv\Scripts\python.exe'
if (-not (Test-Path $pythonExe)) {
  $pythonExe = 'python'
}
$pythonScriptsDir = Split-Path $pythonExe -Parent
$pyarmorExe = Join-Path $pythonScriptsDir 'pyarmor.exe'
if (-not (Test-Path $pyarmorExe)) {
  $pyarmorExe = 'pyarmor'
}

$exeName = 'VulnMngSysDesktop'
$finalExe = Join-Path $parentDir "$exeName.exe"
$legacyCliExe = Join-Path $parentDir 'VulnMngSysDesktop-CLI.exe'

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

Write-Host '[1/5] Building React frontend...'
Push-Location $reactUiDir
try {
  Invoke-CheckedCommand -FilePath 'npm' -Arguments @('run', 'build')
}
finally {
  Pop-Location
}

if (Test-Path $frontendDistDir) {
  Remove-Item -Recurse -Force $frontendDistDir
}
New-Item -ItemType Directory -Path $frontendDistDir -Force | Out-Null
Copy-Item -Path (Join-Path $reactDistDir '*') -Destination $frontendDistDir -Recurse -Force

Write-Host '[2/5] Preparing Python build tools...'
Invoke-CheckedCommand -FilePath $pythonExe -Arguments @('-m', 'pip', 'install', '--quiet', 'pyarmor', 'pyinstaller', 'pywebview')

Write-Host '[3/5] Obfuscating Python sources with PyArmor...'
if (Test-Path $obfuscatedDir) {
  Remove-Item -Recurse -Force $obfuscatedDir
}

Invoke-CheckedCommand -FilePath $pyarmorExe -Arguments @(
  'gen',
  '-O', $obfuscatedDir,
  '-r',
  'main.py',
  'cli.py',
  'app_bootstrap',
  'vulnmngsys_app',
  'scripts'
)

Copy-Item -Path (Join-Path $rootDir 'main.py') -Destination (Join-Path $obfuscatedDir 'main.py') -Force

$pyarmorRuntime = Get-ChildItem -Path $obfuscatedDir -Directory -Filter 'pyarmor_runtime_*' | Select-Object -First 1
$pyarmorHiddenImportArgs = @()
if ($pyarmorRuntime) {
  $pyarmorHiddenImportArgs = @('--hidden-import', $pyarmorRuntime.Name)
}

function Invoke-PyInstallerBuild {
  param(
    [Parameter(Mandatory = $true)][string]$EntryPoint,
    [Parameter(Mandatory = $true)][string]$ExeName,
    [Parameter(Mandatory = $true)][string]$FinalExePath
  )

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
    '--name', $ExeName,
    '--paths', $obfuscatedDir,
    '--hidden-import', 'platform',
    '--hidden-import', 'ctypes',
    '--hidden-import', '_ctypes',
    '--hidden-import', 'uuid',
    '--hidden-import', 'webbrowser',
    '--collect-submodules', 'app_bootstrap',
    '--collect-submodules', 'vulnmngsys_app',
    '--collect-submodules', 'webview',
    '--add-data', "${frontendDistDir};vulnmngsys_app/frontend/dist",
    '--add-data', "${rulesDir};rules",
    '--add-data', "${scriptsDir};scripts" # Đã thêm tham số gộp folder scripts vào file .exe
  )

  if ($pyarmorHiddenImportArgs.Count -gt 0) {
    $pyinstallerArgs += $pyarmorHiddenImportArgs
  }

  $pyinstallerArgs += $EntryPoint
  Invoke-CheckedCommand -FilePath $pythonExe -Arguments $pyinstallerArgs

  if (-not (Test-Path (Join-Path $distDir "$ExeName.exe"))) {
    throw "Expected output not found: $(Join-Path $distDir "$ExeName.exe")"
  }

  if (Test-Path $FinalExePath) {
    try {
      Remove-Item $FinalExePath -Force -ErrorAction Stop
    }
    catch {
      Write-Warning "Could not remove existing output '$FinalExePath': $($_.Exception.Message)"
    }
  }

  try {
    Copy-Item -Path (Join-Path $distDir "$ExeName.exe") -Destination $FinalExePath -Force -ErrorAction Stop
  }
  catch {
    Write-Warning "Could not copy '$ExeName.exe' to '$FinalExePath': $($_.Exception.Message)"
    Write-Warning "Keeping the built executable in '$distDir' instead."
  }
}

Write-Host '[4/5] Packaging single executable with PyInstaller...'
Invoke-PyInstallerBuild -EntryPoint (Join-Path $obfuscatedDir 'main.py') -ExeName $exeName -FinalExePath $finalExe

Write-Host '[4/5] Packaging CLI executable with PyInstaller...'
Invoke-PyInstallerBuild -EntryPoint (Join-Path $obfuscatedDir 'cli.py') -ExeName 'VulnMngSysDesktop-CLI' -FinalExePath $legacyCliExe

Write-Host '[5/5] Copying output to deployment folder...'
try {
  & taskkill /F /IM "$exeName.exe" /T | Out-Null
} catch {
}
try {
  & taskkill /F /IM 'VulnMngSysDesktop-CLI.exe' /T | Out-Null
} catch {
}
Start-Sleep -Milliseconds 500
Get-Process -Name $exeName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "Build complete: $finalExe"
Write-Host "Build complete: $legacyCliExe"