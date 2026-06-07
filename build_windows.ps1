param(
  [switch]$SkipFrontend,
  [switch]$SkipToolInstall,
  [switch]$NoObfuscate,
  [switch]$CliOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = $PSScriptRoot
$ParentDir = Resolve-Path (Join-Path $RootDir '..')
$BuildDir = Join-Path $RootDir 'build'
$DistDir = Join-Path $RootDir 'dist'
$ObfuscatedDir = Join-Path $RootDir 'obfuscated_src'
$ReactUiDir = Join-Path $RootDir 'react-ui'
$ReactDistDir = Join-Path $ReactUiDir 'dist'
$FrontendDistDir = Join-Path $RootDir 'vulnmngsys_app\frontend\dist'
$PythonExe = Join-Path $ParentDir '.venv\Scripts\python.exe'
if (-not (Test-Path $PythonExe)) { $PythonExe = 'python' }

$BuildTools = @('pyarmor', 'pyinstaller')
$HiddenImports = @('platform', 'ctypes', '_ctypes', 'uuid', 'webbrowser', 'pymetasploit3', 'pymetasploit3.msfrpc')
$CollectPackages = @('app_bootstrap', 'vulnmngsys_app', 'webview', 'pymetasploit3')
$ObfuscateInputs = @('main.py', 'cli.py', 'app_bootstrap', 'vulnmngsys_app', 'scripts')
$DataFolders = @(
  @{ Source = $FrontendDistDir; Target = 'vulnmngsys_app/frontend/dist'; DesktopOnly = $true },
  @{ Source = (Join-Path $RootDir 'rules'); Target = 'rules'; DesktopOnly = $false },
  @{ Source = (Join-Path $RootDir 'scripts'); Target = 'scripts'; DesktopOnly = $false },
  @{ Source = (Join-Path $RootDir 'metasploit_modules'); Target = 'metasploit_modules'; DesktopOnly = $false }
)

Set-Location $RootDir

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

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

function Get-PyArmorExe {
  $scriptsDir = Split-Path $PythonExe -Parent
  $localExe = Join-Path $scriptsDir 'pyarmor.exe'
  if (Test-Path $localExe) { return $localExe }
  return 'pyarmor'
}

function Install-BuildTools {
  if ($SkipToolInstall) { return }
  Write-Step 'Installing/updating Python build tools'
  if (Test-Path (Join-Path $RootDir 'requirements.txt')) {
    Invoke-Checked $PythonExe @('-m', 'pip', 'install', '--quiet', '-r', 'requirements.txt')
  }
  Invoke-Checked $PythonExe (@('-m', 'pip', 'install', '--quiet') + $BuildTools)
}

function Build-Frontend {
  if ($SkipFrontend -or $CliOnly) { return }
  Write-Step 'Building React frontend'
  Push-Location $ReactUiDir
  try { Invoke-Checked 'npm' @('run', 'build') }
  finally { Pop-Location }

  Remove-PathIfExists $FrontendDistDir
  New-Item -ItemType Directory -Path $FrontendDistDir -Force | Out-Null
  Copy-Item -Path (Join-Path $ReactDistDir '*') -Destination $FrontendDistDir -Recurse -Force
}

function Test-Source {
  Write-Step 'Checking Python source syntax'
  Invoke-Checked $PythonExe @('-m', 'compileall', '-q', 'main.py', 'cli.py', 'app_bootstrap', 'vulnmngsys_app')
  if (Test-Path (Join-Path $RootDir 'scripts\install_metasploit.ps1')) {
    $errors = $null
    [void][System.Management.Automation.PSParser]::Tokenize(
      (Get-Content -Raw (Join-Path $RootDir 'scripts\install_metasploit.ps1')),
      [ref]$errors
    )
    if ($errors) { throw "PowerShell parser found errors in scripts\install_metasploit.ps1" }
  }
}

function New-ObfuscatedSource {
  if ($NoObfuscate) { return $RootDir }
  Write-Step 'Obfuscating Python sources with PyArmor'
  Remove-PathIfExists $ObfuscatedDir
  $existingInputs = $ObfuscateInputs | Where-Object { Test-Path (Join-Path $RootDir $_) }
  Invoke-Checked (Get-PyArmorExe) (@('gen', '-O', $ObfuscatedDir, '-r') + $existingInputs)

  foreach ($entry in @('main.py', 'cli.py')) {
    Copy-Item -Path (Join-Path $RootDir $entry) -Destination (Join-Path $ObfuscatedDir $entry) -Force
  }
  return $ObfuscatedDir
}

function Get-PyArmorHiddenArgs {
  if ($NoObfuscate -or -not (Test-Path $ObfuscatedDir)) { return @() }
  $runtime = Get-ChildItem -Path $ObfuscatedDir -Directory -Filter 'pyarmor_runtime_*' |
    Select-Object -First 1
  if (-not $runtime) { return @() }
  return @('--hidden-import', $runtime.Name)
}

function Get-DataArgs {
  param([bool]$Desktop)
  $args = @()
  foreach ($item in $DataFolders) {
    if (-not $Desktop -and $item.DesktopOnly) { continue }
    if (-not (Test-Path $item.Source)) {
      Write-Warning "Skipping missing data folder: $($item.Source)"
      continue
    }
    $args += @('--add-data', "$($item.Source);$($item.Target)")
  }
  return $args
}

function Stop-ExistingExe {
  param([string]$ExeName)
  $processName = [IO.Path]::GetFileNameWithoutExtension($ExeName)
  Get-Process -Name $processName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Invoke-PyInstallerBuild {
  param(
    [string]$EntryPoint,
    [string]$ExeName,
    [string]$FinalExePath,
    [bool]$Desktop
  )
  Write-Step "Packaging $ExeName"
  Stop-ExistingExe "$ExeName.exe"
  Remove-PathIfExists $DistDir
  Remove-PathIfExists $BuildDir

  $args = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--name', $ExeName)
  $args += @('--paths', (Split-Path $EntryPoint -Parent))
  foreach ($name in $HiddenImports) { $args += @('--hidden-import', $name) }
  foreach ($name in $CollectPackages) { $args += @('--collect-submodules', $name) }
  $args += Get-PyArmorHiddenArgs
  $args += Get-DataArgs -Desktop $Desktop
  $args += $EntryPoint

  Invoke-Checked $PythonExe $args
  $builtExe = Join-Path $DistDir "$ExeName.exe"
  if (-not (Test-Path $builtExe)) { throw "Expected output not found: $builtExe" }
  Copy-Item -Path $builtExe -Destination $FinalExePath -Force
  return $FinalExePath
}

function Write-BuildManifest {
  param([string[]]$Outputs)
  $manifest = [ordered]@{
    builtAt = (Get-Date).ToString('s')
    python = (& $PythonExe --version)
    frontendBuilt = (-not $SkipFrontend -and -not $CliOnly)
    obfuscated = (-not $NoObfuscate)
    outputs = $Outputs
    dataFolders = $DataFolders | ForEach-Object { $_.Target }
  }
  $manifestPath = Join-Path $DistDir 'build_manifest.json'
  New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
  $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8
  Write-Host "Manifest: $manifestPath"
}

Install-BuildTools
Build-Frontend
Test-Source
$SourceRoot = New-ObfuscatedSource

$outputs = @()
if (-not $CliOnly) {
  $outputs += Invoke-PyInstallerBuild -EntryPoint (Join-Path $SourceRoot 'main.py') -ExeName 'VulnMngSysDesktop' -FinalExePath (Join-Path $ParentDir 'VulnMngSysDesktop.exe') -Desktop $true
}
$outputs += Invoke-PyInstallerBuild -EntryPoint (Join-Path $SourceRoot 'cli.py') -ExeName 'VulnMngSysDesktop-CLI' -FinalExePath (Join-Path $ParentDir 'VulnMngSysDesktop-CLI.exe') -Desktop $false

Write-BuildManifest -Outputs $outputs
Write-Host ''
Write-Host 'Build complete:' -ForegroundColor Green
$outputs | ForEach-Object { Write-Host "  $_" }
