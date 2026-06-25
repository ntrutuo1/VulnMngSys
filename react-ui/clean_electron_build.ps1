$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = $PSScriptRoot
$ElectronDist = Join-Path $RootDir 'electron-dist'
$ProcessNames = @(
  'vulnmngsys-react-ui',
  'VulnMngSysBackend',
  'VulnMngSysDesktop',
  'VulnMngSysDesktop-CLI'
)

foreach ($name in $ProcessNames) {
  Get-Process -Name $name -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

try {
  Get-CimInstance Win32_Process -ErrorAction Stop |
    Where-Object {
      $_.Name -in @('electron.exe', 'makensis.exe', '7z.exe', '7za.exe') -and
      (
        ($_.CommandLine -and $_.CommandLine.Contains($RootDir)) -or
        ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($RootDir, [System.StringComparison]::OrdinalIgnoreCase))
      )
    } |
    ForEach-Object {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
} catch {
  Write-Warning "Unable to inspect build helper processes. Continuing with electron-dist cleanup. Original error: $($_.Exception.Message)"
}

Start-Sleep -Milliseconds 500

if (Test-Path $ElectronDist) {
  $removed = $false
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
      Remove-Item -LiteralPath $ElectronDist -Recurse -Force -ErrorAction Stop
      $removed = $true
      break
    } catch {
      Start-Sleep -Milliseconds (400 * $attempt)
    }
  }

  if (-not $removed -and (Test-Path $ElectronDist)) {
    $stalePath = Join-Path $RootDir ("electron-dist.stale-{0:yyyyMMddHHmmss}" -f (Get-Date))
    try {
      Move-Item -LiteralPath $ElectronDist -Destination $stalePath -Force -ErrorAction Stop
    } catch {
      throw "Unable to clear $ElectronDist. Close any running installer, Explorer preview, antivirus scan, or app process that is locking the installer, then rebuild. Original error: $($_.Exception.Message)"
    }
  }
}
