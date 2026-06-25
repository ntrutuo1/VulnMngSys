[CmdletBinding()]
param(
    [string]$DownloadURL = $env:VULNMNGSYS_MSF_INSTALLER_URL,
    [string]$DownloadLocation = "",
    [string]$InstallLocation = "C:\Tools",
    [string]$LogLocation = ""
)

$ErrorActionPreference = "Stop"

if (-not $DownloadLocation) {
    $installParent = Split-Path -Parent $InstallLocation
    if (-not $installParent) {
        $installParent = $InstallLocation
    }
    $DownloadLocation = Join-Path $installParent "installer"
}
if (-not $LogLocation) {
    $LogLocation = Join-Path $DownloadLocation "install.log"
}

$rpcNames = @("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd")

function Find-MsfRpcd {
    param([string[]]$Roots)
    foreach ($root in ($Roots | Where-Object { $_ -and (Test-Path $_) })) {
        $found = Get-ChildItem -Path $root -Recurse -File -Include $rpcNames -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }
    return $null
}

$installRoots = @($InstallLocation)

$existingRpc = Find-MsfRpcd -Roots $installRoots
if ($existingRpc) {
    Write-Output "Metasploit msfrpcd is already available: $existingRpc"
    exit 0
}

New-Item -Path $DownloadLocation -ItemType Directory -Force | Out-Null
New-Item -Path $InstallLocation -ItemType Directory -Force | Out-Null

if ($DownloadURL) {
    Write-Output "DownloadURL is ignored. Place a Metasploit .msi in $DownloadLocation to install into the portable Tools folder."
}

$installer = Get-ChildItem -Path $DownloadLocation -File -Filter "*.msi" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $installer) {
    throw "No Metasploit .msi was found in $DownloadLocation. Copy the installer there and rerun this script with -InstallLocation pointing at the portable Tools folder."
}

$installerPath = $installer.FullName
Write-Output "Using bundled Metasploit installer: $installerPath"
Write-Output "Installing Metasploit Framework to $InstallLocation"
$process = Start-Process -FilePath $installerPath -ArgumentList @(
    "/q",
    "/log",
    "`"$LogLocation`"",
    "INSTALLLOCATION=`"$InstallLocation`""
) -Wait -PassThru -WindowStyle Hidden

if ($process.ExitCode -ne 0) {
    throw "Metasploit installer failed with exit code $($process.ExitCode). Log: $LogLocation"
}

$installedRpc = Find-MsfRpcd -Roots $installRoots
if (-not $installedRpc) {
    throw "Metasploit installer finished, but msfrpcd was not found under $InstallLocation. Log: $LogLocation"
}

Write-Output "Metasploit Framework installation finished: $installedRpc"
