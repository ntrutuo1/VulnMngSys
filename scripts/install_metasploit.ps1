[CmdletBinding()]
param(
    [string]$DownloadURL = $env:VULNMNGSYS_MSF_INSTALLER_URL,
    [string]$DownloadLocation = "$env:APPDATA\Metasploit",
    [string]$InstallLocation = "C:\Tools",
    [string]$LogLocation = ""
)

$ErrorActionPreference = "Stop"

if (-not $DownloadURL) {
    $DownloadURL = "https://windows.metasploit.com/metasploitframework-latest.msi"
}
if (-not $LogLocation) {
    $LogLocation = Join-Path $DownloadLocation "install.log"
}

$rpcNames = @("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd")

function Test-CommandExists {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Find-MsfRpcd {
    param([string[]]$Roots)
    foreach ($name in $rpcNames) {
        if (Test-CommandExists $name) {
            return (Get-Command $name -ErrorAction Stop).Source
        }
    }
    foreach ($root in ($Roots | Where-Object { $_ -and (Test-Path $_) })) {
        $found = Get-ChildItem -Path $root -Recurse -File -Include $rpcNames -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }
    return $null
}

$commonRoots = @(
    $env:METASPLOIT_FRAMEWORK_HOME,
    $InstallLocation,
    "C:\metasploit-framework",
    "$env:ProgramFiles\Metasploit Framework",
    "${env:ProgramFiles(x86)}\Metasploit Framework"
)

$existingRpc = Find-MsfRpcd -Roots $commonRoots
if ($existingRpc) {
    Write-Output "Metasploit msfrpcd is already available: $existingRpc"
    exit 0
}

New-Item -Path $DownloadLocation -ItemType Directory -Force | Out-Null
New-Item -Path $InstallLocation -ItemType Directory -Force | Out-Null

$installer = Join-Path $DownloadLocation "metasploit.msi"
Write-Output "Downloading Metasploit Framework from $DownloadURL"
Invoke-WebRequest -UseBasicParsing -Uri $DownloadURL -OutFile $installer

Write-Output "Installing Metasploit Framework to $InstallLocation"
$process = Start-Process -FilePath $installer -ArgumentList @(
    "/q",
    "/log",
    "`"$LogLocation`"",
    "INSTALLLOCATION=`"$InstallLocation`""
) -Wait -PassThru -WindowStyle Hidden

if ($process.ExitCode -ne 0) {
    throw "Metasploit installer failed with exit code $($process.ExitCode). Log: $LogLocation"
}

$installedRpc = Find-MsfRpcd -Roots $commonRoots
if (-not $installedRpc) {
    throw "Metasploit installer finished, but msfrpcd was not found under $InstallLocation. Log: $LogLocation"
}

Write-Output "Metasploit Framework installation finished: $installedRpc"
