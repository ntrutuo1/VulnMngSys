# Thu thập Actual từ máy local và đối chiếu với expected trong rule JSON (CIS WS 2022).
# Chạy PowerShell as Administrator để có secedit/auditpol đầy đủ.

param(
    [string]$ProfileKey = 'Windows_Server_2022',
    [string]$RulesRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'rules'),
    [string]$OutputDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'reports')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$outDir = $OutputDir
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$os = Get-CimInstance Win32_OperatingSystem
$inventory = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    OsCaption    = $os.Caption
    OsVersion    = $os.Version
    ProductType  = $os.ProductType
    IsServer     = $os.ProductType -in 2, 3
    IsAdmin      = $isAdmin
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
}

# --- net accounts (không cần secedit) ---
$netAccountsRaw = (net accounts 2>&1) -join "`n"
$netMap = @{}
foreach ($line in ($netAccountsRaw -split "`n")) {
    if ($line -match '^\s*Minimum password age \(days\):\s+(\S+)') { $netMap.MinimumPasswordAge = $matches[1] }
    if ($line -match '^\s*Maximum password age \(days\):\s+(\S+)') { $netMap.MaximumPasswordAge = $matches[1] }
    if ($line -match '^\s*Minimum password length:\s+(\S+)') { $netMap.MinimumPasswordLength = $matches[1] }
    if ($line -match '^\s*Length of password history maintained:\s+(\S+)') { $netMap.PasswordHistorySize = $matches[1] }
    if ($line -match '^\s*Lockout threshold:\s+(\S+)') { $netMap.LockoutBadCount = $matches[1] }
    if ($line -match '^\s*Lockout duration \(minutes\):\s+(\S+)') { $netMap.LockoutDuration = $matches[1] }
    if ($line -match '^\s*Lockout observation window \(minutes\):\s+(\S+)') { $netMap.ResetLockoutCount = $matches[1] }
}

$secExport = @{}
if ($isAdmin) {
    $secTemp = Join-Path $env:TEMP "vulnmngsys_baseline_$([guid]::NewGuid()).cfg"
    $null = secedit /export /cfg $secTemp /areas SECURITYPOLICY 2>&1
    if (Test-Path -LiteralPath $secTemp) {
        foreach ($line in Get-Content -LiteralPath $secTemp) {
            if ($line -match '^\s*(\w+)\s*=\s*(.*)\s*$') {
                $secExport[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        Remove-Item -LiteralPath $secTemp -Force -ErrorAction SilentlyContinue
    }
}

$invokeScript = Join-Path $PSScriptRoot 'json_scanners\Invoke-RuleJsonScan.ps1'
$manifestPath = Join-Path $RulesRoot "${ProfileKey}_manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Missing manifest: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$quickFile = Join-Path $RulesRoot $manifest.quick

$tempJson = Join-Path $outDir 'temp\live_quick_scan.json'
New-Item -ItemType Directory -Path (Split-Path $tempJson -Parent) -Force | Out-Null
$null = & $invokeScript -RulesJsonPath $quickFile -OutputJsonPath $tempJson -Quiet

$metaDir = Join-Path $outDir 'temp'
$inventoryFile = Join-Path $metaDir 'live_inventory.json'
$netMapFile = Join-Path $metaDir 'live_net_accounts.json'
$secExportFile = Join-Path $metaDir 'live_secedit_export.json'
($inventory | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $inventoryFile -Encoding UTF8
($netMap | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $netMapFile -Encoding UTF8
($secExport | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $secExportFile -Encoding UTF8

$compareScript = Join-Path $PSScriptRoot 'compare_live_report.py'
$reportJson = Join-Path $outDir 'live_vs_expected.json'

python $compareScript `
    --scan-json $tempJson `
    --rule-file $quickFile `
    --output $reportJson `
    --inventory-file $inventoryFile `
    --net-map-file $netMapFile `
    --sec-export-file $secExportFile

Write-Output "Inventory: $(ConvertTo-Json $inventory -Compress)"
Write-Output "net accounts map: $(ConvertTo-Json $netMap -Compress)"
Write-Output "Report: $reportJson"
