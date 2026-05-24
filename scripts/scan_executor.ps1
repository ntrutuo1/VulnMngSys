<#
.SYNOPSIS
    Entry point cho luồng quét chính (rule compliance scan).
#>
param(
    [string[]]$RuleJsonPaths = @(),
    [string]$RuleListFile,
    [string]$OutputDir,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$jsonScannersDir = Join-Path $scriptDir 'json_scanners'
$invokeScript = Join-Path $jsonScannersDir 'Invoke-RuleJsonScan.ps1'

function Write-ExecutorJson {
    param([object]$Payload)
    $json = $Payload | ConvertTo-Json -Depth 12
    [Console]::Out.WriteLine($json)
}

function Expand-RuleJsonPathList {
    param([string[]]$Paths)
    $expanded = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Paths) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        foreach ($segment in ($entry -split ',')) {
            $path = $segment.Trim().Trim('"').Trim("'")
            if ($path) { $expanded.Add($path) }
        }
    }
    return @($expanded)
}

function Get-RuleJsonPathList {
  param([string[]]$RuleJsonPaths, [string]$RuleListFile)
  $all = [System.Collections.Generic.List[string]]::new()

  if (-not [string]::IsNullOrWhiteSpace($RuleListFile)) {
    if (-not (Test-Path -LiteralPath $RuleListFile)) { throw "Rule list file not found: $RuleListFile" }
    foreach ($line in Get-Content -LiteralPath $RuleListFile) {
      $path = $line.Trim()
      if ($path) { $all.Add($path) }
    }
  }

  foreach ($path in (Expand-RuleJsonPathList -Paths $RuleJsonPaths)) { $all.Add($path) }
  return @($all)
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $appRoot = Split-Path -Parent $scriptDir
    $OutputDir = Join-Path (Join-Path $appRoot 'reports') 'temp'
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$outputs = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[string]]::new()

# ====================================================================
# 1. THỰC THI CÁC FILE RULE JSON (Nếu có)
# ====================================================================
if (Test-Path -LiteralPath $invokeScript) {
    $RuleJsonPaths = Get-RuleJsonPathList -RuleJsonPaths $RuleJsonPaths -RuleListFile $RuleListFile
    foreach ($rulePathRaw in $RuleJsonPaths) {
        $rulePath = [string]$rulePathRaw
        if ([string]::IsNullOrWhiteSpace($rulePath)) { continue }
        if (-not (Test-Path -LiteralPath $rulePath)) {
            $errors.Add("Rule file not found: $rulePath")
            continue
        }

        $ruleFile = Get-Item -LiteralPath $rulePath
        $tempOutput = Join-Path $OutputDir ($ruleFile.BaseName + '_temp.json')

        try {
            $null = & $invokeScript -RulesJsonPath $ruleFile.FullName -OutputJsonPath $tempOutput -Quiet:$Quiet
        } catch {
            $errors.Add("Scan failed for $($ruleFile.Name): $($_.Exception.Message)")
            continue
        }

        if (Test-Path -LiteralPath $tempOutput) {
            $outputs.Add([ordered]@{ ruleFile = $ruleFile.FullName; tempJsonFile = $tempOutput })
        }
    }
}

# ====================================================================
# 2. THỰC THI CÁC FILE POWERSHELL SCAN RULE (scan_rules_*.ps1)
# ====================================================================
if (Test-Path -LiteralPath $jsonScannersDir) {
    $customPsScanners = Get-ChildItem -Path $jsonScannersDir -Filter "scan_rules_*.ps1" -File
    foreach ($psScanner in $customPsScanners) {
        $tempOutput = Join-Path $OutputDir ($psScanner.BaseName + '_temp.json')
        
        try {
            $psResults = & $psScanner.FullName
            
            if ($null -ne $psResults) {
                $parsedObj = $null
                if ($psResults -is [string] -or $psResults[0] -is [string]) {
                    $parsedObj = $psResults -join "`n" | ConvertFrom-Json
                } else {
                    $parsedObj = $psResults
                }
                
                @($parsedObj) | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tempOutput -Encoding UTF8
            }
        }
        catch {
            $errors.Add("Custom PS scan failed for $($psScanner.Name): $($_.Exception.Message)")
            continue
        }

        if (Test-Path -LiteralPath $tempOutput) {
            $outputs.Add([ordered]@{ ruleFile = $psScanner.FullName; tempJsonFile = $tempOutput })
        }
    }
}

# ====================================================================
# 3. TỔNG HỢP VÀ GOM KẾT QUẢ (ĐÃ THÊM CỘT CURRENT STATUS)
# ====================================================================
if ($errors.Count -gt 0 -and $outputs.Count -eq 0) {
    Write-ExecutorJson -Payload @{ ok = $false; error = ($errors -join '; '); outputs = @() }
    exit 1
}

$mergedRows = [System.Collections.Generic.List[object]]::new()

# Hàm nội bộ để tự động chèn thêm cột CurrentStatus vào Object
function Enrich-Row ($row) {
    if ($null -ne $row -and -not $row.PSObject.Properties.Match('CurrentStatus')) {
        
        # Mặc định tôi đang để CurrentStatus lấy giá trị giống cột Status (PASS/FAIL)
        # Bạn có thể sửa lại logic ở đây. Ví dụ:
        # $cStatus = if ($row.Status -eq "PASS") { "Compliant" } else { "Non-Compliant" }
        
        $cStatus = $row.Status 
        
        $row | Add-Member -MemberType NoteProperty -Name 'CurrentStatus' -Value $cStatus
    }
    return $row
}

foreach ($entry in $outputs) {
    $tempPath = [string]$entry.tempJsonFile
    if (-not (Test-Path -LiteralPath $tempPath)) { continue }

    try {
        $chunk = Get-Content -LiteralPath $tempPath -Raw | ConvertFrom-Json
        if ($null -eq $chunk) { continue }

        if ($chunk -is [System.Collections.IEnumerable] -and $chunk -isnot [string]) {
            foreach ($row in $chunk) { 
                $mergedRows.Add((Enrich-Row $row)) 
            }
        } else {
            $mergedRows.Add((Enrich-Row $chunk))
        }
    } catch {
        $errors.Add("Failed to parse JSON from $tempPath")
    }
}

$mergedScanFile = Join-Path $OutputDir 'scan_results_merged.json'
$mergedRows | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $mergedScanFile -Encoding UTF8

Write-ExecutorJson -Payload @{
    ok             = $true
    mergedScanFile = $mergedScanFile
    scanCount      = $mergedRows.Count
    outputs        = @($outputs)
    errors         = @($errors)
}