# ==============================================================================
# Script: scan_rule_17_2022.ps1
# Description: Quét cấu hình Advanced Audit Policy bằng AuditPol và GUID
# ==============================================================================

$script:Results = @()

# 1. Trích xuất toàn bộ cấu hình AuditPol một lần duy nhất (Tối ưu hiệu năng)
# Sử dụng tham số /r để xuất định dạng CSV dễ phân tích
$auditpolRaw = auditpol /get /category:* /r
$AuditPolMap = @{}

foreach ($line in $auditpolRaw) {
    $parts = $line -split ','
    # Cột thứ 4 là GUID, cột thứ 5 là Setting
    if ($parts.Count -ge 5) {
        $guid = $parts[3].Trim().ToUpper()
        $setting = $parts[4].Trim()
        
        # Chỉ lưu các dòng có chứa GUID chuẩn
        if ($guid -match '^\{[A-F0-9-]+\}$') {
            $AuditPolMap[$guid] = $setting
        }
    }
}

# 2. Hàm kiểm tra và gán kết quả
function Add-AuditResult {
    param (
        [string]$RuleID,
        [string]$PolicyName,
        [string]$GUID,
        [string]$Expected
    )

    $currentValue = $AuditPolMap[$GUID.ToUpper()]
    
    if ([string]::IsNullOrWhiteSpace($currentValue)) {
        $currentValue = "Not Defined / No Auditing"
    }

    # Xử lý Logic đối chiếu (Includes vs Exact Match)
    $IsPassed = $false
    if ($Expected -eq "Success and Failure") {
        $IsPassed = ($currentValue -eq "Success and Failure")
    } elseif ($Expected -eq "Success") {
        $IsPassed = ($currentValue -eq "Success")
    } elseif ($Expected -eq "Includes Success") {
        $IsPassed = ($currentValue -match "Success")
    } elseif ($Expected -eq "Includes Failure") {
        $IsPassed = ($currentValue -match "Failure")
    }

    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $currentValue
        "RecommendedValue" = $Expected
        "Status"           = if ($IsPassed) { "PASS" } else { "FAIL" }
    }
}

# ==============================================================================
# 17.1 Account Logon
# ==============================================================================
Add-AuditResult "17.1.1" "Audit Credential Validation" "{0CCE923F-69AE-11D9-BED3-505054503030}" "Success and Failure"

# ==============================================================================
# 17.2 Account Management
# ==============================================================================
Add-AuditResult "17.2.1" "Audit Application Group Management" "{0CCE9239-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.2.2" "Audit Security Group Management" "{0CCE9237-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.2.3" "Audit User Account Management" "{0CCE9235-69AE-11D9-BED3-505054503030}" "Success and Failure"

# ==============================================================================
# 17.3 Detailed Tracking
# ==============================================================================
Add-AuditResult "17.3.1" "Audit PNP Activity" "{0CCE9248-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.3.2" "Audit Process Creation" "{0CCE922B-69AE-11D9-BED3-505054503030}" "Includes Success"

# ==============================================================================
# 17.5 Logon/Logoff
# ==============================================================================
Add-AuditResult "17.5.1" "Audit Account Lockout" "{0CCE9217-69AE-11D9-BED3-505054503030}" "Includes Failure"
Add-AuditResult "17.5.2" "Audit Group Membership" "{0CCE9249-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.5.3" "Audit Logoff" "{0CCE9216-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.5.4" "Audit Logon" "{0CCE9215-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.5.5" "Audit Other Logon/Logoff Events" "{0CCE921C-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.5.6" "Audit Special Logon" "{0CCE921B-69AE-11D9-BED3-505054503030}" "Includes Success"

# ==============================================================================
# 17.6 Object Access
# ==============================================================================
Add-AuditResult "17.6.1" "Audit Detailed File Share" "{0CCE9244-69AE-11D9-BED3-505054503030}" "Includes Failure"
Add-AuditResult "17.6.2" "Audit File Share" "{0CCE9224-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.6.3" "Audit Other Object Access Events" "{0CCE9227-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.6.4" "Audit Removable Storage" "{0CCE9245-69AE-11D9-BED3-505054503030}" "Success and Failure"

# ==============================================================================
# 17.7 Policy Change
# ==============================================================================
Add-AuditResult "17.7.1" "Audit Audit Policy Change" "{0CCE922F-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.7.2" "Audit Authentication Policy Change" "{0CCE9230-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.7.3" "Audit Authorization Policy Change" "{0CCE9231-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.7.4" "Audit MPSSVC Rule-Level Policy Change" "{0CCE9232-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.7.5" "Audit Other Policy Change Events" "{0CCE9234-69AE-11D9-BED3-505054503030}" "Includes Failure"

# ==============================================================================
# 17.8 Privilege Use
# ==============================================================================
Add-AuditResult "17.8.1" "Audit Sensitive Privilege Use" "{0CCE9228-69AE-11D9-BED3-505054503030}" "Success"

# ==============================================================================
# 17.9 System
# ==============================================================================
Add-AuditResult "17.9.1" "Audit IPsec Driver" "{0CCE9213-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.9.2" "Audit Other System Events" "{0CCE9214-69AE-11D9-BED3-505054503030}" "Success and Failure"
Add-AuditResult "17.9.3" "Audit Security State Change" "{0CCE9210-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.9.4" "Audit Security System Extension" "{0CCE9211-69AE-11D9-BED3-505054503030}" "Includes Success"
Add-AuditResult "17.9.5" "Audit System Integrity" "{0CCE9212-69AE-11D9-BED3-505054503030}" "Success and Failure"

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress