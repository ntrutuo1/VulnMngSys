# ==============================================================================
# Script: scan_rule_1_2022.ps1
# Description: Quét cấu hình Account Policies (Password & Lockout)
# ==============================================================================

$script:Results = @()

# 1. Xuất cấu hình Local Security Policy hiện tại ra file tạm
$secTemp = "$env:TEMP\secpol_audit_$([guid]::NewGuid()).cfg"
secedit /export /cfg $secTemp /areas SECURITYPOLICY | Out-Null
$secContent = Get-Content $secTemp

# Hàm hỗ trợ đọc giá trị từ file cấu hình secedit
function Get-SecValue ($Key) {
    $line = $secContent | Where-Object { $_ -match "^\s*$Key\s*=\s*(.*)" }
    if ($line -match "^\s*$Key\s*=\s*(.*)") {
        return [int]$matches[1]
    }
    return $null
}

# 2. Thu thập các giá trị cấu hình thực tế trên máy
$PasswordHistorySize   = Get-SecValue "PasswordHistorySize"
$MaximumPasswordAge    = Get-SecValue "MaximumPasswordAge"
$MinimumPasswordAge    = Get-SecValue "MinimumPasswordAge"
$MinimumPasswordLength = Get-SecValue "MinimumPasswordLength"
$PasswordComplexity    = Get-SecValue "PasswordComplexity"
$ClearTextPassword     = Get-SecValue "ClearTextPassword"

$LockoutDuration       = Get-SecValue "LockoutDuration"
$LockoutBadCount       = Get-SecValue "LockoutBadCount"
$ResetLockoutCount     = Get-SecValue "ResetLockoutCount"
$AllowAdminLockout     = Get-SecValue "AllowAdministratorLockout"

# ==============================================================================
# ĐÃ FIX LỖI TẠI ĐÂY: Xử lý an toàn khi Registry Key không tồn tại
# ==============================================================================
$regPath = "HKLM:\System\CurrentControlSet\Control\SAM"
$RelaxMinPwLen = 0
try {
    $regVal = Get-ItemPropertyValue -Path $regPath -Name "RelaxMinimumPasswordLengthLimits" -ErrorAction Stop
    if ($null -ne $regVal) { $RelaxMinPwLen = $regVal }
} catch {
    $RelaxMinPwLen = 0
}
# ==============================================================================

# 3. Hàm gán kết quả vào mảng
function Add-Result ($RuleID, $PolicyName, $CurrentValue, $RecommendedText, $IsPassed) {
    $Status = if ($IsPassed) { "PASS" } else { "FAIL" }
    $CurrentDisplay = if ($null -eq $CurrentValue) { "Not Defined" } else { $CurrentValue }
    
    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $CurrentDisplay
        "RecommendedValue" = $RecommendedText
        "Status"           = $Status
    }
}

# ==============================================================================
# 1.1 Password Policy
# ==============================================================================
# 1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)'
Add-Result "1.1.1" "Enforce password history" $PasswordHistorySize "24 or more password(s)" ($PasswordHistorySize -ge 24)

# 1.1.2 Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
Add-Result "1.1.2" "Maximum password age" $MaximumPasswordAge "365 or fewer days, but not 0" ($MaximumPasswordAge -le 365 -and $MaximumPasswordAge -gt 0)

# 1.1.3 Ensure 'Minimum password age' is set to '1 or more day(s)'
Add-Result "1.1.3" "Minimum password age" $MinimumPasswordAge "1 or more day(s)" ($MinimumPasswordAge -ge 1)

# 1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'
Add-Result "1.1.4" "Minimum password length" $MinimumPasswordLength "14 or more character(s)" ($MinimumPasswordLength -ge 14)

# 1.1.5 Ensure 'Password must meet complexity requirements' is set to 'Enabled'
Add-Result "1.1.5" "Password must meet complexity requirements" $PasswordComplexity "Enabled (1)" ($PasswordComplexity -eq 1)

# 1.1.6 Ensure 'Relax minimum password length limits' is set to 'Enabled'
Add-Result "1.1.6" "Relax minimum password length limits" $RelaxMinPwLen "Enabled (1)" ($RelaxMinPwLen -eq 1)

# 1.1.7 Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
Add-Result "1.1.7" "Store passwords using reversible encryption" $ClearTextPassword "Disabled (0)" ($ClearTextPassword -eq 0)


# ==============================================================================
# 1.2 Account Lockout Policy
# ==============================================================================
# 1.2.1 Ensure 'Account lockout duration' is set to '15 or more minute(s)'
Add-Result "1.2.1" "Account lockout duration" $LockoutDuration "15 or more minute(s)" ($LockoutDuration -ge 15)

# 1.2.2 Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
Add-Result "1.2.2" "Account lockout threshold" $LockoutBadCount "5 or fewer invalid logon attempt(s), but not 0" ($LockoutBadCount -le 5 -and $LockoutBadCount -gt 0)

# 1.2.3 Ensure 'Allow Administrator account lockout' is set to 'Enabled'
Add-Result "1.2.3" "Allow Administrator account lockout" $AllowAdminLockout "Enabled (1)" ($AllowAdminLockout -eq 1)

# 1.2.4 Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
Add-Result "1.2.4" "Reset account lockout counter after" $ResetLockoutCount "15 or more minute(s)" ($ResetLockoutCount -ge 15)

# ==============================================================================
# 4. Cleanup & Xuất JSON
# ==============================================================================
Remove-Item $secTemp -ErrorAction SilentlyContinue

# Đẩy mảng object ra dạng chuỗi JSON để scan_executor xử lý
$script:Results | ConvertTo-Json -Depth 4 -Compress