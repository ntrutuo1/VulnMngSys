# ==============================================================================
# Script: scan_rule_5_9_2022.ps1
# Description: Quét cấu hình System Services (Mục 5) và Windows Firewall (Mục 9)
# ==============================================================================

$script:Results = @()

# Hàm hỗ trợ đọc Registry an toàn
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($null -eq $val) { return $null }
        return $val
    } catch {
        return $null
    }
}

# Hàm gán kết quả vào mảng
function Add-Result ($RuleID, $PolicyName, $CurrentValue, $RecommendedText, $IsPassed) {
    $Status = if ($IsPassed) { "PASS" } else { "FAIL" }
    $CurrentDisplay = if ($null -eq $CurrentValue -or [string]::IsNullOrWhiteSpace([string]$CurrentValue)) { "Not Defined / Empty" } else { $CurrentValue }
    
    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $CurrentDisplay
        "RecommendedValue" = $RecommendedText
        "Status"           = $Status
    }
}

# ==============================================================================
# Mục 5: System Services
# ==============================================================================
$v51 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" "Start"
Add-Result "5.1" "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'" $v51 "4 (Disabled)" ($v51 -eq 4)

# ==============================================================================
# Mục 9: Windows Defender Firewall with Advanced Security
# ==============================================================================

# --- 9.2 Private Profile ---
$fwPrivPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$fwPrivLogPath = "$fwPrivPath\Logging"

$v921 = Get-RegValue $fwPrivPath "EnableFirewall"
Add-Result "9.2.1" "Windows Firewall: Private: Firewall state" $v921 "1 (On)" ($v921 -eq 1)

$v922 = Get-RegValue $fwPrivPath "DefaultInboundAction"
Add-Result "9.2.2" "Windows Firewall: Private: Inbound connections" $v922 "1 (Block)" ($v922 -eq 1)

$v923 = Get-RegValue $fwPrivPath "DisableNotifications"
Add-Result "9.2.3" "Windows Firewall: Private: Settings: Display a notification" $v923 "1 (No)" ($v923 -eq 1)

$v924 = Get-RegValue $fwPrivLogPath "LogFilePath"
Add-Result "9.2.4" "Windows Firewall: Private: Logging: Name" $v924 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v924))

$v925 = Get-RegValue $fwPrivLogPath "LogFileSize"
Add-Result "9.2.5" "Windows Firewall: Private: Logging: Size limit (KB)" $v925 ">= 16384" ($null -ne $v925 -and $v925 -ge 16384)

$v926 = Get-RegValue $fwPrivLogPath "LogDroppedPackets"
Add-Result "9.2.6" "Windows Firewall: Private: Logging: Log dropped packets" $v926 "1 (Yes)" ($v926 -eq 1)

$v927 = Get-RegValue $fwPrivLogPath "LogSuccessfulConnections"
Add-Result "9.2.7" "Windows Firewall: Private: Logging: Log successful connections" $v927 "1 (Yes)" ($v927 -eq 1)


# --- 9.3 Public Profile ---
$fwPubPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$fwPubLogPath = "$fwPubPath\Logging"

$v931 = Get-RegValue $fwPubPath "EnableFirewall"
Add-Result "9.3.1" "Windows Firewall: Public: Firewall state" $v931 "1 (On)" ($v931 -eq 1)

$v932 = Get-RegValue $fwPubPath "DefaultInboundAction"
Add-Result "9.3.2" "Windows Firewall: Public: Inbound connections" $v932 "1 (Block)" ($v932 -eq 1)

$v933 = Get-RegValue $fwPubPath "DisableNotifications"
Add-Result "9.3.3" "Windows Firewall: Public: Settings: Display a notification" $v933 "1 (No)" ($v933 -eq 1)

$v934 = Get-RegValue $fwPubLogPath "LogFilePath"
Add-Result "9.3.4" "Windows Firewall: Public: Logging: Name" $v934 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v934))

$v935 = Get-RegValue $fwPubLogPath "LogFileSize"
Add-Result "9.3.5" "Windows Firewall: Public: Logging: Size limit (KB)" $v935 ">= 16384" ($null -ne $v935 -and $v935 -ge 16384)

$v936 = Get-RegValue $fwPubLogPath "LogDroppedPackets"
Add-Result "9.3.6" "Windows Firewall: Public: Logging: Log dropped packets" $v936 "1 (Yes)" ($v936 -eq 1)

$v937 = Get-RegValue $fwPubLogPath "LogSuccessfulConnections"
Add-Result "9.3.7" "Windows Firewall: Public: Logging: Log successful connections" $v937 "1 (Yes)" ($v937 -eq 1)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress