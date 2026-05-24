# ==============================================================================
# Script: scan_rule_18_part1_2022.ps1
# Description: Quét cấu hình Mục 18 (18.1 Control Panel, 18.4 MS Security Guide, 18.5 MSS)
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
# 18.1 Control Panel
# ==============================================================================
$v18111 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
Add-Result "18.1.1.1" "Prevent enabling lock screen camera" $v18111 "1 (Enabled)" ($v18111 -eq 1)

$v18112 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
Add-Result "18.1.1.2" "Prevent enabling lock screen slide show" $v18112 "1 (Enabled)" ($v18112 -eq 1)

$v18122 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization"
Add-Result "18.1.2.2" "Allow users to enable online speech recognition services" $v18122 "0 (Disabled)" ($v18122 -eq 0)

$v1813 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips"
Add-Result "18.1.3" "Allow Online Tips" $v1813 "0 (Disabled)" ($v1813 -eq 0)

# ==============================================================================
# 18.4 MS Security Guide
# ==============================================================================
$v1841 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
Add-Result "18.4.1" "Configure SMB v1 client driver" $v1841 "4 (Disabled)" ($v1841 -eq 4)

$v1842 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
Add-Result "18.4.2" "Configure SMB v1 server" $v1842 "0 (Disabled)" ($v1842 -eq 0)

# 18.4.3 Yêu cầu quét cả 2 đường dẫn (Native và Wow6432Node)
$v1843_1 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck"
$v1843_2 = Get-RegValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck"
$v1843_Passed = ($v1843_1 -in @(1, '1')) -and ($v1843_2 -in @(1, '1'))
$v1843_Display = "Native: $v1843_1 | Wow64: $v1843_2"
Add-Result "18.4.3" "Enable Certificate Padding" $v1843_Display "1 (Enabled) on both" $v1843_Passed

$v1844 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"
Add-Result "18.4.4" "Enable Structured Exception Handling Overwrite Protection (SEHOP)" $v1844 "0 (Enabled)" ($v1844 -eq 0)

$v1845 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType"
Add-Result "18.4.5" "NetBT NodeType configuration" $v1845 "2 (P-node)" ($v1845 -eq 2)

# ==============================================================================
# 18.5 MSS (Legacy)
# ==============================================================================
$v1851 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
Add-Result "18.5.1" "MSS: (AutoAdminLogon) Enable Automatic Logon" $v1851 "0 (Disabled)" ($v1851 -eq '0' -or $v1851 -eq 0)

$v1852 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"
Add-Result "18.5.2" "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level" $v1852 "2 (Highest protection)" ($v1852 -eq 2)

$v1853 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
Add-Result "18.5.3" "MSS: (DisableIPSourceRouting) IP source routing protection level" $v1853 "2 (Highest protection)" ($v1853 -eq 2)

$v1854 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
Add-Result "18.5.4" "MSS: (EnableICMPRedirect) Allow ICMP redirects..." $v1854 "0 (Disabled)" ($v1854 -eq 0)

$v1855 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime"
Add-Result "18.5.5" "MSS: (KeepAliveTime) How often keep-alive packets are sent" $v1855 "300000" ($v1855 -eq 300000)

$v1856 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand"
Add-Result "18.5.6" "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release..." $v1856 "1 (Enabled)" ($v1856 -eq 1)

$v1857 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery"
Add-Result "18.5.7" "MSS: (PerformRouterDiscovery) Allow IRDP to detect..." $v1857 "0 (Disabled)" ($v1857 -eq 0)

$v1858 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
Add-Result "18.5.8" "MSS: (SafeDllSearchMode) Enable Safe DLL search mode" $v1858 "1 (Enabled)" ($v1858 -eq 1)

$v1859 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "TcpMaxDataRetransmissions"
Add-Result "18.5.9" "MSS: (TcpMaxDataRetransmissions IPv6)" $v1859 "3" ($v1859 -eq 3)

$v18510 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions"
Add-Result "18.5.10" "MSS: (TcpMaxDataRetransmissions)" $v18510 "3" ($v18510 -eq 3)

$v18511 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel"
Add-Result "18.5.11" "MSS: (WarningLevel) Percentage threshold for the security event log..." $v18511 "<= 90" ($null -ne $v18511 -and $v18511 -le 90)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress