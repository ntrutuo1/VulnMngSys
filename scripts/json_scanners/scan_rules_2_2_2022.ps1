# ==============================================================================
# Script: scan_rule_2_3_part2_2022.ps1
# Description: Quét cấu hình Local Policies - Security Options (2.3.10 - 2.3.17)
# ==============================================================================

$script:Results = @()

# 1. Xuất cấu hình Local Security Policy hiện tại ra file tạm (cho các rule không có Registry)
$secTemp = "$env:TEMP\secpol_audit_$([guid]::NewGuid()).cfg"
secedit /export /cfg $secTemp /areas SECURITYPOLICY | Out-Null
$secContent = Get-Content $secTemp

function Get-SecValue ($Key) {
    $line = $secContent | Where-Object { $_ -match "^\s*$Key\s*=\s*(.*)" }
    if ($line -match "^\s*$Key\s*=\s*(.*)") {
        return $matches[1].Trim()
    }
    return $null
}

# 2. Hàm hỗ trợ đọc Registry an toàn (hỗ trợ cả REG_MULTI_SZ)
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($null -eq $val) { return $null }
        if ($val -is [System.Array]) { return ($val -join ', ') }
        return $val
    } catch {
        return $null
    }
}

# 3. Hàm gán kết quả vào mảng
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
# 2.3.10 Network access (Truy cập mạng)
# ==============================================================================
$v23101 = Get-SecValue "LSAAnonymousNameLookup"
Add-Result "2.3.10.1" "Network access: Allow anonymous SID/Name translation" $v23101 "Disabled (0)" ($v23101 -eq '0')

$v23102 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
Add-Result "2.3.10.2" "Network access: Do not allow anonymous enumeration of SAM accounts" $v23102 "1 (Enabled)" ($v23102 -eq 1)

$v23103 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
Add-Result "2.3.10.3" "Network access: Do not allow anonymous enumeration of SAM accounts and shares" $v23103 "1 (Enabled)" ($v23103 -eq 1)

$v23104 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds"
Add-Result "2.3.10.4" "Network access: Do not allow storage of passwords and credentials..." $v23104 "1 (Enabled)" ($v23104 -eq 1)

$v23105 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
Add-Result "2.3.10.5" "Network access: Let Everyone permissions apply to anonymous users" $v23105 "0 (Disabled)" ($v23105 -eq 0)

$v23106 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
$v23106_Passed = ([string]::IsNullOrWhiteSpace($v23106) -or $v23106 -eq "BROWSER")
Add-Result "2.3.10.6" "Network access: Named Pipes that can be accessed anonymously" $v23106 "None or 'BROWSER'" $v23106_Passed

$v23107 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" "Machine"
Add-Result "2.3.10.7" "Network access: Remotely accessible registry paths" $v23107 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v23107))

$v23108 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" "Machine"
Add-Result "2.3.10.8" "Network access: Remotely accessible registry paths and sub-paths" $v23108 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v23108))

$v23109 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess"
Add-Result "2.3.10.9" "Network access: Restrict anonymous access to Named Pipes and Shares" $v23109 "1 (Enabled)" ($v23109 -eq 1)

$v231010 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "restrictremotesam"
Add-Result "2.3.10.10" "Network access: Restrict clients allowed to make remote calls to SAM" $v231010 "O:BAG:BAD:(A;;RC;;;BA)" ($v231010 -eq 'O:BAG:BAD:(A;;RC;;;BA)')

$v231011 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares"
Add-Result "2.3.10.11" "Network access: Shares that can be accessed anonymously" $v231011 "None (Empty)" ([string]::IsNullOrWhiteSpace($v231011))

$v231012 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "ForceGuest"
Add-Result "2.3.10.12" "Network access: Sharing and security model for local accounts" $v231012 "0 (Classic)" ($v231012 -eq 0)

# ==============================================================================
# 2.3.11 Network security (Bảo mật Mạng)
# ==============================================================================
$v23111 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId"
Add-Result "2.3.11.1" "Network security: Allow Local System to use computer identity for NTLM" $v23111 "1 (Enabled)" ($v23111 -eq 1)

$v23112 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback"
Add-Result "2.3.11.2" "Network security: Allow LocalSystem NULL session fallback" $v23112 "0 (Disabled)" ($v23112 -eq 0)

$v23113 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID"
Add-Result "2.3.11.3" "Network Security: Allow PKU2U authentication requests..." $v23113 "0 (Disabled)" ($v23113 -eq 0)

$v23114 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
Add-Result "2.3.11.4" "Network security: Configure encryption types allowed for Kerberos" $v23114 "2147483640" ($v23114 -eq 2147483640)

$v23115 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
Add-Result "2.3.11.5" "Network security: Do not store LAN Manager hash value on next password change" $v23115 "1 (Enabled)" ($v23115 -eq 1)

$v23116 = Get-SecValue "ForceLogoffWhenHourExpire"
Add-Result "2.3.11.6" "Network security: Force logoff when logon hours expire" $v23116 "1 (Enabled)" ($v23116 -eq '1')

$v23117 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
Add-Result "2.3.11.7" "Network security: LAN Manager authentication level" $v23117 "5 (Send NTLMv2 response only...)" ($v23117 -eq 5)

$v23118 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity"
Add-Result "2.3.11.8" "Network security: LDAP client signing requirements" $v23118 "1 or 2" ($v23118 -in @(1, 2))

$v23119 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
Add-Result "2.3.11.9" "Network security: Minimum session security for NTLM SSP based clients" $v23119 "537395200" ($v23119 -eq 537395200)

$v231110 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
Add-Result "2.3.11.10" "Network security: Minimum session security for NTLM SSP based servers" $v231110 "537395200" ($v231110 -eq 537395200)

$v231111 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AuditReceivingNTLMTraffic"
Add-Result "2.3.11.11" "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" $v231111 "2 (Enable auditing...)" ($v231111 -eq 2)

$v231112 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic"
Add-Result "2.3.11.12" "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" $v231112 "1 or 2" ($v231112 -in @(1, 2))

# ==============================================================================
# 2.3.13 Shutdown (Tắt máy)
# ==============================================================================
$v23131 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
Add-Result "2.3.13.1" "Shutdown: Allow system to be shut down without having to log on" $v23131 "0 (Disabled)" ($v23131 -eq 0)

# ==============================================================================
# 2.3.15 System objects (Đối tượng Hệ thống)
# ==============================================================================
$v23151 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "ObCaseInsensitive"
Add-Result "2.3.15.1" "System objects: Require case insensitivity for non-Windows subsystems" $v23151 "1 (Enabled)" ($v23151 -eq 1)

$v23152 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode"
Add-Result "2.3.15.2" "System objects: Strengthen default permissions of internal system objects" $v23152 "1 (Enabled)" ($v23152 -eq 1)

# ==============================================================================
# 2.3.17 User Account Control (UAC)
# ==============================================================================
$v23171 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
Add-Result "2.3.17.1" "UAC: Admin Approval Mode for the Built-in Administrator account" $v23171 "1 (Enabled)" ($v23171 -eq 1)

$v23172 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
Add-Result "2.3.17.2" "UAC: Behavior of the elevation prompt for administrators..." $v23172 "1 or 2" ($v23172 -in @(1, 2))

$v23173 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser"
Add-Result "2.3.17.3" "UAC: Behavior of the elevation prompt for standard users" $v23173 "0" ($v23173 -eq 0)

$v23174 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"
Add-Result "2.3.17.4" "UAC: Detect application installations and prompt for elevation" $v23174 "1 (Enabled)" ($v23174 -eq 1)

$v23175 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths"
Add-Result "2.3.17.5" "UAC: Only elevate UIAccess applications that are installed in secure locations" $v23175 "1 (Enabled)" ($v23175 -eq 1)

$v23176 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
Add-Result "2.3.17.6" "UAC: Run all administrators in Admin Approval Mode" $v23176 "1 (Enabled)" ($v23176 -eq 1)

$v23177 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"
Add-Result "2.3.17.7" "UAC: Switch to the secure desktop when prompting for elevation" $v23177 "1 (Enabled)" ($v23177 -eq 1)

$v23178 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization"
Add-Result "2.3.17.8" "UAC: Virtualize file and registry write failures to per-user locations" $v23178 "1 (Enabled)" ($v23178 -eq 1)

# ==============================================================================
# Xuất JSON
# ==============================================================================
Remove-Item $secTemp -ErrorAction SilentlyContinue

$script:Results | ConvertTo-Json -Depth 4 -Compress