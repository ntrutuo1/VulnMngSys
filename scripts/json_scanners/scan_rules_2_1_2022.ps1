# ==============================================================================
# Script: scan_rule_2_3_part1_2022.ps1
# Description: Quét cấu hình Local Policies - Security Options (2.3.1 - 2.3.9)
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
    $CurrentDisplay = if ($null -eq $CurrentValue -or [string]::IsNullOrWhiteSpace([string]$CurrentValue)) { "Not Defined" } else { $CurrentValue }
    
    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $CurrentDisplay
        "RecommendedValue" = $RecommendedText
        "Status"           = $Status
    }
}

# Lấy thông tin tài khoản Local (Dựa vào SID: -500 là Admin, -501 là Guest)
$adminUser = Get-LocalUser | Where-Object { $_.SID.Value -match "-500$" }
$guestUser = Get-LocalUser | Where-Object { $_.SID.Value -match "-501$" }

# ==============================================================================
# 2.3.1 Accounts (Tài khoản)
# ==============================================================================
$guestStatus = if ($null -ne $guestUser -and $guestUser.Enabled) { "Enabled" } elseif ($null -ne $guestUser) { "Disabled" } else { "Not Found" }
Add-Result "2.3.1.1" "Accounts: Guest account status" $guestStatus "Disabled" ($guestStatus -eq "Disabled")

$v2312 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
Add-Result "2.3.1.2" "Accounts: Limit local account use of blank passwords to console logon only" $v2312 "1 (Enabled)" ($v2312 -eq 1)

$adminName = if ($null -ne $adminUser) { $adminUser.Name } else { $null }
Add-Result "2.3.1.3" "Accounts: Rename administrator account" $adminName "Not 'Administrator'" ($null -ne $adminName -and $adminName -ne "Administrator")

$guestName = if ($null -ne $guestUser) { $guestUser.Name } else { $null }
Add-Result "2.3.1.4" "Accounts: Rename guest account" $guestName "Not 'Guest'" ($null -ne $guestName -and $guestName -ne "Guest")

# ==============================================================================
# 2.3.2 Audit (Kiểm toán)
# ==============================================================================
$v2321 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
Add-Result "2.3.2.1" "Audit: Force audit policy subcategory settings..." $v2321 "1 (Enabled)" ($v2321 -eq 1)

$v2322 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"
Add-Result "2.3.2.2" "Audit: Shut down system immediately if unable to log security audits" $v2322 "0 (Disabled)" ($v2322 -eq 0)

# ==============================================================================
# 2.3.4 Devices (Thiết bị)
# ==============================================================================
$v2341 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
Add-Result "2.3.4.1" "Devices: Prevent users from installing printer drivers" $v2341 "1 (Enabled)" ($v2341 -eq 1)

# ==============================================================================
# 2.3.7 Interactive logon (Đăng nhập tương tác)
# ==============================================================================
$v2371 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
Add-Result "2.3.7.1" "Interactive logon: Do not require CTRL+ALT+DEL" $v2371 "0 (Disabled)" ($v2371 -eq 0)

$v2372 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
Add-Result "2.3.7.2" "Interactive logon: Don't display last signed-in" $v2372 "1 (Enabled)" ($v2372 -eq 1)

$v2373 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
Add-Result "2.3.7.3" "Interactive logon: Machine inactivity limit" $v2373 "<= 900 and != 0" ($null -ne $v2373 -and $v2373 -le 900 -and $v2373 -gt 0)

$v2374 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
Add-Result "2.3.7.4" "Interactive logon: Message text for users attempting to log on" $v2374 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v2374))

$v2375 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
Add-Result "2.3.7.5" "Interactive logon: Message title for users attempting to log on" $v2375 "Configured (Not Empty)" (-not [string]::IsNullOrWhiteSpace($v2375))

$v2376 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning"
Add-Result "2.3.7.6" "Interactive logon: Prompt user to change password before expiration" $v2376 "5 to 14 days" ($null -ne $v2376 -and $v2376 -ge 5 -and $v2376 -le 14)

$v2377 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption"
Add-Result "2.3.7.7" "Interactive logon: Smart card removal behavior" $v2377 "1, 2, or 3" ($v2377 -in @('1', '2', '3', 1, 2, 3))

# ==============================================================================
# 2.3.8 Microsoft network client
# ==============================================================================
$v2381 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
Add-Result "2.3.8.1" "Microsoft network client: Digitally sign communications (always)" $v2381 "1 (Enabled)" ($v2381 -eq 1)

$v2382 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
Add-Result "2.3.8.2" "Microsoft network client: Send unencrypted password to third-party SMB servers" $v2382 "0 (Disabled)" ($v2382 -eq 0)

# ==============================================================================
# 2.3.9 Microsoft network server
# ==============================================================================
$v2391 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect"
Add-Result "2.3.9.1" "Microsoft network server: Amount of idle time required before suspending session" $v2391 "<= 15" ($null -ne $v2391 -and $v2391 -le 15)

$v2392 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
Add-Result "2.3.9.2" "Microsoft network server: Digitally sign communications (always)" $v2392 "1 (Enabled)" ($v2392 -eq 1)

$v2393 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "enableforcedlogoff"
Add-Result "2.3.9.3" "Microsoft network server: Disconnect clients when logon hours expire" $v2393 "1 (Enabled)" ($v2393 -eq 1)

$v2394 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "SMBServerNameHardeningLevel"
Add-Result "2.3.9.4" "Microsoft network server: Server SPN target name validation level" $v2394 "1 or 2" ($v2394 -in @(1, 2, '1', '2'))

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress