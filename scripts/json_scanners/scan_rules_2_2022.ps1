# ==============================================================================
# Script: scan_rule_2_2022.ps1
# Description: Quét cấu hình Local Policies - User Rights Assignment
# ==============================================================================

$script:Results = @()

# 1. Xuất cấu hình User Rights Assignment hiện tại ra file tạm
$secTemp = "$env:TEMP\secpol_user_rights_$([guid]::NewGuid()).cfg"
secedit /export /cfg $secTemp /areas USER_RIGHTS | Out-Null
$secContent = Get-Content $secTemp

# 2. Bảng ánh xạ SID sang tên Group chuẩn để dễ so sánh
$SidMap = @{
    '*S-1-5-32-544' = 'Administrators'
    '*S-1-5-32-546' = 'Guests'
    '*S-1-5-11'     = 'Authenticated Users'
    '*S-1-5-19'     = 'LOCAL SERVICE'
    '*S-1-5-20'     = 'NETWORK SERVICE'
    '*S-1-5-32-555' = 'Remote Desktop Users'
    '*S-1-5-6'      = 'SERVICE'
    '*S-1-5-83-0'   = 'NT VIRTUAL MACHINE\Virtual Machines'
    '*S-1-5-90-0'   = 'Window Manager\Window Manager Group'
    '*S-1-5-80-3139157870-2983391045-3678747466-658725182-3232115800' = 'NT SERVICE\WdiServiceHost'
}

# 3. Hàm phân tích, kiểm tra và gán kết quả
function Add-UserRightResult {
    param (
        [string]$RuleID,
        [string]$PolicyName,
        [string]$PrivilegeName,
        [string[]]$ExpectedGroups,
        [switch]$Includes
    )

    # Lấy dòng cấu hình từ file secedit
    $line = $secContent | Where-Object { $_ -match "^\s*$PrivilegeName\s*=\s*(.*)" }
    $currentGroups = @()
    
    if ($line -match "^\s*$PrivilegeName\s*=\s*(.*)") {
        $sids = $matches[1] -split ',' | Where-Object { $_ -ne "" }
        foreach ($sid in $sids) {
            $sidStr = $sid.Trim()
            if ($SidMap.ContainsKey($sidStr)) {
                $currentGroups += $SidMap[$sidStr]
            } else {
                $currentGroups += $sidStr # Giữ nguyên SID nếu không có trong từ điển
            }
        }
    }

    # Định dạng chuỗi hiển thị
    $CurrentDisplay = if ($currentGroups.Count -eq 0) { "No One" } else { ($currentGroups | Sort-Object) -join ', ' }
    $ExpectedDisplay = if ($ExpectedGroups.Count -eq 0) { "No One" } else { ($ExpectedGroups | Sort-Object) -join ', ' }

    # Xử lý Logic Đạt / Không đạt (Pass/Fail)
    $IsPassed = $false
    if ($Includes) {
        $ExpectedDisplay = "Includes: $ExpectedDisplay"
        # Điều kiện: Phải bao gồm (chứa) các nhóm yêu cầu
        $passedAll = $true
        foreach ($ex in $ExpectedGroups) {
            if ($currentGroups -notcontains $ex) {
                $passedAll = $false
                break
            }
        }
        $IsPassed = ($currentGroups.Count -gt 0 -and $passedAll)
    } else {
        # Điều kiện: Phải khớp chính xác tuyệt đối (Exact match)
        if ($currentGroups.Count -eq 0 -and $ExpectedGroups.Count -eq 0) {
            $IsPassed = $true
        } else {
            $curSorted = ($currentGroups | Sort-Object) -join ','
            $expSorted = ($ExpectedGroups | Sort-Object) -join ','
            $IsPassed = ($curSorted -eq $expSorted)
        }
    }

    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $CurrentDisplay
        "RecommendedValue" = $ExpectedDisplay
        "Status"           = if ($IsPassed) { "PASS" } else { "FAIL" }
    }
}

# ==============================================================================
# 4. Thực thi kiểm tra từng chính sách
# ==============================================================================

# 2.2.1 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
Add-UserRightResult "2.2.1" "Access Credential Manager as a trusted caller" "SeTrustedCredManAccessPrivilege" @()

# 2.2.2 Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
Add-UserRightResult "2.2.2" "Access this computer from the network" "SeNetworkLogonRight" @("Administrators", "Authenticated Users")

# 2.2.3 Ensure 'Act as part of the operating system' is set to 'No One'
Add-UserRightResult "2.2.3" "Act as part of the operating system" "SeTcbPrivilege" @()

# 2.2.4 Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
Add-UserRightResult "2.2.4" "Adjust memory quotas for a process" "SeIncreaseQuotaPrivilege" @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.5 Ensure 'Allow log on locally' is set to 'Administrators'
Add-UserRightResult "2.2.5" "Allow log on locally" "SeInteractiveLogonRight" @("Administrators")

# 2.2.6 Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
Add-UserRightResult "2.2.6" "Allow log on through Remote Desktop Services" "SeRemoteInteractiveLogonRight" @("Administrators", "Remote Desktop Users")

# 2.2.7 Ensure 'Back up files and directories' is set to 'Administrators'
Add-UserRightResult "2.2.7" "Back up files and directories" "SeBackupPrivilege" @("Administrators")

# 2.2.8 Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
Add-UserRightResult "2.2.8" "Change the system time" "SeSystemtimePrivilege" @("Administrators", "LOCAL SERVICE")

# 2.2.9 Ensure 'Create a pagefile' is set to 'Administrators'
Add-UserRightResult "2.2.9" "Create a pagefile" "SeCreatePagefilePrivilege" @("Administrators")

# 2.2.10 Ensure 'Create a token object' is set to 'No One'
Add-UserRightResult "2.2.10" "Create a token object" "SeCreateTokenPrivilege" @()

# 2.2.11 Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
Add-UserRightResult "2.2.11" "Create global objects" "SeCreateGlobalPrivilege" @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

# 2.2.12 Ensure 'Create permanent shared objects' is set to 'No One'
Add-UserRightResult "2.2.12" "Create permanent shared objects" "SeCreatePermanentPrivilege" @()

# 2.2.13 Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
Add-UserRightResult "2.2.13" "Create symbolic links" "SeCreateSymbolicLinkPrivilege" @("Administrators", "NT VIRTUAL MACHINE\Virtual Machines")

# 2.2.14 Ensure 'Debug programs' is set to 'Administrators'
Add-UserRightResult "2.2.14" "Debug programs" "SeDebugPrivilege" @("Administrators")

# 2.2.15 Ensure 'Deny access to this computer from the network' to include 'Guests' (Lưu ý: Include)
Add-UserRightResult "2.2.15" "Deny access to this computer from the network" "SeDenyNetworkLogonRight" @("Guests") -Includes

# 2.2.16 Ensure 'Deny log on as a batch job' to include 'Guests' (Lưu ý: Include)
Add-UserRightResult "2.2.16" "Deny log on as a batch job" "SeDenyBatchLogonRight" @("Guests") -Includes

# 2.2.17 Ensure 'Deny log on as a service' to include 'Guests' (Lưu ý: Include)
Add-UserRightResult "2.2.17" "Deny log on as a service" "SeDenyServiceLogonRight" @("Guests") -Includes

# 2.2.18 Ensure 'Deny log on locally' to include 'Guests' (Lưu ý: Include)
Add-UserRightResult "2.2.18" "Deny log on locally" "SeDenyInteractiveLogonRight" @("Guests") -Includes

# 2.2.19 Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'
Add-UserRightResult "2.2.19" "Deny log on through Remote Desktop Services" "SeDenyRemoteInteractiveLogonRight" @("Guests")

# 2.2.20 Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
Add-UserRightResult "2.2.20" "Enable computer and user accounts to be trusted for delegation" "SeEnableDelegationPrivilege" @()

# 2.2.21 Ensure 'Force shutdown from a remote system' is set to 'Administrators'
Add-UserRightResult "2.2.21" "Force shutdown from a remote system" "SeRemoteShutdownPrivilege" @("Administrators")

# 2.2.22 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
Add-UserRightResult "2.2.22" "Generate security audits" "SeAuditPrivilege" @("LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.23 Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
Add-UserRightResult "2.2.23" "Impersonate a client after authentication" "SeImpersonatePrivilege" @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")

# 2.2.24 Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
Add-UserRightResult "2.2.24" "Increase scheduling priority" "SeIncreaseBasePriorityPrivilege" @("Administrators", "Window Manager\Window Manager Group")

# 2.2.25 Ensure 'Load and unload device drivers' is set to 'Administrators'
Add-UserRightResult "2.2.25" "Load and unload device drivers" "SeLoadDriverPrivilege" @("Administrators")

# 2.2.26 Ensure 'Lock pages in memory' is set to 'No One'
Add-UserRightResult "2.2.26" "Lock pages in memory" "SeLockMemoryPrivilege" @()

# 2.2.27 Ensure 'Manage auditing and security log' is set to 'Administrators'
Add-UserRightResult "2.2.27" "Manage auditing and security log" "SeSecurityPrivilege" @("Administrators")

# 2.2.28 Ensure 'Modify an object label' is set to 'No One'
Add-UserRightResult "2.2.28" "Modify an object label" "SeRelabelPrivilege" @()

# 2.2.29 Ensure 'Modify firmware environment values' is set to 'Administrators'
Add-UserRightResult "2.2.29" "Modify firmware environment values" "SeSystemEnvironmentPrivilege" @("Administrators")

# 2.2.30 Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
Add-UserRightResult "2.2.30" "Perform volume maintenance tasks" "SeManageVolumePrivilege" @("Administrators")

# 2.2.31 Ensure 'Profile single process' is set to 'Administrators'
Add-UserRightResult "2.2.31" "Profile single process" "SeProfileSingleProcessPrivilege" @("Administrators")

# 2.2.32 Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
Add-UserRightResult "2.2.32" "Profile system performance" "SeSystemProfilePrivilege" @("Administrators", "NT SERVICE\WdiServiceHost")

# 2.2.33 Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
Add-UserRightResult "2.2.33" "Replace a process level token" "SeAssignPrimaryTokenPrivilege" @("LOCAL SERVICE", "NETWORK SERVICE")

# 2.2.34 Ensure 'Restore files and directories' is set to 'Administrators'
Add-UserRightResult "2.2.34" "Restore files and directories" "SeRestorePrivilege" @("Administrators")

# 2.2.35 Ensure 'Shut down the system' is set to 'Administrators'
Add-UserRightResult "2.2.35" "Shut down the system" "SeShutdownPrivilege" @("Administrators")

# 2.2.36 Ensure 'Take ownership of files or other objects' is set to 'Administrators'
Add-UserRightResult "2.2.36" "Take ownership of files or other objects" "SeTakeOwnershipPrivilege" @("Administrators")

# ==============================================================================
# 5. Cleanup & Xuất JSON
# ==============================================================================
Remove-Item $secTemp -ErrorAction SilentlyContinue

# Đẩy mảng object ra dạng chuỗi JSON cho scan_executor
$script:Results | ConvertTo-Json -Depth 4 -Compress