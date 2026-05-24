# ==============================================================================
# Script: scan_rule_19_2022.ps1
# Description: Quét cấu hình Mục 19 (Administrative Templates - User Profiles)
# ==============================================================================

$script:Results = @()

# 1. Thu thập danh sách các User SID (bỏ qua các tài khoản hệ thống)
# ĐÃ FIX: Bọc @() để đảm bảo luôn là mảng, tránh lỗi .Count khi không có user nào
$UserSIDs = @(Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object {
    $_.PSChildName -match "^S-1-5-21-\d+-\d+-\d+-\d+$" -and $_.PSChildName -notmatch "_Classes$"
})

# 2. Hàm hỗ trợ đọc Registry theo từng SID
function Get-RegValueHKU {
    param([string]$SID, [string]$SubPath, [string]$Name)
    try {
        $fullPath = "Registry::HKEY_USERS\$SID\$SubPath"
        # ĐÃ FIX: Dùng Get-ItemPropertyValue an toàn hơn cho Strict Mode
        $val = Get-ItemPropertyValue -Path $fullPath -Name $Name -ErrorAction Stop
        if ($null -eq $val) { return $null }
        return $val
    } catch {
        return $null
    }
}

# 3. Hàm kiểm tra gộp cho tất cả user (Nếu 1 user fail => Hệ thống fail)
function Add-UserResult ($RuleID, $PolicyName, $SubPath, $RegKey, $ExpectedVal, $Desc) {
    # ĐÃ FIX: Kiểm tra an toàn $null trước khi đếm Count
    if ($null -eq $UserSIDs -or $UserSIDs.Count -eq 0) {
        # Không có user nào log in / tải profile
        $script:Results += [PSCustomObject]@{ 
            "RuleID" = $RuleID; 
            "PolicyName" = $PolicyName; 
            "CurrentValue" = "No Users Loaded"; 
            "RecommendedValue" = $Desc; 
            "Status" = "PASS" 
        }
        return
    }

    $allPassed = $true
    $failList = @()

    foreach ($user in $UserSIDs) {
        $sid = $user.PSChildName
        $val = Get-RegValueHKU $sid $SubPath $RegKey
        
        if ($val -ne $ExpectedVal) {
            $allPassed = $false
            $disp = if ($null -eq $val) { "Empty" } else { $val }
            $failList += "$sid ($disp)"
        }
    }

    $CurrentDisplay = if ($allPassed) { "All Users Compliant" } else { "Failures on: " + ($failList -join ', ') }
    
    $script:Results += [PSCustomObject]@{
        "RuleID"           = $RuleID
        "PolicyName"       = $PolicyName
        "CurrentValue"     = $CurrentDisplay
        "RecommendedValue" = $Desc
        "Status"           = if ($allPassed) { "PASS" } else { "FAIL" }
    }
}

# ==============================================================================
# 19.5 - 19.7 User Policies
# ==============================================================================
$pnPath = "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
Add-UserResult "19.5.1.1" "Turn off toast notifications on the lock screen" $pnPath "NoToastApplicationNotificationOnLockScreen" 1 "1 (Enabled)"

$assistPath = "Software\Policies\Microsoft\Assistance\Client\1.0"
Add-UserResult "19.6.6.1.1" "Turn off Help Experience Improvement Program" $assistPath "NoImplicitFeedback" 1 "1 (Enabled)"

$attachPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
Add-UserResult "19.7.5.1" "Do not preserve zone information in file attachments" $attachPath "SaveZoneInformation" 2 "2 (Disabled)"
Add-UserResult "19.7.5.2" "Notify antivirus programs when opening attachments" $attachPath "ScanWithAntiVirus" 3 "3 (Enabled)"

$cloudPath = "Software\Policies\Microsoft\Windows\CloudContent"
Add-UserResult "19.7.8.1" "Configure Windows spotlight on lock screen" $cloudPath "ConfigureWindowsSpotlight" 2 "2 (Disabled)"
Add-UserResult "19.7.8.2" "Do not suggest third-party content in Windows spotlight" $cloudPath "DisableThirdPartySuggestions" 1 "1 (Enabled)"
Add-UserResult "19.7.8.3" "Do not use diagnostic data for tailored experiences" $cloudPath "DisableTailoredExperiencesWithDiagnosticData" 1 "1 (Enabled)"
Add-UserResult "19.7.8.4" "Turn off all Windows spotlight features" $cloudPath "DisableWindowsSpotlightFeatures" 1 "1 (Enabled)"
Add-UserResult "19.7.8.5" "Turn off Spotlight collection on Desktop" $cloudPath "DisableSpotlightCollectionOnDesktop" 1 "1 (Enabled)"

$expPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Add-UserResult "19.7.26.1" "Prevent users from sharing files within their profile" $expPath "NoInplaceSharing" 1 "1 (Enabled)"

$wmpPath = "Software\Policies\Microsoft\WindowsMediaPlayer"
Add-UserResult "19.7.46.2.1" "Prevent Codec Download" $wmpPath "PreventCodecDownload" 1 "1 (Enabled)"

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress