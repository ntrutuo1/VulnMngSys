# ==============================================================================
# Script: scan_rule_18_part3_2022.ps1
# Description: Quét cấu hình Mục 18 (18.9 System: 18.9.7 - 18.9.37)
# ==============================================================================

$script:Results = @()

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
# 18.9.7 - 18.9.19
# ==============================================================================
$v18972 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork"
Add-Result "18.9.7.2" "Prevent automatic download of applications associated with device metadata" $v18972 "1 (Enabled)" ($v18972 -eq 1)

$v189131 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
Add-Result "18.9.13.1" "Boot-Start Driver Initialization Policy" $v189131 "3" ($v189131 -eq 3)

$v189171 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies" "ClfsAuthenticationChecking"
Add-Result "18.9.17.1" "Enable / disable CLFS logfile authentication" $v189171 "1 (Enabled)" ($v189171 -eq 1)

$v189192 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp"
Add-Result "18.9.19.2" "Continue experiences on this device" $v189192 "0 (Disabled)" ($v189192 -eq 0)

# ==============================================================================
# 18.9.20 Internet Communication Management
# ==============================================================================
$v1892011 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload"
Add-Result "18.9.20.1.1" "Turn off downloading of print drivers over HTTP" $v1892011 "1 (Enabled)" ($v1892011 -eq 1)

$v1892012 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing"
Add-Result "18.9.20.1.2" "Turn off handwriting personalization data sharing" $v1892012 "1 (Enabled)" ($v1892012 -eq 1)

$v1892013 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports"
Add-Result "18.9.20.1.3" "Turn off handwriting recognition error reporting" $v1892013 "1 (Enabled)" ($v1892013 -eq 1)

$v1892014 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW"
Add-Result "18.9.20.1.4" "Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com" $v1892014 "1 (Enabled)" ($v1892014 -eq 1)

$v1892015 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices"
Add-Result "18.9.20.1.5" "Turn off Internet download for Web publishing..." $v1892015 "1 (Enabled)" ($v1892015 -eq 1)

$v1892016 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting"
Add-Result "18.9.20.1.6" "Turn off printing over HTTP" $v1892016 "1 (Enabled)" ($v1892016 -eq 1)

$v1892017 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration"
Add-Result "18.9.20.1.7" "Turn off Registration if URL connection is referring to Microsoft.com" $v1892017 "1 (Enabled)" ($v1892017 -eq 1)

$v1892018 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates"
Add-Result "18.9.20.1.8" "Turn off Search Companion content file updates" $v1892018 "1 (Enabled)" ($v1892018 -eq 1)

$v1892019 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard"
Add-Result "18.9.20.1.9" "Turn off the Order Prints picture task" $v1892019 "1 (Enabled)" ($v1892019 -eq 1)

$v18920110 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard"
Add-Result "18.9.20.1.10" "Turn off the Publish to Web task for files and folders" $v18920110 "1 (Enabled)" ($v18920110 -eq 1)

$v18920111 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP"
Add-Result "18.9.20.1.11" "Turn off the Windows Messenger Customer Experience Improvement Program" $v18920111 "2 (Enabled)" ($v18920111 -eq 2)

$v18920112 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable"
Add-Result "18.9.20.1.12" "Turn off Windows Customer Experience Improvement Program" $v18920112 "0 (Enabled)" ($v18920112 -eq 0)

$vWER1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled"
$vWER2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport"
$vWER_Pass = ($vWER1 -eq 1) -and ($vWER2 -eq 0)
Add-Result "18.9.20.1.13" "Turn off Windows Error Reporting" "Multi-Key Check" "Disabled=1, DoReport=0" $vWER_Pass

# ==============================================================================
# 18.9.24 - 18.9.37
# ==============================================================================
$v189241 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
Add-Result "18.9.24.1" "Enumeration policy for external devices incompatible with Kernel DMA Protection" $v189241 "0 (Block All)" ($v189241 -eq 0)

$v189271 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "RunAsPPL"
Add-Result "18.9.27.1" "Configures LSASS to run as a protected process" $v189271 "1 (Enabled)" ($v189271 -eq 1)

$v189281 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" "BlockUserInputMethodsForSignIn"
Add-Result "18.9.28.1" "Disallow copying of user input methods to the system account for sign-in" $v189281 "1 (Enabled)" ($v189281 -eq 1)

$v189291 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin"
Add-Result "18.9.29.1" "Block user from showing account details on sign-in" $v189291 "1 (Enabled)" ($v189291 -eq 1)

$v189292 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI"
Add-Result "18.9.29.2" "Do not display network selection UI" $v189292 "1 (Enabled)" ($v189292 -eq 1)

$v189293 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications"
Add-Result "18.9.29.3" "Turn off app notifications on the lock screen" $v189293 "1 (Enabled)" ($v189293 -eq 1)

$v189294 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon"
Add-Result "18.9.29.4" "Turn on convenience PIN sign-in" $v189294 "0 (Disabled)" ($v189294 -eq 0)

$v189331 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard"
Add-Result "18.9.33.1" "Allow Clipboard synchronization across devices" $v189331 "0 (Disabled)" ($v189331 -eq 0)

$v189332 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities"
Add-Result "18.9.33.2" "Allow upload of User Activities" $v189332 "0 (Disabled)" ($v189332 -eq 0)

# Power Management
$v1893561 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "DCSettingIndex"
Add-Result "18.9.35.6.1" "Allow network connectivity during connected-standby (on battery)" $v1893561 "0 (Disabled)" ($v1893561 -eq 0)

$v1893562 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "ACSettingIndex"
Add-Result "18.9.35.6.2" "Allow network connectivity during connected-standby (plugged in)" $v1893562 "0 (Disabled)" ($v1893562 -eq 0)

$v1893563 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex"
Add-Result "18.9.35.6.3" "Require a password when a computer wakes (on battery)" $v1893563 "1 (Enabled)" ($v1893563 -eq 1)

$v1893564 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex"
Add-Result "18.9.35.6.4" "Require a password when a computer wakes (plugged in)" $v1893564 "1 (Enabled)" ($v1893564 -eq 1)

# Remote Assistance
$v189371 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"
Add-Result "18.9.37.1" "Configure Offer Remote Assistance" $v189371 "0 (Disabled)" ($v189371 -eq 0)

$v189372 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"
Add-Result "18.9.37.2" "Configure Solicited Remote Assistance" $v189372 "0 (Disabled)" ($v189372 -eq 0)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress