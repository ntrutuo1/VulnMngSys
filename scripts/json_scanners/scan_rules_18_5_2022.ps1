# ==============================================================================
# Script: scan_rule_18_part6_2022.ps1
# Description: Quét cấu hình Mục 18 (Từ 18.10.36 đến 18.11 Custom Settings)
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
# 18.10.36 - 18.10.56 Location, Messaging, Accounts, Push To Install
# ==============================================================================
$v1810361 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation"
Add-Result "18.10.36.1" "Turn off location" $v1810361 "1 (Enabled)" ($v1810361 -eq 1)

$v1810401 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync"
Add-Result "18.10.40.1" "Allow Message Service Cloud Sync" $v1810401 "0 (Disabled)" ($v1810401 -eq 0)

$v1810411 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth"
Add-Result "18.10.41.1" "Block all consumer Microsoft account user authentication" $v1810411 "1 (Enabled)" ($v1810411 -eq 1)

$v1810561 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall"
Add-Result "18.10.56.1" "Turn off Push To Install service" $v1810561 "1 (Enabled)" ($v1810561 -eq 1)

# ==============================================================================
# 18.10.57 Remote Desktop Services
# ==============================================================================
$rdpTermPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$v18105722 = Get-RegValue $rdpTermPath "DisablePasswordSaving"
Add-Result "18.10.57.2.2" "Do not allow passwords to be saved" $v18105722 "1 (Enabled)" ($v18105722 -eq 1)

$v181057321 = Get-RegValue $rdpTermPath "fSingleSessionPerUser"
Add-Result "18.10.57.3.2.1" "Restrict RDS users to a single session" $v181057321 "1 (Enabled)" ($v181057321 -eq 1)

$v181057331 = Get-RegValue $rdpTermPath "EnableUiaRedirection"
Add-Result "18.10.57.3.3.1" "Allow UI Automation redirection" $v181057331 "0 (Disabled)" ($v181057331 -eq 0)

$v181057332 = Get-RegValue $rdpTermPath "fDisableCcm"
Add-Result "18.10.57.3.3.2" "Do not allow COM port redirection" $v181057332 "1 (Enabled)" ($v181057332 -eq 1)

$v181057333 = Get-RegValue $rdpTermPath "fDisableCdm"
Add-Result "18.10.57.3.3.3" "Do not allow drive redirection" $v181057333 "1 (Enabled)" ($v181057333 -eq 1)

$v181057334 = Get-RegValue $rdpTermPath "fDisableLocationRedir"
Add-Result "18.10.57.3.3.4" "Do not allow location redirection" $v181057334 "1 (Enabled)" ($v181057334 -eq 1)

$v181057335 = Get-RegValue $rdpTermPath "fDisableLPT"
Add-Result "18.10.57.3.3.5" "Do not allow LPT port redirection" $v181057335 "1 (Enabled)" ($v181057335 -eq 1)

$v181057336 = Get-RegValue $rdpTermPath "fDisablePNPRedir"
Add-Result "18.10.57.3.3.6" "Do not allow supported Plug and Play device redirection" $v181057336 "1 (Enabled)" ($v181057336 -eq 1)

$v181057337 = Get-RegValue $rdpTermPath "fDisableWebAuthn"
Add-Result "18.10.57.3.3.7" "Do not allow WebAuthn redirection" $v181057337 "1 (Enabled)" ($v181057337 -eq 1)

$v181057391 = Get-RegValue $rdpTermPath "fPromptForPassword"
Add-Result "18.10.57.3.9.1" "Always prompt for password upon connection" $v181057391 "1 (Enabled)" ($v181057391 -eq 1)

$v181057392 = Get-RegValue $rdpTermPath "fEncryptRPCTraffic"
Add-Result "18.10.57.3.9.2" "Require secure RPC communication" $v181057392 "1 (Enabled)" ($v181057392 -eq 1)

$v181057393 = Get-RegValue $rdpTermPath "SecurityLayer"
Add-Result "18.10.57.3.9.3" "Require use of specific security layer for RDP" $v181057393 "2 (SSL)" ($v181057393 -eq 2)

$v181057394 = Get-RegValue $rdpTermPath "UserAuthentication"
Add-Result "18.10.57.3.9.4" "Require Network Level Authentication" $v181057394 "1 (Enabled)" ($v181057394 -eq 1)

$v181057395 = Get-RegValue $rdpTermPath "MinEncryptionLevel"
Add-Result "18.10.57.3.9.5" "Set client connection encryption level" $v181057395 "3 (High Level)" ($v181057395 -eq 3)

$v1810573101 = Get-RegValue $rdpTermPath "MaxIdleTime"
Add-Result "18.10.57.3.10.1" "Set time limit for active but idle RDS sessions" $v1810573101 "<= 900000 and != 0" ($null -ne $v1810573101 -and $v1810573101 -le 900000 -and $v1810573101 -ne 0)

$v1810573111 = Get-RegValue $rdpTermPath "DeleteTempDirsOnExit"
Add-Result "18.10.57.3.11.1" "Do not delete temp folders upon exit" $v1810573111 "0 (Disabled)" ($v1810573111 -eq 0)

$v1810573112 = Get-RegValue $rdpTermPath "PerSessionTempDir"
Add-Result "18.10.57.3.11.2" "Do not use temporary folders per session" $v1810573112 "0 (Disabled)" ($v1810573112 -eq 0)

# ==============================================================================
# 18.10.58 - 18.10.93 WinRM, WinRS, Security, etc.
# ==============================================================================
$v1810592 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch"
Add-Result "18.10.59.2" "Allow Cloud Search" $v1810592 "0 (Disabled)" ($v1810592 -eq 0)

$v18107721 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
$v18107721_Str = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"
$vSmart_Pass = ($v18107721 -eq 1 -and $v18107721_Str -eq "Block")
Add-Result "18.10.77.2.1" "Configure Windows Defender SmartScreen" "Multi-Key Check" "1 and Block" $vSmart_Pass

$v1810881 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
Add-Result "18.10.88.1" "Turn on PowerShell Script Block Logging" $v1810881 "1 (Enabled)" ($v1810881 -eq 1)

$v1810882 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
Add-Result "18.10.88.2" "Turn on PowerShell Transcription" $v1810882 "1 (Enabled)" ($v1810882 -eq 1)

# WinRM
$vWRMC1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"
$vWRMS1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"
Add-Result "18.10.90.x.1" "WinRM: Allow Basic authentication" "Client:$vWRMC1 | Svc:$vWRMS1" "Both 0" ($vWRMC1 -eq 0 -and $vWRMS1 -eq 0)

$vWRMC2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic"
$vWRMS2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
Add-Result "18.10.90.x.2" "WinRM: Allow unencrypted traffic" "Client:$vWRMC2 | Svc:$vWRMS2" "Both 0" ($vWRMC2 -eq 0 -and $vWRMS2 -eq 0)

$v18109022 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig"
Add-Result "18.10.90.2.2" "Allow remote server management through WinRM" $v18109022 "0 (Disabled)" ($v18109022 -eq 0)

$v1810911 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess"
Add-Result "18.10.91.1" "Allow Remote Shell Access" $v1810911 "0 (Disabled)" ($v1810911 -eq 0)

$v18109321 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride"
Add-Result "18.10.93.2.1" "Prevent users from modifying settings" $v18109321 "1 (Enabled)" ($v18109321 -eq 1)

# ==============================================================================
# 18.10.94 Windows Update & 18.11 Custom Settings
# ==============================================================================
$wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

$v18109411 = Get-RegValue $wuAUPath "NoAutoRebootWithLoggedOnUsers"
Add-Result "18.10.94.1.1" "No auto-restart with logged on users..." $v18109411 "0 (Disabled)" ($v18109411 -eq 0)

$v18109421 = Get-RegValue $wuAUPath "NoAutoUpdate"
Add-Result "18.10.94.2.1" "Configure Automatic Updates" $v18109421 "0 (Enabled)" ($v18109421 -eq 0)

$v18109422 = Get-RegValue $wuAUPath "ScheduledInstallDay"
Add-Result "18.10.94.2.2" "Configure Automatic Updates: Scheduled install day" $v18109422 "0" ($v18109422 -eq 0)

$v18111 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad"
Add-Result "18.11.1" "Disable HTTP proxy features: Disable WPAD" $v18111 "1 (Enabled)" ($v18111 -eq 1)

$v18112 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisableProxyAuthenticationSchemes"
Add-Result "18.11.2" "Disable HTTP proxy features: Disable proxy authentication" $v18112 "256 or 287" ($v18112 -in @(256, 287))

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress