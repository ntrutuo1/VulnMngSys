# ==============================================================================
# Script: scan_rule_18_part4_2022.ps1
# Description: Quét cấu hình Mục 18 (18.9.38 - 18.9.53 và 18.10.4 - 18.10.15)
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
# 18.9.38 - 18.9.53 System
# ==============================================================================
$v189381 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution"
Add-Result "18.9.38.1" "Enable RPC Endpoint Mapper Client Authentication" $v189381 "1 (Enabled)" ($v189381 -eq 1)

$v189382 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients"
Add-Result "18.9.38.2" "Restrict Unauthenticated RPC clients" $v189382 "1 (Authenticated)" ($v189382 -eq 1)

$v1894951 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer"
Add-Result "18.9.49.5.1" "MSDT: Turn on MSDT interactive communication with support provider" $v1894951 "0 (Disabled)" ($v1894951 -eq 0)

$v18949111 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" "ScenarioExecutionEnabled"
Add-Result "18.9.49.11.1" "Enable/Disable PerfTrack" $v18949111 "0 (Disabled)" ($v18949111 -eq 0)

$v189511 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy"
Add-Result "18.9.51.1" "Turn off the advertising ID" $v189511 "1 (Enabled)" ($v189511 -eq 1)

$v1895311 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled"
Add-Result "18.9.53.1.1" "Enable Windows NTP Client" $v1895311 "1 (Enabled)" ($v1895311 -eq 1)

# ==============================================================================
# 18.10.4 - 18.10.15 Windows Components
# ==============================================================================
$v181041 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData"
Add-Result "18.10.4.1" "Allow a Windows app to share application data between users" $v181041 "0 (Disabled)" ($v181041 -eq 0)

$v181061 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"
Add-Result "18.10.6.1" "Allow Microsoft accounts to be optional" $v181061 "1 (Enabled)" ($v181061 -eq 1)

$v181081 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume"
Add-Result "18.10.8.1" "Disallow Autoplay for non-volume devices" $v181081 "1 (Enabled)" ($v181081 -eq 1)

$v181082 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
Add-Result "18.10.8.2" "Set the default behavior for AutoRun" $v181082 "1 (Do not execute any autorun commands)" ($v181082 -eq 1)

$v181083 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
Add-Result "18.10.8.3" "Turn off Autoplay" $v181083 "255 (All drives)" ($v181083 -eq 255)

$v1810911 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"
Add-Result "18.10.9.1.1" "Configure enhanced anti-spoofing" $v1810911 "1 (Enabled)" ($v1810911 -eq 1)

$v1810111 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera"
Add-Result "18.10.11.1" "Allow Use of Camera" $v1810111 "0 (Disabled)" ($v1810111 -eq 0)

$v1810131 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent"
Add-Result "18.10.13.1" "Turn off cloud consumer account state content" $v1810131 "1 (Enabled)" ($v1810131 -eq 1)

$v1810132 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent"
Add-Result "18.10.13.2" "Turn off cloud optimized content" $v1810132 "1 (Enabled)" ($v1810132 -eq 1)

$v1810141 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing"
Add-Result "18.10.14.1" "Require pin for pairing" $v1810141 "1 or 2" ($v1810141 -in @(1, 2))

$v1810151 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
Add-Result "18.10.15.1" "Do not display the password reveal button" $v1810151 "1 (Enabled)" ($v1810151 -eq 1)

$v1810152 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators"
Add-Result "18.10.15.2" "Enumerate administrator accounts on elevation" $v1810152 "0 (Disabled)" ($v1810152 -eq 0)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress