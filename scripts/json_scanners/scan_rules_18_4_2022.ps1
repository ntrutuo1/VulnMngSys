# ==============================================================================
# Script: scan_rule_18_part5_2022.ps1
# Description: Quét cấu hình Mục 18 (18.10.16 Data Collection - 18.10.29 Explorer)
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
# 18.10.16 Data Collection
# ==============================================================================
$v1810161 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
Add-Result "18.10.16.1" "Allow Diagnostic Data" $v1810161 "0 or 1" ($v1810161 -in @(0, 1))

$v1810162 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy"
Add-Result "18.10.16.2" "Configure Authenticated Proxy usage..." $v1810162 "1 (Enabled)" ($v1810162 -eq 1)

$v1810163 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications"
Add-Result "18.10.16.3" "Do not show feedback notifications" $v1810163 "1 (Enabled)" ($v1810163 -eq 1)

$v1810164 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing"
Add-Result "18.10.16.4" "Enable OneSettings Auditing" $v1810164 "1 (Enabled)" ($v1810164 -eq 1)

$v1810165 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection"
Add-Result "18.10.16.5" "Limit Diagnostic Log Collection" $v1810165 "1 (Enabled)" ($v1810165 -eq 1)

$v1810166 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection"
Add-Result "18.10.16.6" "Limit Dump Collection" $v1810166 "1 (Enabled)" ($v1810166 -eq 1)

# ==============================================================================
# 18.10.18 Desktop App Installer
# ==============================================================================
$v1810181 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableAppInstaller"
Add-Result "18.10.18.1" "Enable App Installer" $v1810181 "0 (Disabled)" ($v1810181 -eq 0)

$v1810182 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableExperimentalFeatures"
Add-Result "18.10.18.2" "Enable App Installer Experimental Features" $v1810182 "0 (Disabled)" ($v1810182 -eq 0)

$v1810183 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableHashOverride"
Add-Result "18.10.18.3" "Enable App Installer Hash Override" $v1810183 "0 (Disabled)" ($v1810183 -eq 0)

$v1810184 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableLocalArchiveMalwareScanOverride"
Add-Result "18.10.18.4" "Enable App Installer Local Archive Malware Scan Override" $v1810184 "0 (Disabled)" ($v1810184 -eq 0)

$v1810185 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableMSAppInstallerProtocol"
Add-Result "18.10.18.5" "Enable App Installer ms-appinstaller protocol" $v1810185 "0 (Disabled)" ($v1810185 -eq 0)

$v1810186 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableBypassCertificatePinningForMicrosoftStore"
Add-Result "18.10.18.6" "Enable App Installer Microsoft Store Source Certificate Validation Bypass" $v1810186 "0 (Disabled)" ($v1810186 -eq 0)

$v1810187 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableWindowsPackageManagerCommandLineInterfaces"
Add-Result "18.10.18.7" "Enable Windows Package Manager command line interfaces" $v1810187 "0 (Disabled)" ($v1810187 -eq 0)

# ==============================================================================
# 18.10.26 Event Log Service
# ==============================================================================
# Application Log
$v18102611 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention"
Add-Result "18.10.26.1.1" "Application: Control Event Log behavior... reaches its maximum size" $v18102611 "'0' (Disabled)" ($v18102611 -eq "0")

$v18102612 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize"
Add-Result "18.10.26.1.2" "Application: Specify the maximum log file size (KB)" $v18102612 ">= 32768" ($null -ne $v18102612 -and $v18102612 -ge 32768)

# Security Log
$v18102621 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention"
Add-Result "18.10.26.2.1" "Security: Control Event Log behavior... reaches its maximum size" $v18102621 "'0' (Disabled)" ($v18102621 -eq "0")

$v18102622 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize"
Add-Result "18.10.26.2.2" "Security: Specify the maximum log file size (KB)" $v18102622 ">= 196608" ($null -ne $v18102622 -and $v18102622 -ge 196608)

# Setup Log
$v18102631 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention"
Add-Result "18.10.26.3.1" "Setup: Control Event Log behavior... reaches its maximum size" $v18102631 "'0' (Disabled)" ($v18102631 -eq "0")

$v18102632 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize"
Add-Result "18.10.26.3.2" "Setup: Specify the maximum log file size (KB)" $v18102632 ">= 32768" ($null -ne $v18102632 -and $v18102632 -ge 32768)

# System Log
$v18102641 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention"
Add-Result "18.10.26.4.1" "System: Control Event Log behavior... reaches its maximum size" $v18102641 "'0' (Disabled)" ($v18102641 -eq "0")

$v18102642 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize"
Add-Result "18.10.26.4.2" "System: Specify the maximum log file size (KB)" $v18102642 ">= 32768" ($null -ne $v18102642 -and $v18102642 -ge 32768)

# ==============================================================================
# 18.10.29 File Explorer
# ==============================================================================
$v1810292 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableMotWOnInsecurePathCopy"
Add-Result "18.10.29.2" "Do not apply the Mark of the Web tag to files copied from insecure sources" $v1810292 "0 (Disabled)" ($v1810292 -eq 0)

$v1810293 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention"
Add-Result "18.10.29.3" "Turn off Data Execution Prevention for Explorer" $v1810293 "0 (Disabled)" ($v1810293 -eq 0)

$v1810294 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption"
Add-Result "18.10.29.4" "Turn off heap termination on corruption" $v1810294 "0 (Disabled)" ($v1810294 -eq 0)

$v1810295 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior"
Add-Result "18.10.29.5" "Turn off shell protocol protected mode" $v1810295 "0 (Disabled)" ($v1810295 -eq 0)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress