# ==============================================================================
# Script: scan_rule_18_part2_2022.ps1
# Description: Quét cấu hình Mục 18 (18.6 Network, 18.7 Printers, 18.8, 18.9.3-18.9.5)
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
# 18.6 Network
# ==============================================================================
$v18641 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMDNS"
Add-Result "18.6.4.1" "Configure multicast DNS (mDNS) protocol" $v18641 "0 (Disabled)" ($v18641 -eq 0)

$v18642 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableIPv6DefaultDnsServers"
Add-Result "18.6.4.2" "Turn off default IPv6 DNS Servers" $v18642 "1 (Enabled)" ($v18642 -eq 1)

$v18651 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders"
Add-Result "18.6.5.1" "Enable Font Providers" $v18651 "0 (Disabled)" ($v18651 -eq 0)

$v18671 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "MinSmb2Dialect"
Add-Result "18.6.7.1" "Mandate the minimum version of SMB" $v18671 "785 (3.1.1)" ($v18671 -eq 785)

$v18681 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth"
Add-Result "18.6.8.1" "Enable insecure guest logons" $v18681 "0 (Disabled)" ($v18681 -eq 0)

$v18682 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "RequireEncryption"
Add-Result "18.6.8.2" "Require Encryption" $v18682 "1 (Enabled)" ($v18682 -eq 1)

# 18.6.9.1 LLTDIO Driver (Check 4 keys)
$v18691_1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnDomain"
$v18691_2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnPublicNet"
$v18691_3 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableLLTDIO"
$v18691_4 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitLLTDIOOnPrivateNet"
$v18691_Pass = ($v18691_1 -eq 0) -and ($v18691_2 -eq 0) -and ($v18691_3 -eq 0) -and ($v18691_4 -eq 0)
Add-Result "18.6.9.1" "Turn on Mapper I/O (LLTDIO) driver" "Multi-Key Check" "All 0 (Disabled)" $v18691_Pass

# 18.6.9.2 RSPNDR Driver (Check 4 keys)
$v18692_1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnDomain"
$v18692_2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnPublicNet"
$v18692_3 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableRspndr"
$v18692_4 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitRspndrOnPrivateNet"
$v18692_Pass = ($v18692_1 -eq 0) -and ($v18692_2 -eq 0) -and ($v18692_3 -eq 0) -and ($v18692_4 -eq 0)
Add-Result "18.6.9.2" "Turn on Responder (RSPNDR) driver" "Multi-Key Check" "All 0 (Disabled)" $v18692_Pass

$v186102 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled"
Add-Result "18.6.10.2" "Turn off Microsoft Peer-to-Peer Networking Services" $v186102 "1 (Enabled)" ($v186102 -eq 1)

$v186112 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA"
Add-Result "18.6.11.2" "Prohibit installation and configuration of Network Bridge..." $v186112 "0 (Disabled)" ($v186112 -eq 0)

$v186113 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI"
Add-Result "18.6.11.3" "Prohibit use of Internet Connection Sharing..." $v186113 "0 (Disabled)" ($v186113 -eq 0)

# 18.6.14.1 Hardened UNC Paths
$v186141_1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON"
$v186141_2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL"
$v186141_Pass = ($v186141_1 -match "RequireMutualAuthentication=1" -and $v186141_1 -match "RequireIntegrity=1" -and $v186141_1 -match "RequirePrivacy=1") -and `
                ($v186141_2 -match "RequireMutualAuthentication=1" -and $v186141_2 -match "RequireIntegrity=1" -and $v186141_2 -match "RequirePrivacy=1")
Add-Result "18.6.14.1" "Hardened UNC Paths" "Multi-Key Check" "Configured for NETLOGON & SYSVOL" $v186141_Pass

$v1861921 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents"
Add-Result "18.6.19.2.1" "Disable IPv6" $v1861921 "255 (0xff)" ($v1861921 -eq 255)

# 18.6.20.1 Windows Connect Now Registrars (Check 5 keys)
$vWCN1 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "EnableRegistrars"
$vWCN2 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableUPnPRegistrar"
$vWCN3 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableInBand802DOT11Registrar"
$vWCN4 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar"
$vWCN5 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableWPDRegistrar"
$vWCN_Pass = ($vWCN1 -eq 0 -and $vWCN2 -eq 0 -and $vWCN3 -eq 0 -and $vWCN4 -eq 0 -and $vWCN5 -eq 0)
Add-Result "18.6.20.1" "Configuration of wireless settings using Windows Connect Now" "Multi-Key Check" "All 0 (Disabled)" $vWCN_Pass

$v186202 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi"
Add-Result "18.6.20.2" "Prohibit access of the Windows Connect Now wizards" $v186202 "1 (Enabled)" ($v186202 -eq 1)

$v186211 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections"
Add-Result "18.6.21.1" "Minimize the number of simultaneous connections..." $v186211 "3" ($v186211 -eq 3)

# ==============================================================================
# 18.7 Printers
# ==============================================================================
$v1871 = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint"
Add-Result "18.7.1" "Allow Print Spooler to accept client connections" $v1871 "2 (Disabled)" ($v1871 -eq 2)

$v1872 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RedirectionguardPolicy"
Add-Result "18.7.2" "Configure Redirection Guard" $v1872 "1 (Enabled)" ($v1872 -eq 1)

$v1873 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcUseNamedPipeProtocol"
Add-Result "18.7.3" "Configure RPC connection settings: Protocol to use..." $v1873 "0 (Enabled: RPC over TCP)" ($v1873 -eq 0)

$v1874 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcAuthentication"
Add-Result "18.7.4" "Configure RPC connection settings: Use authentication..." $v1874 "0 (Default)" ($v1874 -eq 0)

$v1875 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcProtocols"
Add-Result "18.7.5" "Configure RPC listener settings: Protocols to allow..." $v1875 "5 (RPC over TCP)" ($v1875 -eq 5)

$v1876 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "ForceKerberosForRpc"
Add-Result "18.7.6" "Configure RPC listener settings: Authentication protocol..." $v1876 "0 or 1" ($v1876 -in @(0, 1))

$v1877 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcTcpPort"
Add-Result "18.7.7" "Configure RPC over TCP port" $v1877 "0" ($v1877 -eq 0)

$v1878 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled"
Add-Result "18.7.8" "Configure RPC packet level privacy setting..." $v1878 "1 (Enabled)" ($v1878 -eq 1)

$v1879 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators"
Add-Result "18.7.9" "Limits print driver installation to Administrators" $v1879 "1 (Enabled)" ($v1879 -eq 1)

$v18710 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "CopyFilesPolicy"
Add-Result "18.7.10" "Manage processing of Queue-specific files" $v18710 "1 (Enabled)" ($v18710 -eq 1)

$v18711 = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "NoWarningNoElevationOnInstall"
Add-Result "18.7.11" "Point and Print Restrictions: When installing drivers..." $v18711 "0 (Enabled)" ($v18711 -eq 0)

$v18712 = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "UpdatePromptSettings"
Add-Result "18.7.12" "Point and Print Restrictions: When updating drivers..." $v18712 "0 (Enabled)" ($v18712 -eq 0)

# ==============================================================================
# 18.8 Start Menu and 18.9 System (Early parts)
# ==============================================================================
$v18811 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification"
Add-Result "18.8.1.1" "Turn off notifications network usage" $v18811 "1 (Enabled)" ($v18811 -eq 1)

$v18931 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
Add-Result "18.9.3.1" "Include command line in process creation events" $v18931 "1 (Enabled)" ($v18931 -eq 1)

$v18941 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"
Add-Result "18.9.4.1" "Encryption Oracle Remediation" $v18941 "0 (Force Updated Clients)" ($v18941 -eq 0)

$v18942 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
Add-Result "18.9.4.2" "Remote host allows delegation of non-exportable credentials" $v18942 "1 (Enabled)" ($v18942 -eq 1)

$v18951 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity"
Add-Result "18.9.5.1" "Turn On Virtualization Based Security" $v18951 "1 (Enabled)" ($v18951 -eq 1)

$v18952 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures"
Add-Result "18.9.5.2" "Turn On Virtualization Based Security: Select Platform Security Level" $v18952 "1 or 3" ($v18952 -in @(1, 3))

$v18953 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity"
Add-Result "18.9.5.3" "Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity" $v18953 "1" ($v18953 -eq 1)

$v18954 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired"
Add-Result "18.9.5.4" "Turn On Virtualization Based Security: Require UEFI Memory Attributes Table" $v18954 "1" ($v18954 -eq 1)

$v18955 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags"
Add-Result "18.9.5.5" "Turn On Virtualization Based Security: Credential Guard Configuration" $v18955 "1" ($v18955 -eq 1)

$v18956 = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch"
Add-Result "18.9.5.6" "Turn On Virtualization Based Security: Secure Launch Configuration" $v18956 "1 (Enabled)" ($v18956 -eq 1)

# ==============================================================================
# Xuất JSON
# ==============================================================================
$script:Results | ConvertTo-Json -Depth 4 -Compress