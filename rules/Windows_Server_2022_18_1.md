# Mục 18: Administrative Templates (Computer) - Phần 2

## 18.6 Network (Mạng)

* **18.6.4.1 Ensure 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMDNS` (Giá trị `REG_DWORD`: `0`).

* **18.6.4.2 Ensure 'Turn off default IPv6 DNS Servers' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:DisableIPv6DefaultDnsServers` (Giá trị `REG_DWORD`: `1`).

* **18.6.5.1 Ensure 'Enable Font Providers' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableFontProviders` (Giá trị `REG_DWORD`: `0`).

* **18.6.7.1 Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: 3.1.1.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:MinSmb2Dialect` (Giá trị `REG_DWORD`: `785` - tương đương `0x311` hệ hex).

* **18.6.8.1 Ensure 'Enable insecure guest logons' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AllowInsecureGuestAuth` (Giá trị `REG_DWORD`: `0`).

* **18.6.8.2 Ensure 'Require Encryption' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled (Bắt buộc mã hóa SMB).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:RequireEncryption` (Giá trị `REG_DWORD`: `1`).

* **18.6.9.1 Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry (cần check cả 4 khóa):** 
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnDomain` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnPublicNet` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableLLTDIO` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitLLTDIOOnPrivateNet` (`0`)

* **18.6.9.2 Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry (cần check cả 4 khóa):** 
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnDomain` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnPublicNet` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableRspndr` (`0`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitRspndrOnPrivateNet` (`0`)

* **18.6.10.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Peernet:Disabled` (Giá trị `REG_DWORD`: `1`).

* **18.6.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA` (Giá trị `REG_DWORD`: `0`).

* **18.6.11.3 Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI` (Giá trị `REG_DWORD`: `0`).

* **18.6.14.1 Ensure 'Hardened UNC Paths' is set to 'Enabled...' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled, với "Require Mutual Authentication", "Require Integrity", và "Require Privacy" được set cho các share NETLOGON và SYSVOL.
  * **Đường dẫn Registry:** 
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\NETLOGON` (Giá trị `REG_SZ`: `RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1`)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\SYSVOL` (Giá trị `REG_SZ`: `RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1`)

* **18.6.19.2.1 Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)') (Automated)**
  * **Trạng thái khuyến nghị:** DisabledComponents = 0xff (255).
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters:DisabledComponents` (Giá trị `REG_DWORD`: `255`).

* **18.6.20.1 Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry (cần check các khóa sau với giá trị 0):** 
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:EnableRegistrars`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableUPnPRegistrar`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableInBand802DOT11Registrar`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableFlashConfigRegistrar`
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableWPDRegistrar`

* **18.6.20.2 Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI:DisableWcnUi` (Giá trị `REG_DWORD`: `1`).

* **18.6.21.1 Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: 3.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections` (Giá trị `REG_DWORD`: `3`).

---

## 18.7 Printers (Máy in)

* **18.7.1 Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers:RegisterSpoolerRemoteRpcEndPoint` (Giá trị `REG_DWORD`: `2`).

* **18.7.2 Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Redirection Guard Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:RedirectionguardPolicy` (Giá trị `REG_DWORD`: `1`).

* **18.7.3 Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: RPC over TCP.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcUseNamedPipeProtocol` (Giá trị `REG_DWORD`: `0`).

* **18.7.4 Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Default.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcAuthentication` (Giá trị `REG_DWORD`: `0`).

* **18.7.5 Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: RPC over TCP.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcProtocols` (Giá trị `REG_DWORD`: `5`).

* **18.7.6 Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Negotiate (hoặc Kerberos).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:ForceKerberosForRpc` (Giá trị `REG_DWORD`: `0` hoặc `1`).

* **18.7.7 Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: 0.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcTcpPort` (Giá trị `REG_DWORD`: `0`).

* **18.7.8 Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Print:RpcAuthnLevelPrivacyEnabled` (Giá trị `REG_DWORD`: `1`).

* **18.7.9 Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint:RestrictDriverInstallationToAdministrators` (Giá trị `REG_DWORD`: `1`).

* **18.7.10 Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Limit Queue-specific files to Color profiles.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:CopyFilesPolicy` (Giá trị `REG_DWORD`: `1`).

* **18.7.11 Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Show warning and elevation prompt.
  * **Đường dẫn Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:NoWarningNoElevationOnInstall` (Giá trị `REG_DWORD`: `0`).

* **18.7.12 Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Show warning and elevation prompt.
  * **Đường dẫn Registry:** `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:UpdatePromptSettings` (Giá trị `REG_DWORD`: `0`).

---

## 18.8 Start Menu and Taskbar

* **18.8.1.1 Ensure 'Turn off notifications network usage' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications:NoCloudApplicationNotification` (Giá trị `REG_DWORD`: `1`).

---

## 18.9 System (Hệ thống) - Từ 18.9.3 đến 18.9.5

* **18.9.3.1 Ensure 'Include command line in process creation events' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit:ProcessCreationIncludeCmdLine_Enabled` (Giá trị `REG_DWORD`: `1`).

* **18.9.4.1 Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Force Updated Clients.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters:AllowEncryptionOracle` (Giá trị `REG_DWORD`: `0`).

* **18.9.4.2 Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation:AllowProtectedCreds` (Giá trị `REG_DWORD`: `1`).

* **18.9.5.1 Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:EnableVirtualizationBasedSecurity` (Giá trị `REG_DWORD`: `1`).

* **18.9.5.2 Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Secure Boot (hoặc Secure Boot and DMA Protection).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:RequirePlatformSecurityFeatures` (Giá trị `REG_DWORD`: `1` hoặc `3`).

* **18.9.5.3 Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled with UEFI lock.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:HypervisorEnforcedCodeIntegrity` (Giá trị `REG_DWORD`: `1`).

* **18.9.5.4 Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)' (Automated)**
  * **Trạng thái khuyến nghị:** True (checked).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:HVCIMATRequired` (Giá trị `REG_DWORD`: `1`).

* **18.9.5.5 Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled with UEFI lock (Chỉ áp dụng trên Member Server).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:LsaCfgFlags` (Giá trị `REG_DWORD`: `1`).

* **18.9.5.6 Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:ConfigureSystemGuardLaunch` (Giá trị `REG_DWORD`: `1`).
  