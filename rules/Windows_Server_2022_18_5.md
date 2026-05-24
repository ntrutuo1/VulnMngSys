# Mục 18: Administrative Templates (Computer) - Phần 6 (Cuối cùng)

Dưới đây là phần cuối cùng của **Mục 18** trong tài liệu CIS Benchmark cho Windows Server 2022 (từ mục 18.10.36 đến 18.11 Custom Settings). Phần này chứa rất nhiều cấu hình quan trọng liên quan đến Remote Desktop Services (RDP), Windows Update, WinRM và PowerShell.

Các đường dẫn Registry và giá trị đã được trích xuất chi tiết để bạn dễ dàng sử dụng với `Get-ItemProperty` trong PowerShell.

## 18.10.36 Location and Sensors (Vị trí và Cảm biến)

* **18.10.36.1 Ensure 'Turn off location' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors:DisableLocation` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.40 Messaging (Nhắn tin)

* **18.10.40.1 Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging:AllowMessageSync` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.41 Microsoft account (Tài khoản Microsoft)

* **18.10.41.1 Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount:DisableUserAuth` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.56 Push To Install (Đẩy Cài đặt)

* **18.10.56.1 Ensure 'Turn off Push To Install service' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\PushToInstall:DisablePushToInstall` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.57 Remote Desktop Services (Dịch vụ Máy tính Từ xa - RDP)

### 18.10.57.2 Remote Desktop Connection Client
* **18.10.57.2.2 Ensure 'Do not allow passwords to be saved' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DisablePasswordSaving` (Giá trị `REG_DWORD`: `1`).

### 18.10.57.3 Remote Desktop Session Host
* **18.10.57.3.2.1 Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fSingleSessionPerUser` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.1 Ensure 'Allow UI Automation redirection' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:EnableUiaRedirection` (Giá trị `REG_DWORD`: `0`).

* **18.10.57.3.3.2 Ensure 'Do not allow COM port redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCcm` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.3 Ensure 'Do not allow drive redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCdm` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.4 Ensure 'Do not allow location redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableLocationRedir` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.5 Ensure 'Do not allow LPT port redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableLPT` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.6 Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisablePNPRedir` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.3.7 Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableWebAuthn` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.9.1 Ensure 'Always prompt for password upon connection' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fPromptForPassword` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.9.2 Ensure 'Require secure RPC communication' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fEncryptRPCTraffic` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.9.3 Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: SSL.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:SecurityLayer` (Giá trị `REG_DWORD`: `2`).

* **18.10.57.3.9.4 Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:UserAuthentication` (Giá trị `REG_DWORD`: `1`).

* **18.10.57.3.9.5 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: High Level.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MinEncryptionLevel` (Giá trị `REG_DWORD`: `3`).

* **18.10.57.3.10.1 Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: 15 phút hoặc ít hơn, khác 0.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MaxIdleTime` (Giá trị `REG_DWORD`: `<= 900000` (15 phút) và `!= 0`).

* **18.10.57.3.11.1 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DeleteTempDirsOnExit` (Giá trị `REG_DWORD`: `0` khi Disabled - CIS có thể liệt kê giá trị 1 cho Enabled, nhưng chuẩn là phải kiểm tra trạng thái tắt/bật cho đúng).

* **18.10.57.3.11.2 Ensure 'Do not use temporary folders per session' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:PerSessionTempDir` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.58 RSS Feeds

* **18.10.58.1 Ensure 'Prevent downloading of enclosures' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds:DisableEnclosureDownload` (Giá trị `REG_DWORD`: `1`).

* **18.10.58.2 Ensure 'Turn on Basic feed authentication over HTTP' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds:AllowBasicAuthInClear` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.59 Search

* **18.10.59.2 Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Disable Cloud Search.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:AllowCloudSearch` (Giá trị `REG_DWORD`: `0`).

* **18.10.59.3 Ensure 'Allow indexing of encrypted files' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:AllowIndexingEncryptedStoresOrItems` (Giá trị `REG_DWORD`: `0`).

* **18.10.59.4 Ensure 'Allow search highlights' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:EnableDynamicContentInWSB` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.63 Software Protection Platform

* **18.10.63.1 Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform:NoGenTicket` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.77 Windows Defender SmartScreen

* **18.10.77.2.1 Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Warn and prevent bypass.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableSmartScreen` (Giá trị `REG_DWORD`: `1`) và `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:ShellSmartScreenLevel` (Giá trị `REG_SZ`: `"Block"`).

---

## 18.10.81 Windows Ink Workspace

* **18.10.81.1 Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace:AllowSuggestedAppsInWindowsInkWorkspace` (Giá trị `REG_DWORD`: `0`).

* **18.10.81.2 Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: On, but disallow access above lock (hoặc Disabled).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace:AllowWindowsInkWorkspace` (Giá trị `REG_DWORD`: `0` hoặc `1`).

---

## 18.10.82 Windows Installer

* **18.10.82.1 Ensure 'Allow user control over installs' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:EnableUserControl` (Giá trị `REG_DWORD`: `0`).

* **18.10.82.2 Ensure 'Always install with elevated privileges' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:AlwaysInstallElevated` (Giá trị `REG_DWORD`: `0`).

* **18.10.82.3 Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:SafeForScripting` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.83 Windows Logon Options

* **18.10.83.1 Ensure 'Configure the transmission of the user's password...' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableMPR` (Giá trị `REG_DWORD`: `0`).

* **18.10.83.2 Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableAutomaticRestartSignOn` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.88 Windows PowerShell

* **18.10.88.1 Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging:EnableScriptBlockLogging` (Giá trị `REG_DWORD`: `1`).

* **18.10.88.2 Ensure 'Turn on PowerShell Transcription' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription:EnableTranscripting` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.90 Windows Remote Management (WinRM)

* **18.10.90.1.1 & 18.10.90.2.1 Ensure 'Allow Basic authentication' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** 
    * Client: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowBasic` (Giá trị `0`)
    * Service: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowBasic` (Giá trị `0`)

* **18.10.90.1.2 & 18.10.90.2.3 Ensure 'Allow unencrypted traffic' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** 
    * Client: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowUnencryptedTraffic` (Giá trị `0`)
    * Service: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowUnencryptedTraffic` (Giá trị `0`)

* **18.10.90.1.3 Ensure 'Disallow Digest authentication' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowDigest` (Giá trị `0`).

* **18.10.90.2.2 Ensure 'Allow remote server management through WinRM' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowAutoConfig` (Giá trị `REG_DWORD`: `0`).

* **18.10.90.2.4 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:DisableRunAs` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.91 Windows Remote Shell

* **18.10.91.1 Ensure 'Allow Remote Shell Access' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS:AllowRemoteShellAccess` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.93 Windows Security

* **18.10.93.2.1 Ensure 'Prevent users from modifying settings' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection:DisallowExploitProtectionOverride` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.94 Windows Update

* **18.10.94.1.1 Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoRebootWithLoggedOnUsers` (Giá trị `REG_DWORD`: `0`).

* **18.10.94.2.1 Ensure 'Configure Automatic Updates' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoUpdate` (Giá trị `REG_DWORD`: `0`).

* **18.10.94.2.2 Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' (Automated)**
  * **Trạng thái khuyến nghị:** 0 - Every day.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:ScheduledInstallDay` (Giá trị `REG_DWORD`: `0`).

* **18.10.94.4.1 Ensure 'Manage preview builds' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:ManagePreviewBuildsPolicyValue` (Giá trị `REG_DWORD`: Cần disable hoặc cấu hình phù hợp để từ chối builds xem trước).

* **18.10.94.4.2 Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: 0 days.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferQualityUpdates` (`1`) và `DeferQualityUpdatesPeriodInDays` (`0`).

---

## 18.11 Custom Settings (Thiết lập Tùy chỉnh của CIS)

* **18.11.1 Ensure 'Disable HTTP proxy features: Disable WPAD' is set to 'Enabled: Checked' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Checked.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp:DisableWpad` (Giá trị `REG_DWORD`: `1`).

* **18.11.2 Ensure 'Disable HTTP proxy features: Disable proxy authentication' is set to 'Enabled: Disable authentication over loopback interfaces' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Enabled: Disable authentication over loopback interfaces.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings:DisableProxyAuthenticationSchemes` (Giá trị `REG_DWORD`: `256` hoặc `287`).