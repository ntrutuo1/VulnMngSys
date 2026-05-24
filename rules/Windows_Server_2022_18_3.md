# Mục 18: Administrative Templates (Computer) - Phần 4

## 18.9.38 Remote Procedure Call (RPC)

* **18.9.38.1 Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (Automated)** [1, 2]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:EnableAuthEpResolution` (Giá trị `REG_DWORD`: `1`).

* **18.9.38.2 Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (Automated)** [3, 4]
  * **Trạng thái khuyến nghị:** Enabled: Authenticated.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:RestrictRemoteClients` (Giá trị `REG_DWORD`: `1`).

---

## 18.9.49 Troubleshooting and Diagnostics (Khắc phục sự cố)

* **18.9.49.5.1 Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled' (Automated)** [5, 6]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy:DisableQueryRemoteServer` (Giá trị `REG_DWORD`: `0`).

* **18.9.49.11.1 Ensure 'Enable/Disable PerfTrack' is set to 'Disabled' (Automated)** [7, 8]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}:ScenarioExecutionEnabled` (Giá trị `REG_DWORD`: `0`).

---

## 18.9.51 User Profiles (Hồ sơ người dùng)

* **18.9.51.1 Ensure 'Turn off the advertising ID' is set to 'Enabled' (Automated)** [9, 10]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo:DisabledByGroupPolicy` (Giá trị `REG_DWORD`: `1`).

---

## 18.9.53 Windows Time Service (Dịch vụ thời gian)

* **18.9.53.1.1 Ensure 'Enable Windows NTP Client' is set to 'Enabled' (Automated)** [11, 12]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient:Enabled` (Giá trị `REG_DWORD`: `1`).

---

## 18.10 Windows Components (Thành phần Windows)

### 18.10.4 App Package Deployment

* **18.10.4.1 Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled' (Automated)** [13, 14]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager:AllowSharedLocalAppData` (Giá trị `REG_DWORD`: `0`).

### 18.10.6 App runtime

* **18.10.6.1 Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled' (Automated)** [15, 16]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:MSAOptional` (Giá trị `REG_DWORD`: `1`).

### 18.10.8 AutoPlay Policies (Chính sách Tự động chạy)

* **18.10.8.1 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled' (Automated)** [17, 18]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoAutoplayfornonVolume` (Giá trị `REG_DWORD`: `1`).

* **18.10.8.2 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands' (Automated)** [19, 20]
  * **Trạng thái khuyến nghị:** Enabled: Do not execute any autorun commands.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoAutorun` (Giá trị `REG_DWORD`: `1`).

* **18.10.8.3 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives' (Automated)** [21, 22]
  * **Trạng thái khuyến nghị:** Enabled: All drives.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoDriveTypeAutoRun` (Giá trị `REG_DWORD`: `255`).

### 18.10.9 Biometrics (Sinh trắc học)

* **18.10.9.1.1 Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled' (Automated)** [23, 24]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures:EnhancedAntiSpoofing` (Giá trị `REG_DWORD`: `1`).

### 18.10.11 Camera

* **18.10.11.1 Ensure 'Allow Use of Camera' is set to 'Disabled' (Automated)** [25, 26]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Camera:AllowCamera` (Giá trị `REG_DWORD`: `0`).

### 18.10.13 Cloud Content (Nội dung Đám mây)

* **18.10.13.1 Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' (Automated)** [27, 28]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableConsumerAccountStateContent` (Giá trị `REG_DWORD`: `1`).

* **18.10.13.2 Ensure 'Turn off cloud optimized content' is set to 'Enabled' (Automated)** [29, 30]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableCloudOptimizedContent` (Giá trị `REG_DWORD`: `1`).

### 18.10.14 Connect

* **18.10.14.1 Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always' (Automated)** [31, 32]
  * **Trạng thái khuyến nghị:** Enabled: First Time (hoặc Always).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect:RequirePinForPairing` (Giá trị `REG_DWORD`: `1` hoặc `2`).

### 18.10.15 Credential User Interface

* **18.10.15.1 Ensure 'Do not display the password reveal button' is set to 'Enabled' (Automated)** [33, 34]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI:DisablePasswordReveal` (Giá trị `REG_DWORD`: `1`).

* **18.10.15.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled' (Automated)** [35, 36]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI:EnumerateAdministrators` (Giá trị `REG_DWORD`: `0`).