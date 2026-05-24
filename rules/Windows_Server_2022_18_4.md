# Mục 18: Administrative Templates (Computer) - Phần 5

## 18.10.16 Data Collection and Preview Builds (Thu thập dữ liệu)

* **18.10.16.1 Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off' or 'Send required diagnostic data' (Automated)** [1, 2]
  * **Trạng thái khuyến nghị:** Enabled: Diagnostic data off (not recommended) HOẶC Enabled: Send required diagnostic data.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:AllowTelemetry` (Giá trị `REG_DWORD`: `0` hoặc `1`).

* **18.10.16.2 Ensure 'Configure Authenticated Proxy usage for the Connected User Experience...' is set to 'Enabled: Disable...' (Automated)** [3, 4]
  * **Trạng thái khuyến nghị:** Enabled: Disable Authenticated Proxy usage.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DisableEnterpriseAuthProxy` (Giá trị `REG_DWORD`: `1`).

* **18.10.16.3 Ensure 'Do not show feedback notifications' is set to 'Enabled' (Automated)** [5]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DoNotShowFeedbackNotifications` (Giá trị `REG_DWORD`: `1`).

* **18.10.16.4 Ensure 'Enable OneSettings Auditing' is set to 'Enabled' (Automated)** [6, 7]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:EnableOneSettingsAuditing` (Giá trị `REG_DWORD`: `1`).

* **18.10.16.5 Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled' (Automated)** [8, 9]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDiagnosticLogCollection` (Giá trị `REG_DWORD`: `1`).

* **18.10.16.6 Ensure 'Limit Dump Collection' is set to 'Enabled' (Automated)** [10, 11]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDumpCollection` (Giá trị `REG_DWORD`: `1`).

---

## 18.10.18 Desktop App Installer (Trình cài đặt Ứng dụng)

* **18.10.18.1 Ensure 'Enable App Installer' is set to 'Disabled' (Automated)** [12, 13]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableAppInstaller` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.2 Ensure 'Enable App Installer Experimental Features' is set to 'Disabled' (Automated)** [14, 15]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableExperimentalFeatures` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.3 Ensure 'Enable App Installer Hash Override' is set to 'Disabled' (Automated)** [16, 17]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableHashOverride` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.4 Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled' (Automated)** [18, 19]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableLocalArchiveMalwareScanOverride` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.5 Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled' (Automated)** [20, 21]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableMSAppInstallerProtocol` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.6 Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled' (Automated)** [22, 23]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableBypassCertificatePinningForMicrosoftStore` (Giá trị `REG_DWORD`: `0`).

* **18.10.18.7 Ensure 'Enable Windows Package Manager command line interfaces' is set to 'Disabled' (Automated)** [24, 25]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableWindowsPackageManagerCommandLineInterfaces` (Giá trị `REG_DWORD`: `0`).

---

## 18.10.26 Event Log Service (Dịch vụ Nhật ký Sự kiện)

*(Lưu ý: Các khóa `Retention` của Event Log có kiểu `REG_SZ` (chuỗi), cần chú ý kiểm tra đúng định dạng string trong script PowerShell)*

* **18.10.26.1.1 Application: Control Event Log behavior... reaches its maximum size** [26]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:Retention` (Giá trị `REG_SZ`: `"0"`).

* **18.10.26.1.2 Application: Specify the maximum log file size (KB)** [27-29]
  * **Trạng thái khuyến nghị:** Enabled: 32,768 or greater.
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:MaxSize` (Giá trị `REG_DWORD`: `>= 32768`).

* **18.10.26.2.1 Security: Control Event Log behavior... reaches its maximum size** [30, 31]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:Retention` (Giá trị `REG_SZ`: `"0"`).

* **18.10.26.2.2 Security: Specify the maximum log file size (KB)** [32, 33]
  * **Trạng thái khuyến nghị:** Enabled: 196,608 or greater.
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:MaxSize` (Giá trị `REG_DWORD`: `>= 196608`).

* **18.10.26.3.1 Setup: Control Event Log behavior... reaches its maximum size** [34, 35]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:Retention` (Giá trị `REG_SZ`: `"0"`).

* **18.10.26.3.2 Setup: Specify the maximum log file size (KB)** [36, 37]
  * **Trạng thái khuyến nghị:** Enabled: 32,768 or greater.
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:MaxSize` (Giá trị `REG_DWORD`: `>= 32768`).

* **18.10.26.4.1 System: Control Event Log behavior... reaches its maximum size** [38, 39]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:Retention` (Giá trị `REG_SZ`: `"0"`).

* **18.10.26.4.2 System: Specify the maximum log file size (KB)** [40, 41]
  * **Trạng thái khuyến nghị:** Enabled: 32,768 or greater.
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:MaxSize` (Giá trị `REG_DWORD`: `>= 32768`).

---

## 18.10.29 File Explorer (Cấu hình Explorer)

* **18.10.29.2 Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled' (Automated)** [42, 43]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:DisableMotWOnInsecurePathCopy` (Giá trị `REG_DWORD`: `0`).

* **18.10.29.3 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled' (Automated)** [44, 45]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoDataExecutionPrevention` (Giá trị `REG_DWORD`: `0`).

* **18.10.29.4 Ensure 'Turn off heap termination on corruption' is set to 'Disabled' (Automated)** [46, 47]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoHeapTerminationOnCorruption` (Giá trị `REG_DWORD`: `0`).

* **18.10.29.5 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' (Automated)** [48, 49]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:PreXPSP2ShellProtocolBehavior` (Giá trị `REG_DWORD`: `0`).
Phần tiếp theo và cũng là phần cuối cùng của Mục 18 sẽ bao gồm các 