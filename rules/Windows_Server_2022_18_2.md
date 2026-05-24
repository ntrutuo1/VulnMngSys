# Mục 18: Administrative Templates (Computer) - Phần 3

## 18.9.7 Device Installation (Cài đặt Thiết bị)

* **18.9.7.2 Ensure 'Prevent automatic download of applications associated with device metadata' is set to 'Enabled' (Automated)** [1, 2]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata:PreventDeviceMetadataFromNetwork` (Giá trị `REG_DWORD`: `1`) [3, 4].

---

## 18.9.13 Early Launch Antimalware

* **18.9.13.1 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' (Automated)** [5, 6]
  * **Trạng thái khuyến nghị:** Enabled: Good, unknown and bad but critical.
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch:DriverLoadPolicy` (Giá trị `REG_DWORD`: `3`) [7].

---

## 18.9.17 Filesystem

* **18.9.17.1 Ensure 'Enable / disable CLFS logfile authentication' is set to 'Enabled' (Automated)** [8]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Policies:ClfsAuthenticationChecking` (Giá trị `REG_DWORD`: `1`) [9, 10].

---

## 18.9.19 Group Policy

* **18.9.19.2 Ensure 'Continue experiences on this device' is set to 'Disabled' (Automated)** [11]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableCdp` (Giá trị `REG_DWORD`: `0`) [12].

---

## 18.9.20 Internet Communication Management

* **18.9.20.1.1 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' (Automated)** [13]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableWebPnPDownload` (Giá trị `REG_DWORD`: `1`) [14].

* **18.9.20.1.2 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' (Automated)** [15, 16]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC:PreventHandwritingDataSharing` (Giá trị `REG_DWORD`: `1`) [16].

* **18.9.20.1.3 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled' (Automated)** [17, 18]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports:PreventHandwritingErrorReports` (Giá trị `REG_DWORD`: `1`) [18].

* **18.9.20.1.4 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled' (Automated)** [19, 20]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard:ExitOnMSICW` (Giá trị `REG_DWORD`: `1`) [20].

* **18.9.20.1.5 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' (Automated)** [21]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoWebServices` (Giá trị `REG_DWORD`: `1`) [22].

* **18.9.20.1.6 Ensure 'Turn off printing over HTTP' is set to 'Enabled' (Automated)** [23]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableHTTPPrinting` (Giá trị `REG_DWORD`: `1`) [24, 25].

* **18.9.20.1.7 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled' (Automated)** [26, 27]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control:NoRegistration` (Giá trị `REG_DWORD`: `1`) [27, 28].

* **18.9.20.1.8 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled' (Automated)** [29]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion:DisableContentFileUpdates` (Giá trị `REG_DWORD`: `1`) [30].

* **18.9.20.1.9 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled' (Automated)** [31, 32]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoOnlinePrintsWizard` (Giá trị `REG_DWORD`: `1`) [32, 33].

* **18.9.20.1.10 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled' (Automated)** [34, 35]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoPublishingWizard` (Giá trị `REG_DWORD`: `1`) [35].

* **18.9.20.1.11 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled' (Automated)** [36, 37]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client:CEIP` (Giá trị `REG_DWORD`: `2`) [37, 38].

* **18.9.20.1.12 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled' (Automated)** [39]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows:CEIPEnable` (Giá trị `REG_DWORD`: `0`) [40].

* **18.9.20.1.13 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' (Automated)** [41]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry (cần check 2 khóa):** 
    * `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting:Disabled` (Giá trị `1`) [42].
    * `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting:DoReport` (Giá trị `0`) [42].

---

## 18.9.24 Kernel DMA Protection

* **18.9.24.1 Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All' (Automated)** [43]
  * **Trạng thái khuyến nghị:** Enabled: Block All.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection:DeviceEnumerationPolicy` (Giá trị `REG_DWORD`: `0`) [44].

---

## 18.9.27 Local Security Authority

* **18.9.27.1 Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock' (Automated)** [45, 46]
  * **Trạng thái khuyến nghị:** Enabled: Enabled with UEFI Lock.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:RunAsPPL` (Giá trị `REG_DWORD`: `1`) [47].

---

## 18.9.28 Locale Services

* **18.9.28.1 Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled' (Automated)** [48]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International:BlockUserInputMethodsForSignIn` (Giá trị `REG_DWORD`: `1`) [49].

---

## 18.9.29 Logon (Đăng nhập)

* **18.9.29.1 Ensure 'Block user from showing account details on sign-in' is set to 'Enabled' (Automated)** [50]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockUserFromShowingAccountDetailsOnSignin` (Giá trị `REG_DWORD`: `1`) [51].

* **18.9.29.2 Ensure 'Do not display network selection UI' is set to 'Enabled' (Automated)** [52]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontDisplayNetworkSelectionUI` (Giá trị `REG_DWORD`: `1`) [53].

* **18.9.29.3 Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' (Automated)** [54, 55]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DisableLockScreenAppNotifications` (Giá trị `REG_DWORD`: `1`) [55, 56].

* **18.9.29.4 Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled' (Automated)** [57, 58]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowDomainPINLogon` (Giá trị `REG_DWORD`: `0`) [59].

---

## 18.9.33 OS Policies

* **18.9.33.1 Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled' (Automated)** [60]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowCrossDeviceClipboard` (Giá trị `REG_DWORD`: `0`) [61].

* **18.9.33.2 Ensure 'Allow upload of User Activities' is set to 'Disabled' (Automated)** [62]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System:UploadUserActivities` (Giá trị `REG_DWORD`: `0`) [63].

---

## 18.9.35 Power Management \ Sleep Settings (Quản lý Nguồn & Giấc ngủ)

* **18.9.35.6.1 Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled' (Automated)** [64, 65]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:DCSettingIndex` (Giá trị `REG_DWORD`: `0`) [66].

* **18.9.35.6.2 Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled' (Automated)** [67]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:ACSettingIndex` (Giá trị `REG_DWORD`: `0`) [68].

* **18.9.35.6.3 Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled' (Automated)** [69]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:DCSettingIndex` (Giá trị `REG_DWORD`: `1`) [70].

* **18.9.35.6.4 Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled' (Automated)** [71]
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:ACSettingIndex` (Giá trị `REG_DWORD`: `1`) [72].

---

## 18.9.37 Remote Assistance (Hỗ trợ từ xa)

* **18.9.37.1 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled' (Automated)** [73, 74]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowUnsolicited` (Giá trị `REG_DWORD`: `0`) [75].

* **18.9.37.2 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled' (Automated)** [76, 77]
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowToGetHelp` (Giá trị `REG_DWORD`: `0`) [78].