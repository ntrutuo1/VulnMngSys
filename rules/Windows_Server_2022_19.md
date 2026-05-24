# Mục 19: Administrative Templates (User)

*Lưu ý cho script PowerShell: Tất cả các cấu hình dưới đây nằm trong nhánh `HKEY_USERS\[USER SID]\...`. Bạn sẽ cần bỏ qua các SID hệ thống như `.DEFAULT`, `S-1-5-18`, `S-1-5-19`, `S-1-5-20` và các `NT SERVICE` SIDs (`S-1-5-80-*`), chỉ tập trung quét trên các SID người dùng thực tế (thường bắt đầu bằng `S-1-5-21-*`)* [2-4].

## 19.5 Start Menu and Taskbar (Menu Bắt đầu và Thanh tác vụ)

* **19.5.1.1 Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled' (Automated)** [5]
  * **Trạng thái khuyến nghị:** Enabled. [5]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications:NoToastApplicationNotificationOnLockScreen` (Giá trị `REG_DWORD`: `1`). [6]

---

## 19.6 System (Hệ thống)

* **19.6.6.1.1 Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled' (Automated)** [7]
  * **Trạng thái khuyến nghị:** Enabled. [7]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Assistance\Client\1.0:NoImplicitFeedback` (Giá trị `REG_DWORD`: `1`). [8]

---

## 19.7 Windows Components (Thành phần Windows)

### 19.7.5 Attachment Manager (Trình quản lý Tệp đính kèm)

* **19.7.5.1 Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled' (Automated)** [9]
  * **Trạng thái khuyến nghị:** Disabled. [9]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:SaveZoneInformation` (Giá trị `REG_DWORD`: `2`). [10]

* **19.7.5.2 Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled' (Automated)** [11]
  * **Trạng thái khuyến nghị:** Enabled. [11]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:ScanWithAntiVirus` (Giá trị `REG_DWORD`: `3`). [12]

### 19.7.8 Cloud Content (Nội dung Đám mây)

* **19.7.8.1 Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled' (Automated)** [13]
  * **Trạng thái khuyến nghị:** Disabled. [13]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:ConfigureWindowsSpotlight` (Giá trị `REG_DWORD`: `2`). [14]

* **19.7.8.2 Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled' (Automated)** [15]
  * **Trạng thái khuyến nghị:** Enabled. [15]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableThirdPartySuggestions` (Giá trị `REG_DWORD`: `1`). [16]

* **19.7.8.3 Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled' (Automated)** [17]
  * **Trạng thái khuyến nghị:** Enabled. [18]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableTailoredExperiencesWithDiagnosticData` (Giá trị `REG_DWORD`: `1`). [19]

* **19.7.8.4 Ensure 'Turn off all Windows spotlight features' is set to 'Enabled' (Automated)** [20]
  * **Trạng thái khuyến nghị:** Enabled. [20]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableWindowsSpotlightFeatures` (Giá trị `REG_DWORD`: `1`). [21, 22]

* **19.7.8.5 Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled' (Automated)** [23]
  * **Trạng thái khuyến nghị:** Enabled. [23]
  * **Đường dẫn Registry:** `HKU\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableSpotlightCollectionOnDesktop`. (Nếu thuộc tính này được tạo qua GPO, cần check sự tồn tại hoặc giá trị tương ứng để vô hiệu hóa tính năng). [24]

### 19.7.26 Network Sharing (Chia sẻ Mạng)

* **19.7.26.1 Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled' (Automated)** [25]
  * **Trạng thái khuyến nghị:** Enabled. [26]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoInplaceSharing` (Giá trị `REG_DWORD`: `1`). [27]

### 19.7.46 Windows Media Player

* **19.7.46.2.1 Ensure 'Prevent Codec Download' is set to 'Enabled' (Automated)** [28]
  * **Trạng thái khuyến nghị:** Enabled. [28]
  * **Đường dẫn Registry:** `HKU\[USER SID]\Software\Policies\Microsoft\WindowsMediaPlayer:PreventCodecDownload` (Giá trị `REG_DWORD`: `1`). [29]