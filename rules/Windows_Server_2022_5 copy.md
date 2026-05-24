# Mục 5: System Services (Dịch vụ Hệ thống)

Mục này quy định về các dịch vụ hệ thống cốt lõi cần vô hiệu hóa để giảm thiểu bề mặt tấn công [4].

* **5.1 Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (Automated)** [1, 4]
  * **Mô tả:** Vô hiệu hóa dịch vụ Print Spooler để chống lại lỗ hổng PrintNightmare và các cuộc tấn công nhắm vào dịch vụ in ấn [7].
  * **Trạng thái khuyến nghị:** Disabled [7].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Spooler` | Key `Start` (Kiểu `REG_DWORD`, Giá trị `4`) [8].
  * **Lệnh PowerShell tương đương:** `Set-Service -Name Spooler -StartupType Disabled` [8].

---

# Mục 9: Windows Defender Firewall with Advanced Security 

Mục này tập trung vào cấu hình Tường lửa của Windows (Windows Firewall) cho các profile mạng khác nhau [2, 6]. 
*(Lưu ý: Domain Profile được cấu hình qua Group Policy của Domain nên CIS Stand-alone để trống)* [6, 9].

## 9.2 Private Profile (Cấu hình cho mạng Nội bộ/Cá nhân) [6, 9]

* **9.2.1 Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)' (Automated)** [9, 10]
  * **Trạng thái khuyến nghị:** On (recommended) [10].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:EnableFirewall` (Giá trị `1`) [11].

* **9.2.2 Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)' (Automated)** [9, 12]
  * **Trạng thái khuyến nghị:** Block (default) [12].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DefaultInboundAction` (Giá trị `1`) [13].

* **9.2.3 Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No' (Automated)** [9, 14]
  * **Mô tả:** Không hiển thị thông báo cho người dùng khi một ứng dụng bị tường lửa chặn [15, 16].
  * **Trạng thái khuyến nghị:** No [15].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DisableNotifications` (Giá trị `1`) [16].

* **9.2.4 Ensure 'Windows Firewall: Private: Logging: Name' is configured (Automated)** [9, 17]
  * **Trạng thái khuyến nghị:** Đã cấu hình (Ví dụ: `%SystemRoot%\System32\logfiles\firewall\privatefw.log`) [18].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFilePath` (Kiểu `REG_SZ`, Giá trị `<path>\<filename>.log`) [19].

* **9.2.5 Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater' (Automated)** [9, 20]
  * **Trạng thái khuyến nghị:** 16,384 KB trở lên [20].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFileSize` (Giá trị `16384` hoặc lớn hơn) [21].

* **9.2.6 Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes' (Automated)** [9, 22]
  * **Trạng thái khuyến nghị:** Yes [22].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogDroppedPackets` (Giá trị `1`) [23].

* **9.2.7 Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes' (Automated)** [9, 24]
  * **Trạng thái khuyến nghị:** Yes [25].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogSuccessfulConnections` (Giá trị `1`) [26].

---

## 9.3 Public Profile (Cấu hình cho mạng Công cộng) [27-29]

* **9.3.1 Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)' (Automated)** [27, 29]
  * **Trạng thái khuyến nghị:** On (recommended) [30].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:EnableFirewall` (Giá trị `1`) [30].

* **9.3.2 Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)' (Automated)** [27, 31]
  * **Trạng thái khuyến nghị:** Block (default) [31].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DefaultInboundAction` (Giá trị `1`) [32].

* **9.3.3 Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No' (Automated)** [27, 33]
  * **Trạng thái khuyến nghị:** No [33].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DisableNotifications` (Giá trị `1`) [34].

* **9.3.4 Ensure 'Windows Firewall: Public: Logging: Name' is configured (Automated)** [27, 35]
  * **Trạng thái khuyến nghị:** Đã cấu hình (Ví dụ: `%SystemRoot%\System32\logfiles\firewall\publicfw.log`) [36].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFilePath` (Kiểu `REG_SZ`) [37].

* **9.3.5 Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater' (Automated)** [27, 38]
  * **Trạng thái khuyến nghị:** 16,384 KB trở lên [38].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFileSize` (Giá trị `16384` hoặc lớn hơn) [39].

* **9.3.6 Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes' (Automated)** [27, 40]
  * **Trạng thái khuyến nghị:** Yes [40].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogDroppedPackets` (Giá trị `1`) [41].

* **9.3.7 Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes' (Automated)** [27, 42]
  * **Trạng thái khuyến nghị:** Yes [43].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogSuccessfulConnections` (Giá trị `1`) [44].