# Mục 2: Local Policies (Chính sách Cục bộ) - Phần 2: Security Options (Từ 2.3.1 đến 2.3.9)

Phần **2.3 Security Options** chứa rất nhiều rule cấu hình, dưới đây là đợt rule đầu tiên (từ mục 2.3.1 đến 2.3.9) kèm theo Registry Key để bạn tiếp tục xây dựng script quét tự động [1].

*Ghi chú chung: Đường dẫn Group Policy gốc cho các rule này nằm tại:*
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\`

## 2.3.1 Accounts (Tài khoản)

* **2.3.1.1 Ensure 'Accounts: Guest account status' is set to 'Disabled' (Automated)** [2]
  * **Trạng thái khuyến nghị:** Disabled [2].
  * **Đường dẫn cấu hình (Group Policy):** `Accounts: Guest account status` [3].

* **2.3.1.2 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled' (Automated)** [4]
  * **Trạng thái khuyến nghị:** Enabled [5].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse` (Kiểu `REG_DWORD`, Giá trị `1`) [6].

* **2.3.1.3 Configure 'Accounts: Rename administrator account' (Automated)** [7]
  * **Trạng thái khuyến nghị:** Đổi tên tài khoản quản trị mặc định thành một tên khác [7].
  * **Đường dẫn cấu hình (Group Policy):** `Accounts: Rename administrator account` [8].

* **2.3.1.4 Configure 'Accounts: Rename guest account' (Automated)** [9]
  * **Trạng thái khuyến nghị:** Đổi tên tài khoản khách mặc định thành một tên khác [9].
  * **Đường dẫn cấu hình (Group Policy):** `Accounts: Rename guest account` [10].

---

## 2.3.2 Audit (Kiểm toán)

* **2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled' (Automated)** [11]
  * **Trạng thái khuyến nghị:** Enabled [11].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:SCENoApplyLegacyAuditPolicy` (Kiểu `REG_DWORD`, Giá trị `1`) [12].

* **2.3.2.2 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' (Automated)** [13]
  * **Trạng thái khuyến nghị:** Disabled [14].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:CrashOnAuditFail` (Kiểu `REG_DWORD`, Giá trị `0`) [15].

---

## 2.3.4 Devices (Thiết bị)

* **2.3.4.1 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled' (Automated)** [16]
  * **Trạng thái khuyến nghị:** Enabled [17].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers:AddPrinterDrivers` (Kiểu `REG_DWORD`, Giá trị `1`) [18].

---

## 2.3.7 Interactive logon (Đăng nhập tương tác)

* **2.3.7.1 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' (Automated)** [19]
  * **Trạng thái khuyến nghị:** Disabled [20].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableCAD` (Kiểu `REG_DWORD`, Giá trị `0`) [21].

* **2.3.7.2 Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled' (Automated)** [22]
  * **Trạng thái khuyến nghị:** Enabled [22].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DontDisplayLastUserName` (Kiểu `REG_DWORD`, Giá trị `1`) [23].

* **2.3.7.3 Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' (Automated)** [24]
  * **Trạng thái khuyến nghị:** 900 giây (15 phút) trở xuống, nhưng không bằng 0 [24].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs` (Kiểu `REG_DWORD`, Giá trị `<= 900` và `!= 0`) [25].

* **2.3.7.4 Configure 'Interactive logon: Message text for users attempting to log on' (Automated)** [26]
  * **Trạng thái khuyến nghị:** Cấu hình văn bản thông báo phù hợp với tổ chức của bạn [27].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeText` (Kiểu `REG_SZ`) [28].

* **2.3.7.5 Configure 'Interactive logon: Message title for users attempting to log on' (Automated)** [29]
  * **Trạng thái khuyến nghị:** Cấu hình tiêu đề thông báo phù hợp với tổ chức của bạn [30].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeCaption` (Kiểu `REG_SZ`) [31].

* **2.3.7.6 Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' (Automated)** [32]
  * **Trạng thái khuyến nghị:** Từ 5 đến 14 ngày [33].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:PasswordExpiryWarning` (Kiểu `REG_DWORD`, Giá trị `5 - 14`) [34].

* **2.3.7.7 Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher (Automated)** [35]
  * **Trạng thái khuyến nghị:** Lock Workstation (hoặc Force Logoff / Disconnect) [35].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScRemoveOption` (Kiểu `REG_SZ`, Giá trị `1, 2, hoặc 3`) [36].

---

## 2.3.8 Microsoft network client (Máy khách mạng Microsoft)

* **2.3.8.1 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' (Automated)** [37]
  * **Trạng thái khuyến nghị:** Enabled [38].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature` (Kiểu `REG_DWORD`, Giá trị `1`) [39].

* **2.3.8.2 Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' (Automated)** [40]
  * **Trạng thái khuyến nghị:** Disabled [41].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnablePlainTextPassword` (Kiểu `REG_DWORD`, Giá trị `0`) [42].

---

## 2.3.9 Microsoft network server (Máy chủ mạng Microsoft)

* **2.3.9.1 Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)' (Automated)** [43]
  * **Trạng thái khuyến nghị:** 15 phút trở xuống [43].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:AutoDisconnect` (Kiểu `REG_DWORD`, Giá trị `<= 15`) [44].

* **2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' (Automated)** [45]
  * **Trạng thái khuyến nghị:** Enabled [46].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RequireSecuritySignature` (Kiểu `REG_DWORD`, Giá trị `1`) [47].

* **2.3.9.3 Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' (Automated)** [48]
  * **Trạng thái khuyến nghị:** Enabled [49].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:enableforcedlogoff` (Kiểu `REG_DWORD`, Giá trị `1`) [50].

* **2.3.9.4 Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (Automated)** [51]
  * **Trạng thái khuyến nghị:** Accept if provided by client (hoặc Required from client) [52].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:SMBServerNameHardeningLevel` (Kiểu `REG_DWORD`, Giá trị `1 hoặc 2`) [53].