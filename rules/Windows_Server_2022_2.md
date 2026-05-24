# Mục 2: Local Policies (Chính sách Cục bộ) - Phần 1: User Rights Assignment

Phần này quy định cụ thể quyền hạn của từng nhóm hoặc tài khoản trên hệ thống. Để quét tự động bằng PowerShell, bạn sẽ cần dùng lệnh `secedit /export /cfg` để trích xuất cấu hình bảo mật cục bộ, thay vì đọc Registry.

*Ghi chú: Tất cả các rule dưới đây đều có chung đường dẫn Group Policy:*
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\`

* **2.2.1 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [2].

* **2.2.2 Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, Authenticated Users [3].

* **2.2.3 Ensure 'Act as part of the operating system' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [4].

* **2.2.4 Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, LOCAL SERVICE, NETWORK SERVICE [5].

* **2.2.5 Ensure 'Allow log on locally' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [6].

* **2.2.6 Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, Remote Desktop Users [7].

* **2.2.7 Ensure 'Back up files and directories' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [8].

* **2.2.8 Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, LOCAL SERVICE [9].

* **2.2.9 Ensure 'Create a pagefile' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [10].

* **2.2.10 Ensure 'Create a token object' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [11].

* **2.2.11 Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE [12].

* **2.2.12 Ensure 'Create permanent shared objects' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [13].

* **2.2.13 Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, NT VIRTUAL MACHINE\Virtual Machines [14].

* **2.2.14 Ensure 'Debug programs' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [15].

* **2.2.15 Ensure 'Deny access to this computer from the network' to include 'Guests' (Automated)**
  * **Trạng thái khuyến nghị:** Bao gồm Guests [16].

* **2.2.16 Ensure 'Deny log on as a batch job' to include 'Guests' (Automated)**
  * **Trạng thái khuyến nghị:** Bao gồm Guests [17].

* **2.2.17 Ensure 'Deny log on as a service' to include 'Guests' (Automated)**
  * **Trạng thái khuyến nghị:** Bao gồm Guests [18].

* **2.2.18 Ensure 'Deny log on locally' to include 'Guests' (Automated)**
  * **Trạng thái khuyến nghị:** Bao gồm Guests [19].

* **2.2.19 Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (Automated)**
  * **Trạng thái khuyến nghị:** Guests [20].

* **2.2.20 Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [21].

* **2.2.21 Ensure 'Force shutdown from a remote system' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [22].

* **2.2.22 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** LOCAL SERVICE, NETWORK SERVICE [23].

* **2.2.23 Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE [24].

* **2.2.24 Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, Window Manager\Window Manager Group [25].

* **2.2.25 Ensure 'Load and unload device drivers' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [26].

* **2.2.26 Ensure 'Lock pages in memory' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [27].

* **2.2.27 Ensure 'Manage auditing and security log' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [28].

* **2.2.28 Ensure 'Modify an object label' is set to 'No One' (Automated)**
  * **Trạng thái khuyến nghị:** No One [29].

* **2.2.29 Ensure 'Modify firmware environment values' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [30].

* **2.2.30 Ensure 'Perform volume maintenance tasks' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [31].

* **2.2.31 Ensure 'Profile single process' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [32].

* **2.2.32 Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators, NT SERVICE\WdiServiceHost [33].

* **2.2.33 Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Automated)**
  * **Trạng thái khuyến nghị:** LOCAL SERVICE, NETWORK SERVICE [34].

* **2.2.34 Ensure 'Restore files and directories' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [35].

* **2.2.35 Ensure 'Shut down the system' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [36].

* **2.2.36 Ensure 'Take ownership of files or other objects' is set to 'Administrators' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators [37].