# Mục 18: Administrative Templates (Computer) - Phần 1

## 18.1 Control Panel (Bảng Điều khiển)

* **18.1.1.1 Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' (Automated)** [4]
  * **Trạng thái khuyến nghị:** Enabled [4].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenCamera` (Giá trị `REG_DWORD`: `1`) [5].

* **18.1.1.2 Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled' (Automated)** [6]
  * **Trạng thái khuyến nghị:** Enabled [6].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenSlideshow` (Giá trị `REG_DWORD`: `1`) [7].

* **18.1.2.2 Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled' (Automated)** [8]
  * **Trạng thái khuyến nghị:** Disabled [9].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization:AllowInputPersonalization` (Giá trị `REG_DWORD`: `0`) [10].

* **18.1.3 Ensure 'Allow Online Tips' is set to 'Disabled' (Automated)** [11]
  * **Trạng thái khuyến nghị:** Disabled [11].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:AllowOnlineTips` (Giá trị `REG_DWORD`: `0`) [12].

---

## 18.4 MS Security Guide (Hướng dẫn Bảo mật của MS)

* **18.4.1 Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' (Automated)** [13]
  * **Trạng thái khuyến nghị:** Enabled: Disable driver [14].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start` (Giá trị `REG_DWORD`: `4`) [15].

* **18.4.2 Ensure 'Configure SMB v1 server' is set to 'Disabled' (Automated)** [16]
  * **Trạng thái khuyến nghị:** Disabled [16].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1` (Giá trị `REG_DWORD`: `0`) [17].

* **18.4.3 Ensure 'Enable Certificate Padding' is set to 'Enabled' (Automated)** [18]
  * **Trạng thái khuyến nghị:** Enabled [19].
  * **Đường dẫn Registry (cần quét cả 2 đường dẫn):** 
    * `HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config:EnableCertPaddingCheck` (Giá trị `REG_DWORD` hoặc `REG_SZ`: `1`) [20].
    * `HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config:EnableCertPaddingCheck` (Giá trị `REG_DWORD` hoặc `REG_SZ`: `1`) [20].

* **18.4.4 Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' (Automated)** [21]
  * **Trạng thái khuyến nghị:** Enabled [22].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel:DisableExceptionChainValidation` (Giá trị `REG_DWORD`: `0`) [23].

* **18.4.5 Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' (Automated)** [24]
  * **Trạng thái khuyến nghị:** Enabled: P-node (recommended) [25].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NodeType` (Giá trị `REG_DWORD`: `2`) [26].

---

## 18.5 MSS (Legacy)

* **18.5.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' (Automated)** [27]
  * **Trạng thái khuyến nghị:** Disabled [28].
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon` (Giá trị `REG_SZ`: `0`) [29].

* **18.5.2 Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection...' (Automated)** [30]
  * **Trạng thái khuyến nghị:** Enabled: Highest protection, source routing is completely disabled [30].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting` (Giá trị `REG_DWORD`: `2`) [31].

* **18.5.3 Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection...' (Automated)** [32]
  * **Trạng thái khuyến nghị:** Enabled: Highest protection, source routing is completely disabled [33].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting` (Giá trị `REG_DWORD`: `2`) [34].

* **18.5.4 Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' (Automated)** [35]
  * **Trạng thái khuyến nghị:** Disabled [36].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:EnableICMPRedirect` (Giá trị `REG_DWORD`: `0`) [37].

* **18.5.5 Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes' (Automated)** [38]
  * **Trạng thái khuyến nghị:** Enabled: 300,000 or 5 minutes [39].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:KeepAliveTime` (Giá trị `REG_DWORD`: `300000`) [40].

* **18.5.6 Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' (Automated)** [41]
  * **Trạng thái khuyến nghị:** Enabled [42].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NoNameReleaseOnDemand` (Giá trị `REG_DWORD`: `1`) [43].

* **18.5.7 Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled' (Automated)** [44]
  * **Trạng thái khuyến nghị:** Disabled [45].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:PerformRouterDiscovery` (Giá trị `REG_DWORD`: `0`) [46].

* **18.5.8 Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled' (Automated)** [47]
  * **Trạng thái khuyến nghị:** Enabled [48].
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode` (Giá trị `REG_DWORD`: `1`) [49].

* **18.5.9 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' (Automated)** [50]
  * **Trạng thái khuyến nghị:** Enabled: 3 [51].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters:TcpMaxDataRetransmissions` (Giá trị `REG_DWORD`: `3`) [52].

* **18.5.10 Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' (Automated)** [53]
  * **Trạng thái khuyến nghị:** Enabled: 3 [54].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:TcpMaxDataRetransmissions` (Giá trị `REG_DWORD`: `3`) [54].

* **18.5.11 Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less' (Automated)** [55]
  * **Trạng thái khuyến nghị:** Enabled: 90% or less [56].
  * **Đường dẫn Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security:WarningLevel` (Giá trị `REG_DWORD`: `<= 90`) [57].
Phần tiếp theo của Mục 18 là 18.6 Network (có tới 21 mục con cấu hình 