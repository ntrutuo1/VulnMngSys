# Mục 2: Local Policies - Phần 2: Security Options (Từ 2.3.10 đến 2.3.17)

*Ghi chú chung: Đường dẫn Group Policy gốc cho các rule này nằm tại:*
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\`

## 2.3.10 Network access (Truy cập mạng)

* **2.3.10.1 Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.

* **2.3.10.2 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM` (Kiểu `REG_DWORD`, Giá trị `1`).

* **2.3.10.3 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous` (Kiểu `REG_DWORD`, Giá trị `1`).

* **2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:DisableDomainCreds` (Kiểu `REG_DWORD`, Giá trị `1`).

* **2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:EveryoneIncludesAnonymous` (Kiểu `REG_DWORD`, Giá trị `0`).

* **2.3.10.6 Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured (Automated)**
  * **Trạng thái khuyến nghị:** Trống (None) hoặc `BROWSER` (nếu dịch vụ Computer Browser bật).
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionPipes` (Kiểu `REG_MULTI_SZ`).

* **2.3.10.7 Ensure 'Network access: Remotely accessible registry paths' is configured (Automated)**
  * **Trạng thái khuyến nghị:** Phải chứa các đường dẫn cụ thể (System\CurrentControlSet\Control\ProductOptions, v.v.)
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths:Machine` (Kiểu `REG_MULTI_SZ`).

* **2.3.10.8 Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured (Automated)**
  * **Trạng thái khuyến nghị:** Phải chứa các đường dẫn và sub-paths cụ thể theo chuẩn CIS.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths:Machine` (Kiểu `REG_MULTI_SZ`).

* **2.3.10.9 Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RestrictNullSessAccess` (Kiểu `REG_DWORD`, Giá trị `1`).

* **2.3.10.10 Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (Automated)**
  * **Trạng thái khuyến nghị:** Administrators: Remote Access: Allow.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:restrictremotesam` (Kiểu `REG_SZ`, Giá trị `O:BAG:BAD:(A;;RC;;;BA)`).

* **2.3.10.11 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' (Automated)**
  * **Trạng thái khuyến nghị:** None (Trống).
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionShares` (Kiểu `REG_MULTI_SZ`, không chứa giá trị).

* **2.3.10.12 Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic...' (Automated)**
  * **Trạng thái khuyến nghị:** Classic - local users authenticate as themselves.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:ForceGuest` (Kiểu `REG_DWORD`, Giá trị `0`).

---

## 2.3.11 Network security (Bảo mật Mạng)

* **2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseMachineId` (Giá trị `1`).

* **2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AllowNullSessionFallback` (Giá trị `0`).

* **2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u:AllowOnlineID` (Giá trị `0`).

* **2.3.11.4 Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' (Automated)**
  * **Trạng thái khuyến nghị:** AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters:SupportedEncryptionTypes` (Giá trị `2147483640`).

* **2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash` (Giá trị `1`).

* **2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (Manual)**
  * **Trạng thái khuyến nghị:** Enabled.

* **2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM' (Automated)**
  * **Trạng thái khuyến nghị:** Send NTLMv2 response only. Refuse LM & NTLM.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel` (Giá trị `5`).

* **2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Negotiate signing (hoặc Require signing).
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LDAP:LDAPClientIntegrity` (Giá trị `1` hoặc `2`).

* **2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (Automated)**
  * **Trạng thái khuyến nghị:** Require NTLMv2 session security, Require 128-bit encryption.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinClientSec` (Giá trị `537395200`).

* **2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (Automated)**
  * **Trạng thái khuyến nghị:** Require NTLMv2 session security, Require 128-bit encryption.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec` (Giá trị `537395200`).

* **2.3.11.11 Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts' (Automated)**
  * **Trạng thái khuyến nghị:** Enable auditing for all accounts.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AuditReceivingNTLMTraffic` (Giá trị `2`).

* **2.3.11.12 Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Audit all (hoặc Deny All).
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:RestrictSendingNTLMTraffic` (Giá trị `1` hoặc `2`).

---

## 2.3.13 Shutdown (Tắt máy)

* **2.3.13.1 Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled' (Automated)**
  * **Trạng thái khuyến nghị:** Disabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ShutdownWithoutLogon` (Giá trị `0`).

---

## 2.3.15 System objects (Đối tượng Hệ thống)

* **2.3.15.1 Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel:ObCaseInsensitive` (Giá trị `1`).

* **2.3.15.2 Ensure 'System objects: Strengthen default permissions of internal system objects' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:ProtectionMode` (Giá trị `1`).

---

## 2.3.17 User Account Control (UAC - Kiểm soát tài khoản người dùng)

* **2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:FilterAdministratorToken` (Giá trị `1`).

* **2.3.17.2 Ensure 'User Account Control: Behavior of the elevation prompt for administrators...' is set to 'Prompt for consent on the secure desktop' or higher (Automated)**
  * **Trạng thái khuyến nghị:** Prompt for consent on the secure desktop (hoặc Prompt for credentials...).
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin` (Giá trị `1` hoặc `2`).

* **2.3.17.3 Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' (Automated)**
  * **Trạng thái khuyến nghị:** Automatically deny elevation requests.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorUser` (Giá trị `0`).

* **2.3.17.4 Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableInstallerDetection` (Giá trị `1`).

* **2.3.17.5 Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableSecureUIAPaths` (Giá trị `1`).

* **2.3.17.6 Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA` (Giá trị `1`).

* **2.3.17.7 Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:PromptOnSecureDesktop` (Giá trị `1`).

* **2.3.17.8 Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' (Automated)**
  * **Trạng thái khuyến nghị:** Enabled.
  * **Đường dẫn Registry:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableVirtualization` (Giá trị `1`).