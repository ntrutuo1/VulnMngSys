# Mục 17: Advanced Audit Policy Configuration

Mục này xác định các sự kiện hệ thống nào sẽ được ghi lại (Log) vào Security Event Log. Để quét tự động bằng PowerShell, bạn nên sử dụng công cụ `auditpol.exe` tích hợp sẵn của Windows thông qua mã GUID của Subcategory để đọc cấu hình hiện tại.

*Ghi chú chung: Đường dẫn Group Policy gốc cho các rule này nằm tại:*
`Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\`

## 17.1 Account Logon (Đăng nhập Tài khoản)

* **17.1.1 Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated)** [1, 2]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}"` [3]

## 17.2 Account Management (Quản lý Tài khoản)

* **17.2.1 Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Automated)** [4, 5]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9239-69ae-11d9-bed3-505054503030}"` [6]

* **17.2.2 Ensure 'Audit Security Group Management' is set to include 'Success' (Automated)** [7, 8]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9237-69ae-11d9-bed3-505054503030}"` [9]

* **17.2.3 Ensure 'Audit User Account Management' is set to 'Success and Failure' (Automated)** [10, 11]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9235-69ae-11d9-bed3-505054503030}"` [12]

## 17.3 Detailed Tracking (Theo dõi Chi tiết)

* **17.3.1 Ensure 'Audit PNP Activity' is set to include 'Success' (Automated)** [13, 14]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9248-69ae-11d9-bed3-505054503030}"` [15]

* **17.3.2 Ensure 'Audit Process Creation' is set to include 'Success' (Automated)** [16, 17]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce922b-69ae-11d9-bed3-505054503030}"` [18]

*(Lưu ý: Mục 17.4 DS Access được CIS để trống cho Member Server [19])*

## 17.5 Logon/Logoff (Đăng nhập/Đăng xuất)

* **17.5.1 Ensure 'Audit Account Lockout' is set to include 'Failure' (Automated)** [20]
  * **Trạng thái khuyến nghị:** Bao gồm Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9217-69ae-11d9-bed3-505054503030}"` [21]

* **17.5.2 Ensure 'Audit Group Membership' is set to include 'Success' (Automated)** [22]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9249-69ae-11d9-bed3-505054503030}"` [23, 24]

* **17.5.3 Ensure 'Audit Logoff' is set to include 'Success' (Automated)** [25, 26]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9216-69ae-11d9-bed3-505054503030}"` [27]

* **17.5.4 Ensure 'Audit Logon' is set to 'Success and Failure' (Automated)** [28, 29]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9215-69ae-11d9-bed3-505054503030}"` [30]

* **17.5.5 Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Automated)** [31, 32]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce921c-69ae-11d9-bed3-505054503030}"` [33]

* **17.5.6 Ensure 'Audit Special Logon' is set to include 'Success' (Automated)** [34, 35]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce921b-69ae-11d9-bed3-505054503030}"` [36]

## 17.6 Object Access (Truy cập Đối tượng)

* **17.6.1 Ensure 'Audit Detailed File Share' is set to include 'Failure' (Automated)** [37, 38]
  * **Trạng thái khuyến nghị:** Bao gồm Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9244-69ae-11d9-bed3-505054503030}"` [39]

* **17.6.2 Ensure 'Audit File Share' is set to 'Success and Failure' (Automated)** [40, 41]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9224-69ae-11d9-bed3-505054503030}"` [42]

* **17.6.3 Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' (Automated)** [43, 44]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9227-69ae-11d9-bed3-505054503030}"` [45]

* **17.6.4 Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Automated)** [46, 47]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9245-69ae-11d9-bed3-505054503030}"` [48]

## 17.7 Policy Change (Thay đổi Chính sách)

* **17.7.1 Ensure 'Audit Audit Policy Change' is set to include 'Success' (Automated)** [49, 50]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce922f-69ae-11d9-bed3-505054503030}"` [51]

* **17.7.2 Ensure 'Audit Authentication Policy Change' is set to include 'Success' (Automated)** [52, 53]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9230-69ae-11d9-bed3-505054503030}"` [54]

* **17.7.3 Ensure 'Audit Authorization Policy Change' is set to include 'Success' (Automated)** [55]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9231-69ae-11d9-bed3-505054503030}"` [56]

* **17.7.4 Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Automated)** [57, 58]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9232-69ae-11d9-bed3-505054503030}"` [59]

* **17.7.5 Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated)** [60, 61]
  * **Trạng thái khuyến nghị:** Bao gồm Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9234-69ae-11d9-bed3-505054503030}"` [62]

## 17.8 Privilege Use (Sử dụng Đặc quyền)

* **17.8.1 Ensure 'Audit Sensitive Privilege Use' is set to 'Success' (Automated)** [63, 64]
  * **Trạng thái khuyến nghị:** Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9228-69ae-11d9-bed3-505054503030}"` [65]

## 17.9 System (Hệ thống)

* **17.9.1 Ensure 'Audit IPsec Driver' is set to 'Success and Failure' (Automated)** [66, 67]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9213-69ae-11d9-bed3-505054503030}"` [68]

* **17.9.2 Ensure 'Audit Other System Events' is set to 'Success and Failure' (Automated)** [69, 70]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9214-69ae-11d9-bed3-505054503030}"` [71]

* **17.9.3 Ensure 'Audit Security State Change' is set to include 'Success' (Automated)** [72, 73]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9210-69ae-11d9-bed3-505054503030}"` [74]

* **17.9.4 Ensure 'Audit Security System Extension' is set to include 'Success' (Automated)** [75, 76]
  * **Trạng thái khuyến nghị:** Bao gồm Success.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9211-69ae-11d9-bed3-505054503030}"` [77]

* **17.9.5 Ensure 'Audit System Integrity' is set to 'Success and Failure' (Automated)** [78, 79]
  * **Trạng thái khuyến nghị:** Success and Failure.
  * **Lệnh quét Auditpol:** `auditpol /get /subcategory:"{0cce9212-69ae-11d9-bed3-505054503030}"` [80]