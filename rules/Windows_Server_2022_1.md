# Mục 1: Account Policies (Chính sách Tài khoản)

Mục lớn đầu tiên này bao gồm các khuyến nghị về Chính sách Mật khẩu và Chính sách Khóa tài khoản [1, 2].

## 1.1 Password Policy (Chính sách Mật khẩu)

* **1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)**
  * **Mô tả:** Xác định số lượng mật khẩu cũ không được phép tái sử dụng [3].
  * **Trạng thái khuyến nghị:** 24 or more password(s) [3].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Enforce password history` [4].

* **1.1.2 Ensure 'Maximum password age' is set to '365 or fewer days, but not 0' (Automated)**
  * **Mô tả:** Xác định khoảng thời gian người dùng có thể sử dụng mật khẩu trước khi nó hết hạn [5].
  * **Trạng thái khuyến nghị:** 365 or fewer days, but not 0 [6].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Maximum password age` [7].

* **1.1.3 Ensure 'Minimum password age' is set to '1 or more day(s)' (Automated)**
  * **Mô tả:** Xác định số ngày tối thiểu phải sử dụng mật khẩu trước khi có thể thay đổi [8].
  * **Trạng thái khuyến nghị:** 1 or more day(s) [9].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password age` [10].

* **1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)' (Automated)**
  * **Mô tả:** Xác định số lượng ký tự tối thiểu để tạo mật khẩu [11].
  * **Trạng thái khuyến nghị:** 14 or more character(s) [11].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password length` [12].

* **1.1.5 Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Automated)**
  * **Mô tả:** Yêu cầu các mật khẩu mới phải đáp ứng các tiêu chuẩn về độ phức tạp cơ bản [13].
  * **Trạng thái khuyến nghị:** Enabled [14].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Password must meet complexity requirements` [15].

* **1.1.6 Ensure 'Relax minimum password length limits' is set to 'Enabled' (Automated)**
  * **Mô tả:** Cho phép nới lỏng giới hạn độ dài tối thiểu của mật khẩu (giúp thiết lập độ dài vượt mức giới hạn 14 ký tự cũ) [16].
  * **Trạng thái khuyến nghị:** Enabled [16].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Relax minimum password length limits` [17].

* **1.1.7 Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Automated)**
  * **Mô tả:** Cấm lưu trữ mật khẩu dưới dạng mã hóa có thể dịch ngược (tương đương với lưu bản rõ) [18].
  * **Trạng thái khuyến nghị:** Disabled [19].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Store passwords using reversible encryption` [20].

---

## 1.2 Account Lockout Policy (Chính sách Khóa tài khoản)

* **1.2.1 Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Automated)**
  * **Mô tả:** Xác định thời gian tài khoản bị khóa trước khi được tự động mở lại [21].
  * **Trạng thái khuyến nghị:** 15 or more minute(s) [22].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout duration` [23].

* **1.2.2 Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0' (Automated)**
  * **Mô tả:** Xác định số lần đăng nhập sai cho phép trước khi tài khoản bị khóa [24].
  * **Trạng thái khuyến nghị:** 5 or fewer invalid logon attempt(s), but not 0 [24].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout threshold` [25].

* **1.2.3 Ensure 'Allow Administrator account lockout' is set to 'Enabled' (Manual)**
  * **Mô tả:** Áp dụng chính sách khóa tài khoản cho cả tài khoản Administrator mặc định [26].
  * **Trạng thái khuyến nghị:** Enabled [27].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policies\Allow Administrator account lockout` [28].

* **1.2.4 Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Automated)**
  * **Mô tả:** Xác định khoảng thời gian cần thiết để hệ thống đặt lại bộ đếm số lần đăng nhập sai về 0 [29].
  * **Trạng thái khuyến nghị:** 15 or more minute(s) [30].
  * **Đường dẫn cấu hình:** `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Reset account lockout counter after` [31].