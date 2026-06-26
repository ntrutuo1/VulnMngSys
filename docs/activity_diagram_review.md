# Activity Diagram Review

## Diagram inspected

- File: `docs/FUNCTION_ACTIVITY_DIAGRAMS.puml`
- Directive: `D:\VulnMngSys\Reference\implementation(1).md`

## Kết quả kiểm tra ban đầu

- Diagram cũ bị mojibake nên không đạt yêu cầu trình bày tiếng Việt.
- Diagram cũ có 10 chức năng, còn directive mới yêu cầu 7 chức năng chính.
- `getIISCVE` và `scanIISCVE` nên gộp vào `scanServiceCVE`.
- `reconfigConfiguration`, `ReconfigIIS`, `backupAndRollbackConfiguration`, `backupAndRollbackIISService` nên gom thành `reconfigure` và `backupandRollback`.
- Lane `Backend` quá rộng, chưa tách rõ Controller, Service, Adapter, Backup và Report Writer.

## Swim lane review

- Người dùng: OK, chỉ thao tác chọn scan, chọn remediation, xác nhận apply.
- Frontend: OK, chỉ gửi request và hiển thị kết quả.
- Controller / API: OK, giữ token, quyền, validate request, không chạy lệnh hệ thống trực tiếp.
- IIS Audit Service: OK, điều phối use case và quyết định nghiệp vụ.
- Local Windows Collector: OK, thu thập OS/build/KB/service bằng PowerShell cục bộ.
- IIS Configuration Adapter: OK, đọc/ghi IIS, registry, secedit, auditpol, appcmd.
- CVE / Metasploit Adapter: OK, map fingerprint sang CVE/module, chỉ chạy safe check nếu có.
- Backup / Rollback Manager: OK, tạo backup trước apply, verify backup, rollback khi lỗi.
- Report Writer: OK, chỉ chuẩn hóa và ghi báo cáo.
- Local Windows Server / IIS: OK, là hệ thống cục bộ bị đọc hoặc thay đổi.
- Metasploit Server: OK, chỉ là adapter phụ trợ cho metadata/check an toàn.

## Missing branches found

- Thiếu nhánh `appcmd not found`.
- Thiếu nhánh `CVE cache unavailable`.
- Thiếu nhánh `MSFRPC unavailable` nhưng vẫn tiếp tục bằng local cache.
- Thiếu safety gate `confirmed=true` trước apply.
- Thiếu nhánh `backup failed` chặn reconfigure.
- Thiếu nhánh `rollback failed` trả `MANUAL_RECOVERY_REQUIRED`.
- Thiếu nhánh `pendingReboot` nhưng không tự reboot.
- Thiếu nguyên tắc không đánh `FAIL` khi không có evidence.

## Corrections applied

- Viết lại PlantUML thành 7 diagram theo đúng tên chức năng:
  - `getOSInfo`
  - `scanConfiguration`
  - `backupandRollback`
  - `reconfigure`
  - `scanServiceCVE`
  - `generateIISReport`
  - `generateConfigScanReport`
- Tách swim lane theo chiều dọc và theo đúng trách nhiệm.
- Thêm failure branch và safety gate trước khi thay đổi IIS.
- Gộp flow IIS CVE vào `scanServiceCVE`.
- Gộp backup/rollback cấu hình và IIS service vào một flow `backupandRollback`.

## Final decision

- ACCEPTED

## Reason

Diagram mới khớp directive, khớp code hiện tại, có đủ tác nhân, có đủ nhánh lỗi chính và có safety gate trước mọi thay đổi hệ thống.
