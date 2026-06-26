# Đặc tả luồng chức năng VulnMngSys

Tài liệu này bám theo `docs/FUNCTION_ACTIVITY_DIAGRAMS.puml`, class diagram `docs/IIS_AUDIT_CLASS_DIAGRAM.puml` và lớp use-case `vulnmngsys_app/services/iis_audit.py`.

| Chức năng | Điểm vào chính | Mã nguồn chính | Đầu ra | Kiểm soát lỗi |
|---|---|---|---|---|
| `getOSInfo` | `GET /api/iis/os-info`, tương thích `GET /api/inventory` | `services/iis_audit.py`, `scanflow/inventory.py` | Fingerprint OS/IIS/KB/service dạng JSON | Field không đọc được trả `UNKNOWN`, lỗi PowerShell vào `errors[]` |
| `scanConfiguration` | `POST /api/iis/scan/configuration`, tương thích `POST /api/scan` | `services/iis_audit.py`, `scan_facade.py`, `scanner.py` | Danh sách rule và evidence PASS/FAIL/UNKNOWN/NOT_APPLICABLE | Kiểm tra quyền scan, rule lỗi trả `SCAN_FAILED`, không FAIL nếu thiếu evidence |
| `backupandRollback` | Nội bộ, `POST /api/iis/rollback` | `adapters/backup_manager.py`, `services/iis_audit.py` | `backupId`, `backupPath`, trạng thái rollback | Backup phải verify trước apply, rollback lỗi trả `MANUAL_RECOVERY_REQUIRED` |
| `reconfigure` | `POST /api/iis/reconfigure/preview`, `POST /api/iis/reconfigure/apply`, tương thích `POST /api/reconfig` | `services/iis_audit.py`, `scanflow/reconfig.py` | Preview script hoặc kết quả apply | Apply cần confirmation, selected rules, backup, verify sau apply, rollback khi lỗi |
| `scanService` | `POST /api/iis/scan/service`, tương thích `POST /api/iis/scan/cve` và `POST /api/msf/audit` | `services/iis_audit.py`, `msf_audit/msfrpc_runner.py`, `local_warehouse.py` | Kết quả `check` của mọi module liên quan service được tick | Warehouse chỉ dùng để truy xuất module nhanh; kết quả scan bắt buộc đến từ MSFRPC `check`; module không hỗ trợ `check` trả `CHECK_UNSUPPORTED`; port/datastore là option của từng module |
| `generateIISReport` | Nội bộ sau `scanService` | `services/iis_audit.py`, `msf_audit/report_writer.py` | JSON/HTML IIS audit report | Lỗi ghi report trả `REPORT_GENERATION_FAILED` |
| `generateConfigScanReport` | Nội bộ sau `scanConfiguration`, `GET /api/iis/reports/config` | `services/iis_audit.py`, `scanflow/facades/scan_view.py` | JSON config scan report | Report thiếu trả `REPORT_GENERATION_FAILED` hoặc `REPORT_UNAVAILABLE` |

## Class chính cho báo cáo OOP

- `IISAuditOrchestrator`: điều phối 7 chức năng chính, không gọi trực tiếp HTTP, UI hay lệnh hệ thống.
- `OSInfoCollector`: thu thập fingerprint OS/IIS.
- `ConfigurationScanService`: chạy scan cấu hình qua scan facade hiện có.
- `BackupRollbackUseCase`: quản lý create/verify/list/rollback backup.
- `ReconfigureUseCase`: preview/apply cấu hình, kiểm tra confirmation và selected rules.
- `ServiceCveScanUseCase`: quét service được tick; warehouse chỉ chọn module, sau đó bắt buộc gọi MSFRPC `check` cho từng module. Không dùng metadata/cache làm kết quả scan.
- `AuditReportService`: sinh báo cáo cấu hình và IIS.
- `IISCveReconfigureUseCase`: preview/apply kế hoạch CVE theo hướng patch-led.

## Chính sách an toàn

- Không chạy exploit, không cấu hình payload, không tạo session.
- Không tự reboot.
- Không apply khi chưa có preview, selected rule/CVE và xác nhận apply.
- Không thay đổi IIS nếu backup không tạo hoặc không verify được.
- Nếu apply lỗi hoặc service đang chạy bị dừng, hệ thống rollback từ backup.
- Nếu rollback lỗi, trả `MANUAL_RECOVERY_REQUIRED`.
- CVE `PATCHED` luôn ưu tiên khi phát hiện fixed KB/build.
- CVE thiếu evidence trả `UNKNOWN`, không tự khẳng định `CONFIRMED`.

## Swim lane đã chốt

- `Người dùng`: Tác nhân bên ngoài thực hiện tương tác.
- `Frontend`: Giao diện ứng dụng gửi request và nhận kết quả hiển thị.
- `Backend`: Gộp toàn bộ Controller / API, IIS Audit Service, CVE / Metasploit Adapter, Backup / Rollback Manager, và Report Writer.
- `Server`: Gộp Target Windows Server (gồm Local Windows Collector, IIS Configuration Adapter, File System) và Metasploit Server.

