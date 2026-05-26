# Scan Flow Package

Package `app_bootstrap.scanflow` tách riêng theo component:

- `inventory.py`: khi khởi động, gọi trực tiếp `json_scanners/Get-WindowsServerInventory.ps1` để nhận diện phiên bản OS và dịch vụ.
- `selection.py`: hiển thị hộp chọn chế độ quét (nhanh/đầy đủ/bỏ qua).
- `json_rule_engine.py`: đọc trực tiếp rule JSON, thu thập snapshot `secedit`/`auditpol`/registry/HKU và sinh kết quả scan chuẩn hóa.
- `scanner.py`: wrapper mỏng tạo `reports/temp/scan_results_merged.json` từ engine JSON.
- `report_builder.py`: tổng hợp PASS/FAIL/MANUAL từ merged scan và ghi `reports/scan_compare_report.json`.
- `scan_executor_client.py`: compatibility wrapper, hiện cũng đi qua engine JSON.
- `comparator.py`: so sánh kết quả quét với rule mẫu JSON.
- `guidance.py`: sinh hướng dẫn xử lý chuẩn cho các rule fail.
- `orchestrator.py`: điều phối toàn bộ flow scan sau khi app được nâng quyền.
- `rule_catalog.py`: nạp manifest rule chuẩn để xác định bộ rule mặc định.
- `matching/`: tối ưu lookup rule bằng hash table + binary search.

Kết quả so sánh cuối cùng được lưu tại `reports/scan_compare_report.json`.

Rule baseline mặc định được chốt trong `rules/Windows_Server_2022_manifest.json`.

## Chiến thuật tăng tốc pass/fail

- Rule lookup dùng hash table theo key chuẩn hóa (`id`/`code`) để đạt tra cứu trung bình O(1).
- Khi có collision cùng hash, bucket được sắp xếp và dùng binary search O(log k).
- Công thức băm: FNV-1a 64-bit

```text
h0 = 14695981039346656037
h(i+1) = ((h(i) XOR byte(i)) * 1099511628211) mod 2^64
```

Benchmark nhanh: dùng script validation hiện có để kiểm tra rule/output trước khi chạy scan chính.

## Kiểm chuẩn rule/output

Script `scripts/validate_scan_standards.py` dùng để xác nhận:

- Rule mặc định có đủ trường chuẩn để làm baseline.
- `temp.json` từ PowerShell scan có đủ key output bắt buộc.
- Report so sánh có đúng schema contract để frontend/backend dùng ổn định.

Chạy:

```powershell
python .\scripts\validate_scan_standards.py
```
