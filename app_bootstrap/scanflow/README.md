# Scan Flow Package

Package `app_bootstrap.scanflow` tách riêng theo component:

- `inventory.py`: khi khởi động, gọi trực tiếp `json_scanners/Get-WindowsServerInventory.ps1` để nhận diện phiên bản OS và dịch vụ.
- `selection.py`: hiển thị hộp chọn chế độ quét (nhanh/đầy đủ/bỏ qua).
- `scanner.py`: luồng quét chính qua `scripts/scan_executor.ps1`; manifest `rules/` chỉ chọn file đưa vào scanner, không dùng để so sánh lại ở Python.
- `scan_executor.ps1`: gộp kết quả thành `reports/temp/scan_results_merged.json` — đây là nguồn dữ liệu cho báo cáo.
- `report_builder.py`: đánh giá PASS/FAIL từ merged scan (metadata `Expected`/`RuleType` đã nhúng trong output), ghi `reports/scan_compare_report.json`.
- `scan_executor_client.py`: wrapper subprocess chỉ cho `scan_executor.ps1` (không dùng cho inventory).
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

Benchmark nhanh:

```powershell
python .\scripts\benchmark_rule_matching.py
```

## Kiểm chuẩn rule/output

Script `scripts/validate_scan_standards.py` dùng để xác nhận:

- Rule mặc định có đủ trường chuẩn để làm baseline.
- `temp.json` từ PowerShell scan có đủ key output bắt buộc.
- Report so sánh có đúng schema contract để frontend/backend dùng ổn định.

Chạy:

```powershell
python .\scripts\validate_scan_standards.py
```
