# JSON Scanner Utilities

Backend Python gọi hai điểm khác nhau:

1. **Khởi động / inventory** — gọi trực tiếp `Get-WindowsServerInventory.ps1` (phiên bản OS, dịch vụ).
2. **Quét chính** — gọi `scripts/scan_executor.ps1`, script đó chỉ điều phối `Invoke-RuleJsonScan.ps1`.

```powershell
# Inventory (khởi động)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsServerInventory.ps1 -AsJson

# Scan (sau khi user chọn quick/full)
powershell -NoProfile -ExecutionPolicy Bypass -File ..\scan_executor.ps1 `
  -RuleJsonPaths "D:\...\rules\Windows_Server_2022_1.json" `
  -OutputDir "D:\...\reports\temp" -Quiet
```

## `Get-WindowsServerInventory.ps1`

- Tự động nhận diện phiên bản hệ điều hành Windows Server hiện tại.
- Thu thập danh sách dịch vụ trọng yếu đang tồn tại trên máy.
- Trả ra JSON để backend/frontend dùng cho luồng nghiệp vụ quét.

Ví dụ chạy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsServerInventory.ps1 -AsJson
```

## Luồng wizard quét

`app_bootstrap/scan_wizard.py` sẽ gọi script inventory, hiển thị hộp chọn:

- `Yes`: Quét nhanh (profile `_rules`)
- `No`: Quét đầy đủ (toàn bộ script profile)
- `Cancel`: Bỏ qua