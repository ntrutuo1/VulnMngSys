# VulnMngSys - Windows Server configuration vulnerability scanner

This application scans Windows Server machines for configuration misconfigurations using the CIS Benchmark rule set (Windows Server 2022) and runs locally with Administrator privileges.

## Scope

- Account Policy (`secedit`)
- User Rights Assignment (`secedit /areas USER_RIGHTS`)
- Security Options / Registry
- Advanced Audit Policy (`auditpol`)
- Some per-user rules (HKU)

Not included: network scanning, CVE databases, and the Metasploit runtime.

## Kiến trúc

```mermaid
flowchart LR
  UI[React UI] --> API[api_server.py]
  API --> Scan[scan_backend.py]
  Scan --> Eng[app_bootstrap.scanflow.json_rule_engine]
  Scan --> Cmp[report_builder.py]
  Cmp --> Report[reports/scan_compare_report.json]
```

## Requirements

- Windows Server 2016 / 2019 / 2022 (2022 recommended)
- Python 3.10+
- PowerShell 5.1+
- Administrator privileges (UAC)

## Development Run

```powershell
cd VulnMngSys
python main.py
```

CLI:

```powershell
python main.py --cli
```

Xác thực hợp đồng rule/scan/report:

```powershell
python scripts\validate_scan_standards.py
```

## Build UI + EXE

```powershell
cd react-ui
npm install
npm run build
cd ..
.\build_windows.ps1
```

## Add a New Rule

Ví dụ password policy:

```json
{
  "id": "1.1.1",
  "title": "Enforce password history",
  "type": "secedit",
  "key": "PasswordHistorySize",
  "expected": { "min": 24 },
  "description": "24 or more passwords retained"
}
```

Supported `type` values: `secedit`, `user_right`, `registry`, `user_registry`, `auditpol`, `local_account`.

Manifest: [`rules/Windows_Server_2022_manifest.json`](rules/Windows_Server_2022_manifest.json) — `quick` / `full`.

## Local API

| Endpoint | Description |
|----------|--------|
| `GET /api/inventory` | OS / profile information |
| `POST /api/scan` | Body: `{ "mode": "quick\|full", "profileKey": "Windows_Server_2022" }` |
| `GET /api/report` | Latest JSON report |
| `GET /api/report/export?format=html` | Export HTML |

## Reports

- JSON: `reports/scan_compare_report.json`
- HTML: `reports/scan_report.html` (after export)
