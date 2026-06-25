# Tổng Quan Kiến Trúc Hệ Thống VulnMngSys

VulnMngSys là ứng dụng desktop chạy cục bộ trên Windows Server để rà quét cấu hình bảo mật, đối chiếu rule CIS, sinh báo cáo và hỗ trợ preview/apply remediation có rollback.

## 1. Sơ Đồ Kiến Trúc Tổng Quan

```mermaid
flowchart TB
  subgraph UI["Presentation Layer / View"]
    React["React Web UI\nreact-ui/src"]
    Static["Packaged UI\nvulnmngsys_app/views/dist"]
    Desktop["Desktop WebView\nstartup/ui.py"]
  end

  subgraph API["Controller Layer"]
    ApiServer["Local HTTP API\ncontrollers/api_server.py"]
    ConfigRoutes["Scan / Report / Reconfig Routes\ncontrollers/config_routes.py"]
    MsfRoutes["IIS CVE Audit Routes\ncontrollers/msf_routes.py"]
  end

  subgraph Service["Service Layer"]
    ScanFacade["Scan Facade\nservices/scan_facade.py"]
    ScanFlow["Scan Flow Engine\nservices/scanflow"]
    RuleEngine["JSON Rule Engine\njson_rule_engine.py"]
    ReportBuilder["Report Builder\nreport_builder.py"]
    Reconfig["Remediation Pipeline\nreconfig.py"]
    MsfAudit["MSF Audit Service\nscanflow/msf_audit"]
  end

  subgraph Model["Model / Contract Layer"]
    Models["Protocols + Result Models\nmodels/"]
  end

  subgraph Adapter["Adapter Layer"]
    Registry["Registry Checker"]
    Secedit["Secedit Checker"]
    Auditpol["Auditpol Checker"]
    PowerShell["PowerShell Checker"]
    Collector["Windows Collector"]
    Backup["Backup / Rollback Adapter"]
  end

  subgraph External["Windows / External Runtime"]
    Windows["Windows Server APIs\nRegistry / Services / Local Users"]
    Rules["CIS JSON Rules\nrules/"]
    Reports["JSON / HTML Reports\nreports/"]
    Msf["Metasploit RPC\noptional local runtime"]
  end

  React --> Static
  Desktop --> Static
  Static --> ApiServer
  ApiServer --> ConfigRoutes
  ApiServer --> MsfRoutes
  ConfigRoutes --> ScanFacade
  ConfigRoutes --> Reconfig
  MsfRoutes --> MsfAudit
  ScanFacade --> ScanFlow
  ScanFlow --> RuleEngine
  ScanFlow --> ReportBuilder
  ScanFlow --> Models
  RuleEngine --> Adapter
  Reconfig --> Backup
  Adapter --> Windows
  RuleEngine --> Rules
  ReportBuilder --> Reports
  MsfAudit --> Msf
  MsfAudit --> Reports
```

## 2. Mô Hình MVC Đang Áp Dụng

| Thành phần MVC | Package / Module | Vai trò |
|----------------|------------------|---------|
| View | `react-ui/src`, `vulnmngsys_app/views/dist` | Giao diện người dùng, dashboard, gọi API nội bộ |
| Controller | `vulnmngsys_app/controllers` | Nhận HTTP request, validate quyền, gọi service |
| Model | `vulnmngsys_app/models` | Protocol, contract, dữ liệu kết quả scan |
| Service | `vulnmngsys_app/services` | Nghiệp vụ scan, report, remediation, MSF audit |
| Adapter | `vulnmngsys_app/adapters` | Tích hợp Windows: registry, secedit, auditpol, PowerShell, backup |
| Startup | `vulnmngsys_app/startup` | Entry point, khởi tạo UI/API, ghép dependency |

Root package `vulnmngsys_app` chỉ giữ `__init__.py`; logic không đặt ở root.

## 3. Luồng Rà Quét Cấu Hình

```mermaid
sequenceDiagram
  actor Admin as Quản trị viên
  participant UI as React UI
  participant API as Controller API
  participant Facade as Scan Facade
  participant Scanner as Scan Flow
  participant Engine as JSON Rule Engine
  participant Win as Windows Server
  participant Report as Report Builder

  Admin->>UI: Chọn Quick Scan / Full Scan
  UI->>API: POST /api/scan
  API->>Facade: run_scan_and_save_report()
  Facade->>Scanner: run_scan_for_profile()
  Scanner->>Engine: scan_rule_files()
  Engine->>Win: Đọc registry / secedit / auditpol / local user
  Win-->>Engine: Actual configuration
  Engine-->>Scanner: RuleComparisonResult[]
  Scanner->>Report: Build report
  Report-->>Facade: JSON report
  Facade-->>API: Summary payload
  API-->>UI: Scan result
```

## 4. Luồng Remediation

```mermaid
sequenceDiagram
  actor Admin as Quản trị viên
  participant UI as React UI
  participant API as Reconfig Controller
  participant Pipeline as Remediation Pipeline
  participant Backup as Backup Adapter
  participant PS as PowerShell Executor
  participant Health as Service Verifier

  Admin->>UI: Preview remediation
  UI->>API: POST /api/reconfig apply=false
  API->>Pipeline: preview()
  Pipeline-->>UI: PowerShell script preview

  Admin->>UI: Apply remediation
  UI->>API: POST /api/reconfig apply=true
  API->>Pipeline: apply()
  Pipeline->>Backup: Create backup
  Pipeline->>PS: Execute script
  Pipeline->>Health: Verify critical services
  alt Service health failed
    Pipeline->>Backup: Rollback
  end
  Pipeline-->>UI: Apply result
```

## 5. Luồng IIS CVE Audit

```mermaid
sequenceDiagram
  actor Auditor as Auditor
  participant UI as React UI
  participant API as MSF Controller
  participant Loader as Module Loader
  participant Manager as Metasploit Manager
  participant Runner as Audit Runner
  participant Writer as Report Writer

  Auditor->>UI: Chạy IIS CVE Audit
  UI->>API: POST /api/msf/audit
  API->>API: Validate target / activeTest
  API->>Loader: Load safe modules
  alt Module cần MSF
    API->>Manager: wait_until_connected()
  end
  API->>Runner: run_iis_msf_audit()
  Runner-->>API: Audit payload
  API->>Writer: Write JSON / HTML report
  API-->>UI: Audit result
```

## 6. Thành Phần Chính

| Thành phần | Trách nhiệm |
|------------|-------------|
| React UI | Hiển thị dashboard, kết quả scan, service tree, remediation, MSF audit |
| Local API | Cổng giao tiếp nội bộ giữa UI và backend |
| Scan Facade | Cung cấp API nghiệp vụ đơn giản cho controller |
| Scan Flow | Điều phối scan theo profile Windows Server |
| JSON Rule Engine | Đọc rule, lấy actual value, so sánh expected/actual |
| Report Builder | Chuẩn hóa kết quả và sinh report |
| Remediation Pipeline | Preview/apply script, backup, rollback |
| MSF Audit | Kiểm tra IIS CVE bằng local check và Metasploit RPC |
| Adapters | Đóng gói chi tiết Windows-specific |

## 7. Nguyên Tắc Thiết Kế

- **Single Responsibility:** mỗi layer chỉ xử lý đúng việc của nó.
- **Low Coupling:** UI không gọi trực tiếp service; controller không xử lý Windows API.
- **High Cohesion:** scan, report, remediation, MSF audit tách thành service riêng.
- **Dependency Inversion:** service làm việc qua model/protocol; startup ghép implementation cụ thể.
- **Windows Server only:** không giữ nhánh Linux/headless trong kiến trúc chính.

## 8. Artifact Build / Runtime

```mermaid
flowchart LR
  Source["Source Code"] --> Build["build_windows.ps1"]
  React["react-ui/dist"] --> Views["vulnmngsys_app/views/dist"]
  Build --> Exe["dist/VulnMngSysDesktop.exe"]
  Build --> Cli["dist/VulnMngSysDesktop-CLI.exe"]
  Exe --> Runtime["Local Desktop Runtime"]
  Cli --> Runtime
```

Output build chuẩn hiện tại nằm trong:

```text
D:\VulnMngSys\VulnMngSys\dist
```

## 9. Kết Luận Kiến Trúc

Hệ thống hiện được tổ chức theo MVC mở rộng:

- View: React/WebView.
- Controller: local HTTP route.
- Model: protocol và result model.
- Service: nghiệp vụ chính.
- Adapter: tích hợp Windows.
- Startup: composition root.

Cách chia này phù hợp để bảo vệ vì giải thích được luồng nghiệp vụ, điểm mở rộng, dependency direction và giới hạn phạm vi Windows Server.
