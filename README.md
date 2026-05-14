# VulnMngSys Desktop

Windows Server service audit and hardening scanner written in Python.

This project is intentionally focused on Windows Server environments and on scanning all installed or running services, in the same spirit as Lynis, but adapted for Windows Server administration and Windows desktop app development.

## What It Does

- Scans Windows Server services and related configuration surfaces.
- Evaluates service exposure, hardening posture, startup behavior, and risky settings.
- Produces a Lynis hardening index and grade.
- Runs as a Windows desktop app built with Python.
- Includes a React-based UI for a modern Windows app experience.

## Focus

- Platform: Windows Server only
- Language: Python
- UI: Windows desktop app development
- Scope: service discovery, service inspection, hardening checks, and reporting

## Project Layout

- `main.py`: application entrypoint
- `vulnmngsys_app/domain/`: entities and contracts
- `vulnmngsys_app/application/`: composition root and factories
- `vulnmngsys_app/infrastructure/`: scanning, reporting, platform, privilege, catalog, and intelligence adapters
- `vulnmngsys_app/interfaces/`: CLI and desktop UI delivery layers
- `vulnmngsys_app/modules/`: hardcoded service and check definitions
- `rules/`: JSON rule sources used by the scanner, including check commands
- `react-ui/`: React frontend for the desktop app

## Scoring Model

The scanner uses the Lynis hardening index and grade criteria:

- `hardening_index = round((passed_weight / total_weight) * 100)`
- Grade bands:
  - `A`: `90-100`
  - `B`: `75-89`
  - `C`: `60-74`
  - `D`: `< 60`

## Lynis-Inspired Workflow

1. Detect host and service context.
2. Load CIS-aligned rule modules from JSON.
3. Resolve config paths and read configuration data.
4. Evaluate rules, aggregate score, and collect suggestions.
5. Optional service vulnerability checks (CVE and Metasploit) based on context.
6. Output a report with hardening index, warnings, and recommendations.

## CIS-Based Modules

Rules are stored in JSON under `rules/`. Each entry maps to a CIS control with a code like `1.1.1`.

Example format:

```json
{
  "code": "1.1.1",
  "title": "Password history",
  "severity": "High",
  "key": "PasswordHistoryCount",
  "expected": "24",
  "explanation": "...",
  "powershell_check": "Select-String \"PasswordHistoryCount\" $env:temp\\audit.inf"
}
```

## Metasploit Modules (JSON)

Metasploit auxiliary modules are listed in `rules/metasploit_windows_modules.json` and loaded at runtime:

```json
{
  "modules": [
    {
      "module": "auxiliary/scanner/smb/smb_version",
      "enabled": true,
      "options": { "RPORT": "445" }
    }
  ]
}
```

## Performance & Optimization

- CVE lookups are indexed by service type to avoid scanning unrelated advisories.
- Version parsing is cached for fast comparisons.
- API requests are bounded in size to avoid memory spikes.
- Scan history is append-only JSONL for low overhead.

## Easy Install (Windows)

Quick path for development:

```powershell
python -m venv .venv
.
.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
python main.py
```

## Run

```bash
python main.py
```

If you want the React UI during development:

```bash
cd react-ui
npm install
npm run dev
```

## Windows Quick Start

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the app:

```powershell
python main.py
```

## Build Windows Executable

Use the provided PowerShell script to build the Windows desktop app:

```powershell
.\build_windows.ps1
```

This produces stable executables in `dist/` for the GUI app and CLI variant.

If you want to build manually:

```powershell
cd react-ui
npm install
npm run build
cd ..
& "D:\VulnMngSys\.venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name VulnMngSysDesktop --add-data "rules;rules" --add-data "react-ui/dist;react-ui/dist" main.py
```

## Process Flow

1. Start the app.
2. Detect the Windows Server host and enumerate services.
3. Inspect service configuration, startup type, permissions, and exposure.
4. Run hardening checks for each discovered service.
5. Calculate the score and grade.
6. Show the results in the desktop UI and save a report.

## Notes

- The project does not use MySQL or SQLite.
- The scanner is code-driven so checks are deterministic and easy to extend.
- CVE lookups use service-type hash indexes and cached version parsing to keep scans fast and memory-friendly.
- The desktop API rejects oversized scan payloads and normalizes request fields before dispatch.
- New Windows Server service checks can be added in `vulnmngsys_app/modules/`.
