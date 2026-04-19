# VulnMngSys Desktop (No-DB)

Desktop security configuration scanner written in Python.

This rebuild removes database usage and uses hardcoded scan modules by:
- OS family (`linux`, `windows`, `macos`)
- OS version (for example `ubuntu-22.04`, `ubuntu-24.04`, `windows-11`)
- Service type (`ssh`, `apache-http`, `apache-tomcat`)

Rule sources are kept in `rules/` and mapped to executable checks in code.

## Key Behavior

- Desktop app (Tkinter) runs on Linux, Windows, and macOS.
- On startup, app attempts to relaunch with elevated privilege:
  - Linux/macOS: `sudo -E`
  - Windows: UAC `runas`
- Scanner reads real configuration files and evaluates checks.
- Scoring uses a Lynis-style hardening index:
  - `hardening_index = round((passed_weight / total_weight) * 100)`
  - Grade bands: `A >= 90`, `B >= 75`, `C >= 60`, `D < 60`

## Project Layout

- `main.py`: app entrypoint
- `vulnmngsys_app/domain/`: entities + contracts (pure domain)
- `vulnmngsys_app/application/`: factories/composition root
- `vulnmngsys_app/infrastructure/`: adapters (scan, report, platform, privilege, catalog, CVE intel)
- `vulnmngsys_app/interfaces/`: delivery layers (CLI, Tk GUI, desktop frontend host)
- `vulnmngsys_app/modules/`: hardcoded module definitions by service/version
  - `modules/ssh/`: SSH modules by OS/version
  - `modules/apache/`: Apache modules by OS/version
- `vulnmngsys_app/*.py` (legacy names): compatibility facades to keep old imports working
- `rules/`: source rule text files

## SOLID Notes

- SRP: scanning, scoring, report writing, module catalog are separated classes.
- OCP: new scoring/report implementations can be added without changing UI/CLI flows.
- LSP: UI/CLI depend on interfaces (`ScanEngine`, `ReportWriter`, `ModuleCatalog`).
- ISP: small focused interfaces in `contracts.py`.
- DIP: high-level modules receive abstractions, concrete defaults are injected centrally.

## Run

```bash
python main.py
```

The packaged app now opens the React frontend inside a desktop window.
On Linux, you must run inside a graphical desktop session with a valid `DISPLAY`; a headless SSH-only shell cannot show the UI.
If GTK/QT Python backends are missing on Linux, the app falls back to the legacy desktop UI instead of crashing.

For Linux frozen builds, the app uses Firefox web-view mode by default.

For Ubuntu, install these system packages to enable the native React window:

```bash
sudo apt install -y python3-gi gir1.2-gtk-3.0 libgtk-3-0 libwebkit2gtk-4.0-37
sudo apt install -y firefox
```

## React UI

New React interface is available in `react-ui/`.

```bash
cd react-ui
npm install
npm run dev
```

## Ubuntu 22.04 Quick Start

Install required system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk policykit-1
```

If you already created a venv before installing python3-tk, recreate the venv so tkinter is available inside it.

Create and activate virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
```

Run app (it will auto-request root using pkexec or sudo):

```bash
python main.py
```

If you are on a headless Ubuntu server (no GUI / no DISPLAY), the app automatically switches to CLI mode.

You can also force CLI mode:

```bash
python main.py --cli --service ssh
python main.py --cli --service apache-http
python main.py --cli --module-id linux-ubuntu22-ssh
python main.py --cli --service apache-http --os-version ubuntu-22.04 --service-version 2.4.50
```

Interactive CLI selection (recommended on Linux/headless):

```bash
python main.py --cli --interactive
```

This will let you choose service, module, OS version, and service version step by step.

If running from frozen Linux binary without GUI backends, interactive CLI can still be used:

```bash
./VulnMngSysDesktop-CLI-linux-<timestamp> --cli --interactive
```

### CVE intelligence (version-aware)

The scanner can evaluate hardcoded CVE knowledge for:
- Apache HTTP/Tomcat version ranges
- OpenSSH version ranges
- Combined Apache/SSH + OS context rules (for example Ubuntu 22.04)

To enable this, provide service version in GUI or use CLI flags:

```bash
python main.py --cli --service ssh --os-version ubuntu-22.04 --service-version 9.2
```

If `--os-version` or `--service-version` is omitted, the scanner now auto-detects values from host commands/files across Windows, Linux, and macOS where possible.

### Detect and list service versions (SSH/HTTPD/Tomcat)

The project now includes a dedicated script that probes and lists versions from multiple sources, including XAMPP/LAMPP paths.

```bash
python scripts/detect_and_install_services.py
```

Probe only selected services:

```bash
python scripts/detect_and_install_services.py --services ssh apache-http apache-tomcat
```

Apache layout mode (when you are not sure if host uses XAMPP or standalone):

```bash
python scripts/detect_and_install_services.py --services apache-http apache-tomcat --apache-layout auto
python scripts/detect_and_install_services.py --services apache-http apache-tomcat --apache-layout xampp
python scripts/detect_and_install_services.py --services apache-http apache-tomcat --apache-layout standalone
```

If XAMPP is installed in a custom folder, provide it explicitly:

```bash
python scripts/detect_and_install_services.py --services apache-http apache-tomcat --apache-layout xampp --xampp-root D:/tools/xampp
```

In `xampp` mode, the probe tries to locate Apache/Tomcat `bin` directories first, changes into them, runs version commands, and parses output for version auto-fill.

Attempt automatic installation for missing services:

```bash
python scripts/detect_and_install_services.py --install-missing
```

Non-interactive install mode:

```bash
python scripts/detect_and_install_services.py --install-missing --yes
```

Notes:
- Windows: `ssh` uses OpenSSH capability install, `apache-http` and `apache-tomcat` use XAMPP via `winget`.
- Linux: installer uses detected package manager (`apt-get`, `dnf`, `yum`, or `pacman`).
- On systems without package manager support in this script, install command must be run manually.

### Build Linux executable

```bash
python -m pip install -U pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name VulnMngSysDesktop --add-data "rules:rules" --add-data "react-ui/dist:react-ui/dist" main.py
```

The script now creates 2 Linux binaries in `dist/`:

- `VulnMngSysDesktop-linux-<timestamp>`: GUI desktop build.
- `VulnMngSysDesktop-CLI-linux-<timestamp>`: dedicated CLI build.

Or run one command:

```bash
bash build_linux.sh
```

The Linux build script will also build `react-ui/` first and bundle it into the executable.

### Build Windows executable with React UI

Use the provided PowerShell script to bundle the React frontend into the exe:

```powershell
.\build_windows.ps1
```
Script sẽ tạo 2 file trong thư mục `dist`:

- `VulnMngSysDesktop-<timestamp>.exe`: bản GUI desktop (React UI).
- `VulnMngSysDesktop-CLI-<timestamp>.exe`: bản CLI (hỗ trợ `--cli --interactive`).

Ví dụ chạy bản CLI interactive trên Windows:

```powershell
.\dist\VulnMngSysDesktop-CLI-<timestamp>.exe --cli --interactive
```

If you want to run the commands manually:

```powershell
cd react-ui
npm install
npm run build
cd ..
& "D:\VulnMngSys\.venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name VulnMngSysDesktop --add-data "rules;rules" --add-data "react-ui/dist;react-ui/dist" main.py
```

The exe will open as a desktop app window, not inside Chrome.

If native webview backends are missing on Linux but you still want the React interface, allow browser fallback:

```bash
python main.py --web-ui
```

Windows builds now generate a timestamped exe name in `dist/` to avoid overwriting a locked running binary.

## Process Flow

1. Start app.
2. Ensure root/admin privileges.
3. Choose OS + service module from hardcoded matrix.
4. Resolve config file path candidates.
5. Run all checks in selected module.
6. Calculate hardening index and grade.
7. Display results and save report into `reports/`.

## Notes

- This version intentionally does not use MySQL/SQLite.
- Checks are deterministic and code-based for portability.
- You can extend modules in `vulnmngsys_app/modules/` for additional OS versions and services.
