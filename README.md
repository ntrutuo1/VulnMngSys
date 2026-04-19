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
- `vulnmngsys_app/privilege.py`: privilege elevation
- `vulnmngsys_app/modules.py`: hardcoded module matrix and rules
- `vulnmngsys_app/scanner.py`: evaluation engine
- `vulnmngsys_app/ui.py`: desktop interface
- `vulnmngsys_app/reporting.py`: report export
- `rules/`: source rule text files

## Run

```bash
python main.py
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
```

### Build Linux executable

```bash
python -m pip install -U pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name VulnMngSysDesktop --add-data "rules:rules" main.py
```

The output binary will be created in `dist/VulnMngSysDesktop`.

Or run one command:

```bash
bash build_linux.sh
```

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
- You can extend modules in `vulnmngsys_app/modules.py` for additional OS versions and services.
