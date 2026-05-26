# JSON Scanner Utilities

The Python backend uses two entry points:

1. **Startup / inventory** - directly invokes `Get-WindowsServerInventory.ps1` (OS version, services).
2. **Primary scan** - goes through the internal JSON rule engine in `app_bootstrap.scanflow`.

```powershell
# Inventory (startup)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsServerInventory.ps1 -AsJson

# Scan (after the user selects quick/full) -- handled by the Python engine
python ..\..\main.py --cli
```

## `Get-WindowsServerInventory.ps1`

- Automatically detects the current Windows Server edition.
- Collects the list of critical services present on the machine.
- Returns JSON for the backend and frontend scan workflow.

Example:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsServerInventory.ps1 -AsJson
```

## Scan Wizard Flow

`app_bootstrap/scan_wizard.py` will call the inventory script and display a selection dialog:

- `Yes`: Quick scan (profile `_rules`)
- `No`: Full scan (entire script profile)
- `Cancel`: Skip