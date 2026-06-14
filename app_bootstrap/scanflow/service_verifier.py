from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

MONITORED_SERVICES = ("W3SVC", "IISADMIN", "MSSQLSERVER", "WMSvc", "MsDepSvc", "WsusService", "HTTP")


@dataclass(frozen=True, slots=True)
class ServiceStatus:
    name: str
    status: str
    display_name: str = ""


@dataclass(frozen=True, slots=True)
class ServiceHealthWarning:
    name: str
    before: str
    after: str
    message: str


def capture_service_snapshot(service_names: tuple[str, ...] = MONITORED_SERVICES) -> dict[str, ServiceStatus]:
    names = [name for name in service_names if name]
    if not names:
        return {}
    quoted = ", ".join(_ps(name) for name in names)
    command = (
        f"$names = @({quoted}); "
        "Get-Service -Name $names -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,DisplayName | ConvertTo-Json -Depth 3"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        return {}
    return _parse_service_snapshot(result.stdout)


def verify_service_health(
    before: dict[str, ServiceStatus],
    after: dict[str, ServiceStatus],
) -> list[ServiceHealthWarning]:
    warnings: list[ServiceHealthWarning] = []
    for name, prior in before.items():
        current = after.get(name)
        if current is None:
            warnings.append(
                ServiceHealthWarning(
                    name=name,
                    before=prior.status,
                    after="Missing",
                    message=f"{name} was present before reconfig but missing after reconfig.",
                )
            )
            continue
        if prior.status.casefold() == "running" and current.status.casefold() != "running":
            warnings.append(
                ServiceHealthWarning(
                    name=name,
                    before=prior.status,
                    after=current.status,
                    message=f"{name} changed from Running to {current.status} after reconfig.",
                )
            )
    return warnings


def warnings_payload(warnings: list[ServiceHealthWarning]) -> list[dict[str, str]]:
    return [
        {
            "name": warning.name,
            "before": warning.before,
            "after": warning.after,
            "message": warning.message,
        }
        for warning in warnings
    ]


def check_wsus_role() -> dict[str, Any]:
    command = (
        "if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { "
        "Get-WindowsFeature -Name UpdateServices,UpdateServices-Services,UpdateServices-WidDB "
        "-ErrorAction SilentlyContinue | Select-Object Name,DisplayName,InstallState | ConvertTo-Json -Depth 4 "
        "} else { @() | ConvertTo-Json }"
    )
    rows = _run_json_command(command)
    features = rows if isinstance(rows, list) else ([rows] if isinstance(rows, dict) else [])
    return {
        "installed": any(str(row.get("InstallState", "")).casefold() == "installed" for row in features),
        "features": features,
    }


def check_webdeploy_installed() -> dict[str, Any]:
    services = capture_service_snapshot(("WMSvc", "MsDepSvc"))
    command = (
        "$paths = @("
        "'%ProgramFiles%\\IIS\\Microsoft Web Deploy V3\\msdeploy.exe',"
        "'%ProgramFiles%\\IIS\\Microsoft Web Deploy V3\\msdepsvc.exe'"
        "); "
        "$files = foreach ($path in $paths) { "
        "$expanded = [Environment]::ExpandEnvironmentVariables($path); "
        "$item = Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue; "
        "if ($item) { [pscustomobject]@{ Path=$expanded; Exists=$true; Version=[string]$item.VersionInfo.FileVersion } } "
        "else { [pscustomobject]@{ Path=$expanded; Exists=$false; Version='' } } "
        "}; "
        "$reg = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\IIS Extensions\\MSDeploy\\3' -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ Files=@($files); RegistryExists=[bool]$reg } | ConvertTo-Json -Depth 5"
    )
    payload = _run_json_command(command)
    files = payload.get("Files", []) if isinstance(payload, dict) else []
    if isinstance(files, dict):
        files = [files]
    return {
        "installed": bool(services) or any(row.get("Exists") for row in files) or bool(payload.get("RegistryExists") if isinstance(payload, dict) else False),
        "services": {
            name: {
                "name": status.name,
                "status": status.status,
                "display_name": status.display_name,
            }
            for name, status in services.items()
        },
        "files": files,
        "registry_exists": bool(payload.get("RegistryExists") if isinstance(payload, dict) else False),
    }


def check_httpsys_driver() -> dict[str, Any]:
    command = (
        "$path = Join-Path $env:windir 'System32\\drivers\\http.sys'; "
        "$item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue; "
        "if ($item) { "
        "[pscustomobject]@{ Exists=$true; Path=$path; Version=[string]$item.VersionInfo.FileVersion; "
        "ProductVersion=[string]$item.VersionInfo.ProductVersion; LastWriteTime=$item.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ss') } "
        "} else { [pscustomobject]@{ Exists=$false; Path=$path } } | ConvertTo-Json -Depth 4"
    )
    payload = _run_json_command(command)
    return payload if isinstance(payload, dict) else {"exists": False}


def _parse_service_snapshot(raw: str) -> dict[str, ServiceStatus]:
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    rows = parsed if isinstance(parsed, list) else [parsed]
    snapshot: dict[str, ServiceStatus] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip()
        if not name:
            continue
        snapshot[name] = ServiceStatus(
            name=name,
            status=str(row.get("Status") or "").strip(),
            display_name=str(row.get("DisplayName") or "").strip(),
        )
    return snapshot


def _run_json_command(command: str) -> Any:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        return {}
    text = (result.stdout or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"
