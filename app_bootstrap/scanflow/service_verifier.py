from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

MONITORED_SERVICES = ("W3SVC", "IISADMIN", "MSSQLSERVER")


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


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"
