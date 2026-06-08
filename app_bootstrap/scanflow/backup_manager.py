from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def build_backup_commands(rows: list[dict[str, Any]], backup_dir: Path) -> list[str]:
    commands = [
        "# Pre-fix backup",
        f"$backupDir = {_ps(str(backup_dir))}",
        "New-Item -ItemType Directory -Path $backupDir -Force | Out-Null",
        "$backupManifest = @()",
        "$seceditBackup = Join-Path $backupDir 'secedit_before.inf'",
        "secedit /export /cfg $seceditBackup /areas SECURITYPOLICY USER_RIGHTS | Out-Null",
        "$backupManifest += \"secedit=$seceditBackup\"",
    ]

    for index, registry_key in enumerate(_registry_keys(rows), start=1):
        export_file = f"registry_{index}.reg"
        commands += [
            f"$regBackup{index} = Join-Path $backupDir {_ps(export_file)}",
            f"reg export {_ps(registry_key)} $regBackup{index} /y | Out-Null",
            f"$backupManifest += {_ps(f'registry={registry_key};file=')} + $regBackup{index}",
        ]

    commands += [
        "$backupManifest | Set-Content -Path (Join-Path $backupDir 'manifest.txt') -Encoding UTF8",
        "",
    ]
    return commands


def _registry_keys(rows: list[dict[str, Any]]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        spec = _text(row.get("registry_path")) or _text(row.get("source"))
        key = _registry_key(spec)
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def _registry_key(spec: str) -> str:
    if ":" not in spec or not spec.upper().startswith(("HK", "HKEY_")):
        return ""
    path = spec.split(":", 1)[0]
    aliases = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_USERS": "HKU",
    }
    segments = [segment for segment in re.split(r"\\+", path) if segment]
    if not segments:
        return ""
    hive = aliases.get(segments[0].upper(), segments[0])
    return "\\".join([hive, *segments[1:]])


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"
