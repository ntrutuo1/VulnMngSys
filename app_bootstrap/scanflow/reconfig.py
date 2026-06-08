from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .json_rule_engine import SECURITY_POLICY_KEYS


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_text(item) for item in value if _text(item)]
    text = _text(value)
    if not text:
        return []
    if "," in text:
        return [item.strip() for item in text.split(",") if item.strip()]
    return [text]


def _registry_parts(spec: str) -> tuple[str, str] | None:
    if ":" not in spec or not spec.upper().startswith(("HK", "HKEY_")):
        return None
    path, name = spec.split(":", 1)
    aliases = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_USERS": "HKU",
    }
    segments = [item for item in path.split("\\") if item]
    if not segments or not name:
        return None
    hive = aliases.get(segments[0].upper(), segments[0])
    subkey = "\\".join(segments[1:])
    return f"{hive}:\\{subkey}", name


def _registry_value(expected: Any, spec: str) -> tuple[str, str]:
    values = _as_list(expected)
    if isinstance(expected, bool):
        return ("1" if expected else "0"), "DWord"
    if isinstance(expected, list) and values and all(item.isdigit() for item in values):
        return values[0], "DWord"
    if isinstance(expected, (int, float)) or (_text(expected).isdigit() and len(values) <= 1):
        return _text(expected), "DWord"
    if isinstance(expected, list) or "NullSession" in spec:
        return "@(" + ", ".join(_ps(item.lstrip("*")) for item in values) + ")", "MultiString"
    return _ps(_text(expected)), "String"


def _key_from_check(row: dict[str, Any]) -> str:
    check = _text(row.get("powershell_check"))
    match = re.search(r"\^([A-Za-z0-9_]+)", check)
    return match.group(1) if match else ""


def _load_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    merged_text = _text(report.get("mergedScanFile"))
    merged = Path(merged_text) if merged_text else None
    if merged and merged.exists() and merged.is_file():
        payload = json.loads(merged.read_text(encoding="utf-8-sig"))
        return [item for item in payload if isinstance(item, dict)]
    return [item for item in report.get("items", []) if isinstance(item, dict)]


def _failed_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row for row in rows
        if _text(row.get("verdict")).upper() == "FAIL" or row.get("passed") is False
    ]


def _add_registry(row: dict[str, Any], lines: list[str]) -> bool:
    registry_path = _text(row.get("registry_path"))
    source = _text(row.get("source"))
    spec = registry_path if _registry_parts(registry_path) else source
    parts = _registry_parts(spec)
    if not parts or _text(row.get("operator")) in {"!=", "NotEqual"}:
        return False
    path, name = parts
    value, value_type = _registry_value(row.get("expected"), spec)
    lines += [
        f"# {row.get('id') or row.get('ruleId')}: {_text(row.get('title'))}",
        f"New-Item -Path {_ps(path)} -Force | Out-Null",
        f"New-ItemProperty -Path {_ps(path)} -Name {_ps(name)} -Value {value} -PropertyType {value_type} -Force | Out-Null",
        "",
    ]
    return True


def _add_secedit(row: dict[str, Any], system: dict[str, str], rights: dict[str, str]) -> bool:
    rule_id = _text(row.get("id") or row.get("ruleId"))
    expected = row.get("expected")
    if rule_id in SECURITY_POLICY_KEYS:
        system[SECURITY_POLICY_KEYS[rule_id]] = _text(expected)
        return True
    key = _key_from_check(row)
    if not key:
        return False
    check_type = _text(row.get("check_type") or row.get("checkType")).casefold()
    if check_type == "userrights":
        rights[key] = ",".join(_as_list(expected))
        return True
    return False


def _append_secedit(lines: list[str], system: dict[str, str], rights: dict[str, str]) -> None:
    if not system and not rights:
        return
    lines += [
        "$cfg = Join-Path $env:TEMP 'vulnmngsys_reconfig.inf'",
        "$db = Join-Path $env:TEMP 'vulnmngsys_reconfig.sdb'",
        "$inf = @(",
        "  '[Unicode]'",
        "  'Unicode=yes'",
        "  '[Version]'",
        "  'signature=\"$CHICAGO$\"'",
        "  'Revision=1'",
    ]
    if system:
        lines.append("  '[System Access]'")
        lines += [f"  {_ps(f'{key} = {value}')}" for key, value in system.items()]
    if rights:
        lines.append("  '[Privilege Rights]'")
        lines += [f"  {_ps(f'{key} = {value}')}" for key, value in rights.items()]
    lines += [
        ")",
        "$inf | Set-Content -Path $cfg -Encoding Unicode",
        "secedit /configure /db $db /cfg $cfg /areas SECURITYPOLICY USER_RIGHTS | Out-Null",
        "",
    ]


def generate_reconfig_script(report: dict[str, Any], app_root: Path) -> dict[str, Any]:
    out_dir = app_root / "reports" / "reconfig"
    out_dir.mkdir(parents=True, exist_ok=True)
    script = out_dir / "vulnmngsys_reconfig.ps1"
    lines = [
        "# Generated by VulnMngSys. Review before running in production.",
        "$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()",
        "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }",
        "$ErrorActionPreference = 'Stop'",
        "",
    ]
    system: dict[str, str] = {}
    rights: dict[str, str] = {}
    applied = 0
    skipped: list[str] = []
    for row in _failed_rows(_load_rows(report)):
        if _add_registry(row, lines) or _add_secedit(row, system, rights):
            applied += 1
        else:
            skipped.append(_text(row.get("id") or row.get("ruleId") or row.get("title")))
    _append_secedit(lines, system, rights)
    if skipped:
        lines += ["# Skipped rules without safe automatic remediation:"]
        lines += [f"# - {item}" for item in skipped if item]
    lines.append("Write-Output 'VulnMngSys reconfiguration completed.'")
    script.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    return {"scriptPath": str(script), "applied": applied, "skipped": len(skipped)}


def run_reconfig_script(report: dict[str, Any], app_root: Path) -> dict[str, Any]:
    payload = generate_reconfig_script(report, app_root)
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", payload["scriptPath"]],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    return {
        "ok": result.returncode == 0,
        **payload,
        "stdout": (result.stdout or "").strip(),
        "stderr": (result.stderr or "").strip(),
        "exitCode": result.returncode,
    }
