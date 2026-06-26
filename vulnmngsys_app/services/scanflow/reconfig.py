from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .json_rule_engine import SECURITY_POLICY_KEYS
from .remediation_logger import log_reconfig_event

logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _as_list(value: Any) -> list[str]:
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
        row
        for row in rows
        if _text(row.get("verdict")).upper() == "FAIL" or row.get("passed") is False
    ]


def _row_id(row: dict[str, Any]) -> str:
    return _text(row.get("id") or row.get("ruleId") or row.get("rule_id") or row.get("title"))


def _selected_rows(rows: list[dict[str, Any]], selected_rule_ids: list[str] | None) -> list[dict[str, Any]]:
    selected = {_text(item) for item in selected_rule_ids or [] if _text(item)}
    if not selected:
        return rows
    return [row for row in rows if _row_id(row) in selected]


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
        f"Set-RegistryValue -Path {_ps(path)} -Name {_ps(name)} -Value {value} -Type {_ps(value_type)}",
        "",
    ]
    return True


def _registry_backup_key(row: dict[str, Any]) -> str:
    registry_path = _text(row.get("registry_path"))
    source = _text(row.get("source"))
    spec = registry_path if _registry_parts(registry_path) else source
    parts = _registry_parts(spec)
    if not parts:
        return ""
    path, _ = parts
    return path.replace(":\\", "\\")


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


@dataclass(frozen=True)
class RemediationPlan:
    script_path: Path
    selected_count: int
    applied_count: int
    skipped_rule_ids: list[str]
    registry_backup_keys: list[str]

    def payload(self) -> dict[str, Any]:
        return {
            "scriptPath": str(self.script_path),
            "applied": self.applied_count,
            "skipped": len(self.skipped_rule_ids),
            "selected": self.selected_count,
            "registryBackupKeys": self.registry_backup_keys,
        }


class RemediationScriptRenderer:
    def render(self, rows: list[dict[str, Any]]) -> tuple[list[str], int, list[str], list[str]]:
        lines = self._header()
        system: dict[str, str] = {}
        rights: dict[str, str] = {}
        applied = 0
        skipped: list[str] = []
        registry_backup_keys: list[str] = []

        for row in rows:
            if _add_registry(row, lines) or _add_secedit(row, system, rights):
                applied += 1
                registry_key = _registry_backup_key(row)
                if registry_key:
                    registry_backup_keys.append(registry_key)
            else:
                skipped.append(_row_id(row))

        _append_secedit(lines, system, rights)

        if skipped:
            lines += ["# Skipped rules without safe automatic remediation:"]
            lines += [f"# - {item}" for item in skipped if item]

        lines.append("Write-Output 'VulnMngSys reconfiguration completed.'")
        lines.append("Stop-Transcript")
        return lines, applied, skipped, list(dict.fromkeys(registry_backup_keys))

    def _header(self) -> list[str]:
        return [
            "# Generated by VulnMngSys. Review before running in production.",
            "$transcriptPath = Join-Path $env:TEMP 'vulnmngsys_reconfig_transcript.log'",
            "Start-Transcript -Path $transcriptPath -Force",
            "$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()",
            "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "
            "throw 'Run as Administrator.' }",
            "$ErrorActionPreference = 'Stop'",
            "function Set-RegistryValue {",
            "  param([string]$Path, [string]$Name, [object]$Value, [string]$Type)",
            "  if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }",
            "  try {",
            "    $null = Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop",
            "    Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value",
            "  } catch {",
            "    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null",
            "  }",
            "}",
            "",
        ]


class RemediationPlanner:
    def __init__(self, renderer: RemediationScriptRenderer | None = None) -> None:
        self.renderer = renderer or RemediationScriptRenderer()

    def build_plan(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_rule_ids: list[str] | None = None,
    ) -> RemediationPlan:
        out_dir = app_root / "reports" / "reconfig"
        out_dir.mkdir(parents=True, exist_ok=True)
        script_path = out_dir / "vulnmngsys_reconfig.ps1"
        rows = _selected_rows(_failed_rows(_load_rows(report)), selected_rule_ids)
        lines, applied, skipped, registry_backup_keys = self.renderer.render(rows)
        script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return RemediationPlan(
            script_path=script_path,
            selected_count=len(rows),
            applied_count=applied,
            skipped_rule_ids=skipped,
            registry_backup_keys=registry_backup_keys,
        )


class PowerShellScriptExecutor:
    def run(self, script_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )


class RemediationPipeline:
    def __init__(
        self,
        *,
        planner: RemediationPlanner | None = None,
        backup=None,
        verifier=None,
        executor: PowerShellScriptExecutor | None = None,
    ) -> None:
        self.planner = planner or RemediationPlanner()
        self.backup = backup
        self.verifier = verifier
        self.executor = executor or PowerShellScriptExecutor()

    def preview(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_rule_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        plan = self.planner.build_plan(report, app_root, selected_rule_ids)
        payload = plan.payload()
        log_reconfig_event(app_root, "reconfig_preview", payload)
        return payload

    def apply(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_rule_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if self.backup is None or self.verifier is None:
            raise ValueError("Remediation apply requires backup and verifier dependencies.")

        logger.getChild("remediation").info(
            "Starting Reconfig Process. Selected rules: %s",
            len(selected_rule_ids) if selected_rule_ids else "ALL",
        )

        plan = self.planner.build_plan(report, app_root, selected_rule_ids)
        backup_id = self.backup.trigger_backup(selected_rule_ids, registry_paths=plan.registry_backup_keys)
        before_status = self.verifier.get_services_status()
        result = self.executor.run(plan.script_path)
        is_stable = self.verifier.verify_after_fix(before_status)
        should_rollback = result.returncode != 0 or not is_stable
        auto_rolled_back = False

        if should_rollback:
            logger.error("Reconfig failed or service health check failed. Starting rollback.")
            rollback_success = self.backup.rollback_config(backup_id)
            auto_rolled_back = True
            logger.getChild("remediation").warning(
                "Automatic rollback activated. Backup ID: %s. Success: %s",
                backup_id,
                rollback_success,
            )

        response = {
            "ok": result.returncode == 0 and is_stable,
            "autoRolledBack": auto_rolled_back,
            "backupId": backup_id,
            "backupPath": str(self.backup.backup_path(backup_id)) if hasattr(self.backup, "backup_path") else "",
            **plan.payload(),
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
            "exitCode": result.returncode,
            "serviceWarnings": [{"message": "Service crashed and system rolled back"}] if auto_rolled_back else [],
        }

        logger.getChild("remediation").info(
            "Reconfig Process Completed. OK: %s, RolledBack: %s",
            response["ok"],
            auto_rolled_back,
        )
        log_reconfig_event(app_root, "reconfig_apply", response)
        return response


def generate_reconfig_script(
    report: dict[str, Any],
    app_root: Path,
    selected_rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    return RemediationPipeline().preview(report, app_root, selected_rule_ids)
