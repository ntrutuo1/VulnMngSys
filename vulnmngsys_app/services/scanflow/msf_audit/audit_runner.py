"""Orchestrate the focused IIS critical CVE audit."""
from __future__ import annotations

import datetime
import json
import subprocess
from ipaddress import ip_address
from typing import Any, Iterable

from .module_loader import load_cve_modules, load_profile_metadata
from .msfrpc_runner import MsfRpcConnectionError, MsfRpcRunner
from .result_analyzer import analyze
from .score_calculator import calculate_score, score_color, score_label


def run_iis_msf_audit(
    *,
    target: str = "127.0.0.1",
    msfrpc_host: str = "127.0.0.1",
    msfrpc_port: int = 55552,
    msfrpc_password: str = "",
    msfrpc_ssl: bool = True,
    active_test: bool = False,
    ports: Iterable[int] | None = None,
    selected_cves: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Run focused IIS CVE checks and return a report payload."""
    metadata = load_profile_metadata()
    selected_ports = (
        _normalize_ports(ports)
        if ports is not None
        else list(metadata.get("scope", {}).get("default_ports", []))
    )
    modules = load_cve_modules(selected_cves=selected_cves, ports=selected_ports)
    runner = MsfRpcRunner(
        host=msfrpc_host,
        port=msfrpc_port,
        password=msfrpc_password,
        ssl=msfrpc_ssl,
    )

    results: list[dict[str, Any]] = []
    for mod in modules:
        display_id = mod.get("display_id", mod.get("id", ""))
        local_check_result = run_local_patch_check(
            _primary_cve(mod),
            target=target,
            config=mod.get("local_check") or {},
        )

        if mod.get("check_method") == "local_only":
            analysis = analyze(mod, "", local_check_result)
            results.append(
                _build_result_entry(
                    mod,
                    display_id,
                    analysis,
                    local_check_result=local_check_result,
                    msf_results=[],
                    port="N/A",
                    ssl=False,
                )
            )
            continue

        variant_results: list[dict[str, Any]] = []
        for variant in mod.get("local_variants", [{}]):
            datastore = dict(mod.get("default_datastore", {}))
            datastore.update(variant)
            datastore["RHOSTS"] = target
            raw_output = ""

            try:
                if mod.get("module_type") == "exploit":
                    raw_output = runner.run_exploit_check(str(mod.get("module") or ""), datastore)
                else:
                    raw_output = runner.run_module(str(mod.get("module") or ""), datastore)
                analysis = analyze(mod, raw_output, local_check_result)
            except MsfRpcConnectionError as exc:
                raw_output = f"failed to load module: msfrpc connection error: {exc}"
                analysis = analyze(mod, raw_output, local_check_result)
            except Exception as exc:
                raw_output = f"failed to load module: {exc}"
                analysis = analyze(mod, raw_output, local_check_result)

            variant_results.append(
                {
                    "port": datastore.get("RPORT", ""),
                    "ssl": bool(datastore.get("SSL", False)),
                    "raw_output": raw_output,
                    **analysis,
                }
            )

        results.append(
            _merge_variant_results(
                mod,
                display_id,
                variant_results,
                local_check_result=local_check_result,
            )
        )

    score = calculate_score(results)
    summary = _build_summary(results)

    return {
        "ok": True,
        "profile": metadata.get("profile_name", ""),
        "target": target,
        "service": "IIS / HTTP.sys / Web Deploy / WSUS",
        "scan_mode": "focused_cve_local",
        "active_test": active_test,
        "timestamp": datetime.datetime.now().isoformat(),
        "selected_ports": list(selected_ports),
        "selected_cves": [cve for cve in selected_cves or []],
        "score": score,
        "score_label": score_label(score),
        "score_color": score_color(score),
        "summary": summary,
        "kb_patch_summary": _build_kb_patch_summary(results),
        "results": results,
    }


def run_local_patch_check(
    cve_id: str,
    *,
    target: str = "127.0.0.1",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the configured local PowerShell check for a CVE."""
    if not _is_local_target(target):
        return {
            "status": "SKIPPED",
            "cve_id": cve_id,
            "evidence": "Local PowerShell check skipped because target is not localhost.",
            "applicable": None,
            "patch_found": None,
        }

    cfg = config or {}
    try:
        data = _run_powershell_json(_build_local_check_script(cfg))
    except Exception as exc:
        return {
            "status": "ERROR",
            "cve_id": cve_id,
            "evidence": f"PowerShell local check failed: {exc}",
            "applicable": None,
            "patch_found": None,
            "patch_after": cfg.get("patch_after", ""),
            "patch_guidance": cfg.get("patch_guidance", ""),
        }

    return _evaluate_local_check(cve_id, cfg, data)


def run_local_service_check(service_names: Iterable[str]) -> dict[str, Any]:
    """Return local service status details for service_names."""
    cfg = {"service_names": list(service_names), "patch_after": "1900-01-01"}
    try:
        data = _run_powershell_json(_build_local_check_script(cfg))
    except Exception as exc:
        return {"ok": False, "error": str(exc), "services": []}
    return {"ok": True, "services": data.get("Services", [])}


_STATUS_RANK: dict[str, int] = {
    "ERROR": 5,
    "FAIL": 4,
    "WARNING": 3,
    "INFO": 2,
    "SKIPPED": 1,
    "PASS": 0,
}


def _merge_variant_results(
    mod: dict[str, Any],
    display_id: str,
    variant_results: list[dict[str, Any]],
    *,
    local_check_result: dict[str, Any],
) -> dict[str, Any]:
    if not variant_results:
        analysis = analyze(mod, "", local_check_result)
        return _build_result_entry(
            mod,
            display_id,
            analysis,
            local_check_result=local_check_result,
            msf_results=[],
            port="N/A",
            ssl=False,
        )

    worst = max(
        variant_results,
        key=lambda r: _STATUS_RANK.get(str(r.get("status", "PASS")), 0),
    )
    return _build_result_entry(
        mod,
        display_id,
        worst,
        local_check_result=local_check_result,
        msf_results=[
            {
                "port": item.get("port", ""),
                "ssl": item.get("ssl", False),
                "status": item.get("status", ""),
                "evidence": item.get("evidence", ""),
            }
            for item in variant_results
        ],
        port=worst.get("port", ""),
        ssl=bool(worst.get("ssl", False)),
    )


def _build_result_entry(
    mod: dict[str, Any],
    display_id: str,
    analysis: dict[str, Any],
    *,
    local_check_result: dict[str, Any],
    msf_results: list[dict[str, Any]],
    port: int | str,
    ssl: bool,
) -> dict[str, Any]:
    return {
        "id": display_id,
        "module_id": mod.get("id", ""),
        "module": mod.get("module") or "",
        "module_type": mod.get("module_type", ""),
        "check_method": mod.get("check_method", ""),
        "name": mod.get("name", ""),
        "category": mod.get("category", ""),
        "risk": mod.get("risk", ""),
        "cve": mod.get("cve", []),
        "severity": mod.get("severity", ""),
        "cvss": mod.get("cvss"),
        "port": port,
        "ssl": ssl,
        "status": analysis.get("status", "PASS"),
        "evidence": analysis.get("evidence", ""),
        "remediation": analysis.get("remediation", ""),
        "local_check_result": local_check_result,
        "msf_results": msf_results,
        "server_2022_relevance": mod.get("server_2022_relevance", ""),
        "expected_signal": mod.get("expected_signal", ""),
    }


def _build_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "warning": 0,
        "info": 0,
        "skipped": 0,
        "error": 0,
    }
    for result in results:
        key = str(result.get("status", "")).lower()
        if key in counts:
            counts[key] += 1
    return counts


def _build_kb_patch_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for result in results:
        local = result.get("local_check_result") or {}
        summary.append(
            {
                "cve": _primary_cve(result),
                "severity": result.get("severity", ""),
                "status": local.get("status", result.get("status", "")),
                "patch_after": local.get("patch_after", ""),
                "patch_found": local.get("patch_found"),
                "installed_hotfixes": [
                    item.get("HotFixID", "")
                    for item in local.get("hotfixes", [])
                    if item.get("HotFixID")
                ],
                "required_patch": local.get("patch_guidance", ""),
                "evidence": local.get("evidence", ""),
            }
        )
    return summary


def _evaluate_local_check(cve_id: str, cfg: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    services = _ensure_list(data.get("Services"))
    hotfixes = _ensure_list(data.get("HotFixesSincePatchDate"))
    files = _ensure_list(data.get("FileVersions"))
    features = _ensure_list(data.get("WindowsFeatures"))
    registry = _ensure_list(data.get("Registry"))
    service_names = cfg.get("service_names") or []
    patch_after = str(cfg.get("patch_after") or "")
    patch_found = bool(hotfixes)
    service_present = bool(services)
    installed_feature = any(str(item.get("InstallState", "")).lower() == "installed" for item in features)
    existing_files = [item for item in files if item.get("Exists")]
    existing_registry = [item for item in registry if item.get("Exists")]
    local_payload = {
        "cve_id": cve_id,
        "patch_after": patch_after,
        "patch_guidance": cfg.get("patch_guidance", ""),
        "services": services,
        "hotfixes": hotfixes,
        "file_versions": files,
        "windows_features": features,
        "registry": registry,
        "patch_found": patch_found,
    }

    if cve_id == "CVE-2025-53772":
        applicable = service_present or bool(existing_files) or bool(existing_registry)
        if not applicable:
            return {
                **local_payload,
                "status": "PASS",
                "applicable": False,
                "evidence": "Web Deploy services/files/registry were not found locally; CVE is not applicable.",
            }
        return _patch_based_result(
            local_payload,
            patch_found,
            f"Web Deploy is present ({_format_services(services)}).",
        )

    if cve_id == "CVE-2025-27473":
        applicable = service_present or bool(existing_files)
        if not applicable:
            return {
                **local_payload,
                "status": "WARNING",
                "applicable": None,
                "evidence": "HTTP.sys service/driver details could not be confirmed locally.",
            }
        return _patch_based_result(
            local_payload,
            patch_found,
            f"HTTP.sys/IIS local components are present ({_format_services(services)}).",
        )

    if cve_id == "CVE-2025-59282":
        return _patch_based_result(
            local_payload,
            patch_found,
            "Inbox COM libraries checked locally.",
            applicable=True,
        )

    if cve_id == "CVE-2025-59287":
        applicable = service_present or installed_feature or bool(existing_files)
        if not applicable:
            return {
                **local_payload,
                "status": "PASS",
                "applicable": False,
                "evidence": "WSUS service/role/files were not found locally; CVE is not applicable.",
            }
        return _patch_based_result(
            local_payload,
            patch_found,
            f"WSUS is present ({_format_services(services)}).",
        )

    return _patch_based_result(local_payload, patch_found, "Local patch posture checked.")


def _patch_based_result(
    payload: dict[str, Any],
    patch_found: bool,
    base_evidence: str,
    *,
    applicable: bool = True,
) -> dict[str, Any]:
    patch_after = payload.get("patch_after") or "the configured patch date"
    if patch_found:
        hotfix_text = ", ".join(
            item.get("HotFixID", "")
            for item in payload.get("hotfixes", [])
            if item.get("HotFixID")
        )
        return {
            **payload,
            "status": "PASS",
            "applicable": applicable,
            "evidence": f"{base_evidence} Found installed hotfix on/after {patch_after}: {hotfix_text or 'present'}.",
        }
    return {
        **payload,
        "status": "FAIL",
        "applicable": applicable,
        "evidence": f"{base_evidence} No installed hotfix was found on/after {patch_after}.",
    }


def _build_local_check_script(cfg: dict[str, Any]) -> str:
    return f"""
$ErrorActionPreference = 'SilentlyContinue'
function Expand-EnvPath([string]$Path) {{
  $expanded = $Path
  if ($expanded -match '^\\$env:([^\\\\/]+)(.*)$') {{
    $envValue = [Environment]::GetEnvironmentVariable($matches[1])
    if ($envValue) {{
      $expanded = $envValue + $matches[2]
    }}
  }}
  [Environment]::ExpandEnvironmentVariables($expanded)
}}
function Convert-Date($Value) {{
  try {{ return [datetime]$Value }} catch {{ return $null }}
}}
$serviceNames = {_ps_array(cfg.get("service_names") or [])}
$featureNames = {_ps_array(cfg.get("windows_features") or [])}
$filePaths = {_ps_array(cfg.get("file_paths") or [])}
$registryPaths = {_ps_array(cfg.get("registry_paths") or [])}
$patchAfter = Convert-Date {_ps(cfg.get("patch_after") or "1900-01-01")}
$services = @()
foreach ($name in $serviceNames) {{
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {{
    $services += [pscustomobject]@{{
      Name = $svc.Name
      Status = [string]$svc.Status
      DisplayName = $svc.DisplayName
    }}
  }}
}}
$hotfixes = @()
Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {{
  $installed = Convert-Date $_.InstalledOn
  if ($installed -and $installed -ge $patchAfter) {{
    $hotfixes += [pscustomobject]@{{
      HotFixID = $_.HotFixID
      Description = $_.Description
      InstalledOn = $installed.ToString('yyyy-MM-dd')
    }}
  }}
}}
$files = @()
foreach ($path in $filePaths) {{
  $expanded = Expand-EnvPath $path
  $item = Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue
  if ($item) {{
    $files += [pscustomobject]@{{
      Path = $expanded
      Exists = $true
      Version = [string]$item.VersionInfo.FileVersion
      ProductVersion = [string]$item.VersionInfo.ProductVersion
      LastWriteTime = $item.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ss')
    }}
  }} else {{
    $files += [pscustomobject]@{{ Path = $expanded; Exists = $false }}
  }}
}}
$features = @()
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {{
  foreach ($name in $featureNames) {{
    $feature = Get-WindowsFeature -Name $name -ErrorAction SilentlyContinue
    if ($feature) {{
      $features += [pscustomobject]@{{
        Name = $feature.Name
        DisplayName = $feature.DisplayName
        InstallState = [string]$feature.InstallState
      }}
    }}
  }}
}}
$registry = @()
foreach ($path in $registryPaths) {{
  $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
  $registry += [pscustomobject]@{{
    Path = $path
    Exists = [bool]$item
  }}
}}
[pscustomobject]@{{
  Services = @($services)
  HotFixesSincePatchDate = @($hotfixes)
  FileVersions = @($files)
  WindowsFeatures = @($features)
  Registry = @($registry)
}} | ConvertTo-Json -Depth 6
"""


def _run_powershell_json(script: str) -> dict[str, Any]:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Unknown PowerShell error"
        raise RuntimeError(detail)
    text = result.stdout.strip()
    if not text:
        return {}
    parsed = json.loads(text)
    return parsed if isinstance(parsed, dict) else {}


def _normalize_ports(ports: Iterable[int] | None) -> list[int]:
    normalized: list[int] = []
    for port in ports or []:
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= port_number <= 65535 and port_number not in normalized:
            normalized.append(port_number)
    return normalized


def _is_local_target(target: str) -> bool:
    lowered = (target or "").strip().casefold()
    if lowered in {"localhost", "::1"}:
        return True
    try:
        return ip_address(lowered).is_loopback
    except ValueError:
        return False


def _primary_cve(item: dict[str, Any]) -> str:
    cves = item.get("cve") or []
    return str(cves[0]) if cves else ""


def _ensure_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _format_services(services: list[dict[str, Any]]) -> str:
    if not services:
        return "no matching service status returned"
    return ", ".join(
        f"{service.get('Name', '')}:{service.get('Status', '')}"
        for service in services
    )


def _ps_array(values: Iterable[Any]) -> str:
    values = [value for value in values if value]
    if not values:
        return "@()"
    return "@(" + ", ".join(_ps(value) for value in values) + ")"


def _ps(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"
