"""Load and filter Metasploit modules from the focused IIS CVE profile."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from vulnmngsys_app.services.scanflow.paths import project_root

_PROFILE_DIR = project_root() / "metasploit_modules"
_PROFILE_CANDIDATES = (
    _PROFILE_DIR / "iis_windows_server_msf_modules.json",
    _PROFILE_DIR / "iis_windows_server_2022_msf_modules.json",
)


def _load_profile() -> dict[str, Any]:
    for profile_path in _PROFILE_CANDIDATES:
        if profile_path.exists():
            return json.loads(profile_path.read_text(encoding="utf-8"))
    searched = ", ".join(str(path) for path in _PROFILE_CANDIDATES)
    raise FileNotFoundError(f"MSF profile JSON not found. Searched: {searched}")


def load_safe_modules(
    active_test: bool = False,
    *,
    selected_cves: Iterable[str] | None = None,
    ports: Iterable[int] | None = None,
) -> list[dict[str, Any]]:
    """Return safe CVE-mapped modules enriched with display_id.

    ``active_test`` is kept for API compatibility. The focused CVE profile has no
    conditional active-write modules.
    """
    return load_cve_modules(selected_cves=selected_cves, ports=ports)


def load_cve_modules(
    *,
    selected_cves: Iterable[str] | None = None,
    ports: Iterable[int] | None = None,
) -> list[dict[str, Any]]:
    """Return only modules mapped to configured CVEs."""
    profile = _load_profile()
    selected = _normalize_cves(selected_cves)
    ports_supplied = ports is not None
    selected_ports = _normalize_ports(ports)
    excluded_paths = {
        item.get("module", "")
        for item in profile.get("excluded_or_dangerous_modules", [])
    }

    result: list[dict[str, Any]] = []
    for index, mod in enumerate(profile.get("modules", []), start=1):
        cves = [str(cve).upper() for cve in mod.get("cve", []) if cve]
        if not cves:
            continue
        if selected and not selected.intersection(cves):
            continue

        module_path = mod.get("module")
        if module_path and module_path in excluded_paths:
            continue
        if mod.get("safe_to_run") is not True:
            continue

        enriched = dict(mod)
        enriched["cve"] = cves
        enriched["display_id"] = f"{mod.get('display_id_prefix', 'IIS-CVE')}-{index:03d}"

        variants = list(mod.get("local_variants", []))
        if ports_supplied and variants:
            variants = [
                variant for variant in variants
                if _variant_port(variant) in selected_ports
            ]
            if not variants and mod.get("check_method") != "local_only":
                continue
        enriched["local_variants"] = variants

        result.append(enriched)

    return result


def get_local_check_config(module_id: str) -> dict[str, Any]:
    """Return the PowerShell local-check config for a module id."""
    for mod in load_cve_modules():
        if mod.get("id") == module_id:
            return dict(mod.get("local_check") or {})
    return {}


def load_excluded_modules() -> list[dict[str, Any]]:
    """Return list of excluded/dangerous modules for UI information."""
    profile = _load_profile()
    return profile.get("excluded_or_dangerous_modules", [])


def load_profile_metadata() -> dict[str, Any]:
    """Return profile-level metadata and the focused CVE/port list."""
    profile = _load_profile()
    modules = profile.get("modules", [])
    cves = []
    for mod in modules:
        cve_ids = mod.get("cve", [])
        if not cve_ids:
            continue
        cves.append(
            {
                "id": cve_ids[0],
                "name": mod.get("name", ""),
                "severity": mod.get("severity", ""),
                "cvss": mod.get("cvss"),
                "module_id": mod.get("id", ""),
                "module": mod.get("module", ""),
                "module_type": mod.get("module_type", ""),
                "check_method": mod.get("check_method", ""),
                "component": mod.get("component", ""),
                "aliases": mod.get("aliases", []),
                "cpe": mod.get("cpe", []),
                "ports": _module_ports(mod),
                "execution": mod.get("execution", {}),
                "applicability": mod.get("applicability", {}),
                "evidence_contract": mod.get("evidence_contract", {}),
            }
        )
    return {
        "profile_name": profile.get("profile_name", ""),
        "schema_version": profile.get("schema_version", ""),
        "scope": profile.get("scope", {}),
        "common_http_options": profile.get("common_http_options", {}),
        "common_https_options": profile.get("common_https_options", {}),
        "common_local_options": profile.get("common_local_options", {}),
        "execution_defaults": profile.get("execution_defaults", {}),
        "cves": cves,
    }


def _normalize_cves(cves: Iterable[str] | None) -> set[str]:
    return {str(cve).strip().upper() for cve in cves or [] if str(cve).strip()}


def _normalize_ports(ports: Iterable[int] | None) -> set[int]:
    normalized: set[int] = set()
    for port in ports or []:
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= port_number <= 65535:
            normalized.add(port_number)
    return normalized


def _variant_port(variant: dict[str, Any]) -> int | None:
    try:
        return int(variant.get("RPORT"))
    except (TypeError, ValueError):
        return None


def _module_ports(mod: dict[str, Any]) -> list[int]:
    ports = {_variant_port(variant) for variant in mod.get("local_variants", [])}
    ports.discard(None)
    return sorted(port for port in ports if port is not None)
