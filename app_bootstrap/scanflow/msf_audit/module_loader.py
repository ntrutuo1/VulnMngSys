"""Load and filter Metasploit modules from the IIS profile JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_PROFILE_JSON = (
    Path(__file__).resolve().parents[3]
    / "metasploit_modules"
    / "iis_windows_server_2022_msf_modules.json"
)

# Sequential display IDs for the 12 modules in order
_MODULE_DISPLAY_IDS: dict[str, str] = {
    "iis_internal_ip_http": "IIS-MSF-001",
    "iis_shortname_scanner_http": "IIS-MSF-002",
    "http_trace_xst": "IIS-MSF-003",
    "http_options": "IIS-MSF-004",
    "webdav_scanner": "IIS-MSF-005",
    "http_put_write_test": "IIS-MSF-006",
    "http_dir_listing": "IIS-MSF-007",
    "http_interesting_files": "IIS-MSF-008",
    "robots_txt": "IIS-MSF-009",
    "http_version": "IIS-MSF-010",
    "ssl_tls_version": "IIS-MSF-011",
    "http_ssl_certificate": "IIS-MSF-012",
}


def _load_profile() -> dict[str, Any]:
    if not _PROFILE_JSON.exists():
        raise FileNotFoundError(f"MSF profile JSON not found: {_PROFILE_JSON}")
    return json.loads(_PROFILE_JSON.read_text(encoding="utf-8"))


def load_safe_modules(active_test: bool = False) -> list[dict[str, Any]]:
    """Return list of safe modules enriched with display_id.

    Args:
        active_test: If True, include conditional modules (http_put_write_test).
    """
    profile = _load_profile()
    modules: list[dict[str, Any]] = profile.get("modules", [])
    excluded_paths = {
        item.get("module", "")
        for item in profile.get("excluded_or_dangerous_modules", [])
    }

    result: list[dict[str, Any]] = []
    for mod in modules:
        module_path = mod.get("module", "")
        if module_path in excluded_paths:
            continue

        safe_to_run = mod.get("safe_to_run", False)
        # "conditional" modules only included in active_test mode
        if safe_to_run is True:
            pass  # always include
        elif safe_to_run == "conditional":
            if not active_test:
                continue
        else:
            continue  # False or unknown — skip

        module_id = mod.get("id", module_path)
        enriched = dict(mod)
        enriched["display_id"] = _MODULE_DISPLAY_IDS.get(module_id, module_id)
        result.append(enriched)

    return result


def load_excluded_modules() -> list[dict[str, Any]]:
    """Return list of excluded/dangerous modules (for UI information only)."""
    profile = _load_profile()
    return profile.get("excluded_or_dangerous_modules", [])


def load_profile_metadata() -> dict[str, Any]:
    """Return profile-level metadata (scope, common options, etc.)."""
    profile = _load_profile()
    return {
        "profile_name": profile.get("profile_name", ""),
        "scope": profile.get("scope", {}),
        "common_http_options": profile.get("common_http_options", {}),
        "common_https_options": profile.get("common_https_options", {}),
    }
