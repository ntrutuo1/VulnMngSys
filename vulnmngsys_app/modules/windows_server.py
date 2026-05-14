from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import ModuleDefinition
from ..infrastructure.platform.audit_generator import get_audit_inf_path
from .common import make_assignment_check, rules_file


WINDOWS_SERVER_RULES_FILE = rules_file("Windows_Server_2022_rules.json")


def _load_windows_server_rule_specs() -> list[dict[str, str]]:
    rule_path = Path(WINDOWS_SERVER_RULES_FILE)
    raw_rules = json.loads(rule_path.read_text(encoding="utf-8"))
    if not isinstance(raw_rules, list):
        raise ValueError("Windows Server rules JSON must contain a list of rule objects")

    normalized_rules: list[dict[str, str]] = []
    required_keys = {
        "code",
        "title",
        "severity",
        "key",
        "expected",
        "explanation",
        "powershell_check",
    }
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError("Each Windows Server rule entry must be a JSON object")
        missing = required_keys - item.keys()
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(f"Windows Server rule entry is missing required keys: {missing_list}")
        normalized_rules.append(
            {
                "code": str(item["code"]),
                "title": str(item["title"]),
                "severity": str(item["severity"]),
                "key": str(item["key"]),
                "expected": str(item["expected"]),
                "explanation": str(item["explanation"]),
                "powershell_check": str(item["powershell_check"]),
            }
        )

    return normalized_rules


WINDOWS_SERVER_RULE_SPECS: list[dict[str, str]] = _load_windows_server_rule_specs()


def build_windows_server_check_metadata() -> dict[str, dict[str, str]]:
    metadata: dict[str, dict[str, str]] = {}
    for spec in WINDOWS_SERVER_RULE_SPECS:
        metadata[spec["code"]] = {
            "search": spec["key"],
            "baseline": f'{spec["key"]} = {spec["expected"]}',
            "explanation": spec["explanation"],
            "powershell_check": spec["powershell_check"],
        }
    return metadata


def windows_server_audit_inf_paths() -> list[str]:
    """
    Get candidate paths for audit.inf.
    
    Returns paths in order of preference:
    1. Dynamic path from get_audit_inf_path() (TEMP environment variable)
    2. Hardcoded fallback paths if TEMP is unavailable
    """
    candidates: list[str] = []
    
    # Primary: dynamic path from the audit_generator module
    primary_path = get_audit_inf_path()
    candidates.append(str(primary_path))
    
    # Fallback: if the dynamic path didn't pick up TEMP for some reason,
    # try alternative locations
    fallback_paths = [
        r"C:\Windows\Temp\audit.inf",
        r"C:\Temp\audit.inf",
    ]
    
    # Only add fallbacks if they're different from the primary path
    primary_str = str(primary_path).lower()
    for fallback in fallback_paths:
        if fallback.lower() != primary_str:
            candidates.append(fallback)
    
    return candidates


def build_windows_server_checks() -> list:
    return [
        make_assignment_check(
            code=spec["code"],
            title=spec["title"],
            severity=spec["severity"],
            config_file_key="audit_inf",
            key=spec["key"],
            expected_value=spec["expected"],
            explanation=spec["explanation"],
        )
        for spec in WINDOWS_SERVER_RULE_SPECS
    ]


def build_windows_server_module() -> ModuleDefinition:
    return ModuleDefinition(
        module_id="windows-server-2022-security-policy",
        os_family="windows",
        os_version="windows-server-2022",
        service_type="windows-server",
        display_name="Windows Server 2022 - Security Policy Baseline",
        rules_source_file=WINDOWS_SERVER_RULES_FILE,
        config_paths={"audit_inf": windows_server_audit_inf_paths()},
        checks=build_windows_server_checks(),
        check_metadata=build_windows_server_check_metadata(),
    )