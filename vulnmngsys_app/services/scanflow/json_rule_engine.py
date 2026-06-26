from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import winreg

from .constants import AUDITPOL_BITMASKS, AUDITPOL_TEXT_TO_MASK
from .guidance import build_guidance
from .models import ComparisonSummary, RuleComparisonResult
from .rule_metadata import cis_reference, short_reason
from .rule_catalog import get_full_rule_files, get_quick_rule_file
from .security import validate_powershell_check, verify_rule_file_integrity


def _rule_text(rule: dict[str, Any], *field_names: str) -> str:
    for field_name in field_names:
        value = rule.get(field_name)
        if value is None:
            continue
        text = _normalize_text(value)
        if text:
            return text
    return ""


def _rule_list(rule: dict[str, Any], *field_names: str) -> list[str]:
    for field_name in field_names:
        value = rule.get(field_name)
        if isinstance(value, list):
            return [_normalize_text(item) for item in value if _normalize_text(item)]
    return []


def _is_registry_spec(path_spec: str) -> bool:
    return ":" in path_spec and path_spec.upper().startswith(("HK", "HKEY_"))


def _sanitize_powershell_output(text: str) -> str:
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    lines = [line for line in lines if line]
    if not lines:
        return ""
    if len(lines) == 1:
        return lines[0]
    return "; ".join(lines)

SECURITY_POLICY_KEYS = {
    "1.1.1": "PasswordHistorySize",
    "1.1.2": "MaximumPasswordAge",
    "1.1.3": "MinimumPasswordAge",
    "1.1.4": "MinimumPasswordLength",
    "1.1.5": "PasswordComplexity",
    "1.1.7": "ClearTextPassword",
    "1.2.1": "LockoutDuration",
    "1.2.2": "LockoutBadCount",
    "1.2.3": "AllowAdministratorLockout",
    "1.2.4": "ResetLockoutCount",
}

LOCAL_USER_RULES = {"2.3.1.1", "2.3.1.3", "2.3.1.4"}

SERVICE_CATALOG_PATH = Path(__file__).resolve().parents[2] / "rules" / "service_catalog.json"


@dataclass(frozen=True, slots=True)
class ScanSnapshots:
    security_policy: dict[str, Any]
    user_rights: dict[str, list[str]]
    audit_policy: dict[str, str]
    local_users: list[dict[str, Any]]


def _normalize_service_name(value: Any) -> str:
    return _normalize_text(value).casefold()


def _load_service_catalog(profile_key: str) -> list[dict[str, Any]]:
    if not SERVICE_CATALOG_PATH.exists():
        return []

    payload = json.loads(SERVICE_CATALOG_PATH.read_text(encoding="utf-8-sig"))
    if isinstance(payload, dict):
        profiles = payload.get("profiles")
        if isinstance(profiles, dict):
            entries = profiles.get(profile_key) or profiles.get("default") or []
        else:
            entries = payload.get("services") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []

    return [item for item in entries if isinstance(item, dict)]


def _rule_field_text(rule: dict[str, Any], field_name: str) -> str:
    aliases = {
        "service_name": ("service", "service_name"),
        "service": ("service", "service_name"),
        "registry": ("registry_path", "registry"),
        "registry_path": ("registry_path", "registry", "gp_path"),
        "gp_path": ("registry_path", "gp_path"),
        "check_type": ("check_type", "checkType", "type"),
        "type": ("check_type", "type", "checkType"),
        "remediation": ("remediation",),
        "powershell_check": ("powershell_check",),
        "title": ("title",),
        "reason": ("reason",),
    }
    lookup_fields = aliases.get(field_name, (field_name,))
    return _rule_text(rule, *lookup_fields)


def _matcher_matches(rule: dict[str, Any], matcher: dict[str, Any]) -> bool:
    field_name = _normalize_text(matcher.get("field"))
    if not field_name:
        return False

    haystack = _rule_field_text(rule, field_name)
    if not haystack:
        return False

    haystack_lower = haystack.casefold()

    contains = matcher.get("contains")
    if contains is not None:
        if _normalize_text(contains).casefold() not in haystack_lower:
            return False

    contains_any = matcher.get("contains_any")
    if isinstance(contains_any, list) and contains_any:
        needles = [_normalize_text(item).casefold() for item in contains_any if _normalize_text(item)]
        if not any(needle in haystack_lower for needle in needles):
            return False

    equals = matcher.get("equals")
    if equals is not None and haystack_lower != _normalize_text(equals).casefold():
        return False

    regex = matcher.get("regex")
    if regex is not None and not re.search(_normalize_text(regex), haystack, flags=re.IGNORECASE):
        return False

    return True


def _classify_rule_service(rule: dict[str, Any], service_catalog: list[dict[str, Any]]) -> str:
    rule_id = _normalize_text(rule.get("id"))

    for entry in service_catalog:
        service_name = _normalize_text(entry.get("service") or entry.get("service_name") or entry.get("name"))
        if not service_name:
            continue

        rule_ids = entry.get("rule_ids")
        if rule_id and isinstance(rule_ids, list):
            normalized_rule_ids = {_normalize_text(item) for item in rule_ids if _normalize_text(item)}
            if rule_id in normalized_rule_ids:
                return service_name

        match_any = entry.get("match_any")
        if isinstance(match_any, list) and match_any and any(_matcher_matches(rule, matcher) for matcher in match_any if isinstance(matcher, dict)):
            return service_name

        aliases = entry.get("aliases")
        if isinstance(aliases, list) and aliases:
            normalized_aliases = [_normalize_text(item) for item in aliases if _normalize_text(item)]
            for field_name in ("title", "remediation", "registry_path", "powershell_check", "reason"):
                haystack = _rule_field_text(rule, field_name).casefold()
                if haystack and any(alias.casefold() in haystack for alias in normalized_aliases):
                    return service_name

        match_all = entry.get("match_all")
        if isinstance(match_all, list) and match_all and all(_matcher_matches(rule, matcher) for matcher in match_all if isinstance(matcher, dict)):
            return service_name

    return ""


def _prepare_rules_for_scan(
    rules: list[dict[str, Any]],
    *,
    profile_key: str,
) -> list[dict[str, Any]]:
    service_catalog = _load_service_catalog(profile_key)
    if not service_catalog:
        return rules

    prepared: list[dict[str, Any]] = []
    for rule in rules:
        service_name = _classify_rule_service(rule, service_catalog)
        if service_name:
            enriched_rule = dict(rule)
            enriched_rule["service"] = service_name
            prepared.append(enriched_rule)
        else:
            prepared.append(rule)

    return prepared


def _load_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    return get_full_rule_files(profile_key) if full_scan else [get_quick_rule_file(profile_key)]


def _load_json_rules(rule_files: list[Path]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule_file in rule_files:
        raw = json.loads(rule_file.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, list):
            raise ValueError(f"Rule file must contain a JSON list: {rule_file}")
        for item in raw:
            if isinstance(item, dict):
                rules.append(item)
    return rules


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _to_number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, set)):
        return [_normalize_text(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_text(item) for item in value]
    text = _normalize_text(value)
    if not text:
        return []
    if "," in text:
        return [item.strip() for item in text.split(",")]
    return [text]


def _principal_set(value: Any) -> set[str]:
    return {item.strip().lstrip("*").casefold() for item in _to_list(value) if item.strip().lstrip("*")}


def _is_allowed_principal_subset(expected: Any, actual: Any) -> bool:
    expected_set = _principal_set(expected)
    actual_set = _principal_set(actual)
    if not expected_set:
        return not actual_set
    return bool(actual_set) and actual_set.issubset(expected_set)


def _display_value(value: Any) -> str:
    if value is None:
        return "Not Defined / Empty"
    if isinstance(value, (list, tuple)):
        return ", ".join(_normalize_text(item) for item in value if _normalize_text(item) or item == "")
    text = _normalize_text(value)
    return text if text else "Not Defined / Empty"


def _extract_expected_display(rule: dict[str, Any]) -> str:
    expected = rule.get("expected")
    if isinstance(expected, list):
        return ", ".join(_normalize_text(item) for item in expected)
    return _normalize_text(expected)


def _is_empty_expected(rule: dict[str, Any]) -> bool:
    expected = rule.get("expected")
    if expected is None:
        return False
    if isinstance(expected, str):
        return not expected.strip()
    if isinstance(expected, list):
        return not any(_normalize_text(item) for item in expected)
    return False


def _missing_value_passes(rule: dict[str, Any]) -> bool:
    operator = _normalize_text(rule.get("operator")).casefold()
    equality_ops = {"", "==", "exactmatch", "exactmatch_array"}
    return _is_empty_expected(rule) and operator in equality_ops


def _run_powershell(command: str) -> str:
    # Normalize escaped command text before execution. Rule JSON often stores
    # PowerShell snippets with escaped quotes (\") and Windows paths that need
    # to be passed to powershell.exe as real PowerShell syntax.
    try:
        command = command.replace('\\"', '"')
        command = command.replace("-Path '$env:TEMP\\secpol.inf'", "-Path \"$env:TEMP\\secpol.inf\"")
    except Exception:
        pass

    validate_powershell_check(command)

    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or f"PowerShell command failed: {command}")
    return (completed.stdout or "").strip()


def _export_secedit(area: str) -> Path:
    tmp_dir = Path(tempfile.gettempdir())
    tmp_file = tmp_dir / f"vulnmngsys_{area.lower()}_{os.getpid()}.cfg"
    if tmp_file.exists():
        tmp_file.unlink()
    completed = subprocess.run(
        ["secedit", "/export", "/cfg", str(tmp_file), "/areas", area],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not tmp_file.exists():
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or f"Failed to export secedit area: {area}")
    return tmp_file


def _parse_secedit_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-16", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _parse_user_rights_file(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-16", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        entries = [item.strip() for item in value.split(",")]
        values[key.strip()] = [entry for entry in entries if entry]
    return values


def _auditpol_mask(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        numeric = int(value)
        return AUDITPOL_BITMASKS.get(numeric, numeric if numeric >= 0 else None)

    text = _normalize_text(value).lower()
    if not text:
        return None
    if text in AUDITPOL_TEXT_TO_MASK:
        return AUDITPOL_TEXT_TO_MASK[text]
    if text.isdigit():
        numeric = int(text)
        return AUDITPOL_BITMASKS.get(numeric, numeric if numeric >= 0 else None)
    return None


def _collect_auditpol_snapshot() -> dict[str, str]:
    completed = subprocess.run(
        ["auditpol", "/get", "/category:*", "/r"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or "Failed to collect audit policy snapshot")

    snapshot: dict[str, str] = {}
    for raw_line in (completed.stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            continue
        guid = parts[3].upper()
        if re.fullmatch(r"\{[0-9A-F\-]+\}", guid):
            snapshot[guid] = parts[4]
    return snapshot


def _collect_local_users() -> list[dict[str, Any]]:
    command = "Get-LocalUser | Select-Object @{Name='SID';Expression={$_.SID.Value}},Name,Enabled | ConvertTo-Json -Depth 3"
    raw = _run_powershell(command)
    if not raw:
        return []

    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def _load_snapshots() -> ScanSnapshots:
    security_tmp = _export_secedit("SECURITYPOLICY")
    user_rights_tmp = _export_secedit("USER_RIGHTS")

    try:
        security_policy = _parse_secedit_file(security_tmp)
        user_rights = _parse_user_rights_file(user_rights_tmp)
    finally:
        security_tmp.unlink(missing_ok=True)
        user_rights_tmp.unlink(missing_ok=True)

    try:
        audit_policy = _collect_auditpol_snapshot()
    except Exception:
        audit_policy = {}

    try:
        local_users = _collect_local_users()
    except Exception:
        local_users = []

    return ScanSnapshots(
        security_policy=security_policy,
        user_rights=user_rights,
        audit_policy=audit_policy,
        local_users=local_users,
    )


def _get_registry_root(hive_name: str):
    hive = hive_name.upper().strip()
    if hive in {"HKLM", "HKEY_LOCAL_MACHINE"}:
        return winreg.HKEY_LOCAL_MACHINE
    if hive in {"HKCU", "HKEY_CURRENT_USER"}:
        return winreg.HKEY_CURRENT_USER
    if hive in {"HKU", "HKEY_USERS"}:
        return winreg.HKEY_USERS
    raise ValueError(f"Unsupported registry hive: {hive_name}")


def _read_registry_value(path_spec: str) -> tuple[Any, str]:
    if ":" not in path_spec:
        raise ValueError(f"Invalid registry specification: {path_spec}")

    path_part, value_name = path_spec.split(":", 1)
    segments = [segment for segment in path_part.split("\\") if segment]
    if not segments:
        raise ValueError(f"Invalid registry specification: {path_spec}")

    hive_name = segments[0]
    subkey = "\\".join(segments[1:])
    root = _get_registry_root(hive_name)

    with winreg.OpenKey(root, subkey) as handle:
        value, _ = winreg.QueryValueEx(handle, value_name)
    return value, _display_value(value)


def _enumerate_user_sids() -> list[str]:
    sids: list[str] = []
    with winreg.OpenKey(winreg.HKEY_USERS, "") as root:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            if re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", name):
                sids.append(name)
    return sids


def _read_user_registry_value(path_spec: str) -> tuple[Any, str, list[str]]:
    if ":" not in path_spec:
        raise ValueError(f"Invalid user registry specification: {path_spec}")

    path_part, value_name = path_spec.split(":", 1)
    user_sids = _enumerate_user_sids()
    if not user_sids:
        raise LookupError("No loaded user hives found")

    sub_path = path_part.replace("HKU\\[USER SID]\\", "", 1)
    collected: list[str] = []
    missing: list[str] = []

    for sid in user_sids:
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, f"{sid}\\{sub_path}") as handle:
                value, _ = winreg.QueryValueEx(handle, value_name)
            if isinstance(value, (list, tuple)):
                normalized = ", ".join(_normalize_text(item) for item in value)
            else:
                normalized = _display_value(value)
            collected.append(f"{sid}: {normalized}")
        except OSError:
            missing.append(sid)

    if missing and not collected:
        raise LookupError(f"User hive value not found for loaded SID(s): {', '.join(missing)}")

    return collected, "; ".join(collected) if collected else "Not Defined / Empty", missing


def _normalize_expected_numeric(rule: dict[str, Any]) -> float | None:
    expected = rule.get("expected")
    if isinstance(expected, list) and expected:
        expected = expected[0]
    return _to_number(expected)


def _compare_numeric(rule: dict[str, Any], actual: Any) -> tuple[bool, str]:
    expected = rule.get("expected")
    actual_number = _to_number(actual)
    if actual_number is None:
        return False, _display_value(actual)

    operator = str(rule.get("operator") or "").strip()
    if operator == ">=":
        threshold = _normalize_expected_numeric(rule)
        return (threshold is not None and actual_number >= threshold), _display_value(actual)
    if operator == "<=":
        threshold = _normalize_expected_numeric(rule)
        return (threshold is not None and actual_number <= threshold), _display_value(actual)
    if operator == "<=_not_0":
        threshold = _normalize_expected_numeric(rule)
        return (threshold is not None and 0 < actual_number <= threshold), _display_value(actual)
    if operator == "Between" and isinstance(expected, list) and len(expected) >= 2:
        lower = _to_number(expected[0])
        upper = _to_number(expected[1])
        return (lower is not None and upper is not None and lower <= actual_number <= upper), _display_value(actual)
    if operator == "InList" and isinstance(expected, list):
        allowed = {str(item).strip() for item in expected}
        return (str(actual).strip() in allowed), _display_value(actual)
    if operator == "==":
        if isinstance(expected, list):
            allowed = {_to_number(item) for item in expected}
            return (actual_number in allowed), _display_value(actual)
        return (actual_number == _to_number(expected)), _display_value(actual)
    return (actual_number == _to_number(expected)), _display_value(actual)


def _compare_string(rule: dict[str, Any], actual: Any) -> tuple[bool, str]:
    expected = rule.get("expected")
    operator = str(rule.get("operator") or "").strip()
    actual_text = _normalize_text(actual)
    expected_text = _normalize_text(expected)

    if "expected_sids" in rule and isinstance(rule.get("expected_sids"), list):
        expected_sids = _principal_set(rule.get("expected_sids"))
        actual_sids = _principal_set(actual)
        return _is_allowed_principal_subset(expected_sids, actual_sids), ", ".join(sorted(actual_sids)) or "No One"

    if operator in {"NotEqual", "!="}:
        return (actual_text.lower() != expected_text.lower()), actual_text
    if operator == "RegexMatch":
        return bool(re.search(expected_text, actual_text, flags=re.IGNORECASE)), actual_text
    if operator == "Contains":
        expected_mask = _auditpol_mask(expected)
        actual_mask = _auditpol_mask(actual)
        if expected_mask is not None and actual_mask is not None:
            return ((actual_mask & expected_mask) == expected_mask), actual_text
        if isinstance(expected, list):
            expected_set = _principal_set(expected)
            actual_set = _principal_set(actual)
            return expected_set.issubset(actual_set), ", ".join(sorted(actual_set)) or "No One"
        if expected_text:
            return expected_text.lower() in actual_text.lower(), actual_text
        return bool(actual_text), actual_text
    if operator == "InList":
        if isinstance(expected, list):
            allowed = {str(item).strip().lower() for item in expected}
            return actual_text.lower() in allowed, actual_text
        return actual_text.lower() == expected_text.lower(), actual_text
    if operator == "Subset":
        actual_set = _principal_set(actual)
        return _is_allowed_principal_subset(expected, actual), ", ".join(sorted(actual_set))
    if operator == "ExactMatch_Array":
        actual_set = _principal_set(actual)
        return _is_allowed_principal_subset(expected, actual), ", ".join(sorted(actual_set))
    if operator == "ExactMatch_Array_With_Exceptions":
        expected_list = {str(item).strip() for item in expected or []}
        actual_list = {str(item).strip() for item in _to_list(actual)}
        allowed_extras = {"CertSvc", "WINS"}
        extra_items = actual_list - expected_list
        return extra_items.issubset(allowed_extras), ", ".join(sorted(actual_list))
    if operator == "ExactMatch":
        if isinstance(expected, list):
            expected_set = _principal_set(expected)
            actual_set = _principal_set(actual)
            if not expected_set:
                return not actual_set, ", ".join(sorted(actual_set)) or "No One"
            return _is_allowed_principal_subset(expected, actual), ", ".join(sorted(actual_set)) or "No One"
        if expected_text.lower() in {"enabled", "disabled"} and actual_text.strip() in {"0", "1", "True", "False", "true", "false"}:
            target = "1" if expected_text.lower() == "enabled" else "0"
            if actual_text.strip().lower() in {"true", "false"}:
                return actual_text.strip().lower() == (target == "1"), actual_text
            return actual_text.strip() == target, actual_text
        return actual_text.lower() == expected_text.lower(), actual_text

    return (actual_text.lower() == expected_text.lower()), actual_text


def _compare_rule(rule: dict[str, Any], snapshots: ScanSnapshots) -> RuleComparisonResult:
    rule_id = _normalize_text(rule.get("id"))
    title = _normalize_text(rule.get("title"))
    operator = _normalize_text(rule.get("operator"))
    service_name = _normalize_text(rule.get("service") or rule.get("service_name"))
    source = ""
    check_type = "manual"
    actual_value: Any = None
    passed = False
    verdict = "MANUAL"
    status = "NoDirectProbe"

    powershell_check = _normalize_text(rule.get("powershell_check"))
    registry_spec = _normalize_text(rule.get("registry_path") or rule.get("registry") or rule.get("gp_path"))

    try:
        if registry_spec:
            source = registry_spec
            if "[USER SID]" in registry_spec:
                check_type = "user_registry"
                actual_value, actual_text, missing = _read_user_registry_value(registry_spec)
                if missing:
                    passed = False
                    status = "Collected"
                    verdict = "FAIL"
                    actual_text = f"Missing on SID(s): {', '.join(missing)}"
                    expected_display = _extract_expected_display(rule)
                    guidance = build_guidance(rule, source=registry_spec, expected=expected_display)
                    return RuleComparisonResult(
                        rule_id=rule_id,
                        title=title,
                        service_name=service_name,
                        passed=passed,
                        verdict=verdict,
                        expected=expected_display,
                        actual=actual_text,
                        status=status,
                        check_type=check_type,
                        source=source,
                        guidance=guidance,
                    )
                if operator in {">=", "<=", "<=_not_0", "Between", "InList"}:
                    passed, actual_text = _compare_numeric(rule, actual_value)
                else:
                    passed, actual_text = _compare_string(rule, actual_value)
                status = "Collected"
                verdict = "PASS" if passed else "FAIL"
                return RuleComparisonResult(
                    rule_id=rule_id,
                    title=title,
                    service_name=service_name,
                    passed=passed,
                    verdict=verdict,
                    expected=_extract_expected_display(rule),
                    actual=actual_text,
                    status=status,
                    check_type=check_type,
                    source=source,
                    guidance=[] if passed else build_guidance(rule, source=source, expected=_extract_expected_display(rule)),
                )

            check_type = "registry"
            actual_value, actual_text = _read_registry_value(registry_spec)
            if operator in {">=", "<=", "<=_not_0", "Between", "InList"}:
                passed, actual_text = _compare_numeric(rule, actual_value)
            else:
                passed, actual_text = _compare_string(rule, actual_value)
            status = "Collected"
            verdict = "PASS" if passed else "FAIL"
        elif rule_id in SECURITY_POLICY_KEYS:
            check_type = "secedit"
            source = "secedit /export SECURITYPOLICY"
            if powershell_check:
                check_type = "powershell"
                source = powershell_check
                actual_text = _run_powershell(powershell_check)
                if operator in {">=", "<=", "<=_not_0", "Between", "InList"}:
                    passed, actual_text = _compare_numeric(rule, actual_text)
                else:
                    passed, actual_text = _compare_string(rule, actual_text)
                status = "Collected"
                verdict = "PASS" if passed else "FAIL"
            else:
                actual_value = snapshots.security_policy.get(SECURITY_POLICY_KEYS[rule_id])
                if actual_value is None:
                    status = "NoDirectProbe"
                    verdict = "MANUAL"
                    actual_text = "Not Defined / Empty"
                else:
                    if operator in {">=", "<=", "<=_not_0", "Between", "InList"}:
                        passed, actual_text = _compare_numeric(rule, actual_value)
                    else:
                        passed, actual_text = _compare_string(rule, actual_value)
                    status = "Collected"
                    verdict = "PASS" if passed else "FAIL"
        elif rule_id in LOCAL_USER_RULES:
            check_type = "local_account"
            source = "Get-LocalUser"
            users = snapshots.local_users
            sid_suffix = "500" if rule_id == "2.3.1.3" else "501"
            matching = [user for user in users if _normalize_text(user.get("SID")).endswith(f"-{sid_suffix}")]
            if not matching:
                status = "NoDirectProbe"
                verdict = "MANUAL"
                actual_text = "No local user with expected SID was found"
            else:
                user = matching[0]
                if rule_id == "2.3.1.1":
                    actual_value = user.get("Enabled")
                    expected_value = str(rule.get("expected")).strip().lower()
                    actual_text = str(bool(actual_value))
                    passed = actual_text.lower() == expected_value
                else:
                    actual_value = user.get("Name")
                    actual_text = _normalize_text(actual_value)
                    passed, actual_text = _compare_string(rule, actual_value)
                status = "Collected"
                verdict = "PASS" if passed else "FAIL"
        elif powershell_check:
            if "auditpol /get" in powershell_check.lower():
                check_type = "auditpol"
                source = powershell_check
                guid_match = re.search(r"\{[0-9a-fA-F\-]+\}", powershell_check)
                guid = guid_match.group(0).upper() if guid_match else ""
                actual_value = snapshots.audit_policy.get(guid)
                if actual_value is None:
                    status = "NoDirectProbe"
                    verdict = "MANUAL"
                    actual_text = "Not Defined / No Auditing"
                else:
                    passed, actual_text = _compare_string(rule, actual_value)
                    status = "Collected"
                    verdict = "PASS" if passed else "FAIL"
            elif "secpol.inf" in powershell_check.lower():
                rule_check_type = _normalize_text(rule.get("check_type")).casefold()
                is_security_options = rule_check_type in {"securityoptions", "security_option", "security option"}
                area = "SECURITYPOLICY" if is_security_options else "USER_RIGHTS"
                source = f"secedit /export {area}"
                check_type = "security_option" if is_security_options else "user_right"
                key_match = re.search(r"\^([A-Za-z0-9_]+)", powershell_check)
                key_name = key_match.group(1) if key_match else ""
                try:
                    secedit_values = snapshots.security_policy if is_security_options else snapshots.user_rights
                    actual_value = secedit_values.get(key_name, [] if not is_security_options else "")
                    passed, actual_text = _compare_string(rule, actual_value)
                    status = "Collected"
                    verdict = "PASS" if passed else "FAIL"
                except Exception as exc:
                    status = "MANUAL"
                    verdict = "MANUAL"
                    actual_text = str(exc)
            else:
                check_type = "powershell"
                source = powershell_check
                actual_text = _run_powershell(powershell_check)
                if operator in {">=", "<=", "<=_not_0", "Between", "InList"}:
                    passed, actual_text = _compare_numeric(rule, actual_text)
                else:
                    passed, actual_text = _compare_string(rule, actual_text)
                status = "Collected"
                verdict = "PASS" if passed else "FAIL"
        else:
            status = "NoDirectProbe"
            verdict = "MANUAL"
            actual_text = "N/A (manual check)"
            source = registry_spec
    except LookupError as exc:
        status = "MANUAL"
        verdict = "MANUAL"
        actual_text = str(exc)
        source = registry_spec or powershell_check or source
    except OSError as exc:
        status = "Collected" if getattr(exc, "winerror", None) == 2 else "MANUAL"
        passed = status == "Collected" and _missing_value_passes(rule)
        verdict = "PASS" if passed else "FAIL" if status == "Collected" else "MANUAL"
        actual_text = "Not Defined / Empty" if status == "Collected" else str(exc)
        source = registry_spec or powershell_check or source
    except Exception as exc:
        status = "ProbeError"
        verdict = "MANUAL"
        actual_text = str(exc)
        source = registry_spec or powershell_check or source

    expected_display = _extract_expected_display(rule)
    guidance = [] if verdict == "PASS" else build_guidance(rule, source=source, expected=expected_display)

    return RuleComparisonResult(
        rule_id=rule_id,
        title=title,
        service_name=service_name,
        passed=passed,
        verdict=verdict,
        expected=expected_display,
        actual=_display_value(actual_text),
        status=status,
        check_type=check_type,
        source=source,
        guidance=guidance,
    )


def scan_profile(
    profile_key: str,
    full_scan: bool,
) -> tuple[list[RuleComparisonResult], list[Path]]:
    rule_files = _load_rule_files(profile_key, full_scan)
    return scan_rule_files(
        rule_files,
        profile_key=profile_key,
    ), rule_files


def scan_rule_files(
    rule_files: list[Path],
    *,
    profile_key: str,
) -> list[RuleComparisonResult]:
    verify_rule_file_integrity(rule_files)
    rules = _load_json_rules(rule_files)
    rules = _prepare_rules_for_scan(
        rules,
        profile_key=profile_key,
    )
    if not rules:
        return []
    snapshots = _load_snapshots()
    return [_compare_rule(rule, snapshots) for rule in rules]


def write_merged_scan_from_files(
    rule_files: list[Path],
    output_dir: Path,
    *,
    profile_key: str,
) -> Path:
    verify_rule_file_integrity(rule_files)
    rules = _load_json_rules(rule_files)
    rules = _prepare_rules_for_scan(
        rules,
        profile_key=profile_key,
    )
    snapshots = _load_snapshots()
    results = [_compare_rule(rule, snapshots) for rule in rules]

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "scan_results_merged.json"
    payload = []
    for rule, item in zip(rules, results, strict=False):
        payload.append(
            {
                "hash_id": str(rule.get("hash_id") or ""),
                "service": str(rule.get("service") or item.service_name),
                "id": str(rule.get("id") or item.rule_id),
                "title": str(rule.get("title") or item.title),
                "check_type": str(rule.get("check_type") or item.check_type),
                "registry_path": str(rule.get("registry_path") or ""),
                "expected": rule.get("expected"),
                "operator": str(rule.get("operator") or ""),
                "powershell_check": str(rule.get("powershell_check") or ""),
                "remediation": str(rule.get("remediation") or ""),
                "reason": short_reason(rule.get("reason")),
                "cis_reference": cis_reference(profile_key, rule.get("id")),
                "actual": item.actual,
                "status": item.status,
                "source": item.source,
                "passed": item.passed,
                "verdict": item.verdict,
                "guidance": item.guidance,
            }
        )

    merged_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")
    return merged_path


def write_merged_scan(
    profile_key: str,
    full_scan: bool,
    output_dir: Path,
) -> Path:
    rule_files = _load_rule_files(profile_key, full_scan)
    return write_merged_scan_from_files(
        rule_files,
        output_dir,
        profile_key=profile_key,
    )


def build_summary(profile_key: str, full_scan: bool, report_file: Path) -> ComparisonSummary:
    results, _ = scan_profile(profile_key, full_scan)
    total = len(results)
    passed = sum(1 for item in results if item.verdict == "PASS")
    failed = sum(1 for item in results if item.verdict == "FAIL")
    manual = sum(1 for item in results if item.verdict == "MANUAL")
    return ComparisonSummary(
        total=total,
        passed=passed,
        failed=failed,
        manual=manual,
        items=results,
        report_file=report_file,
    )
