from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REQUIRED_SCAN_KEYS = {"RuleId", "Title", "CheckType", "Actual", "Status", "Source"}
REQUIRED_REPORT_KEYS = {"passed", "failed", "manual", "items"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _ensure_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    return [payload]


def _validate_rule_item(item: dict[str, Any], idx: int, file_name: str) -> list[str]:
    issues: list[str] = []

    rule_id = str(item.get("id") or item.get("code") or "").strip()
    if not rule_id:
        issues.append(f"{file_name}#{idx}: thiếu `id`/`code`")

    if not str(item.get("title") or "").strip():
        issues.append(f"{file_name}#{idx}: thiếu `title`")

    typed_probe = str(item.get("type") or "").strip() in {
        "secedit",
        "security_policy",
        "user_right",
        "registry",
        "registry-multi",
        "user_registry",
        "auditpol",
        "local_account",
    }
    has_probe = typed_probe or any(
        key in item
        for key in (
            "registry",
            "registry_keys",
            "auditpol",
            "auditpol_subcategory_guid",
            "powershell_check",
            "gp_path",
        )
    )
    if not has_probe:
        issues.append(f"{file_name}#{idx}: thiếu field probe (type/registry/auditpol/...)")

    registry_value = item.get("registry")
    if (
        "registry" in item
        and "registry_value" in item
        and isinstance(registry_value, str)
        and registry_value.count(":") != 1
    ):
        issues.append(f"{file_name}#{idx}: `registry` nên có định dạng PATH:ValueName khi dùng `registry_value`")

    has_expected = ("recommended" in item) or ("expected" in item) or ("registry_value" in item)
    if not has_expected:
        issues.append(f"{file_name}#{idx}: thiếu chuẩn kỳ vọng (`recommended`/`expected`/`registry_value`)")

    return issues


def validate_rule_files(rule_files: list[Path]) -> list[str]:
    issues: list[str] = []
    seen_ids: dict[str, Path] = {}

    for rule_file in rule_files:
        payload = _load_json(rule_file)
        items = _ensure_list(payload)
        for idx, row in enumerate(items, start=1):
            if not isinstance(row, dict):
                issues.append(f"{rule_file.name}#{idx}: phần tử không phải object")
                continue

            issues.extend(_validate_rule_item(row, idx, rule_file.name))

            rule_id = str(row.get("id") or row.get("code") or "").strip()
            if rule_id:
                prior = seen_ids.get(rule_id)
                if prior and prior != rule_file:
                    issues.append(
                        f"Trùng rule id/code `{rule_id}` giữa {prior.name} và {rule_file.name}"
                    )
                seen_ids[rule_id] = rule_file

    return issues


def validate_scan_rows_schema(temp_json_file: Path) -> list[str]:
    issues: list[str] = []
    payload = _load_json(temp_json_file)
    items = _ensure_list(payload)

    for idx, row in enumerate(items, start=1):
        if not isinstance(row, dict):
            issues.append(f"{temp_json_file.name}#{idx}: scan row không phải object")
            continue

        missing = sorted(REQUIRED_SCAN_KEYS - set(row.keys()))
        if missing:
            issues.append(f"{temp_json_file.name}#{idx}: thiếu key output {', '.join(missing)}")

    return issues


def validate_report_schema(report_file: Path) -> list[str]:
    issues: list[str] = []
    payload = _load_json(report_file)

    if not isinstance(payload, dict):
        return [f"{report_file.name}: report root phải là object"]

    missing = sorted(REQUIRED_REPORT_KEYS - set(payload.keys()))
    if missing:
        issues.append(f"{report_file.name}: thiếu key report {', '.join(missing)}")

    if "total" not in payload and "total_rules" not in payload:
        issues.append(f"{report_file.name}: thiếu `total` hoặc `total_rules`")

    items = payload.get("items")
    if not isinstance(items, list):
        issues.append(f"{report_file.name}: `items` phải là list")
        return issues

    required_item_keys = {"title", "passed", "verdict", "expected", "actual", "status", "guidance"}
    for idx, row in enumerate(items, start=1):
        if not isinstance(row, dict):
            issues.append(f"{report_file.name}#items[{idx}]: phải là object")
            continue
        if not (row.get("rule_id") or row.get("ruleId")):
            issues.append(f"{report_file.name}#items[{idx}]: thiếu rule_id/ruleId")
        miss = sorted(required_item_keys - set(row.keys()))
        if miss:
            issues.append(f"{report_file.name}#items[{idx}]: thiếu key {', '.join(miss)}")
        if not (row.get("check_type") or row.get("checkType")):
            issues.append(f"{report_file.name}#items[{idx}]: thiếu check_type/checkType")

    return issues
