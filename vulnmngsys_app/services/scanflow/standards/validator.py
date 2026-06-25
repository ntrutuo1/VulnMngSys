from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REQUIRED_SCAN_KEYS = {
    "hash_id",
    "service",
    "id",
    "title",
    "check_type",
    "registry_path",
    "expected",
    "operator",
    "powershell_check",
    "remediation",
    "reason",
    "actual",
    "status",
    "source",
}
REQUIRED_REPORT_KEYS = {"passed", "failed", "manual", "items"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _ensure_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    return [payload]


def _validate_rule_item(item: dict[str, Any], idx: int, file_name: str) -> list[str]:
    issues: list[str] = []

    rule_id = str(item.get("id") or "").strip()
    if not rule_id:
        issues.append(f"{file_name}#{idx}: missing `id`")

    if not str(item.get("title") or "").strip():
        issues.append(f"{file_name}#{idx}: missing `title`")

    if not str(item.get("service") or "").strip():
        issues.append(f"{file_name}#{idx}: missing `service`")

    if not str(item.get("check_type") or "").strip():
        issues.append(f"{file_name}#{idx}: missing `check_type`")

    if not str(item.get("operator") or "").strip():
        issues.append(f"{file_name}#{idx}: missing `operator`")

    has_probe = any(str(item.get(key) or "").strip() for key in ("registry_path", "powershell_check"))
    if not has_probe:
        issues.append(f"{file_name}#{idx}: missing probe source (`registry_path` or `powershell_check`)")

    if "expected" not in item:
        issues.append(f"{file_name}#{idx}: missing `expected`")

    registry_path = str(item.get("registry_path") or "").strip()
    if (
        registry_path
        and ":" not in registry_path
        and not registry_path.lower().startswith(("computer configuration", "user configuration"))
    ):
        issues.append(f"{file_name}#{idx}: `registry_path` should be a registry or policy path")

    return issues


def validate_rule_files(rule_files: list[Path]) -> list[str]:
    issues: list[str] = []
    seen_ids: dict[str, Path] = {}

    for rule_file in rule_files:
        payload = _load_json(rule_file)
        items = _ensure_list(payload)
        for idx, row in enumerate(items, start=1):
            if not isinstance(row, dict):
                issues.append(f"{rule_file.name}#{idx}: item is not an object")
                continue

            issues.extend(_validate_rule_item(row, idx, rule_file.name))

            rule_id = str(row.get("id") or "").strip()
            if rule_id:
                prior = seen_ids.get(rule_id)
                if prior and prior != rule_file:
                    issues.append(f"Duplicate rule id `{rule_id}` between {prior.name} and {rule_file.name}")
                seen_ids[rule_id] = rule_file

    return issues


def validate_scan_rows_schema(temp_json_file: Path) -> list[str]:
    issues: list[str] = []
    payload = _load_json(temp_json_file)
    items = _ensure_list(payload)

    for idx, row in enumerate(items, start=1):
        if not isinstance(row, dict):
            issues.append(f"{temp_json_file.name}#{idx}: scan row is not an object")
            continue

        missing = sorted(REQUIRED_SCAN_KEYS - set(row.keys()))
        if missing:
            issues.append(f"{temp_json_file.name}#{idx}: missing output keys {', '.join(missing)}")

    return issues


def validate_report_schema(report_file: Path) -> list[str]:
    issues: list[str] = []
    payload = _load_json(report_file)

    if not isinstance(payload, dict):
        return [f"{report_file.name}: report root must be an object"]

    missing = sorted(REQUIRED_REPORT_KEYS - set(payload.keys()))
    if missing:
        issues.append(f"{report_file.name}: missing report keys {', '.join(missing)}")

    if "total" not in payload and "total_rules" not in payload:
        issues.append(f"{report_file.name}: missing `total` or `total_rules`")

    items = payload.get("items")
    if not isinstance(items, list):
        issues.append(f"{report_file.name}: `items` must be a list")
        return issues

    required_item_keys = {"title", "passed", "verdict", "expected", "actual", "status", "guidance"}
    for idx, row in enumerate(items, start=1):
        if not isinstance(row, dict):
            issues.append(f"{report_file.name}#items[{idx}]: must be an object")
            continue
        if not row.get("rule_id"):
            issues.append(f"{report_file.name}#items[{idx}]: missing `rule_id`")
        miss = sorted(required_item_keys - set(row.keys()))
        if miss:
            issues.append(f"{report_file.name}#items[{idx}]: missing keys {', '.join(miss)}")
        if not row.get("check_type"):
            issues.append(f"{report_file.name}#items[{idx}]: missing `check_type`")

    return issues
