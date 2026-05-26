from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app_bootstrap.scanflow.inventory import load_windows_inventory
from app_bootstrap.scanflow.scanner import run_scan_for_profile


SCAN_FEATURE_MESSAGE = "The new scan flow uses the internal JSON rule engine."


def get_resource_path(relative_path: str) -> Path:
    """Resolve a bundled resource path for dev and PyInstaller builds."""
    base_path = Path(__file__).resolve().parents[1]
    return base_path / relative_path


def _default_profile_key() -> str:
    try:
        inventory = load_windows_inventory()
        if inventory.profile_key:
            return inventory.profile_key
    except Exception:
        pass
    return "Windows_Server_2022"


def _app_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _report_file() -> Path:
    return _app_root() / "reports" / "scan_compare_report.json"


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_status(status: str) -> str:
    return status.upper().strip()


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    if "verdict" in row or "passed" in row:
        verdict = _normalize_status(_coerce_text(row.get("verdict") or ("PASS" if row.get("passed") else "FAIL")))
        status = _coerce_text(row.get("status") or row.get("Status") or verdict)
        return {
            "hash_id": _coerce_text(row.get("hash_id") or row.get("hashId") or ""),
            "ruleId": _coerce_text(row.get("id") or row.get("RuleId") or row.get("ruleId") or row.get("RuleID") or row.get("rule_id")),
            "rule_id": _coerce_text(row.get("id") or row.get("RuleId") or row.get("ruleId") or row.get("RuleID") or row.get("rule_id")),
            "service": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
            "title": _coerce_text(row.get("title") or row.get("Title") or row.get("PolicyName") or row.get("policyName")),
            "serviceName": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
            "service_name": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
            "passed": bool(row.get("passed")),
            "verdict": _coerce_text(row.get("verdict") or verdict),
            "expected": _coerce_text(row.get("expected") or row.get("Expected") or row.get("Recommended") or row.get("RecommendedValue") or row.get("recommended")),
            "actual": _coerce_text(row.get("actual") or row.get("Actual") or row.get("CurrentValue") or row.get("currentValue")),
            "status": status or verdict,
            "registry_path": _coerce_text(row.get("registry_path") or row.get("registryPath") or ""),
            "operator": _coerce_text(row.get("operator") or ""),
            "checkType": _coerce_text(row.get("check_type") or row.get("CheckType") or row.get("checkType")),
            "check_type": _coerce_text(row.get("check_type") or row.get("CheckType") or row.get("checkType")),
            "source": _coerce_text(row.get("source") or row.get("Source")),
            "powershell_check": _coerce_text(row.get("powershell_check") or ""),
            "remediation": _coerce_text(row.get("remediation") or ""),
            "reason": _coerce_text(row.get("reason") or ""),
            "guidance": list(row.get("guidance") or []),
        }

    rule_id = _coerce_text(
        row.get("id")
        or row.get("RuleId")
        or row.get("ruleId")
        or row.get("RuleID")
        or row.get("rule_id")
    )
    title = _coerce_text(row.get("title") or row.get("Title") or row.get("PolicyName") or row.get("policyName"))
    expected = _coerce_text(
        row.get("expected")
        or row.get("Expected")
        or row.get("Recommended")
        or row.get("RecommendedValue")
        or row.get("recommended")
    )
    actual = _coerce_text(row.get("actual") or row.get("Actual") or row.get("CurrentValue") or row.get("currentValue"))
    status = _normalize_status(
        _coerce_text(row.get("Status") or row.get("status") or row.get("Verdict") or row.get("verdict"))
    )
    check_type = _coerce_text(row.get("check_type") or row.get("CheckType") or row.get("checkType"))
    source = _coerce_text(row.get("source") or row.get("Source"))

    passed = status == "PASS"
    verdict = "PASS" if passed else "FAIL"

    return {
        "hash_id": _coerce_text(row.get("hash_id") or row.get("hashId") or ""),
        "ruleId": rule_id,
        "rule_id": rule_id,
        "service": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
        "title": title,
        "serviceName": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
        "service_name": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
        "passed": passed,
        "verdict": verdict,
        "expected": expected,
        "actual": actual,
        "status": status or verdict,
        "registry_path": _coerce_text(row.get("registry_path") or row.get("registryPath") or ""),
        "operator": _coerce_text(row.get("operator") or ""),
        "checkType": check_type,
        "check_type": check_type,
        "source": source,
        "powershell_check": _coerce_text(row.get("powershell_check") or ""),
        "remediation": _coerce_text(row.get("remediation") or ""),
        "reason": _coerce_text(row.get("reason") or ""),
        "guidance": [] if passed else ([f"Review rule {rule_id}"] if rule_id else []),
    }


def _flatten_scan_rows(raw_payload: Any) -> list[dict[str, Any]]:
    if isinstance(raw_payload, list):
        rows = raw_payload
    else:
        rows = [raw_payload]

    flattened: list[dict[str, Any]] = []
    for item in rows:
        if isinstance(item, list):
            for nested in item:
                if isinstance(nested, dict):
                    flattened.append(nested)
        elif isinstance(item, dict):
            flattened.append(item)
    return flattened


def _build_report_payload(*, profile_key: str, full_scan: bool, merged_scan_file: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    passed = sum(1 for item in rows if item.get("verdict") == "PASS")
    failed = sum(1 for item in rows if item.get("verdict") == "FAIL")
    manual = sum(1 for item in rows if item.get("verdict") == "MANUAL")
    status = "Secure" if failed == 0 and manual == 0 else "Vulnerable"
    report_file = _report_file()

    payload = {
        "status": status,
        "profileKey": profile_key,
        "fullScan": full_scan,
        "total_rules": total,
        "total": total,
        "passed": passed,
        "failed": failed,
        "manual": manual,
        "reportFile": str(report_file),
        "mergedScanFile": str(merged_scan_file),
        "items": rows,
    }

    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def run_profile_scan(
    *,
    profile_key: str | None = None,
    full_scan: bool = False,
    selected_service_names: set[str] | None = None,
) -> dict[str, Any]:
    selected_profile = profile_key or _default_profile_key()
    try:
        inventory = load_windows_inventory()
    except Exception:
        inventory = None

    normalized_selected_services = {
        str(name).strip()
        for name in (selected_service_names or set())
        if str(name).strip()
    }

    merged_scan_file = run_scan_for_profile(
        profile_key=selected_profile,
        full_scan=full_scan,
        inventory=inventory,
        selected_service_names=normalized_selected_services or None,
    )

    raw_payload = json.loads(merged_scan_file.read_text(encoding="utf-8-sig"))
    normalized_rows = [_normalize_row(row) for row in _flatten_scan_rows(raw_payload)]
    report_payload = _build_report_payload(
        profile_key=selected_profile,
        full_scan=full_scan,
        merged_scan_file=merged_scan_file,
        rows=normalized_rows,
    )
    return {"ok": True, **report_payload, "selectedServices": sorted(normalized_selected_services)}


def run_scan_and_save_report(
    *,
    profile_key: str | None = None,
    mode: str = "quick",
    selected_service_names: set[str] | None = None,
) -> dict[str, Any]:
    return run_profile_scan(profile_key=profile_key, full_scan=mode == "full", selected_service_names=selected_service_names)


def load_report_file(report_file: Path | None = None) -> dict[str, Any]:
    path = report_file or _report_file()
    if not path.exists():
        raise FileNotFoundError(SCAN_FEATURE_MESSAGE)
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(payload, dict):
        payload.setdefault("ok", True)
    return payload
