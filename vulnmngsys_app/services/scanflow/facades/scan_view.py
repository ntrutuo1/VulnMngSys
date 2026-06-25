from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from vulnmngsys_app.services.scanflow.rule_metadata import cis_reference, short_reason
from vulnmngsys_app.services.scanflow.paths import project_root, writable_reports_dir
from vulnmngsys_app.services.scanflow.service_tree import group_rows_by_service
from vulnmngsys_app.services.scanflow.facades.scan_messages import (
    build_result_message as _build_result_message,
    build_scan_mode_prompt as _build_scan_mode_prompt,
)


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_status(status: str) -> str:
    return status.upper().strip()


def _first_value(row: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        value = row.get(key)
        if value:
            return value
    return default


def _rule_id(row: dict[str, Any]) -> str:
    return _coerce_text(_first_value(row, ("id", "RuleId", "ruleId", "RuleID", "rule_id")))


def _service(row: dict[str, Any]) -> str:
    return _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name"))


def _expected(row: dict[str, Any]) -> str:
    return _coerce_text(_first_value(row, ("expected", "Expected", "Recommended", "RecommendedValue", "recommended")))


def _actual(row: dict[str, Any]) -> str:
    return _coerce_text(row.get("actual") or row.get("Actual") or row.get("CurrentValue") or row.get("currentValue"))


class ScanView:
    _instance: ClassVar[ScanView | None] = None

    @classmethod
    def instance(cls) -> ScanView:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def flatten_rows(self, raw_payload: Any) -> list[dict[str, Any]]:
        rows = raw_payload if isinstance(raw_payload, list) else [raw_payload]
        flattened: list[dict[str, Any]] = []
        for item in rows:
            if isinstance(item, list):
                flattened.extend(nested for nested in item if isinstance(nested, dict))
            elif isinstance(item, dict):
                flattened.append(item)
        return flattened

    def normalize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        if "verdict" in row or "passed" in row:
            verdict = _normalize_status(_coerce_text(row.get("verdict") or ("PASS" if row.get("passed") else "FAIL")))
            raw_status = _coerce_text(row.get("status") or row.get("Status") or "")
            status = verdict if raw_status.casefold() in {"", "collected", "collected."} else raw_status
            passed = bool(row.get("passed")) if "passed" in row else verdict == "PASS"
        else:
            raw_status = _normalize_status(_coerce_text(_first_value(row, ("Status", "status", "Verdict", "verdict"))))
            passed = bool(row.get("passed")) if "passed" in row else raw_status == "PASS"
            verdict = "PASS" if passed else "FAIL"
            status = verdict if raw_status in {"", "COLLECTED", "COLLECTED."} else raw_status or verdict

        rule_id = _rule_id(row)
        check_type = _coerce_text(_first_value(row, ("check_type", "CheckType", "checkType", "type")))
        return {
            "hash_id": _coerce_text(row.get("hash_id") or row.get("hashId") or ""),
            "ruleId": rule_id,
            "rule_id": rule_id,
            "service": _service(row),
            "serviceName": _service(row),
            "service_name": _service(row),
            "service_id": row.get("service_id") or row.get("serviceId") or "",
            "title": _coerce_text(_first_value(row, ("title", "Title", "PolicyName", "policyName"))),
            "passed": passed,
            "verdict": _coerce_text(row.get("verdict") or verdict),
            "expected": _expected(row),
            "actual": _actual(row),
            "status": status or verdict,
            "registry_path": _coerce_text(row.get("registry_path") or row.get("registryPath") or ""),
            "operator": _coerce_text(row.get("operator") or ""),
            "checkType": check_type,
            "check_type": check_type,
            "source": _coerce_text(row.get("source") or row.get("Source")),
            "powershell_check": _coerce_text(row.get("powershell_check") or ""),
            "remediation": _coerce_text(row.get("remediation") or ""),
            "reason": short_reason(row.get("reason")),
            "cis_reference": _coerce_text(row.get("cis_reference") or cis_reference("", rule_id)),
            "guidance": list(
                row.get("guidance")
                or ([] if passed else ([f"Review rule {rule_id}"] if rule_id else []))
            ),
        }

    def build_report_payload(
        self,
        *,
        profile_key: str,
        full_scan: bool,
        merged_scan_file: Path,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        total = len(rows)
        passed = sum(1 for item in rows if item.get("verdict") == "PASS")
        failed = sum(1 for item in rows if item.get("verdict") == "FAIL")
        manual = sum(1 for item in rows if item.get("verdict") == "MANUAL")
        report_file = self.report_file()
        payload = {
            "status": "Secure" if failed == 0 and manual == 0 else "Vulnerable",
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
            "groups": self.group_by_service(rows, profile_key=profile_key),
        }
        report_file.parent.mkdir(parents=True, exist_ok=True)
        report_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return payload

    def normalize_report_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(payload)
        items = normalized.get("items")
        if isinstance(items, list):
            normalized["items"] = [self.normalize_row(item) for item in items if isinstance(item, dict)]
            normalized["groups"] = self.group_by_service(
                normalized["items"],
                profile_key=_coerce_text(normalized.get("profileKey") or normalized.get("profile_key")),
            )
        return normalized

    def group_by_service(self, rows: list[dict[str, Any]], *, profile_key: str | None = None) -> list[dict[str, Any]]:
        return group_rows_by_service(rows, profile_key=profile_key)

    def report_payload_to_summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": payload.get("status"),
            "total_rules": payload.get("total_rules", payload.get("total", 0)),
            "passed": payload.get("passed", 0),
            "failed": payload.get("failed", 0),
            "manual": payload.get("manual", 0),
            "reportFile": payload.get("reportFile"),
            "items": payload.get("items", []),
        }

    def report_file(self) -> Path:
        return writable_reports_dir(project_root()) / "scan_compare_report.json"

    def build_scan_mode_prompt(self, *, inventory: Any) -> str:
        return _build_scan_mode_prompt(inventory=inventory)

    def build_result_message(self, *, summary: Any, failed_ids: list[str] | None = None) -> str:
        return _build_result_message(summary=summary, failed_ids=failed_ids)


def get_scan_view() -> ScanView:
    return ScanView.instance()
