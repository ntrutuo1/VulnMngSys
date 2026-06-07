from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_status(status: str) -> str:
    return status.upper().strip()


class ScanView:
    _instance: ClassVar[ScanView | None] = None

    @classmethod
    def instance(cls) -> ScanView:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def flatten_rows(self, raw_payload: Any) -> list[dict[str, Any]]:
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

    def normalize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        if "verdict" in row or "passed" in row:
            verdict = _normalize_status(_coerce_text(row.get("verdict") or ("PASS" if row.get("passed") else "FAIL")))
            raw_status = _coerce_text(row.get("status") or row.get("Status") or "")
            status = verdict if raw_status.casefold() in {"", "collected", "collected."} else raw_status
            passed = bool(row.get("passed")) if "passed" in row else verdict == "PASS"
            return {
                "hash_id": _coerce_text(row.get("hash_id") or row.get("hashId") or ""),
                "ruleId": _coerce_text(row.get("id") or row.get("RuleId") or row.get("ruleId") or row.get("RuleID") or row.get("rule_id")),
                "rule_id": _coerce_text(row.get("id") or row.get("RuleId") or row.get("ruleId") or row.get("RuleID") or row.get("rule_id")),
                "service": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
                "title": _coerce_text(row.get("title") or row.get("Title") or row.get("PolicyName") or row.get("policyName")),
                "serviceName": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
                "service_name": _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name")),
                "passed": passed,
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
        raw_status = _normalize_status(
            _coerce_text(row.get("Status") or row.get("status") or row.get("Verdict") or row.get("verdict"))
        )
        check_type = _coerce_text(row.get("check_type") or row.get("CheckType") or row.get("checkType"))
        source = _coerce_text(row.get("source") or row.get("Source"))

        passed = bool(row.get("passed")) if "passed" in row else raw_status == "PASS"
        verdict = "PASS" if passed else "FAIL"
        status = verdict if raw_status in {"", "COLLECTED", "COLLECTED."} else raw_status or verdict

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
        status = "Secure" if failed == 0 and manual == 0 else "Vulnerable"
        report_file = self.report_file()

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

    def normalize_report_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(payload)
        items = normalized.get("items")
        if isinstance(items, list):
            normalized["items"] = [self.normalize_row(item) for item in items if isinstance(item, dict)]
        return normalized

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
        return Path(__file__).resolve().parents[3] / "reports" / "scan_compare_report.json"

    def build_scan_mode_prompt(self, *, inventory: Any) -> str:
        return (
            "Windows Server environment confirmed.\n\n"
            f"OS: {inventory.os_caption}\n"
            f"Version: {inventory.os_version}\n"
            f"Build: {getattr(inventory, 'build_number', '')}\n"
            f"Profile: {inventory.profile_key}\n"
            "Choose the scan mode:\n"
            "Yes = Quick scan\n"
            "No = Full scan\n"
            "Cancel = Do not scan"
        )

    def build_result_message(self, *, summary: Any, failed_ids: list[str] | None = None) -> str:
        failed_ids = failed_ids or []
        fail_list = "\n".join(f"- {rule_id}" for rule_id in failed_ids) or "- Không xác định"

        if getattr(summary, "failed", 0) > 0:
            return (
                f"Quét hoàn tất: {summary.total} rule\n"
                f"PASS: {summary.passed}\n"
                f"FAIL: {summary.failed}\n"
                f"MANUAL: {summary.manual}\n\n"
                "Rule FAIL tiêu biểu:\n"
                f"{fail_list}\n\n"
                f"Xem hướng dẫn chuẩn trong file:\n{summary.report_file}"
            )

        return (
            f"Quét hoàn tất: {summary.total} rule\n"
            f"PASS: {summary.passed}\n"
            f"FAIL: {summary.failed}\n\n"
            f"MANUAL: {summary.manual}\n\n"
            f"Báo cáo lưu tại:\n{summary.report_file}"
        )


def get_scan_view() -> ScanView:
    return ScanView.instance()
