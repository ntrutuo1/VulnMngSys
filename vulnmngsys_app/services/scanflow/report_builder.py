from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evaluate import evaluate_rule_verdict, format_expected_display
from .service_tree import group_rows_by_service
from .guidance import build_guidance
from .models import ComparisonSummary, RuleComparisonResult
from .facades.scan_view import get_scan_view


_VIEW = get_scan_view()


def _normalize(value: Any) -> str:
    return str(value).strip()


def _first_value(row: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        value = row.get(key)
        if value:
            return value
    return default


def _rule_from_scan_row(row: dict[str, Any]) -> dict[str, Any]:
    """Build evaluation context from scan output only (no rules/ re-read)."""
    expected = row.get("expected")
    if expected is None:
        expected = row.get("Expected")

    registry_value = row.get("registry_path")
    if registry_value is None:
        registry_value = row.get("RegistryValue")
    if registry_value is None:
        registry_value = row.get("registry_value")

    rule_type = _normalize(_first_value(row, ("check_type", "RuleType", "ruleType", "type")))
    check_type = _normalize(row.get("check_type") or row.get("CheckType") or row.get("checkType") or "")

    return {
        "id": _normalize(row.get("id") or row.get("RuleId") or row.get("ruleId") or ""),
        "title": _normalize(row.get("title") or row.get("Title") or ""),
        "type": rule_type or check_type,
        "expected": expected,
        "match": row.get("Match") or row.get("match"),
        "registry_value": registry_value,
        "description": _normalize(row.get("reason") or row.get("Description") or row.get("description") or ""),
        "recommended": _normalize(_first_value(row, ("expected", "Expected", "Recommended", "recommended"))),
    }


def _compare_scan_rows(scan_items: list[Any]) -> list[RuleComparisonResult]:
    results: list[RuleComparisonResult] = []

    for row in scan_items:
        if not isinstance(row, dict):
            continue

        if "verdict" in row or "passed" in row:
            verdict = _normalize(row.get("verdict") or ("PASS" if row.get("passed") else "FAIL"))
            passed = bool(row.get("passed")) if "passed" in row else verdict == "PASS"
            results.append(
                RuleComparisonResult(
                    rule_id=_normalize(row.get("id") or row.get("RuleId") or row.get("ruleId") or ""),
                    title=_normalize(row.get("title") or row.get("Title") or ""),
                    service_name=_normalize(_first_value(row, ("service", "serviceName", "service_name"))),
                    passed=passed,
                    verdict=verdict,
                    expected=_normalize(_first_value(row, ("expected", "Expected", "Recommended", "recommended"))),
                    actual=_normalize(_first_value(row, ("actual", "Actual", "CurrentValue", "currentValue"))),
                    status=_normalize(row.get("status") or row.get("Status") or verdict),
                    check_type=_normalize(_first_value(row, ("check_type", "CheckType", "checkType", "type"))),
                    source=_normalize(row.get("source") or row.get("Source") or ""),
                    guidance=list(row.get("guidance") or []),
                )
            )
            continue

        rule = _rule_from_scan_row(row)
        rule_id = _normalize(rule.get("id") or "")
        status = _normalize(row.get("status") or row.get("Status") or "")
        check_type = _normalize(row.get("check_type") or row.get("CheckType") or row.get("checkType") or "")
        actual = _normalize(row.get("actual") or row.get("Actual") or "")
        source = _normalize(row.get("source") or row.get("Source") or "")
        title = _normalize(rule.get("title") or "")
        recommended = _normalize(
            row.get("expected")
            or row.get("Expected")
            or row.get("Recommended")
            or row.get("recommended")
            or format_expected_display(rule.get("expected"), str(rule.get("description") or ""))
        )

        passed, verdict, expected = evaluate_rule_verdict(
            rule=rule,
            check_type=check_type,
            status=status,
            actual=actual,
            recommended=recommended,
        )

        guidance = [] if verdict == "PASS" else build_guidance(rule, source=source, expected=expected)

        results.append(
            RuleComparisonResult(
                rule_id=rule_id,
                title=title,
                service_name=_normalize(_first_value(row, ("service", "serviceName", "service_name"))),
                passed=passed,
                verdict=verdict,
                expected=expected,
                actual=actual,
                status=status,
                check_type=check_type,
                source=source,
                guidance=guidance,
            )
        )

    return results


def build_report_from_merged_scan(merged_scan_file: Path, report_file: Path) -> ComparisonSummary:
    """Build final report from scan_executor merged output — không đọc lại rules/."""
    raw = json.loads(merged_scan_file.read_text(encoding="utf-8-sig"))
    scan_items = _VIEW.flatten_rows(raw)
    results = _compare_scan_rows(scan_items)

    total = len(results)
    passed_count = sum(1 for item in results if item.verdict == "PASS")
    failed_count = sum(1 for item in results if item.verdict == "FAIL")
    manual_count = sum(1 for item in results if item.verdict == "MANUAL")
    status_label = "Secure" if failed_count == 0 and manual_count == 0 else "Vulnerable"

    report_payload = build_report_payload(
        status=status_label,
        total=total,
        passed=passed_count,
        failed=failed_count,
        manual=manual_count,
        items=results,
        report_file=report_file,
    )

    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    return ComparisonSummary(
        total=total,
        passed=passed_count,
        failed=failed_count,
        manual=manual_count,
        items=results,
        report_file=report_file,
    )


def build_report_payload(
    *,
    status: str,
    total: int,
    passed: int,
    failed: int,
    manual: int,
    items: list[RuleComparisonResult],
    report_file: Path,
) -> dict[str, Any]:
    rows = [
        {
            "ruleId": item.rule_id,
            "rule_id": item.rule_id,
            "title": item.title,
            "service": item.service_name,
            "serviceName": item.service_name,
            "service_name": item.service_name,
            "passed": item.passed,
            "verdict": item.verdict,
            "expected": item.expected,
            "actual": item.actual,
            "status": item.status,
            "checkType": item.check_type,
            "check_type": item.check_type,
            "source": item.source,
            "guidance": item.guidance,
        }
        for item in items
    ]
    return {
        "status": status,
        "total_rules": total,
        "total": total,
        "passed": passed,
        "failed": failed,
        "manual": manual,
        "reportFile": str(report_file),
        "items": rows,
        "groups": group_rows_by_service(rows),
    }


def report_payload_to_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return _VIEW.report_payload_to_summary(payload)
