from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evaluate import evaluate_rule_verdict, format_expected_display
from .guidance import build_guidance
from .models import ComparisonSummary, RuleComparisonResult


def _normalize(value: Any) -> str:
    return str(value).strip()


def _rule_from_scan_row(row: dict[str, Any]) -> dict[str, Any]:
    """Build evaluation context from scan output only (no rules/ re-read)."""
    expected = row.get("Expected")
    if expected is None:
        expected = row.get("expected")

    registry_value = row.get("RegistryValue")
    if registry_value is None:
        registry_value = row.get("registry_value")

    rule_type = _normalize(row.get("RuleType") or row.get("ruleType") or row.get("type") or "")
    check_type = _normalize(row.get("CheckType") or row.get("checkType") or "")

    return {
        "id": _normalize(row.get("RuleId") or row.get("ruleId") or ""),
        "title": _normalize(row.get("Title") or row.get("title") or ""),
        "type": rule_type or check_type,
        "expected": expected,
        "match": row.get("Match") or row.get("match"),
        "registry_value": registry_value,
        "description": _normalize(row.get("Description") or row.get("description") or ""),
        "recommended": _normalize(row.get("Recommended") or row.get("recommended") or ""),
    }


def _compare_scan_rows(scan_items: list[Any]) -> list[RuleComparisonResult]:
    results: list[RuleComparisonResult] = []

    for row in scan_items:
        if not isinstance(row, dict):
            continue

        rule = _rule_from_scan_row(row)
        rule_id = _normalize(rule.get("id") or "")
        status = _normalize(row.get("Status") or "")
        check_type = _normalize(row.get("CheckType") or row.get("checkType") or "")
        actual = _normalize(row.get("Actual") or row.get("actual") or "")
        source = _normalize(row.get("Source") or row.get("source") or "")
        title = _normalize(rule.get("title") or "")
        recommended = _normalize(
            row.get("Recommended")
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
    scan_items = raw if isinstance(raw, list) else [raw]
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
    return {
        "status": status,
        "total_rules": total,
        "total": total,
        "passed": passed,
        "failed": failed,
        "manual": manual,
        "reportFile": str(report_file),
        "items": [
            {
                "ruleId": item.rule_id,
                "rule_id": item.rule_id,
                "title": item.title,
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
        ],
    }


def report_payload_to_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": payload.get("status"),
        "total_rules": payload.get("total_rules", payload.get("total", 0)),
        "passed": payload.get("passed", 0),
        "failed": payload.get("failed", 0),
        "manual": payload.get("manual", 0),
        "reportFile": payload.get("reportFile"),
        "items": payload.get("items", []),
    }
