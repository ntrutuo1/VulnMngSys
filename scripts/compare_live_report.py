"""Build live vs expected report from scan JSON + optional net accounts fallback."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_bootstrap.scanflow.evaluate import evaluate_numeric_expected, evaluate_rule_verdict, format_expected_display
from app_bootstrap.scanflow.matching import RuleLookupIndex


def _load_rules(path: Path) -> RuleLookupIndex:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    items = payload if isinstance(payload, list) else [payload]
    return RuleLookupIndex.from_rules([item for item in items if isinstance(item, dict)])


def _net_fallback_actual(rule: dict, net_map: dict[str, str]) -> str | None:
    key = str(rule.get("key") or "")
    mapping = {
        "PasswordHistorySize": "PasswordHistorySize",
        "MaximumPasswordAge": "MaximumPasswordAge",
        "MinimumPasswordAge": "MinimumPasswordAge",
        "MinimumPasswordLength": "MinimumPasswordLength",
        "LockoutBadCount": "LockoutBadCount",
        "LockoutDuration": "LockoutDuration",
        "ResetLockoutCount": "ResetLockoutCount",
    }
    net_key = mapping.get(key)
    if not net_key or net_key not in net_map:
        return None
    raw = net_map[net_key]
    if net_key == "PasswordHistorySize" and raw.lower() == "none":
        return "0"
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-json", required=True)
    parser.add_argument("--rule-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--inventory-file")
    parser.add_argument("--net-map-file")
    parser.add_argument("--sec-export-file")
    args = parser.parse_args()

    def _read_json_file(path: str | None) -> dict:
        if not path:
            return {}
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))

    inventory = _read_json_file(args.inventory_file)
    net_map = _read_json_file(args.net_map_file)
    sec_export = _read_json_file(args.sec_export_file)

    rule_index = _load_rules(Path(args.rule_file))
    scan_items = json.loads(Path(args.scan_json).read_text(encoding="utf-8-sig"))
    if not isinstance(scan_items, list):
        scan_items = [scan_items]

    rows: list[dict] = []
    for row in scan_items:
        if not isinstance(row, dict):
            continue
        rule_id = str(row.get("RuleId") or "").strip()
        rule = rule_index.get(rule_id) or {}
        status = str(row.get("Status") or "")
        actual = str(row.get("Actual") or "").strip()
        check_type = str(row.get("CheckType") or "")

        fallback_source = None
        if not actual and str(rule.get("type") or "") in {"secedit", "security_policy"}:
            sec_key = str(rule.get("key") or "")
            if sec_key in sec_export:
                actual = sec_export[sec_key]
                fallback_source = "secedit_export"
                status = "Collected"
            else:
                net_actual = _net_fallback_actual(rule, net_map)
                if net_actual is not None:
                    actual = net_actual
                    fallback_source = "net_accounts"
                    status = "Collected"

        expected_display = format_expected_display(
            rule.get("expected"),
            str(rule.get("description") or ""),
        )
        passed, verdict, expected = evaluate_rule_verdict(
            rule=rule,
            check_type=check_type,
            status=status,
            actual=actual,
            recommended=expected_display,
        )

        rows.append(
            {
                "ruleId": rule_id,
                "title": rule.get("title") or row.get("Title"),
                "verdict": verdict,
                "passed": passed,
                "expected": expected,
                "expectedRaw": rule.get("expected"),
                "actual": actual,
                "scanStatus": status,
                "checkType": check_type,
                "source": row.get("Source"),
                "fallbackSource": fallback_source,
                "cisPdfSection": rule_id,
            }
        )

    passed = sum(1 for item in rows if item["verdict"] == "PASS")
    failed = sum(1 for item in rows if item["verdict"] == "FAIL")
    manual = sum(1 for item in rows if item["verdict"] == "MANUAL")

    report = {
        "inventory": inventory,
        "netAccounts": net_map,
        "seceditExportKeys": list(sec_export.keys()),
        "summary": {"total": len(rows), "passed": passed, "failed": failed, "manual": manual},
        "items": rows,
        "note": "expectedRaw/description align with CIS JSON rules; PDF: Reference/CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.pdf",
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8-sig")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
