from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnmngsys_app.services.scanflow.report_builder import build_report_from_merged_scan
from vulnmngsys_app.services.scanflow.rule_catalog import get_full_rule_files
from vulnmngsys_app.services.scanflow.scanner import run_scan_for_profile
from vulnmngsys_app.services.scanflow.standards import (
    validate_report_schema,
    validate_rule_files,
    validate_scan_rows_schema,
)
from vulnmngsys_app.startup.dependencies import scan_dependencies


def _collect_default_rule_files(rules_dir: Path) -> list[Path]:
    _ = rules_dir
    return get_full_rule_files("Windows_Server_2022")


def main() -> int:
    project_root = PROJECT_ROOT
    rules_dir = project_root / "rules"
    reports_dir = project_root / "reports"

    rule_files = _collect_default_rule_files(rules_dir)
    if not rule_files:
        print("No default rule files found.")
        return 2

    issues = validate_rule_files(rule_files)

    dependencies = scan_dependencies("Windows_Server_2022")
    merged_scan_file = run_scan_for_profile(
        profile_key="Windows_Server_2022",
        full_scan=False,
        rule_repository=dependencies[0],
        collector=dependencies[1],
        checkers=dependencies[2],
        result_mapper=dependencies[3],
    )
    issues.extend(validate_scan_rows_schema(merged_scan_file))

    report_file = reports_dir / "scan_compare_report_contract.json"
    summary = build_report_from_merged_scan(merged_scan_file, report_file)
    issues.extend(validate_report_schema(report_file))

    print(
        json.dumps(
            {
                "rule_files": [str(item) for item in rule_files],
                "merged_scan": str(merged_scan_file),
                "report": str(summary.report_file),
                "total": summary.total,
                "passed": summary.passed,
                "failed": summary.failed,
                "manual": summary.manual,
                "contract_issues": issues,
            },
            ensure_ascii=True,
            indent=2,
        )
    )

    return 0 if not issues else 3


if __name__ == "__main__":
    raise SystemExit(main())
