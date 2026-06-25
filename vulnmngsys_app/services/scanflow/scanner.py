from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from vulnmngsys_app.services.rule_repository import RuleRepository
from vulnmngsys_app.services.scan_result_mapper import LegacyScanPayloadMapper, ScanResultMapper
from vulnmngsys_app.services.scan_service import ScanService
from vulnmngsys_app.models.protocols import RuleChecker, SystemCollector

from .models import ScanInventory
from .paths import project_root, writable_reports_dir
from .progress import (
    complete_scan_progress,
    fail_scan_progress,
    mark_rule_finished,
    mark_rule_started,
    start_scan_progress,
)


def _collect_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    _ = (profile_key, full_scan)
    return []


def run_scan_for_profile(
    profile_key: str,
    full_scan: bool,
    inventory: ScanInventory | None = None,
    rule_repository: RuleRepository | None = None,
    collector: SystemCollector | None = None,
    checkers: list[RuleChecker] | None = None,
    result_mapper: ScanResultMapper | None = None,
    app_root: Path | None = None,
    scan_id: str = "",
) -> Path:
    """Run the scan service for a Windows Server profile."""
    _ = inventory
    root = app_root or project_root()
    report_temp_dir = writable_reports_dir(root, "temp")

    if rule_repository is None or collector is None or checkers is None:
        raise ValueError("Scan dependencies must be provided by the app entrypoint.")

    rules = rule_repository.load_rules(profile_key, full_scan)
    if scan_id:
        start_scan_progress(scan_id, profile_key=profile_key, full_scan=full_scan, total=len(rules))

    service = ScanService(
        collector,
        checkers,
        result_mapper=result_mapper or LegacyScanPayloadMapper(profile_key=profile_key),
    )
    try:
        results = service.run_scan(rules, progress_callback=_progress_callback(scan_id))
        if scan_id:
            complete_scan_progress(scan_id)
    except Exception as exc:
        if scan_id:
            fail_scan_progress(scan_id, str(exc))
        raise

    report_temp_dir.mkdir(parents=True, exist_ok=True)
    mode = "full" if full_scan else "quick"
    safe_profile = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile_key).strip("_") or "profile"
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    merged_path = report_temp_dir / f"scan_results_merged_{safe_profile}_{mode}_{timestamp}.json"
    merged_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    return merged_path


def _progress_callback(scan_id: str):
    if not scan_id:
        return None

    def callback(event: str, rule, index: int, total: int, result) -> None:
        if event == "rule_started":
            mark_rule_started(scan_id, rule, index=index, total=total)
        elif event == "rule_finished":
            mark_rule_finished(scan_id, rule, index=index, total=total, result=result)

    return callback
