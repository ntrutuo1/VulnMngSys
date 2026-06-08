from __future__ import annotations

import json
from pathlib import Path

from application.rule_repository import RuleRepository
from application.scan_result_mapper import LegacyScanPayloadMapper
from application.scan_service import ScanService
from infrastructure.checkers.checker_registry import CheckerRegistry, default_checker_registry
from infrastructure.collectors.windows_collector import WindowsCollector
from infrastructure.logging.system_logger import logger
from infrastructure.rule_repository import JsonRuleRepository

from .models import ScanInventory


def _collect_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    _ = (profile_key, full_scan)
    return []


def run_scan_for_profile(
    profile_key: str,
    full_scan: bool,
    inventory: ScanInventory | None = None,
    rule_repository: RuleRepository | None = None,
    checker_registry: CheckerRegistry | None = None,
    app_root: Path | None = None,
) -> Path:
    """Run the scan service for a Windows Server profile."""
    _ = inventory
    root = app_root or Path(__file__).resolve().parents[2]
    report_temp_dir = root / "reports" / "temp"

    repository = rule_repository or JsonRuleRepository()
    registry = checker_registry or default_checker_registry()
    rules = repository.load_rules(profile_key, full_scan)

    logger.info("Initializing ScanService with WindowsCollector and strategy checkers.")
    service = ScanService(
        WindowsCollector(),
        registry.build(),
        result_mapper=LegacyScanPayloadMapper(profile_key=profile_key),
    )
    results = service.run_scan(rules)

    report_temp_dir.mkdir(parents=True, exist_ok=True)
    merged_path = report_temp_dir / "scan_results_merged.json"
    merged_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    return merged_path
