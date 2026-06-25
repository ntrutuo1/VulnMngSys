from __future__ import annotations

import sys

from vulnmngsys_app.models.protocols import RuleChecker, SystemCollector
from vulnmngsys_app.services.rule_repository import RuleRepository
from vulnmngsys_app.services.scan_result_mapper import ScanResultMapper

from .facades.scan_view import get_scan_view
from .inventory import load_windows_inventory
from .paths import project_root
from .report_builder import build_report_from_merged_scan
from .scanner import run_scan_for_profile
from .selection import ask_scan_mode, show_message_box


def run_windows_server_scan_flow(
    *,
    rule_repository: RuleRepository,
    collector: SystemCollector,
    checkers: list[RuleChecker],
    result_mapper: ScanResultMapper | None = None,
) -> None:
    if not sys.platform.startswith("win"):
        return

    try:
        inventory = load_windows_inventory()
    except Exception as exc:
        show_message_box(
            f"Cannot detect operating system: {exc}",
            "VulnMngSys - Scan Flow",
            0x10 | 0x40000,
        )
        return

    if not inventory.is_server:
        return

    if not inventory.profile_key:
        show_message_box(
            "Cannot identify a Windows Server scan profile.",
            "VulnMngSys - Scan Flow",
            0x30 | 0x40000,
        )
        return

    selection = ask_scan_mode(inventory)
    if selection.cancelled:
        return

    try:
        merged_scan_file = run_scan_for_profile(
            profile_key=inventory.profile_key,
            full_scan=selection.full_scan,
            inventory=inventory,
            rule_repository=rule_repository,
            collector=collector,
            checkers=checkers,
            result_mapper=result_mapper,
        )
    except Exception as exc:
        show_message_box(
            f"Scan failed: {exc}",
            "VulnMngSys - Scan Flow",
            0x10 | 0x40000,
        )
        return

    try:
        report_path = project_root() / "reports" / "scan_compare_report.json"
        summary = build_report_from_merged_scan(merged_scan_file, report_file=report_path)
    except Exception as exc:
        show_message_box(
            f"Failed to compare scan results: {exc}",
            "VulnMngSys - Scan Flow",
            0x10 | 0x40000,
        )
        return

    if summary.failed > 0:
        failed_ids = [item.rule_id for item in summary.items if not item.passed][:6]
        message = get_scan_view().build_result_message(summary=summary, failed_ids=failed_ids)
        show_message_box(message, "VulnMngSys - Scan Result", 0x30 | 0x40000)
        return

    show_message_box(
        get_scan_view().build_result_message(summary=summary),
        "VulnMngSys - Scan Result",
        0x40 | 0x40000,
    )
