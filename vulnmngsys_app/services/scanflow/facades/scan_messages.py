from __future__ import annotations

from typing import Any


def build_scan_mode_prompt(*, inventory: Any) -> str:
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


def build_result_message(*, summary: Any, failed_ids: list[str] | None = None) -> str:
    failed_ids = failed_ids or []
    fail_list = "\n".join(f"- {rule_id}" for rule_id in failed_ids) or "- Khong xac dinh"
    if getattr(summary, "failed", 0) > 0:
        return (
            f"Scan completed: {summary.total} rule\n"
            f"PASS: {summary.passed}\n"
            f"FAIL: {summary.failed}\n"
            f"MANUAL: {summary.manual}\n\n"
            "Representative failed rules:\n"
            f"{fail_list}\n\n"
            f"Report file:\n{summary.report_file}"
        )
    return (
        f"Scan completed: {summary.total} rule\n"
        f"PASS: {summary.passed}\n"
        f"FAIL: {summary.failed}\n"
        f"MANUAL: {summary.manual}\n\n"
        f"Report file:\n{summary.report_file}"
    )
