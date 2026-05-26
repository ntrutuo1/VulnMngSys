from __future__ import annotations

import sys
from pathlib import Path

from .report_builder import build_report_from_merged_scan
from .inventory import load_windows_inventory
from .scanner import run_scan_for_profile
from .selection import ask_scan_mode, show_message_box


def run_windows_server_scan_flow() -> None:
    if not sys.platform.startswith("win"):
        return

    try:
        inventory = load_windows_inventory()
    except Exception as exc:
        show_message_box(f"Không thể nhận diện hệ điều hành: {exc}", "VulnMngSys - Scan Flow", 0x10 | 0x40000)
        return

    if not inventory.is_server:
        return

    if not inventory.profile_key:
        show_message_box("Không nhận diện được profile Windows Server để quét.", "VulnMngSys - Scan Flow", 0x30 | 0x40000)
        return

    selection = ask_scan_mode(inventory)
    if selection.cancelled:
        return

    try:
        merged_scan_file = run_scan_for_profile(
            profile_key=inventory.profile_key,
            full_scan=selection.full_scan,
            inventory=inventory,
        )
    except Exception as exc:
        show_message_box(f"Lỗi khi chạy script quét: {exc}", "VulnMngSys - Scan Flow", 0x10 | 0x40000)
        return

    try:
        report_path = Path(__file__).resolve().parents[2] / "reports" / "scan_compare_report.json"
        summary = build_report_from_merged_scan(merged_scan_file, report_file=report_path)
    except Exception as exc:
        show_message_box(f"Lỗi khi so sánh kết quả quét: {exc}", "VulnMngSys - Scan Flow", 0x10 | 0x40000)
        return

    if summary.failed > 0:
        failed_ids = [item.rule_id for item in summary.items if not item.passed][:6]
        fail_list = "\n".join(f"- {rule_id}" for rule_id in failed_ids) or "- Không xác định"
        show_message_box(
            (
                f"Quét hoàn tất: {summary.total} rule\n"
                f"PASS: {summary.passed}\n"
                f"FAIL: {summary.failed}\n"
                f"MANUAL: {summary.manual}\n\n"
                "Rule FAIL tiêu biểu:\n"
                f"{fail_list}\n\n"
                f"Xem hướng dẫn chuẩn trong file:\n{summary.report_file}"
            ),
            "VulnMngSys - Kết quả quét",
            0x30 | 0x40000,
        )
        return

    show_message_box(
        (
            f"Quét hoàn tất: {summary.total} rule\n"
            f"PASS: {summary.passed}\n"
            f"FAIL: {summary.failed}\n\n"
            f"MANUAL: {summary.manual}\n\n"
            f"Báo cáo lưu tại:\n{summary.report_file}"
        ),
        "VulnMngSys - Kết quả quét",
        0x40 | 0x40000,
    )
