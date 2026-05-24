from __future__ import annotations

from pathlib import Path

from .rule_catalog import get_full_rule_files, get_quick_rule_file
from .scan_executor_client import run_scan_via_executor


def _collect_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    if full_scan:
        return get_full_rule_files(profile_key)
    return [get_quick_rule_file(profile_key)]


def run_scan_for_profile(profile_key: str, full_scan: bool) -> Path:
    """
    Chạy scan_executor → trả về file merged scan (kết quả thu thập).
    Manifest rules/ chỉ dùng để biết file nào đưa vào scanner, không dùng để so sánh lại.
    """
    app_root = Path(__file__).resolve().parents[2]
    report_temp_dir = app_root / "reports" / "temp"

    selected_rules = _collect_rule_files(profile_key=profile_key, full_scan=full_scan)
    if not selected_rules:
        raise RuntimeError(f"Không tìm thấy file rule cho profile {profile_key}")

    return run_scan_via_executor(rule_files=selected_rules, output_dir=report_temp_dir)
