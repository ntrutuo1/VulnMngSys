from __future__ import annotations

from pathlib import Path

from .models import ComparisonSummary
from .report_builder import build_report_from_merged_scan

__all__ = ["build_report_from_merged_scan"]


def compare_scan_outputs(merged_scan_file: Path, report_file: Path) -> ComparisonSummary:
    """Alias giữ tương thích — nhận file merged từ scan_executor."""
    return build_report_from_merged_scan(merged_scan_file, report_file)
