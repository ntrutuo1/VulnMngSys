from __future__ import annotations

from pathlib import Path

from .models import ScanReport
from .services import TextReportWriter, build_default_report_writer


_default_writer: TextReportWriter = build_default_report_writer()


def get_report_writer() -> TextReportWriter:
    return _default_writer


def set_report_writer(writer: TextReportWriter) -> None:
    global _default_writer
    _default_writer = writer


def write_report(report: ScanReport, output_dir: Path) -> Path:
    return _default_writer.write(report, output_dir)
