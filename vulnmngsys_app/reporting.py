from __future__ import annotations

from pathlib import Path

from .application.factories import get_report_writer as _get_report_writer
from .application.factories import set_report_writer as _set_report_writer
from .domain.models import ScanReport
from .infrastructure.reporting.text_writer import TextReportWriter

def get_report_writer() -> TextReportWriter:
    return _get_report_writer()


def set_report_writer(writer: TextReportWriter) -> None:
    _set_report_writer(writer)


def write_report(report: ScanReport, output_dir: Path) -> Path:
    return get_report_writer().write(report, output_dir)
