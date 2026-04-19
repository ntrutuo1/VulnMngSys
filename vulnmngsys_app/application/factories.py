from __future__ import annotations

from ..infrastructure.reporting.text_writer import TextReportWriter
from ..infrastructure.scan.components import ComplianceScanner, LocalConfigReader, LocalPathSelector, LynisScoringStrategy


def build_default_scanner() -> ComplianceScanner:
    return ComplianceScanner(
        path_selector=LocalPathSelector(),
        config_reader=LocalConfigReader(),
        scoring_strategy=LynisScoringStrategy(),
    )


def build_default_report_writer() -> TextReportWriter:
    return TextReportWriter()


_default_scanner: ComplianceScanner = build_default_scanner()
_default_writer: TextReportWriter = build_default_report_writer()


def get_scanner() -> ComplianceScanner:
    return _default_scanner


def set_scanner(scanner: ComplianceScanner) -> None:
    global _default_scanner
    _default_scanner = scanner


def get_report_writer() -> TextReportWriter:
    return _default_writer


def set_report_writer(writer: TextReportWriter) -> None:
    global _default_writer
    _default_writer = writer
