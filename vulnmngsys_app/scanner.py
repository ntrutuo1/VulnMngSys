from __future__ import annotations

from .models import ModuleDefinition, ScanReport
from .services import ComplianceScanner, build_default_scanner


_default_scanner: ComplianceScanner = build_default_scanner()


def get_scanner() -> ComplianceScanner:
    return _default_scanner


def set_scanner(scanner: ComplianceScanner) -> None:
    global _default_scanner
    _default_scanner = scanner


def scan_module(
    module: ModuleDefinition,
    os_version: str | None = None,
    service_version: str | None = None,
) -> ScanReport:
    return _default_scanner.scan(module, os_version=os_version, service_version=service_version)
