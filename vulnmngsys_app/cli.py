from __future__ import annotations

import platform
from pathlib import Path

from .models import ModuleDefinition
from .modules import load_modules
from .reporting import write_report
from .scanner import scan_module


def _detect_linux_version() -> str:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return "generic"

    data = os_release.read_text(encoding="utf-8", errors="ignore")
    if "22.04" in data:
        return "ubuntu-22.04"
    if "24.04" in data:
        return "ubuntu-24.04"
    return "generic"


def _detect_host() -> tuple[str, str]:
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows", "windows-11"
    if system == "darwin":
        return "macos", "macos-14"
    return "linux", _detect_linux_version()


def _pick_module(modules: list[ModuleDefinition], module_id: str | None, service: str) -> ModuleDefinition:
    if module_id:
        matched = next((item for item in modules if item.module_id == module_id), None)
        if matched is None:
            raise RuntimeError(f"Unknown module_id: {module_id}")
        return matched

    family, version = _detect_host()
    exact = next(
        (
            item
            for item in modules
            if item.os_family == family and item.os_version == version and item.service_type == service
        ),
        None,
    )
    if exact is not None:
        return exact

    generic = next(
        (
            item
            for item in modules
            if item.os_family == family and item.os_version == "generic" and item.service_type == service
        ),
        None,
    )
    if generic is not None:
        return generic

    raise RuntimeError(f"No module available for family={family}, version={version}, service={service}")


def run_headless_scan(module_id: str | None = None, service: str = "ssh") -> int:
    modules = load_modules()
    module = _pick_module(modules, module_id=module_id, service=service)
    report = scan_module(module)

    print(f"Module: {report.module.display_name}")
    print(f"Hardening Index: {report.summary.hardening_index}")
    print(f"Grade: {report.summary.grade}")
    print(f"Passed: {report.summary.passed_checks}/{report.summary.total_checks}")
    print("")
    for result in report.results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.code} | {result.title} | {result.reason}")

    reports_dir = Path.cwd() / "reports"
    report_path = write_report(report, reports_dir)
    print("")
    print(f"Report saved: {report_path}")

    return 0
