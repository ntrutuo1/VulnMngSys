from __future__ import annotations

from pathlib import Path

from ...application.factories import get_report_writer, get_scanner
from ...domain.contracts import ModuleCatalog, ReportWriter, ScanEngine
from ...domain.models import ModuleDefinition
from ...infrastructure.catalog.hardcoded_catalog import HardcodedModuleCatalog
from ...infrastructure.platform.service_probe import detect_host_family, detect_host_version, detect_service_version


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
    family = detect_host_family()
    if family == "linux":
        return family, _detect_linux_version()
    return family, detect_host_version()


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


def _prompt_choice(prompt: str, options: list[str], default_index: int = 0) -> str:
    if not options:
        raise RuntimeError("No options available for selection")

    while True:
        print("")
        print(prompt)
        for idx, item in enumerate(options, start=1):
            marker = "*" if (idx - 1) == default_index else " "
            print(f"  {idx}. [{marker}] {item}")
        raw = input(f"Select [default {default_index + 1}]: ").strip()
        if not raw:
            return options[default_index]
        if raw.isdigit():
            selected = int(raw)
            if 1 <= selected <= len(options):
                return options[selected - 1]
        print("Invalid selection. Try again.")


def _prompt_value(prompt: str, default_value: str = "") -> str:
    if default_value:
        raw = input(f"{prompt} [default: {default_value}]: ").strip()
        return raw or default_value
    return input(f"{prompt}: ").strip()


def _interactive_pick(
    modules: list[ModuleDefinition],
    service: str,
    os_version: str | None,
    service_version: str | None,
) -> tuple[ModuleDefinition, str, str]:
    service_options = ["ssh", "apache-http", "apache-tomcat"]
    selected_service = _prompt_choice("Choose service", service_options, default_index=service_options.index(service))

    matching = [item for item in modules if item.service_type == selected_service]
    module_options = [f"{item.display_name} ({item.module_id})" for item in matching]
    selected_module_text = _prompt_choice("Choose module", module_options)
    selected_idx = module_options.index(selected_module_text)
    selected_module = matching[selected_idx]

    chosen_os_version = _prompt_value("Enter OS version context", os_version or selected_module.os_version)
    auto_service_version = detect_service_version(selected_module.service_type) or ""
    chosen_service_version = _prompt_value(
        "Enter service version context",
        service_version or auto_service_version,
    )
    return selected_module, chosen_os_version, chosen_service_version


def run_headless_scan(
    module_id: str | None = None,
    service: str = "ssh",
    os_version: str | None = None,
    service_version: str | None = None,
    interactive: bool = False,
    module_catalog: ModuleCatalog | None = None,
    scan_engine: ScanEngine | None = None,
    report_writer: ReportWriter | None = None,
) -> int:
    catalog = module_catalog or HardcodedModuleCatalog()
    scanner = scan_engine or get_scanner()
    writer = report_writer or get_report_writer()

    modules = catalog.list_modules()
    if interactive:
        module, selected_os_version, selected_service_version = _interactive_pick(
            modules,
            service=service,
            os_version=os_version,
            service_version=service_version,
        )
    else:
        module = _pick_module(modules, module_id=module_id, service=service)
        selected_os_version = os_version or module.os_version
        selected_service_version = service_version or detect_service_version(module.service_type)

    report = scanner.scan(
        module,
        os_version=selected_os_version,
        service_version=selected_service_version,
    )

    print(f"Module: {report.module.display_name}")
    print(f"Hardening Index: {report.summary.hardening_index}")
    print(f"Grade: {report.summary.grade}")
    print(f"Passed: {report.summary.passed_checks}/{report.summary.total_checks}")
    print("")
    for result in report.results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.code} | {result.title} | {result.reason}")

    if report.cve_advisories:
        print("")
        print("CVE Intelligence:")
        for item in report.cve_advisories:
            print(f"[{item.severity.upper()}] {item.cve_id} | {item.title} | {item.reason}")

    reports_dir = Path.cwd() / "reports"
    report_path = writer.write(report, reports_dir)
    print("")
    print(f"Report saved: {report_path}")

    return 0
