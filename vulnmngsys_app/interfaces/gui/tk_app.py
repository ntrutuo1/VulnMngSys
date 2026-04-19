from __future__ import annotations

import tkinter as tk
import traceback
from pathlib import Path
from tkinter import messagebox, ttk

from ...application.factories import get_report_writer, get_scanner
from ...domain.contracts import ModuleCatalog, ReportWriter, ScanEngine
from ...domain.models import ModuleDefinition, ScanReport
from ...infrastructure.catalog.hardcoded_catalog import HardcodedModuleCatalog
from ...infrastructure.platform.service_probe import detect_host_family, detect_host_version, detect_service_version


class AppState:
    def __init__(self, module_catalog: ModuleCatalog) -> None:
        self.modules = module_catalog.list_modules()
        self.module_map = {item.display_name: item for item in self.modules}


def _detect_host_family() -> str:
    return detect_host_family()


def _filter_modules(modules: list[ModuleDefinition], os_family: str, service: str) -> list[ModuleDefinition]:
    return [
        item
        for item in modules
        if (item.os_family == os_family or os_family == "all") and (item.service_type == service or service == "all")
    ]


def _format_report(report: ScanReport) -> str:
    summary = report.summary
    lines: list[str] = []
    lines.append(f"Module: {report.module.display_name}")
    lines.append(f"Rules file: {report.module.rules_source_file}")
    lines.append("")
    lines.append("Resolved config paths:")
    for key, value in report.used_config_paths.items():
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("Lynis-style score:")
    lines.append(f"- Hardening index: {summary.hardening_index}")
    lines.append(f"- Grade: {summary.grade}")
    lines.append(f"- Passed: {summary.passed_checks}/{summary.total_checks}")

    if summary.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in summary.warnings:
            lines.append(f"- {warning}")

    if report.version_context:
        lines.append("")
        lines.append("Version context:")
        lines.append(f"- OS version: {report.version_context.get('os_version', '')}")
        lines.append(f"- Service version: {report.version_context.get('service_version', '')}")

    if report.cve_advisories:
        lines.append("")
        lines.append("CVE intelligence:")
        for item in report.cve_advisories:
            lines.append(
                f"- [{item.severity.upper()}] {item.cve_id} | {item.title} | {item.reason}"
            )

    lines.append("")
    lines.append("Rule results:")
    for row in report.results:
        status = "PASS" if row.passed else "FAIL"
        lines.append(
            f"[{status}] {row.code} | sev={row.severity} | w={row.weight} | {row.title} | {row.reason}"
        )
    return "\n".join(lines)


def _build_missing_target_message(module: ModuleDefinition) -> str:
    lines: list[str] = []
    lines.append("Cannot run scan for selected module because target config files are missing.")
    lines.append(f"Module: {module.display_name}")
    lines.append("")
    lines.append("Checked candidate paths:")
    for key, candidates in module.config_paths.items():
        lines.append(f"- {key}:")
        for path in candidates:
            lines.append(f"    {path}")

    lines.append("")
    lines.append("How to fix:")
    lines.append("1) Install and configure the selected service on this host.")
    lines.append("2) Run this app as Administrator/root.")
    lines.append("3) Pick a module that matches installed services.")

    if module.os_family == "windows" and module.service_type == "ssh":
        lines.append("")
        lines.append("Windows OpenSSH quick setup:")
        lines.append("- Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        lines.append("- Start-Service sshd")
        lines.append("- Set-Service -Name sshd -StartupType Automatic")

    return "\n".join(lines)


def _module_targets_exist(module: ModuleDefinition) -> tuple[bool, dict[str, str]]:
    resolved: dict[str, str] = {}
    for key, candidates in module.config_paths.items():
        existing = next((item for item in candidates if Path(item).exists()), None)
        if existing is None:
            return False, {}
        resolved[key] = existing
    return True, resolved


def run_app(
    module_catalog: ModuleCatalog | None = None,
    scanner: ScanEngine | None = None,
    report_writer: ReportWriter | None = None,
) -> None:
    catalog = module_catalog or HardcodedModuleCatalog()
    scan_engine = scanner or get_scanner()
    writer = report_writer or get_report_writer()
    state = AppState(catalog)

    root = tk.Tk()
    root.title("VulnMngSys Desktop Scanner")
    root.geometry("1080x760")

    top_frame = ttk.Frame(root, padding=12)
    top_frame.pack(fill="x")

    ttk.Label(top_frame, text="OS Family").grid(row=0, column=0, sticky="w", padx=(0, 8))
    os_var = tk.StringVar(value=_detect_host_family())
    os_combo = ttk.Combobox(top_frame, textvariable=os_var, values=["linux", "windows", "macos", "all"], state="readonly", width=16)
    os_combo.grid(row=0, column=1, sticky="w")

    ttk.Label(top_frame, text="Service").grid(row=0, column=2, sticky="w", padx=(16, 8))
    service_var = tk.StringVar(value="all")
    service_combo = ttk.Combobox(
        top_frame,
        textvariable=service_var,
        values=["all", "ssh", "apache-http", "apache-tomcat"],
        state="readonly",
        width=18,
    )
    service_combo.grid(row=0, column=3, sticky="w")

    ttk.Label(top_frame, text="Module").grid(row=0, column=4, sticky="w", padx=(16, 8))
    module_var = tk.StringVar()
    module_combo = ttk.Combobox(top_frame, textvariable=module_var, state="readonly", width=48)
    module_combo.grid(row=0, column=5, sticky="we")

    ttk.Label(top_frame, text="OS Version").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
    os_version_var = tk.StringVar(value="")
    ttk.Entry(top_frame, textvariable=os_version_var, width=18).grid(row=1, column=1, sticky="w", pady=(8, 0))

    ttk.Label(top_frame, text="Service Version").grid(row=1, column=2, sticky="w", padx=(16, 8), pady=(8, 0))
    service_version_var = tk.StringVar(value="")
    ttk.Entry(top_frame, textvariable=service_version_var, width=20).grid(row=1, column=3, sticky="w", pady=(8, 0))

    top_frame.columnconfigure(5, weight=1)

    text_frame = ttk.Frame(root, padding=(12, 0, 12, 12))
    text_frame.pack(fill="both", expand=True)

    output = tk.Text(text_frame, wrap="word", font=("Consolas", 10))
    output.pack(side="left", fill="both", expand=True)

    scroll = ttk.Scrollbar(text_frame, orient="vertical", command=output.yview)
    scroll.pack(side="right", fill="y")
    output.configure(yscrollcommand=scroll.set)

    button_frame = ttk.Frame(root, padding=(12, 0, 12, 12))
    button_frame.pack(fill="x")

    def refresh_module_list(*_args) -> None:
        filtered = _filter_modules(state.modules, os_var.get(), service_var.get())
        names = [item.display_name for item in filtered]
        module_combo["values"] = names
        if names:
            module_var.set(names[0])
            selected = state.module_map[names[0]]
            os_version_var.set(detect_host_version() if os_var.get() == detect_host_family() else selected.os_version)
            detected_service = detect_service_version(selected.service_type)
            service_version_var.set(detected_service or "")
        else:
            module_var.set("")
            os_version_var.set("")
            service_version_var.set("")

    def on_module_change(*_args) -> None:
        selected_name = module_var.get().strip()
        if not selected_name:
            return
        module = state.module_map[selected_name]
        os_version_var.set(detect_host_version() if module.os_family == detect_host_family() else module.os_version)
        detected_service = detect_service_version(module.service_type)
        if detected_service:
            service_version_var.set(detected_service)

    def run_scan() -> None:
        selected_name = module_var.get().strip()
        if not selected_name:
            messagebox.showwarning("No module", "Please select a module before scanning.")
            return

        module = state.module_map[selected_name]
        exists, _resolved = _module_targets_exist(module)
        if not exists:
            output.delete("1.0", tk.END)
            output.insert(tk.END, _build_missing_target_message(module))
            return

        try:
            report = scan_engine.scan(
                module,
                os_version=os_version_var.get().strip() or module.os_version,
                service_version=service_version_var.get().strip(),
            )
        except FileNotFoundError as exc:
            output.delete("1.0", tk.END)
            output.insert(
                tk.END,
                "Missing config file.\n"
                f"Checked path: {exc}\n"
                "Run with root/admin and verify the service is installed on this host.",
            )
            return
        except Exception:
            output.delete("1.0", tk.END)
            output.insert(tk.END, traceback.format_exc())
            return

        output.delete("1.0", tk.END)
        output.insert(tk.END, _format_report(report))

        reports_dir = Path.cwd() / "reports"
        report_path = writer.write(report, reports_dir)
        messagebox.showinfo("Scan complete", f"Report saved at:\n{report_path}")

    def show_flow() -> None:
        flow_text = (
            "Flow:\n"
            "1) App starts and requests root/admin privileges\n"
            "2) User selects OS and service module (hardcoded matrix)\n"
            "3) Scanner resolves config path candidates\n"
            "4) Rule checks evaluate live configuration\n"
            "5) Weighted hardening index is calculated\n"
            "6) Report is shown and exported to reports/"
        )
        messagebox.showinfo("Process Flow", flow_text)

    ttk.Button(button_frame, text="Scan", command=run_scan).pack(side="left")
    ttk.Button(button_frame, text="Flow", command=show_flow).pack(side="left", padx=(8, 0))
    ttk.Button(button_frame, text="Refresh Modules", command=refresh_module_list).pack(side="left", padx=(8, 0))

    os_combo.bind("<<ComboboxSelected>>", refresh_module_list)
    service_combo.bind("<<ComboboxSelected>>", refresh_module_list)
    module_combo.bind("<<ComboboxSelected>>", on_module_change)

    refresh_module_list()
    output.insert(
        tk.END,
        "Ready. Select module and click Scan.\n\n"
        "If nothing happens, the selected service may not be installed on this host.\n"
        "The app will show exact missing config paths when you click Scan.",
    )
    root.mainloop()
