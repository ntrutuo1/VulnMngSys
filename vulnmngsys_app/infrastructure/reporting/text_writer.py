from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ...domain.contracts import ReportWriter
from ...domain.models import ScanReport


class TextReportWriter(ReportWriter):
    def write(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"scan-{report.module.module_id}-{timestamp}.txt"
        path = output_dir / filename

        lines: list[str] = []
        lines.append(f"Module: {report.module.display_name}")
        lines.append(f"OS: {report.module.os_family} / {report.module.os_version}")
        lines.append(f"Service: {report.module.service_type}")
        lines.append(f"Rules Source: {report.module.rules_source_file}")
        if report.version_context:
            lines.append("Version Context:")
            lines.append(f"- OS Version Input: {report.version_context.get('os_version', '')}")
            lines.append(f"- Service Version Input: {report.version_context.get('service_version', '')}")
        lines.append("")
        lines.append("Resolved Config Paths:")
        for key, value in report.used_config_paths.items():
            lines.append(f"- {key}: {value}")

        summary = report.summary
        lines.append("")
        lines.append("Summary (Lynis-style hardening index):")
        lines.append(f"- Total checks: {summary.total_checks}")
        lines.append(f"- Passed checks: {summary.passed_checks}")
        lines.append(f"- Failed checks: {summary.failed_checks}")
        lines.append(f"- Total weight: {summary.total_weight}")
        lines.append(f"- Passed weight: {summary.passed_weight}")
        lines.append(f"- Hardening index: {summary.hardening_index}")
        lines.append(f"- Grade: {summary.grade}")

        if summary.warnings:
            lines.append("")
            lines.append("Warnings:")
            for warning in summary.warnings:
                lines.append(f"- {warning}")

        if report.cve_advisories:
            lines.append("")
            lines.append("CVE Intelligence (version-based):")
            for advisory in report.cve_advisories:
                lines.append(
                    f"- [{advisory.severity.upper()}] {advisory.cve_id} | {advisory.title} | "
                    f"{advisory.reason} | {advisory.reference}"
                )

        lines.append("")
        lines.append("Rule Results:")
        for result in report.results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(
                f"- [{status}] {result.code} | sev={result.severity} | w={result.weight} | "
                f"{result.title} | {result.reason}"
            )

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
