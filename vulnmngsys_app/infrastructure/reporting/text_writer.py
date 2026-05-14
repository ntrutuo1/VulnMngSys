from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ...domain.contracts import ReportWriter
from ...domain.models import ScanReport
from .history_store import append_scan_history


class TextReportWriter(ReportWriter):
    def write(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"scan-{report.module.module_id}-{timestamp}.txt"
        path = output_dir / filename

        lines: list[str] = []
        lines.append("VulnMngSys Report (Lynis-inspired)")
        lines.append("=================================")
        lines.append(f"Module: {report.module.display_name}")
        lines.append(f"OS: {report.module.os_family} / {report.module.os_version}")
        lines.append(f"Service: {report.module.service_type}")
        lines.append(f"Rules Source: {report.module.rules_source_file}")
        if report.version_context:
            lines.append("Version Context:")
            lines.append(f"- OS Version Input: {report.version_context.get('os_version', '')}")
            lines.append(f"- Service Version Input: {report.version_context.get('service_version', '')}")
        lines.append("")
        lines.append("[+] Resolved Config Paths")
        for key, value in report.used_config_paths.items():
            lines.append(f"- {key}: {value}")

        summary = report.summary
        lines.append("")
        lines.append("[+] Hardening Index (Lynis-style)")
        lines.append(f"- Total checks: {summary.total_checks}")
        lines.append(f"- Passed checks: {summary.passed_checks}")
        lines.append(f"- Failed checks: {summary.failed_checks}")
        lines.append(f"- Total weight: {summary.total_weight}")
        lines.append(f"- Passed weight: {summary.passed_weight}")
        lines.append(f"- Hardening index: {summary.hardening_index}")
        lines.append(f"- Grade: {summary.grade}")

        severity_counts: dict[str, int] = {}
        for result in report.results:
            severity = result.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if severity_counts:
            lines.append("")
            lines.append("[+] Checks by Severity")
            for level in ("critical", "high", "medium", "low"):
                if level in severity_counts:
                    lines.append(f"- {level.title()}: {severity_counts[level]}")

        if summary.warnings:
            lines.append("")
            lines.append("[!] Warnings")
            for warning in summary.warnings:
                lines.append(f"- {warning}")

        if report.cve_advisories:
            lines.append("")
            lines.append("[+] CVE Intelligence (version-based)")
            for advisory in report.cve_advisories:
                lines.append(
                    f"- [{advisory.severity.upper()}] {advisory.cve_id} | {advisory.title} | "
                    f"{advisory.reason} | {advisory.reference}"
                )

        if report.metasploit_results:
            lines.append("")
            lines.append("[+] Metasploit Service Scan")
            for item in report.metasploit_results:
                status = "OK" if item.success else "FAIL"
                lines.append(f"- [{status}] {item.module} | {item.target} | {item.summary}")

        failed_suggestions = [
            result
            for result in report.results
            if not result.passed and (result.suggested_line or result.baseline)
        ]
        if failed_suggestions:
            lines.append("")
            lines.append("[+] Suggestions")
            for result in failed_suggestions:
                expected = result.suggested_line or result.baseline
                lines.append(f"- {result.code} | {result.title} | {expected}")

        lines.append("")
        lines.append("[+] Rule Results")
        for result in report.results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(
                f"- [{status}] {result.code} | sev={result.severity} | w={result.weight} | "
                f"{result.title} | {result.reason}"
            )

        path.write_text("\n".join(lines), encoding="utf-8")
        append_scan_history(report, output_dir)
        return path
