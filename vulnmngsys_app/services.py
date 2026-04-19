from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .contracts import ConfigReader, PathSelector, ReportWriter, ScoringStrategy
from .cve_intelligence import evaluate_cves
from .models import CveAdvisory, ModuleDefinition, RuleResult, ScanReport, ScanSummary


class LocalPathSelector(PathSelector):
    def resolve(self, candidates: list[str]) -> str:
        for candidate in candidates:
            if Path(candidate).exists():
                return candidate
        return candidates[0]


class LocalConfigReader(ConfigReader):
    def read_text(self, path: str) -> str:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(path)
        return file_path.read_text(encoding="utf-8", errors="ignore")


class LynisScoringStrategy(ScoringStrategy):
    @staticmethod
    def _grade_for_index(index: int) -> str:
        if index >= 90:
            return "A"
        if index >= 75:
            return "B"
        if index >= 60:
            return "C"
        return "D"

    def summarize(self, results: list[RuleResult]) -> ScanSummary:
        total_checks = len(results)
        passed_checks = len([item for item in results if item.passed])
        failed_checks = total_checks - passed_checks
        total_weight = sum(item.weight for item in results)
        passed_weight = sum(item.weight for item in results if item.passed)

        hardening_index = int(round((passed_weight / total_weight) * 100)) if total_weight else 0
        summary = ScanSummary(
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            total_weight=total_weight,
            passed_weight=passed_weight,
            hardening_index=hardening_index,
            grade=self._grade_for_index(hardening_index),
            warnings=[],
        )

        for item in results:
            if not item.passed and item.severity.lower() in {"critical", "high"}:
                summary.warnings.append(f"{item.code}: {item.title}")

        return summary


class ComplianceScanner:
    def __init__(
        self,
        path_selector: PathSelector,
        config_reader: ConfigReader,
        scoring_strategy: ScoringStrategy,
    ) -> None:
        self._path_selector = path_selector
        self._config_reader = config_reader
        self._scoring_strategy = scoring_strategy

    def scan(
        self,
        module: ModuleDefinition,
        os_version: str | None = None,
        service_version: str | None = None,
    ) -> ScanReport:
        used_paths: dict[str, str] = {
            key: self._path_selector.resolve(paths) for key, paths in module.config_paths.items()
        }

        cache: dict[str, str] = {}
        for key, path in used_paths.items():
            cache[key] = self._config_reader.read_text(path)

        results: list[RuleResult] = []
        for check in module.checks:
            raw_text = cache.get(check.config_file_key, "")
            passed, reason = check.evaluator(raw_text)
            results.append(
                RuleResult(
                    code=check.code,
                    title=check.title,
                    severity=check.severity,
                    weight=check.weight,
                    passed=passed,
                    reason=reason,
                )
            )

        summary = self._scoring_strategy.summarize(results)
        version_context = {
            "os_family": module.os_family,
            "os_version": os_version or module.os_version,
            "service_type": module.service_type,
            "service_version": service_version or "",
        }

        cve_matches = evaluate_cves(
            os_family=module.os_family,
            os_version=version_context["os_version"],
            service_type=module.service_type,
            service_version=version_context["service_version"],
        )
        cve_advisories = [
            CveAdvisory(
                cve_id=item.cve_id,
                title=item.title,
                severity=item.severity,
                reason=item.reason,
                reference=item.reference,
            )
            for item in cve_matches
        ]

        return ScanReport(
            module=module,
            used_config_paths=used_paths,
            summary=summary,
            results=results,
            version_context=version_context,
            cve_advisories=cve_advisories,
        )


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


def build_default_scanner() -> ComplianceScanner:
    return ComplianceScanner(
        path_selector=LocalPathSelector(),
        config_reader=LocalConfigReader(),
        scoring_strategy=LynisScoringStrategy(),
    )


def build_default_report_writer() -> TextReportWriter:
    return TextReportWriter()
