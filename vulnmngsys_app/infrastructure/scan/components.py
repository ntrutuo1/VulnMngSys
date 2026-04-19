from __future__ import annotations

from pathlib import Path

from ...domain.contracts import ConfigReader, PathSelector, ScoringStrategy
from ...domain.models import CveAdvisory, ModuleDefinition, RuleResult, ScanReport, ScanSummary
from ..intel.cve_intelligence import evaluate_cves


def _find_first_line_number(raw_text: str, needles: list[str]) -> int:
    lowered_needles = [needle.lower() for needle in needles if needle]
    if not lowered_needles:
        return 0

    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = stripped.split("#", 1)[0].strip()
        if not content:
            continue
        line_lower = content.lower()
        if any(needle in line_lower for needle in lowered_needles):
            return line_number
    return 0


def _read_line_content(raw_text: str, line_number: int) -> str:
    if line_number <= 0:
        return ""
    lines = raw_text.splitlines()
    if line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()


def _first_baseline_line(baseline: str) -> str:
    if not baseline:
        return ""
    for line in baseline.splitlines():
        trimmed = line.strip()
        if trimmed:
            return trimmed
    return ""


def _xampp_upgrade_warning(xampp_version: str | None) -> str:
    normalized = (xampp_version or "").strip()
    if normalized == "8.1.25":
        return "XAMPP 8.1.25 requires an upgrade. This version is flagged as outdated and should be updated to a newer supported release before deployment."
    return ""


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
        # Score is based on match ratio with baseline only, ignoring severity weights.
        total_weight = total_checks
        passed_weight = passed_checks

        hardening_index = int(round((passed_checks / total_checks) * 100)) if total_checks else 0
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
        xampp_version: str | None = None,
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

            metadata = module.check_metadata.get(check.code, {})
            search_terms = metadata.get("search", "").split("|") if metadata.get("search") else []
            config_line = _find_first_line_number(raw_text, search_terms)
            config_path = used_paths.get(check.config_file_key, "")
            baseline = metadata.get("baseline", "")
            explanation = metadata.get("explanation", "")
            actual_line = _read_line_content(raw_text, config_line)
            results.append(
                RuleResult(
                    code=check.code,
                    title=check.title,
                    severity=check.severity,
                    weight=check.weight,
                    passed=passed,
                    reason=reason,
                    config_path=config_path,
                    config_line=config_line,
                    baseline=baseline,
                    explanation=explanation,
                    actual_line=actual_line,
                    suggested_line=_first_baseline_line(baseline),
                )
            )

        summary = self._scoring_strategy.summarize(results)
        xampp_warning = _xampp_upgrade_warning(xampp_version)
        if xampp_warning:
            summary.warnings.insert(0, xampp_warning)
        version_context = {
            "os_family": module.os_family,
            "os_version": os_version or module.os_version,
            "service_type": module.service_type,
            "service_version": service_version or "",
            "xampp_version": xampp_version or "",
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
                likelihood=item.likelihood,
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
