from __future__ import annotations

from pathlib import Path

from ...domain.contracts import ConfigReader, PathSelector, ScoringStrategy
from ...domain.models import (
    ModuleDefinition,
    RuleResult,
    ScanReport,
    ScanSummary,
)
from .discovery import DiscoveryEngine
from .fingerprint import FingerprintEngine
from .rule_engine import RuleEngine


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
        self._discovery = DiscoveryEngine(path_selector, config_reader)
        self._rule_engine = RuleEngine()
        self._fingerprint_engine = FingerprintEngine()
        self._scoring_strategy = scoring_strategy

    def scan(
        self,
        module: ModuleDefinition,
        os_version: str | None = None,
        service_version: str | None = None,
        xampp_version: str | None = None,
        target_host: str | None = None,
        enable_metasploit: bool = False,
    ) -> ScanReport:
        discovery = self._discovery.discover(module)
        rule_result = self._rule_engine.evaluate(module, discovery.config_texts, discovery.resolved_paths)
        results = rule_result.results

        summary = self._scoring_strategy.summarize(results)
        fingerprint = self._fingerprint_engine.fingerprint(
            module,
            os_version=os_version,
            service_version=service_version,
            xampp_version=xampp_version,
            target_host=target_host,
            enable_metasploit=enable_metasploit,
        )
        if fingerprint.warnings:
            summary.warnings[:0] = fingerprint.warnings

        return ScanReport(
            module=module,
            used_config_paths=discovery.resolved_paths,
            summary=summary,
            results=results,
            scan_id=fingerprint.scan_id,
            vulnerability_findings=fingerprint.vulnerability_findings,
            version_context=fingerprint.version_context,
            cve_advisories=fingerprint.cve_advisories,
            metasploit_results=fingerprint.metasploit_results,
        )
