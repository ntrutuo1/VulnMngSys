from __future__ import annotations

from typing import Any

from application.scan_result_mapper import LegacyScanPayloadMapper, ScanResultMapper
from domain.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from infrastructure.logging.system_logger import logger


class ScanService:
    """Orchestrates scans by selecting a checker for each rule."""

    def __init__(
        self,
        collector: SystemCollector,
        checkers: list[RuleChecker],
        result_mapper: ScanResultMapper | None = None,
    ) -> None:
        self.collector = collector
        self.checkers = checkers
        self.result_mapper = result_mapper or LegacyScanPayloadMapper()

    def parse_raw_rules(self, raw_rules: list[dict[str, Any]]) -> list[Rule]:
        rules = []
        for raw in raw_rules:
            rules.append(
                Rule(
                    id=str(raw.get("id") or raw.get("ruleId") or ""),
                    title=str(raw.get("title", "")),
                    service=str(raw.get("service") or raw.get("service_name") or ""),
                    check_type=str(raw.get("check_type", "")),
                    expected=raw.get("expected"),
                    description=str(raw.get("description", "")),
                    remediation=str(raw.get("remediation", "")),
                    raw_spec=raw,
                )
            )
        return rules

    def run_scan(self, raw_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rules = self.parse_raw_rules(raw_rules)
        results_payload: list[dict[str, Any]] = []

        logger.info("Starting configuration scan for %s rules.", len(rules))

        for rule in rules:
            result = self._check_rule(rule)
            results_payload.append(self.result_mapper.map(rule, result))

        logger.info("Configuration scan completed.")
        return results_payload

    def _check_rule(self, rule: Rule) -> RuleComparisonResult:
        for checker in self.checkers:
            if not checker.can_handle(rule):
                continue
            try:
                return checker.check(rule, self.collector)
            except Exception as exc:
                logger.error("Error while checking rule %s: %s", rule.id, exc)
                return RuleComparisonResult(False, "ERROR", "Exception", rule.expected, str(exc))

        return RuleComparisonResult(False, "MANUAL", "N/A", rule.expected, "No available checker")
