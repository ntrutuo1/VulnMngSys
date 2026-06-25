from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from vulnmngsys_app.services.scan_result_mapper import LegacyScanPayloadMapper, ScanResultMapper
from vulnmngsys_app.models.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector

logger = logging.getLogger(__name__)


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

    def run_scan(
        self,
        raw_rules: list[dict[str, Any]],
        *,
        progress_callback: Callable[[str, Rule, int, int, RuleComparisonResult | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        rules = self.parse_raw_rules(raw_rules)
        results_payload: list[dict[str, Any]] = []

        logger.info("Starting configuration scan for %s rules.", len(rules))

        total = len(rules)
        for index, rule in enumerate(rules, start=1):
            self._emit_progress(progress_callback, "rule_started", rule, index, total, None)
            result = self._check_rule(rule)
            self._emit_progress(progress_callback, "rule_finished", rule, index, total, result)
            results_payload.append(self.result_mapper.map(rule, result))

        logger.info("Configuration scan completed.")
        return results_payload

    def _emit_progress(
        self,
        callback: Callable[[str, Rule, int, int, RuleComparisonResult | None], None] | None,
        event: str,
        rule: Rule,
        index: int,
        total: int,
        result: RuleComparisonResult | None,
    ) -> None:
        if callback is None:
            return
        try:
            callback(event, rule, index, total, result)
        except Exception as exc:
            logger.warning("Scan progress callback failed for rule %s: %s", rule.id, exc)

    def _check_rule(self, rule: Rule) -> RuleComparisonResult:
        for checker in self.checkers:
            if not checker.can_handle(rule):
                continue
            try:
                return checker.check(rule, self.collector)
            except Exception as exc:
                logger.error("Error while checking rule %s: %s", rule.id, exc)
                return RuleComparisonResult(False, "ERROR", str(exc), rule.expected, str(exc))

        return RuleComparisonResult(False, "MANUAL", "N/A", rule.expected, "No available checker")
