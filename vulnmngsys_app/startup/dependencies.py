from __future__ import annotations

from vulnmngsys_app.services.scan_result_mapper import LegacyScanPayloadMapper
from vulnmngsys_app.services.scanflow.reconfig import RemediationPipeline
from vulnmngsys_app.models.protocols import RuleChecker, SystemCollector
from vulnmngsys_app.adapters.backup_manager import backup_manager
from vulnmngsys_app.adapters.checkers.checker_registry import default_checker_registry
from vulnmngsys_app.adapters.collectors.windows_collector import WindowsCollector
from vulnmngsys_app.adapters.rule_repository import JsonRuleRepository
from vulnmngsys_app.adapters.service_verifier import service_verifier


def scan_dependencies(
    profile_key: str,
) -> tuple[JsonRuleRepository, SystemCollector, list[RuleChecker], LegacyScanPayloadMapper]:
    return (
        JsonRuleRepository(),
        WindowsCollector(),
        default_checker_registry().build(),
        LegacyScanPayloadMapper(profile_key=profile_key),
    )


def remediation_pipeline() -> RemediationPipeline:
    return RemediationPipeline(backup=backup_manager, verifier=service_verifier)
